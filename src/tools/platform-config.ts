/**
 * platform_config Tool
 *
 * Get and update project settings, Runtime configuration, and LLM configuration
 * via the Runtime REST API.
 *
 * Endpoints:
 *   GET  /api/projects/:projectId/settings    — Get project settings
 *   PUT  /api/projects/:projectId/settings    — Update project settings
 *   GET  /api/projects/:projectId/runtime-config — Get project-effective Runtime config
 *   GET  /api/projects/:projectId/llm-config  — Get LLM config (operation-tier mapping)
 *   PUT  /api/projects/:projectId/llm-config  — Update LLM config
 */

import { z } from 'zod';
import type { DebugContext } from './index.js';
import { validatePathParam } from '../utils/validate.js';
import {
  sanitizeResponse,
  sanitizeResponseBounded,
  sanitizeResponseIterative,
} from '../utils/sanitize.js';
import { resolveRuntimeOwnedPath } from '../utils/url.js';

// =============================================================================
// SCHEMA
// =============================================================================

/**
 * Frozen discovery contract for clients that opt into the legacy-v1 profile.
 * Keep this schema byte-for-byte equivalent to the pre-ABLP-4433 contract.
 */
export const legacyPlatformConfigSchema = z.object({
  action: z.enum(['get_settings', 'update_settings', 'get_llm_config', 'update_llm_config']),
  projectId: z.string().describe('Project ID'),
  settings: z.record(z.unknown()).optional().describe('Settings to update'),
});

export const platformConfigSchema = z.object({
  action: z.enum([
    'get_settings',
    'update_settings',
    'get_runtime_config',
    'get_llm_config',
    'update_llm_config',
  ]),
  projectId: z.string().describe('Project ID'),
  settings: z.record(z.unknown()).optional().describe('Settings to update'),
});

export const RUNTIME_CONFIG_RESPONSE_MAX_BYTES = 2 * 1024 * 1024;
export const RUNTIME_CONFIG_TIMEOUT_MS = 10_000;
export const RUNTIME_CONFIG_AI_OUTPUT_MAX_BYTES = 48 * 1024;

type PlatformConfigArgs = z.infer<typeof platformConfigSchema>;

// =============================================================================
// HELPERS
// =============================================================================

function success(data: unknown): string {
  return JSON.stringify({ success: true, data });
}

const SERIALIZATION_BATCH_MAX_TOKENS = 4_096;
const SERIALIZATION_BATCH_MAX_CHARS = 64 * 1024;

/**
 * Use the native serializer for ordinary responses, then fall back to bounded token batches only
 * when extreme nesting exceeds its call-stack depth. This preserves the historical wide-response
 * memory profile without rejecting a transport-valid deeply nested response.
 */
function successIterative(data: unknown): string {
  try {
    return success(data);
  } catch (error: unknown) {
    if (!(error instanceof RangeError)) throw error;
  }

  type Task =
    | { type: 'value'; value: unknown }
    | { type: 'array'; value: unknown[]; index: number }
    | {
        type: 'object';
        value: Record<string, unknown>;
        key?: string;
        keyCursor?: string;
        keyCursorOffset: number;
        emitted: number;
      };
  const tasks: Task[] = [{ type: 'value', value: { success: true, data } }];
  const chunks: string[] = [];
  let tokens: string[] = [];
  let tokenChars = 0;
  const flushTokens = (): void => {
    if (tokens.length === 0) return;
    chunks.push(tokens.join(''));
    tokens = [];
    tokenChars = 0;
  };
  const append = (token: string): void => {
    tokens.push(token);
    tokenChars += token.length;
    if (
      tokens.length >= SERIALIZATION_BATCH_MAX_TOKENS ||
      tokenChars >= SERIALIZATION_BATCH_MAX_CHARS
    ) {
      flushTokens();
    }
  };
  const encodeKeyCursor = (keys: string[]): string => {
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index] ?? '';
      keys[index] = `${key.length.toString(36)}:${key}`;
    }
    return keys.join('');
  };
  const nextTaskKey = (task: Extract<Task, { type: 'object' }>): string | undefined => {
    if (task.key !== undefined) {
      const key = task.key;
      task.key = undefined;
      return key;
    }
    const cursor = task.keyCursor;
    if (cursor === undefined || task.keyCursorOffset >= cursor.length) return undefined;
    const separator = cursor.indexOf(':', task.keyCursorOffset);
    const keyLength = Number.parseInt(cursor.slice(task.keyCursorOffset, separator), 36);
    const keyStart = separator + 1;
    const keyEnd = keyStart + keyLength;
    task.keyCursorOffset = keyEnd;
    return cursor.slice(keyStart, keyEnd);
  };
  while (tasks.length > 0) {
    const task = tasks.pop();
    if (!task) continue;
    if (task.type === 'array') {
      if (task.index >= task.value.length) {
        append(']');
        continue;
      }
      if (task.index > 0) append(',');
      const child = task.value[task.index];
      task.index += 1;
      tasks.push(task);
      tasks.push({ type: 'value', value: child });
      continue;
    }
    if (task.type === 'object') {
      let scheduledChild = false;
      let key = nextTaskKey(task);
      while (key !== undefined) {
        const child = task.value[key];
        if (child === undefined || typeof child === 'function' || typeof child === 'symbol') {
          key = nextTaskKey(task);
          continue;
        }
        if (task.emitted > 0) append(',');
        append(`${JSON.stringify(key)}:`);
        task.emitted += 1;
        tasks.push(task);
        tasks.push({ type: 'value', value: child });
        scheduledChild = true;
        break;
      }
      if (!scheduledChild) append('}');
      continue;
    }
    const value = task.value;
    if (value === null || typeof value !== 'object') {
      append(JSON.stringify(value) ?? 'null');
      continue;
    }
    if (Array.isArray(value)) {
      append('[');
      tasks.push({ type: 'array', value, index: 0 });
      continue;
    }
    append('{');
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record);
    // Preserve Object.keys order without retaining one key array for every active depth.
    tasks.push({
      type: 'object',
      value: record,
      ...(keys.length === 1 ? { key: keys[0] } : { keyCursor: encodeKeyCursor(keys) }),
      keyCursorOffset: 0,
      emitted: 0,
    });
  }
  flushTokens();
  return chunks.join('');
}

function error(message: string, hint?: string): string {
  return JSON.stringify({ success: false, error: message, ...(hint ? { hint } : {}) });
}

function safeErrorMessage(value: unknown): string {
  try {
    const raw = value instanceof Error ? value.message : String(value);
    if (raw.length > 16_384 || new TextEncoder().encode(raw).byteLength > 16_384) {
      return 'Error detail omitted because it exceeded the safe limit';
    }
    const sanitized = sanitizeResponseBounded(raw, {
      maxDepth: 1,
      maxArrayItems: 1,
      maxObjectKeys: 1,
      maxStringLength: 16_384,
    });
    return typeof sanitized === 'string' ? sanitized : 'Unknown error';
  } catch {
    return 'Unknown error';
  }
}

type AiSafeProjectionMarkerKind =
  | 'runtime_config_ai_safe'
  | 'runtime_config_ai_safe_legacy_fallback';

function isAiSafeProjectionMarker(
  value: unknown,
  allowedKinds: readonly AiSafeProjectionMarkerKind[] = ['runtime_config_ai_safe'],
): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const marker = value as Record<string, unknown>;
  return (
    typeof marker.kind === 'string' &&
    allowedKinds.includes(marker.kind as AiSafeProjectionMarkerKind) &&
    marker.version === 1 &&
    typeof marker.redacted === 'boolean' &&
    typeof marker.summarized === 'boolean' &&
    typeof marker.redactionCount === 'number' &&
    Number.isInteger(marker.redactionCount) &&
    marker.redactionCount >= 0 &&
    typeof marker.summaryCount === 'number' &&
    Number.isInteger(marker.summaryCount) &&
    marker.summaryCount >= 0 &&
    Array.isArray(marker.redactedPaths) &&
    marker.redactedPaths.length <= 50 &&
    marker.redactedPaths.every((path) => typeof path === 'string' && path.length <= 512) &&
    Array.isArray(marker.summarizedPaths) &&
    marker.summarizedPaths.length <= 50 &&
    marker.summarizedPaths.every((path) => typeof path === 'string' && path.length <= 512)
  );
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Required response signature from immutable Artemis_1.1.0 (`f1c5a7e`). */
const artemis110RuntimeConfigSchema = z
  .object({
    projectId: z.string(),
    operationTierOverrides: z.record(z.string()),
    extraction: z
      .object({
        strategy: z.string(),
        correction_detection: z.string(),
        sidecar_timeout_ms: z.number(),
        sidecar_circuit_breaker_threshold: z.number(),
        nlu_provider: z.string(),
        advanced_sidecar_timeout_ms: z.number(),
        advanced_sidecar_circuit_breaker_threshold: z.number(),
        advanced_sidecar_url: z.string().optional(),
      })
      .passthrough(),
    multi_intent: z
      .object({
        enabled: z.boolean(),
        strategy: z.string(),
        unknown_relationship_strategy: z.string(),
        max_intents: z.number().int(),
        confidence_threshold: z.number(),
        queue_max_age_ms: z.number().int(),
      })
      .passthrough(),
    inference: z
      .object({
        confidence: z.number(),
        confirm: z.boolean(),
        model_tier: z.string(),
        max_fields_per_pass: z.number(),
      })
      .passthrough(),
    conversion: z.object({ currency_mode: z.string() }).passthrough(),
    pii_redaction: z
      .object({ enabled: z.boolean(), redact_input: z.boolean(), redact_output: z.boolean() })
      .passthrough(),
    lookup_tables: z.array(z.record(z.unknown())),
    filler: z.record(z.unknown()),
    analytics: z.record(z.unknown()),
  })
  .passthrough();

function pickPrimitiveFields(
  value: unknown,
  allowed: readonly string[],
): Record<string, string | number | boolean | null> | undefined {
  if (!isPlainRecord(value)) return undefined;
  const picked: Record<string, string | number | boolean | null> = {};
  for (const key of allowed) {
    const child = value[key];
    if (
      typeof child === 'string' ||
      typeof child === 'number' ||
      typeof child === 'boolean' ||
      child === null
    ) {
      picked[key] = child;
    }
  }
  return picked;
}

function projectLegacyRuntimeConfig(
  value: z.infer<typeof artemis110RuntimeConfigSchema>,
): Record<string, unknown> {
  return {
    projectId: String(value.projectId).slice(0, 4_096),
    extraction: pickPrimitiveFields(value.extraction, [
      'strategy',
      'correction_detection',
      'pipeline_v2_enabled',
      'mode',
      'sidecar_fallback',
      'confidence_threshold',
      'include_confidence',
    ]),
    multi_intent: pickPrimitiveFields(value.multi_intent, [
      'enabled',
      'strategy',
      'unknown_relationship_strategy',
      'max_intents',
      'confidence_threshold',
      'queue_max_age_ms',
    ]),
    inference: pickPrimitiveFields(value.inference, [
      'confidence',
      'confirm',
      'model_tier',
      'max_fields_per_pass',
    ]),
    streaming_safety: pickPrimitiveFields(value.streaming_safety, ['mode']),
    _projectionNotice:
      'Prior Runtime detected; credential-capable and free-text sections were omitted during rolling-upgrade compatibility.',
    _aiSafeProjection: {
      kind: 'runtime_config_ai_safe_legacy_fallback',
      version: 1,
      redacted: false,
      summarized: true,
      redactionCount: 0,
      summaryCount: 1,
      redactedPaths: [],
      summarizedPaths: ['$'],
    },
  };
}

function unwrapDataEnvelope(value: unknown, allowLegacy: boolean): unknown {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Runtime returned malformed configuration.');
  }
  const record = value as Record<string, unknown>;
  if ('success' in record) {
    if (record.success !== true) {
      throw new Error('Runtime rejected the configuration read');
    }
    if (typeof record.data !== 'object' || record.data === null || Array.isArray(record.data)) {
      throw new Error('Runtime returned malformed configuration.');
    }
    const projection = (record.data as Record<string, unknown>)._aiSafeProjection;
    if (!isAiSafeProjectionMarker(projection)) {
      const legacy = allowLegacy ? artemis110RuntimeConfigSchema.safeParse(record.data) : null;
      if (legacy?.success) {
        return projectLegacyRuntimeConfig(legacy.data);
      }
      throw new Error('Runtime did not return a valid AI-safe or prior canonical configuration.');
    }
    if (typeof (record.data as Record<string, unknown>).projectId !== 'string') {
      throw new Error('Runtime returned malformed configuration.');
    }
    return record.data;
  }
  throw new Error('Runtime returned malformed configuration.');
}

function sanitizeRuntimeConfigProjection(value: unknown): unknown {
  let localRedactionCount = 0;
  const localRedactedPaths: string[] = [];
  const sanitized = sanitizeResponseBounded(value, {
    maxDepth: 16,
    maxArrayItems: 100,
    maxObjectKeys: 100,
    maxStringLength: 4_096,
    redactUrlLocations: true,
    redactPii: true,
    allowCredentialMetadata: false,
    onRedaction: (path) => {
      localRedactionCount += 1;
      if (localRedactedPaths.length < 50) localRedactedPaths.push(path.slice(0, 512));
    },
  });
  if (!isPlainRecord(sanitized)) return sanitized;
  const marker = sanitized._aiSafeProjection;
  if (
    !isAiSafeProjectionMarker(marker, [
      'runtime_config_ai_safe',
      'runtime_config_ai_safe_legacy_fallback',
    ])
  ) {
    return sanitized;
  }
  const validMarker = marker as {
    kind: AiSafeProjectionMarkerKind;
    version: 1;
    redacted: boolean;
    summarized: boolean;
    redactionCount: number;
    summaryCount: number;
    redactedPaths: string[];
    summarizedPaths: string[];
  };
  return {
    ...sanitized,
    _aiSafeProjection: {
      ...validMarker,
      redacted: validMarker.redacted || localRedactionCount > 0,
      redactionCount: Math.min(
        Number.MAX_SAFE_INTEGER,
        validMarker.redactionCount + localRedactionCount,
      ),
      redactedPaths: [...new Set([...validMarker.redactedPaths, ...localRedactedPaths])].slice(
        0,
        50,
      ),
    },
  };
}

function boundConfigurationOutput(value: unknown, runtimeConfig = false): unknown {
  if (
    new TextEncoder().encode(JSON.stringify(value)).byteLength <= RUNTIME_CONFIG_AI_OUTPUT_MAX_BYTES
  ) {
    return value;
  }
  const record = isPlainRecord(value) ? value : {};
  const marker = isPlainRecord(record._aiSafeProjection) ? record._aiSafeProjection : {};
  const redactionCount =
    typeof marker.redactionCount === 'number' && Number.isSafeInteger(marker.redactionCount)
      ? Math.max(0, marker.redactionCount)
      : 0;
  const summaryCount =
    typeof marker.summaryCount === 'number' && Number.isSafeInteger(marker.summaryCount)
      ? Math.max(0, marker.summaryCount)
      : 0;
  if (!runtimeConfig) {
    return { _summary: 'Configuration response omitted to preserve the AI context budget.' };
  }
  const validInputMarker = isAiSafeProjectionMarker(marker, [
    'runtime_config_ai_safe',
    'runtime_config_ai_safe_legacy_fallback',
  ]);
  const redactedPaths = validInputMarker ? [...(marker.redactedPaths as string[])] : [];
  const fallback = {
    projectId: typeof record.projectId === 'string' ? record.projectId.slice(0, 4_096) : '',
    _projectionNotice: 'Runtime configuration was omitted to preserve the AI context budget.',
    _aiSafeProjection: {
      kind: 'runtime_config_ai_safe_client_fallback',
      version: 1,
      redacted: redactionCount > 0 || (validInputMarker && marker.redacted === true),
      summarized: true,
      redactionCount,
      summaryCount: Math.min(Number.MAX_SAFE_INTEGER, summaryCount + 1),
      redactedPaths,
      summarizedPaths: ['$'],
    },
  };
  while (
    new TextEncoder().encode(JSON.stringify(fallback)).byteLength >
      RUNTIME_CONFIG_AI_OUTPUT_MAX_BYTES &&
    redactedPaths.length > 0
  ) {
    redactedPaths.pop();
  }
  return fallback;
}

async function readBoundedConfiguration(ctx: DebugContext, path: string): Promise<unknown> {
  const response = await ctx.httpClient.getBoundedJson(path, {
    timeoutMs: RUNTIME_CONFIG_TIMEOUT_MS,
    maxResponseBytes: RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(
      `GET ${path} failed: ${response.status} ${safeErrorMessage(response.statusText)}`,
    );
  }
  // The transport has already limited the serialized JSON body to 2 MiB. A JSON array element or
  // object member necessarily consumes at least one byte, so the byte ceiling is also a strict,
  // linear-work upper bound for structural cardinality. Do not reuse the model-output collection
  // limit here: these pre-existing actions must return every successful value within their
  // historical transport contract rather than summarizing or rejecting the 1,001st entry.
  return sanitizeResponseIterative(response.body, RUNTIME_CONFIG_RESPONSE_MAX_BYTES);
}

// =============================================================================
// HANDLER
// =============================================================================

export async function platformConfig(args: PlatformConfigArgs, ctx: DebugContext): Promise<string> {
  const { action, projectId, settings } = args;
  const safeProjectId = validatePathParam(projectId, 'projectId');

  try {
    switch (action) {
      // ----- GET SETTINGS -----
      case 'get_settings': {
        const data = await readBoundedConfiguration(ctx, `/api/projects/${safeProjectId}/settings`);
        return successIterative(data);
      }

      // ----- UPDATE SETTINGS -----
      case 'update_settings': {
        if (!settings) {
          return error('settings is required for the "update_settings" action.');
        }
        const data = await ctx.httpClient.put(`/api/projects/${safeProjectId}/settings`, settings);
        return success(sanitizeResponse(data));
      }

      // ----- GET PROJECT-EFFECTIVE RUNTIME CONFIG -----
      case 'get_runtime_config': {
        let legacyFallback = false;
        const aiSafePath = resolveRuntimeOwnedPath(
          ctx.httpClient,
          `/api/projects/${safeProjectId}/runtime-config/ai-safe`,
        );
        const legacyPath = resolveRuntimeOwnedPath(
          ctx.httpClient,
          `/api/projects/${safeProjectId}/runtime-config`,
        );
        let response = await ctx.httpClient.getBoundedJson(aiSafePath, {
          timeoutMs: RUNTIME_CONFIG_TIMEOUT_MS,
          maxResponseBytes: RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
        });
        if (response.status === 404) {
          legacyFallback = true;
          response = await ctx.httpClient.getBoundedJson(legacyPath, {
            timeoutMs: RUNTIME_CONFIG_TIMEOUT_MS,
            maxResponseBytes: RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
          });
        }
        if (response.status < 200 || response.status >= 300) {
          return error(
            'Configuration request failed.',
            'Ensure the runtime is running and you are connected (platform_connect).',
          );
        }
        const sanitized = sanitizeRuntimeConfigProjection(
          unwrapDataEnvelope(response.body, legacyFallback),
        );
        return success(boundConfigurationOutput(sanitized, true));
      }

      // ----- GET LLM CONFIG -----
      case 'get_llm_config': {
        const data = await readBoundedConfiguration(
          ctx,
          `/api/projects/${safeProjectId}/llm-config`,
        );
        return successIterative(data);
      }

      // ----- UPDATE LLM CONFIG -----
      case 'update_llm_config': {
        if (!settings) {
          return error('settings is required for the "update_llm_config" action.');
        }
        const data = await ctx.httpClient.put(
          `/api/projects/${safeProjectId}/llm-config`,
          settings,
        );
        return success(sanitizeResponse(data));
      }

      default:
        return error(`Unknown action: ${action}`);
    }
  } catch (err) {
    const message =
      action === 'get_runtime_config'
        ? 'Configuration request failed.'
        : `Configuration request failed: ${safeErrorMessage(err)}`;
    return error(
      message,
      'Ensure the runtime is running and you are connected (platform_connect).',
    );
  }
}
