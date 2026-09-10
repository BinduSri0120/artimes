import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpClient } from '../client/http-client.js';
import { HttpResponseDecodeError } from '../client/http-client.js';
import { ResponseSizeLimitError } from '../utils/bounded-response.js';
import { FetchError } from '../utils/fetch.js';
import {
  platformConfig,
  platformConfigSchema,
  RUNTIME_CONFIG_AI_OUTPUT_MAX_BYTES,
  RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
  RUNTIME_CONFIG_TIMEOUT_MS,
} from '../tools/platform-config.js';
import type { DebugContext } from '../tools/index.js';

const originalFetch = globalThis.fetch;
const MAX_WIDE_SERIALIZER_RSS_GROWTH_KIB = 80 * 1024;
const MAX_DEEP_SERIALIZER_RSS_GROWTH_KIB = 112 * 1024;
const CHILD_PROCESS_OUTPUT_MAX_BYTES = 1024 * 1024;
const AI_SAFE_METADATA = {
  kind: 'runtime_config_ai_safe',
  version: 1,
  redacted: true,
  summarized: false,
  redactionCount: 1,
  summaryCount: 0,
  redactedPaths: ['api_key'],
  summarizedPaths: [],
};
const UNREDACTED_AI_SAFE_METADATA = {
  ...AI_SAFE_METADATA,
  redacted: false,
  redactionCount: 0,
  redactedPaths: [],
};

/** Exact required response shape from immutable Artemis_1.1.0 (`f1c5a7e`). */
function legacyRuntimeConfig() {
  return {
    projectId: 'project-1',
    operationTierOverrides: {},
    extraction: {
      strategy: 'hybrid',
      correction_detection: 'enabled',
      sidecar_timeout_ms: 2_000,
      sidecar_circuit_breaker_threshold: 3,
      nlu_provider: 'builtin',
      advanced_sidecar_timeout_ms: 2_000,
      advanced_sidecar_circuit_breaker_threshold: 3,
    },
    multi_intent: {
      enabled: false,
      strategy: 'sequential',
      unknown_relationship_strategy: 'route_first',
      max_intents: 3,
      confidence_threshold: 0,
      queue_max_age_ms: 0,
    },
    inference: { confidence: 0, confirm: false, model_tier: 'fast', max_fields_per_pass: 3 },
    conversion: { currency_mode: 'live', currency_api_url: 'https://secret.invalid/path?auth=x' },
    pii_redaction: { enabled: true, redact_input: true, redact_output: true },
    lookup_tables: [{ values: ['owner@example.test', 'sk-proj-abcdefghijklmnopqrstuvwxyz123'] }],
    filler: { enabled: false },
    analytics: { dimensions: [] },
  };
}

afterEach(() => {
  vi.stubGlobal('fetch', originalFetch);
  vi.restoreAllMocks();
});

function createContext(): DebugContext {
  const httpClient = new HttpClient('https://runtime.example.invalid');
  httpClient.setAuthToken('test-token');
  return { httpClient } as DebugContext;
}

describe('platform_config get_runtime_config', () => {
  it('advertises the additive project-effective Runtime configuration action', () => {
    expect(
      platformConfigSchema.safeParse({
        action: 'get_runtime_config',
        projectId: 'project-1',
      }).success,
    ).toBe(true);
  });

  it('re-sanitizes a forged marked response and reports truthful local redaction metadata', async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        success: true,
        data: {
          projectId: 'project-1',
          multi_intent: {
            enabled: true,
            strategy: 'primary_queue',
            unknown_relationship_strategy: 'parallel',
            max_intents: 3,
            confidence_threshold: 0,
            queue_max_age_ms: 600_000,
          },
          inference: {
            confidence: 0,
            confirm: true,
            model_tier: 'fast',
            max_fields_per_pass: 3,
          },
          api_key: 'must-not-be-returned',
          managedCredentialKey: 'platform-llm',
          credentialProvider: 'openai',
          authProfileId: 'auth-profile-internal-123',
          credentialSource: 'platform',
          credentialMode: 'managed',
          credentialScope: 'tenant',
          credentialReadiness: 'ready',
          _aiSafeProjection: UNREDACTED_AI_SAFE_METADATA,
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(fetchMock).toHaveBeenCalledWith(
      'https://runtime.example.invalid/api/runtime/projects/project-1/runtime-config/ai-safe',
      expect.objectContaining({ headers: { Authorization: 'Bearer test-token' } }),
    );
    expect(result).toEqual({
      success: true,
      data: {
        projectId: 'project-1',
        multi_intent: {
          enabled: true,
          strategy: 'primary_queue',
          unknown_relationship_strategy: 'parallel',
          max_intents: 3,
          confidence_threshold: 0,
          queue_max_age_ms: 600_000,
        },
        inference: {
          confidence: 0,
          confirm: true,
          model_tier: 'fast',
          max_fields_per_pass: 3,
        },
        api_key: '[REDACTED]',
        managedCredentialKey: '[REDACTED]',
        credentialProvider: '[REDACTED]',
        authProfileId: '[REDACTED]',
        credentialSource: '[REDACTED]',
        credentialMode: '[REDACTED]',
        credentialScope: '[REDACTED]',
        credentialReadiness: '[REDACTED]',
        _aiSafeProjection: {
          ...UNREDACTED_AI_SAFE_METADATA,
          redacted: true,
          redactionCount: 8,
          redactedPaths: [
            'api_key',
            'managedCredentialKey',
            'credentialProvider',
            'authProfileId',
            'credentialSource',
            'credentialMode',
            'credentialScope',
            'credentialReadiness',
          ],
        },
      },
    });
  });

  it('strictly removes URL locations only from Runtime configuration output', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          success: true,
          data: {
            projectId: 'project-1',
            providerDsn: 'mongodb://user:password@example.test/tenant-db?replicaSet=private',
            malformedEndpoint: 'http://%/private/customer/alice?case=42',
            _aiSafeProjection: UNREDACTED_AI_SAFE_METADATA,
          },
        }),
      ),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result).toMatchObject({
      success: true,
      data: {
        providerDsn: 'mongodb://example.test/[REDACTED_PATH]',
        malformedEndpoint: '[REDACTED_URL]',
        _aiSafeProjection: { redacted: true, redactionCount: 2 },
      },
    });
    expect(JSON.stringify(result)).not.toContain('tenant-db');
    expect(JSON.stringify(result)).not.toContain('password');
  });

  it('keeps benign size-only fallback redaction metadata false and orthogonal to summarization', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          success: true,
          data: {
            projectId: 'project-1',
            benign: Array.from({ length: 100 }, () => 'x'.repeat(1_000)),
            _aiSafeProjection: UNREDACTED_AI_SAFE_METADATA,
          },
        }),
      ),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result.data._aiSafeProjection).toEqual({
      kind: 'runtime_config_ai_safe_client_fallback',
      version: 1,
      redacted: false,
      summarized: true,
      redactionCount: 0,
      summaryCount: 1,
      redactedPaths: [],
      summarizedPaths: ['$'],
    });
  });

  it('preserves truthful local secret accounting through the size fallback', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          success: true,
          data: {
            projectId: 'project-1',
            benign: Array.from({ length: 100 }, () => 'x'.repeat(1_000)),
            api_key: 'opaque-sensitive-value',
            _aiSafeProjection: UNREDACTED_AI_SAFE_METADATA,
          },
        }),
      ),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result.data._aiSafeProjection).toMatchObject({
      kind: 'runtime_config_ai_safe_client_fallback',
      redacted: true,
      summarized: true,
      redactionCount: 1,
      redactedPaths: ['api_key'],
    });
    expect(JSON.stringify(result)).not.toContain('opaque-sensitive-value');
  });

  it.each([
    ['primitive', 'compatible-response'],
    ['array', [{ projectId: 'project-1' }]],
    ['null', null],
  ])('rejects a malformed compatible %s response shape', async (_label, body) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(body)),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result).toMatchObject({ success: false, error: 'Configuration request failed.' });
  });

  it('fails closed for an unmarked malformed success envelope', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          success: true,
          data: {
            projectId: 'project-1',
            api_key: 'secret',
          },
        }),
      ),
    );
    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );
    expect(result).toMatchObject({
      success: false,
      error: expect.stringContaining('Configuration request failed'),
    });
    expect(JSON.stringify(result)).not.toContain('api_key');
  });

  it('uses a bounded field allowlist for a prior Runtime during rolling upgrade', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(Response.json({ success: true, data: legacyRuntimeConfig() }));
    vi.stubGlobal('fetch', fetchMock);
    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );
    const serialized = JSON.stringify(result);
    expect(result).toMatchObject({
      success: true,
      data: {
        extraction: { strategy: 'hybrid', correction_detection: 'enabled' },
        multi_intent: { enabled: false, confidence_threshold: 0 },
        inference: {
          confidence: 0,
          confirm: false,
          model_tier: 'fast',
          max_fields_per_pass: 3,
        },
        _aiSafeProjection: {
          kind: 'runtime_config_ai_safe_legacy_fallback',
          redacted: false,
          redactionCount: 0,
          redactedPaths: [],
        },
      },
    });
    expect(fetchMock.mock.calls.map(([request]) => String(request))).toEqual([
      'https://runtime.example.invalid/api/runtime/projects/project-1/runtime-config/ai-safe',
      'https://runtime.example.invalid/api/runtime/projects/project-1/runtime-config',
    ]);
    expect(new TextEncoder().encode(JSON.stringify(result)).byteLength).toBeLessThan(
      RUNTIME_CONFIG_AI_OUTPUT_MAX_BYTES,
    );
    expect(serialized).not.toContain('owner@example.test');
    expect(serialized).not.toContain('sk-proj-');
    expect(serialized).not.toContain('secret.invalid');
  });

  it('accounts for strict local redaction in a projected Artemis 1.1.0 primitive', async () => {
    const legacy = legacyRuntimeConfig();
    legacy.inference.model_tier =
      'https://provider.example.invalid/customer/model?oauth_code=SENSITIVE123';
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(Response.json({ success: true, data: legacy })),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result).toMatchObject({
      success: true,
      data: {
        inference: { model_tier: 'https://provider.example.invalid/[REDACTED_PATH]' },
        _aiSafeProjection: {
          kind: 'runtime_config_ai_safe_legacy_fallback',
          redacted: true,
          redactionCount: 1,
          redactedPaths: ['inference.model_tier'],
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain('SENSITIVE123');
  });

  it.each(['operationTierOverrides', 'extraction', 'multi_intent', 'analytics'])(
    'rejects an Artemis_1.1.0 envelope missing %s',
    async (missingField) => {
      const legacy = { ...legacyRuntimeConfig() } as Record<string, unknown>;
      delete legacy[missingField];
      vi.stubGlobal(
        'fetch',
        vi
          .fn()
          .mockResolvedValueOnce(new Response(null, { status: 404 }))
          .mockResolvedValueOnce(Response.json({ success: true, data: legacy })),
      );

      const result = JSON.parse(
        await platformConfig(
          { action: 'get_runtime_config', projectId: 'project-1' },
          createContext(),
        ),
      );

      expect(result).toMatchObject({ success: false, error: 'Configuration request failed.' });
    },
  );

  it('rejects a direct Artemis_1.1.0 object after the compatibility retry', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(Response.json(legacyRuntimeConfig())),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result).toMatchObject({ success: false, error: 'Configuration request failed.' });
  });

  it('handles alternating prior and current Runtime pods without caching compatibility state', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(Response.json({ success: true, data: legacyRuntimeConfig() }))
      .mockResolvedValueOnce(
        Response.json({
          success: true,
          data: { projectId: 'project-1', _aiSafeProjection: AI_SAFE_METADATA },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);
    const args = { action: 'get_runtime_config' as const, projectId: 'project-1' };

    const prior = JSON.parse(await platformConfig(args, createContext()));
    const current = JSON.parse(await platformConfig(args, createContext()));

    expect(prior).toMatchObject({
      success: true,
      data: { _aiSafeProjection: { kind: 'runtime_config_ai_safe_legacy_fallback' } },
    });
    expect(current).toMatchObject({
      success: true,
      data: { _aiSafeProjection: { kind: 'runtime_config_ai_safe' } },
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('honors a failure envelope returned with HTTP 200', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          success: false,
          error: { message: 'denied: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890' },
        }),
      ),
    );
    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );
    expect(result).toMatchObject({
      success: false,
      error: 'Configuration request failed.',
    });
    expect(JSON.stringify(result)).not.toContain('sk-proj-');
  });

  it('returns a sanitized failure when Runtime rejects the read', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 403, statusText: 'Forbidden' })),
    );

    const result = JSON.parse(
      await platformConfig(
        { action: 'get_runtime_config', projectId: 'project-1' },
        createContext(),
      ),
    );

    expect(result).toMatchObject({
      success: false,
      error: 'Configuration request failed.',
    });
  });

  it('uses one named deadline and response-size bound for headers and body', async () => {
    const ctx = createContext();
    const bounded = vi.spyOn(ctx.httpClient, 'getBoundedJson');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          success: true,
          data: {
            projectId: 'project-1',
            _aiSafeProjection: AI_SAFE_METADATA,
          },
        }),
      ),
    );

    await platformConfig({ action: 'get_runtime_config', projectId: 'project-1' }, ctx);

    expect(bounded).toHaveBeenCalledWith('/api/runtime/projects/project-1/runtime-config/ai-safe', {
      timeoutMs: RUNTIME_CONFIG_TIMEOUT_MS,
      maxResponseBytes: RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
    });
  });

  it.each([
    ['malformed JSON', new HttpResponseDecodeError(200, 'OK'), 'Runtime returned malformed JSON'],
    [
      'oversized response',
      new ResponseSizeLimitError(RUNTIME_CONFIG_RESPONSE_MAX_BYTES),
      'exceeded the 2097152-byte limit',
    ],
    [
      'body timeout',
      new FetchError('Request timed out', 'TIMEOUT', 'https://runtime.example.invalid'),
      'Request timed out',
    ],
  ])('returns a generic failure for a %s', async (_label, failure, _expected) => {
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockRejectedValue(failure);

    const result = JSON.parse(
      await platformConfig({ action: 'get_runtime_config', projectId: 'project-1' }, ctx),
    );

    expect(result).toMatchObject({ success: false, error: 'Configuration request failed.' });
  });

  it('rejects unsafe project identifiers before issuing a request', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      platformConfig(
        { action: 'get_runtime_config', projectId: '../other-project' },
        createContext(),
      ),
    ).rejects.toThrow('Invalid projectId');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(['update_settings', 'update_llm_config'] as const)(
    'preserves the missing-settings validation for %s',
    async (action) => {
      const result = JSON.parse(
        await platformConfig({ action, projectId: 'project-1' }, createContext()),
      );

      expect(result).toMatchObject({
        success: false,
        error: expect.stringContaining('settings is required'),
      });
    },
  );

  it.each([
    ['get_settings', '/api/projects/project-1/settings'],
    ['get_llm_config', '/api/projects/project-1/llm-config'],
  ] as const)(
    'preserves a successful 49 KiB %s response without summarizing it',
    async (action, path) => {
      const payload = { value: 'x'.repeat(49 * 1_024) };
      const ctx = createContext();
      const bounded = vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
        status: 200,
        statusText: 'OK',
        body: payload,
      });

      const result = JSON.parse(await platformConfig({ action, projectId: 'project-1' }, ctx));

      expect(result).toEqual({ success: true, data: payload });
      expect(bounded).toHaveBeenCalledWith(path, {
        timeoutMs: RUNTIME_CONFIG_TIMEOUT_MS,
        maxResponseBytes: RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
      });
    },
  );

  it.each([
    ['get_settings', '/api/projects/project-1/settings'],
    ['get_llm_config', '/api/projects/project-1/llm-config'],
  ] as const)(
    'preserves more than 1,000 tiny object members for a successful %s response',
    async (action, path) => {
      const payload = Object.fromEntries(
        Array.from({ length: 1_001 }, (_, index) => [`setting_${index}`, index]),
      );
      const ctx = createContext();
      const bounded = vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
        status: 200,
        statusText: 'OK',
        body: payload,
      });

      const result = JSON.parse(await platformConfig({ action, projectId: 'project-1' }, ctx));

      expect(result).toEqual({ success: true, data: payload });
      expect(Object.keys(result.data)).toHaveLength(1_001);
      expect(bounded).toHaveBeenCalledWith(path, {
        timeoutMs: RUNTIME_CONFIG_TIMEOUT_MS,
        maxResponseBytes: RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
      });
    },
  );

  it.each(['get_settings', 'get_llm_config'] as const)(
    'preserves more than 1,000 tiny array items for a successful %s response',
    async (action) => {
      const payload = Array.from({ length: 1_001 }, (_, index) => index);
      const ctx = createContext();
      vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
        status: 200,
        statusText: 'OK',
        body: payload,
      });

      const result = JSON.parse(await platformConfig({ action, projectId: 'project-1' }, ctx));

      expect(result).toEqual({ success: true, data: payload });
      expect(result.data).toHaveLength(1_001);
    },
  );

  it.each(['get_settings', 'get_llm_config'] as const)(
    'preserves a successful %s response nested beyond the former depth limit',
    async (action) => {
      let payload: Record<string, unknown> = { leaf: 'safe-value' };
      for (let depth = 0; depth < 17; depth += 1) payload = { child: payload };
      const ctx = createContext();
      vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
        status: 200,
        statusText: 'OK',
        body: payload,
      });

      const result = JSON.parse(await platformConfig({ action, projectId: 'project-1' }, ctx));

      expect(result).toEqual({ success: true, data: payload });
    },
  );

  it('retains credential redaction inside a deeply nested legacy response', async () => {
    let payload: Record<string, unknown> = {
      api_key: 'must-not-escape',
      note: 'Bearer SYNTHETIC123',
    };
    for (let depth = 0; depth < 100; depth += 1) payload = { child: payload };
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
      status: 200,
      statusText: 'OK',
      body: payload,
    });

    const serialized = await platformConfig(
      { action: 'get_settings', projectId: 'project-1' },
      ctx,
    );

    expect(serialized).not.toContain('must-not-escape');
    expect(serialized).not.toContain('SYNTHETIC123');
    expect(serialized).toContain('[REDACTED]');
  });

  it('keeps legacy read sanitization linear for a successful response near the byte ceiling', async () => {
    // 1,000,000 zeros serialize to 2,000,001 bytes before the success envelope: below 2 MiB while
    // exercising the maximum-cardinality shape that is meaningful under the transport limit.
    const payload = new Array<number>(1_000_000).fill(0);
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
      status: 200,
      statusText: 'OK',
      body: payload,
    });
    const startedAt = performance.now();

    const serialized = await platformConfig(
      { action: 'get_settings', projectId: 'project-1' },
      ctx,
    );
    const elapsedMs = performance.now() - startedAt;
    const result = JSON.parse(serialized);

    expect(new TextEncoder().encode(JSON.stringify(payload)).byteLength).toBeLessThan(
      RUNTIME_CONFIG_RESPONSE_MAX_BYTES,
    );
    expect(result.success).toBe(true);
    expect(result.data).toHaveLength(payload.length);
    expect(elapsedMs).toBeLessThan(5_000);
  });

  it('bounds wide-response serializer RSS in an isolated process', () => {
    const script = `
      const { platformConfig } = await import('./src/tools/platform-config.ts');
      const body = new Array(1_000_000).fill(0);
      const before = process.resourceUsage().maxRSS;
      const ctx = {
        httpClient: {
          getBoundedJson: async () => ({ status: 200, statusText: 'OK', body }),
        },
      };
      const serialized = await platformConfig(
        { action: 'get_settings', projectId: 'project-1' },
        ctx,
      );
      process.stdout.write(JSON.stringify({
        outputLength: serialized.length,
        rssGrowthKiB: Math.max(0, process.resourceUsage().maxRSS - before),
      }));
    `;
    const child = spawnSync(
      process.execPath,
      ['--import', 'tsx', '--input-type=module', '--eval', script],
      { cwd: process.cwd(), encoding: 'utf8', maxBuffer: CHILD_PROCESS_OUTPUT_MAX_BYTES },
    );

    expect(child.status, child.stderr).toBe(0);
    const measurement = JSON.parse(child.stdout) as {
      outputLength: number;
      rssGrowthKiB: number;
    };
    expect(measurement.outputLength).toBe(2_000_025);
    // Node reports maxRSS in KiB. The prior per-token rope added more than 100 MiB on this case.
    expect(measurement.rssGrowthKiB).toBeLessThan(MAX_WIDE_SERIALIZER_RSS_GROWTH_KIB);
  });

  it('sanitizes a substantially deep response iteratively within the transport byte budget', async () => {
    let payload: Record<string, unknown> = {
      leaf: 'safe-value',
      omittedUndefined: undefined,
      omittedFunction: () => 'not serialized',
      omittedSymbol: Symbol('not serialized'),
      arrayJsonSemantics: [undefined, () => 'not serialized', Symbol('not serialized')],
    };
    for (let depth = 0; depth < 150_000; depth += 1) payload = { child: payload };
    // Each `{\"child\":...}` wrapper contributes ten ASCII bytes to the wire representation.
    const minimumPayloadBytes = 150_000 * 10 + '{"leaf":"safe-value"}'.length;
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
      status: 200,
      statusText: 'OK',
      body: payload,
    });
    const startedAt = performance.now();

    const serialized = await platformConfig(
      { action: 'get_llm_config', projectId: 'project-1' },
      ctx,
    );
    const elapsedMs = performance.now() - startedAt;

    expect(minimumPayloadBytes).toBeGreaterThan(1_000_000);
    expect(minimumPayloadBytes).toBeLessThan(RUNTIME_CONFIG_RESPONSE_MAX_BYTES);
    expect(serialized.startsWith('{"success":true,"data":')).toBe(true);
    expect(serialized).toContain('"leaf":"safe-value"');
    expect(serialized).toContain('"arrayJsonSemantics":[null,null,null]');
    expect(serialized).not.toContain('omittedUndefined');
    expect(serialized).not.toContain('omittedFunction');
    expect(serialized).not.toContain('omittedSymbol');
    expect(elapsedMs).toBeLessThan(5_000);
  });

  it('preserves Object.keys order and exact key text in the deep fallback cursor', async () => {
    let payload: Record<string, unknown> = {};
    payload['2'] = 'two';
    payload['1'] = 'one';
    payload[''] = 'empty';
    payload['a:b'] = 'colon';
    payload['emoji-💡'] = 'unicode';
    payload.omittedUndefined = undefined;
    payload.omittedFunction = () => 'not serialized';
    payload.omittedSymbol = Symbol('not serialized');
    payload.arrayJsonSemantics = [undefined, () => 'not serialized', Symbol('not serialized')];
    for (let depth = 0; depth < 10_000; depth += 1) payload = { child: payload };
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
      status: 200,
      statusText: 'OK',
      body: payload,
    });

    const serialized = await platformConfig(
      { action: 'get_llm_config', projectId: 'project-1' },
      ctx,
    );

    expect(serialized).toContain(
      '"1":"one","2":"two","":"empty","a:b":"colon","emoji-💡":"unicode",' +
        '"arrayJsonSemantics":[null,null,null]',
    );
    expect(serialized).not.toContain('omittedUndefined');
    expect(serialized).not.toContain('omittedFunction');
    expect(serialized).not.toContain('omittedSymbol');
  });

  it.each([
    { shape: 'one-key', depth: 150_000, outputLength: 1_500_083 },
    { shape: 'two-key-child-first', depth: 116_500, outputLength: 2_097_083 },
  ])(
    'bounds $shape deep-response sanitizer and serializer RSS',
    ({ shape, depth, outputLength }) => {
      const script = `
      const { platformConfig } = await import('./src/tools/platform-config.ts');
      const shape = ${JSON.stringify(shape)};
      let body = {
        leaf: 'safe-value',
        omittedUndefined: undefined,
        omittedFunction: () => 'not serialized',
        omittedSymbol: Symbol('not serialized'),
        arrayJsonSemantics: [undefined, () => 'not serialized', Symbol('not serialized')],
      };
      for (let level = 0; level < ${depth}; level += 1) {
        body = shape === 'one-key' ? { child: body } : { child: body, pad: 0 };
      }
      globalThis.gc();
      const before = process.resourceUsage().maxRSS;
      const serialized = await platformConfig(
        { action: 'get_llm_config', projectId: 'project-1' },
        { httpClient: { getBoundedJson: async () => ({ status: 200, statusText: 'OK', body }) } },
      );
      process.stdout.write(JSON.stringify({
        outputLength: serialized.length,
        rssGrowthKiB: Math.max(0, process.resourceUsage().maxRSS - before),
      }));
    `;
      const child = spawnSync(
        process.execPath,
        ['--expose-gc', '--import', 'tsx', '--input-type=module', '--eval', script],
        { cwd: process.cwd(), encoding: 'utf8', maxBuffer: CHILD_PROCESS_OUTPUT_MAX_BYTES },
      );

      expect(child.status, child.stderr).toBe(0);
      const measurement = JSON.parse(child.stdout) as {
        outputLength: number;
        rssGrowthKiB: number;
      };
      expect(measurement.outputLength).toBe(outputLength);
      // Retained per-depth key arrays previously grew isolated maxRSS by 141 MiB for the one-key
      // case and could exceed this gate for a near-ceiling child-first multi-key response.
      expect(measurement.rssGrowthKiB).toBeLessThan(MAX_DEEP_SERIALIZER_RSS_GROWTH_KIB);
    },
  );

  it('handles an unexpected in-memory response cycle without recursive failure', async () => {
    const payload: Record<string, unknown> = { value: 'safe' };
    payload.self = payload;
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
      status: 200,
      statusText: 'OK',
      body: payload,
    });

    const result = JSON.parse(
      await platformConfig({ action: 'get_settings', projectId: 'project-1' }, ctx),
    );

    expect(result).toEqual({ success: true, data: { value: 'safe', self: '[CIRCULAR]' } });
  });

  it.each([
    ['get_settings', '/api/projects/project-1/settings'],
    ['get_llm_config', '/api/projects/project-1/llm-config'],
  ] as const)(
    'preserves the sanitized historical error detail for a non-2xx %s response',
    async (action, _path) => {
      const ctx = createContext();
      vi.spyOn(ctx.httpClient, 'getBoundedJson').mockResolvedValue({
        status: 503,
        statusText: 'Service Unavailable',
        body: { error: 'provider secret must not escape' },
      });

      const result = JSON.parse(await platformConfig({ action, projectId: 'project-1' }, ctx));

      expect(result).toEqual({
        success: false,
        error: `Configuration request failed: GET ${_path} failed: 503 Service Unavailable`,
        hint: 'Ensure the runtime is running and you are connected (platform_connect).',
      });
      expect(JSON.stringify(result)).not.toContain('provider secret');
    },
  );

  it('fails safely when rendering an old-action error itself throws', async () => {
    const ctx = createContext();
    vi.spyOn(ctx.httpClient, 'getBoundedJson').mockRejectedValue({
      toString() {
        throw new Error('authorization=must-not-escape');
      },
    });

    const result = JSON.parse(
      await platformConfig({ action: 'get_settings', projectId: 'project-1' }, ctx),
    );

    expect(result).toEqual({
      success: false,
      error: 'Configuration request failed: Unknown error',
      hint: 'Ensure the runtime is running and you are connected (platform_connect).',
    });
    expect(JSON.stringify(result)).not.toContain('must-not-escape');
  });

  it.each([
    [
      'PEM',
      `${'x'.repeat(16_350)}-----BEGIN PRIVATE KEY-----\nSENSITIVE_BODY\n-----END PRIVATE KEY-----`,
    ],
    ['JWT', `${'x'.repeat(16_350)}eyJ${'a'.repeat(40)}.${'b'.repeat(40)}.${'c'.repeat(40)}`],
  ])(
    'omits an oversized old-action error before sanitizing a boundary-crossing %s',
    async (_label, message) => {
      const ctx = createContext();
      vi.spyOn(ctx.httpClient, 'getBoundedJson').mockRejectedValue(new Error(message));

      const result = JSON.parse(
        await platformConfig({ action: 'get_llm_config', projectId: 'project-1' }, ctx),
      );

      expect(result).toEqual({
        success: false,
        error:
          'Configuration request failed: Error detail omitted because it exceeded the safe limit',
        hint: 'Ensure the runtime is running and you are connected (platform_connect).',
      });
      expect(JSON.stringify(result)).not.toContain('PRIVATE KEY');
      expect(JSON.stringify(result)).not.toContain('eyJ');
    },
  );

  it('preserves the defensive unknown-action failure', async () => {
    const result = JSON.parse(
      await platformConfig(
        { action: 'not_registered', projectId: 'project-1' } as never,
        createContext(),
      ),
    );

    expect(result).toEqual({ success: false, error: 'Unknown action: not_registered' });
  });
});
