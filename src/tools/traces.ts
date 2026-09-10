/**
 * Trace Tools
 *
 * debug_traces - Get and search trace events with optional filters
 */

import { z } from 'zod';
import type { DebugContext } from './index.js';
import type { TraceEventType, TraceEventWithId } from '../types.js';
import type { TraceRetention } from '../store/trace-store.js';

// =============================================================================
// debug_traces — unified get + search
// =============================================================================

export const tracesSchema = z.object({
  text: z.string().optional().describe('Text to search for in event data'),
  // Accept any string to be forward-compatible with new runtime event types
  types: z.array(z.string()).optional().describe('Filter by event types'),
  agentName: z.string().optional().describe('Filter by agent name'),
  hasError: z.boolean().optional().describe('Filter for error events only'),
  sessionId: z.string().optional().describe('Filter by or search within a specific session'),
  limit: z
    .number()
    .optional()
    .default(50)
    .describe(
      'Maximum events to return. Clamped to 1..1000 (default 50); non-positive or fractional values are normalized, never returning the whole buffer.',
    ),
  offset: z
    .number()
    .optional()
    .default(0)
    .describe(
      'Events to skip from the start of the matched set, newest first (default 0). Negative/fractional values are normalized to a non-negative integer.',
    ),
});

const MAX_TRACE_LIMIT = 1000;

function normalizeLimit(raw: number | undefined): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return 50;
  return Math.min(Math.max(Math.trunc(raw), 1), MAX_TRACE_LIMIT);
}

function normalizeOffset(raw: number | undefined): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) return 0;
  return Math.trunc(raw);
}

// Input type: limit/offset carry schema defaults, so they are optional to
// callers. The handler normalizes both (including undefined) before use.
export type TracesArgs = z.input<typeof tracesSchema>;

export async function traces(args: TracesArgs, ctx: DebugContext): Promise<string> {
  try {
    const { text, types, agentName, hasError, sessionId } = args;
    const limit = normalizeLimit(args.limit);
    const offset = normalizeOffset(args.offset);

    // Use active session if not specified
    const effectiveSessionId = sessionId || ctx.sessionStore.getActiveSessionId();

    const hasSearchFilters =
      text !== undefined || agentName !== undefined || hasError !== undefined;

    if (hasSearchFilters) {
      // Search mode — use traceStore.search over the full matched set, then page.
      const events = ctx.traceStore.search(
        {
          text,
          types: types as TraceEventType[] | undefined,
          agentName,
          hasError,
        },
        effectiveSessionId || undefined,
      );

      const total = events.length;
      const page = events.slice(offset, offset + limit);
      const formattedEvents = page.map(formatTraceEvent);
      const retention = resolveTraceRetention(
        ctx.traceStore,
        effectiveSessionId || undefined,
        total,
      );
      const pagingTruncated = offset + formattedEvents.length < total;

      return JSON.stringify({
        success: true,
        count: formattedEvents.length,
        total,
        // Retained for backward compatibility; equals `total`.
        totalMatches: total,
        offset,
        limit,
        is_truncated: pagingTruncated || retention.isTruncated,
        retention: formatRetention(retention),
        sessionId: effectiveSessionId,
        filters: { text, types, agentName, hasError },
        events: formattedEvents,
      });
    }

    // Simple get mode — read the full matched set from the bounded live buffer,
    // then page. Passing no limit to the store yields the complete filtered set
    // so `total`/`offset`/`is_truncated` describe the buffer honestly instead of
    // returning the whole buffer whenever limit is non-positive.
    const events = effectiveSessionId
      ? ctx.traceStore.getBySession(
          effectiveSessionId,
          undefined,
          types as TraceEventType[] | undefined,
        )
      : ctx.traceStore.getRecent(undefined, types as TraceEventType[] | undefined);

    const total = events.length;
    const page = events.slice(offset, offset + limit);
    const formattedEvents = page.map(formatTraceEvent);
    const retention = resolveTraceRetention(ctx.traceStore, effectiveSessionId || undefined, total);
    const pagingTruncated = offset + formattedEvents.length < total;

    return JSON.stringify({
      success: true,
      count: formattedEvents.length,
      total,
      offset,
      limit,
      is_truncated: pagingTruncated || retention.isTruncated,
      retention: formatRetention(retention),
      sessionId: effectiveSessionId,
      events: formattedEvents,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return JSON.stringify({
      success: false,
      error: `debug_traces failed: ${message}`,
    });
  }
}

// =============================================================================
// Helpers
// =============================================================================

function resolveTraceRetention(
  traceStore: { getRetention?: (sessionId?: string) => TraceRetention },
  sessionId: string | undefined,
  fallbackRetainedCount: number,
): TraceRetention {
  // Keep compatibility with embedders that provide the pre-retention TraceStore
  // shape. Such stores cannot prove eviction, so the fallback is deliberately
  // non-truncated and scoped to the set they returned.
  return (
    traceStore.getRetention?.(sessionId) ?? {
      maxSize: fallbackRetainedCount,
      retainedCount: fallbackRetainedCount,
      evictedCount: 0,
      isTruncated: false,
    }
  );
}

function formatRetention(retention: {
  maxSize: number;
  retainedCount: number;
  evictedCount: number;
  isTruncated: boolean;
}): Record<string, unknown> {
  return {
    max_size: retention.maxSize,
    retained_count: retention.retainedCount,
    evicted_count: retention.evictedCount,
    is_truncated: retention.isTruncated,
  };
}

function formatTraceEvent(e: TraceEventWithId): Record<string, unknown> {
  return {
    id: e.id,
    type: e.type,
    timestamp: e.timestamp,
    agentName: e.agentName,
    durationMs: e.durationMs,
    spanId: e.spanId,
    data: summarizeData(e.data),
  };
}

/**
 * Summarize event data, truncating long strings
 */
function summarizeData(data: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string' && value.length > 200) {
      result[key] = value.substring(0, 200) + '...';
    } else if (Array.isArray(value) && value.length > 10) {
      result[key] = [...value.slice(0, 10), `... (${value.length} total)`];
    } else if (typeof value === 'object' && value !== null) {
      const str = JSON.stringify(value);
      if (str.length > 200) {
        // Don't try to parse truncated JSON - just indicate it was truncated
        result[key] = { _truncated: true, _preview: str.substring(0, 200) + '...' };
      } else {
        result[key] = value;
      }
    } else {
      result[key] = value;
    }
  }

  return result;
}
