/**
 * Turn outcome derived from the trace events a turn produced.
 *
 * `debug_send_message` used to answer `{"success": true, …}` whenever a
 * response frame arrived, even when the runtime never produced an answer. A
 * project without a resolvable model, for example, replies
 * "I apologize, but I encountered an error." while the session's traces carry
 * `execution.failed` — so a caller (especially an agent) reads success and
 * concludes the project works. The MCP contract has to reflect what happened,
 * not merely that bytes came back.
 *
 * This module is pure: it takes the events already captured in the client trace
 * store and reports whether the turn produced an answer.
 */

import type { TraceEventWithId } from '../types.js';

/** One runtime-reported failure attributed to a turn. */
export interface TurnFailure {
  /** Trace event type, e.g. `execution.failed` or `error`. */
  type: string;
  /** Runtime error code when the event carries one. */
  code?: string;
  message: string;
}

export interface TurnOutcome {
  status: 'answered' | 'failed';
  failures: TurnFailure[];
}

/**
 * Event types that mean the turn itself did not complete. Socket-level problems
 * are already reported through `wsClient.onError`; these are runtime failures
 * that still end with a response frame.
 */
const TURN_FAILURE_TYPES: readonly string[] = ['execution.failed', 'error', 'agent_error'];

/**
 * Upper bound on reported failures. One broken turn can emit many error events;
 * the first few identify the cause and the rest are noise in an LLM's context.
 */
const MAX_REPORTED_FAILURES = 5;

function readString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Pull `{ code, message }` out of the several shapes runtime error events use:
 * `data.error.{code,message}`, `data.message`, `data.errorType`.
 */
function readFailure(event: TraceEventWithId): TurnFailure | null {
  const data = asRecord(event.data) ?? {};
  const nested = asRecord(data.error);

  const code = readString(nested?.code) ?? readString(data.code) ?? readString(data.errorType);
  const message =
    readString(nested?.message) ?? readString(data.message) ?? readString(data.reason);

  if (!code && !message) {
    return null;
  }

  return {
    type: event.type,
    ...(code ? { code } : {}),
    message: message ?? (code as string),
  };
}

function isSameFailure(a: TurnFailure, b: TurnFailure): boolean {
  return a.type === b.type && a.code === b.code && a.message === b.message;
}

/**
 * Classify a turn from its session's trace events.
 *
 * `sinceMs` bounds attribution to the current turn: an error from an earlier
 * turn in the same session must not mark this one failed. Events without a
 * usable timestamp are kept, because dropping them would silently under-report.
 */
export function summarizeTurnOutcome(
  events: readonly TraceEventWithId[],
  options: { sinceMs?: number } = {},
): TurnOutcome {
  const { sinceMs } = options;
  const failures: TurnFailure[] = [];

  for (const event of events) {
    if (failures.length >= MAX_REPORTED_FAILURES) {
      break;
    }
    if (!TURN_FAILURE_TYPES.includes(event.type)) {
      continue;
    }
    if (sinceMs !== undefined) {
      const at = event.timestamp instanceof Date ? event.timestamp.getTime() : Number.NaN;
      if (Number.isFinite(at) && at < sinceMs) {
        continue;
      }
    }
    const failure = readFailure(event);
    if (!failure) {
      continue;
    }
    if (failures.some((existing) => isSameFailure(existing, failure))) {
      continue;
    }
    failures.push(failure);
  }

  return { status: failures.length > 0 ? 'failed' : 'answered', failures };
}
