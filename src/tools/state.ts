/**
 * debug_get_current_state Tool
 *
 * Get the current session state including context, flow state, etc.
 */

import { z } from 'zod';
import type { DebugContext } from './index.js';
import type { AgentState } from '../types.js';

export const getCurrentStateSchema = z.object({
  sessionId: z.string().optional().describe('Session ID (uses active session if not specified)'),
});

export type GetCurrentStateArgs = z.infer<typeof getCurrentStateSchema>;

export async function getCurrentState(
  args: GetCurrentStateArgs,
  ctx: DebugContext,
): Promise<string> {
  // Use active session if not specified
  const sessionId = args.sessionId || ctx.sessionStore.getActiveSessionId();

  if (!sessionId) {
    return JSON.stringify({
      success: false,
      error: 'No session specified and no active session. Load an agent first.',
    });
  }

  const session = ctx.sessionStore.getSession(sessionId);
  if (!session) {
    return JSON.stringify({
      success: false,
      error: `Session not found: ${sessionId}`,
    });
  }

  // If we have state in the session store, return it (bounded)
  if (session.state) {
    const bounded = boundStateForResponse(session.state);
    return JSON.stringify({
      success: true,
      sessionId,
      agentId: session.agentId,
      state: bounded.state,
      lastActivityAt: session.lastActivityAt,
      ...(bounded.truncated ? { stateTruncated: true, stateByteLimit: bounded.byteLimit } : {}),
    });
  }

  const wsClient = ctx.sessionConnections?.get(sessionId) ?? ctx.wsClient;
  if (ctx.sessionConnections && wsClient === ctx.wsClient) {
    return JSON.stringify({
      success: false,
      error: `Dedicated connection unavailable for session: ${sessionId}. Load the agent again.`,
    });
  }

  // If connected, request fresh state from server
  if (wsClient.isConnected()) {
    return new Promise((resolve) => {
      let resolved = false;
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          wsClient.onStateUpdate = originalOnStateUpdate;
          resolve(
            JSON.stringify({
              success: false,
              error: 'Timeout waiting for state update',
            }),
          );
        }
      }, 5000);

      // Set up one-time handler
      const originalOnStateUpdate = wsClient.onStateUpdate;

      wsClient.onStateUpdate = (msgSessionId, state) => {
        if (msgSessionId === sessionId) {
          // Restore original handler
          wsClient.onStateUpdate = originalOnStateUpdate;

          // Update store
          ctx.sessionStore.updateState(sessionId, state);

          clearTimeout(timeout);
          if (!resolved) {
            resolved = true;
            const bounded = boundStateForResponse(state);
            resolve(
              JSON.stringify({
                success: true,
                sessionId,
                agentId: session.agentId,
                state: bounded.state,
                source: 'fresh',
                ...(bounded.truncated
                  ? { stateTruncated: true, stateByteLimit: bounded.byteLimit }
                  : {}),
              }),
            );
          }
        }

        // Call original handler
        originalOnStateUpdate?.(msgSessionId, state);
      };

      // Request state
      wsClient.getState(sessionId);
    });
  }

  // No state available
  return JSON.stringify({
    success: true,
    sessionId,
    agentId: session.agentId,
    state: null,
    message: 'No state available yet. Send a message to the agent first.',
  });
}

// =============================================================================
// Response bounding
// =============================================================================

// A normal hybrid-kernel session's agent state (large context maps, tool
// results, decision logs) can serialize to 700+ KB and exceed the MCP tool's
// own output limit. Bound the payload: under the ceiling it is returned
// verbatim; over it, each oversized top-level field is replaced with a typed
// truncation marker so callers still see the shape and know the result is
// partial rather than silently receiving a clipped or rejected response.
const MAX_STATE_RESPONSE_BYTES = 96 * 1024;
const MAX_STATE_FIELD_BYTES = 4 * 1024;
const MAX_STATE_MARKER_KEYS = 256;

interface BoundedState {
  state: unknown;
  truncated: boolean;
  byteLimit?: number;
}

function boundStateForResponse(state: AgentState): BoundedState {
  if (jsonLength(state) <= MAX_STATE_RESPONSE_BYTES) {
    return { state, truncated: false };
  }

  const bounded: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(state as unknown as Record<string, unknown>)) {
    bounded[key] = boundStateField(value);
  }
  return {
    state: compactStateToResponseLimit(bounded),
    truncated: true,
    byteLimit: MAX_STATE_RESPONSE_BYTES,
  };
}

function boundStateField(value: unknown): unknown {
  const size = jsonLength(value);
  if (size <= MAX_STATE_FIELD_BYTES) {
    return value;
  }

  if (Array.isArray(value)) {
    const kept: unknown[] = [];
    let used = 0;
    for (const entry of value) {
      const entryBytes = jsonLength(entry);
      if (used + entryBytes > MAX_STATE_FIELD_BYTES) break;
      kept.push(entry);
      used += entryBytes;
    }
    return [
      ...kept,
      {
        _truncated: true,
        _totalEntries: value.length,
        _omittedEntries: value.length - kept.length,
        _bytes: size,
      },
    ];
  }

  const marker: Record<string, unknown> = {
    _truncated: true,
    _bytes: size,
    _preview: jsonString(value).slice(0, MAX_STATE_FIELD_BYTES),
  };
  if (value && typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>);
    marker._keys = keys.slice(0, MAX_STATE_MARKER_KEYS);
    if (keys.length > MAX_STATE_MARKER_KEYS) {
      marker._keyCount = keys.length;
      marker._keysTruncated = true;
    }
  }
  return marker;
}

function compactStateToResponseLimit(state: Record<string, unknown>): Record<string, unknown> {
  if (jsonLength(state) <= MAX_STATE_RESPONSE_BYTES) return state;

  const compact: Record<string, unknown> = {
    __truncated: true,
    __byteLimit: MAX_STATE_RESPONSE_BYTES,
    __omittedFields: 0,
  };
  for (const [key, value] of Object.entries(state)) {
    const candidate = { ...compact, [key]: value };
    if (jsonLength(candidate) <= MAX_STATE_RESPONSE_BYTES) {
      compact[key] = value;
    } else {
      compact.__omittedFields = Number(compact.__omittedFields) + 1;
    }
  }
  return compact;
}

function jsonString(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

function jsonLength(value: unknown): number {
  return Buffer.byteLength(jsonString(value), 'utf8');
}
