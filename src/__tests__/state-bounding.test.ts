import { describe, test, expect } from 'vitest';
import { getCurrentState } from '../tools/state.js';
import { SessionStore } from '../store/session-store.js';
import { TraceStore } from '../store/trace-store.js';
import type { DebugContext } from '../tools/index.js';
import type { AgentState, DecisionLogEntry } from '../types.js';

function baseState(overrides: Partial<AgentState> = {}): AgentState {
  return {
    context: {},
    conversationPhase: 'active',
    gatherProgress: {},
    constraintResults: {},
    lastToolResults: {},
    memory: { session: {}, persistentCache: {}, pendingRemembers: [] },
    ...overrides,
  };
}

function ctxWithState(state: AgentState): DebugContext {
  const sessionStore = new SessionStore();
  sessionStore.createSession('s1', 'agent-1');
  sessionStore.updateState('s1', state);
  return {
    sessionStore,
    traceStore: new TraceStore(),
    wsClient: { isConnected: () => false },
  } as unknown as DebugContext;
}

describe('debug_get_current_state bounding (ABLP-4531)', () => {
  test('small state is returned verbatim without a truncation marker', async () => {
    const ctx = ctxWithState(baseState({ context: { foo: 'bar' } }));
    const res = JSON.parse(await getCurrentState({ sessionId: 's1' }, ctx));

    expect(res.success).toBe(true);
    expect(res.stateTruncated).toBeUndefined();
    expect(res.state.context).toEqual({ foo: 'bar' });
  });

  test('an oversized field is replaced with a typed marker and the payload stays bounded', async () => {
    const blob = 'x'.repeat(200 * 1024); // 200 KB, well over the response ceiling
    const ctx = ctxWithState(baseState({ context: { blob } }));

    const raw = await getCurrentState({ sessionId: 's1' }, ctx);
    const res = JSON.parse(raw);

    expect(res.success).toBe(true);
    expect(res.stateTruncated).toBe(true);
    expect(res.stateByteLimit).toBeGreaterThan(0);
    // The whole response is far smaller than the original 200 KB blob.
    expect(raw.length).toBeLessThan(200 * 1024);
    // The oversized field carries a truncation marker, not the full blob.
    expect(res.state.context._truncated).toBe(true);
    expect(res.state.context._bytes).toBeGreaterThan(200 * 1024 - 1);
    expect(res.state.context._keys).toContain('blob');
  });

  test('an oversized array keeps a bounded prefix and reports the omitted entries', async () => {
    const decisionLog: DecisionLogEntry[] = Array.from({ length: 5000 }, (_, i) => ({
      timestamp: i,
      type: 'constraint_check',
      outcome: 'x'.repeat(200),
      matched: true,
      turn: i,
    })) as unknown as DecisionLogEntry[];
    const ctx = ctxWithState(baseState({ decisionLog }));

    const res = JSON.parse(await getCurrentState({ sessionId: 's1' }, ctx));

    expect(res.stateTruncated).toBe(true);
    const marker = res.state.decisionLog[res.state.decisionLog.length - 1];
    expect(marker._truncated).toBe(true);
    expect(marker._totalEntries).toBe(5000);
    expect(marker._omittedEntries).toBeGreaterThan(0);
    // A bounded prefix of real entries survives ahead of the marker.
    expect(res.state.decisionLog.length).toBeGreaterThan(1);
    expect(res.state.decisionLog.length).toBeLessThan(5000);
  });

  test('does not keep an oversized first array entry or exceed the state byte ceiling', async () => {
    const decisionLog: DecisionLogEntry[] = [
      {
        timestamp: 0,
        type: 'constraint_check',
        outcome: 'x'.repeat(100 * 1024),
        matched: true,
        turn: 0,
      },
      {
        timestamp: 1,
        type: 'constraint_check',
        outcome: 'kept',
        matched: true,
        turn: 1,
      },
    ] as unknown as DecisionLogEntry[];
    const ctx = ctxWithState(baseState({ decisionLog }));

    const raw = await getCurrentState({ sessionId: 's1' }, ctx);
    const res = JSON.parse(raw);

    expect(res.stateTruncated).toBe(true);
    expect(raw.length).toBeLessThan(96 * 1024 + 1024);
    expect(res.state.decisionLog[0]?._truncated).toBe(true);
    expect(res.state.decisionLog[0]?.outcome).toBeUndefined();
  });
});
