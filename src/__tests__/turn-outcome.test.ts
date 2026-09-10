import { describe, expect, it } from 'vitest';
import { summarizeTurnOutcome } from '../tools/turn-outcome.js';
import type { TraceEventWithId } from '../types.js';

const SESSION_ID = 'session-1';

function event(type: string, data: Record<string, unknown>, atMs = 1_000): TraceEventWithId {
  return {
    id: `${type}-${atMs}`,
    sessionId: SESSION_ID,
    type: type as TraceEventWithId['type'],
    timestamp: new Date(atMs),
    data,
  };
}

describe('summarizeTurnOutcome', () => {
  it('reports a failed turn from execution.failed', () => {
    // The live case: the runtime answered "I apologize, but I encountered an
    // error." and the tool still said success:true.
    const outcome = summarizeTurnOutcome([
      event('agent_enter', { agentName: 'FX' }),
      event('execution.failed', {
        error: {
          code: 'EXECUTION_FAILED',
          message: 'A project-scoped model selection is required in enforced mode',
        },
      }),
    ]);

    expect(outcome.status).toBe('failed');
    expect(outcome.failures).toEqual([
      {
        type: 'execution.failed',
        code: 'EXECUTION_FAILED',
        message: 'A project-scoped model selection is required in enforced mode',
      },
    ]);
  });

  it('reports an answered turn when nothing failed', () => {
    expect(
      summarizeTurnOutcome([
        event('turn_start', {}),
        event('llm_call', { model: 'x' }),
        event('turn_end', {}),
      ]),
    ).toEqual({ status: 'answered', failures: [] });
  });

  it('reads the flat error shapes runtime also emits', () => {
    const outcome = summarizeTurnOutcome([
      event('error', { errorType: 'execution_error', message: 'model unavailable' }),
    ]);

    expect(outcome.failures).toEqual([
      { type: 'error', code: 'execution_error', message: 'model unavailable' },
    ]);
  });

  it('ignores failures from an earlier turn in the same session', () => {
    // Attribution matters: a session is long-lived, and a previous turn's error
    // must not condemn the current one.
    const outcome = summarizeTurnOutcome(
      [event('execution.failed', { message: 'old failure' }, 1_000), event('turn_end', {}, 5_000)],
      { sinceMs: 4_000 },
    );

    expect(outcome).toEqual({ status: 'answered', failures: [] });
  });

  it('keeps a failure emitted after the message was sent', () => {
    const outcome = summarizeTurnOutcome(
      [event('execution.failed', { message: 'new failure' }, 6_000)],
      { sinceMs: 4_000 },
    );

    expect(outcome.status).toBe('failed');
  });

  it('deduplicates repeated identical failures', () => {
    const repeated = event('error', { code: 'E', message: 'same' }, 7_000);
    const outcome = summarizeTurnOutcome([repeated, { ...repeated, id: 'other' }]);

    expect(outcome.failures).toHaveLength(1);
  });

  it('caps how many failures it reports', () => {
    const many = Array.from({ length: 12 }, (_, index) =>
      event('error', { code: `E${index}`, message: `failure ${index}` }, 8_000 + index),
    );

    expect(summarizeTurnOutcome(many).failures).toHaveLength(5);
  });

  it('ignores error events that carry no usable detail', () => {
    expect(summarizeTurnOutcome([event('error', {})])).toEqual({
      status: 'answered',
      failures: [],
    });
  });

  it('keeps events whose timestamp is unusable rather than under-reporting', () => {
    const broken = {
      ...event('execution.failed', { message: 'timestamp missing' }),
      timestamp: undefined,
    } as unknown as TraceEventWithId;

    expect(summarizeTurnOutcome([broken], { sinceMs: 1_000 }).status).toBe('failed');
  });
});
