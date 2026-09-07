import { describe, expect, test } from 'vitest';
import { analyzeOrchestrationFailures } from '../tools/analysis-rules.js';
import type { TraceEventWithId } from '../types.js';

const BASE_TIME = Date.parse('2024-01-01T10:00:00.000Z');

function trace(
  id: string,
  type: TraceEventWithId['type'],
  data: Record<string, unknown> = {},
  offsetMs = 0,
  turnId?: string,
): TraceEventWithId {
  return {
    id,
    sessionId: 'analysis-rules-session',
    type,
    data,
    timestamp: new Date(BASE_TIME + offsetMs),
    ...(turnId ? { turnId } : {}),
  };
}

describe('orchestration analysis rules', () => {
  test('detects an ordinary duplicate final without requiring correlation IDs', () => {
    const result = analyzeOrchestrationFailures([
      trace('first', 'agent_response', { content: 'Same   answer', agentName: 'Agent' }, 0),
      trace('intermediate', 'engine_decision', { decision: 'finish' }, 1),
      trace('duplicate', 'agent_response', { response: 'Same answer', agentName: 'Agent' }, 2),
    ]);

    expect(result.issues).toContainEqual(
      expect.objectContaining({ title: 'Duplicate final output', eventId: 'duplicate' }),
    );
  });

  test('does not combine non-final, empty, different-text, or different-turn responses', () => {
    const result = analyzeOrchestrationFailures([
      trace('internal', 'agent_response', { content: 'same', isFinalForTurn: false }, 0, 'turn-1'),
      trace('empty', 'agent_response', { content: '   ' }, 1, 'turn-1'),
      trace('agent-a', 'agent_response', { content: 'same', agentName: 'A' }, 2, 'turn-1'),
      trace('agent-b', 'agent_response', { content: 'different', agentName: 'B' }, 3, 'turn-1'),
      trace('next-turn', 'agent_response', { content: 'same', agentName: 'A' }, 4, 'turn-2'),
      trace('outside-window', 'agent_response', { content: 'no-id' }, 20_000),
      trace('outside-window-copy', 'agent_response', { content: 'no-id' }, 30_000),
    ]);

    expect(result.issues.map((issue) => issue.title)).not.toContain('Duplicate final output');
  });

  test('uses top-level execution IDs when turn IDs are unavailable', () => {
    const first = trace('first', 'agent_response', { content: 'same' }, 0);
    first.executionId = 'execution-1';
    const otherExecution = trace('other', 'agent_response', { content: 'same' }, 1);
    otherExecution.executionId = 'execution-2';
    const duplicate = trace('duplicate', 'agent_response', { content: 'same' }, 2);
    duplicate.executionId = 'execution-1';

    const result = analyzeOrchestrationFailures([first, otherExecution, duplicate]);

    expect(result.issues.filter((issue) => issue.title === 'Duplicate final output')).toEqual([
      expect.objectContaining({ eventId: 'duplicate' }),
    ]);
  });

  test('recognizes committed and canonical queue dispatch evidence', () => {
    const scenarios: TraceEventWithId[][] = [
      [
        trace('accepted-committed', 'multi_intent_queue_accepted', {
          provenancePhase: 'dispatch_committed',
        }),
      ],
      [trace('accepted-auto', 'multi_intent_queue_accepted', { automatic: true })],
      [
        trace('accepted-semantic', 'multi_intent_queue_accepted'),
        trace('semantic', 'semantic_execution_dispatch', {}, 1),
      ],
      [
        trace('accepted-agent', 'multi_intent_queue_accepted', { target: 'A' }),
        trace('agent-enter', 'agent_enter', { agentName: 'A' }, 1),
      ],
      [
        trace('accepted-flow', 'multi_intent_queue_accepted', { target: 'step-a' }),
        trace('flow-transition', 'flow_transition', { toStep: 'step-a' }, 1),
      ],
      [
        trace('accepted-step', 'multi_intent_queue_accepted', { target: 'step-a' }),
        trace('flow-step', 'flow_step_enter', { stepName: 'step-a' }, 1),
      ],
      [trace('accepted-llm', 'multi_intent_queue_accepted'), trace('llm', 'llm_call', {}, 1)],
      [trace('accepted-tool', 'multi_intent_queue_accepted'), trace('tool', 'tool_call', {}, 1)],
      [
        trace('accepted-tool-start', 'multi_intent_queue_accepted'),
        trace('tool-start', 'tool_call_start', {}, 1),
      ],
    ];

    for (const scenario of scenarios) {
      const result = analyzeOrchestrationFailures(scenario);
      expect(result.issues.map((issue) => issue.title)).not.toContain(
        'Accepted queued task was not dispatched',
      );
    }
  });

  test('reports a targetless queue drop when a new turn closes the evidence window', () => {
    const result = analyzeOrchestrationFailures([
      trace('accepted', 'multi_intent_queue_accepted', {}, 0, 'turn-1'),
      trace('new-turn', 'user_message', {}, 1, 'turn-2'),
    ]);

    expect(result.issues).toContainEqual(
      expect.objectContaining({
        title: 'Accepted queued task was not dispatched',
        description: expect.stringContaining('"unknown"'),
      }),
    );
  });

  test('does not let an unrelated semantic dispatch hide a targeted queued-task drop', () => {
    const unrelatedDispatch = trace('unrelated', 'semantic_execution_dispatch', {}, 1, 'turn');
    unrelatedDispatch.agentName = 'specialist';
    const result = analyzeOrchestrationFailures([
      trace('accepted', 'multi_intent_queue_accepted', { target: 'specialist' }, 0, 'turn'),
      unrelatedDispatch,
      trace('response', 'agent_response', { content: 'done' }, 2, 'turn'),
    ]);

    expect(result.issues).toContainEqual(
      expect.objectContaining({
        title: 'Accepted queued task was not dispatched',
        eventId: 'accepted',
      }),
    );
  });

  test('requires a positive targeted route and respects explicit denial', () => {
    const ignored = analyzeOrchestrationFailures([
      trace('negative', 'handoff_condition_check', { target: 'A', result: false }, 0, 'turn'),
      trace('missing-target', 'handoff_condition_check', { result: true }, 1, 'turn'),
      trace('response', 'agent_response', { content: 'done' }, 2, 'turn'),
    ]);
    const denied = analyzeOrchestrationFailures([
      trace('matched', 'handoff_condition_check', { target: 'A', passed: true }, 0, 'turn'),
      trace('denied', 'handoff_authority_denied', { target: 'A' }, 1, 'turn'),
      trace('response', 'agent_response', { content: 'handled' }, 2, 'turn'),
    ]);

    expect(ignored.issues.map((issue) => issue.title)).not.toContain(
      'Matched specialist route was bypassed',
    );
    expect(denied.issues.map((issue) => issue.title)).not.toContain(
      'Matched specialist route was bypassed',
    );
  });

  test('does not accept a conflicting handoff decision as the matched route dispatch', () => {
    const result = analyzeOrchestrationFailures([
      trace(
        'matched',
        'handoff_condition_check',
        { target: 'A', result: true, decisionId: 'expected' },
        0,
        'turn',
      ),
      trace(
        'wrong-decision',
        'handoff',
        { from: 'Supervisor', to: 'A', decisionId: 'different' },
        1,
        'turn',
      ),
      trace('response', 'agent_response', { content: 'handled' }, 2, 'turn'),
    ]);

    expect(result.issues.map((issue) => issue.title)).toContain(
      'Matched specialist route was bypassed',
    );
  });

  test('detects repeated disconnected edges but resets cycle evidence at turn boundaries', () => {
    const repeated = analyzeOrchestrationFailures([
      trace('a-b-1', 'handoff', { from: 'A', to: 'B' }, 0, 'turn-1'),
      trace('a-b-2', 'handoff', { from: 'A', to: 'B' }, 1, 'turn-1'),
      trace('a-b-3', 'handoff', { from: 'A', to: 'B' }, 2, 'turn-1'),
    ]);
    const reset = analyzeOrchestrationFailures([
      trace('a-b-1', 'handoff', { from: 'A', to: 'B' }, 0, 'turn-1'),
      trace('new-input', 'user_message', {}, 1, 'turn-2'),
      trace('a-b-2', 'handoff', { from: 'A', to: 'B' }, 2, 'turn-2'),
      trace('new-turn-edge', 'handoff', { from: 'A', to: 'B' }, 3, 'turn-3'),
      trace('missing-from', 'handoff', { to: 'B' }, 4, 'turn-3'),
      trace('missing-to', 'handoff', { from: 'A' }, 5, 'turn-3'),
    ]);

    expect(repeated.issues.map((issue) => issue.title)).toContain('Runaway handoff cycle');
    expect(reset.issues.map((issue) => issue.title)).not.toContain('Runaway handoff cycle');
  });
});
