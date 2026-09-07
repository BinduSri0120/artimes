/**
 * Tests for the session analysis tool
 */
import { describe, test, expect, beforeEach, vi } from 'vitest';
import type { TraceEventWithId, AgentState } from '../types.js';
import { analyzeSession, analyzeTraces } from '../tools/analysis.js';
import { TraceStore } from '../store/trace-store.js';
import type { DebugContext } from '../tools/index.js';

let nextEventSeq = 1;

// Helper to create trace events
function createTrace(
  type: string,
  data: Record<string, unknown> = {},
  timestamp?: Date,
): TraceEventWithId {
  return {
    id: `trace_${Math.random().toString(36).substr(2, 9)}`,
    type: type as TraceEventWithId['type'],
    timestamp: timestamp || new Date(),
    sessionId: 'test-session',
    data,
    eventSeq: nextEventSeq++,
  };
}

describe('Session Analysis', () => {
  describe('Handler', () => {
    function context(overrides: {
      activeSessionId?: string;
      session?: Record<string, unknown>;
      traces?: TraceEventWithId[];
    }): DebugContext {
      return {
        sessionStore: {
          getActiveSessionId: vi.fn(() => overrides.activeSessionId),
          getSession: vi.fn(() => overrides.session),
        },
        traceStore: {
          getBySession: vi.fn(() => overrides.traces ?? []),
        },
      } as unknown as DebugContext;
    }

    test('requires an explicit or active session', async () => {
      const result = JSON.parse(await analyzeSession({}, context({})));

      expect(result.error).toContain('No session specified and no active session');
    });

    test('reports an unknown requested session', async () => {
      const result = JSON.parse(
        await analyzeSession(
          { sessionId: 'missing-session' },
          context({ activeSessionId: 'other' }),
        ),
      );

      expect(result).toEqual({ error: 'Session not found: missing-session' });
    });

    test('analyzes the active session and exposes its agent name', async () => {
      const result = JSON.parse(
        await analyzeSession(
          {},
          context({
            activeSessionId: 'active-session',
            session: {
              state: { conversationPhase: 'complete' },
              agentDetails: { name: 'ChronologyAgent' },
            },
            traces: [createTrace('agent_enter')],
          }),
        ),
      );

      expect(result).toMatchObject({
        sessionId: 'active-session',
        agentName: 'ChronologyAgent',
        analysis: { summary: { totalEvents: 1 }, currentState: { phase: 'complete' } },
      });
    });

    test('uses the compatibility agent-name fallback', async () => {
      const result = JSON.parse(
        await analyzeSession(
          { sessionId: 'legacy-session' },
          context({ session: { state: {} }, traces: [] }),
        ),
      );

      expect(result.agentName).toBe('unknown');
    });
  });

  describe('Summary Statistics', () => {
    test('should count total events', () => {
      const traces = [
        createTrace('agent_enter'),
        createTrace('llm_call'),
        createTrace('agent_exit'),
      ];

      const result = analyzeTraces(traces);

      expect(result.summary.totalEvents).toBe(3);
    });

    test('should count event types correctly', () => {
      const traces = [
        createTrace('llm_call'),
        createTrace('llm_call'),
        createTrace('tool_call'),
        createTrace('error'),
      ];

      const result = analyzeTraces(traces);

      expect(result.summary.eventCounts['llm_call']).toBe(2);
      expect(result.summary.eventCounts['tool_call']).toBe(1);
      expect(result.summary.eventCounts['error']).toBe(1);
    });

    test('should count llmCalls correctly', () => {
      const traces = [
        createTrace('llm_call'),
        createTrace('tool_call'),
        createTrace('llm_call'),
        createTrace('llm_call'),
      ];

      const result = analyzeTraces(traces);

      expect(result.summary.llmCalls).toBe(3);
    });

    test('should count toolCalls correctly', () => {
      const traces = [
        createTrace('tool_call', { tool: 'search' }),
        createTrace('tool_call', { tool: 'lookup' }),
      ];

      const result = analyzeTraces(traces);

      expect(result.summary.toolCalls).toBe(2);
    });

    test('should count errors correctly', () => {
      const traces = [
        createTrace('error', { message: 'Error 1' }),
        createTrace('error', { message: 'Error 2' }),
      ];

      const result = analyzeTraces(traces);

      expect(result.summary.errors).toBe(2);
    });

    test('should calculate duration between first and last event', () => {
      const start = new Date('2024-01-01T10:00:00Z');
      const end = new Date('2024-01-01T10:00:05Z'); // 5 seconds later

      const traces = [
        createTrace('agent_enter', {}, start),
        createTrace('llm_call', {}, new Date('2024-01-01T10:00:02Z')),
        createTrace('agent_exit', {}, end),
      ];

      const result = analyzeTraces(traces);

      expect(result.summary.duration).toBe(5000); // 5000ms
    });

    test('uses authoritative timestamp order for the newest-first trace-store contract', () => {
      const traceStore = new TraceStore();
      traceStore.addEvent(
        createTrace('flow_step_enter', { stepName: 'start' }, new Date('2024-01-01T10:00:00Z')),
      );
      traceStore.addEvent(
        createTrace('flow_step_enter', { stepName: 'current' }, new Date('2024-01-01T10:00:05Z')),
      );

      const newestFirst = traceStore.getBySession('test-session');
      expect(newestFirst.map((event) => event.data.stepName)).toEqual(['current', 'start']);

      const result = analyzeTraces(newestFirst);

      expect(result.summary.duration).toBe(5_000);
      expect(result.currentState.step).toBe('current');
    });

    test('uses event sequence to order equal-millisecond events from newest-first browsing', () => {
      const timestamp = new Date('2024-01-01T10:00:00.000Z');
      const start = createTrace('flow_step_enter', { stepName: 'start' }, timestamp);
      start.eventSeq = 41;
      const current = createTrace('flow_step_enter', { stepName: 'current' }, timestamp);
      current.eventSeq = 42;

      const result = analyzeTraces([current, start]);

      expect(result.currentState.step).toBe('current');
    });

    test('reverses newest-first input ties when canonical event sequence is unavailable', () => {
      const timestamp = new Date('2024-01-01T10:00:00.000Z');
      const current = createTrace('flow_step_enter', { stepName: 'current' }, timestamp);
      const start = createTrace('flow_step_enter', { stepName: 'start' }, timestamp);
      delete current.eventSeq;
      delete start.eventSeq;
      const result = analyzeTraces([current, start]);

      expect(result.currentState.step).toBe('current');
    });

    test('uses one total fallback order for mixed sequenced and legacy timestamp ties', () => {
      const timestamp = new Date('2024-01-01T10:00:00.000Z');
      const newest = createTrace('flow_step_enter', { stepName: 'current' }, timestamp);
      newest.eventSeq = 1;
      const legacy = createTrace('flow_step_enter', { stepName: 'middle' }, timestamp);
      delete legacy.eventSeq;
      const oldest = createTrace('flow_step_enter', { stepName: 'start' }, timestamp);
      oldest.eventSeq = 3;

      const result = analyzeTraces([newest, legacy, oldest]);

      expect(result.currentState.step).toBe('current');
    });

    test('reports malformed timestamps while retaining valid chronological evidence', () => {
      const malformed = createTrace('flow_step_enter', { stepName: 'untrusted' });
      malformed.id = 'malformed-timestamp';
      malformed.timestamp = new Date('not-a-timestamp');

      const result = analyzeTraces([
        createTrace('agent_exit', {}, new Date('2024-01-01T10:00:05Z')),
        malformed,
        createTrace('agent_enter', {}, new Date('2024-01-01T10:00:00Z')),
      ]);

      expect(result.summary.totalEvents).toBe(3);
      expect(result.summary.duration).toBe(5_000);
      expect(result.issues).toContainEqual({
        type: 'error',
        title: 'Malformed trace timestamp',
        description:
          'Trace event "malformed-timestamp" has an invalid timestamp and was excluded from chronological analysis.',
        eventId: 'malformed-timestamp',
      });
    });

    test('should return null duration for single event', () => {
      const traces = [createTrace('agent_enter')];

      const result = analyzeTraces(traces);

      expect(result.summary.duration).toBeNull();
    });

    test('should handle empty traces array', () => {
      const result = analyzeTraces([]);

      expect(result.summary.totalEvents).toBe(0);
      expect(result.summary.llmCalls).toBe(0);
      expect(result.summary.toolCalls).toBe(0);
      expect(result.summary.errors).toBe(0);
      expect(result.summary.duration).toBeNull();
      expect(result.issues).toHaveLength(0);
    });
  });

  describe('Current State Detection', () => {
    test('should detect current flow step', () => {
      const traces = [
        createTrace('flow_step_enter', { stepName: 'greeting' }),
        createTrace('flow_step_exit', { stepName: 'greeting' }),
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
      ];

      const result = analyzeTraces(traces);

      expect(result.currentState.step).toBe('collect_info');
    });

    test('should detect phase from state', () => {
      const traces = [createTrace('agent_enter')];
      const state: AgentState = {
        conversationPhase: 'gathering',
      } as AgentState;

      const result = analyzeTraces(traces, state);

      expect(result.currentState.phase).toBe('gathering');
    });

    test('should extract collected fields from dsl_set events', () => {
      const traces = [
        createTrace('dsl_set', { field: 'name', value: 'John' }),
        createTrace('dsl_set', { field: 'email', value: 'john@example.com' }),
      ];

      const result = analyzeTraces(traces);

      expect(result.currentState.collectedFields).toContain('name');
      expect(result.currentState.collectedFields).toContain('email');
    });

    test('should extract missing fields from dsl_collect events', () => {
      const traces = [
        createTrace('dsl_collect', { field: 'name', collected: true }),
        createTrace('dsl_collect', { field: 'email', collected: false }),
        createTrace('dsl_collect', { field: 'phone', collected: false }),
      ];

      const result = analyzeTraces(traces);

      expect(result.currentState.missingFields).toContain('email');
      expect(result.currentState.missingFields).toContain('phone');
      expect(result.currentState.missingFields).not.toContain('name');
    });

    test('merges gathered state without duplicating trace-derived fields', () => {
      const result = analyzeTraces(
        [
          createTrace('dsl_set', { field: 'email' }),
          createTrace('dsl_collect', { field: 'phone', collected: false }),
          createTrace('flow_step_enter', {}),
        ],
        {
          gatherProgress: {
            email: { collected: true },
            phone: { collected: false },
            name: { collected: true },
            address: { collected: false },
            ignoredNull: null,
            ignoredString: 'invalid',
          },
        } as unknown as AgentState,
      );

      expect(result.currentState).toMatchObject({
        step: null,
        collectedFields: ['email', 'name'],
        missingFields: ['phone', 'address'],
      });
    });
  });

  describe('Loop Detection', () => {
    test('should detect potential loop when step entered more than 3 times', () => {
      const traces = [
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
      ];

      const result = analyzeTraces(traces);

      const loopIssue = result.issues.find((i) => i.title === 'Potential loop detected');
      expect(loopIssue).toBeDefined();
      expect(loopIssue?.type).toBe('warning');
      expect(loopIssue?.description).toContain('collect_info');
      expect(loopIssue?.description).toContain('4 times');
    });

    test('should not flag loop for 3 or fewer entries', () => {
      const traces = [
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
        createTrace('flow_step_enter', { stepName: 'collect_info' }),
      ];

      const result = analyzeTraces(traces);

      const loopIssue = result.issues.find((i) => i.title === 'Potential loop detected');
      expect(loopIssue).toBeUndefined();
    });

    test('should add suggestion for loop issues', () => {
      const traces = [
        createTrace('flow_step_enter', { stepName: 'broken_step' }),
        createTrace('flow_step_enter', { stepName: 'broken_step' }),
        createTrace('flow_step_enter', { stepName: 'broken_step' }),
        createTrace('flow_step_enter', { stepName: 'broken_step' }),
      ];

      const result = analyzeTraces(traces);

      expect(result.suggestions.some((s) => s.includes('broken_step'))).toBe(true);
    });
  });

  describe('Orchestration correctness', () => {
    function orchestrationTrace(
      id: string,
      type: TraceEventWithId['type'],
      data: Record<string, unknown>,
      offsetMs: number,
      turnId = 'turn-orchestration',
    ): TraceEventWithId {
      return {
        ...createTrace(type, data, new Date(`2024-01-01T10:00:00.000Z`)),
        id,
        timestamp: new Date(Date.parse('2024-01-01T10:00:00.000Z') + offsetMs),
        turnId,
      } as TraceEventWithId;
    }

    test('detects duplicate final output and a response copied across successful completion', () => {
      const result = analyzeTraces([
        orchestrationTrace(
          'response-before',
          'agent_response',
          {
            agentName: 'BillingSpecialist',
            content: 'Your request is complete.',
            isFinalForTurn: true,
          },
          0,
        ),
        orchestrationTrace(
          'completion',
          'completion_check',
          {
            agent: 'Supervisor',
            result: true,
          },
          1,
        ),
        orchestrationTrace(
          'response-copy',
          'agent_response',
          {
            agentName: 'Supervisor',
            response: 'Your request is complete.',
            isFinalForTurn: true,
          },
          2,
        ),
      ]);

      expect(result.issues.map((issue) => issue.title)).toEqual(
        expect.arrayContaining(['Unexpected completion response copy']),
      );
    });

    test('detects an accepted queued task that reaches turn completion without dispatch', () => {
      const result = analyzeTraces([
        orchestrationTrace(
          'accepted',
          'multi_intent_queue_accepted',
          {
            intent: 'check_balance',
            target: 'BalanceSpecialist',
            targetKind: 'agent',
          },
          0,
        ),
        orchestrationTrace(
          'closed',
          'agent_response',
          {
            agentName: 'Supervisor',
            content: 'Anything else?',
            isFinalForTurn: true,
          },
          10,
        ),
      ]);

      expect(result.issues).toContainEqual(
        expect.objectContaining({
          title: 'Accepted queued task was not dispatched',
          eventId: 'accepted',
        }),
      );
    });

    test('does not report a queued task whose targeted dispatch commits', () => {
      const result = analyzeTraces([
        orchestrationTrace(
          'accepted',
          'multi_intent_queue_accepted',
          {
            intent: 'check_balance',
            target: 'BalanceSpecialist',
            targetKind: 'agent',
          },
          0,
        ),
        orchestrationTrace(
          'handoff',
          'handoff',
          {
            from: 'Supervisor',
            to: 'BalanceSpecialist',
          },
          1,
        ),
        orchestrationTrace(
          'closed',
          'agent_response',
          {
            agentName: 'BalanceSpecialist',
            content: 'Your balance is available.',
            isFinalForTurn: true,
          },
          2,
        ),
      ]);

      expect(result.issues.map((issue) => issue.title)).not.toContain(
        'Accepted queued task was not dispatched',
      );
    });

    test('detects a matched specialist route that the supervisor bypasses', () => {
      const result = analyzeTraces([
        orchestrationTrace(
          'route-match',
          'handoff_condition_check',
          {
            sourceAgent: 'Supervisor',
            targetAgent: 'BillingSpecialist',
            result: true,
            decisionId: 'decision-billing',
          },
          0,
        ),
        orchestrationTrace(
          'supervisor-output',
          'agent_response',
          {
            agentName: 'Supervisor',
            content: 'I handled billing myself.',
            isFinalForTurn: true,
          },
          1,
        ),
      ]);

      expect(result.issues).toContainEqual(
        expect.objectContaining({
          title: 'Matched specialist route was bypassed',
          eventId: 'route-match',
        }),
      );
    });

    test('does not report a matched specialist route followed by its handoff', () => {
      const result = analyzeTraces([
        orchestrationTrace(
          'route-match',
          'handoff_condition_check',
          {
            sourceAgent: 'Supervisor',
            targetAgent: 'BillingSpecialist',
            result: true,
            decisionId: 'decision-billing',
          },
          0,
        ),
        orchestrationTrace(
          'route-dispatch',
          'handoff',
          {
            from: 'Supervisor',
            to: 'BillingSpecialist',
            decisionId: 'decision-billing',
          },
          1,
        ),
      ]);

      expect(result.issues.map((issue) => issue.title)).not.toContain(
        'Matched specialist route was bypassed',
      );
    });

    test('detects repeated handoff cycles and runaway trace volume', () => {
      const cycle = [
        orchestrationTrace('handoff-a-b-1', 'handoff', { from: 'A', to: 'B' }, 0),
        orchestrationTrace('handoff-b-a-1', 'handoff', { from: 'B', to: 'A' }, 1),
        orchestrationTrace('handoff-a-b-2', 'handoff', { from: 'A', to: 'B' }, 2),
        orchestrationTrace('handoff-b-a-2', 'handoff', { from: 'B', to: 'A' }, 3),
      ];
      const runawayVolume = Array.from({ length: 1_001 }, (_, index) =>
        orchestrationTrace(
          `decision-${index}`,
          'engine_decision',
          { decision: 'retry' },
          index + 4,
        ),
      );

      const result = analyzeTraces([...cycle, ...runawayVolume]);

      expect(result.issues.map((issue) => issue.title)).toEqual(
        expect.arrayContaining(['Runaway handoff cycle', 'Runaway trace volume']),
      );
    });
  });

  describe('Error Detection', () => {
    test('should report all error events', () => {
      const traces = [
        createTrace('error', { message: 'Connection timeout' }),
        createTrace('error', { message: 'Invalid input' }),
      ];

      const result = analyzeTraces(traces);

      const errorIssues = result.issues.filter((i) => i.title === 'Error occurred');
      expect(errorIssues).toHaveLength(2);
      expect(errorIssues[0].type).toBe('error');
    });

    test('should include error message in description', () => {
      const traces = [createTrace('error', { message: 'Specific error message' })];

      const result = analyzeTraces(traces);

      const errorIssue = result.issues.find((i) => i.title === 'Error occurred');
      expect(errorIssue?.description).toBe('Specific error message');
    });

    test('should include event ID for errors', () => {
      const traces = [createTrace('error', { message: 'Test error' })];

      const result = analyzeTraces(traces);

      const errorIssue = result.issues.find((i) => i.title === 'Error occurred');
      expect(errorIssue?.eventId).toBeDefined();
    });
  });

  describe('Constraint Violation Detection', () => {
    test('should detect constraint violations', () => {
      const traces = [createTrace('constraint_check', { constraint: 'max_amount', passed: false })];

      const result = analyzeTraces(traces);

      const violation = result.issues.find((i) => i.title === 'Constraint violation');
      expect(violation).toBeDefined();
      expect(violation?.description).toContain('max_amount');
    });

    test('should not flag passing constraints', () => {
      const traces = [createTrace('constraint_check', { constraint: 'max_amount', passed: true })];

      const result = analyzeTraces(traces);

      const violation = result.issues.find((i) => i.title === 'Constraint violation');
      expect(violation).toBeUndefined();
    });

    test('should add suggestion for constraint violations', () => {
      const traces = [
        createTrace('constraint_check', { constraint: 'user_authenticated', passed: false }),
      ];

      const result = analyzeTraces(traces);

      expect(result.suggestions.some((s) => s.includes('user_authenticated'))).toBe(true);
    });
  });

  describe('Tool Failure Detection', () => {
    test('should detect tool failures', () => {
      const traces = [
        createTrace('tool_call', { tool: 'search_api', success: false, error: 'API timeout' }),
      ];

      const result = analyzeTraces(traces);

      const failure = result.issues.find((i) => i.title === 'Tool call failed');
      expect(failure).toBeDefined();
      expect(failure?.type).toBe('error');
      expect(failure?.description).toContain('search_api');
      expect(failure?.description).toContain('API timeout');
    });

    test('should not flag successful tool calls', () => {
      const traces = [createTrace('tool_call', { tool: 'search_api', success: true })];

      const result = analyzeTraces(traces);

      const failure = result.issues.find((i) => i.title === 'Tool call failed');
      expect(failure).toBeUndefined();
    });

    test('should add suggestion for tool failures', () => {
      const traces = [
        createTrace('tool_call', { tool: 'broken_tool', success: false, error: 'Error' }),
      ];

      const result = analyzeTraces(traces);

      expect(result.suggestions.some((s) => s.includes('broken_tool'))).toBe(true);
    });
  });

  describe('Missing Fields Detection', () => {
    test('should report missing required fields', () => {
      const traces = [createTrace('dsl_collect', { field: 'email', collected: false })];

      const result = analyzeTraces(traces);

      const missingIssue = result.issues.find((i) => i.title === 'Missing required fields');
      expect(missingIssue).toBeDefined();
      expect(missingIssue?.type).toBe('info');
      expect(missingIssue?.description).toContain('email');
    });
  });

  describe('High LLM Call Detection', () => {
    test('should warn when LLM calls exceed threshold', () => {
      const traces = Array.from({ length: 11 }, () => createTrace('llm_call'));

      const result = analyzeTraces(traces);

      const llmIssue = result.issues.find((i) => i.title === 'High LLM call count');
      expect(llmIssue).toBeDefined();
      expect(llmIssue?.type).toBe('info');
    });

    test('should not warn when LLM calls are at threshold', () => {
      const traces = Array.from({ length: 10 }, () => createTrace('llm_call'));

      const result = analyzeTraces(traces);

      const llmIssue = result.issues.find((i) => i.title === 'High LLM call count');
      expect(llmIssue).toBeUndefined();
    });
  });

  describe('Multiple Escalations Detection', () => {
    test('should warn about multiple escalations', () => {
      const traces = [
        createTrace('escalation', { reason: 'User frustrated' }),
        createTrace('escalation', { reason: 'Cannot handle' }),
      ];

      const result = analyzeTraces(traces);

      const escalationIssue = result.issues.find((i) => i.title === 'Multiple escalations');
      expect(escalationIssue).toBeDefined();
      expect(escalationIssue?.type).toBe('warning');
    });

    test('should not warn for single escalation', () => {
      const traces = [createTrace('escalation', { reason: 'User frustrated' })];

      const result = analyzeTraces(traces);

      const escalationIssue = result.issues.find((i) => i.title === 'Multiple escalations');
      expect(escalationIssue).toBeUndefined();
    });
  });

  describe('Long Session Detection', () => {
    test('should report long-running sessions', () => {
      const start = new Date('2024-01-01T10:00:00Z');
      const end = new Date('2024-01-01T10:02:00Z'); // 2 minutes later

      const traces = [createTrace('agent_enter', {}, start), createTrace('agent_exit', {}, end)];

      const result = analyzeTraces(traces);

      const longSession = result.issues.find((i) => i.title === 'Long-running session');
      expect(longSession).toBeDefined();
      expect(longSession?.type).toBe('info');
    });

    test('should not report short sessions', () => {
      const start = new Date('2024-01-01T10:00:00Z');
      const end = new Date('2024-01-01T10:00:30Z'); // 30 seconds later

      const traces = [createTrace('agent_enter', {}, start), createTrace('agent_exit', {}, end)];

      const result = analyzeTraces(traces);

      const longSession = result.issues.find((i) => i.title === 'Long-running session');
      expect(longSession).toBeUndefined();
    });
  });

  describe('No LLM Calls Detection', () => {
    test('should warn when no LLM calls with many events', () => {
      const traces = [
        createTrace('agent_enter'),
        createTrace('flow_step_enter', { stepName: 'start' }),
        createTrace('dsl_prompt'),
        createTrace('flow_step_enter', { stepName: 'next' }),
        createTrace('dsl_prompt'),
        createTrace('flow_step_enter', { stepName: 'more' }),
      ];

      const result = analyzeTraces(traces);

      const noLlmIssue = result.issues.find((i) => i.title === 'No LLM calls detected');
      expect(noLlmIssue).toBeDefined();
      expect(noLlmIssue?.type).toBe('warning');
    });

    test('should not warn with few events', () => {
      const traces = [
        createTrace('agent_enter'),
        createTrace('flow_step_enter', { stepName: 'start' }),
      ];

      const result = analyzeTraces(traces);

      const noLlmIssue = result.issues.find((i) => i.title === 'No LLM calls detected');
      expect(noLlmIssue).toBeUndefined();
    });
  });
});
