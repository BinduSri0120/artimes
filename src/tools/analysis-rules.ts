import type { TraceEventWithId } from '../types.js';

export interface OrchestrationAnalysisIssue {
  type: 'warning' | 'error' | 'info';
  title: string;
  description: string;
  eventId?: string;
}

export interface OrchestrationAnalysisResult {
  issues: OrchestrationAnalysisIssue[];
  suggestions: string[];
}

const FALLBACK_CORRELATION_WINDOW_MS = 5_000;
// TraceStore's per-session ring buffer is 500. Reaching the exact bound means
// earlier evidence may already have been evicted, so a rollout gate must fail
// visibly instead of treating the retained tail as a complete clean session.
const RUNAWAY_TRACE_EVENT_THRESHOLD = 500;
const RUNAWAY_REPEATED_EDGE_THRESHOLD = 3;
const RUNAWAY_CONNECTED_EDGE_THRESHOLD = 4;

function dataOf(trace: TraceEventWithId): Record<string, unknown> {
  return trace.data && typeof trace.data === 'object' ? trace.data : {};
}

function firstString(record: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

function traceTurnId(trace: TraceEventWithId): string | undefined {
  if (typeof trace.turnId === 'string' && trace.turnId.length > 0) return `turn:${trace.turnId}`;
  if (typeof trace.executionId === 'string' && trace.executionId.length > 0) {
    return `execution:${trace.executionId}`;
  }
  const data = dataOf(trace);
  const dataTurnId = firstString(data, ['turnId', 'turn_id']);
  if (dataTurnId) return `turn:${dataTurnId}`;
  const dataExecutionId = firstString(data, ['executionId', 'execution_id']);
  return dataExecutionId ? `execution:${dataExecutionId}` : undefined;
}

function traceAgent(trace: TraceEventWithId): string | undefined {
  return (
    trace.agentName ??
    firstString(dataOf(trace), ['agentName', 'agent', 'sourceAgent', 'from', 'fromAgent'])
  );
}

function traceTarget(trace: TraceEventWithId): string | undefined {
  return firstString(dataOf(trace), [
    'targetAgent',
    'target',
    'to',
    'toAgent',
    'queuedIntentTarget',
  ]);
}

function traceTimestampMs(trace: TraceEventWithId): number {
  return new Date(trace.timestamp).getTime();
}

function sameLogicalTurn(left: TraceEventWithId, right: TraceEventWithId): boolean {
  const leftTurnId = traceTurnId(left);
  const rightTurnId = traceTurnId(right);
  if (leftTurnId || rightTurnId) return leftTurnId !== undefined && leftTurnId === rightTurnId;
  return (
    Math.abs(traceTimestampMs(right) - traceTimestampMs(left)) <= FALLBACK_CORRELATION_WINDOW_MS
  );
}

function responseText(trace: TraceEventWithId): string | undefined {
  if (trace.type !== 'agent_response') return undefined;
  const text = firstString(dataOf(trace), ['content', 'response', 'message', 'agent_response']);
  return text?.replace(/\s+/g, ' ');
}

function isFinalResponse(trace: TraceEventWithId): boolean {
  return trace.type === 'agent_response' && dataOf(trace).isFinalForTurn !== false;
}

function isSuccessfulCompletion(trace: TraceEventWithId): boolean {
  if (trace.type !== 'completion_check') return false;
  return hasPositiveResult(trace);
}

function hasPositiveResult(trace: TraceEventWithId): boolean {
  const data = dataOf(trace);
  return data.result === true || data.passed === true;
}

function isTurnBoundary(trace: TraceEventWithId): boolean {
  return (
    trace.type === 'user_message' ||
    trace.type === 'session_end' ||
    trace.type === 'session_ended' ||
    isFinalResponse(trace)
  );
}

function matchingTarget(candidate: string | undefined, expected: string | undefined): boolean {
  return expected === undefined || candidate === expected;
}

function isQueueDispatchEvidence(trace: TraceEventWithId, target: string | undefined): boolean {
  const data = dataOf(trace);
  switch (trace.type as string) {
    case 'semantic_execution_dispatch':
      return matchingTarget(traceTarget(trace), target);
    case 'handoff':
      return matchingTarget(traceTarget(trace), target);
    case 'agent_enter':
      return matchingTarget(traceAgent(trace), target);
    case 'flow_transition':
      return matchingTarget(firstString(data, ['toStep', 'to', 'target']), target);
    case 'flow_step_enter':
      return matchingTarget(firstString(data, ['stepName', 'step', 'target']), target);
    case 'llm_call':
    case 'tool_call':
    case 'tool_call_start':
      return target === undefined;
    default:
      return false;
  }
}

function analyzeResponseCopies(traces: TraceEventWithId[]): OrchestrationAnalysisResult {
  const issues: OrchestrationAnalysisIssue[] = [];
  const suggestions: string[] = [];
  const priorResponses: Array<{ trace: TraceEventWithId; index: number; text: string }> = [];

  traces.forEach((trace, index) => {
    if (!isFinalResponse(trace)) return;
    const text = responseText(trace);
    if (!text) return;
    const agent = traceAgent(trace) ?? 'unknown';
    const prior = [...priorResponses]
      .reverse()
      .find((candidate) => candidate.text === text && sameLogicalTurn(candidate.trace, trace));

    if (prior) {
      const copiedAcrossCompletion = traces
        .slice(prior.index + 1, index)
        .some(
          (candidate) => isSuccessfulCompletion(candidate) && sameLogicalTurn(candidate, trace),
        );
      issues.push({
        type: 'error',
        title: copiedAcrossCompletion
          ? 'Unexpected completion response copy'
          : 'Duplicate final output',
        description: copiedAcrossCompletion
          ? `Final output from agent "${agent}" was emitted again after a successful completion check in the same turn.`
          : `Agent "${agent}" emitted the same final output more than once in the same turn.`,
        eventId: trace.id,
      });
      suggestions.push(
        'Inspect final response ownership and completion/return composition; one turn must have one customer-visible final owner.',
      );
    }

    priorResponses.push({ trace, index, text });
  });

  return { issues, suggestions };
}

function analyzeQueuedDispatches(traces: TraceEventWithId[]): OrchestrationAnalysisResult {
  const issues: OrchestrationAnalysisIssue[] = [];
  const suggestions: string[] = [];

  traces.forEach((trace, index) => {
    if (trace.type !== 'multi_intent_queue_accepted') return;
    const data = dataOf(trace);
    if (data.provenancePhase === 'dispatch_committed' || data.automatic === true) return;

    const target = traceTarget(trace);
    let closed = false;
    let dispatched = false;
    for (let cursor = index + 1; cursor < traces.length; cursor += 1) {
      const candidate = traces[cursor];
      if (!sameLogicalTurn(trace, candidate) || candidate.type === 'user_message') {
        closed = true;
        break;
      }
      if (isQueueDispatchEvidence(candidate, target)) {
        dispatched = true;
        break;
      }
      if (isTurnBoundary(candidate)) {
        closed = true;
        break;
      }
    }

    if (closed && !dispatched) {
      const intent = firstString(data, ['label', 'intent', 'queuedIntent']) ?? 'unknown';
      issues.push({
        type: 'error',
        title: 'Accepted queued task was not dispatched',
        description: `Queued task "${intent}" was accepted but the turn closed without matching dispatch evidence${target ? ` for target "${target}"` : ''}.`,
        eventId: trace.id,
      });
      suggestions.push(
        'Inspect queue dequeue, replay, and restoration traces; acceptance must be emitted only with a committed dispatch or followed by target execution.',
      );
    }
  });

  return { issues, suggestions };
}

function analyzeSpecialistRoutes(traces: TraceEventWithId[]): OrchestrationAnalysisResult {
  const issues: OrchestrationAnalysisIssue[] = [];
  const suggestions: string[] = [];

  traces.forEach((trace, index) => {
    if (trace.type !== 'handoff_condition_check' || !hasPositiveResult(trace)) return;
    const target = traceTarget(trace);
    if (!target) return;
    const data = dataOf(trace);
    const decisionId = firstString(data, ['decisionId', 'decision_id']);
    const sourceAgent = traceAgent(trace);
    let dispatched = false;
    let explicitlyDenied = false;
    let bypassed = false;

    for (let cursor = index + 1; cursor < traces.length; cursor += 1) {
      const candidate = traces[cursor];
      if (!sameLogicalTurn(trace, candidate) || candidate.type === 'user_message') break;
      const candidateData = dataOf(candidate);
      const candidateDecisionId = firstString(candidateData, ['decisionId', 'decision_id']);
      if (
        candidate.type === 'handoff' &&
        traceTarget(candidate) === target &&
        (!decisionId || !candidateDecisionId || candidateDecisionId === decisionId)
      ) {
        dispatched = true;
        break;
      }
      if (
        (candidate.type as string) === 'handoff_authority_denied' &&
        traceTarget(candidate) === target
      ) {
        explicitlyDenied = true;
        break;
      }
      if (isFinalResponse(candidate) && (!sourceAgent || traceAgent(candidate) === sourceAgent)) {
        bypassed = true;
        break;
      }
    }

    if (bypassed && !dispatched && !explicitlyDenied) {
      issues.push({
        type: 'error',
        title: 'Matched specialist route was bypassed',
        description: `Route to specialist "${target}" matched, but the source agent produced the turn's final response without the matching handoff.`,
        eventId: trace.id,
      });
      suggestions.push(
        'Inspect route-selection authority and handoff dispatch; a matched specialist route must not fall through to source-agent completion.',
      );
    }
  });

  return { issues, suggestions };
}

function analyzeRunawayExecution(traces: TraceEventWithId[]): OrchestrationAnalysisResult {
  const issues: OrchestrationAnalysisIssue[] = [];
  const suggestions: string[] = [];

  if (traces.length >= RUNAWAY_TRACE_EVENT_THRESHOLD) {
    issues.push({
      type: 'error',
      title: 'Runaway trace volume',
      description: `Session filled the debugger's ${RUNAWAY_TRACE_EVENT_THRESHOLD}-event analysis buffer (${traces.length} retained events); earlier evidence may be truncated and the retained volume indicates a possible runaway.`,
    });
    suggestions.push(
      'Inspect loop guards, retry budgets, and repeated routing edges before using this session as rollout evidence.',
    );
  }

  let activeTurnId: string | undefined;
  let connectedPath: string[] = [];
  let connectedEdgeCount = 0;
  let reportedForSegment = false;
  const edgeCounts = new Map<string, number>();

  const resetSegment = (turnId?: string): void => {
    activeTurnId = turnId;
    connectedPath = [];
    connectedEdgeCount = 0;
    reportedForSegment = false;
    edgeCounts.clear();
  };

  for (const trace of traces) {
    const turnId = traceTurnId(trace);
    if (trace.type === 'user_message' || (activeTurnId && turnId && turnId !== activeTurnId)) {
      resetSegment(turnId);
    } else if (!activeTurnId && turnId) {
      activeTurnId = turnId;
    }
    if (trace.type !== 'handoff') continue;
    const from = firstString(dataOf(trace), ['from', 'sourceAgent', 'fromAgent', 'agentName']);
    const to = traceTarget(trace);
    if (!from || !to) continue;

    const edgeKey = `${from}\u0000${to}`;
    const edgeCount = (edgeCounts.get(edgeKey) ?? 0) + 1;
    edgeCounts.set(edgeKey, edgeCount);

    if (connectedPath.at(-1) === from) {
      connectedPath.push(to);
      connectedEdgeCount += 1;
    } else {
      connectedPath = [from, to];
      connectedEdgeCount = 1;
    }

    const closesConnectedCycle =
      connectedEdgeCount >= RUNAWAY_CONNECTED_EDGE_THRESHOLD &&
      connectedPath.slice(0, -1).includes(to);
    if (
      !reportedForSegment &&
      (edgeCount >= RUNAWAY_REPEATED_EDGE_THRESHOLD || closesConnectedCycle)
    ) {
      issues.push({
        type: 'error',
        title: 'Runaway handoff cycle',
        description: `Repeated handoff path reached edge "${from} → ${to}" without a new customer turn.`,
        eventId: trace.id,
      });
      suggestions.push(
        'Inspect handoff return ownership and cycle guards; repeated routing must terminate or wait for new customer input.',
      );
      reportedForSegment = true;
    }
  }

  return { issues, suggestions };
}

export function analyzeOrchestrationFailures(
  traces: TraceEventWithId[],
): OrchestrationAnalysisResult {
  const analyses = [
    analyzeResponseCopies(traces),
    analyzeQueuedDispatches(traces),
    analyzeSpecialistRoutes(traces),
    analyzeRunawayExecution(traces),
  ];
  return {
    issues: analyses.flatMap((analysis) => analysis.issues),
    suggestions: [...new Set(analyses.flatMap((analysis) => analysis.suggestions))],
  };
}
