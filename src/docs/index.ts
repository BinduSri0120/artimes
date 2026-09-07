/**
 * Embedded MCP fallback docs.
 *
 * Studio serves the full documentation bundle from GET /api/abl/docs. The MCP
 * package is distributed independently, so these focused topics keep the most
 * important platform contracts discoverable when the connected platform is
 * older, offline, or missing a newly documented route.
 */

export interface EmbeddedDocTopic {
  id: string;
  title: string;
  category: string;
}

const FALLBACK_SEARCH_STOP_WORDS: readonly string[] = [
  'a',
  'after',
  'and',
  'are',
  'between',
  'do',
  'does',
  'for',
  'how',
  'i',
  'in',
  'is',
  'it',
  'of',
  'one',
  'the',
  'to',
  'what',
  'when',
  'with',
];
const MIN_FALLBACK_SEARCH_TOKEN_LENGTH = 3;
const MIN_FALLBACK_SEARCH_TOKEN_MATCHES = 2;
const FALLBACK_SEARCH_EXCERPT_CONTEXT_CHARS = 80;
const FALLBACK_SEARCH_EXCERPT_TRAILING_CHARS = 180;

function fallbackSearchTokens(value: string): string[] {
  return [
    ...new Set<string>(
      value
        .toLowerCase()
        .split(/[^a-z0-9_]+/u)
        .filter(
          (token) =>
            token.length >= MIN_FALLBACK_SEARCH_TOKEN_LENGTH &&
            !FALLBACK_SEARCH_STOP_WORDS.includes(token),
        ),
    ),
  ];
}

export const ABL_DOCS: Record<string, string> = {
  'abl/flow-lifecycle': `# FLOW Retry and Lifecycle Contract

This embedded page is the offline MCP fallback for the connected Studio topic
\`abl-reference/flow\`. The connected topic is the authoritative full reference.

Use \`MAX_ATTEMPTS\` with \`ON_EXHAUSTED\` to bound unsuccessful attempts that
may span customer messages. Runtime consumes an attempt for failed required
GATHER input, an authored ON_INPUT retry that returns to the protected step, or
a reasoning customer turn that ends without satisfying EXIT_WHEN. Successfully
leaving the retry cycle clears the counter. The counter survives session
serialization and is isolated to the active agent thread.

\`MAX_TURNS\` is different: it limits reasoning/model/tool cycles inside one
Runtime invocation (one customer turn). It never ends a zone across customer
messages. Pair both limits when one customer message may require several
model/tool cycles but the conversation must stop after a bounded number of
unsuccessful customer messages.

\`EXIT_WHEN\` is evaluated after the reasoning iteration returns. \`always\` is
the built-in unconditional sentinel (equivalent to \`true\`) on every condition
surface, so \`EXIT_WHEN: always\` exits the zone on the same turn and follows
THEN; the THEN target's RESPOND is the authoritative text and the zone reply is
appended. Only the bare identifier is the sentinel; never name a session
variable \`always\`. A goal-only zone (no PRESENT) whose THEN path cycles straight
back into it re-executes on the empty re-entry, so an unconditional exit runs to
the FLOW iteration ceiling; add a PRESENT or a deterministic wait step.

\`\`\`abl
FLOW:
  resolve_request:
    REASONING: true
    GOAL: "Resolve the customer's request."
    EXIT_WHEN: resolution_ready == true
    MAX_TURNS: 5
    MAX_ATTEMPTS: 3
    ON_EXHAUSTED: escalate_to_human
    THEN: present_resolution
\`\`\`

For deterministic input retries, an explicit self-transition consumes an
ON_INPUT retry and creates a new step occurrence. Entry actions such as SET,
CLEAR, LOG, and DO run again for that occurrence. Restoring a session that is
merely parked on the step continues the existing occurrence and does not rerun
those actions.

\`\`\`abl
FLOW:
  confirm_transfer:
    REASONING: false
    MAX_ATTEMPTS: 3
    ON_EXHAUSTED: cancel_transfer
    RESPOND: "Type confirm or cancel."
    ON_INPUT:
      - IF: input == "confirm"
        THEN: execute_transfer
      - IF: input == "cancel"
        THEN: cancel_transfer
      - ELSE:
        RESPOND: "Please type confirm or cancel."
        THEN: confirm_transfer
\`\`\`

A promptless ON_INPUT step is legal. Add ELSE when every message must be
consumed. Without ELSE, unmatched input remains parked on the same step and the
compiler emits a warning.

\`execution.max_flow_iterations\` counts accepted step-to-step transitions
cumulatively across customer messages and restored sessions. Runtime refuses the
next nonterminal transition that would exceed the limit. Terminal completion and
an intercepted handoff remain allowed at the exact ceiling; parent and child
agent threads use independent counters.`,
  'mcp/platform-contract': `# Platform Contract for MCP Repair Tools

The MCP package can inspect local folders, zip archives, or import payloads without requiring callers to manually build a file map.

Package inputs accepted by repair tools:
- path: absolute or relative path to a project folder or .zip file.
- files: object mapping relative file paths to UTF-8 file content.
- data.files: import-style payload file map. This is normalized the same way as files.

Normalization rules:
- Backslashes are converted to forward slashes.
- Absolute paths, null bytes, and .. path traversal are rejected.
- Common archive wrappers, including nested wrappers such as repo-main/src/, are stripped when they contain project.json, abl.lock, or a supported package content directory.
- Supported content directories include agents, tools, behavior_profiles, config, core, connections, prompts, guardrails, workflows, evals, search, channels, vocabulary, locales, deployments, and environment.
- Skipped directories: .git, node_modules, dist, build, .turbo, __MACOSX.
- Skipped files: .DS_Store.
- Limits: 500 files and 1 MB per file in local MCP assembly.

Recommended Arch loop:
1. Build with platform_import_export, platform_projects, platform_agents, platform_tools, and platform_config.
2. Optimize with platform_validate_package, platform_package_model, and debug_lint_abl.
3. Evaluate with platform_eval_* tools to run persona/scenario/evaluator/set/run workflows.
4. Debug with platform_connect, debug_traces, debug_get_errors, and debug_why_transcript_failed.
5. Analyze with debug_diagnose and debug_analyze_session, then patch and repeat until validation/evals are clean.`,

  'mcp/import-contract': `# Import Preview and Apply Contract

Import endpoints are mounted under Studio project routes:
- POST /api/projects/:projectId/import/preview
- POST /api/projects/:projectId/import/apply

Payload fields:
- files: required file map after local MCP assembly.
- layers: optional array of supported layer names. Unsupported names return INVALID_LAYERS.
- deleteUnmatched: optional boolean. false maps to merge; true maps to replace.
- bindingResolutions: optional object keyed by resolution id.
- previewDigest: apply acknowledgement digest from preview.
- acknowledgedIssueIds: non-blocking preview issue ids acknowledged by the caller.

Apply acknowledgement rules:
- Blocking preview issues must be fixed before apply.
- Non-blocking issues require acknowledgement.
- The safe apply payload includes previewDigest and all non-blocking issue ids.
- platform_import_export auto-previews and auto-acknowledges non-blocking issues when confirm: true and no complete manual acknowledgement is supplied.
- Partial manual acknowledgement is treated as stale by default and replaced by a fresh preview unless autoAcknowledgeNonBlocking is false.

platform_validate_package with projectId returns importPreview details:
- previewDigest
- acknowledgedIssueIdsNeeded
- requiresAcknowledgement
- acknowledgementReady
- canApply
- missingAcknowledgementIssueIdCount
- suggestedApplyArgs

Use suggestedApplyArgs with platform_import_export import when you want explicit manual apply control.`,

  'mcp/behavior-profiles': `# Behavior Profile Package Contract

Agents attach standalone behavior profiles with:

USE BEHAVIOR_PROFILE: profile_name

Behavior profile files should be standalone ABL documents, typically under:

behavior_profiles/<name>.behavior_profile.abl

project.json should declare behavior profiles by name with a path, for example:

{
  "format_version": "2.0",
  "behavior_profiles": {
    "shared_voice": {
      "path": "behavior_profiles/shared_voice.behavior_profile.abl",
      "priority": 10
    }
  }
}

Compiler/import expectations:
- The profile document must exist in the package files.
- The agent USE BEHAVIOR_PROFILE name must match a declared/available profile.
- Preview diagnostics may report PROFILE_NOT_FOUND when the profile is referenced but not supplied as a package file.
- Behavior profile documents compile before agent attachment; invalid profile DSL is a package validation issue.

Repair workflow:
1. Use platform_package_model to list behaviorProfiles, profile references, and unresolvedRefs.
2. If an agent references a missing profile, add the profile file and project.json declaration or remove the USE BEHAVIOR_PROFILE line.
3. Use debug_lint_abl and platform_validate_package to catch syntax, dependency, and design issues before import apply.`,

  'mcp/abl-repair-loop': `# Arch ABL Repair and Eval Loop

Arch's MCP tools are designed for iterative ABL repair, not only import troubleshooting.

Suggested workflow:
1. platform_package_model: inspect what the compiler sees.
2. debug_lint_abl: find design risks such as empty RESPOND, empty finalize steps, undeclared handoff-condition variables, side-effect tool chains, and tool-call plus customer-text reasoning risks.
3. debug_why_transcript_failed (or alias debug_diagnose_transcript): correlate transcript symptoms to ABL file/line causes, including finalize -> COMPLETE -> RESPOND: "".
4. platform_validate_package: run platform validation and import preview when projectId is available.
5. platform_eval_personas, platform_eval_scenarios, platform_eval_evaluators, platform_eval_sets, and platform_eval_runs: generate or run eval assets.
6. platform_eval_runs with action "cases": drill from a failing heatmap cell into diagnosticTranscript, conversation, traceEvents, toolCalls, trajectory, and evaluator scores.
7. Patch the local package and repeat until validation and evals agree.

The key debugging question is: what does the compiler see?

Use platform_package_model for:
- agents
- tools
- handoffs and delegates
- memory variables
- behavior profile references
- compiled flow steps
- constraint observability: raw constraint bullets, parsed constraint AST, inert parser warnings, compiled IR constraints, and runtime-check phases
- unresolved references
- compiler diagnostics

Constraint contract facts surfaced by package model and validation:
- rawConstraints counts authored CONSTRAINTS bullets.
- parsedConstraints counts only REQUIRE/WARN/LIMIT/RESTRICT entries parsed into the AST.
- inertConstraintWarnings identifies plain CONSTRAINTS bullets that are ignored by the constraints compiler.
- compiledRuntimeConstraints counts entries that reached compiled ir.constraints.constraints.
- phaseSemantics.labelsOnly is true: always: and named phases are readability labels today, not lifecycle hooks.
- runtimeChecks shows the semantic runtime surfaces: state-context checks, before_tool_call checkpoints, before_response checkpoints, and after_tool_result checks.

Tool contract facts:
- side_effects plus confirmation controls user approval flow; it is not an authorization policy.
- identity_tier_required is the current identity gate. Generic tool requires/effects authorization policy is not modeled here.`,

  'mcp/agent-tables': `# Agent Tables for Arch MCP

Agent Tables are typed, durable, queryable project data stores backed by the platform. Arch exposes them through the agent_tables MCP tool and should use agent_tables(action: "availability") first when a user reports TABLE_UNAVAILABLE.

Best-fit use cases:
- Use Agent Tables when an agent needs durable structured rows it can query, update, and reuse over time: customer preferences, support tickets, bookings/orders, product catalogs, case queues, workflow state, and disruption/exception tracking.
- Use project scope for shared catalogs, configuration, and operational queues; end_user scope for per-customer preferences, orders, and tickets across channels; session scope for short-lived scratch rows in one conversation.
- Do not use Agent Tables for a single memory value (use FactStore/REMEMBER), entity-extraction value lists (use Lookup Tables), full-text/vector/document search (use SearchAI or Knowledge Bases), large blobs/files (use attachments/object storage), or analytics/aggregations (use analytics/SearchAI).

Availability gates, in order:
1. Global emergency switch: if blocked, Agent Tables is intentionally off for the runtime.
2. Infrastructure: Agent Tables exists only when the runtime has Postgres data and DDL connections configured. Do not surface connection strings.
3. Tenant/project config: the tenant entitlement and project overrides must resolve to enabled.
4. Environment tier: direct deployed table-tool calls require production. Studio debug uses an isolated synthetic overlay; workflow-invoked table tools use production context.

Storage model:
- The physical store is a fixed at_* schema; a user table is catalog metadata plus rows.
- Data is tenant/project isolated. Scope keys are derived by the server, never supplied by the caller.
- Sensitive values are encrypted/redacted; reveal requires explicit permission and is audited.

Table model:
- A table has name, displayName, optional description, scope, schemaVersion, and columns.
- Scopes are project, end_user, and session. Project scope is shared by the project. End-user scope is per contact/customer identity. Session scope is one conversation/scratch space.
- Workflow tool nodes can use project-scoped table tools directly. End-user or session tables must go through an agent session with identity.

Column model:
- Types: string, integer, number, boolean, datetime, enum, reference, json.
- Flags: required, indexed, unique, sensitive.
- Indexed fields may be filtered/sorted. Unique implies indexed. Sensitive excludes unique. JSON excludes indexed and unique. Reference columns require reference metadata and are not for sensitive values.
- Additive schema changes bump schemaVersion. Add column and add index are supported. Destructive drop/retype/enum changes are blocked unless a future migration path explicitly supports them.
- TABLE_SCHEMA_VERSION_MISMATCH means the tool binding/deployment must be refreshed against the current schema version.

Tool binding model:
- Agent tools use type: table and bind a table, scope, schema version pins, and allowed operations.
- Empty operations means read-only get/query/count.
- Write operations include insert, update, upsert, delete, bulkInsert, bulkUpsert.
- The caller supplies values, filters, row IDs, rowVersion, and query parameters only. The caller must never supply tenantId, projectId, environment, contactId, sessionId, scopeKey, tableId, runIdKey, SQL state, or physical storage identifiers.

Query rules and SQL:
- Structured query supports filters, predicate trees, sort, limit, cursor, and count.
- SQL text is accepted only when query evolution is enabled. The parser compiles bounded SELECT/INSERT/UPDATE/DELETE into table IR before execution.
- SQL templates must use placeholders for caller values and must not accept raw caller SQL.
- Filtering/sorting on unindexed columns is rejected. Sensitive columns allow constrained equality lookup paths only when enabled and authorized.

MCP tool actions:
- availability: explain whether Agent Tables is usable and name the blocking gate.
- list/describe: inspect table definitions, columns, scopes, schemaVersion, and capabilities.
- create/update/migrate/delete: manage table definitions. Delete requires confirm=true.
- insert/query/get_row/update_row/delete_row/upsert/reveal: manage project-scoped row data through Runtime APIs. Delete row requires confirm=true; reveal requires sensitive reveal permission.

Safety rules:
- Never expose Postgres URLs, tokens, raw sqlstate, key material, or physical at_* internals to the user.
- Never expose decrypted sensitive values except through the explicit reveal action after Runtime authorization and audit.
- Prefer least privilege operations. Do not add write/delete operations to an agent table tool unless the user explicitly needs mutation.
- Use availability before attempting mutation when the environment or project enablement is unknown.`,
};

export const DOC_TOPICS: EmbeddedDocTopic[] = [
  {
    id: 'abl/flow-lifecycle',
    title: 'FLOW Retry and Lifecycle Contract',
    category: 'ABL Fallback',
  },
  { id: 'mcp/platform-contract', title: 'MCP Platform Contract', category: 'MCP Fallback' },
  {
    id: 'mcp/import-contract',
    title: 'Import Preview and Apply Contract',
    category: 'MCP Fallback',
  },
  {
    id: 'mcp/behavior-profiles',
    title: 'Behavior Profile Package Contract',
    category: 'MCP Fallback',
  },
  {
    id: 'mcp/abl-repair-loop',
    title: 'Arch ABL Repair and Eval Loop',
    category: 'MCP Fallback',
  },
  {
    id: 'mcp/agent-tables',
    title: 'Agent Tables MCP Guide',
    category: 'MCP Fallback',
  },
];

export function searchDocumentation(query: string): Array<{
  id: string;
  topic: string;
  title: string;
  category: string;
  excerpt: string;
}> {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return [];
  }

  const queryTokens = fallbackSearchTokens(normalized);
  const results: Array<{
    id: string;
    topic: string;
    title: string;
    category: string;
    excerpt: string;
    score: number;
  }> = [];

  for (const topic of DOC_TOPICS) {
    const content = ABL_DOCS[topic.id] ?? '';
    const normalizedTitle = topic.title.toLowerCase();
    const normalizedContent = content.toLowerCase();
    const titleMatch = normalizedTitle.includes(normalized);
    const exactContentIndex = normalizedContent.indexOf(normalized);
    const matchedTokens = queryTokens.filter(
      (token) => normalizedTitle.includes(token) || normalizedContent.includes(token),
    );
    const requiredTokenMatches = Math.min(MIN_FALLBACK_SEARCH_TOKEN_MATCHES, queryTokens.length);
    if (
      !titleMatch &&
      exactContentIndex === -1 &&
      (requiredTokenMatches === 0 || matchedTokens.length < requiredTokenMatches)
    ) {
      continue;
    }

    const firstMatchedToken = matchedTokens.find((token) => normalizedContent.includes(token));
    const contentIndex =
      exactContentIndex !== -1
        ? exactContentIndex
        : firstMatchedToken
          ? normalizedContent.indexOf(firstMatchedToken)
          : -1;
    const start =
      contentIndex === -1 ? 0 : Math.max(0, contentIndex - FALLBACK_SEARCH_EXCERPT_CONTEXT_CHARS);
    const end =
      contentIndex === -1
        ? Math.min(content.length, FALLBACK_SEARCH_EXCERPT_TRAILING_CHARS)
        : Math.min(
            content.length,
            contentIndex +
              (exactContentIndex !== -1 ? normalized.length : (firstMatchedToken?.length ?? 0)) +
              FALLBACK_SEARCH_EXCERPT_TRAILING_CHARS,
          );
    results.push({
      id: topic.id,
      topic: topic.id,
      title: topic.title,
      category: topic.category,
      excerpt: `${start > 0 ? '...' : ''}${content.slice(start, end).trim()}${end < content.length ? '...' : ''}`,
      score: (titleMatch ? 100 : 0) + (exactContentIndex !== -1 ? 50 : 0) + matchedTokens.length,
    });
  }

  return results
    .sort((left, right) => right.score - left.score || left.title.localeCompare(right.title))
    .map(({ score: _score, ...result }) => result);
}
