import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { MCPDebugServer } from '../server.js';
import { ARCH_KNOWLEDGE_MEDIA_TYPE } from '../knowledge/contracts.js';
import { getKnowledgePrompt, readKnowledgeResource } from '../knowledge/discovery.js';
import { getToolContracts } from '../tools/index.js';

const CURRENT_V2_CONTRACT_SHA256 = {
  platform_connect: '3e01c35a0321c43fccedfc3d678debd33b780fad5dbfcd0981a87262eb4cf8ce',
  debug_list_agents: '5896f4be1483c1474b89b9b84c2af9de1ad61a1df5032a24bdc4afd026778bf1',
  debug_load_agent: '576e3e2639016d43186edb0c787bf0c1cc8339f2f68a05b23677137fe0296f78',
  debug_send_message: '02b05ab977e1dded2e7033923fe7a556478945f418506d0a0f8b7249c4d9f2d7',
  debug_traces: '0a9b76ae99a00ab4e0e96132b4d1a9095822da684f1df76e62b1173c287266cc',
  debug_session_history: 'a56832e3522a41f70126038101815e81210c7b0e921c35da290d17fe5bb3b4f8',
  debug_get_current_state: 'f71e3e0128d490518ed8432fa0af5fefe30fe61b14f8d136ec003ffb555ab533',
  debug_get_span_tree: '014e1ab92fa2245fa90d57b4f80c46c01305826c7cca6b211f0c22b77ebd5670',
  debug_get_errors: '917fa56b7fc9160189c8963f7a0e94c0074ae8b18fe0d556dfd3fe2866294242',
  debug_explain_decision: 'bd8b0d2670e5930f10a207d631dfc3f3eb1a3eeb8c306e504f21935ba37fdd0c',
  debug_get_flow_graph: 'd7dcfac2714db47d3eeced9ceeae2f1bdc5eddfd83acdd128b9322d89576ed70',
  debug_list_active_sessions: 'fdabc994f6526a24ba7b65e4e4438db477328439f2af2c88374908b533d4aead',
  debug_session: '065b248106d47524f519a12e1427b0872b6bfcc63aea0987929c09dece3bbcc3',
  debug_docs: '96decfa2052d9f169445cd4765cb7dc2112ddd24d9829f59851f1dfd5040d99b',
  debug_analyze_session: '8cfbd2d93a6c211fbef181898c7cf03ffd9e563f1a0657ce727692df185d891c',
  debug_harness_logs: 'd4b09aa51d7889721fb9e230851b768ad8287dfe2340106e1289e12be629d344',
  platform_project_builder: 'e0f6db20645311be111a6539dcd358f658276c7a3fa0d6b6192cd940cc7b5286',
  platform_project_builder_operations: '940480e4d15b158bd7209b748d36b446f37bc713530e67191fee23d73a48e967',
  platform_projects: '15b4326946d86a44be013ba55938d4d789fedf0d12db175c0819aee6009b3949',
  platform_workflows: '0c3957c6f6b95b6c2c739904f93e2329c7d2e7723012f182278140f796132d89',
  platform_arch_sop: 'f12931d03544158db560e546e06edcd033fa90d5d77355b1017900e4f886f363',
  platform_arch_auto_loop: '5de663d213d94f7847c0c09e6f11cb1dcea82a617b60566661339831ba90a7f1',
  platform_auth_profiles: 'deafdbc5e472f8debda11d70af075951150690e5e4a7569bc798bb2e7241aba5',
  platform_integrations: '7f75252da581bcfb569017c038a795e0665765e1faeaaf80ec4829a90dce44ca',
  platform_mcp_servers: '1ef0ffd404d7e9f0cc47f05d44e8cba134172923c62e98a6e03ea83055e06915',
  platform_agents: 'd0186a20e7f6c0ebed5cb1b7dee6d67919eef4135df4d684edba13266d741b7c',
  platform_versions: '369eaa8930ad72c7fa50509dc41b7e3b3e5cdb0d136b2f669e937a73fdf204e7',
  platform_deployments: '009b1ec6a71d6a887db072b3200b2405001e1ab3955ba25233545cb8806e3798',
  platform_sdk_channels: '4100daf2fc201cc7a602ee74b3e5e1f6e1fbfeb35da024169a64e794786b4f12',
  platform_tools: '9c5add427c8fff7a88b6118e31ef00771f98c6f3c1898b1b91ab06537c920285',
  agent_tables: '38a9b2973c678bffecedf01a5001303454f3805542398f9dd1b5f276866b6109',
  platform_import_export: '074eca9c3411188b468ec5d55d66f463aa15fadb6db7cc6e0230734a9642414c',
  platform_validate_package: 'f8c2d00b64b8a41acc9e59975f3c7d327cd3615acf3a657f2d1357cdb1adece3',
  platform_package_model: '00a57a8d8f9e15855394f8c335436d3bf8aa71721e5e7dec18de015ad93aa340',
  debug_lint_abl: '91a2852c940e8e0943d155bf10a63b06255effb30779f0e37f44cf19ef6fe62f',
  debug_why_transcript_failed: 'cd7e859e32a1cc6481e1e5695bc15db3807e951fecb5171e3df322283ec18ee2',
  debug_diagnose_transcript: '799b7c35027a975df980cab5b41087463666a23b9122593be7cdb679635f2de8',
  platform_eval_personas: '55dabb28d906c4fb6c5335eea2a66558bb9ae82718b4426bd48963cf924b2437',
  platform_eval_scenarios: 'ab63a9105f50cc711d1d2f7a92325f809527a2a1f0d7c34a330142f62128031b',
  platform_eval_evaluators: '34c85d40e60965791e91811c801b2ad6cce62cdffb6a274b4456192e49983ae3',
  platform_eval_sets: 'af2205ba68decc56ed1538891d47d7ad523c2b2318b78956582d96e5d148d512',
  platform_eval_runs: '106427c31d949eda0dd377ba8dd9457442b15e220bf6635902abe074af169d1b',
  platform_config: '991331ed767eb11aa09155fa920090356f859d75e0b74c53ba5ed70817660021',
  platform_workspaces: 'afafcc861bd4101edf86068a25205878ffdec1ada683b2b80c638d543669173d',
  debug_diagnose: '4cd8c99929789f000fad9eed1e259f8bbce15be6812322a947dd1fb7cd45616d',
} as const;

const active: Array<{ client: Client; server: MCPDebugServer }> = [];

afterEach(async () => {
  await Promise.all(
    active.splice(0).map(({ client, server }) => Promise.all([client.close(), server.stop()])),
  );
});

describe('Arch knowledge MCP discovery', () => {
  it('preserves the complete 45-tool MCP discovery contract', async () => {
    const client = await connectedClient();
    const listed = await client.listTools();

    expect(listed.tools).toHaveLength(45);
    expect(listed.tools.map(({ name }) => name)).toEqual(
      getToolContracts('current-v2').map(({ name }) => name),
    );
  });

  it('governs current-v2 schemas per tool without coupling them to descriptions', () => {
    const contracts = getToolContracts('current-v2');
    const digests = Object.fromEntries(
      contracts.map((contract) => [contract.name, sha256(contract)]),
    );

    expect(digests).toEqual(CURRENT_V2_CONTRACT_SHA256);
  });

  it('appends versioned resources and templates after existing project-builder discovery', async () => {
    const client = await connectedClient();
    const resources = await client.listResources();

    expect(resources.resources.slice(0, 2).map(({ uri }) => uri)).toEqual([
      'arch://project-builder/registry',
      'arch://project-builder/providers/workflow',
    ]);
    expect(resources.resources.slice(2).map(({ uri }) => uri)).toEqual([
      'arch://guidance/v1/manifest',
      'arch://guidance/v1/features',
      'arch://guidance/v1/operations',
      'arch://guidance/v1/dependencies',
      'arch://contract/v2/manifest',
    ]);
    expect(resources.resources.slice(2, 6).every(({ mimeType }) => mimeType === ARCH_KNOWLEDGE_MEDIA_TYPE)).toBe(true);
    expect(resources.resources[6]?.mimeType).toBe(
      'application/vnd.kore.arch-mcp-contract+json;version=2',
    );

    const templates = await client.listResourceTemplates();
    expect(templates.resourceTemplates.map(({ name }) => name)).toEqual([
      'project-builder-project-report',
      'guidance-feature-detail',
      'guidance-tool-detail',
    ]);
  });

  it('publishes structured compatibility metadata for the active profile', async () => {
    const current = await connectedClient('current-v2');
    const legacy = await connectedClient('legacy-v1');

    const read = async (client: Client) => {
      const result = await client.readResource({ uri: 'arch://contract/v2/manifest' });
      const content = result.contents[0];
      if (!content || !('text' in content)) throw new Error('Expected contract manifest text');
      return JSON.parse(content.text) as Record<string, unknown>;
    };

    expect(await read(current)).toMatchObject({
      schemaVersion: 2,
      profile: 'current-v2',
      runtimeContract: 'unchanged',
      compatibility: {
        targetlessRequests: 'preserved',
        unknownResponseFields: 'ignored',
        legacyFallbackProfile: 'legacy-v1',
      },
      features: { evalTargets: true, lockedTargetSnapshots: true },
      toolCount: 45,
    });
    const legacyManifest = await read(legacy);
    expect(legacyManifest).toMatchObject({
      schemaVersion: 2,
      profile: 'legacy-v1',
      features: { evalTargets: false, lockedTargetSnapshots: false },
      toolCount: 45,
    });
    expect(Object.keys(legacyManifest.contractHashes as object)).toEqual(
      getToolContracts('legacy-v1').map(({ name }) => name),
    );
  });

  it('reads manifest, feature, tool, operation, and dependency projections', async () => {
    const client = await connectedClient();
    const manifest = await readJson(client, 'arch://guidance/v1/manifest');
    expect(manifest).toMatchObject({
      schemaVersion: '1',
      generatedFrom: 'runtime-tool-registry',
      counts: { features: 13, tools: 45 },
    });

    const features = (await readJson(client, 'arch://guidance/v1/features')) as unknown[];
    const operations = (await readJson(client, 'arch://guidance/v1/operations')) as unknown[];
    const dependencies = (await readJson(client, 'arch://guidance/v1/dependencies')) as unknown[];
    expect(features).toHaveLength(13);
    expect(operations.length).toBeGreaterThan(150);
    expect(dependencies.length).toBeGreaterThan(10);

    expect(await readJson(client, 'arch://guidance/v1/features/release-delivery')).toMatchObject({
      feature: { id: 'release-delivery' },
    });
    expect(await readJson(client, 'arch://guidance/v1/tools/platform_deployments')).toMatchObject({
      tool: { name: 'platform_deployments', featureId: 'release-delivery' },
    });
  });

  it('appends planning and verification prompts while preserving existing prompts', async () => {
    const client = await connectedClient();
    const prompts = await client.listPrompts();
    expect(prompts.prompts.map(({ name }) => name)).toEqual([
      'build-agentic-project',
      'continue-project-operation',
      'plan-platform-operation',
      'verify-platform-operation',
    ]);

    const plan = await client.getPrompt({
      name: 'plan-platform-operation',
      arguments: { goal: 'Safely deploy the project', featureId: 'release-delivery' },
    });
    expect(plan.messages[0]?.content).toMatchObject({
      type: 'text',
      text: expect.stringContaining('Resolve every required dependency'),
    });
    const verify = await client.getPrompt({
      name: 'verify-platform-operation',
      arguments: { tool: 'platform_deployments', action: 'create' },
    });
    expect(verify.messages[0]?.content).toMatchObject({
      type: 'text',
      text: expect.stringContaining('platform_deployments action=get'),
    });
  });

  it('keeps invalid knowledge identifiers and arguments explicit', async () => {
    const client = await connectedClient();
    await expect(
      client.readResource({ uri: 'arch://guidance/v1/features/unknown' }),
    ).rejects.toThrow(/Unknown Arch feature/);
    await expect(client.readResource({ uri: 'arch://guidance/v1/unknown' })).rejects.toThrow(
      /Unknown guidance resource/,
    );
    await expect(
      client.getPrompt({ name: 'plan-platform-operation', arguments: {} }),
    ).rejects.toThrow(/goal is required/);
    await expect(
      client.getPrompt({
        name: 'verify-platform-operation',
        arguments: { tool: 'unknown', action: 'invoke' },
      }),
    ).rejects.toThrow(/Unknown Arch operation/);
    expect(
      getKnowledgePrompt('plan-platform-operation', { goal: 'Inspect support' }).messages[0]
        ?.content,
    ).toMatchObject({ text: expect.stringContaining('discover before acting') });
    expect(
      getKnowledgePrompt('verify-platform-operation', {
        tool: 'platform_auth_profiles',
        action: 'create',
      }).messages[0]?.content,
    ).toMatchObject({ text: expect.stringContaining('Never pass raw secrets') });
    expect(() => getKnowledgePrompt('unknown-guidance-prompt')).toThrow(/Unknown guidance prompt/);
    expect(() => readKnowledgeResource('https://example.invalid/v1/manifest')).toThrow(
      /Unknown guidance resource/,
    );
  });
});

async function connectedClient(
  discoveryProfile: 'legacy-v1' | 'current-v2' = 'current-v2',
): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = new MCPDebugServer({ discoveryProfile });
  const client = new Client({ name: 'knowledge-test', version: '1.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  active.push({ client, server });
  return client;
}

async function readJson(client: Client, uri: string): Promise<unknown> {
  const result = await client.readResource({ uri });
  const content = result.contents[0];
  if (!('text' in content)) throw new Error(`Expected text resource: ${uri}`);
  expect(content.mimeType).toBe(ARCH_KNOWLEDGE_MEDIA_TYPE);
  return JSON.parse(content.text);
}

function sha256(value: unknown): string {
  // Keep this test-only fingerprint deterministic and independent of prose.
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
