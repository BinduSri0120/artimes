import { afterEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { MCPDebugServer } from '../server.js';

const active: Array<{ client: Client; server: MCPDebugServer }> = [];

afterEach(async () => {
  await Promise.all(
    active.splice(0).map(({ client, server }) => Promise.all([client.close(), server.stop()])),
  );
});

describe('eval execution targets over MCP protocol', () => {
  it('keeps legacy-v1 schemas separate from the current target-aware profile', async () => {
    const current = await connectedClient(new MCPDebugServer({ discoveryProfile: 'current-v2' }));
    const legacy = await connectedClient(new MCPDebugServer({ discoveryProfile: 'legacy-v1' }));

    const currentTools = await current.listTools();
    const legacyTools = await legacy.listTools();
    const currentSets = currentTools.tools.find((tool) => tool.name === 'platform_eval_sets');
    const legacySets = legacyTools.tools.find((tool) => tool.name === 'platform_eval_sets');

    expect(currentTools.tools).toHaveLength(45);
    expect(legacyTools.tools).toHaveLength(45);
    expect(currentTools._meta).toMatchObject({
      archContract: {
        profile: 'current-v2',
        manifestUri: 'arch://contract/v2/manifest',
        runtimeContract: 'unchanged',
      },
    });
    expect(legacyTools._meta).toMatchObject({
      archContract: {
        profile: 'legacy-v1',
        manifestUri: 'arch://contract/v2/manifest',
        runtimeContract: 'unchanged',
      },
    });
    expect(JSON.stringify(currentSets?.inputSchema)).toContain('targets');
    expect(JSON.stringify(currentSets?.inputSchema)).toContain('working_copy');
    expect(JSON.stringify(legacySets?.inputSchema)).not.toContain('working_copy');
    expect(JSON.stringify(legacySets?.inputSchema)).not.toContain('targets');
  });

  it.each([
    [
      'platform_eval_sets',
      { type: 'working_copy' },
      { action: 'create', projectId: 'project-1', target: { type: 'working_copy' } },
    ],
    [
      'platform_eval_runs',
      { type: 'working_copy' },
      { action: 'create', projectId: 'project-1', evalTarget: { type: 'working_copy' } },
    ],
  ])('rejects target arguments for %s at the legacy-v1 protocol boundary', async (name, _target, arguments_) => {
    const client = await connectedClient(new MCPDebugServer({ discoveryProfile: 'legacy-v1' }));
    const result = await client.callTool({
      name,
      arguments: arguments_,
    });

    expect(result.isError).toBe(true);
  });

  it('keeps legacy guidance aligned with its legacy tool schemas', async () => {
    const client = await connectedClient(new MCPDebugServer({ discoveryProfile: 'legacy-v1' }));
    const resource = await client.readResource({ uri: 'arch://guidance/v1/operations' });
    const content = resource.contents[0];
    if (!content || !('text' in content)) throw new Error('Expected text guidance resource');
    const operations = JSON.parse(content.text) as Array<{ id: string }>;

    expect(operations.some(({ id }) => id === 'platform_eval_sets:targets')).toBe(false);
    expect(operations.some(({ id }) => id === 'platform_eval_sets:create')).toBe(true);
  });

  it('advertises target discovery and every typed execution-target variant on existing tools', async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = new MCPDebugServer();
    const client = new Client({ name: 'eval-target-contract-test', version: '1.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    active.push({ client, server });

    const listed = await client.listTools();
    const sets = listed.tools.find((tool) => tool.name === 'platform_eval_sets');
    const runs = listed.tools.find((tool) => tool.name === 'platform_eval_runs');
    expect(sets).toBeDefined();
    expect(runs).toBeDefined();

    const setsSchema = JSON.stringify(sets?.inputSchema);
    const runsSchema = JSON.stringify(runs?.inputSchema);
    expect(setsSchema).toContain('targets');
    for (const targetType of ['working_copy', 'environment', 'deployment', 'agent_version']) {
      expect(setsSchema).toContain(targetType);
      expect(runsSchema).toContain(targetType);
    }
  });

});

async function connectedClient(server = new MCPDebugServer()): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'eval-profile-contract-test', version: '1.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  active.push({ client, server });
  return client;
}
