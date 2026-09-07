/**
 * Agent Tools
 *
 * debug_list_agents - List available agents
 * debug_load_agent - Load an agent and create debug session
 */

import { z } from 'zod';
import type { DebugContext } from './index.js';

// =============================================================================
// debug_list_agents
// =============================================================================

export const listAgentsSchema = z.object({
  domain: z.string().optional().describe('Filter by domain'),
});

export type ListAgentsArgs = z.infer<typeof listAgentsSchema>;

export async function listAgents(args: ListAgentsArgs, ctx: DebugContext): Promise<string> {
  try {
    const response = await ctx.httpClient.listAgents();

    if (!response.success) {
      return JSON.stringify({
        success: false,
        error: 'Failed to list agents',
      });
    }

    // Runtime returns a flat array of agents. Group by domain for the MCP response.
    const rawAgents = Array.isArray(response.agents)
      ? (response.agents as Array<Record<string, unknown>>)
      : [];

    // Group by domain (fall back to "default" if agent has no domain)
    const grouped: Record<string, Array<Record<string, unknown>>> = {};
    for (const agent of rawAgents) {
      const domain = (agent.domain as string) || 'default';
      if (!grouped[domain]) grouped[domain] = [];
      grouped[domain].push(agent);
    }

    // Filter by domain if specified
    if (args.domain) {
      const filtered = grouped[args.domain] || [];
      return JSON.stringify({
        success: true,
        total: filtered.length,
        domains: [args.domain],
        agents: { [args.domain]: filtered },
      });
    }

    return JSON.stringify({
      success: true,
      total: rawAgents.length,
      domains: Object.keys(grouped),
      agents: grouped,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return JSON.stringify({
      success: false,
      error: `Failed to list agents: ${message}`,
    });
  }
}

// =============================================================================
// debug_load_agent
// =============================================================================

export const loadAgentSchema = z.object({
  agentPath: z
    .string()
    .describe('Agent path in format "domain/name" (e.g., "hotel-booking/booking_agent")'),
  projectId: z.string().describe('Project ID that owns the agent'),
});

export type LoadAgentArgs = z.infer<typeof loadAgentSchema>;

export async function loadAgent(args: LoadAgentArgs, ctx: DebugContext): Promise<string> {
  const { agentPath, projectId } = args;

  // Ensure connected
  if (!ctx.wsClient.isConnected()) {
    return JSON.stringify({
      success: false,
      error: 'Not connected to server. Call platform_connect first.',
    });
  }

  let wsClient = ctx.wsClient;
  if (ctx.sessionConnections) {
    try {
      wsClient = await ctx.sessionConnections.createForLoad();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return JSON.stringify({
        success: false,
        error: `Failed to create an isolated debug session connection: ${message}`,
      });
    }
  }

  return new Promise((resolve) => {
    let resolved = false;
    const discardDedicatedConnection = () => {
      if (wsClient !== ctx.wsClient) ctx.sessionConnections?.discard(wsClient);
    };
    const restoreHandlers = () => {
      wsClient.onAgentLoaded = originalOnAgentLoaded;
      wsClient.onAgentLoadError = originalOnAgentLoadError;
    };
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        restoreHandlers();
        discardDedicatedConnection();
        resolve(
          JSON.stringify({
            success: false,
            error: 'Timeout waiting for agent to load',
          }),
        );
      }
    }, 30000);

    // Set up one-time handlers for the response
    const originalOnAgentLoaded = wsClient.onAgentLoaded;
    const originalOnAgentLoadError = wsClient.onAgentLoadError;

    wsClient.onAgentLoaded = (sessionId, agent) => {
      // Restore original handlers
      restoreHandlers();

      // Create session in store
      if (wsClient !== ctx.wsClient) ctx.sessionConnections?.register(sessionId, wsClient);
      ctx.sessionStore.createSession(sessionId, agent.id, agent);

      clearTimeout(timeout);
      if (!resolved) {
        resolved = true;
        resolve(
          JSON.stringify({
            success: true,
            sessionId,
            agent: {
              id: agent.id,
              name: agent.name,
              domain: agent.domain,
              type: agent.type,
              mode: agent.mode,
              toolCount: agent.toolCount,
              gatherFieldCount: agent.gatherFieldCount,
              isSupervisor: agent.isSupervisor,
            },
            message: `Agent "${agent.name}" loaded successfully. Session ID: ${sessionId}`,
          }),
        );
      }

      // Call original handler if it exists
      originalOnAgentLoaded?.(sessionId, agent);
    };

    wsClient.onAgentLoadError = (error) => {
      // Restore original handlers
      restoreHandlers();
      discardDedicatedConnection();

      clearTimeout(timeout);
      if (!resolved) {
        resolved = true;
        resolve(
          JSON.stringify({
            success: false,
            error,
          }),
        );
      }

      // Call original handler if it exists
      originalOnAgentLoadError?.(error);
    };

    // Send load request
    try {
      wsClient.loadAgent(agentPath, projectId);
    } catch (error) {
      clearTimeout(timeout);
      restoreHandlers();
      discardDedicatedConnection();
      resolved = true;
      const message = error instanceof Error ? error.message : String(error);
      resolve(JSON.stringify({ success: false, error: message }));
    }
  });
}
