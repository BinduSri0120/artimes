import { afterEach, describe, expect, it, vi } from 'vitest';
import type { WebSocketClient } from '../client/websocket-client.js';
import type { DebugContext } from '../tools/index.js';
import { loadAgent } from '../tools/agents.js';
import { sendMessage } from '../tools/interaction.js';
import { getCurrentState } from '../tools/state.js';
import { SessionStore } from '../store/session-store.js';
import { TraceStore } from '../store/trace-store.js';
import { SessionConnectionRegistry } from '../client/session-connection-registry.js';
import type { AgentState } from '../types.js';
import { MCPDebugServer } from '../server.js';

afterEach(() => {
  vi.useRealTimers();
});

function createClient(sessionId: string, authToken: string | null = 'test-token') {
  const client = {
    isConnected: vi.fn(() => true),
    connect: vi.fn(async () => undefined),
    disconnect: vi.fn(),
    getUrl: vi.fn(() => 'ws://runtime.test/ws'),
    setUrl: vi.fn(),
    getAuthToken: vi.fn((): string | null => authToken),
    setAuthToken: vi.fn(),
    loadAgent: vi.fn(function (this: typeof client) {
      queueMicrotask(() =>
        this.onAgentLoaded?.(sessionId, {
          id: `agent-${sessionId}`,
          name: `Agent ${sessionId}`,
          domain: 'test',
          dsl: 'agent test {}',
          filePath: `test/${sessionId}`,
          type: 'agent',
          mode: 'reasoning',
          toolCount: 0,
          gatherFieldCount: 0,
          isSupervisor: false,
        }),
      );
    }),
    sendMessage: vi.fn(),
    getState: vi.fn(function (this: typeof client, requestedSessionId: string) {
      queueMicrotask(() => {
        this.onStateUpdate?.('other-session', createState({ ignored: true }));
        this.onStateUpdate?.(requestedSessionId, createState());
      });
    }),
    onAgentLoaded: undefined as WebSocketClient['onAgentLoaded'],
    onAgentLoadError: undefined as WebSocketClient['onAgentLoadError'],
    onResponseStart: undefined as WebSocketClient['onResponseStart'],
    onResponseChunk: undefined as WebSocketClient['onResponseChunk'],
    onResponseEnd: undefined as WebSocketClient['onResponseEnd'],
    onStateUpdate: undefined as WebSocketClient['onStateUpdate'],
    onTraceEvent: undefined as WebSocketClient['onTraceEvent'],
    onConnected: undefined as WebSocketClient['onConnected'],
    onDisconnected: undefined as WebSocketClient['onDisconnected'],
    onInfo: undefined as WebSocketClient['onInfo'],
    onError: undefined as WebSocketClient['onError'],
  };
  return client;
}

function createState(context: Record<string, unknown> = {}): AgentState {
  return {
    context,
    conversationPhase: 'active',
    gatherProgress: {},
    constraintResults: {},
    lastToolResults: {},
    memory: { session: {}, persistentCache: {}, pendingRemembers: [] },
  };
}

describe('ABLP-4438 session transport ownership', () => {
  it('keeps an earlier loaded session usable after another agent is loaded', async () => {
    const controlClient = createClient('control-session');
    const firstClient = createClient('session-1');
    const secondClient = createClient('session-2');
    const pendingClients = [firstClient, secondClient];
    const connections = new Map<string, typeof firstClient>();
    const sessionConnections = {
      createForLoad: vi.fn(async () => pendingClients.shift()!),
      register: vi.fn((sessionId: string, client: typeof firstClient) => {
        connections.set(sessionId, client);
      }),
      get: vi.fn((sessionId: string) => connections.get(sessionId)),
      discard: vi.fn(),
      clear: vi.fn(),
    };
    const context = {
      wsClient: controlClient,
      httpClient: {},
      sessionStore: new SessionStore(),
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections,
    } as unknown as DebugContext;

    expect(JSON.parse(await loadAgent({ agentPath: 'test/one', projectId: 'p' }, context))).toEqual(
      expect.objectContaining({ success: true, sessionId: 'session-1' }),
    );
    expect(JSON.parse(await loadAgent({ agentPath: 'test/two', projectId: 'p' }, context))).toEqual(
      expect.objectContaining({ success: true, sessionId: 'session-2' }),
    );

    const result = JSON.parse(
      await sendMessage(
        { sessionId: 'session-1', text: 'still alive', waitForResponse: false, timeout: 100 },
        context,
      ),
    );

    expect(result).toEqual(expect.objectContaining({ success: true, sessionId: 'session-1' }));
    expect(firstClient.sendMessage).toHaveBeenCalledWith('session-1', 'still alive');
    expect(secondClient.sendMessage).not.toHaveBeenCalled();
    expect(controlClient.sendMessage).not.toHaveBeenCalled();

    expect(JSON.parse(await getCurrentState({ sessionId: 'session-1' }, context))).toEqual(
      expect.objectContaining({ success: true, sessionId: 'session-1', source: 'fresh' }),
    );
    expect(firstClient.getState).toHaveBeenCalledWith('session-1');
    expect(secondClient.getState).not.toHaveBeenCalled();
    expect(controlClient.getState).not.toHaveBeenCalled();
  });

  it('bounds dedicated connections with LRU eviction and clears every owned transport', async () => {
    const controlClient = createClient('control');
    const firstClient = createClient('session-1');
    const secondClient = createClient('session-2');
    const thirdClient = createClient('session-3');
    const clients = [firstClient, secondClient, thirdClient];
    const evicted: string[] = [];
    const registry = new SessionConnectionRegistry(controlClient as unknown as WebSocketClient, {
      maxConnections: 2,
      createClient: () => clients.shift()! as unknown as WebSocketClient,
      onEvict: (sessionId) => evicted.push(sessionId),
    });

    registry.register('session-1', await registry.createForLoad());
    registry.register('session-2', await registry.createForLoad());
    expect(registry.get('session-1')).toBe(firstClient);

    registry.register('session-3', await registry.createForLoad());

    expect(registry.get('session-2')).toBeUndefined();
    expect(secondClient.disconnect).toHaveBeenCalledOnce();
    expect(evicted).toEqual(['session-2']);

    registry.clear();
    expect(firstClient.disconnect).toHaveBeenCalledOnce();
    expect(thirdClient.disconnect).toHaveBeenCalledOnce();
    expect(evicted).toEqual(['session-2', 'session-1', 'session-3']);
  });

  it('discards a dedicated transport when Runtime rejects the agent load', async () => {
    const controlClient = createClient('control');
    const rejectedClient = createClient('rejected');
    rejectedClient.loadAgent.mockImplementation(function (this: typeof rejectedClient) {
      queueMicrotask(() => this.onAgentLoadError?.('Agent not found'));
    });
    const sessionConnections = {
      createForLoad: vi.fn(async () => rejectedClient),
      register: vi.fn(),
      get: vi.fn(),
      discard: vi.fn(),
      clear: vi.fn(),
    };
    const context = {
      wsClient: controlClient,
      httpClient: {},
      sessionStore: new SessionStore(),
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections,
    } as unknown as DebugContext;

    expect(
      JSON.parse(await loadAgent({ agentPath: 'test/missing', projectId: 'p' }, context)),
    ).toEqual({ success: false, error: 'Agent not found' });
    expect(sessionConnections.discard).toHaveBeenCalledWith(rejectedClient);
    expect(sessionConnections.register).not.toHaveBeenCalled();
  });

  it.each([new Error('connection refused'), 'connection refused'])(
    'returns a bounded error when an isolated transport cannot be created (%s)',
    async (failure) => {
      const controlClient = createClient('control');
      const context = {
        wsClient: controlClient,
        httpClient: {},
        sessionStore: new SessionStore(),
        traceStore: new TraceStore(),
        authenticate: vi.fn(),
        sessionConnections: {
          createForLoad: vi.fn(async () => {
            throw failure;
          }),
          register: vi.fn(),
          get: vi.fn(),
          discard: vi.fn(),
          clear: vi.fn(),
        },
      } as unknown as DebugContext;

      expect(
        JSON.parse(await loadAgent({ agentPath: 'test/one', projectId: 'p' }, context)),
      ).toEqual({
        success: false,
        error: 'Failed to create an isolated debug session connection: connection refused',
      });
      expect(controlClient.loadAgent).not.toHaveBeenCalled();
    },
  );

  it.each([0, -1, 1.5])('rejects invalid dedicated connection capacity %s', (maxConnections) => {
    expect(
      () =>
        new SessionConnectionRegistry(createClient('control') as unknown as WebSocketClient, {
          maxConnections,
        }),
    ).toThrow('maxConnections must be a positive integer.');
  });

  it.each([
    ['idleTtlMs', { idleTtlMs: 0 }, 'idleTtlMs must be a positive integer.'],
    ['sweepIntervalMs', { sweepIntervalMs: 0 }, 'sweepIntervalMs must be a positive integer.'],
  ])('rejects invalid %s', (_name, options, message) => {
    expect(
      () =>
        new SessionConnectionRegistry(createClient('control') as unknown as WebSocketClient, {
          ...options,
        }),
    ).toThrow(message);
  });

  it('rejects connection creation without a connected authenticated control transport', async () => {
    const disconnected = createClient('control');
    disconnected.isConnected.mockReturnValue(false);
    const disconnectedRegistry = new SessionConnectionRegistry(
      disconnected as unknown as WebSocketClient,
    );
    await expect(disconnectedRegistry.createForLoad()).rejects.toThrow(
      'Control WebSocket is not connected.',
    );

    const unauthenticated = createClient('control', null);
    const unauthenticatedRegistry = new SessionConnectionRegistry(
      unauthenticated as unknown as WebSocketClient,
    );
    await expect(unauthenticatedRegistry.createForLoad()).rejects.toThrow(
      'Control WebSocket has no authenticated session token.',
    );
  });

  it('bounds pending connections and cleans up a failed handshake', async () => {
    vi.useFakeTimers();
    const control = createClient('control');
    const pending = createClient('pending');
    const failed = createClient('failed');
    failed.connect.mockRejectedValue(new Error('handshake failed'));
    const clients = [pending, failed];
    const registry = new SessionConnectionRegistry(control as unknown as WebSocketClient, {
      maxConnections: 1,
      createClient: () => clients.shift()! as unknown as WebSocketClient,
    });

    await registry.createForLoad();
    expect(vi.getTimerCount()).toBe(1);
    await expect(registry.createForLoad()).rejects.toThrow(
      'Debug session connection capacity is currently exhausted.',
    );
    registry.discard(pending as unknown as WebSocketClient);
    expect(vi.getTimerCount()).toBe(0);

    await expect(registry.createForLoad()).rejects.toThrow('handshake failed');
    expect(failed.disconnect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('keeps the prior LRU session when an at-capacity replacement handshake fails', async () => {
    const control = createClient('control');
    const stable = createClient('stable');
    const failed = createClient('failed');
    failed.connect.mockRejectedValue(new Error('handshake failed'));
    const clients = [stable, failed];
    const registry = new SessionConnectionRegistry(control as unknown as WebSocketClient, {
      maxConnections: 1,
      createClient: () => clients.shift()! as unknown as WebSocketClient,
    });

    registry.register('stable', await registry.createForLoad());
    await expect(registry.createForLoad()).rejects.toThrow('handshake failed');

    expect(registry.get('stable')).toBe(stable);
    expect(stable.disconnect).not.toHaveBeenCalled();
  });

  it('expires inactive owned transports and restarts sweeping after clear', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-02T00:00:00.000Z'));
    const control = createClient('control');
    const first = createClient('first');
    const second = createClient('second');
    const clients = [first, second];
    const evicted: string[] = [];
    const registry = new SessionConnectionRegistry(control as unknown as WebSocketClient, {
      idleTtlMs: 1_000,
      sweepIntervalMs: 100,
      createClient: () => clients.shift()! as unknown as WebSocketClient,
      onEvict: (sessionId) => evicted.push(sessionId),
    });

    registry.register('first', await registry.createForLoad());
    await vi.advanceTimersByTimeAsync(1_000);
    expect(registry.get('first')).toBeUndefined();
    expect(first.disconnect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);

    registry.clear();
    registry.register('second', await registry.createForLoad());
    await vi.advanceTimersByTimeAsync(1_000);
    expect(second.disconnect).toHaveBeenCalledOnce();
    expect(evicted).toEqual(['first', 'second']);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('retires replaced, disconnected, and explicitly discarded registered transports', async () => {
    const control = createClient('control');
    const first = createClient('first');
    const replacement = createClient('replacement');
    const evicted: string[] = [];
    const clients = [first, replacement];
    const registry = new SessionConnectionRegistry(control as unknown as WebSocketClient, {
      createClient: () => clients.shift()! as unknown as WebSocketClient,
      onEvict: (sessionId) => evicted.push(sessionId),
    });

    registry.register('session', await registry.createForLoad());
    registry.register('session', await registry.createForLoad());
    expect(first.disconnect).toHaveBeenCalledOnce();

    replacement.isConnected.mockReturnValue(false);
    expect(registry.get('session')).toBeUndefined();
    expect(replacement.disconnect).toHaveBeenCalledOnce();
    expect(evicted).toEqual(['session']);

    const registered = createClient('registered');
    const discardRegistry = new SessionConnectionRegistry(control as unknown as WebSocketClient, {
      createClient: () => registered as unknown as WebSocketClient,
      onEvict: (sessionId) => evicted.push(sessionId),
    });
    discardRegistry.register('discarded', await discardRegistry.createForLoad());
    discardRegistry.discard(registered as unknown as WebSocketClient);
    expect(registered.disconnect).toHaveBeenCalledOnce();
    expect(evicted).toEqual(['session', 'discarded']);
  });

  it('preserves the legacy control-client load path for embedding contexts', async () => {
    const controlClient = createClient('legacy-session');
    const originalLoaded = vi.fn();
    controlClient.onAgentLoaded = originalLoaded;
    const context = {
      wsClient: controlClient,
      httpClient: {},
      sessionStore: new SessionStore(),
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
    } as unknown as DebugContext;

    expect(
      JSON.parse(await loadAgent({ agentPath: 'test/legacy', projectId: 'p' }, context)),
    ).toEqual(expect.objectContaining({ success: true, sessionId: 'legacy-session' }));
    expect(controlClient.loadAgent).toHaveBeenCalledWith('test/legacy', 'p');
    expect(originalLoaded).toHaveBeenCalledOnce();
  });

  it('rejects loads while disconnected and cleans up synchronous send failures', async () => {
    const disconnected = createClient('disconnected');
    disconnected.isConnected.mockReturnValue(false);
    const disconnectedContext = {
      wsClient: disconnected,
      httpClient: {},
      sessionStore: new SessionStore(),
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
    } as unknown as DebugContext;
    expect(
      JSON.parse(await loadAgent({ agentPath: 'test/one', projectId: 'p' }, disconnectedContext)),
    ).toEqual({
      success: false,
      error: 'Not connected to server. Call platform_connect first.',
    });

    const control = createClient('control');
    const child = createClient('child');
    child.loadAgent.mockImplementation(() => {
      throw 'socket closed';
    });
    const discard = vi.fn();
    const context = {
      wsClient: control,
      httpClient: {},
      sessionStore: new SessionStore(),
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections: {
        createForLoad: vi.fn(async () => child),
        register: vi.fn(),
        get: vi.fn(),
        discard,
        clear: vi.fn(),
      },
    } as unknown as DebugContext;
    expect(JSON.parse(await loadAgent({ agentPath: 'test/one', projectId: 'p' }, context))).toEqual(
      { success: false, error: 'socket closed' },
    );
    expect(discard).toHaveBeenCalledWith(child);
  });

  it('times out an unacknowledged load and discards its dedicated transport', async () => {
    vi.useFakeTimers();
    const control = createClient('control');
    const child = createClient('child');
    child.loadAgent.mockImplementation(() => undefined);
    const discard = vi.fn();
    const context = {
      wsClient: control,
      httpClient: {},
      sessionStore: new SessionStore(),
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections: {
        createForLoad: vi.fn(async () => child),
        register: vi.fn(),
        get: vi.fn(),
        discard,
        clear: vi.fn(),
      },
    } as unknown as DebugContext;

    const pending = loadAgent({ agentPath: 'test/one', projectId: 'p' }, context);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(JSON.parse(await pending)).toEqual({
      success: false,
      error: 'Timeout waiting for agent to load',
    });
    expect(discard).toHaveBeenCalledWith(child);
  });

  it('waits for a response on the session-owned transport and preserves prior callbacks', async () => {
    const control = createClient('control');
    const child = createClient('session');
    const originalStart = vi.fn();
    const originalChunk = vi.fn();
    const originalEnd = vi.fn();
    child.onResponseStart = originalStart;
    child.onResponseChunk = originalChunk;
    child.onResponseEnd = originalEnd;
    child.sendMessage.mockImplementation(function (this: typeof child) {
      queueMicrotask(() => {
        this.onResponseStart?.('other-session', 'ignored');
        this.onResponseStart?.('session', 'message-1');
        this.onResponseChunk?.('session', 'ignored', 'wrong');
        this.onResponseChunk?.('session', 'message-1', 'hello');
        this.onResponseEnd?.('session', 'ignored', 'wrong');
        this.onResponseEnd?.('session', 'message-1', 'hello');
      });
    });
    const sessionStore = new SessionStore();
    sessionStore.createSession('session', 'agent');
    const context = {
      wsClient: control,
      httpClient: {},
      sessionStore,
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections: {
        createForLoad: vi.fn(),
        register: vi.fn(),
        get: vi.fn(() => child),
        discard: vi.fn(),
        clear: vi.fn(),
      },
    } as unknown as DebugContext;

    expect(
      JSON.parse(
        await sendMessage(
          { sessionId: 'session', text: 'hi', waitForResponse: true, timeout: 100 },
          context,
        ),
      ),
    ).toEqual({
      success: true,
      // A response frame alone is not an answer: the envelope now states the
      // turn outcome, and this session produced no failure events.
      turnStatus: 'answered',
      sessionId: 'session',
      messageId: 'message-1',
      sentText: 'hi',
      response: 'hello',
      responseLength: 5,
    });
    expect(originalStart).toHaveBeenCalledTimes(2);
    expect(originalChunk).toHaveBeenCalledTimes(2);
    expect(originalEnd).toHaveBeenCalledTimes(2);
  });

  it('returns owned-transport errors and bounded response timeouts', async () => {
    const control = createClient('control');
    const child = createClient('session');
    const sessionStore = new SessionStore();
    sessionStore.createSession('session', 'agent');
    const context = {
      wsClient: control,
      httpClient: {},
      sessionStore,
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections: {
        createForLoad: vi.fn(),
        register: vi.fn(),
        get: vi.fn(() => child),
        discard: vi.fn(),
        clear: vi.fn(),
      },
    } as unknown as DebugContext;

    child.sendMessage.mockImplementation(function (this: typeof child) {
      queueMicrotask(() => this.onError?.('Runtime rejected the turn'));
    });
    expect(
      JSON.parse(
        await sendMessage(
          { sessionId: 'session', text: 'hi', waitForResponse: true, timeout: 100 },
          context,
        ),
      ),
    ).toEqual({ success: false, error: 'Runtime rejected the turn' });

    child.sendMessage.mockImplementation(function (this: typeof child) {
      queueMicrotask(() => {
        this.onResponseStart?.('session', 'message-2');
        this.onResponseChunk?.('session', 'message-2', 'partial');
      });
    });
    expect(
      JSON.parse(
        await sendMessage(
          { sessionId: 'session', text: 'again', waitForResponse: true, timeout: 1 },
          context,
        ),
      ),
    ).toEqual({
      success: false,
      error: 'Timeout waiting for response',
      partialResponse: 'partial',
    });

    child.isConnected.mockReturnValue(false);
    expect(
      JSON.parse(
        await sendMessage(
          { sessionId: 'session', text: 'again', waitForResponse: false, timeout: 1 },
          context,
        ),
      ),
    ).toEqual({
      success: false,
      error: 'Not connected to server. Call platform_connect first.',
    });

    child.isConnected.mockReturnValue(true);
    const noOwnedTransport = {
      ...context,
      sessionConnections: {
        ...context.sessionConnections,
        get: vi.fn(() => undefined),
      },
    } as DebugContext;
    expect(
      JSON.parse(
        await sendMessage(
          { sessionId: 'session', text: 'control fallback', waitForResponse: false, timeout: 1 },
          noOwnedTransport,
        ),
      ),
    ).toEqual({
      success: false,
      error: 'Dedicated connection unavailable for session: session. Load the agent again.',
    });
    expect(control.sendMessage).not.toHaveBeenCalled();
  });

  it('covers empty, missing, cached, and disconnected session state outcomes', async () => {
    const control = createClient('control');
    const sessionStore = new SessionStore();
    const context = {
      wsClient: control,
      httpClient: {},
      sessionStore,
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
    } as unknown as DebugContext;

    expect(JSON.parse(await getCurrentState({}, context))).toEqual({
      success: false,
      error: 'No session specified and no active session. Load an agent first.',
    });
    expect(JSON.parse(await getCurrentState({ sessionId: 'missing' }, context))).toEqual({
      success: false,
      error: 'Session not found: missing',
    });

    const cached = sessionStore.createSession('cached', 'agent');
    cached.state = createState({ answer: 42 });
    expect(JSON.parse(await getCurrentState({ sessionId: 'cached' }, context))).toEqual(
      expect.objectContaining({ success: true, sessionId: 'cached', state: cached.state }),
    );

    sessionStore.createSession('disconnected', 'agent');
    control.isConnected.mockReturnValue(false);
    expect(JSON.parse(await getCurrentState({ sessionId: 'disconnected' }, context))).toEqual({
      success: true,
      sessionId: 'disconnected',
      agentId: 'agent',
      state: null,
      message: 'No state available yet. Send a message to the agent first.',
    });

    control.isConnected.mockReturnValue(true);
    const isolatedContext = {
      ...context,
      sessionConnections: {
        createForLoad: vi.fn(),
        register: vi.fn(),
        get: vi.fn(() => undefined),
        discard: vi.fn(),
        clear: vi.fn(),
      },
    } as unknown as DebugContext;
    expect(
      JSON.parse(await getCurrentState({ sessionId: 'disconnected' }, isolatedContext)),
    ).toEqual({
      success: false,
      error: 'Dedicated connection unavailable for session: disconnected. Load the agent again.',
    });
    expect(control.getState).not.toHaveBeenCalled();
  });

  it('restores the owned state callback after a timeout', async () => {
    vi.useFakeTimers();
    const control = createClient('control');
    const child = createClient('session');
    child.getState.mockImplementation(() => undefined);
    const originalStateUpdate = vi.fn();
    child.onStateUpdate = originalStateUpdate;
    const sessionStore = new SessionStore();
    sessionStore.createSession('session', 'agent');
    const context = {
      wsClient: control,
      httpClient: {},
      sessionStore,
      traceStore: new TraceStore(),
      authenticate: vi.fn(),
      sessionConnections: {
        createForLoad: vi.fn(),
        register: vi.fn(),
        get: vi.fn(() => child),
        discard: vi.fn(),
        clear: vi.fn(),
      },
    } as unknown as DebugContext;

    const pending = getCurrentState({ sessionId: 'session' }, context);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(JSON.parse(await pending)).toEqual({
      success: false,
      error: 'Timeout waiting for state update',
    });
    expect(child.onStateUpdate).toBe(originalStateUpdate);
  });

  it('wires child session events into the server stores without control-connection logs', async () => {
    const server = new MCPDebugServer({ serverUrl: 'https://agents-dev.kore.ai' });
    const child = createClient('session');
    const internal = server as unknown as {
      setupWebSocketHandlers(client: WebSocketClient, logConnectionStatus: boolean): void;
      sessionStore: SessionStore;
      traceStore: TraceStore;
    };
    internal.sessionStore.createSession('session', 'agent');
    internal.setupWebSocketHandlers(child as unknown as WebSocketClient, false);

    child.onTraceEvent?.('session', {
      id: 'event-1',
      sessionId: 'session',
      timestamp: new Date(),
      type: 'agent_enter',
      data: {},
    });
    child.onStateUpdate?.('session', createState());
    child.onAgentLoaded?.('session', {
      id: 'agent',
      name: 'Agent',
      domain: 'test',
      dsl: 'agent test {}',
      filePath: 'test/agent',
      type: 'agent',
      mode: 'reasoning',
      toolCount: 0,
      gatherFieldCount: 0,
      isSupervisor: false,
    });
    child.onConnected?.();
    child.onDisconnected?.();
    child.onError?.('expected child error');
    child.onInfo?.('expected child info', true);

    expect(internal.traceStore.getBySession('session')).toHaveLength(1);
    expect(internal.sessionStore.getSession('session')?.state).toEqual(createState());
    await server.stop();
  });
});
