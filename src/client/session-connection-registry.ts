import { WebSocketClient } from './websocket-client.js';

const DEFAULT_MAX_SESSION_CONNECTIONS = 32;
const DEFAULT_SESSION_CONNECTION_IDLE_TTL_MS = 30 * 60 * 1_000;
const DEFAULT_SESSION_CONNECTION_SWEEP_INTERVAL_MS = 60 * 1_000;

export interface SessionConnectionProvider {
  createForLoad(): Promise<WebSocketClient>;
  register(sessionId: string, client: WebSocketClient): void;
  get(sessionId: string): WebSocketClient | undefined;
  discard(client: WebSocketClient): void;
  clear(): void;
}

interface SessionConnectionRegistryOptions {
  maxConnections?: number;
  idleTtlMs?: number;
  sweepIntervalMs?: number;
  configureClient?: (client: WebSocketClient) => void;
  onEvict?: (sessionId: string) => void;
  createClient?: () => WebSocketClient;
}

/**
 * Owns the dedicated Runtime WebSocket used by each MCP-created debug session.
 * Runtime intentionally binds one debug session to one transport, so sharing the
 * control socket would make every new load supersede the previous session.
 */
export class SessionConnectionRegistry implements SessionConnectionProvider {
  private readonly sessions = new Map<
    string,
    { client: WebSocketClient; lastAccessedAt: number }
  >();
  private readonly pending = new Set<WebSocketClient>();
  private readonly maxConnections: number;
  private readonly idleTtlMs: number;
  private readonly sweepIntervalMs: number;
  private readonly configureClient?: (client: WebSocketClient) => void;
  private readonly onEvict?: (sessionId: string) => void;
  private readonly createClient: () => WebSocketClient;
  private sweepTimer?: ReturnType<typeof setInterval>;

  constructor(
    private readonly controlClient: WebSocketClient,
    options: SessionConnectionRegistryOptions = {},
  ) {
    this.maxConnections = options.maxConnections ?? DEFAULT_MAX_SESSION_CONNECTIONS;
    if (!Number.isInteger(this.maxConnections) || this.maxConnections < 1) {
      throw new Error('maxConnections must be a positive integer.');
    }
    this.idleTtlMs = options.idleTtlMs ?? DEFAULT_SESSION_CONNECTION_IDLE_TTL_MS;
    this.sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SESSION_CONNECTION_SWEEP_INTERVAL_MS;
    if (!Number.isInteger(this.idleTtlMs) || this.idleTtlMs < 1) {
      throw new Error('idleTtlMs must be a positive integer.');
    }
    if (!Number.isInteger(this.sweepIntervalMs) || this.sweepIntervalMs < 1) {
      throw new Error('sweepIntervalMs must be a positive integer.');
    }
    this.configureClient = options.configureClient;
    this.onEvict = options.onEvict;
    this.createClient = options.createClient ?? (() => new WebSocketClient({ reconnect: false }));
  }

  async createForLoad(): Promise<WebSocketClient> {
    if (!this.controlClient.isConnected()) {
      throw new Error('Control WebSocket is not connected.');
    }

    this.pruneExpired();
    const retainedAndPending = this.sessions.size + this.pending.size;
    const isSingleAtomicReplacement =
      this.sessions.size === this.maxConnections && this.pending.size === 0;
    if (retainedAndPending >= this.maxConnections && !isSingleAtomicReplacement) {
      throw new Error('Debug session connection capacity is currently exhausted.');
    }

    const authToken = this.controlClient.getAuthToken();
    if (!authToken?.trim()) {
      throw new Error('Control WebSocket has no authenticated session token.');
    }

    const client = this.createClient();
    client.setUrl(this.controlClient.getUrl());
    client.setAuthToken(authToken);
    this.configureClient?.(client);
    this.pending.add(client);
    this.ensureSweepTimer();

    try {
      await client.connect();
      return client;
    } catch (error) {
      this.pending.delete(client);
      client.disconnect();
      this.stopSweepTimerIfIdle();
      throw error;
    }
  }

  register(sessionId: string, client: WebSocketClient): void {
    this.pending.delete(client);
    const previous = this.sessions.get(sessionId);
    if (previous && previous.client !== client) {
      previous.client.disconnect();
    }
    this.sessions.delete(sessionId);
    this.sessions.set(sessionId, { client, lastAccessedAt: Date.now() });
    while (this.sessions.size + this.pending.size > this.maxConnections) {
      this.evictOldest();
    }
    this.ensureSweepTimer();
  }

  get(sessionId: string): WebSocketClient | undefined {
    this.pruneExpired();
    const entry = this.sessions.get(sessionId);
    if (!entry) return undefined;
    if (!entry.client.isConnected()) {
      this.removeSession(sessionId, entry.client);
      return undefined;
    }

    // Refresh insertion order so bounded eviction is least-recently-used.
    this.sessions.delete(sessionId);
    entry.lastAccessedAt = Date.now();
    this.sessions.set(sessionId, entry);
    return entry.client;
  }

  discard(client: WebSocketClient): void {
    this.pending.delete(client);
    for (const [sessionId, registered] of this.sessions) {
      if (registered.client === client) {
        this.removeSession(sessionId, client);
        return;
      }
    }
    client.disconnect();
    this.stopSweepTimerIfIdle();
  }

  clear(): void {
    const clients = new Set<WebSocketClient>(this.pending);
    const sessionIds = [...this.sessions.keys()];
    for (const { client } of this.sessions.values()) clients.add(client);
    this.pending.clear();
    this.sessions.clear();
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.sweepTimer = undefined;
    for (const client of clients) client.disconnect();
    for (const sessionId of sessionIds) this.onEvict?.(sessionId);
  }

  private evictOldest(): void {
    const oldest = this.sessions.entries().next().value as
      | [string, { client: WebSocketClient; lastAccessedAt: number }]
      | undefined;
    if (oldest) this.removeSession(oldest[0], oldest[1].client);
  }

  private removeSession(sessionId: string, client: WebSocketClient): void {
    if (this.sessions.get(sessionId)?.client !== client) return;
    this.sessions.delete(sessionId);
    client.disconnect();
    this.onEvict?.(sessionId);
    this.stopSweepTimerIfIdle();
  }

  private pruneExpired(): void {
    const expiresBefore = Date.now() - this.idleTtlMs;
    for (const [sessionId, entry] of this.sessions) {
      if (entry.lastAccessedAt <= expiresBefore) this.removeSession(sessionId, entry.client);
    }
  }

  private ensureSweepTimer(): void {
    if (this.sweepTimer) return;
    this.sweepTimer = setInterval(() => this.pruneExpired(), this.sweepIntervalMs);
    this.sweepTimer.unref?.();
  }

  private stopSweepTimerIfIdle(): void {
    if (this.sessions.size > 0 || this.pending.size > 0 || !this.sweepTimer) return;
    clearInterval(this.sweepTimer);
    this.sweepTimer = undefined;
  }
}
