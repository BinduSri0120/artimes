import { describe, test, expect } from 'vitest';
import { traces } from '../tools/traces.js';
import { TraceStore } from '../store/trace-store.js';
import { SessionStore } from '../store/session-store.js';
import type { DebugContext } from '../tools/index.js';
import type { TraceEventWithId } from '../types.js';

function makeEvent(i: number, sessionId: string): TraceEventWithId {
  return {
    id: `e${i}`,
    sessionId,
    type: 'tool_call',
    timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    data: {},
  } as unknown as TraceEventWithId;
}

function ctxWithEvents(events: TraceEventWithId[]): DebugContext {
  // Large buffers so the 30 seeded events are never evicted during the test.
  const traceStore = new TraceStore(10000, 10000);
  for (const e of events) traceStore.addEvent(e);
  return {
    sessionStore: new SessionStore(),
    traceStore,
    wsClient: { isConnected: () => false },
  } as unknown as DebugContext;
}

const EVENTS = Array.from({ length: 30 }, (_, i) => makeEvent(i, 'sess'));

describe('debug_traces pagination + contract (ABLP-4531)', () => {
  test('simple-get reports total, offset, limit, and is_truncated', async () => {
    const ctx = ctxWithEvents(EVENTS);
    const res = JSON.parse(await traces({ sessionId: 'sess', limit: 10, offset: 0 }, ctx));

    expect(res.success).toBe(true);
    expect(res.total).toBe(30);
    expect(res.count).toBe(10);
    expect(res.offset).toBe(0);
    expect(res.limit).toBe(10);
    expect(res.is_truncated).toBe(true);
  });

  test('offset pages through the full matched set exactly once', async () => {
    const ctx = ctxWithEvents(EVENTS);
    const p1 = JSON.parse(await traces({ sessionId: 'sess', limit: 10, offset: 0 }, ctx));
    const p2 = JSON.parse(await traces({ sessionId: 'sess', limit: 10, offset: 10 }, ctx));
    const p3 = JSON.parse(await traces({ sessionId: 'sess', limit: 10, offset: 20 }, ctx));

    const ids = [...p1.events, ...p2.events, ...p3.events].map((e: { id: string }) => e.id);
    expect(new Set(ids).size).toBe(30); // every event exactly once
    expect(p3.is_truncated).toBe(false);

    // A page past the end is empty and honest — NOT the first page again.
    const p4 = JSON.parse(await traces({ sessionId: 'sess', limit: 10, offset: 30 }, ctx));
    expect(p4.count).toBe(0);
    expect(p4.total).toBe(30);
    expect(p4.is_truncated).toBe(false);
  });

  test('non-positive / fractional limit and offset are normalized, never the whole buffer', async () => {
    const ctx = ctxWithEvents(EVENTS);

    expect(JSON.parse(await traces({ sessionId: 'sess', limit: 0 }, ctx)).count).toBe(1);
    expect(JSON.parse(await traces({ sessionId: 'sess', limit: -5 }, ctx)).count).toBe(1);
    expect(JSON.parse(await traces({ sessionId: 'sess', limit: 3.9 }, ctx)).count).toBe(3);

    const negOffset = JSON.parse(await traces({ sessionId: 'sess', limit: 5, offset: -3 }, ctx));
    expect(negOffset.offset).toBe(0);
    expect(negOffset.count).toBe(5);
  });

  test('search mode also reports total/offset/is_truncated (totalMatches kept for compat)', async () => {
    const ctx = ctxWithEvents(EVENTS);
    const res = JSON.parse(
      await traces({ sessionId: 'sess', hasError: false, limit: 10, offset: 0 }, ctx),
    );

    expect(res.total).toBe(30);
    expect(res.totalMatches).toBe(30);
    expect(res.count).toBe(10);
    expect(res.is_truncated).toBe(true);
    expect(res.events.map((event: { id: string }) => event.id)).toEqual(
      EVENTS.slice(-10)
        .reverse()
        .map((event) => event.id),
    );
  });

  test('reports bounded session retention without inflating the retained total', async () => {
    const traceStore = new TraceStore(10, 2);
    for (const event of EVENTS.slice(0, 3)) traceStore.addEvent(event);
    const ctx = {
      sessionStore: new SessionStore(),
      traceStore,
      wsClient: { isConnected: () => false },
    } as unknown as DebugContext;

    const res = JSON.parse(await traces({ sessionId: 'sess', limit: 10 }, ctx));

    expect(res.total).toBe(2);
    expect(res.count).toBe(2);
    expect(res.is_truncated).toBe(true);
    expect(res.retention).toEqual({
      max_size: 2,
      retained_count: 2,
      evicted_count: 1,
      is_truncated: true,
    });
  });
});
