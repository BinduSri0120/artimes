import { describe, expect, test } from 'vitest';
import { ABL_DOCS, DOC_TOPICS, searchDocumentation } from '../docs/index.js';
import { docs, type DocsDependencies } from '../tools/docs.js';
import type { DebugContext } from '../tools/index.js';

interface FetchCall {
  url: string;
  options: RequestInit;
  timeoutMs: number;
}

interface FetchRecorder {
  calls: FetchCall[];
  dependencies: DocsDependencies;
}

const connectedCtx = {
  httpClient: {
    getBaseUrl: () => 'http://localhost:3112',
    getAuthToken: () => 'token-123',
  },
} as unknown as DebugContext;

const disconnectedCtx = {
  httpClient: {
    getBaseUrl: () => '',
    getAuthToken: () => null,
  },
} as unknown as DebugContext;

describe('Embedded documentation fallback', () => {
  test('ABL_DOCS includes focused MCP fallback topics', () => {
    expect(ABL_DOCS['abl/flow-lifecycle']).toContain('MAX_ATTEMPTS');
    expect(ABL_DOCS['abl/flow-lifecycle']).toContain('MAX_TURNS');
    expect(ABL_DOCS['abl/flow-lifecycle']).toContain('promptless ON_INPUT');
    expect(ABL_DOCS['abl/flow-lifecycle']).toContain('max_flow_iterations');
    expect(ABL_DOCS['mcp/import-contract']).toContain('Import Preview and Apply Contract');
    expect(ABL_DOCS['mcp/behavior-profiles']).toContain('Behavior Profile Package Contract');
    expect(ABL_DOCS['mcp/abl-repair-loop']).toContain('compiledRuntimeConstraints');
    expect(ABL_DOCS['mcp/agent-tables']).toContain('Agent Tables');
    expect(ABL_DOCS['mcp/agent-tables']).toContain('Best-fit use cases');
  });

  test('DOC_TOPICS exposes topic metadata', () => {
    expect(DOC_TOPICS).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'abl/flow-lifecycle',
          title: 'FLOW Retry and Lifecycle Contract',
        }),
        expect.objectContaining({
          id: 'mcp/platform-contract',
          title: 'MCP Platform Contract',
        }),
        expect.objectContaining({
          id: 'mcp/agent-tables',
          title: 'Agent Tables MCP Guide',
        }),
      ]),
    );
  });

  test('searchDocumentation returns fallback excerpts', () => {
    expect(searchDocumentation('previewDigest')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'mcp/import-contract',
          excerpt: expect.stringContaining('previewDigest'),
        }),
      ]),
    );
  });

  test('searchDocumentation rejects empty, stop-word-only, and unrelated queries', () => {
    expect(searchDocumentation('   ')).toEqual([]);
    expect(searchDocumentation('how do I')).toEqual([]);
    expect(searchDocumentation('quuxyz-unrelated-topic')).toEqual([]);
  });

  test('searchDocumentation supports title and exact-content matches with bounded excerpts', () => {
    const titleResult = searchDocumentation('FLOW Retry and Lifecycle Contract')[0];
    const exactContentResult = searchDocumentation('session serialization')[0];

    expect(titleResult).toMatchObject({ id: 'abl/flow-lifecycle' });
    expect(titleResult?.excerpt).toContain('FLOW Retry and Lifecycle Contract');
    expect(exactContentResult).toMatchObject({ id: 'abl/flow-lifecycle' });
    expect(exactContentResult?.excerpt.replace(/\s+/gu, ' ')).toContain('session serialization');
  });

  test('searchDocumentation can return topic metadata when fallback content is unavailable', () => {
    const topicId = 'mcp/agent-tables';
    const originalContent = ABL_DOCS[topicId];
    delete ABL_DOCS[topicId];

    try {
      expect(searchDocumentation('Agent Tables MCP Guide')[0]).toMatchObject({
        id: topicId,
        excerpt: '',
      });
    } finally {
      if (originalContent !== undefined) {
        ABL_DOCS[topicId] = originalContent;
      }
    }
  });

  test.each([
    'MAX_ATTEMPTS and ON_EXHAUSTED',
    'difference between MAX_TURNS and MAX_ATTEMPTS',
    'stop reasoning after unsuccessful customer messages',
    'promptless ON_INPUT unmatched input',
    'same step transition SET runs again',
    'max_flow_iterations restored session',
  ])('finds FLOW lifecycle guidance for an agent-developer scenario: %s', (query) => {
    expect(searchDocumentation(query)[0]).toMatchObject({ id: 'abl/flow-lifecycle' });
  });
});

describe('debug_docs fallback behavior', () => {
  test('lists embedded topics when not connected', async () => {
    const result = JSON.parse(await docs({}, disconnectedCtx)) as {
      source: string;
      total: number;
    };

    expect(result.source).toBe('embedded');
    expect(result.total).toBeGreaterThan(0);
  });

  test('uses embedded search when authenticated Studio context is missing', async () => {
    const unauthenticatedCtx = {
      httpClient: {
        getBaseUrl: () => 'http://localhost:3112',
        getAuthToken: () => null,
      },
    } as unknown as DebugContext;

    const result = JSON.parse(await docs({ query: 'previewDigest' }, unauthenticatedCtx)) as {
      source: string;
      resultCount: number;
      detail: string;
    };

    expect(result.source).toBe('embedded');
    expect(result.resultCount).toBeGreaterThan(0);
    expect(result.detail).toContain('Not authenticated');
  });

  test('returns lifecycle guidance when Studio is unavailable', async () => {
    const result = JSON.parse(
      await docs({ query: 'stop reasoning after unsuccessful customer messages' }, disconnectedCtx),
    ) as {
      source: string;
      results: Array<{ id: string }>;
    };

    expect(result.source).toBe('embedded');
    expect(result.results[0]?.id).toBe('abl/flow-lifecycle');
  });

  test('lists Studio topics from the local Studio origin', async () => {
    const fetchRecorder = createFetchRecorder(
      jsonResponse({
        success: true,
        topics: [{ id: 'abl-reference/flow', title: 'Flow', category: 'ABL' }],
      }),
    );

    const result = JSON.parse(await docs({}, connectedCtx, fetchRecorder.dependencies)) as {
      source: string;
      total: number;
      availableTopics: Array<{ id: string }>;
    };

    expect(result.source).toBe('api');
    expect(result.total).toBe(1);
    expect(result.availableTopics[0]?.id).toBe('abl-reference/flow');
    expect(fetchRecorder.calls).toEqual([
      {
        url: 'http://localhost:5173/api/abl/docs',
        options: { headers: { Authorization: 'Bearer token-123' } },
        timeoutMs: 10_000,
      },
    ]);
  });

  test('returns a Studio topic when the API finds it', async () => {
    const fetchRecorder = createFetchRecorder(
      jsonResponse({
        success: true,
        topic: {
          id: 'abl-reference/flow',
          title: 'Flow',
          category: 'ABL',
          content: 'FLOW docs from Studio',
        },
      }),
    );

    const result = JSON.parse(
      await docs({ topic: 'abl-reference/flow' }, connectedCtx, fetchRecorder.dependencies),
    ) as {
      source: string;
      topic: string;
      content: string;
    };

    expect(result).toMatchObject({
      source: 'api',
      topic: 'abl-reference/flow',
      content: 'FLOW docs from Studio',
    });
    expect(fetchRecorder.calls[0]?.url).toBe(
      'http://localhost:5173/api/abl/docs?topic=abl-reference%2Fflow',
    );
  });

  test('returns embedded topics when Studio docs are unavailable', async () => {
    const fetchRecorder = createFetchRecorder(
      jsonResponse({ success: false }, { status: 404, statusText: 'Not Found' }),
    );

    const result = JSON.parse(
      await docs({ topic: 'mcp/import-contract' }, connectedCtx, fetchRecorder.dependencies),
    ) as {
      source: string;
      content: string;
      detail: string;
    };

    expect(result.source).toBe('embedded');
    expect(result.content).toContain('previewDigest');
    expect(result.detail).toContain('Failed to fetch Studio topic');
  });

  test('merges embedded search results with Studio search results', async () => {
    const fetchRecorder = createFetchRecorder(
      jsonResponse({
        success: true,
        results: [{ id: 'abl-reference/flow', title: 'Flow', excerpt: 'FLOW docs' }],
      }),
    );

    const result = JSON.parse(
      await docs({ query: 'previewDigest' }, connectedCtx, fetchRecorder.dependencies),
    ) as {
      source: string;
      resultCount: number;
      embeddedFallbackResultCount: number;
      results: Array<{ id: string }>;
    };

    expect(result.source).toBe('api');
    expect(result.embeddedFallbackResultCount).toBeGreaterThan(0);
    expect(result.results.map((entry) => entry.id)).toContain('mcp/import-contract');
    expect(result.resultCount).toBe(result.results.length);
    expect(fetchRecorder.calls[0]?.url).toBe(
      'http://localhost:5173/api/abl/docs?search=previewDigest',
    );
  });

  test('uses embedded search when Studio search fails', async () => {
    const fetchRecorder = createFetchRecorder(new Error('offline'));

    const result = JSON.parse(
      await docs({ query: 'previewDigest' }, connectedCtx, fetchRecorder.dependencies),
    ) as {
      source: string;
      detail: string;
      resultCount: number;
    };

    expect(result.source).toBe('embedded');
    expect(result.detail).toContain('Studio search failed');
    expect(result.resultCount).toBeGreaterThan(0);
  });
});

function createFetchRecorder(...responses: Array<Response | Error>): FetchRecorder {
  const calls: FetchCall[] = [];
  const queue = [...responses];
  const fetchWithTimeout: DocsDependencies['fetchWithTimeout'] = async (
    url,
    options = {},
    timeoutMs = 5000,
  ) => {
    calls.push({ url, options, timeoutMs });
    const next = queue.shift();
    if (next instanceof Error) {
      throw next;
    }
    return next ?? jsonResponse({});
  };

  return {
    calls,
    dependencies: { fetchWithTimeout },
  };
}

function jsonResponse(
  body: unknown,
  init: { status?: number; statusText?: string } = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    statusText: init.statusText ?? 'OK',
    headers: { 'Content-Type': 'application/json' },
  });
}
