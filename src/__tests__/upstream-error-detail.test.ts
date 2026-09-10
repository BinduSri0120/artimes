import { describe, expect, it } from 'vitest';
import {
  buildUpstreamErrorMessage,
  describeUpstreamError,
} from '../tools/upstream-error-detail.js';

describe('describeUpstreamError', () => {
  it('lifts a structured route error', () => {
    // The live case: the caller only ever saw "500 Internal Server Error" while
    // the cause sat two levels down, so agent clients reported an outage.
    expect(
      describeUpstreamError({
        success: false,
        error: {
          code: 'STAGING_FAILED',
          message: 'two records share the same unique key',
          stage: 'apply',
        },
      }),
    ).toBe('STAGING_FAILED: two records share the same unique key');
  });

  it('accepts a code or a message alone', () => {
    expect(describeUpstreamError({ error: { code: 'IMPORT_LOCKED' } })).toBe('IMPORT_LOCKED');
    expect(describeUpstreamError({ error: { message: 'Project not found' } })).toBe(
      'Project not found',
    );
  });

  it('handles a legacy string error and a validation envelope', () => {
    expect(describeUpstreamError({ error: 'Agent not found' })).toBe('Agent not found');
    expect(
      describeUpstreamError({
        success: false,
        errors: [{ msg: 'Not found', code: 'NOT_FOUND' }],
      }),
    ).toBe('NOT_FOUND: Not found');
  });

  it('falls back to a top-level message', () => {
    expect(describeUpstreamError({ message: 'Rate limit exceeded' })).toBe('Rate limit exceeded');
  });

  it('returns null when the body adds nothing', () => {
    expect(describeUpstreamError(undefined)).toBeNull();
    expect(describeUpstreamError({})).toBeNull();
    expect(describeUpstreamError({ error: {} })).toBeNull();
    expect(describeUpstreamError({ error: '   ' })).toBeNull();
    expect(describeUpstreamError([1, 2, 3])).toBeNull();
  });

  it('reads a plain string body', () => {
    expect(describeUpstreamError('Bad Gateway')).toBe('Bad Gateway');
  });
});

describe('buildUpstreamErrorMessage', () => {
  it('appends the upstream cause to the request summary', () => {
    expect(
      buildUpstreamErrorMessage('POST /api/projects/p1/import/apply', 409, 'Conflict', {
        error: { code: 'STAGING_FAILED', message: 'two records share the same unique key' },
      }),
    ).toBe(
      'POST /api/projects/p1/import/apply failed: 409 Conflict: STAGING_FAILED: two records share the same unique key',
    );
  });

  it('keeps the bare status line when there is no cause to add', () => {
    expect(buildUpstreamErrorMessage('GET /api/projects/p1', 502, 'Bad Gateway', {})).toBe(
      'GET /api/projects/p1 failed: 502 Bad Gateway',
    );
  });
});
