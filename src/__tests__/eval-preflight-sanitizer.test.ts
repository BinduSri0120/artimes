import { describe, expect, test } from 'vitest';
import { sanitizeEvalPreflightResponse } from '../utils/eval-preflight-sanitizer.js';

describe('sanitizeEvalPreflightResponse', () => {
  test('keeps public check names stable across repeated sanitization', () => {
    const response = {
      overall: 'fail',
      checks: [{ name: 'llm_credentials', status: 'fail', code: 'MISSING_PROVIDER_KEY' }],
    };

    const once = sanitizeEvalPreflightResponse(response);
    const twice = sanitizeEvalPreflightResponse(once);

    expect(twice).toEqual(once);
    expect(once).toMatchObject({
      overall: 'fail',
      checks: [
        {
          name: 'model_credentials',
          status: 'fail',
          code: 'MISSING_PROVIDER_KEY',
        },
      ],
    });
  });

  test.each([null, 'unreadable', { overall: 'pass', checks: [] }, { overall: 'pass' }])(
    'fails closed for malformed preflight payload %#',
    (payload) => {
      const result = sanitizeEvalPreflightResponse(payload) as {
        overall: string;
        checks: Array<{ code?: string; status: string }>;
      };

      expect(result).toMatchObject({
        overall: 'fail',
        checks: [{ status: 'fail', code: 'PREFLIGHT_RESPONSE_UNREADABLE' }],
      });
    },
  );

  test('fails closed when a check fails despite a claimed passing envelope', () => {
    const result = sanitizeEvalPreflightResponse({
      overall: 'pass',
      checks: [{ name: 'runtime_auth', status: 'fail' }],
    }) as { overall: string };

    expect(result.overall).toBe('fail');
  });

  test('fails closed when the envelope status is missing or invalid', () => {
    for (const overall of [undefined, 'ready']) {
      const result = sanitizeEvalPreflightResponse({
        overall,
        checks: [{ name: 'runtime_auth', status: 'pass' }],
      }) as { overall: string };

      expect(result.overall).toBe('fail');
    }
  });

  test('preserves generated subsystem names across repeated sanitization', () => {
    const once = sanitizeEvalPreflightResponse({
      overall: 'warn',
      checks: [{ name: 'system_check_workflow_engine', status: 'warn' }],
    });

    expect(sanitizeEvalPreflightResponse(once)).toEqual(once);
    expect(once).toMatchObject({
      checks: [
        {
          name: 'system_check_workflow_engine',
          message: 'System check "workflow engine" should be reviewed before evals run.',
        },
      ],
    });
  });

  test('fails closed when an individual check is malformed', () => {
    for (const check of [
      null,
      { status: 'pass' },
      { name: 'runtime_auth', status: 'unknown' },
      { name: 'runtime_auth'.repeat(100), status: 'pass' },
    ]) {
      const result = sanitizeEvalPreflightResponse({ overall: 'pass', checks: [check] }) as {
        overall: string;
        checks: Array<{ status: string; code?: string }>;
      };
      expect(result).toMatchObject({
        overall: 'fail',
        checks: [{ status: 'fail', code: 'PREFLIGHT_CHECK_UNREADABLE' }],
      });
    }
  });

  test('bounds metadata without changing valid readiness semantics', () => {
    const result = sanitizeEvalPreflightResponse({
      overall: 'pass',
      timestamp: 'not-a-timestamp',
      checks: [{ name: 'runtime_auth', status: 'pass', durationMs: Number.MAX_SAFE_INTEGER }],
    }) as {
      overall: string;
      timestamp: string;
      checks: Array<{ durationMs: number }>;
    };

    expect(result.overall).toBe('pass');
    expect(result.timestamp).not.toBe('not-a-timestamp');
    expect(result.checks[0].durationMs).toBe(86_400_000);
  });

  test('fails closed when the check list exceeds the response bound', () => {
    const result = sanitizeEvalPreflightResponse({
      overall: 'pass',
      checks: Array.from({ length: 101 }, () => ({ name: 'runtime_auth', status: 'pass' })),
    }) as { overall: string; checks: Array<{ status: string; code?: string }> };

    expect(result).toMatchObject({
      overall: 'fail',
      checks: [{ status: 'fail', code: 'PREFLIGHT_RESPONSE_TOO_LARGE' }],
    });
  });

  test('keeps only the safe preflight envelope fields', () => {
    const result = sanitizeEvalPreflightResponse({
      success: true,
      result: { overall: 'pass', checks: [{ name: 'runtime_auth', status: 'pass' }] },
      internalDiagnostics: 'secret deployment topology',
      details: { rawProviderKey: 'do-not-return' },
    });

    expect(result).toEqual({
      success: true,
      result: {
        overall: 'pass',
        checks: [
          {
            name: 'agent_service_authorization',
            status: 'pass',
            message: 'Agent service authorization is ready.',
            durationMs: 0,
          },
        ],
        timestamp: expect.any(String),
      },
    });
  });
});
