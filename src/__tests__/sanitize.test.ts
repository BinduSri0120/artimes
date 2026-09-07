import { describe, expect, it } from 'vitest';
import {
  findSensitiveFieldPath,
  findSensitiveFieldPathBounded,
  sanitizeResponse,
  sanitizeResponseBounded,
} from '../utils/sanitize.js';
import {
  containsEmbeddedWorkflowCredentialLiteral,
  isWorkflowSourceCodePath,
  redactEmbeddedWorkflowCredentialLiterals,
  WORKFLOW_SOURCE_SANITIZER_POLICY,
} from '../utils/workflow-source.js';

describe('sanitizer path policies', () => {
  const source = 'const token = tokenStep.access_token || fallback;';

  it('preserves only the explicit workflow source path and still protects structured secrets', () => {
    const payload = {
      data: {
        nodes: [{ config: { code: source, accessToken: 'secret-value' } }],
        summary: 'authorization=secret-value',
      },
    };

    expect(findSensitiveFieldPath(payload, '', WORKFLOW_SOURCE_SANITIZER_POLICY)).toBe(
      'data.nodes[0].config.accessToken',
    );
    expect(sanitizeResponse(payload, WORKFLOW_SOURCE_SANITIZER_POLICY)).toEqual({
      data: {
        nodes: [{ config: { code: source, accessToken: '[REDACTED]' } }],
        summary: 'authorization=[REDACTED]',
      },
    });
    expect(isWorkflowSourceCodePath('nodes[0].config.code')).toBe(true);
    expect(isWorkflowSourceCodePath('data.nodes[12].config.code')).toBe(true);
    expect(isWorkflowSourceCodePath('nodes[0].config.description')).toBe(false);
  });

  it('rejects and redacts credential literals embedded in workflow source', () => {
    const literalSource = "const auth = 'Authorization: Bearer ablp4181-secret';";
    const payload = { nodes: [{ config: { code: literalSource } }] };

    expect(findSensitiveFieldPath(payload, '', WORKFLOW_SOURCE_SANITIZER_POLICY)).toBe(
      'nodes[0].config.code',
    );
    expect(sanitizeResponse(payload, WORKFLOW_SOURCE_SANITIZER_POLICY)).toEqual({
      nodes: [{ config: { code: "const auth = '[REDACTED]';" } }],
    });

    const assignment = { nodes: [{ config: { code: "const token = 'secret-value';" } }] };
    expect(findSensitiveFieldPath(assignment, '', WORKFLOW_SOURCE_SANITIZER_POLICY)).toBe(
      'nodes[0].config.code',
    );
    expect(sanitizeResponse(assignment, WORKFLOW_SOURCE_SANITIZER_POLICY)).toEqual({
      nodes: [{ config: { code: "const token = '[REDACTED]';" } }],
    });

    const quotedHeader = {
      nodes: [{ config: { code: 'const headers = {"X-API-Key": "ablp4181-secret"};' } }],
    };
    expect(findSensitiveFieldPath(quotedHeader, '', WORKFLOW_SOURCE_SANITIZER_POLICY)).toBe(
      'nodes[0].config.code',
    );
    expect(sanitizeResponse(quotedHeader, WORKFLOW_SOURCE_SANITIZER_POLICY)).toEqual({
      nodes: [{ config: { code: 'const headers = {"X-API-Key": "[REDACTED]"};' } }],
    });
  });

  it('uses JavaScript syntax rather than quote scanning for source credential literals', () => {
    const source = [
      'const quote = /"/;',
      'const token = "ablp4181-secret";',
      'const headers = {["X-API-Key"]: "another-secret"};',
      'const guidance = "Use Bearer token authentication";',
    ].join('\n');

    expect(containsEmbeddedWorkflowCredentialLiteral(source)).toBe(true);
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      [
        'const quote = /"/;',
        'const token = "[REDACTED]";',
        'const headers = {["X-API-Key"]: "[REDACTED]"};',
        'const guidance = "Use Bearer token authentication";',
      ].join('\n'),
    );
  });

  it('fails closed when workflow source cannot be parsed', () => {
    const source = 'const token = "secret"; {';
    expect(containsEmbeddedWorkflowCredentialLiteral(source)).toBe(true);
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe('[REDACTED]');
  });

  it('deduplicates semantic and embedded matches for one credential literal', () => {
    const source = 'const authorization = "Bearer ablp4181-secret";\nreturn authorization;';
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      'const authorization = "[REDACTED]";\nreturn authorization;',
    );
  });

  it('redacts credential literals in comments and static string composition', () => {
    const source = [
      '// token = "ablp4181-secret"',
      '/* Authorization: Bearer ablp4181-secret */',
      'const token = "ablp4181-" + "secret";',
    ].join('\n');

    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      ['//[REDACTED]', '/*[REDACTED]*/', 'const token = "[REDACTED]";'].join('\n'),
    );
  });

  it('covers member assignments, static templates, URLs, and safe dynamic composition', () => {
    const sensitive = [
      'headers.authorization = `ablp4181-${"secret"}`;',
      'const token = "ablp4181-" + 7;',
      'const endpoint = "https://user:password@example.test/path";',
      '// ordinary explanation',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(sensitive)).toBe(
      [
        'headers.authorization = `[REDACTED]`;',
        'const token = "[REDACTED]";',
        'const endpoint = "https://[REDACTED]@example.test/path";',
        '// ordinary explanation',
      ].join('\n'),
    );

    const dynamic = 'const token = prefix + getSecret();\nconst note = "Bearer token";';
    expect(redactEmbeddedWorkflowCredentialLiterals(dynamic)).toBe(dynamic);
  });

  it('redacts sensitive conditional and logical branches without corrupting adjacent source', () => {
    const conditional =
      'const token = flag ? "ablp4181-secret-a" : "ablp4181-secret-b";\nreturn token;';
    expect(redactEmbeddedWorkflowCredentialLiterals(conditional)).toBe(
      'const token = flag ? "[REDACTED]" : "[REDACTED]";\nreturn token;',
    );

    const logical = 'const token = supplied || "ablp4181-secret-fallback";\nreturn token;';
    expect(redactEmbeddedWorkflowCredentialLiterals(logical)).toBe(
      'const token = supplied || "[REDACTED]";\nreturn token;',
    );

    const overlapping = 'const token = "Bearer ablp4181-secret" + "suffix";\nreturn payload;';
    expect(redactEmbeddedWorkflowCredentialLiterals(overlapping)).toBe(
      'const token = "[REDACTED]";\nreturn payload;',
    );
  });

  it('preserves benign literals assigned to credential-shaped identifiers', () => {
    const source = [
      'const token = "disabled";',
      'const cookie = "unavailable";',
      '// token = disabled',
      'const note = "token=disabled";',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(source);
  });

  it('redacts alphabetic passwords and sensitive default/property initializers', () => {
    const source = [
      'const password = "huntertwo";',
      'async function request(token = "ablp4181-secret") { return token; }',
      'const [cookie = "sessionsecret"] = [];',
      'class Client { password = "classsecret"; }',
      'class Vault { #password = "privateclasssecret"; }',
      'const weak = { password: "test" };',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      [
        'const password = "[REDACTED]";',
        'async function request(token = "[REDACTED]") { return token; }',
        'const [cookie = "[REDACTED]"] = [];',
        'class Client { password = "[REDACTED]"; }',
        'class Vault { #password = "[REDACTED]"; }',
        'const weak = { password: "[REDACTED]" };',
      ].join('\n'),
    );
  });

  it('redacts quoted multi-word credentials and preserves ordinary methods', () => {
    const sensitive = [
      '// password = "correct horse battery"',
      '/* {"password": "correct horse battery"} */',
      'const note = \'password="correct horse battery"\';',
      'const escaped = \'password="correct \\"horse\\" battery"\';',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(sensitive)).toBe(
      [
        '//[REDACTED]',
        '/*[REDACTED]*/',
        "const note = 'password=[REDACTED]';",
        "const escaped = 'password=[REDACTED]';",
      ].join('\n'),
    );

    const functions = [
      'const parser = { parse() { return "identifier-name"; } };',
      'metadata.set("token", "identifier-name");',
      'const docs = "Use Bearer authorization for this request";',
      'const pluralDocs = "Use Bearer tokens with this API";',
      'const mechanismDocs = "Use Bearer mechanism for this API";',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(functions)).toBe(functions);

    const composite = 'const token = { type: "identifier", value: "hello" };';
    expect(redactEmbeddedWorkflowCredentialLiterals(composite)).toContain('[REDACTED]');
  });

  it('redacts credential literals in header setter calls and short bearer values', () => {
    const source = [
      'headers.set("Authorization", "Bearer huntertwo");',
      'request.setHeader("X-API-Key", "shortkey");',
      'const docs = "Use Bearer authentication";',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      [
        'headers.set("Authorization", "[REDACTED]");',
        'request.setHeader("X-API-Key", "[REDACTED]");',
        'const docs = "Use Bearer authentication";',
      ].join('\n'),
    );
  });

  it('redacts high-confidence credentials returned by credential-named functions', () => {
    const source = [
      'const token = () => "ablp4181-secret";',
      'const parser = { token() { return "ablp4181-secret"; } };',
      'class Provider { token() { return "ablp4181-secret"; } }',
      'const auth = "Authorization: Bearer secret";',
      'const password = useFallback ? "huntertwo" : "letmein";',
      'class Vault { password() { return "huntertwo"; } }',
      'const shortAuth = "Authorization: Bearer abc123";',
      'const apiKey = useFallback ? "huntertwo" : "letmein";',
      'const clientSecret = String("huntertwo");',
      'const refreshToken = String.raw`huntertwo`;',
      'const accessToken = () => "identifier-name";',
      'const shortAuthWord = "Authorization: Bearer hunter";',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      [
        'const token = () => "[REDACTED]";',
        'const parser = { token() { return "[REDACTED]"; } };',
        'class Provider { token() { return "[REDACTED]"; } }',
        'const auth = "[REDACTED]";',
        'const password = useFallback ? "[REDACTED]" : "[REDACTED]";',
        'class Vault { password() { return "[REDACTED]"; } }',
        'const shortAuth = "Authorization: Bearer [REDACTED]";',
        'const apiKey = useFallback ? "[REDACTED]" : "[REDACTED]";',
        'const clientSecret = String("[REDACTED]");',
        'const refreshToken = String.raw`[REDACTED]`;',
        'const accessToken = () => "[REDACTED]";',
        'const shortAuthWord = "Authorization: Bearer [REDACTED]";',
      ].join('\n'),
    );
  });

  it.each([
    ['const password = "huntertwo".trim();', 'const password = "[REDACTED]".trim();'],
    ['const password = (() => "huntertwo")();', 'const password = (() => "[REDACTED]")();'],
    ['const password = (candidate = "huntertwo");', 'const password = (candidate = "[REDACTED]");'],
    ['const password = ["huntertwo"].at(0);', 'const password = ["[REDACTED]"].at(0);'],
    [
      'const password = ({ value: "huntertwo" }).value;',
      'const password = ({ value: "[REDACTED]" }).value;',
    ],
    ['const password = prefix + "huntertwo";', 'const password = prefix + "[REDACTED]";'],
  ])('redacts credential values extracted through expression wrappers: %s', (source, expected) => {
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(expected);
  });

  it('supports constructed and factory-returned Headers without treating Map#set as headers', () => {
    const source = [
      'new Headers().set("Authorization", "huntertwo");',
      'getHeaders().append("X-API-Key", "huntertwo");',
      'metadata.set("token", "identifier-name");',
      'new globalThis.Headers().set("Authorization", "huntertwo");',
      'response.getHeaders().set("Authorization", "huntertwo");',
      'notHeaders().set("token", "identifier-name");',
      'headers.set("Authorization", "huntertwo".trim());',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(
      [
        'new Headers().set("Authorization", "[REDACTED]");',
        'getHeaders().append("X-API-Key", "[REDACTED]");',
        'metadata.set("token", "identifier-name");',
        'new globalThis.Headers().set("Authorization", "[REDACTED]");',
        'response.getHeaders().set("Authorization", "[REDACTED]");',
        'notHeaders().set("token", "identifier-name");',
        'headers.set("Authorization", "[REDACTED]".trim());',
      ].join('\n'),
    );
  });

  it('governs collection literals assigned to credential-shaped variables', () => {
    const source = [
      'const token = { algorithm: "sha256", version: "v2" };',
      'const cookie = { role: "secretary" };',
    ].join('\n');
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).not.toBe(source);
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).not.toContain('sha256');
  });

  it('does not treat nested helper returns as credential-function return values', () => {
    const source =
      'const password = () => { function status() { return "ready"; } return configuredPassword; };';
    expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(source);
  });

  it('redacts dynamic templates, mixed prose/auth text, header tuples, and spreads', () => {
    const cases = [
      ['const password = `prefix-${"huntertwo"}-${suffix}`;', 'const password = "[REDACTED]";'],
      [
        'const password = redactTag`prefix-${"huntertwo"}-${suffix}`;',
        'const password = redactTag`[REDACTED]`;',
      ],
      [
        'const note = "Use Bearer authentication; current Authorization: Bearer abc123";',
        'const note = "Use Bearer authentication; current Authorization: Bearer [REDACTED]";',
      ],
      [
        'headers.set(...["Authorization", "huntertwo"]);',
        'headers.set(...["Authorization", "[REDACTED]"]);',
      ],
      [
        'new Headers([["Authorization", "huntertwo"]]);',
        'new Headers([["Authorization", "[REDACTED]"]]);',
      ],
      [
        'new Headers([...[["Authorization", "huntertwo"]]]);',
        'new Headers([...[["Authorization", "[REDACTED]"]]]);',
      ],
      [
        'new Headers(...[[["Authorization", "huntertwo"]]]);',
        'new Headers(...[[["Authorization", "[REDACTED]"]]]);',
      ],
      [
        'new Headers(new Map([["Authorization", "huntertwo"]]));',
        'new Headers(new Map([["Authorization", "[REDACTED]"]]));',
      ],
      [
        'new Headers(new Map(...[[["Authorization", "huntertwo"]]]));',
        'new Headers(new Map(...[[["Authorization", "[REDACTED]"]]]));',
      ],
      [
        'headers.set(...[...["Authorization", "huntertwo"]]);',
        'headers.set(...[...["Authorization", "[REDACTED]"]]);',
      ],
      [
        'const password = [...["huntertwo"]].join("");',
        'const password = [...["[REDACTED]"]].join("[REDACTED]");',
      ],
      [
        'const password = {...{value: "huntertwo"}};',
        'const password = {...{value: "[REDACTED]"}};',
      ],
      [
        'const password = ({...{value: "huntertwo"}}).value;',
        'const password = ({...{value: "[REDACTED]"}}).value;',
      ],
    ] as const;
    for (const [source, expected] of cases) {
      expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(expected);
    }

    for (const safeMode of [
      'const auth = "oauth2";',
      'const auth = "disabled";',
      'const auth = "bearer";',
      'const auth = "jwt";',
      'const docs = "Use standard Bearer mechanism";',
      'const docs = "Use Bearer token.";',
      'const docs = "Use Bearer (token) authentication";',
      'const docs = "Use Bearer **token** authentication";',
      'const docs = "Use Bearer token-based authentication";',
      'const docs = "Use Bearer access token authentication";',
      'const docs = "Use Bearer RFC 6750 authentication";',
      'const auth = "apiKey";',
      'const auth = "oidc";',
      'const auth = "saml";',
    ]) {
      expect(redactEmbeddedWorkflowCredentialLiterals(safeMode)).toBe(safeMode);
    }

    for (const sensitiveCollection of [
      'const token = ["ablp4181-secret"];',
      'const cookie = ["sessionsecret"];',
      'const token = { value: "ablp4181-secret" };',
      'const token = () => ["ablp4181-secret"];',
      'const token = ["sk_live_abc123"];',
      'const cookie = ["sess_abc123xyz"];',
      'const token = ["eyJhbGciOiJIUzI1NiJ9.abc.sig"];',
      'const token = ["identifier", "punctuation"];',
      'const cookie = ["chocolate", "oatmeal"];',
      'const token = { type: "password reset" };',
    ]) {
      expect(redactEmbeddedWorkflowCredentialLiterals(sensitiveCollection)).toContain('[REDACTED]');
    }
    expect(redactEmbeddedWorkflowCredentialLiterals('const apiKey = "oauth2";')).toBe(
      'const apiKey = "[REDACTED]";',
    );
    expect(redactEmbeddedWorkflowCredentialLiterals('const accessToken = "jwt";')).toBe(
      'const accessToken = "[REDACTED]";',
    );
  });

  it('covers additional expression and header-dispatch branches', () => {
    const cases = [
      ['const password = (0, "huntertwo");', 'const password = (0, "[REDACTED]");'],
      [
        'const password = await String("huntertwo");',
        'const password = await String("[REDACTED]");',
      ],
      ['const password = new String("huntertwo");', 'const password = new String("[REDACTED]");'],
      ['const password = [, "huntertwo"];', 'const password = [, "[REDACTED]"];'],
      [
        'const password = ({ ["value"]: "huntertwo" }).value;',
        'const password = ({ ["value"]: "[REDACTED]" }).value;',
      ],
      [
        'response.headers.set("Authorization", "huntertwo");',
        'response.headers.set("Authorization", "[REDACTED]");',
      ],
      [
        'createHeaders().append("X-API-Key", "huntertwo");',
        'createHeaders().append("X-API-Key", "[REDACTED]");',
      ],
    ] as const;
    for (const [source, expected] of cases) {
      expect(redactEmbeddedWorkflowCredentialLiterals(source)).toBe(expected);
    }

    for (const safe of [
      'metadata.set("ordinary", "value");',
      'metadata.set("token");',
      'new Map();',
      'new Headers();',
    ]) {
      expect(redactEmbeddedWorkflowCredentialLiterals(safe)).toBe(safe);
    }
  });

  it('does not confuse credential-related identifiers with literal credentials', () => {
    const source = 'const bearer = tokenStep.access_token || fallback;';
    const payload = { nodes: [{ config: { code: source } }] };

    expect(findSensitiveFieldPath(payload, '', WORKFLOW_SOURCE_SANITIZER_POLICY)).toBeNull();
    expect(sanitizeResponse(payload, WORKFLOW_SOURCE_SANITIZER_POLICY)).toEqual(payload);
  });

  it('retains default scanning and redaction behavior outside the policy path', () => {
    expect(findSensitiveFieldPath(['safe', 'Bearer raw-value'])).toBe('[1]');
    expect(findSensitiveFieldPath({ safe: 'value' })).toBeNull();
    expect(findSensitiveFieldPath(null)).toBeNull();
    expect(sanitizeResponse(['safe', 'Basic raw-value', 2, null])).toEqual([
      'safe',
      'Basic [REDACTED]',
      2,
      null,
    ]);
    expect(sanitizeResponse(undefined)).toBeUndefined();
  });

  it('applies the same path policy to bounded traversal', () => {
    const payload = {
      nodes: [{ config: { code: source } }],
      nested: [{ password: 'secret-value' }],
    };
    const options = { preserveStringAtPath: isWorkflowSourceCodePath };

    expect(findSensitiveFieldPathBounded(payload, options)).toBe('nested[0].password');
    expect(sanitizeResponseBounded(payload, options)).toEqual({
      nodes: [{ config: { code: source } }],
      nested: [{ password: '[REDACTED]' }],
    });
  });

  it('bounds depth, arrays, strings, and object keys', () => {
    expect(() =>
      findSensitiveFieldPathBounded({ nested: { value: 'safe' } }, { maxDepth: 1 }),
    ).toThrow('maximum depth');
    expect(() => sanitizeResponseBounded(['a', 'b'], { maxArrayItems: 1 })).toThrow(
      'maximum array items',
    );
    expect(() => sanitizeResponseBounded('long', { maxStringLength: 3 })).toThrow(
      'maximum string length',
    );
    expect(() => findSensitiveFieldPathBounded({ a: 1, b: 2 }, { maxObjectKeys: 1 })).toThrow(
      'maximum object keys',
    );
  });

  it('handles cycles, Error properties, and unreadable values without leaking', () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(findSensitiveFieldPathBounded(cycle)).toBeNull();
    expect(sanitizeResponseBounded(cycle)).toEqual({ self: '[CIRCULAR]' });

    const error = new Error('authorization=secret-value') as Error & { token?: string };
    error.token = 'secret-value';
    expect(sanitizeResponseBounded(error)).toEqual({
      name: 'Error',
      message: 'authorization=[REDACTED]',
      token: '[REDACTED]',
    });

    const unreadable = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(unreadable, 'value', {
      enumerable: true,
      get() {
        throw new Error('unreadable');
      },
    });
    expect(sanitizeResponseBounded(unreadable)).toEqual({ value: '[UNREADABLE]' });
  });
});
