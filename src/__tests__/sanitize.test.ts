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

const PROVIDER_SECRET_CASES = [
  ['PEM private key', '-----BEGIN PRIVATE KEY-----\nSYNTHETICKEYBODY\n-----END PRIVATE KEY-----'],
  ['secret template', '{{ secrets.synthetic_runtime_key }}'],
  ['AWS access key', `AKIA${'A'.repeat(16)}`],
  ['ABL token', `abl_${'a'.repeat(20)}`],
  ['OpenAI project key', `sk-proj-${'a'.repeat(24)}`],
  ['Stripe secret key', `sk_live_${'a'.repeat(20)}`],
  ['GitHub token', `ghp_${'a'.repeat(20)}`],
  ['Google API key', `AIza${'A'.repeat(35)}`],
  ['Slack token', `xoxb-${'a'.repeat(12)}`],
  ['SendGrid token', `SG.${'a'.repeat(22)}.${'b'.repeat(43)}`],
  ['Twilio key', `SK${'a'.repeat(32)}`],
  ['npm token', `npm_${'a'.repeat(36)}`],
  ['PyPI token', `pypi-AgEIcHlwaS5vcmc${'a'.repeat(50)}`],
  ['JWT', `eyJ${'a'.repeat(12)}.${'b'.repeat(16)}.${'c'.repeat(16)}`],
] as const;

const SENSITIVE_DYNAMIC_KEY_CASES = [
  'clientSecret',
  'service_password_v2',
  'oauthAccessToken',
  'databaseCredential',
  'xApiKey',
  'privateKeyPem',
] as const;

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

  it('redacts provider tokens and credential material embedded in dynamic keys', () => {
    const input = {
      'owner@example.test': 'tier-1',
      'api_key=topsecret': 'tier-2',
      prompt: 'Use sk-proj-abcdefghijklmnopqrstuvwxyz1234567890',
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      const serialized = JSON.stringify(result);
      expect(serialized).toContain('owner@example.test');
      expect(serialized).not.toContain('topsecret');
      expect(serialized).not.toContain('sk-proj-abcdefghijklmnopqrstuvwxyz1234567890');
    }
    expect(findSensitiveFieldPath(input)).toBe('[REDACTED_KEY]');
    expect(findSensitiveFieldPathBounded(input)).toBe('[REDACTED_KEY]');
  });

  it('keeps broad PII redaction scoped to strict Runtime-config policy', () => {
    const input = {
      owner: 'owner@example.test',
      sessionId: '1700000000000',
      url: 'https://example.test/sessions/1700000000000',
      phone: '+1 (202) 555-0123',
    };

    expect(sanitizeResponse(input)).toEqual(input);
    expect(sanitizeResponseBounded(input)).toEqual(input);
    for (const result of [
      sanitizeResponse(input, { redactPii: true, redactUrlLocations: true }),
      sanitizeResponseBounded(input, { redactPii: true, redactUrlLocations: true }),
    ]) {
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('owner@example.test');
      expect(serialized).not.toContain('1700000000000');
      expect(serialized).not.toContain('555-0123');
    }
  });

  it('preserves the SDK public-key identifier while still scanning its value for secrets', () => {
    const publicReference = { publicApiKeyId: 'key-1' };
    const secretReference = {
      publicApiKeyId: `sk-proj-${'a'.repeat(24)}`,
    };

    expect(findSensitiveFieldPath(publicReference)).toBeNull();
    expect(findSensitiveFieldPathBounded(publicReference)).toBeNull();
    expect(sanitizeResponse(publicReference)).toEqual(publicReference);
    expect(sanitizeResponseBounded(publicReference)).toEqual(publicReference);

    expect(findSensitiveFieldPath(secretReference)).toBe('publicApiKeyId');
    expect(findSensitiveFieldPathBounded(secretReference)).toBe('publicApiKeyId');
    expect(sanitizeResponse(secretReference)).toEqual({ publicApiKeyId: '[REDACTED]' });
    expect(sanitizeResponseBounded(secretReference)).toEqual({ publicApiKeyId: '[REDACTED]' });
  });

  it('preserves credential metadata keys while still scanning their values', () => {
    const metadata = {
      hasCredentials: true,
      requiredCredentials: [
        'apiKey',
        'password',
        'bot_token',
        'signing_secret',
        'app_id',
        'client_secret',
        'tenant_id',
        'outboundWebhookSignatureSecretToken',
      ],
      apiKeyId: 'key-reference-1',
      apiKeyPrefix: 'sk-proj-',
      credentialStatus: 'configured',
      credentialType: 'oauth',
      passwordPolicy: 'workspace-default',
      secretConfigured: true,
      webhookSecretConfigured: false,
      secretCount: 2,
      allowedSecretCount: 5,
      credentialName: 'Primary Key',
      credentialPolicy: 'tenant',
      secretName: 'database',
    };
    const metadataWithSecret = {
      ...metadata,
      credentialType: `sk-proj-${'a'.repeat(24)}`,
    };

    for (const sanitize of [
      sanitizeResponse,
      sanitizeResponseBounded,
      (value: unknown) => sanitizeResponse(value, { redactPii: true, redactUrlLocations: true }),
      (value: unknown) =>
        sanitizeResponseBounded(value, { redactPii: true, redactUrlLocations: true }),
    ]) {
      expect(sanitize(metadata)).toEqual(metadata);
      expect(sanitize(metadataWithSecret)).toEqual({
        ...metadata,
        credentialType: '[REDACTED]',
      });
    }
    for (const find of [findSensitiveFieldPath, findSensitiveFieldPathBounded]) {
      expect(find(metadata)).toBeNull();
      expect(find(metadataWithSecret)).toBe('credentialType');
    }
  });

  it('preserves global credential metadata contracts while strict Runtime policy fails closed', () => {
    const valid = {
      hasPassword: false,
      secretConfigured: true,
      secretCount: 0,
      requiredCredentials: ['apiKey', 'password'],
      clientSecretId: 'client-secret-123',
      apiKeyId: 'key-reference-1',
      credentialType: 'oauth',
    };
    const contractDerived = {
      credentialType: 'certificate',
      fallbackCredentialType: 'aws_credentials',
      azureCredentialType: 'DefaultAzureCredential',
      monitorCredentialType: 'AuthProfile',
      credentialStatus: 'expired',
      credentialName: 'Primary Key',
      credentialPolicy: 'tenant',
      secretName: 'database',
      apiKeyPrefix: 'abl_aaaa',
    };
    const invalid = {
      hasPassword: 'huntertwo',
      requiredAccessToken: 'huntertwo',
      clientSecretId: 'huntertwo',
      apiKeyId: 'huntertwo',
      credentialType: 'huntertwo',
    };

    for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
      expect(sanitize(valid)).toEqual(valid);
      expect(sanitize(contractDerived)).toEqual(contractDerived);
      expect(sanitize(invalid)).toEqual(invalid);
    }
    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      expect(sanitize(invalid)).toEqual({
        hasPassword: '[REDACTED]',
        requiredAccessToken: '[REDACTED]',
        clientSecretId: '[REDACTED]',
        apiKeyId: '[REDACTED]',
        credentialType: '[REDACTED]',
      });
    }
    for (const find of [findSensitiveFieldPath, findSensitiveFieldPathBounded]) {
      expect(find(valid)).toBeNull();
      expect(find(invalid)).toBeNull();
    }
    expect(findSensitiveFieldPath(invalid, '', { allowCredentialMetadata: false })).toBe(
      'hasPassword',
    );
    expect(findSensitiveFieldPathBounded(invalid, { allowCredentialMetadata: false })).toBe(
      'hasPassword',
    );
  });

  it('preserves nullable and open global metadata shapes while deep-scanning their values', () => {
    const nullableMetadata = {
      credentialId: null,
      authProfileId: 'auth-profile-123',
      tlsAuthProfileId: 'tls-auth-profile-123',
      apiKeyId: null,
      apiKeyPrefix: null,
      managedCredentialKey: null,
      credentialProvider: null,
    };
    const invalidMetadata = {
      credentialId: { unexpected: true },
      apiKeyPrefix: false,
      managedCredentialKey: { unexpected: true },
      credentialProvider: `sk-proj-${'a'.repeat(24)}`,
    };

    for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
      expect(sanitize(nullableMetadata)).toEqual(nullableMetadata);
      expect(sanitize(invalidMetadata)).toEqual({
        credentialId: { unexpected: true },
        apiKeyPrefix: false,
        managedCredentialKey: { unexpected: true },
        credentialProvider: '[REDACTED]',
      });
    }
    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      expect(sanitize(nullableMetadata)).toEqual({
        credentialId: '[REDACTED]',
        authProfileId: '[REDACTED]',
        tlsAuthProfileId: '[REDACTED]',
        apiKeyId: '[REDACTED]',
        apiKeyPrefix: '[REDACTED]',
        managedCredentialKey: '[REDACTED]',
        credentialProvider: '[REDACTED]',
      });
      expect(sanitize(invalidMetadata)).toEqual({
        credentialId: '[REDACTED]',
        apiKeyPrefix: '[REDACTED]',
        managedCredentialKey: '[REDACTED]',
        credentialProvider: '[REDACTED]',
      });
    }
    for (const find of [findSensitiveFieldPath, findSensitiveFieldPathBounded]) {
      expect(find(nullableMetadata)).toBeNull();
      expect(find(invalidMetadata)).toBe('credentialProvider');
    }
  });

  it('preserves contract-derived managed credential and provider discriminators', () => {
    const validMetadataRows = [
      { managedCredentialKey: 'platform-llm', credentialProvider: 'openai' },
      { managedCredentialKey: 'platform-openai' },
      { managedCredentialKey: 'test-kg-model' },
      { credentialProvider: 'my-provider' },
      { credentialProvider: 'huntertwo' },
    ];
    const invalidMetadata = {
      managedCredentialKey: `sk-proj-${'a'.repeat(24)}`,
      credentialProvider: { unexpected: true },
    };

    for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
      for (const validMetadata of validMetadataRows) {
        expect(sanitize(validMetadata)).toEqual(validMetadata);
      }
      expect(sanitize(invalidMetadata)).toEqual({
        managedCredentialKey: '[REDACTED]',
        credentialProvider: { unexpected: true },
      });
    }
    for (const find of [findSensitiveFieldPath, findSensitiveFieldPathBounded]) {
      for (const validMetadata of validMetadataRows) expect(find(validMetadata)).toBeNull();
      expect(find(invalidMetadata)).toBe('managedCredentialKey');
    }
  });

  it('preserves the complete global credential-source contract and rejects it in strict policy', () => {
    const modelResolutionSources = [
      'project_auth_profile',
      'project_credential',
      'tenant_model_connection',
      'user_default_credential',
      'tenant_default_credential',
      'unknown',
    ];
    const routeResponse = {
      tenantModel: {
        credentialSource: 'platform',
        credentialScope: 'tenant',
        credentialReadiness: 'ready',
      },
      voiceProvider: {
        credentialMode: 'managed',
        credentialScope: 'service-provider',
      },
      searchConnector: { credentialMode: 'auth_profile' },
      toolAuthority: { credentialMode: 'session' },
      embeddingWorker: { credentialSource: 'llm-credential' },
      archModel: { credentialSource: 'model_hub' },
      resolutionSources: modelResolutionSources.map((credentialSource) => ({ credentialSource })),
    };
    const invalid = {
      credentialSource: 'ambient',
      credentialScope: { tenant: true },
      credentialMode: `Bearer ${'a'.repeat(32)}`,
      credentialReadiness: 1,
    };

    const secretBearing = { credentialSource: `sk-proj-${'a'.repeat(24)}` };

    for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
      expect(sanitize(routeResponse)).toEqual(routeResponse);
      expect(sanitize(invalid)).toEqual({
        ...invalid,
        credentialMode: 'Bearer [REDACTED]',
      });
      expect(sanitize(secretBearing)).toEqual({ credentialSource: '[REDACTED]' });
    }
    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      for (const credentialSource of modelResolutionSources) {
        expect(sanitize({ credentialSource })).toEqual({ credentialSource: '[REDACTED]' });
      }
      expect(sanitize(invalid)).toEqual({
        credentialSource: '[REDACTED]',
        credentialScope: '[REDACTED]',
        credentialMode: '[REDACTED]',
        credentialReadiness: '[REDACTED]',
      });
    }
    for (const find of [findSensitiveFieldPath, findSensitiveFieldPathBounded]) {
      expect(find(routeResponse)).toBeNull();
      expect(find(invalid)).toBe('credentialMode');
      expect(find(secretBearing)).toBe('credentialSource');
    }
  });

  it('recursively sanitizes the contract-derived SSO credential metadata container', () => {
    const nullableMetadata = { credentialMetadata: null };
    const safeMetadata = {
      credentialMetadata: {
        clientSecretSet: false,
        certificateFingerprints: ['aa:bb', 'cc:dd'],
        certificates: [],
      },
    };
    const unsafeMetadata = {
      credentialMetadata: {
        clientSecretSet: true,
        clientSecret: 'huntertwo',
      },
    };

    for (const sanitize of [
      sanitizeResponse,
      sanitizeResponseBounded,
      (value: unknown) => sanitizeResponse(value, { redactPii: true, redactUrlLocations: true }),
      (value: unknown) =>
        sanitizeResponseBounded(value, { redactPii: true, redactUrlLocations: true }),
    ]) {
      expect(sanitize(nullableMetadata)).toEqual(nullableMetadata);
      expect(sanitize(safeMetadata)).toEqual(safeMetadata);
      expect(sanitize(unsafeMetadata)).toEqual({
        credentialMetadata: {
          clientSecretSet: true,
          clientSecret: '[REDACTED]',
        },
      });
    }
    for (const find of [findSensitiveFieldPath, findSensitiveFieldPathBounded]) {
      expect(find(nullableMetadata)).toBeNull();
      expect(find(safeMetadata)).toBeNull();
      expect(find(unsafeMetadata)).toBe('credentialMetadata.clientSecret');
    }
  });

  it.each([
    ['ftp', 'ftp://user:password@example.test/private/customer.csv'],
    ['mongodb', 'mongodb://user:password@example.test/tenant-db?replicaSet=private'],
    ['redis', 'redis://:password@example.test:6379/4#tenant-cache'],
  ])(
    'redacts userinfo without changing functional location details in a %s DSN',
    (_scheme, dsn) => {
      const input = { message: `Connect with ${dsn}` };

      for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
        const serialized = JSON.stringify(result);
        expect(serialized).not.toContain('password');
        expect(serialized).toContain('[REDACTED]@');
      }
      expect(findSensitiveFieldPath(input)).toBe('message');
      expect(findSensitiveFieldPathBounded(input)).toBe('message');
    },
  );

  it('preserves benign URL paths, redacts sensitive query values, and leaves malformed URLs compatible', () => {
    const malformed = { message: 'Broken http://%/private/customer/alice?case=42' };
    const malformedCredentials = {
      urls: ['ftp://user:SENSITIVE_FTP@%zz/private', 'redis://user:SENSITIVE_REDIS@[invalid/path'],
    };
    const urls = {
      urls: [
        'https://example.test/api/projects/project-1',
        'https://example.test/callback?token=secret-value&signature=signed-value&code=oauth-code&view=full',
        'redis://cache.example.test:6379/4',
      ],
    };

    for (const result of [sanitizeResponse(malformed), sanitizeResponseBounded(malformed)]) {
      expect(result).toEqual(malformed);
    }
    for (const result of [
      sanitizeResponse(malformedCredentials),
      sanitizeResponseBounded(malformedCredentials),
    ]) {
      expect(result).toEqual({
        urls: ['ftp://[REDACTED]@%zz/private', 'redis://[REDACTED]@[invalid/path'],
      });
    }
    for (const result of [sanitizeResponse(urls), sanitizeResponseBounded(urls)]) {
      expect(result).toEqual({
        urls: [
          'https://example.test/api/projects/project-1',
          'https://example.test/callback?token=[REDACTED]&signature=[REDACTED]&code=[REDACTED]&view=full',
          'redis://cache.example.test:6379/4',
        ],
      });
    }
  });

  it('keeps ordinary non-URL code fields while redacting exact signed-URL query keys', () => {
    const input = {
      code: 'NORMAL_OPERATION_CODE',
      links: [
        'https://downloads.example.test/artifact.zip?sig=signed-value',
        'https://downloads.example.test/artifact.zip?signature=signed-value',
        'https://s3.example.test/object?X-Amz-Signature=aws-signed-value&response-content-type=text%2Fplain',
        'https://storage.googleapis.test/object?X-Goog-Signature=gcs-signed-value&generation=7',
        'https://login.example.test/callback?oauth_code=oauth-code&status_code=200',
        'https://login.example.test/callback#code=fragment-code&state=benign-state',
        'https://s3.example.test/object#X-Amz-Signature=fragment-signature&version=7',
        'https://app.example.test/#/callback?code=spa-route-secret&screen=home',
        'https://api.example.test/callback?foo=ok;code=semicolon-secret;mode=full',
        'https://docs.example.test/guide#benign-anchor',
      ],
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      expect(result).toEqual({
        code: 'NORMAL_OPERATION_CODE',
        links: [
          'https://downloads.example.test/artifact.zip?sig=[REDACTED]',
          'https://downloads.example.test/artifact.zip?signature=[REDACTED]',
          'https://s3.example.test/object?X-Amz-Signature=[REDACTED]&response-content-type=text%2Fplain',
          'https://storage.googleapis.test/object?X-Goog-Signature=[REDACTED]&generation=7',
          'https://login.example.test/callback?oauth_code=[REDACTED]&status_code=200',
          'https://login.example.test/callback#code=[REDACTED]&state=benign-state',
          'https://s3.example.test/object#X-Amz-Signature=[REDACTED]&version=7',
          'https://app.example.test/#/callback?code=[REDACTED]&screen=home',
          'https://api.example.test/callback?foo=ok;code=[REDACTED];mode=full',
          'https://docs.example.test/guide#benign-anchor',
        ],
      });
    }
    expect(findSensitiveFieldPath({ code: 'NORMAL_OPERATION_CODE' })).toBeNull();
    expect(findSensitiveFieldPathBounded({ code: 'NORMAL_OPERATION_CODE' })).toBeNull();
  });

  it('redacts encoded nested callback secrets while preserving ordinary encoded values', () => {
    const input = {
      links: [
        'https://app.test/start?redirect_uri=https%3A%2F%2Fcallback.test%2Fdone%3Fcode%3DSENSITIVE123',
        'https://app.test/start?next=%2Fcallback%3Foauth_code%3DSENSITIVE123',
        'https://app.test/#/callback?next=%2Fdone%3Fcode%3DSENSITIVE123',
        'https://app.test/start?redirect_uri=https%253A%252F%252Fcallback.test%252Fdone%253Fcode%253DSENSITIVE123',
        'https://app.test/start?next=%252Fcallback%253Foauth_code%253DSENSITIVE123',
        'https://app.test/start?download=https%253A%252F%252Fs3.example.test%252Fobject%253FX-Amz-Signature%253DSENSITIVE123',
        'https://app.test/start?redirect_uri=https%3A%2F%2Fcallback.test%2Fdone%3Fstate%3Dok',
      ],
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      expect(result).toEqual({
        links: [
          'https://app.test/start?redirect_uri=[REDACTED]',
          'https://app.test/start?next=[REDACTED]',
          'https://app.test/#/callback?next=[REDACTED]',
          'https://app.test/start?redirect_uri=[REDACTED]',
          'https://app.test/start?next=[REDACTED]',
          'https://app.test/start?download=[REDACTED]',
          'https://app.test/start?redirect_uri=https%3A%2F%2Fcallback.test%2Fdone%3Fstate%3Dok',
        ],
      });
    }
  });

  it('redacts encoded generic credential text in URL parameter values', () => {
    const input = {
      links: [
        'https://app.test/start?metadata=Bearer%20SENSITIVE_BEARER',
        'https://app.test/start?metadata=Basic%20SENSITIVE_BASIC',
        'https://app.test/start?metadata=token%3ASENSITIVE_TOKEN',
      ],
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      expect(result).toEqual({
        links: [
          'https://app.test/start?metadata=[REDACTED]',
          'https://app.test/start?metadata=[REDACTED]',
          'https://app.test/start?metadata=[REDACTED]',
        ],
      });
    }
  });

  it('removes encoded credential payloads carried inside URL parameter keys', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const input = {
      links: [
        `https://app.test/?${encodeEveryByte(`sk-proj-${'a'.repeat(24)}`)}=outer`,
        `https://app.test/?${encodeEveryByte('Bearer SENSITIVE_BEARER')}=outer`,
        `https://app.test/?${encodeEveryByte('Basic SENSITIVE_BASIC')}=outer`,
        `https://app.test/#/route?${encodeEveryByte(
          'https://user:SENSITIVE_PASSWORD@host.test/private',
        )}=outer`,
      ],
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      expect(result).toEqual({
        links: [
          'https://app.test/?[REDACTED_KEY]=[REDACTED]',
          'https://app.test/?[REDACTED_KEY]=[REDACTED]',
          'https://app.test/?[REDACTED_KEY]=[REDACTED]',
          'https://app.test/#/route?[REDACTED_KEY]=[REDACTED]',
        ],
      });
      let decoded = JSON.stringify(result);
      for (let pass = 0; pass < 3; pass += 1) decoded = decodeURIComponent(decoded);
      expect(decoded).not.toMatch(/sk-proj-|SENSITIVE_/);
    }
  });

  it('classifies strict encoded credential object keys across the complete visible boundary', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const rows = [500, 507, 508, 509, 510, 511, 512, 513].map((start, index) => {
      const family =
        ['authProfileId', 'apiKey', 'databaseCredential'][index % 3] ?? 'authProfileId';
      return `${'a'.repeat(start)}${encodeEveryByte(family)}`;
    });
    const layered = `${'a'.repeat(509)}${encodeEveryByte(encodeEveryByte('authProfileId'))}`;
    const benign = `display_${'a'.repeat(508)}%20label_${'a'.repeat(200)}`;
    const input = Object.fromEntries([
      ...rows.map((key, index) => [key, `opaque-secret-${index}`]),
      [layered, 'opaque-layered-secret'],
      [benign, 'safe-value'],
    ]);

    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      const result = sanitize(input) as Record<string, unknown>;
      expect(JSON.stringify(result)).not.toContain('opaque-secret');
      expect(JSON.stringify(result)).not.toContain('opaque-layered-secret');
      expect(result[benign]).toBe('safe-value');
      expect(Object.values(result).filter((value) => value === '[REDACTED]')).toHaveLength(9);
    }
  });

  it('distinguishes benign literal-percent keys from nested or malformed credential keys', () => {
    const benignKeys = [
      'displayLabel%25',
      'display%25Label',
      `${'a'.repeat(700)}%25`,
      `${'a'.repeat(508)}%25label_${'b'.repeat(200)}`,
    ];
    const sensitiveKeys = [
      `${'a'.repeat(508)}%2541uthProfileId`,
      `${'a'.repeat(508)}%ZZ%61uthProfileId`,
    ];
    const input = Object.fromEntries([
      ...benignKeys.map((key) => [key, 'safe-value']),
      ...sensitiveKeys.map((key) => [key, 'opaque-value']),
    ]);

    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      const result = sanitize(input) as Record<string, unknown>;
      for (const key of benignKeys) expect(result[key]).toBe('safe-value');
      expect(JSON.stringify(result)).not.toContain('opaque-value');
    }
  });

  it('bounds strict classification of a 2 MiB encoded key without affecting global compatibility', () => {
    const key = `${'a'.repeat(2 * 1024 * 1024)}%20label`;
    const rawSensitiveKey = `${'a'.repeat(2 * 1024 * 1024)}Credential`;
    const input = { [key]: 'opaque-value' };

    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      const startedAt = performance.now();
      const result = sanitize(input);
      expect(performance.now() - startedAt).toBeLessThan(1_000);
      expect(JSON.stringify(result)).not.toContain('opaque-value');
      expect(JSON.stringify(sanitize({ [rawSensitiveKey]: 'raw-opaque-value' }))).not.toContain(
        'raw-opaque-value',
      );
    }
    expect(sanitizeResponse(input)).toEqual(input);
  });

  it('redacts full-key credential payloads after 512 characters in strict lanes', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const encodeDepth = (value: string, depth: number): string => {
      let encoded = value;
      for (let pass = 0; pass < depth; pass += 1) encoded = encodeEveryByte(encoded);
      return encoded;
    };
    const payloads = [
      `sk-proj-${'a'.repeat(24)}`,
      encodeDepth(`AKIA${'A'.repeat(16)}`, 1),
      encodeDepth('Bearer SYNTHETIC123', 2),
      encodeDepth('Basic SYNTHETIC123', 1),
      encodeDepth('https://user:pass@host.test/private', 2),
      encodeDepth(`sk-proj-${'a'.repeat(24)}`, 4),
    ];
    const input = Object.fromEntries(
      payloads.map((payload, index) => [`${'a'.repeat(700)}${payload}`, `opaque-value-${index}`]),
    );

    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
    ]) {
      const result = sanitize(input);
      expect(JSON.stringify(result)).not.toContain('opaque-value');
    }
  });

  it('redacts every provider family in strict keys across raw and encoded boundary positions', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const encodeDepth = (value: string, depth: number): string => {
      let encoded = value;
      for (let pass = 0; pass < depth; pass += 1) encoded = encodeEveryByte(encoded);
      return encoded;
    };
    const input: Record<string, string> = {};
    for (const [label, providerSecret] of PROVIDER_SECRET_CASES) {
      for (const position of [0, 511, 512, 513, 700]) {
        for (const depth of [0, 1, 2]) {
          input[`${'a'.repeat(position)}${encodeDepth(providerSecret, depth)}`] =
            `opaque-${label}-${position}-${depth}`;
        }
      }
    }

    for (const sanitize of [
      (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
      (value: unknown) =>
        sanitizeResponseBounded(value, {
          allowCredentialMetadata: false,
          maxObjectKeys: 300,
        }),
    ]) {
      expect(JSON.stringify(sanitize(input))).not.toContain('opaque-');
    }
  });

  it.each([
    ['long JWT', `eyJ${'a'.repeat(700)}.${'b'.repeat(700)}.${'c'.repeat(700)}`],
    ['long PEM', `-----BEGIN PRIVATE KEY-----\n${'a'.repeat(700)}\n-----END PRIVATE KEY-----`],
    ['long secret template', `{{ secrets.${'a'.repeat(700)} }}`],
    ['provider token', `SG.${'a'.repeat(22)}.${'b'.repeat(43)}`],
  ])(
    'redacts both a sanitized %s key and its companion value only in strict lanes',
    (_label, key) => {
      const input = { [key]: 'opaque-companion-value' };
      for (const sanitize of [
        (value: unknown) => sanitizeResponse(value, { allowCredentialMetadata: false }),
        (value: unknown) => sanitizeResponseBounded(value, { allowCredentialMetadata: false }),
      ]) {
        const serialized = JSON.stringify(sanitize(input));
        expect(serialized).not.toContain('opaque-companion-value');
        expect(serialized).not.toContain(key);
      }
      for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
        expect(Object.values(sanitize(input) as Record<string, unknown>)).toContain(
          'opaque-companion-value',
        );
      }
    },
  );

  it('redacts credential-bearing URL paths and non-pair fragments across encoding layers', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const encodeDepth = (value: string, depth: number): string => {
      let encoded = encodeEveryByte(value);
      for (let pass = 1; pass < depth; pass += 1) encoded = encoded.replace(/%/g, '%25');
      return encoded;
    };
    const providerToken = `sk-proj-${'a'.repeat(24)}`;
    const input = {
      urls: [
        `https://files.test/download/${providerToken}`,
        `https://files.test/download/${encodeDepth(providerToken, 1)}`,
        `https://files.test/download/${encodeDepth('Bearer SENSITIVE_BEARER', 2)}`,
        `https://files.test/download/${encodeDepth('Basic SENSITIVE_BASIC', 1)}`,
        `ftp://files.test/${encodeDepth('https://user:SENSITIVE_PASSWORD@nested.test/private', 2)}`,
        `https://app.test/#${encodeDepth(providerToken, 1)}`,
        `https://app.test/route#${encodeDepth('Bearer SENSITIVE_FRAGMENT', 2)}`,
        'https://files.test/download/%41%42%43',
        'https://app.test/#guide%2Danchor',
      ],
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      expect(result).toEqual({
        urls: [
          'https://files.test/[REDACTED_PATH]',
          'https://files.test/[REDACTED_PATH]',
          'https://files.test/[REDACTED_PATH]',
          'https://files.test/[REDACTED_PATH]',
          'ftp://files.test/[REDACTED_PATH]',
          'https://app.test/#[REDACTED_FRAGMENT]',
          'https://app.test/route#[REDACTED_FRAGMENT]',
          'https://files.test/download/%41%42%43',
          'https://app.test/#guide%2Danchor',
        ],
      });
    }
  });

  it('redacts mixed fragment routes containing credentials even when a query sibling is redacted', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const encodeDepth = (value: string, depth: number): string => {
      let encoded = value;
      for (let pass = 0; pass < depth; pass += 1) encoded = encodeEveryByte(encoded);
      return encoded;
    };
    const providerToken = `sk-proj-${'a'.repeat(24)}`;
    const input = {
      urls: [
        `https://app.test/#/route/${providerToken}?code=oauth-secret`,
        `https://app.test/#/route/${encodeDepth(providerToken, 1)}?token=outer-secret`,
        `https://app.test/#/${encodeDepth('Bearer SENSITIVE_BEARER', 2)}?sig=outer-signature`,
        `https://app.test/#/${encodeDepth(
          'https://user:SENSITIVE_PASSWORD@nested.test/private',
          1,
        )}?code=outer-code`,
        `https://app.test/#/route/${encodeDepth(providerToken, 1)};code=outer-code`,
        'https://app.test/#/guide/getting-started?view=full&code=outer-code',
      ],
    };

    for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
      expect(result).toEqual({
        urls: [
          'https://app.test/#[REDACTED_FRAGMENT]',
          'https://app.test/#[REDACTED_FRAGMENT]',
          'https://app.test/#[REDACTED_FRAGMENT]',
          'https://app.test/#[REDACTED_FRAGMENT]',
          'https://app.test/#[REDACTED_FRAGMENT]',
          'https://app.test/#/guide/getting-started?view=full&code=[REDACTED]',
        ],
      });
      let decoded = JSON.stringify(result);
      for (let pass = 0; pass < 3; pass += 1) decoded = decodeURIComponent(decoded);
      expect(decoded).not.toMatch(/sk-proj-|SENSITIVE_|outer-(?:secret|signature|code)/);
    }
  });

  it.each([0, 1, 2, 3, 4])(
    'redacts sensitive URL keys and nested callbacks at encoding depth %i',
    (depth) => {
      const encodeEveryByte = (value: string): string =>
        [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
      const encodeDepth = (value: string): string => {
        if (depth === 0) return value;
        let encoded = encodeEveryByte(value);
        for (let pass = 1; pass < depth; pass += 1) encoded = encoded.replace(/%/g, '%25');
        return encoded;
      };
      const input = {
        links: [
          `https://app.test/callback?${encodeDepth('code')}=SENSITIVE_QUERY`,
          `https://app.test/#/callback?${encodeDepth('oauth_code')}=SENSITIVE_FRAGMENT`,
          `https://app.test/callback?${encodeDepth('code=SENSITIVE_KEY_VALUE')}=outer`,
          `https://app.test/callback?${encodeDepth('foo&code=SENSITIVE_KEY_PAIR')}=outer`,
          `https://app.test/#/callback?${encodeDepth('oauth_code=SENSITIVE_FRAGMENT_KEY')}=outer`,
          `https://app.test/start?redirect_uri=${encodeDepth(
            'https://callback.test/done?code=SENSITIVE_NESTED',
          )}`,
          `https://app.test/start?download=${encodeDepth(
            'https://s3.example.test/object?X-Amz-Signature=SENSITIVE_SIGNATURE',
          )}`,
        ],
      };

      for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
        const serialized = JSON.stringify(result);
        expect(serialized).not.toContain('SENSITIVE_');
        let decoded = serialized;
        for (let pass = 0; pass < 5; pass += 1) decoded = decodeURIComponent(decoded);
        expect(decoded).not.toContain('SENSITIVE_');
      }
    },
  );

  it.each([3, 4, 5])(
    'fails closed for noncanonical repeated full-byte encoding at depth %i',
    (depth) => {
      const encodeEveryByte = (value: string): string =>
        [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
      const encodeDepth = (value: string): string => {
        let encoded = value;
        for (let pass = 0; pass < depth; pass += 1) encoded = encodeEveryByte(encoded);
        return encoded;
      };
      const providerToken = `sk-proj-${'a'.repeat(24)}`;
      const input = {
        links: [
          `https://app.test/?metadata=${encodeDepth(providerToken)}`,
          `https://app.test/?${encodeDepth(providerToken)}=outer`,
          `https://app.test/download/${encodeDepth(providerToken)}`,
          `https://app.test/#${encodeDepth(providerToken)}`,
        ],
      };

      for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
        let decoded = JSON.stringify(result);
        for (let pass = 0; pass < depth; pass += 1) decoded = decodeURIComponent(decoded);
        expect(decoded).not.toContain('sk-proj-');
      }
    },
  );

  it('preserves canonical over-budget benign encoding but omits ambiguous noncanonical encoding', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const canonical =
      'https://app.test/?metadata=%25252568%25252561%25252572%2525256d%2525256c%25252565%25252573%25252573';
    let noncanonicalValue = 'harmless';
    for (let pass = 0; pass < 4; pass += 1) noncanonicalValue = encodeEveryByte(noncanonicalValue);
    const noncanonical = `https://app.test/?metadata=${noncanonicalValue}`;

    for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
      expect(sanitize(canonical)).toBe(canonical);
      expect(sanitize(noncanonical)).toBe('https://app.test/?metadata=[REDACTED]');
    }
  });

  it('fails closed for malformed URL keys and preserves deeply encoded benign values', () => {
    const malformed = 'https://app.test/callback?%ZZ%63%6f%64%65=SENSITIVE123';
    const benign =
      'https://app.test/start?redirect_uri=%25252568%25252574%25252574%25252570%25252573%2525253a%2525252f%2525252fcallback.test%2525252fdone%2525253fstate%2525253dok';

    for (const sanitize of [sanitizeResponse, sanitizeResponseBounded]) {
      expect(String(sanitize(malformed))).not.toContain('SENSITIVE123');
      expect(sanitize(benign)).toBe(benign);
    }
  });

  it('boundedly scans long encoded values without corrupting benign metadata', () => {
    const encodeEveryByte = (value: string): string =>
      [...Buffer.from(value)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
    const padding = '%41'.repeat(6_000);
    const benign = `https://files.example.test/download?metadata=${padding}`;
    const sensitive = [
      `https://files.example.test/download?metadata=${padding}%3Fcode%3DLATESECRET`,
      `https://files.example.test/download?metadata=${padding}%20${encodeEveryByte(
        `sk-proj-${'a'.repeat(24)}`,
      )}`,
      `https://files.example.test/download?metadata=${padding}%20${encodeEveryByte(
        'https://user:password@nested.example.test/private',
      )}`,
      `https://files.example.test/download?metadata=${encodeEveryByte(
        `https://user:${'p'.repeat(7_000)}@nested.example.test/private`,
      )}`,
      `https://files.example.test/download?metadata=${encodeEveryByte(
        `eyJ${'a'.repeat(5_000)}.${'b'.repeat(5_000)}.${'c'.repeat(5_000)}`,
      )}`,
      `https://files.example.test/download?metadata=${encodeEveryByte(
        `-----BEGIN PRIVATE KEY-----\n${'A'.repeat(6_000)}\n-----END PRIVATE KEY-----`,
      )}`,
      `https://files.example.test/download?metadata=${encodeEveryByte(
        `{{ secrets.${'a'.repeat(6_000)} }}`,
      )}`,
    ];

    for (const sanitize of [
      (value: string) => sanitizeResponse(value),
      (value: string) => sanitizeResponseBounded(value, { maxStringLength: 100_000 }),
    ]) {
      expect(sanitize(benign)).toBe(benign);
      for (const value of sensitive) {
        expect(sanitize(value)).toBe('https://files.example.test/download?metadata=[REDACTED]');
      }
    }
  });

  it('keeps a transport-sized benign encoded value within a bounded scan time', () => {
    const encoded = '%41'.repeat(Math.floor((2 * 1024 * 1024) / 3));
    const inputs = [
      `https://files.example.test/download?metadata=${encoded}`,
      `https://files.example.test/download/${encoded}`,
      `https://files.example.test/#${encoded}`,
    ];
    for (const sanitize of [
      (value: string) => sanitizeResponse(value),
      (value: string) => sanitizeResponseBounded(value, { maxStringLength: 3 * 1024 * 1024 }),
    ]) {
      for (const input of inputs) {
        const startedAt = performance.now();
        expect(sanitize(input)).toBe(input);
        expect(performance.now() - startedAt).toBeLessThan(2_000);
      }
    }
  });

  it.each(PROVIDER_SECRET_CASES)(
    'keeps bounded and unbounded sanitizers aligned for the %s provider-token family',
    (_label, secret) => {
      const input = { prompt: `Use ${secret} only in this test` };

      for (const result of [sanitizeResponse(input), sanitizeResponseBounded(input)]) {
        expect(JSON.stringify(result)).not.toContain(secret);
      }
      expect(findSensitiveFieldPath(input)).toBe('prompt');
      expect(findSensitiveFieldPathBounded(input)).toBe('prompt');
    },
  );

  it.each(SENSITIVE_DYNAMIC_KEY_CASES)(
    'scopes fuzzy dynamic key form %s to strict Runtime policy',
    (key) => {
      const input = { settings: { [key]: 'opaque-sensitive-value' } };
      const legacyExactKey = key === 'clientSecret' || key === 'xApiKey';

      const expectedGlobal = legacyExactKey ? { settings: { [key]: '[REDACTED]' } } : input;
      expect(sanitizeResponse(input)).toEqual(expectedGlobal);
      expect(sanitizeResponseBounded(input)).toEqual(expectedGlobal);
      expect(findSensitiveFieldPath(input)).toBe(legacyExactKey ? `settings.${key}` : null);
      expect(findSensitiveFieldPathBounded(input)).toBe(legacyExactKey ? `settings.${key}` : null);

      for (const result of [
        sanitizeResponse(input, { allowCredentialMetadata: false }),
        sanitizeResponseBounded(input, { allowCredentialMetadata: false }),
      ]) {
        const serialized = JSON.stringify(result);
        expect(serialized).not.toContain('opaque-sensitive-value');
      }
      expect(findSensitiveFieldPath(input, '', { allowCredentialMetadata: false })).toBe(
        `settings.${key}`,
      );
      expect(findSensitiveFieldPathBounded(input, { allowCredentialMetadata: false })).toBe(
        `settings.${key}`,
      );
    },
  );
});
