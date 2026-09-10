const SENSITIVE_KEYS =
  /^(api[_-]?key|x[_-]?api[_-]?key|secret|password|token|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|credential|private[_-]?key|access[_-]?key|client[_-]?secret|(access|refresh|id|bearer)[_-]?token)$/i;

// Keep this distributed-package defense aligned with the Runtime AI-safe projection. The MCP
// package intentionally has no private workspace dependency, so parity is enforced by tests.
const HIGH_CONFIDENCE_SECRET_PATTERNS: readonly RegExp[] = [
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
  /\{\{\s*secrets\.[^}]+\s*\}\}/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /\babl_[A-Za-z0-9]{20,}\b/g,
  /\bsk-[A-Za-z0-9-]{20,}\b/g,
  /\b(?:pk|sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
  /\bgh[po]_[A-Za-z0-9]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  /\bSK[0-9a-fA-F]{32}\b/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];
const HIERARCHICAL_URL_IN_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>`]+/gi;
const MAX_NESTED_URL_PARAMETER_CHARS = 16_384;
const NESTED_URL_SCAN_CHUNK_CHARS = 4_096;
const NESTED_URL_SCAN_OVERLAP_CHARS = 512;
const MAX_NESTED_URL_DECODE_PASSES = 3;
const MAX_ENCODED_KEY_SECURITY_SCAN_CHARS = 16 * 1024;
const STREAMING_PEM_HEADERS = [
  '-----BEGIN PRIVATE KEY-----',
  '-----BEGIN RSA PRIVATE KEY-----',
] as const;

function redactGenericCredentialText(value: string): string {
  return value
    .replace(/\b(cookie|set[_-]?cookie)\s*[:=]\s*[^\r\n]+/gi, '$1=[REDACTED]')
    .replace(/\b(bearer|basic)\s+[^\s,;]+/gi, '$1 [REDACTED]')
    .replace(
      /\b(api[_-]?key|x[_-]?api[_-]?key|secret|credential|private[_-]?key|access[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|authorization|proxy[_-]?authorization|password|token|cookie|set[_-]?cookie)\s*[:=]\s*([^\s,;&]+)/gi,
      '$1=[REDACTED]',
    );
}

function isSensitiveKey(key: string, strictCredentialKeys = false): boolean {
  if (SENSITIVE_KEYS.test(key)) return true;
  if (!strictCredentialKeys) return false;
  // Global MCP compatibility returns above. Only the strict Runtime-config policy applies the
  // fuzzy key classifier and conservatively closes encoded keys beyond the security-scan budget.
  if (key.length > MAX_ENCODED_KEY_SECURITY_SCAN_CHARS) {
    if (/%[0-9a-f]{2}/i.test(key)) return true;
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    return (
      normalized.endsWith('token') ||
      SENSITIVE_NORMALIZED_KEY_PARTS.some((part) => normalized.includes(part))
    );
  }
  if (containsLayeredSensitiveKeyName(key)) return true;
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  return (
    normalized.endsWith('token') ||
    normalized.includes('apikey') ||
    normalized.includes('apisecret') ||
    normalized.includes('secret') ||
    normalized.includes('password') ||
    normalized.includes('passwd') ||
    normalized.includes('credential') ||
    normalized.includes('authprofile') ||
    normalized.includes('privatekey') ||
    normalized.includes('accesskey')
  );
}

function isSensitiveUrlQueryKey(key: string): boolean {
  if (isSensitiveKey(key)) return true;
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  return (
    normalized === 'code' ||
    normalized.endsWith('sig') ||
    normalized.endsWith('signature') ||
    normalized.endsWith('authcode') ||
    normalized.endsWith('oauthcode') ||
    normalized.endsWith('authorizationcode')
  );
}

function containsSensitiveText(
  value: string,
  redactUrlLocations = false,
  redactPii = false,
): boolean {
  return redactSensitiveText(value, redactUrlLocations, redactPii) !== value;
}

function decodeUrlParameterOnce(encodedValue: string): string {
  try {
    return decodeURIComponent(encodedValue.replace(/\+/g, ' '));
  } catch {
    // Decode valid ASCII octets once so a separate malformed escape cannot hide a query key.
    return encodedValue.replace(/%([0-9a-f]{2})/gi, (_match, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
  }
}

function containsDecodedSensitiveUrlMaterial(decoded: string): boolean {
  const queryPair = /(?:^|[?&;])([^=?&;]+)=/g;
  for (const match of decoded.matchAll(queryPair)) {
    if (isSensitiveUrlQueryKey(match[1] ?? '')) return true;
  }
  for (const pattern of HIGH_CONFIDENCE_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded)) return true;
  }
  if (redactGenericCredentialText(decoded) !== decoded) return true;
  HIERARCHICAL_URL_IN_TEXT.lastIndex = 0;
  for (const match of decoded.matchAll(HIERARCHICAL_URL_IN_TEXT)) {
    try {
      const nested = new URL(match[0]);
      if (nested.username || nested.password) return true;
    } catch {
      // Query-like material was checked independently above. Malformed nested URLs do not cause
      // recursive parsing or make an otherwise ordinary encoded value unsafe by themselves.
    }
  }
  return false;
}

function readLayeredUrlParameterCharacter(
  value: string,
  index: number,
): { character: string; nextIndex: number } {
  if (value[index] !== '%') {
    return { character: value[index] === '+' ? ' ' : (value[index] ?? ''), nextIndex: index + 1 };
  }
  let cursor = index + 1;
  while (value.charCodeAt(cursor) === 50 && value.charCodeAt(cursor + 1) === 53) cursor += 2;
  const high = hexValue(value.charCodeAt(cursor));
  const low = hexValue(value.charCodeAt(cursor + 1));
  if (high >= 0 && low >= 0) {
    return {
      character: String.fromCharCode(high * 16 + low),
      nextIndex: cursor + 2,
    };
  }
  return { character: '%', nextIndex: Math.max(index + 1, cursor) };
}

const SENSITIVE_NORMALIZED_KEY_PARTS = [
  'apikey',
  'apisecret',
  'secret',
  'password',
  'passwd',
  'credential',
  'authprofile',
  'privatekey',
  'accesskey',
] as const;

interface PercentStreamState {
  malformed: boolean;
}

function* decodePercentStream(
  input: Iterable<string>,
  state: PercentStreamState,
): Generator<string> {
  let pendingPercent = false;
  let highCharacter = '';
  let high = -1;
  for (const character of input) {
    if (!pendingPercent) {
      if (character === '%') pendingPercent = true;
      else yield character === '+' ? ' ' : character;
      continue;
    }
    if (high < 0) {
      high = hexValue(character.charCodeAt(0));
      if (high >= 0) {
        highCharacter = character;
        continue;
      }
      state.malformed = true;
      yield '%';
      pendingPercent = character === '%';
      if (!pendingPercent) yield character === '+' ? ' ' : character;
      continue;
    }
    const low = hexValue(character.charCodeAt(0));
    if (low >= 0) {
      yield String.fromCharCode(high * 16 + low);
      pendingPercent = false;
      high = -1;
      highCharacter = '';
      continue;
    }
    state.malformed = true;
    yield '%';
    yield highCharacter;
    pendingPercent = character === '%';
    if (!pendingPercent) yield character === '+' ? ' ' : character;
    high = -1;
    highCharacter = '';
  }
  if (pendingPercent) {
    state.malformed = true;
    yield '%';
    if (highCharacter) yield highCharacter;
  }
}

function classifyDecodedKey(input: Iterable<string>): {
  sensitive: boolean;
  hasDecodablePercent: boolean;
} {
  type UrlState = 'seek' | 'scheme' | 'first-slash' | 'second-slash' | 'authority';
  let normalizedTail = '';
  let credentialWindow = '';
  let charactersSinceCredentialCheck = 0;
  let percentState = 0;
  let hasNestedPercent = false;
  let urlState: UrlState = 'seek';
  let previous = '';
  let jwtState = 0;
  let jwtSegmentCharacters = 0;
  const credentialWindowIsSensitive = (): boolean =>
    containsDecodedSensitiveUrlMaterial(credentialWindow) ||
    /(?:bearer|basic)\s+[^\s,;]+/i.test(credentialWindow) ||
    /(?:api[_-]?key|secret|credential|password|token)\s*[:=]\s*[^\s,;&]+/i.test(credentialWindow) ||
    /(?:AKIA[A-Z0-9]{16}|abl_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9-]{20,}|(?:pk|sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}|gh[po]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|SK[0-9a-fA-F]{32}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/i.test(
      credentialWindow,
    ) ||
    credentialWindow.includes('-----BEGIN PRIVATE KEY-----') ||
    /\{\{\s*secrets\./i.test(credentialWindow);
  for (const character of input) {
    const code = character.charCodeAt(0);
    const normalizedCharacter =
      code >= 65 && code <= 90
        ? String.fromCharCode(code + 32)
        : (code >= 97 && code <= 122) || (code >= 48 && code <= 57)
          ? character
          : '';
    if (normalizedCharacter) {
      normalizedTail = `${normalizedTail}${normalizedCharacter}`.slice(-64);
      if (SENSITIVE_NORMALIZED_KEY_PARTS.some((part) => normalizedTail.includes(part))) {
        return { sensitive: true, hasDecodablePercent: hasNestedPercent };
      }
    }
    credentialWindow = `${credentialWindow}${character}`.slice(-512);
    charactersSinceCredentialCheck += 1;
    if (charactersSinceCredentialCheck >= 128) {
      if (credentialWindowIsSensitive()) {
        return { sensitive: true, hasDecodablePercent: hasNestedPercent };
      }
      charactersSinceCredentialCheck = 0;
    }
    const isAlpha = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
    const isAlphanumeric = isAlpha || (code >= 48 && code <= 57);
    switch (urlState) {
      case 'seek':
        if (isAlpha && !/[A-Za-z0-9]/.test(previous)) urlState = 'scheme';
        break;
      case 'scheme':
        if (character === ':') urlState = 'first-slash';
        else if (!isAlphanumeric && !'+.-'.includes(character)) urlState = 'seek';
        break;
      case 'first-slash':
        urlState = character === '/' ? 'second-slash' : 'seek';
        break;
      case 'second-slash':
        urlState = character === '/' ? 'authority' : 'seek';
        break;
      case 'authority':
        if (character === '@') return { sensitive: true, hasDecodablePercent: hasNestedPercent };
        if (character <= ' ' || '/?#'.includes(character)) urlState = 'seek';
        break;
    }
    const isBase64Url = isAlphanumeric || character === '_' || character === '-';
    if (jwtState === 0) {
      if (character === 'e') jwtState = 1;
    } else if (jwtState === 1) {
      jwtState = character === 'y' ? 2 : character === 'e' ? 1 : 0;
    } else if (jwtState === 2) {
      jwtState = character === 'J' ? 3 : character === 'e' ? 1 : 0;
      if (jwtState === 3) jwtSegmentCharacters = 0;
    } else if (jwtState === 3 || jwtState === 4) {
      if (isBase64Url) jwtSegmentCharacters += 1;
      else if (character === '.' && jwtSegmentCharacters >= 10) {
        jwtState += 1;
        jwtSegmentCharacters = 0;
      } else {
        jwtState = character === 'e' ? 1 : 0;
      }
    } else if (isBase64Url) {
      jwtSegmentCharacters += 1;
      if (jwtSegmentCharacters >= 10) {
        return { sensitive: true, hasDecodablePercent: hasNestedPercent };
      }
    } else {
      jwtState = character === 'e' ? 1 : 0;
    }
    if (percentState === 0) percentState = character === '%' ? 1 : 0;
    else if (percentState === 1) {
      percentState = hexValue(code) >= 0 ? 2 : character === '%' ? 1 : 0;
    } else if (hexValue(code) >= 0) {
      hasNestedPercent = true;
      percentState = 0;
    } else {
      percentState = character === '%' ? 1 : 0;
    }
    previous = character;
  }
  return {
    sensitive: normalizedTail.endsWith('token') || credentialWindowIsSensitive(),
    hasDecodablePercent: hasNestedPercent,
  };
}

/** Whole-key, allocation-bounded parity with the shared Runtime-config projector. */
function containsLayeredSensitiveKeyName(value: string): boolean {
  for (let pass = 1; pass <= MAX_NESTED_URL_DECODE_PASSES; pass += 1) {
    let stream: Iterable<string> = value;
    const states: PercentStreamState[] = [];
    for (let depth = 0; depth < pass; depth += 1) {
      const state = { malformed: false };
      states.push(state);
      stream = decodePercentStream(stream, state);
    }
    const classified = classifyDecodedKey(stream);
    if (states.some((state) => state.malformed)) return true;
    if (classified.sensitive) return true;
    if (!classified.hasDecodablePercent) return false;
  }
  return true;
}

function hexValue(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 65 && code <= 70) return code - 55;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

function isAsciiAlpha(character: string): boolean {
  const code = character.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isAsciiAlphanumeric(character: string): boolean {
  const code = character.charCodeAt(0);
  return isAsciiAlpha(character) || (code >= 48 && code <= 57);
}

function isBase64UrlCharacter(character: string): boolean {
  return isAsciiAlphanumeric(character) || character === '_' || character === '-';
}

function containsLayeredEncodedStreamingSensitiveMaterial(encodedValue: string): boolean {
  type State = 'seek' | 'scheme' | 'first-slash' | 'second-slash' | 'authority';
  let state: State = 'seek';
  let previous = '';
  let jwtState = 0;
  let jwtSegmentChars = 0;
  let secretTemplateState = 0;
  const secretTemplateSuffix = 'ecrets.';
  const pemStates = STREAMING_PEM_HEADERS.map(() => 0);
  for (let index = 0; index < encodedValue.length; ) {
    const decoded = readLayeredUrlParameterCharacter(encodedValue, index);
    const character = decoded.character;
    index = decoded.nextIndex;

    switch (state) {
      case 'seek':
        if (isAsciiAlpha(character) && !isAsciiAlphanumeric(previous)) state = 'scheme';
        break;
      case 'scheme':
        if (character === ':') state = 'first-slash';
        else if (!isAsciiAlphanumeric(character) && !'+.-'.includes(character)) state = 'seek';
        break;
      case 'first-slash':
        state = character === '/' ? 'second-slash' : 'seek';
        break;
      case 'second-slash':
        state = character === '/' ? 'authority' : 'seek';
        break;
      case 'authority':
        if (character === '@') return true;
        if (character <= ' ' || '/?#'.includes(character)) state = 'seek';
        break;
    }

    for (let patternIndex = 0; patternIndex < STREAMING_PEM_HEADERS.length; patternIndex += 1) {
      const pattern = STREAMING_PEM_HEADERS[patternIndex];
      let patternState = pemStates[patternIndex] ?? 0;
      if (character === pattern[patternState]) {
        patternState += 1;
        if (patternState === pattern.length) return true;
      } else {
        patternState = character === pattern[0] ? 1 : 0;
      }
      pemStates[patternIndex] = patternState;
    }

    if (secretTemplateState === 0) {
      if (character === '{') secretTemplateState = 1;
    } else if (secretTemplateState === 1) {
      secretTemplateState = character === '{' ? 2 : 0;
    } else if (secretTemplateState === 2) {
      if (character === 's') secretTemplateState = 3;
      else if (!/\s/.test(character)) secretTemplateState = character === '{' ? 1 : 0;
    } else {
      const suffixIndex = secretTemplateState - 3;
      if (character === secretTemplateSuffix[suffixIndex]) {
        secretTemplateState += 1;
        if (secretTemplateState - 3 === secretTemplateSuffix.length) return true;
      } else {
        secretTemplateState = character === '{' ? 1 : 0;
      }
    }

    const jwtCharacter = isBase64UrlCharacter(character);
    if (jwtState === 0) {
      if (character === 'e' && !isBase64UrlCharacter(previous)) jwtState = 1;
    } else if (jwtState === 1) {
      jwtState = character === 'y' ? 2 : character === 'e' ? 1 : 0;
    } else if (jwtState === 2) {
      jwtState = character === 'J' ? 3 : character === 'e' ? 1 : 0;
      if (jwtState === 3) jwtSegmentChars = 0;
    } else if (jwtState === 3) {
      if (jwtCharacter) jwtSegmentChars += 1;
      else if (character === '.' && jwtSegmentChars >= 10) {
        jwtState = 4;
        jwtSegmentChars = 0;
      } else jwtState = character === 'e' ? 1 : 0;
    } else if (jwtState === 4) {
      if (jwtCharacter) jwtSegmentChars += 1;
      else if (character === '.' && jwtSegmentChars >= 10) {
        jwtState = 5;
        jwtSegmentChars = 0;
      } else jwtState = character === 'e' ? 1 : 0;
    } else if (jwtCharacter) {
      jwtSegmentChars += 1;
      if (jwtSegmentChars >= 10) return true;
    } else {
      jwtState = character === 'e' ? 1 : 0;
    }
    previous = character;
  }
  return false;
}

function containsFullyLayeredSensitiveMaterial(encodedValue: string): boolean {
  let window = '';
  for (let index = 0; index < encodedValue.length; ) {
    const decoded = readLayeredUrlParameterCharacter(encodedValue, index);
    index = decoded.nextIndex;
    window += decoded.character;
    if (window.length >= NESTED_URL_SCAN_CHUNK_CHARS) {
      if (containsDecodedSensitiveUrlMaterial(window)) return true;
      window = window.slice(-NESTED_URL_SCAN_OVERLAP_CHARS);
    }
  }
  return containsDecodedSensitiveUrlMaterial(window);
}

function hasResidualDecodablePercentAfterLayeredRead(encodedValue: string): boolean {
  let percentState = 0;
  for (let index = 0; index < encodedValue.length; ) {
    const decoded = readLayeredUrlParameterCharacter(encodedValue, index);
    index = decoded.nextIndex;
    const character = decoded.character;
    if (percentState === 0) {
      percentState = character === '%' ? 1 : 0;
    } else if (percentState === 1) {
      percentState = hexValue(character.charCodeAt(0)) >= 0 ? 2 : character === '%' ? 1 : 0;
    } else if (hexValue(character.charCodeAt(0)) >= 0) {
      return true;
    } else {
      percentState = character === '%' ? 1 : 0;
    }
  }
  return false;
}

function containsSensitiveMaterialWithinDecodeLimit(encodedValue: string): boolean {
  let current = encodedValue;
  for (let pass = 0; pass < MAX_NESTED_URL_DECODE_PASSES; pass += 1) {
    const decoded = decodeUrlParameterOnce(current);
    if (containsDecodedSensitiveUrlMaterial(decoded)) return true;
    if (decoded === current || !/%[0-9a-f]{2}/i.test(decoded)) return false;
    current = decoded;
  }
  return (
    containsFullyLayeredSensitiveMaterial(encodedValue) ||
    containsLayeredEncodedStreamingSensitiveMaterial(encodedValue) ||
    hasResidualDecodablePercentAfterLayeredRead(encodedValue)
  );
}

function containsNestedSensitiveUrlMaterial(encodedValue: string): boolean {
  if (!/%[0-9a-f]{2}/i.test(encodedValue)) return false;
  if (encodedValue.length <= MAX_NESTED_URL_PARAMETER_CHARS) {
    return containsSensitiveMaterialWithinDecodeLimit(encodedValue);
  }

  if (containsFullyLayeredSensitiveMaterial(encodedValue)) return true;

  // A very long userinfo section may span more than one overlap window. Track URL structure with
  // constant state while peeling consecutive percent-encoding wrappers without allocating the
  // fully decoded value.
  return (
    containsLayeredEncodedStreamingSensitiveMaterial(encodedValue) ||
    hasResidualDecodablePercentAfterLayeredRead(encodedValue)
  );
}

function containsSensitiveUrlLocationMaterial(value: string): boolean {
  return containsDecodedSensitiveUrlMaterial(value) || containsNestedSensitiveUrlMaterial(value);
}

function isSensitiveEncodedUrlQueryKey(encodedKey: string): boolean {
  if (encodedKey.length > 512 || /%(?![0-9a-f]{2})/i.test(encodedKey)) return true;
  let current = encodedKey;
  for (let pass = 0; pass < MAX_NESTED_URL_DECODE_PASSES; pass += 1) {
    const decoded = decodeUrlParameterOnce(current);
    if (
      isSensitiveUrlQueryKey(decoded) ||
      containsDecodedSensitiveUrlMaterial(decoded) ||
      /[?&;=]/.test(decoded)
    ) {
      return true;
    }
    if (decoded === current || !/%[0-9a-f]{2}/i.test(decoded)) break;
    current = decoded;
  }
  let fullyLayered = '';
  for (let index = 0; index < encodedKey.length; ) {
    const decoded = readLayeredUrlParameterCharacter(encodedKey, index);
    index = decoded.nextIndex;
    fullyLayered += decoded.character;
    if (fullyLayered.length > 512) return true;
  }
  return (
    isSensitiveUrlQueryKey(fullyLayered) ||
    containsDecodedSensitiveUrlMaterial(fullyLayered) ||
    /[?&;=]/.test(fullyLayered) ||
    hasResidualDecodablePercentAfterLayeredRead(encodedKey)
  );
}

function encodedUrlQueryKeyContainsSensitivePayload(encodedKey: string): boolean {
  let current = encodedKey;
  for (let pass = 0; pass < MAX_NESTED_URL_DECODE_PASSES; pass += 1) {
    const decoded = decodeUrlParameterOnce(current);
    if (/[?&;=]/.test(decoded) || containsDecodedSensitiveUrlMaterial(decoded)) return true;
    if (decoded === current || !/%[0-9a-f]{2}/i.test(decoded)) break;
    current = decoded;
  }
  let fullyLayered = '';
  for (let index = 0; index < encodedKey.length; ) {
    const decoded = readLayeredUrlParameterCharacter(encodedKey, index);
    index = decoded.nextIndex;
    if (/[?&;=]/.test(decoded.character)) return true;
    if (fullyLayered.length <= 512) fullyLayered += decoded.character;
  }
  return (
    containsDecodedSensitiveUrlMaterial(fullyLayered) ||
    containsFullyLayeredSensitiveMaterial(encodedKey) ||
    containsLayeredEncodedStreamingSensitiveMaterial(encodedKey) ||
    hasResidualDecodablePercentAfterLayeredRead(encodedKey)
  );
}

function redactUrlParameters(serialized: string): { value: string; redacted: boolean } {
  let redacted = false;
  const value = serialized.replace(
    /(^|[?&;])([^=?&;]+)=([^?&;]*)/g,
    (match, delimiter: string, encodedKey: string, encodedValue: string) => {
      if (
        !isSensitiveEncodedUrlQueryKey(encodedKey) &&
        !containsNestedSensitiveUrlMaterial(encodedValue)
      ) {
        return match;
      }
      redacted = true;
      const outputKey = encodedUrlQueryKeyContainsSensitivePayload(encodedKey)
        ? '[REDACTED_KEY]'
        : encodedKey;
      return `${delimiter}${outputKey}=[REDACTED]`;
    },
  );
  return {
    value,
    redacted,
  };
}

export interface SanitizerPolicy {
  preserveStringAtPath?: (path: string) => boolean;
  containsSensitiveStringAtPath?: (value: string, path: string) => boolean;
  sanitizeStringAtPath?: (value: string, path: string) => string;
  redactUrlLocations?: boolean;
  redactPii?: boolean;
  allowCredentialMetadata?: boolean;
  onRedaction?: (path: string) => void;
}

export function findSensitiveFieldPath(
  value: unknown,
  prefix = '',
  policy: SanitizerPolicy = {},
): string | null {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findSensitiveFieldPath(value[index], `${prefix}[${index}]`, policy);
      if (found) return found;
    }
    return null;
  }
  if (typeof value === 'string') {
    if (policy.preserveStringAtPath?.(prefix)) {
      return policy.containsSensitiveStringAtPath?.(value, prefix) ? prefix || '$' : null;
    }
    return containsSensitiveText(value, policy.redactUrlLocations, policy.redactPii)
      ? prefix || '$'
      : null;
  }
  if (typeof value !== 'object' || value === null) return null;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (redactSensitiveText(key, policy.redactUrlLocations, policy.redactPii) !== key) {
      return prefix ? `${prefix}.[REDACTED_KEY]` : '[REDACTED_KEY]';
    }
    if (isSensitiveKey(key, policy.allowCredentialMetadata === false)) return path;
    const found = findSensitiveFieldPath(child, path, policy);
    if (found) return found;
  }
  return null;
}

export function sanitizeResponse(data: unknown, policy: SanitizerPolicy = {}, path = ''): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') {
    if (policy.preserveStringAtPath?.(path)) {
      return policy.sanitizeStringAtPath?.(data, path) ?? data;
    }
    const sanitized = redactSensitiveText(data, policy.redactUrlLocations, policy.redactPii);
    if (sanitized !== data) policy.onRedaction?.(path || '$');
    return sanitized;
  }
  if (typeof data !== 'object') return data;
  if (Array.isArray(data)) {
    return data.map((value, index) => sanitizeResponse(value, policy, `${path}[${index}]`));
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    const sanitizedKey = redactSensitiveText(key, policy.redactUrlLocations, policy.redactPii);
    const outputKey =
      sanitizedKey === key ? key : `[REDACTED_KEY_${Object.keys(result).length + 1}]`;
    const strictKeyChanged = policy.allowCredentialMetadata === false && sanitizedKey !== key;
    if (strictKeyChanged || isSensitiveKey(key, policy.allowCredentialMetadata === false)) {
      policy.onRedaction?.(path ? `${path}.${outputKey}` : outputKey);
      result[outputKey] = '[REDACTED]';
    } else {
      if (sanitizedKey !== key) policy.onRedaction?.(path ? `${path}.${outputKey}` : outputKey);
      result[outputKey] = sanitizeResponse(
        value,
        policy,
        path ? `${path}.${outputKey}` : outputKey,
      );
    }
  }
  return result;
}

/**
 * Preserve the historical global sanitizer contract for an already byte-bounded JSON response
 * without using the JavaScript call stack. The explicit node budget must come from the accepted
 * transport size; JSON cannot contain more values than serialized bytes. Cycles are impossible on
 * the wire, but are handled defensively for tests and custom in-memory transports.
 */
export function sanitizeResponseIterative(data: unknown, maxNodes: number): unknown {
  const sanitizeLeaf = (value: unknown): unknown =>
    typeof value === 'string' ? redactSensitiveText(value) : value;
  if (data === null || typeof data !== 'object') return sanitizeLeaf(data);

  type Frame = {
    input: object;
    output: Record<string, unknown> | unknown[];
    key?: string;
    keyCursor?: string;
    keyCursorOffset: number;
    index: number;
  };
  const objectKeys = (value: object, maxEntries: number): string[] => {
    const keys: string[] = [];
    if (value instanceof Error) keys.push('name', 'message');
    for (const key in value) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
      if (value instanceof Error && (key === 'name' || key === 'message')) continue;
      if (keys.length >= maxEntries) throw new Error('Sanitizer maximum object keys exceeded');
      keys.push(key);
    }
    if (keys.length > maxEntries) throw new Error('Sanitizer maximum object keys exceeded');
    return keys;
  };
  const encodeKeyCursor = (keys: string[]): string => {
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index] ?? '';
      keys[index] = `${key.length.toString(36)}:${key}`;
    }
    return keys.join('');
  };
  const nextFrameKey = (frame: Frame): string | undefined => {
    if (frame.key !== undefined) {
      const key = frame.key;
      frame.key = undefined;
      return key;
    }
    const cursor = frame.keyCursor;
    if (cursor === undefined || frame.keyCursorOffset >= cursor.length) return undefined;
    const separator = cursor.indexOf(':', frame.keyCursorOffset);
    const keyLength = Number.parseInt(cursor.slice(frame.keyCursorOffset, separator), 36);
    const keyStart = separator + 1;
    const keyEnd = keyStart + keyLength;
    frame.keyCursorOffset = keyEnd;
    return cursor.slice(keyStart, keyEnd);
  };
  const makeFrame = (
    input: object,
    output: Record<string, unknown> | unknown[],
    remainingNodes: number,
  ): Frame => {
    if (Array.isArray(input)) return { input, output, keyCursorOffset: 0, index: 0 };
    const keys = objectKeys(input, remainingNodes);
    // Retaining an Object.keys array at every level amplified transport-bounded deep responses.
    // A scalar handles the common singleton shape; every wider shape uses one compact ordered
    // cursor string, so enumeration order is preserved without a per-depth array or generator.
    if (keys.length === 1) {
      return { input, output, key: keys[0], keyCursorOffset: 0, index: 0 };
    }
    return { input, output, keyCursor: encodeKeyCursor(keys), keyCursorOffset: 0, index: 0 };
  };
  const root: Record<string, unknown> | unknown[] = Array.isArray(data) ? [] : {};
  const ancestors = new Set<object>([data]);
  const stack: Frame[] = [makeFrame(data, root, maxNodes)];
  let visitedNodes = 1;

  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    const isArray = Array.isArray(frame.input);
    if (isArray && frame.index >= (frame.input as unknown[]).length) {
      ancestors.delete(frame.input);
      stack.pop();
      continue;
    }
    if (isArray) {
      const child = (frame.input as unknown[])[frame.index];
      frame.index += 1;
      visitedNodes += 1;
      if (visitedNodes > maxNodes) throw new Error('Sanitizer maximum nodes exceeded');
      const output = frame.output as unknown[];
      if (child === null || typeof child !== 'object') {
        output.push(sanitizeLeaf(child));
        continue;
      }
      if (ancestors.has(child)) {
        output.push('[CIRCULAR]');
        continue;
      }
      const childOutput: Record<string, unknown> | unknown[] = Array.isArray(child) ? [] : {};
      output.push(childOutput);
      ancestors.add(child);
      stack.push(makeFrame(child, childOutput, maxNodes - visitedNodes + 1));
      continue;
    }

    const key = nextFrameKey(frame);
    if (key === undefined) {
      ancestors.delete(frame.input);
      stack.pop();
      continue;
    }
    let child: unknown;
    try {
      child = (frame.input as Record<string, unknown>)[key];
    } catch {
      child = '[UNREADABLE]';
    }
    frame.index += 1;
    visitedNodes += 1;
    if (visitedNodes > maxNodes) throw new Error('Sanitizer maximum nodes exceeded');

    const sanitizedKey = redactSensitiveText(key);
    const outputKey = sanitizedKey === key ? key : `[REDACTED_KEY_${frame.index}]`;
    const output = frame.output as Record<string, unknown>;

    if (isSensitiveKey(key)) {
      output[outputKey] = '[REDACTED]';
      continue;
    }
    if (child === null || typeof child !== 'object') {
      output[outputKey] = sanitizeLeaf(child);
      continue;
    }
    if (ancestors.has(child)) {
      output[outputKey] = '[CIRCULAR]';
      continue;
    }

    const childOutput: Record<string, unknown> | unknown[] = Array.isArray(child) ? [] : {};
    output[outputKey] = childOutput;
    ancestors.add(child);
    stack.push(makeFrame(child, childOutput, maxNodes - visitedNodes + 1));
  }

  return root;
}

export interface BoundedSanitizerOptions extends SanitizerPolicy {
  maxDepth?: number;
  maxArrayItems?: number;
  maxObjectKeys?: number;
  maxStringLength?: number;
}

type SanitizerLimits = Required<
  Omit<
    BoundedSanitizerOptions,
    | 'preserveStringAtPath'
    | 'containsSensitiveStringAtPath'
    | 'sanitizeStringAtPath'
    | 'redactUrlLocations'
    | 'redactPii'
    | 'allowCredentialMetadata'
    | 'onRedaction'
  >
>;

const BOUNDED_DEFAULTS: SanitizerLimits = {
  maxDepth: 12,
  maxArrayItems: 100,
  maxObjectKeys: 100,
  maxStringLength: 16_384,
};

export function findSensitiveFieldPathBounded(
  value: unknown,
  options: BoundedSanitizerOptions = {},
): string | null {
  const limits: SanitizerLimits = { ...BOUNDED_DEFAULTS, ...options };
  const ancestors = new Set<object>();

  function visit(current: unknown, path: string, depth: number): string | null {
    assertTraversalBound(current, depth, limits);
    if (typeof current === 'string') {
      if (options.preserveStringAtPath?.(path)) {
        return options.containsSensitiveStringAtPath?.(current, path) ? path || '$' : null;
      }
      return containsSensitiveText(current, options.redactUrlLocations, options.redactPii)
        ? path || '$'
        : null;
    }
    if (current === null || typeof current !== 'object') return null;
    if (ancestors.has(current)) return null;
    ancestors.add(current);
    for (const [key, child] of safeEntries(current, limits.maxObjectKeys)) {
      const childPath = Array.isArray(current) ? `${path}[${key}]` : path ? `${path}.${key}` : key;
      if (
        !Array.isArray(current) &&
        redactSensitiveText(key, options.redactUrlLocations, options.redactPii) !== key
      ) {
        return path ? `${path}.[REDACTED_KEY]` : '[REDACTED_KEY]';
      }
      if (isSensitiveKey(key, options.allowCredentialMetadata === false)) return childPath;
      const found = visit(child, childPath, depth + 1);
      if (found) return found;
    }
    ancestors.delete(current);
    return null;
  }

  return visit(value, '', 0);
}

export function sanitizeResponseBounded(
  value: unknown,
  options: BoundedSanitizerOptions = {},
): unknown {
  const limits: SanitizerLimits = { ...BOUNDED_DEFAULTS, ...options };
  const ancestors = new Set<object>();

  function visit(current: unknown, path: string, depth: number): unknown {
    assertTraversalBound(current, depth, limits);
    if (typeof current === 'string') {
      if (options.preserveStringAtPath?.(path)) {
        return options.sanitizeStringAtPath?.(current, path) ?? current;
      }
      const sanitized = redactSensitiveText(current, options.redactUrlLocations, options.redactPii);
      if (sanitized !== current) options.onRedaction?.(path || '$');
      return sanitized;
    }
    if (current === null || typeof current !== 'object') return current;
    if (ancestors.has(current)) return '[CIRCULAR]';
    ancestors.add(current);
    const result: Record<string, unknown> | unknown[] = Array.isArray(current) ? [] : {};
    for (const [key, child] of safeEntries(current, limits.maxObjectKeys)) {
      const sanitizedKey = Array.isArray(current)
        ? key
        : redactSensitiveText(key, options.redactUrlLocations, options.redactPii);
      const outputKey =
        sanitizedKey === key ? key : `[REDACTED_KEY_${Object.keys(result).length + 1}]`;
      const childPath = Array.isArray(current)
        ? `${path}[${key}]`
        : path
          ? `${path}.${outputKey}`
          : outputKey;
      const sensitiveKey =
        (options.allowCredentialMetadata === false && sanitizedKey !== key) ||
        isSensitiveKey(key, options.allowCredentialMetadata === false);
      if (!Array.isArray(current) && sanitizedKey !== key && !sensitiveKey) {
        options.onRedaction?.(childPath);
      }
      if (sensitiveKey) options.onRedaction?.(childPath);
      const sanitized = sensitiveKey ? '[REDACTED]' : visit(child, childPath, depth + 1);
      if (Array.isArray(result)) result.push(sanitized);
      else result[outputKey] = sanitized;
    }
    ancestors.delete(current);
    return result;
  }

  return visit(value, '', 0);
}

function assertTraversalBound(value: unknown, depth: number, limits: SanitizerLimits): void {
  if (depth > limits.maxDepth) throw new Error('Sanitizer maximum depth exceeded');
  if (typeof value === 'string' && value.length > limits.maxStringLength) {
    throw new Error('Sanitizer maximum string length exceeded');
  }
  if (Array.isArray(value) && value.length > limits.maxArrayItems) {
    throw new Error('Sanitizer maximum array items exceeded');
  }
}

function safeEntries(value: object, maxEntries: number): Array<[string, unknown]> {
  if (Array.isArray(value)) return value.map((child, index) => [String(index), child]);
  const entries: Array<[string, unknown]> = [];
  if (value instanceof Error) {
    entries.push(['name', value.name], ['message', value.message]);
  }
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    if (value instanceof Error && (key === 'name' || key === 'message')) continue;
    if (entries.length >= maxEntries) throw new Error('Sanitizer maximum object keys exceeded');
    try {
      entries.push([key, (value as Record<string, unknown>)[key]]);
    } catch {
      entries.push([key, '[UNREADABLE]']);
    }
  }
  if (entries.length > maxEntries) throw new Error('Sanitizer maximum object keys exceeded');
  return entries;
}

function redactSensitiveText(value: string, redactUrlLocations = false, redactPii = false): string {
  let sanitized = value.replace(HIERARCHICAL_URL_IN_TEXT, (candidate) =>
    redactHierarchicalUrl(candidate, redactUrlLocations),
  );
  for (const pattern of HIGH_CONFIDENCE_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }
  sanitized = redactGenericCredentialText(sanitized).replace(
    /(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi,
    '$1[REDACTED]@',
  );
  return redactPii
    ? sanitized
        .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED_EMAIL]')
        .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
        .replace(/\b(?:\d[ -]*?){13,19}\b/g, '[REDACTED_NUMBER]')
        .replace(/(?:^|\s)\+?\d[\d ().-]{7,}\d(?=$|\s)/g, ' [REDACTED_PHONE]')
    : sanitized;
}

function redactHierarchicalUrl(value: string, redactLocation: boolean): string {
  try {
    const parsed = new URL(value);
    if (!redactLocation) {
      const hadUserInfo = Boolean(parsed.username || parsed.password);
      const query = redactUrlParameters(parsed.search.slice(1));
      const fragmentBody = parsed.hash.slice(1);
      let fragment = fragmentBody.includes('=')
        ? redactUrlParameters(fragmentBody)
        : { value: fragmentBody, redacted: false };
      const fragmentQueryStart = ['?', ';', '&'].reduce((earliest, delimiter) => {
        const index = fragmentBody.indexOf(delimiter);
        return index >= 0 && (earliest < 0 || index < earliest) ? index : earliest;
      }, -1);
      const fragmentPrefix =
        fragmentQueryStart >= 0 ? fragmentBody.slice(0, fragmentQueryStart) : fragmentBody;
      const fragmentLocation =
        fragmentQueryStart >= 0 && !fragmentPrefix.includes('=')
          ? fragmentPrefix
          : fragmentBody.includes('=')
            ? ''
            : fragmentBody;
      if (containsSensitiveUrlLocationMaterial(fragmentLocation)) {
        fragment = { value: '[REDACTED_FRAGMENT]', redacted: true };
      }
      const redactPath = containsSensitiveUrlLocationMaterial(parsed.pathname);
      if (!hadUserInfo && !query.redacted && !fragment.redacted && !redactPath) return value;
      const authority = `${parsed.protocol}//${hadUserInfo ? '[REDACTED]@' : ''}${parsed.host}`;
      const hash = parsed.hash ? `#${fragment.redacted ? fragment.value : fragmentBody}` : '';
      const pathname = redactPath ? '/[REDACTED_PATH]' : parsed.pathname;
      return `${authority}${pathname}${query.value ? `?${query.value}` : ''}${hash}`;
    }
    const hasSensitiveLocation =
      Boolean(parsed.username || parsed.password || parsed.search || parsed.hash) ||
      (parsed.pathname !== '' && parsed.pathname !== '/');
    const origin = `${parsed.protocol}//${parsed.host}`;
    return hasSensitiveLocation ? `${origin}/[REDACTED_PATH]` : origin;
  } catch {
    if (redactLocation) return '[REDACTED_URL]';
    const schemeEnd = value.indexOf('://');
    const authorityStart = schemeEnd + 3;
    let authorityEnd = value.length;
    for (const delimiter of ['/', '?', '#']) {
      const delimiterIndex = value.indexOf(delimiter, authorityStart);
      if (delimiterIndex >= 0 && delimiterIndex < authorityEnd) authorityEnd = delimiterIndex;
    }
    const atIndex = value.lastIndexOf('@', authorityEnd - 1);
    return atIndex >= authorityStart
      ? `${value.slice(0, authorityStart)}[REDACTED]@${value.slice(atIndex + 1)}`
      : value;
  }
}
