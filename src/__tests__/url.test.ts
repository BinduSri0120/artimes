/**
 * Tests for URL utility — deriveUrls()
 */

import { describe, test, expect } from 'vitest';
import { deriveUrls, isRemoteUrl } from '../utils/url.js';

describe('deriveUrls', () => {
  // HTTP → WS derivation
  describe('http → ws derivation', () => {
    test('http://localhost:3112 derives ws://localhost:3112/ws', () => {
      const result = deriveUrls('http://localhost:3112');
      expect(result.httpUrl).toBe('http://localhost:3112');
      expect(result.wsUrl).toBe('ws://localhost:3112/ws');
    });

    test('https://api.example.com derives wss://api.example.com/ws', () => {
      const result = deriveUrls('https://api.example.com');
      expect(result.httpUrl).toBe('https://api.example.com');
      expect(result.wsUrl).toBe('wss://api.example.com/ws');
    });

    test('http with port derives ws with same port', () => {
      const result = deriveUrls('http://myhost:8080');
      expect(result.httpUrl).toBe('http://myhost:8080');
      expect(result.wsUrl).toBe('ws://myhost:8080/ws');
    });

    test('https with port derives wss with same port', () => {
      const result = deriveUrls('https://myhost:443');
      expect(result.httpUrl).toBe('https://myhost:443');
      expect(result.wsUrl).toBe('wss://myhost:443/ws');
    });
  });

  // WS → HTTP derivation
  describe('ws → http derivation', () => {
    test('ws://localhost:3112/ws derives http://localhost:3112', () => {
      const result = deriveUrls('ws://localhost:3112/ws');
      expect(result.httpUrl).toBe('http://localhost:3112');
      expect(result.wsUrl).toBe('ws://localhost:3112/ws');
    });

    test('wss://api.example.com/ws derives https://api.example.com', () => {
      const result = deriveUrls('wss://api.example.com/ws');
      expect(result.httpUrl).toBe('https://api.example.com');
      expect(result.wsUrl).toBe('wss://api.example.com/ws');
    });

    test('ws:// without /ws path gets /ws appended', () => {
      const result = deriveUrls('ws://localhost:3112');
      expect(result.httpUrl).toBe('http://localhost:3112');
      expect(result.wsUrl).toBe('ws://localhost:3112/ws');
    });
  });

  // Trailing slashes
  describe('trailing slash handling', () => {
    test('strips trailing slash from http URL', () => {
      const result = deriveUrls('http://localhost:3112/');
      expect(result.httpUrl).toBe('http://localhost:3112');
      expect(result.wsUrl).toBe('ws://localhost:3112/ws');
    });

    test('strips multiple trailing slashes', () => {
      const result = deriveUrls('http://localhost:3112///');
      expect(result.httpUrl).toBe('http://localhost:3112');
      expect(result.wsUrl).toBe('ws://localhost:3112/ws');
    });

    test('strips trailing slash from ws URL', () => {
      const result = deriveUrls('ws://localhost:3112/ws/');
      expect(result.httpUrl).toBe('http://localhost:3112');
      expect(result.wsUrl).toBe('ws://localhost:3112/ws');
    });
  });
});

describe('isRemoteUrl', () => {
  describe('local URLs', () => {
    test('localhost is not remote', () => {
      expect(isRemoteUrl('http://localhost:3112')).toBe(false);
    });

    test('127.0.0.1 is not remote', () => {
      expect(isRemoteUrl('http://127.0.0.1:3112')).toBe(false);
    });

    test('::1 is not remote', () => {
      expect(isRemoteUrl('http://[::1]:3112')).toBe(false);
    });

    test('0.0.0.0 is not remote', () => {
      expect(isRemoteUrl('http://0.0.0.0:3112')).toBe(false);
    });

    test('ws://localhost is not remote', () => {
      expect(isRemoteUrl('ws://localhost:3112/ws')).toBe(false);
    });

    test('wss://localhost is not remote', () => {
      expect(isRemoteUrl('wss://localhost:3112/ws')).toBe(false);
    });
  });

  describe('remote URLs', () => {
    test('agents-dev.kore.ai is remote', () => {
      expect(isRemoteUrl('https://agents-dev.kore.ai')).toBe(true);
    });

    test('api.example.com is remote', () => {
      expect(isRemoteUrl('http://api.example.com:3112')).toBe(true);
    });

    test('wss://remote-host/ws is remote', () => {
      expect(isRemoteUrl('wss://remote-host.example.com/ws')).toBe(true);
    });

    test('192.168.1.100 is remote', () => {
      expect(isRemoteUrl('http://192.168.1.100:3112')).toBe(true);
    });
  });

  describe('edge cases', () => {
    test('invalid URL returns false', () => {
      expect(isRemoteUrl('not-a-url')).toBe(false);
    });

    test('empty string returns false', () => {
      expect(isRemoteUrl('')).toBe(false);
    });
  });
});

describe('toRuntimeOwnedApiPath', () => {
  test('rewrites Runtime-owned project paths through the Studio passthrough on hosted origins', async () => {
    const { toRuntimeOwnedApiPath } = await import('../utils/url.js');
    expect(
      toRuntimeOwnedApiPath('https://agents-staging.kore.ai', '/api/projects/p1/sessions?limit=5'),
    ).toBe('/api/runtime/projects/p1/sessions?limit=5');
    expect(
      toRuntimeOwnedApiPath('https://agents.kore.ai', '/api/projects/p1/sessions/s1/traces'),
    ).toBe('/api/runtime/projects/p1/sessions/s1/traces');
    expect(
      toRuntimeOwnedApiPath('https://agents.kore.ai', '/api/projects/p1/sdk-public-keys'),
    ).toBe('/api/runtime/projects/p1/sdk-public-keys');
  });

  test('leaves direct Runtime (local) targets and non-project paths untouched', async () => {
    const { toRuntimeOwnedApiPath } = await import('../utils/url.js');
    expect(toRuntimeOwnedApiPath('http://localhost:3112', '/api/projects/p1/sessions')).toBe(
      '/api/projects/p1/sessions',
    );
    expect(toRuntimeOwnedApiPath('http://127.0.0.1:3112', '/api/projects/p1/sessions')).toBe(
      '/api/projects/p1/sessions',
    );
    expect(toRuntimeOwnedApiPath('https://agents.kore.ai', '/api/agents')).toBe('/api/agents');
    expect(
      toRuntimeOwnedApiPath('https://agents.kore.ai', '/api/runtime/projects/p1/sessions'),
    ).toBe('/api/runtime/projects/p1/sessions');
  });
});
