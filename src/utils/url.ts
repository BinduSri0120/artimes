/**
 * URL Utilities
 *
 * Derives HTTP and WebSocket URLs from a single server URL.
 */

export interface DerivedUrls {
  httpUrl: string;
  wsUrl: string;
}

/**
 * Derive both HTTP and WebSocket URLs from a single server URL.
 */
export function deriveUrls(serverUrl: string): DerivedUrls {
  // Strip trailing slash
  const url = serverUrl.replace(/\/+$/, '');

  // If given a WebSocket URL, derive HTTP from it.
  if (url.startsWith('ws:') || url.startsWith('wss:')) {
    const httpUrl = url.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:').replace(/\/ws$/, '');
    const wsUrl = url.endsWith('/ws') ? url : `${url}/ws`;
    return { httpUrl, wsUrl };
  }

  // Given an HTTP URL, derive a WebSocket URL from it.
  const httpUrl = url;
  const wsUrl = url.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:') + '/ws';

  return { httpUrl, wsUrl };
}

/** Hostnames that are considered local (not remote) */
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

/**
 * Returns true if the URL points to a remote server (not localhost).
 * Used to decide whether to skip the health check before connecting.
 */
export function isRemoteUrl(url: string): boolean {
  try {
    // Normalize WebSocket schemes to HTTP schemes so URL can parse them.
    const normalized = url.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:');
    const parsed = new URL(normalized);
    // URL wraps IPv6 in brackets (e.g. "[::1]") — strip them for comparison
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    return !LOCAL_HOSTS.has(hostname);
  } catch {
    return false;
  }
}

/** Studio-fronted origins expose Runtime-owned project routes under this passthrough prefix. */
const STUDIO_RUNTIME_PASSTHROUGH_PREFIX = '/api/runtime/projects/';
const RUNTIME_PROJECT_API_PREFIX = '/api/projects/';

/**
 * Rewrite a Runtime-owned `/api/projects/...` path for the connected origin.
 *
 * On hosted environments every `/api/*` request reaches Studio first, and Studio
 * only forwards a Runtime-owned project route when it is addressed through the
 * `/api/runtime/projects/...` passthrough; otherwise the request hits a Studio
 * App Router handler with a different envelope or a Next.js 404 page. Direct
 * Runtime targets (localhost) keep the plain path because Runtime has no
 * `/api/runtime` tree of its own.
 */
export function toRuntimeOwnedApiPath(baseUrl: string, path: string): string {
  if (!isRemoteUrl(baseUrl)) return path;
  if (!path.startsWith(RUNTIME_PROJECT_API_PREFIX)) return path;
  return STUDIO_RUNTIME_PASSTHROUGH_PREFIX + path.slice(RUNTIME_PROJECT_API_PREFIX.length);
}

/**
 * Resolve a Runtime-owned project path against the connected HTTP client.
 * Tolerates minimal client stubs (tests/injected transports) that expose no
 * base URL: those keep the plain path.
 */
export function resolveRuntimeOwnedPath(
  httpClient: { getBaseUrl?: () => string } | undefined,
  path: string,
): string {
  const baseUrl = typeof httpClient?.getBaseUrl === 'function' ? httpClient.getBaseUrl() : '';
  return baseUrl ? toRuntimeOwnedApiPath(baseUrl, path) : path;
}
