/**
 * Lift the actionable part of an upstream error body into the caller-visible
 * error string.
 *
 * A tool that answers only `"POST /api/… failed: 500 Internal Server Error"`
 * hides the reason two levels down in `body.error`. Agent callers report the
 * top-level string, so a precise platform diagnosis
 * (`STAGING_FAILED — two records share the same unique key`) reached users as
 * "the platform is broken". `platform_integrations` already surfaces
 * `body.error`; this keeps every tool consistent with that.
 */

/** The `{ code, message }` shape used by the platform's structured errors. */
interface UpstreamErrorShape {
  code?: unknown;
  message?: unknown;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

/**
 * Extract a short `CODE: message` (or either half) from a platform error body.
 * Returns `null` when the body carries nothing more useful than the status line.
 *
 * Handles the shapes the platform actually emits:
 * - `{ error: { code, message } }` — structured route errors
 * - `{ error: "text" }` — legacy string errors
 * - `{ errors: [{ code, msg }] }` — validation envelopes
 */
export function describeUpstreamError(body: unknown): string | null {
  const record = asRecord(body);
  if (!record) {
    return readString(body);
  }

  const nested = asRecord(record.error) as UpstreamErrorShape | null;
  if (nested) {
    const code = readString(nested.code);
    const message = readString(nested.message);
    if (code && message) {
      return `${code}: ${message}`;
    }
    return message ?? code;
  }

  const flat = readString(record.error);
  if (flat) {
    return flat;
  }

  if (Array.isArray(record.errors)) {
    const parts: string[] = [];
    for (const entry of record.errors) {
      const item = asRecord(entry);
      if (!item) {
        const text = readString(entry);
        if (text) {
          parts.push(text);
        }
        continue;
      }
      const code = readString(item.code);
      const message = readString(item.message) ?? readString(item.msg);
      if (code && message) {
        parts.push(`${code}: ${message}`);
      } else if (message ?? code) {
        parts.push((message ?? code) as string);
      }
    }
    if (parts.length > 0) {
      return parts.join('; ');
    }
  }

  return readString(record.message);
}

/**
 * Build the caller-visible error string for a failed HTTP call, appending the
 * upstream cause when the body has one.
 */
export function buildUpstreamErrorMessage(
  requestSummary: string,
  status: number,
  statusText: string,
  body: unknown,
): string {
  const base = `${requestSummary} failed: ${status} ${statusText}`;
  const detail = describeUpstreamError(body);
  return detail ? `${base}: ${detail}` : base;
}
