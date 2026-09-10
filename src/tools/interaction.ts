/**
 * Interaction Tools
 *
 * debug_send_message - Send a message to the agent
 */

import { z } from 'zod';
import type { DebugContext } from './index.js';
import { summarizeTurnOutcome } from './turn-outcome.js';

// =============================================================================
// debug_send_message
// =============================================================================

export const sendMessageSchema = z.object({
  text: z.string().describe('Message text to send to the agent'),
  sessionId: z.string().optional().describe('Session ID (uses active session if not specified)'),
  waitForResponse: z
    .boolean()
    .optional()
    .default(true)
    .describe('Wait for agent response before returning'),
  timeout: z.number().optional().default(60000).describe('Timeout in ms when waiting for response'),
});

export type SendMessageArgs = z.infer<typeof sendMessageSchema>;

export async function sendMessage(args: SendMessageArgs, ctx: DebugContext): Promise<string> {
  const { text, waitForResponse = true, timeout = 60000 } = args;

  // Use active session if not specified
  const sessionId = args.sessionId || ctx.sessionStore.getActiveSessionId();

  if (!sessionId) {
    return JSON.stringify({
      success: false,
      error:
        'No session specified and no active session. Load an agent first with debug_load_agent.',
    });
  }

  const wsClient = ctx.sessionConnections?.get(sessionId) ?? ctx.wsClient;
  if (ctx.sessionConnections && wsClient === ctx.wsClient) {
    return JSON.stringify({
      success: false,
      error: `Dedicated connection unavailable for session: ${sessionId}. Load the agent again.`,
    });
  }

  // Ensure connected
  if (!wsClient.isConnected()) {
    return JSON.stringify({
      success: false,
      error: 'Not connected to server. Call platform_connect first.',
    });
  }

  // Update session activity
  ctx.sessionStore.touchSession(sessionId);

  // Bound turn-failure attribution to this message: an error from an earlier
  // turn in the same session must not mark this one failed.
  const sentAtMs = Date.now();

  if (!waitForResponse) {
    // Fire and forget
    wsClient.sendMessage(sessionId, text);
    return JSON.stringify({
      success: true,
      sessionId,
      message: 'Message sent (not waiting for response)',
      sentText: text,
    });
  }

  // Wait for response
  return new Promise((resolve) => {
    let resolved = false;
    let responseText = '';
    let currentMessageId = '';
    const chunks: string[] = [];

    const timeoutId = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve(
          JSON.stringify({
            success: false,
            error: 'Timeout waiting for response',
            partialResponse: chunks.join(''),
          }),
        );
      }
    }, timeout);

    const cleanup = () => {
      wsClient.onResponseStart = originalOnResponseStart;
      wsClient.onResponseChunk = originalOnResponseChunk;
      wsClient.onResponseEnd = originalOnResponseEnd;
      wsClient.onError = originalOnError;
    };

    // Store original handlers
    const originalOnResponseStart = wsClient.onResponseStart;
    const originalOnResponseChunk = wsClient.onResponseChunk;
    const originalOnResponseEnd = wsClient.onResponseEnd;
    const originalOnError = wsClient.onError;

    // Set up temporary handlers
    wsClient.onResponseStart = (msgSessionId, messageId) => {
      if (msgSessionId === sessionId) {
        currentMessageId = messageId;
      }
      originalOnResponseStart?.(msgSessionId, messageId);
    };

    wsClient.onResponseChunk = (msgSessionId, messageId, chunk) => {
      if (msgSessionId === sessionId && messageId === currentMessageId) {
        chunks.push(chunk);
      }
      originalOnResponseChunk?.(msgSessionId, messageId, chunk);
    };

    wsClient.onResponseEnd = (msgSessionId, messageId, fullText) => {
      if (msgSessionId === sessionId && messageId === currentMessageId) {
        responseText = fullText;
        clearTimeout(timeoutId);
        if (!resolved) {
          resolved = true;
          cleanup();
          // A response frame is not the same as an answer: the runtime can end
          // a turn with a fallback apology after `execution.failed`. Report the
          // turn outcome so a caller cannot mistake a broken project for a
          // working one.
          const outcome = summarizeTurnOutcome(ctx.traceStore.getBySession(sessionId), {
            sinceMs: sentAtMs,
          });
          resolve(
            JSON.stringify({
              success: outcome.status === 'answered',
              turnStatus: outcome.status,
              sessionId,
              messageId,
              sentText: text,
              response: responseText,
              responseLength: responseText.length,
              ...(outcome.failures.length > 0
                ? {
                    turnFailures: outcome.failures,
                    error: `The agent did not complete this turn: ${outcome.failures
                      .map((failure) => (failure.code ? `${failure.code}: ` : '') + failure.message)
                      .join('; ')}`,
                  }
                : {}),
            }),
          );
        }
      }
      originalOnResponseEnd?.(msgSessionId, messageId, fullText);
    };

    wsClient.onError = (message) => {
      clearTimeout(timeoutId);
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve(
          JSON.stringify({
            success: false,
            error: message,
          }),
        );
      }
      originalOnError?.(message);
    };

    // Send the message
    wsClient.sendMessage(sessionId, text);
  });
}
