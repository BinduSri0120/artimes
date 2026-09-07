/**
 * Interaction Tools
 *
 * debug_send_message - Send a message to the agent
 */

import { z } from 'zod';
import type { DebugContext } from './index.js';

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
          resolve(
            JSON.stringify({
              success: true,
              sessionId,
              messageId,
              sentText: text,
              response: responseText,
              responseLength: responseText.length,
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
