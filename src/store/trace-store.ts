/**
 * Trace Store
 *
 * Higher-level trace event management with session organization.
 */

import type { TraceEventWithId, TraceSearchFilter, TraceEventType } from '../types.js';
import { EventBuffer, type EventBufferRetention } from '../client/event-buffer.js';

export type TraceRetention = EventBufferRetention;

export class TraceStore {
  private globalBuffer: EventBuffer;
  private sessionBuffers: Map<string, EventBuffer> = new Map();
  private maxSessionBufferSize: number;

  constructor(globalBufferSize = 1000, sessionBufferSize = 500) {
    this.globalBuffer = new EventBuffer(globalBufferSize);
    this.maxSessionBufferSize = sessionBufferSize;
  }

  /**
   * Add a trace event
   */
  addEvent(event: TraceEventWithId): void {
    // Add to global buffer
    this.globalBuffer.push(event);

    // Add to session buffer
    let sessionBuffer = this.sessionBuffers.get(event.sessionId);
    if (!sessionBuffer) {
      sessionBuffer = new EventBuffer(this.maxSessionBufferSize);
      this.sessionBuffers.set(event.sessionId, sessionBuffer);
    }
    sessionBuffer.push(event);
  }

  /**
   * Get recent events from global buffer
   */
  getRecent(limit?: number, types?: TraceEventType[]): TraceEventWithId[] {
    return this.globalBuffer.getRecent(limit, types);
  }

  /**
   * Get events for a specific session
   */
  getBySession(sessionId: string, limit?: number, types?: TraceEventType[]): TraceEventWithId[] {
    const sessionBuffer = this.sessionBuffers.get(sessionId);
    if (!sessionBuffer) {
      return [];
    }
    return sessionBuffer.getRecent(limit, types);
  }

  /**
   * Search events with filters
   */
  search(filter: TraceSearchFilter, sessionId?: string): TraceEventWithId[] {
    if (sessionId) {
      const sessionBuffer = this.sessionBuffers.get(sessionId);
      if (!sessionBuffer) {
        return [];
      }
      return sessionBuffer.search(filter);
    }
    return this.globalBuffer.search(filter);
  }

  /**
   * Get all errors and warnings
   */
  getErrors(sessionId?: string): TraceEventWithId[] {
    if (sessionId) {
      const sessionBuffer = this.sessionBuffers.get(sessionId);
      return sessionBuffer ? sessionBuffer.getErrors() : [];
    }
    return this.globalBuffer.getErrors();
  }

  /**
   * Get event by ID
   */
  getById(id: string): TraceEventWithId | undefined {
    return this.globalBuffer.getById(id);
  }

  /**
   * Get events by span
   */
  getBySpan(spanId: string): TraceEventWithId[] {
    return this.globalBuffer.getBySpan(spanId);
  }

  /**
   * Clear session buffer
   */
  clearSession(sessionId: string): void {
    const sessionBuffer = this.sessionBuffers.get(sessionId);
    if (sessionBuffer) {
      sessionBuffer.clear();
    }
  }

  /**
   * Clear all
   */
  clear(): void {
    this.globalBuffer.clear();
    this.sessionBuffers.clear();
  }

  /**
   * Get statistics
   */
  getStats(): { globalSize: number; sessionCount: number; sessionSizes: Record<string, number> } {
    const sessionSizes: Record<string, number> = {};
    for (const [sessionId, buffer] of this.sessionBuffers) {
      sessionSizes[sessionId] = buffer.size();
    }
    return {
      globalSize: this.globalBuffer.size(),
      sessionCount: this.sessionBuffers.size,
      sessionSizes,
    };
  }

  /**
   * Return retention metadata for the same bounded source used by a trace read.
   * A missing session is an empty, non-truncated session buffer.
   */
  getRetention(sessionId?: string): TraceRetention {
    if (sessionId) {
      return (
        this.sessionBuffers.get(sessionId)?.getRetention() ?? {
          maxSize: this.maxSessionBufferSize,
          retainedCount: 0,
          evictedCount: 0,
          isTruncated: false,
        }
      );
    }

    return this.globalBuffer.getRetention();
  }
}
