/**
 * An in-memory session store.
 *
 * FOR TESTS AND LOCAL DEVELOPMENT ONLY, and the name says so rather than
 * leaving it to a comment somebody skims. It is included because writing a
 * throwaway store is the first thing every consumer would otherwise do, and a
 * wrong throwaway store is worse than this one.
 *
 * Why it is not for production, in the order the problems arrive:
 *
 *   - Sessions live in one process. Two workers behind a load balancer do not
 *     share them, so signing in is a coin flip and staying signed in is worse.
 *   - A restart signs everybody out.
 *   - Nothing is ever purged, so an expired session that is never read again
 *     is held for the life of the process.
 *
 * A real store is a table with an index on the hash, and — because §3.5's
 * revocation has to reach every session of an identity session — one on
 * `identitySessionId` too.
 */

import type { SessionRecord, SessionStore } from './session.js';

export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, SessionRecord>();

  async create(record: SessionRecord): Promise<void> {
    this.sessions.set(record.idHash, { ...record });
  }

  async find(idHash: string): Promise<SessionRecord | null> {
    const found = this.sessions.get(idHash);
    // A copy, so a caller mutating what it read cannot rewrite the store
    // by accident — the behaviour a real store has for free.
    return found ? { ...found } : null;
  }

  async touch(idHash: string, lastActivityAt: Date): Promise<void> {
    const found = this.sessions.get(idHash);
    if (found) found.lastActivityAt = lastActivityAt;
  }

  async recordCheck(idHash: string, lastCheckedAt: Date): Promise<void> {
    const found = this.sessions.get(idHash);
    if (found) found.lastCheckedAt = lastCheckedAt;
  }

  async delete(idHash: string): Promise<void> {
    this.sessions.delete(idHash);
  }

  async deleteBySubject(subject: string): Promise<void> {
    for (const [hash, record] of this.sessions) {
      if (record.subject === subject) this.sessions.delete(hash);
    }
  }

  async deleteByIdentitySession(identitySessionId: string): Promise<void> {
    for (const [hash, record] of this.sessions) {
      if (record.identitySessionId === identitySessionId) this.sessions.delete(hash);
    }
  }

  /** Test helper. */
  get size(): number {
    return this.sessions.size;
  }
}
