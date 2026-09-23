/**
 * The application session — standard v0.9 §3.5, §8.1, §8.3.
 *
 * Distinct from the IDENTITY session, which TeamDeck holds. Each application
 * keeps its own, server-side, and the two are independent except in one
 * direction: an application session INHERITS the identity session's
 * authentication time, so none can outlive the twelve-hour overall limit. A
 * session that started its own clock would quietly extend single sign-on past
 * the cap every time somebody opened a second application.
 *
 * WHAT IS STORED, AND WHAT IS NOT. The browser holds a 256-bit random
 * identifier; the store holds only its SHA-256. Anyone who reads the session
 * table therefore cannot impersonate anybody — a stolen backup is not a bag of
 * live sessions. The identifier is opaque: no JWT, no email, nothing about the
 * person (§8.3), because a cookie value is the one part of this an attacker
 * always gets to see.
 *
 * TIMEOUTS ARE ENFORCED HERE, NOT BY THE COOKIE. §8.2 is explicit that cookie
 * expiry SHALL NOT be what enforces a timeout, and the reason is simple: a
 * cookie's lifetime is a request from the server to the browser, and the
 * browser is the party being authenticated. The server decides.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** §8.3: 256 bits, well above the 64-bit floor. */
const IDENTIFIER_BYTES = 32;

/** §8.1, in minutes. Higher-risk access gets NIST's AAL3 figure. */
export const DEFAULT_INACTIVITY_MINUTES = 60;
export const HIGHER_RISK_INACTIVITY_MINUTES = 15;

/** §8.1: twelve hours from authentication, whatever happens in between. */
export const ABSOLUTE_LIFETIME_HOURS = 12;

export interface SessionRecord {
  /**
   * SHA-256 of the identifier the browser holds. The identifier itself is
   * never written anywhere — not here, not in a log, not in an audit row.
   */
  idHash: string;

  /** The account's identifier at the provider (`sub`). */
  subject: string;
  email?: string;
  name?: string;

  /**
   * INHERITED from the identity session (§3.5). When the person authenticated,
   * not when this session began. The absolute limit is measured from it.
   */
  authTime: Date;

  /** From `amr` — how they authenticated (§3.4). */
  methods: string[];

  /** The identity session this came from, so a revocation can find it (§3.5). */
  identitySessionId?: string;

  createdAt: Date;
  lastActivityAt: Date;

  /**
   * When §3.5's check last confirmed this session with the provider.
   *
   * Separate from lastActivityAt because they answer different questions: one
   * is "is this person still here", the other "does the provider still say
   * this session exists". A busy session still has to be checked, and an idle
   * one still has to be checked before it is used again.
   */
  lastCheckedAt: Date;

  /**
   * The CSRF token for this session (§8.4).
   *
   * Stored in the clear, unlike the session identifier, and the difference is
   * deliberate: this value is useless without the session cookie, and the
   * application has to be able to hand it back to the page on every load. A
   * hash would make it write-only and the page could never be given one again.
   */
  csrfToken: string;

  /** §8.1: shortens the inactivity timeout to 15 minutes. */
  higherRisk: boolean;
}

export type SessionLookup =
  | { status: 'active'; session: SessionRecord }
  | { status: 'none' }
  | { status: 'expired'; reason: 'inactivity' | 'absolute'; session: SessionRecord };

/**
 * Where sessions live. The library does not choose — Inventory has Prisma,
 * another application may have Redis, and a store baked in here would be one
 * more thing to fight.
 *
 * Every method is keyed by the HASH, never the identifier, so an implementation
 * cannot accidentally persist the credential itself.
 */
export interface SessionStore {
  create(record: SessionRecord): Promise<void>;
  find(idHash: string): Promise<SessionRecord | null>;
  touch(idHash: string, lastActivityAt: Date): Promise<void>;
  /** Record that §3.5's check confirmed this session. */
  recordCheck(idHash: string, lastCheckedAt: Date): Promise<void>;
  delete(idHash: string): Promise<void>;

  /** Sign out everywhere. Optional; without it, that feature is unavailable. */
  deleteBySubject?(subject: string): Promise<void>;

  /**
   * How a revocation at the provider reaches this application (§3.5).
   * Optional for the same reason, and needed before production.
   */
  deleteByIdentitySession?(identitySessionId: string): Promise<void>;
}

/** 256 bits, base64url. */
export function createSessionIdentifier(): string {
  return randomBytes(IDENTIFIER_BYTES).toString('base64url');
}

export function hashSessionIdentifier(identifier: string): string {
  return createHash('sha256').update(identifier).digest('base64url');
}

/** A CSRF token of the same strength; it guards the same thing. */
export function createCsrfToken(): string {
  return randomBytes(IDENTIFIER_BYTES).toString('base64url');
}

export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function inactivityLimitMinutes(session: Pick<SessionRecord, 'higherRisk'>): number {
  return session.higherRisk ? HIGHER_RISK_INACTIVITY_MINUTES : DEFAULT_INACTIVITY_MINUTES;
}

/**
 * Both limits, checked in the order that makes the reason useful.
 *
 * Absolute first: a session past twelve hours is finished whether or not
 * somebody has been clicking, and reporting "inactivity" for it would send an
 * operator looking at the wrong thing.
 */
export function expiryOf(
  session: SessionRecord,
  now: Date = new Date(),
): 'inactivity' | 'absolute' | null {
  const absoluteDeadline = session.authTime.getTime() + ABSOLUTE_LIFETIME_HOURS * 3600_000;
  if (now.getTime() >= absoluteDeadline) return 'absolute';

  const idleDeadline =
    session.lastActivityAt.getTime() + inactivityLimitMinutes(session) * 60_000;
  if (now.getTime() >= idleDeadline) return 'inactivity';

  return null;
}

/** §3.5: "at least every 5 minutes". The ceiling, not a suggestion. */
export const SESSION_CHECK_INTERVAL_MS = 5 * 60_000;

/** Whether §3.5's check is due. */
export function checkIsDue(
  session: Pick<SessionRecord, 'lastCheckedAt'>,
  now: Date = new Date(),
  intervalMs: number = SESSION_CHECK_INTERVAL_MS,
): boolean {
  return now.getTime() - session.lastCheckedAt.getTime() >= intervalMs;
}

/** When the "Stay signed in" prompt is due (§8.1): 5 minutes before the end. */
export function expiryWarningAt(session: SessionRecord): Date {
  const limit = inactivityLimitMinutes(session);
  const warnAfter = limit === HIGHER_RISK_INACTIVITY_MINUTES ? 10 : 55;
  return new Date(session.lastActivityAt.getTime() + warnAfter * 60_000);
}
