/**
 * How recently did this person actually sign in? — §8.1, §6.2.
 *
 * Some actions are not protected by having a session at all. §8.1 requires a
 * sign-in within the last 15 minutes for "Rosor Admin payroll approvals,
 * administrator actions, and changes to security settings", and §6.2 requires
 * one within 5 minutes before a sign-in method is added, replaced or removed.
 *
 * IT READS authTime, NEVER lastActivityAt, and that is the whole of it.
 *
 * The two are both on the record and both look like recency. Reading the wrong
 * one leaves a check that passes for exactly the sessions it exists to catch:
 * somebody who signed in at nine and has been clicking around ever since has
 * lastActivityAt of a moment ago and authTime of hours back. The threat this
 * addresses is a session left open on an unattended machine, which by
 * definition has recent activity.
 *
 * `authTime` is also inherited from the identity session (§3.5), not set when
 * the application session began — so it is the time the person proved who they
 * were to TeamDeck, which is the thing §8.1 is asking about.
 *
 * THIS IS A PREDICATE, NOT A GUARD. It answers a question; it does not stop
 * anything. Making it fresh again means sending the browser back through the
 * provider with `prompt: 'login'` and a `maxAge` — see `stepUp` below and
 * `SessionManager.reauthenticate`.
 */

import type { SessionRecord } from './session.js';

/** §8.1: "a sign-in within the last 15 minutes" for sensitive actions. */
export const SENSITIVE_ACTION_SECONDS = 15 * 60;

/** §6.2: "Changes require a sign-in within the last 5 minutes". */
export const METHOD_CHANGE_SECONDS = 5 * 60;

/**
 * Whether the sign-in behind this session is recent enough.
 *
 * @param maxAgeSeconds how old the sign-in may be. Use the constants above
 * rather than a literal, so a rule change is one edit rather than a search.
 */
export function isFreshEnough(
  session: Pick<SessionRecord, 'authTime'>,
  maxAgeSeconds: number,
  now: Date = new Date(),
): boolean {
  return ageOfAuthentication(session, now) <= maxAgeSeconds;
}

/** How long ago the person authenticated, in seconds. Never negative. */
export function ageOfAuthentication(
  session: Pick<SessionRecord, 'authTime'>,
  now: Date = new Date(),
): number {
  return Math.max(0, Math.floor((now.getTime() - session.authTime.getTime()) / 1000));
}

/**
 * What a route should do about it.
 *
 * Returned rather than thrown because "not fresh" is not an error — it is a
 * normal step in a flow that ends with the person doing the thing they asked
 * to do. An exception here would push callers towards a catch block that
 * returns 403, which is the wrong answer: the user is who they say they are,
 * they simply proved it too long ago.
 */
export type FreshnessVerdict =
  | { fresh: true }
  | { fresh: false; ageSeconds: number; requiredWithinSeconds: number };

export function checkFreshness(
  session: Pick<SessionRecord, 'authTime'>,
  maxAgeSeconds: number,
  now: Date = new Date(),
): FreshnessVerdict {
  const ageSeconds = ageOfAuthentication(session, now);
  if (ageSeconds <= maxAgeSeconds) return { fresh: true };
  return { fresh: false, ageSeconds, requiredWithinSeconds: maxAgeSeconds };
}

/**
 * The options to hand `beginAuthorization` when a session is not fresh enough.
 *
 * A convenience with one purpose: making it hard to ask for a step-up and
 * forget to check the answer. `prompt: 'login'` without `maxAge` produces a
 * fresh sign-in that the callback has no way to verify was fresh — §3.4 says
 * "The application SHALL reject a token whose auth_time is earlier than its
 * request", and it cannot do that if nothing was requested. Both are set here
 * together, and `completeAuthorization` requires the `maxAge` back.
 */
export function stepUp(maxAgeSeconds: number): { prompt: 'login'; maxAge: number } {
  return { prompt: 'login', maxAge: maxAgeSeconds };
}
