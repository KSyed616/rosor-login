/**
 * Starting, reading and ending an application session.
 *
 * The piece an application actually calls. It ties the store (§8.3), the
 * cookie (§8.3) and the timeout rules (§8.1) together so none of them can be
 * used without the others — a session created without its cookie attributes,
 * or read without its timeout check, is the failure this exists to prevent.
 */

import { clearedSessionCookie, cookieName, readCookie, sessionCookie, type CookieOptions } from './cookie.js';
import type { SignedInUser } from './callback.js';
import {
  checkIsDue,
  createCsrfToken,
  createSessionIdentifier,
  expiryOf,
  hashSessionIdentifier,
  SESSION_CHECK_INTERVAL_MS,
  type SessionLookup,
  type SessionRecord,
  type SessionStore,
} from './session.js';
import { RosorLoginError } from './callback.js';
import type { SessionCheckInput, SessionCheckResult } from './sessionCheck.js';

export interface SessionManagerOptions {
  store: SessionStore;
  /** Becomes `__Host-<appName>_sid`. */
  appName: string;
  /** Development only — see CookieOptions. */
  secure?: boolean;

  /**
   * §3.5's check. Optional, and its absence is a real gap rather than a
   * configuration taste: without it a revocation at the provider never reaches
   * this application, and sessions end only on their own timers.
   */
  sessionCheck?: {
    check(input: SessionCheckInput): Promise<SessionCheckResult>;
    /** Defaults to five minutes, which §3.5 makes the ceiling. */
    intervalMs?: number;
  };
}

/**
 * The outcome of §3.5's check.
 *
 * `checked` says whether the provider was actually asked. A caller that wants
 * certainty before a sensitive action passes `force` and can then rely on it.
 */
export type VerifyOutcome =
  | { status: 'active'; session: SessionRecord; checked: boolean }
  | { status: 'expired' | 'revoked'; session: SessionRecord };

export interface StartedSession {
  /** Put this in `Set-Cookie`. */
  cookie: string;
  /**
   * Hand this to the page. It is not secret from the page — it exists so the
   * page can prove it IS the page (§8.4) — but it must never go somewhere a
   * cross-site document could read it.
   */
  csrfToken: string;
  session: SessionRecord;
}

export interface SessionManager {
  /**
   * §8.3: "Generated in direct response to an authentication event", and "a
   * new identifier is issued on every authentication and re-authentication".
   * Taking a verified user and nothing else is what makes that true by
   * construction — there is no way to mint a session from anything but a
   * completed sign-in.
   */
  start(user: SignedInUser, options?: { higherRisk?: boolean }): Promise<StartedSession>;

  /**
   * Replace a session after a step-up, when the person has signed in again
   * (§8.3, §8.1).
   *
   * §8.3: "a new identifier is issued on every authentication AND
   * re-authentication". §8.1: "successful re-authentication resets both
   * timers". So this is NOT a field update on the existing record — the
   * identifier rotates, the old record is deleted, and a new cookie is issued.
   *
   * WHY ROTATION MATTERS, given it is the same person who already had a
   * session. Whatever prompted the step-up was a sensitive action, and the
   * identifier that existed before it is the one that may have leaked — a
   * shared machine, a proxy log, a copied URL. Carrying it forward would leave
   * the credential guarding the sensitive path the one already in circulation.
   * Rotation is cheap and makes the question moot.
   *
   * THE CSRF TOKEN ROTATES WITH IT, necessarily: §8.4 binds it to the session,
   * so a page still holding the old one fails every write afterwards. The
   * obvious "fix" for that — carrying the old token forward — is session
   * fixation. The caller hands the new one to the page, exactly as after
   * `start`.
   *
   * WHAT CARRIES FORWARD is deliberately almost nothing: `higherRisk`, which
   * classifies the account rather than the session. `authTime` comes from the
   * new token, which is the whole point — an old one would leave the session
   * failing the freshness check it just passed.
   *
   * THE OLD SESSION SURVIVES A FAILED STEP-UP. This is only reachable with a
   * verified SignedInUser, so a provider error, a cancelled passkey or a token
   * that came back too old never arrives here and the existing session is
   * untouched. A failed attempt to prove yourself must not sign you out.
   */
  reauthenticate(
    previous: Pick<SessionRecord, 'idHash' | 'higherRisk'>,
    user: SignedInUser,
  ): Promise<StartedSession>;

  /**
   * Resolve the cookie to a live session, applying both timeouts.
   *
   * An expired session is DELETED as it is read. Leaving it would mean a
   * record that is dead to this check and alive to any other, and the table
   * would fill with sessions nobody can use but everybody has to reason about.
   */
  read(cookieHeader: string | undefined | null, now?: Date): Promise<SessionLookup>;

  /** Record activity. Separate from `read` — see the note on §8.2 below. */
  touch(session: SessionRecord, now?: Date): Promise<void>;

  /**
   * Confirm a session with the provider (§3.5), if it is due or forced.
   *
   * A session the provider no longer recognises is DELETED here — that is the
   * whole point of the mechanism, and leaving it would mean an application
   * that asked whether a session was revoked, was told yes, and carried on.
   *
   * `active` is the caller's to supply, from §8.2's definition: whether the
   * traffic since the last check was a person. Pass `force` before a sensitive
   * action, which §3.5 requires regardless of the timer.
   */
  verify(
    session: SessionRecord,
    options: { active: boolean; force?: boolean; now?: Date },
  ): Promise<VerifyOutcome>;

  /** Sign out: removes the record and returns the cookie that clears it. */
  end(cookieHeader: string | undefined | null): Promise<{ cookie: string }>;

  /** The name the cookie is stored under, for an application that needs it. */
  cookieName(): string;
}

export function createSessionManager(options: SessionManagerOptions): SessionManager {
  const cookieOptions: CookieOptions = { appName: options.appName, secure: options.secure };
  const name = cookieName(cookieOptions);
  const { store } = options;

  return {
    cookieName: () => name,

    async start(user, startOptions = {}): Promise<StartedSession> {
      const identifier = createSessionIdentifier();
      const now = new Date();

      const record: SessionRecord = {
        idHash: hashSessionIdentifier(identifier),
        subject: user.subject,
        email: user.email,
        name: user.name,
        // §3.5: inherited, never "now". This is what keeps the twelve-hour
        // limit a property of the sign-in rather than of each application.
        authTime: user.authTime,
        methods: user.methods,
        identitySessionId: user.sessionId,
        createdAt: now,
        lastActivityAt: now,
        // A session the provider just minted has, in effect, been confirmed
        // by it a moment ago. Starting this at the epoch would make the first
        // request of every session pay for a round trip it does not need.
        lastCheckedAt: now,
        csrfToken: createCsrfToken(),
        higherRisk: startOptions.higherRisk ?? false,
      };

      await store.create(record);

      return {
        cookie: sessionCookie(identifier, cookieOptions),
        csrfToken: record.csrfToken,
        session: record,
      };
    },

    async reauthenticate(previous, user): Promise<StartedSession> {
      // Mint FIRST, delete second. If the store fails between the two, the
      // person is left with two working sessions rather than none — untidy,
      // and both expire on their own. The other order leaves someone who just
      // proved who they are with nothing.
      const started = await this.start(user, { higherRisk: previous.higherRisk });
      await store.delete(previous.idHash);
      return started;
    },

    async read(cookieHeader, now = new Date()): Promise<SessionLookup> {
      const identifier = readCookie(cookieHeader, name);
      if (!identifier) return { status: 'none' };

      const session = await store.find(hashSessionIdentifier(identifier));
      if (!session) return { status: 'none' };

      const expired = expiryOf(session, now);
      if (expired) {
        await store.delete(session.idHash);
        return { status: 'expired', reason: expired, session };
      }

      return { status: 'active', session };
    },

    /**
     * §8.2 draws a line this method deliberately leaves to the caller:
     *
     *   "Activity means authenticated requests caused by a USER ACTION [...]
     *    Not activity: background polling, auto-refresh, Socket.io
     *    keep-alives, and prefetching."
     *
     * So reading a session must NOT extend it. If `read` touched, a page left
     * open with a poll on a timer would never time out, and §8.1's inactivity
     * limit would be enforced against nobody. The caller decides — normally by
     * checking for `X-Rosor-Background: 1`, which part 4 turns into middleware.
     */
    async touch(session, now = new Date()): Promise<void> {
      await store.touch(session.idHash, now);
    },

    async verify(session, verifyOptions): Promise<VerifyOutcome> {
      const check = options.sessionCheck;
      if (!check) {
        throw new RosorLoginError(
          'session_check_not_configured',
          'verify() was called but no sessionCheck was given to createSessionManager, ' +
            'so §3.5 cannot be performed and a revocation cannot reach this application.',
        );
      }

      const now = verifyOptions.now ?? new Date();
      const interval = check.intervalMs ?? SESSION_CHECK_INTERVAL_MS;

      if (!verifyOptions.force && !checkIsDue(session, now, interval)) {
        return { status: 'active', session, checked: false };
      }

      if (!session.identitySessionId) {
        /**
         * REFUSED, not treated as expired.
         *
         * A session with no provider reference cannot be checked, and the
         * tempting reading — "cannot confirm it, so end it" — would sign out
         * every user of a correctly working application the moment checks were
         * switched on. The other reading, treating it as active, silently
         * disables §3.5. Neither is safe to choose quietly, so it is an error
         * that names the cause.
         */
        throw new RosorLoginError(
          'no_session_reference',
          'This session carries no identity session reference, so §3.5 cannot confirm it. ' +
            'The reference comes from the provider at the code exchange; if every session ' +
            'is missing one, the provider is not issuing it.',
        );
      }

      const result = await check.check({
        reference: session.identitySessionId,
        active: verifyOptions.active,
      });

      if (result.status !== 'active') {
        await store.delete(session.idHash);
        return { status: result.status, session };
      }

      await store.recordCheck(session.idHash, now);
      return { status: 'active', session: { ...session, lastCheckedAt: now }, checked: true };
    },

    async end(cookieHeader): Promise<{ cookie: string }> {
      const identifier = readCookie(cookieHeader, name);
      if (identifier) {
        // Not conditional on the record existing: deleting an absent session
        // is a no-op, and the cookie must be cleared either way.
        await store.delete(hashSessionIdentifier(identifier));
      }
      return { cookie: clearedSessionCookie(cookieOptions) };
    },
  };
}
