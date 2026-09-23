/**
 * Activity, and the five-minute session check.
 *
 * Standard v0.9 §8.2 and §3.5.
 *
 * Two mechanisms that only matter when they are wrong in the quiet direction:
 * an inactivity timer nothing ever resets is obvious, while one that everything
 * resets looks exactly like a working system.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BACKGROUND_HEADER,
  InMemorySessionStore,
  SESSION_CHECK_INTERVAL_MS,
  checkIsDue,
  checkSession,
  countsAsActivity,
  createSessionManager,
  isBackgroundRequest,
  resolveConfig,
  type SessionCheckResult,
  type SessionManager,
  type SignedInUser,
} from '../src/index.js';

function signedIn(overrides: Partial<SignedInUser> = {}): SignedInUser {
  return {
    subject: 'account-1',
    email: 'ada.lovelace@rosor.ca',
    authTime: new Date(),
    methods: ['pwd', 'otp'],
    sessionId: 'identity-session-reference',
    claims: {},
    ...overrides,
  };
}

describe('what counts as activity (§8.2)', () => {
  it('treats an ordinary request as activity', () => {
    expect(countsAsActivity({})).toBe(true);
    expect(countsAsActivity({ 'user-agent': 'Firefox' })).toBe(true);
  });

  it('treats a declared background request as not activity', () => {
    expect(countsAsActivity({ [BACKGROUND_HEADER]: '1' })).toBe(false);
    expect(isBackgroundRequest({ [BACKGROUND_HEADER]: '1' })).toBe(true);
  });

  /**
   * Only "1". A control whose spelling can be got subtly wrong fails in
   * whichever direction the typo points, and here the safe direction is to
   * treat an unclear marker as ordinary traffic — a session that stops timing
   * out is visible, where one that logs people out mid-task gets worked around.
   */
  it('accepts only the exact string "1" as a declaration', () => {
    for (const value of ['true', 'yes', '0', '', 'TRUE', '1 ']) {
      expect(isBackgroundRequest({ [BACKGROUND_HEADER]: value })).toBe(false);
    }
  });

  it('reads the header whatever case it arrives in', () => {
    expect(isBackgroundRequest({ 'X-Rosor-Background': '1' })).toBe(true);
  });

  it('takes the first value when a header arrives more than once', () => {
    expect(isBackgroundRequest({ [BACKGROUND_HEADER]: ['1', '0'] })).toBe(true);
  });
});

describe('when the check is due (§3.5)', () => {
  const at = (msAgo: number) => ({ lastCheckedAt: new Date(Date.now() - msAgo) });

  it('is not due before five minutes', () => {
    expect(checkIsDue(at(4 * 60_000))).toBe(false);
  });

  it('is due at five minutes, which §3.5 makes the ceiling', () => {
    expect(checkIsDue(at(SESSION_CHECK_INTERVAL_MS))).toBe(true);
    expect(checkIsDue(at(SESSION_CHECK_INTERVAL_MS + 1))).toBe(true);
  });

  it('honours a shorter interval when one is asked for', () => {
    expect(checkIsDue(at(90_000), new Date(), 60_000)).toBe(true);
  });
});

describe('the session check over the back channel (§3.5)', () => {
  const config = () =>
    resolveConfig({
      issuer: 'https://auth.rosor.test/api/v1/auth-module/oidc',
      internalIssuer: 'http://provider:3001/api/v1/auth-module/oidc',
      sessionCheckUrl: 'http://provider:3001/api/v1/auth-module/internal/session-check',
      clientId: 'inventory',
      clientSecret: 'a-secret-with-a:colon-in-it',
      redirectUri: 'https://inventory.rosor.test/auth/callback',
    });

  function stub(body: unknown, status = 200) {
    return vi.fn(
      async () =>
        new Response(JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
    ) as unknown as typeof fetch;
  }

  it('reports an active session, with the authentication time to inherit', async () => {
    const authTime = new Date(Date.now() - 3600_000);
    const fetchImpl = stub({
      status: 'active',
      subject: 'account-1',
      email: 'ada.lovelace@rosor.ca',
      authTime: authTime.toISOString(),
      amr: 'PASSWORD_AND_APP',
      aal: 'AAL2',
    });

    const result = await checkSession(config(), { reference: 'ref', active: true }, fetchImpl);

    expect(result.status).toBe('active');
    expect(result.subject).toBe('account-1');
    expect(result.authTime?.getTime()).toBe(authTime.getTime());
  });

  it('sends the reference and the activity flag the provider expects', async () => {
    const fetchImpl = stub({ status: 'active', subject: 'a' });
    await checkSession(config(), { reference: 'the-reference', active: false }, fetchImpl);

    const [, init] = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(JSON.parse(init.body as string)).toEqual({
      session: 'the-reference',
      active: false,
    });
  });

  /**
   * The provider's own client authentication splits the decoded string on the
   * first colon and compares raw bytes — it does NOT form-decode, as the token
   * endpoint does. Encoding here would make a secret containing a reserved
   * character fail in a way that reads as a wrong secret.
   */
  it('sends raw Basic credentials, not form-encoded ones', async () => {
    const fetchImpl = stub({ status: 'active', subject: 'a' });
    await checkSession(config(), { reference: 'ref', active: true }, fetchImpl);

    const [, init] = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
    const header = (init.headers as Record<string, string>).Authorization!;
    const decoded = Buffer.from(header.replace('Basic ', ''), 'base64').toString('utf8');

    expect(decoded).toBe('inventory:a-secret-with-a:colon-in-it');
  });

  it('reports a revoked session as revoked, not merely expired', async () => {
    const result = await checkSession(
      config(),
      { reference: 'ref', active: true },
      stub({ status: 'revoked' }),
    );
    expect(result.status).toBe('revoked');
  });

  /** An unrecognised status from a future provider ends the session. */
  it('treats anything that is not explicitly active as over', async () => {
    for (const body of [{ status: 'something-new' }, {}, { status: 'expired' }]) {
      const result = await checkSession(
        config(),
        { reference: 'ref', active: true },
        stub(body),
      );
      expect(result.status).not.toBe('active');
    }
  });

  /** A deployment fault, and it must not read as "everyone signed out". */
  it('distinguishes a refused client secret from an ended session', async () => {
    await expect(
      checkSession(config(), { reference: 'ref', active: true }, stub({ error: 'Unauthorized' }, 401)),
    ).rejects.toMatchObject({ code: 'invalid_client' });
  });

  /**
   * §4: a failure of an external service SHALL NOT weaken a check. Thrown
   * rather than answered, because both safe readings belong to the caller —
   * "still active" extends every session through an outage, "revoked" signs
   * everybody out on a network hiccup.
   */
  it('throws rather than guessing when the provider is unreachable', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;

    await expect(
      checkSession(config(), { reference: 'ref', active: true }, fetchImpl),
    ).rejects.toThrow(/Could not reach the session check/);
  });

  it('names the missing configuration rather than failing obscurely', async () => {
    const withoutUrl = resolveConfig({
      issuer: 'https://auth.rosor.test/api/v1/auth-module/oidc',
      clientId: 'inventory',
      clientSecret: 'secret',
      redirectUri: 'https://inventory.rosor.test/auth/callback',
    });

    await expect(
      checkSession(withoutUrl, { reference: 'ref', active: true }),
    ).rejects.toMatchObject({ code: 'no_session_check_url' });
  });
});

describe('applying the check to a session', () => {
  let store: InMemorySessionStore;
  let sessions: SessionManager;
  let answer: SessionCheckResult;
  let calls: { reference: string; active: boolean }[];

  beforeEach(() => {
    store = new InMemorySessionStore();
    answer = { status: 'active' };
    calls = [];
    sessions = createSessionManager({
      store,
      appName: 'inventory',
      sessionCheck: {
        async check(input) {
          calls.push(input);
          return answer;
        },
      },
    });
  });

  it('does not call the provider before the check is due', async () => {
    const { session } = await sessions.start(signedIn());

    const outcome = await sessions.verify(session, { active: true });

    expect(outcome).toMatchObject({ status: 'active', checked: false });
    expect(calls).toHaveLength(0);
  });

  it('calls it once five minutes have passed', async () => {
    const { session } = await sessions.start(signedIn());
    const later = new Date(Date.now() + SESSION_CHECK_INTERVAL_MS + 1000);

    const outcome = await sessions.verify(session, { active: true, now: later });

    expect(outcome).toMatchObject({ status: 'active', checked: true });
    expect(calls).toEqual([{ reference: 'identity-session-reference', active: true }]);
  });

  /** §3.5 requires a check before a sensitive action, whatever the timer says. */
  it('calls it immediately when forced', async () => {
    const { session } = await sessions.start(signedIn());

    await sessions.verify(session, { active: false, force: true });

    expect(calls).toHaveLength(1);
  });

  it('passes the activity flag through as given', async () => {
    const { session } = await sessions.start(signedIn());
    await sessions.verify(session, { active: false, force: true });

    expect(calls[0]!.active).toBe(false);
  });

  /** The whole point of the mechanism. */
  it('deletes the local session when the provider says revoked', async () => {
    const { session } = await sessions.start(signedIn());
    answer = { status: 'revoked' };

    const outcome = await sessions.verify(session, { active: true, force: true });

    expect(outcome.status).toBe('revoked');
    expect(store.size).toBe(0);
  });

  it('deletes it when the provider says expired', async () => {
    const { session } = await sessions.start(signedIn());
    answer = { status: 'expired' };

    expect(await sessions.verify(session, { active: true, force: true })).toMatchObject({
      status: 'expired',
    });
    expect(store.size).toBe(0);
  });

  it('records the check, so the next one is not due immediately', async () => {
    const { session } = await sessions.start(signedIn());
    const later = new Date(Date.now() + SESSION_CHECK_INTERVAL_MS + 1000);

    await sessions.verify(session, { active: true, now: later });

    const stored = await store.find(session.idHash);
    expect(stored!.lastCheckedAt.getTime()).toBe(later.getTime());
  });

  /**
   * REFUSED rather than resolved either way.
   *
   * "Cannot confirm it, so end it" would sign out every user of a correctly
   * working application the moment checks were switched on. "Cannot confirm
   * it, so allow it" silently disables §3.5. Neither is safe to choose
   * quietly.
   */
  it('refuses to guess when a session carries no provider reference', async () => {
    const { session } = await sessions.start(signedIn({ sessionId: undefined }));

    await expect(
      sessions.verify(session, { active: true, force: true }),
    ).rejects.toMatchObject({ code: 'no_session_reference' });

    expect(store.size).toBe(1);
  });

  it('refuses when no check was configured at all', async () => {
    const unchecked = createSessionManager({ store: new InMemorySessionStore(), appName: 'x' });
    const { session } = await unchecked.start(signedIn());

    await expect(
      unchecked.verify(session, { active: true, force: true }),
    ).rejects.toMatchObject({ code: 'session_check_not_configured' });
  });
});
