/**
 * Freshness and re-authentication — §8.1, §8.3, §6.2.
 *
 * Two rules that look like one and are not. Freshness asks how long ago the
 * person PROVED who they are; the inactivity timeout asks how long ago they
 * last DID something. A session can pass one and fail the other, and the whole
 * value of §8.1's sensitive-action rule is that it catches the case where it
 * does.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  METHOD_CHANGE_SECONDS,
  SENSITIVE_ACTION_SECONDS,
  ageOfAuthentication,
  checkFreshness,
  createSessionManager,
  isFreshEnough,
  stepUp,
  InMemorySessionStore,
  hashSessionIdentifier,
  type SessionManager,
  type SessionRecord,
} from '../src/index.js';
import type { SignedInUser } from '../src/callback.js';

const NOW = new Date('2026-09-23T12:00:00Z');
const minutesBefore = (n: number) => new Date(NOW.getTime() - n * 60_000);

function user(over: Partial<SignedInUser> = {}): SignedInUser {
  return {
    subject: 'account-1',
    email: 'ada.lovelace@rosor.ca',
    authTime: NOW,
    methods: ['swk'],
    sessionId: 'identity-session-1',
    claims: {},
    ...over,
  };
}

describe('how old the sign-in is (§8.1)', () => {
  const at = (authTime: Date) => ({ authTime }) as Pick<SessionRecord, 'authTime'>;

  it('measures from the authentication, in seconds', () => {
    expect(ageOfAuthentication(at(minutesBefore(10)), NOW)).toBe(600);
  });

  it('never reports a negative age, if clocks disagree', () => {
    expect(ageOfAuthentication(at(new Date(NOW.getTime() + 30_000)), NOW)).toBe(0);
  });

  it('accepts a sign-in inside the 15-minute window and refuses one outside', () => {
    expect(isFreshEnough(at(minutesBefore(14)), SENSITIVE_ACTION_SECONDS, NOW)).toBe(true);
    expect(isFreshEnough(at(minutesBefore(16)), SENSITIVE_ACTION_SECONDS, NOW)).toBe(false);
  });

  it('is inclusive at the boundary', () => {
    expect(isFreshEnough(at(minutesBefore(15)), SENSITIVE_ACTION_SECONDS, NOW)).toBe(true);
  });

  it('enforces §6.2’s five minutes independently of §8.1’s fifteen', () => {
    const tenMinutesAgo = at(minutesBefore(10));
    // Fresh enough to approve payroll, NOT fresh enough to change a passkey.
    expect(isFreshEnough(tenMinutesAgo, SENSITIVE_ACTION_SECONDS, NOW)).toBe(true);
    expect(isFreshEnough(tenMinutesAgo, METHOD_CHANGE_SECONDS, NOW)).toBe(false);
  });

  it('reports the age and the requirement when it refuses', () => {
    expect(checkFreshness(at(minutesBefore(40)), SENSITIVE_ACTION_SECONDS, NOW)).toEqual({
      fresh: false,
      ageSeconds: 2400,
      requiredWithinSeconds: 900,
    });
    expect(checkFreshness(at(minutesBefore(1)), SENSITIVE_ACTION_SECONDS, NOW)).toEqual({
      fresh: true,
    });
  });

  /**
   * THE ONE THAT MATTERS. A session busy all morning has recent activity and an
   * old sign-in. Reading lastActivityAt here would make the check pass for
   * exactly the session it exists to catch — a machine left unattended, which
   * by definition has recent activity.
   */
  it('is not satisfied by activity', () => {
    const busyAllMorning = {
      authTime: minutesBefore(180),
      lastActivityAt: minutesBefore(1),
    } as Pick<SessionRecord, 'authTime'>;

    expect(isFreshEnough(busyAllMorning, SENSITIVE_ACTION_SECONDS, NOW)).toBe(false);
  });

  it('asks for a fresh sign-in AND a maxAge, so the answer can be checked', () => {
    // §3.4: "The application SHALL reject a token whose auth_time is earlier
    // than its request" — impossible if nothing was requested.
    expect(stepUp(SENSITIVE_ACTION_SECONDS)).toEqual({ prompt: 'login', maxAge: 900 });
  });
});

describe('re-authentication (§8.3, §8.1)', () => {
  let store: InMemorySessionStore;
  let sessions: SessionManager;

  beforeEach(() => {
    store = new InMemorySessionStore();
    sessions = createSessionManager({ appName: 'inventory', secure: true, store });
  });

  async function signedIn(over: Partial<SignedInUser> = {}, higherRisk = false) {
    return sessions.start(user(over), { higherRisk });
  }

  it('issues a NEW identifier, not a field update', async () => {
    const first = await signedIn({ authTime: minutesBefore(40) });
    const second = await sessions.reauthenticate(first.session, user());

    expect(second.session.idHash).not.toBe(first.session.idHash);
    expect(second.cookie).not.toBe(first.cookie);
  });

  it('rotates the CSRF token with it (§8.4)', async () => {
    const first = await signedIn({ authTime: minutesBefore(40) });
    const second = await sessions.reauthenticate(first.session, user());

    // A page holding the old token must fail, or the binding means nothing.
    expect(second.csrfToken).not.toBe(first.csrfToken);
    expect(second.session.csrfToken).toBe(second.csrfToken);
  });

  it('deletes the old record, so the old cookie resolves to nothing', async () => {
    const first = await signedIn({ authTime: minutesBefore(40) });
    await sessions.reauthenticate(first.session, user());

    expect(await store.find(first.session.idHash)).toBeNull();
    expect(await sessions.read(first.cookie)).toEqual({ status: 'none' });
  });

  it('takes authTime from the new token, which is the point', async () => {
    const stale = await signedIn({ authTime: minutesBefore(40) });
    expect(isFreshEnough(stale.session, SENSITIVE_ACTION_SECONDS, NOW)).toBe(false);

    const fresh = await sessions.reauthenticate(stale.session, user({ authTime: NOW }));
    expect(fresh.session.authTime).toEqual(NOW);
    expect(isFreshEnough(fresh.session, SENSITIVE_ACTION_SECONDS, NOW)).toBe(true);
  });

  it('resets both timers, not just the inactivity one (§8.1)', async () => {
    const stale = await signedIn({ authTime: minutesBefore(700) });
    const fresh = await sessions.reauthenticate(stale.session, user({ authTime: NOW }));

    // The absolute limit is measured from authTime, so it moves too — a
    // re-authenticated session is not still counting down from this morning.
    expect(fresh.session.authTime.getTime()).toBeGreaterThan(stale.session.authTime.getTime());
    expect(fresh.session.lastActivityAt.getTime()).toBeGreaterThanOrEqual(
      stale.session.lastActivityAt.getTime(),
    );
  });

  it('carries higherRisk forward, since it classifies the account', async () => {
    const first = await signedIn({ authTime: minutesBefore(40) }, true);
    const second = await sessions.reauthenticate(first.session, user());

    // §8.1's 15-minute inactivity limit must still apply afterwards.
    expect(second.session.higherRisk).toBe(true);
  });

  it('leaves the old session intact when the step-up never completes', async () => {
    const existing = await signedIn({ authTime: minutesBefore(40) });

    // A cancelled passkey or a token that came back too old never produces a
    // SignedInUser, so reauthenticate is never called. A failed attempt to
    // prove yourself must not sign you out.
    const still = await sessions.read(existing.cookie, NOW);
    expect(still.status).toBe('active');
    expect(await store.find(existing.session.idHash)).not.toBeNull();
  });

  it('the new session is usable immediately, by its own cookie', async () => {
    const first = await signedIn({ authTime: minutesBefore(40) });
    const second = await sessions.reauthenticate(first.session, user());

    const found = await sessions.read(second.cookie, NOW);
    expect(found.status).toBe('active');
    if (found.status === 'active') {
      expect(found.session.idHash).toBe(second.session.idHash);
      expect(found.session.idHash).toBe(
        hashSessionIdentifier(
          /* the identifier inside the cookie */ second.cookie.split('=')[1].split(';')[0],
        ),
      );
    }
  });
});
