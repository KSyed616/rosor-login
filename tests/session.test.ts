/**
 * The application session, its cookie, and the CSRF and Origin checks.
 *
 * Standard v0.9 §8.1, §8.3, §8.4.
 *
 * Most of these assert a property rather than a behaviour — that the
 * identifier is never stored, that the cookie has no expiry, that reading a
 * session does not extend it. Properties are what quietly stop being true.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  ABSOLUTE_LIFETIME_HOURS,
  CSRF_HEADER,
  DEFAULT_INACTIVITY_MINUTES,
  HIGHER_RISK_INACTIVITY_MINUTES,
  InMemorySessionStore,
  clearedSessionCookie,
  cookieName,
  createSessionManager,
  expiryOf,
  expiryWarningAt,
  readCookie,
  verifyCsrf,
  verifyOrigin,
  type SessionManager,
  type SignedInUser,
} from '../src/index.js';

const ORIGIN = 'https://app.example.com';

function signedIn(overrides: Partial<SignedInUser> = {}): SignedInUser {
  return {
    subject: 'account-1',
    email: 'ada.lovelace@rosor.ca',
    name: 'Ada Lovelace',
    authTime: new Date(),
    methods: ['pwd', 'otp'],
    sessionId: 'identity-session-1',
    claims: {},
    ...overrides,
  };
}

/** The cookie a browser would send back, from a Set-Cookie we issued. */
function asRequestCookie(setCookie: string): string {
  return setCookie.split(';')[0]!;
}

let store: InMemorySessionStore;
let sessions: SessionManager;

beforeEach(() => {
  store = new InMemorySessionStore();
  sessions = createSessionManager({ store, appName: 'inventory' });
});

describe('starting a session (§8.3)', () => {
  it('issues a cookie the session can then be read from', async () => {
    const started = await sessions.start(signedIn());

    const lookup = await sessions.read(asRequestCookie(started.cookie));
    expect(lookup.status).toBe('active');
  });

  /**
   * The one that matters most. Anyone reading the session table must not be
   * able to impersonate anybody — a stolen backup is not a bag of live
   * sessions.
   */
  it('stores only a hash of the identifier, never the identifier', async () => {
    const started = await sessions.start(signedIn());
    const identifier = asRequestCookie(started.cookie).split('=')[1]!;

    const stored = await store.find(started.session.idHash);

    expect(stored).not.toBeNull();
    expect(JSON.stringify(stored)).not.toContain(identifier);
    expect(started.session.idHash).toBe(createHash('sha256').update(identifier).digest('base64url'));
  });

  it('issues a different identifier every time (§8.3)', async () => {
    const a = await sessions.start(signedIn());
    const b = await sessions.start(signedIn());

    expect(a.cookie).not.toBe(b.cookie);
    expect(a.session.idHash).not.toBe(b.session.idHash);
    expect(a.csrfToken).not.toBe(b.csrfToken);
  });

  /** §3.5: inherited, so no application session outlives the overall limit. */
  it('inherits the identity session’s authentication time, not "now"', async () => {
    const authTime = new Date(Date.now() - 3 * 3600_000);
    const started = await sessions.start(signedIn({ authTime }));

    expect(started.session.authTime.getTime()).toBe(authTime.getTime());
    expect(started.session.createdAt.getTime()).toBeGreaterThan(authTime.getTime());
  });

  it('carries the identity session forward, so a revocation can find it', async () => {
    const started = await sessions.start(signedIn());
    expect(started.session.identitySessionId).toBe('identity-session-1');
  });

  it('holds nothing personal in the cookie value itself (§8.3)', async () => {
    const started = await sessions.start(signedIn());
    const value = asRequestCookie(started.cookie).split('=')[1]!;

    expect(value).not.toContain('ada');
    expect(value).not.toContain('account-1');
    // Opaque: not a JWT.
    expect(value.split('.').length).toBe(1);
  });
});

describe('the cookie’s attributes (§8.3)', () => {
  it('sets every attribute the standard’s table requires', async () => {
    const { cookie } = await sessions.start(signedIn());

    expect(cookie).toContain('__Host-inventory_sid=');
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Secure');
  });

  /**
   * The attribute most likely to be "fixed" by someone adding a Max-Age.
   * §8.3 wants a browser-session cookie, and §8.2 forbids cookie expiry from
   * being what enforces a timeout.
   */
  it('sets NO expiry, so the cookie dies with the browser', async () => {
    const { cookie } = await sessions.start(signedIn());

    expect(cookie).not.toContain('Max-Age');
    expect(cookie).not.toContain('Expires');
  });

  it('omits Domain, so the cookie is host-only', async () => {
    const { cookie } = await sessions.start(signedIn());
    expect(cookie).not.toContain('Domain');
  });

  /** `__Host-` requires Secure; without it the browser silently drops it. */
  it('drops the __Host- prefix when it cannot set Secure, rather than lying', () => {
    expect(cookieName({ appName: 'inventory' })).toBe('__Host-inventory_sid');
    expect(cookieName({ appName: 'inventory', secure: false })).toBe('inventory_sid');
  });

  it('clears with both an empty value and a past expiry', () => {
    const cleared = clearedSessionCookie({ appName: 'inventory' });

    expect(cleared).toContain('__Host-inventory_sid=;');
    expect(cleared).toContain('Max-Age=0');
    expect(cleared).toContain('Expires=Thu, 01 Jan 1970');
  });

  it('reads the first cookie of a name, not the last', () => {
    const header = '__Host-inventory_sid=first; other=x; __Host-inventory_sid=second';
    expect(readCookie(header, '__Host-inventory_sid')).toBe('first');
  });

  it('treats an empty cookie value as absent', () => {
    expect(readCookie('__Host-inventory_sid=', '__Host-inventory_sid')).toBeNull();
    expect(readCookie(undefined, '__Host-inventory_sid')).toBeNull();
  });
});

describe('timeouts (§8.1)', () => {
  it('expires after 60 minutes of inactivity', async () => {
    const started = await sessions.start(signedIn());
    const later = new Date(Date.now() + (DEFAULT_INACTIVITY_MINUTES + 1) * 60_000);

    const lookup = await sessions.read(asRequestCookie(started.cookie), later);

    expect(lookup).toMatchObject({ status: 'expired', reason: 'inactivity' });
  });

  it('expires a higher-risk session after 15', async () => {
    const started = await sessions.start(signedIn(), { higherRisk: true });
    const later = new Date(Date.now() + (HIGHER_RISK_INACTIVITY_MINUTES + 1) * 60_000);

    expect(await sessions.read(asRequestCookie(started.cookie), later)).toMatchObject({
      status: 'expired',
      reason: 'inactivity',
    });
  });

  /**
   * Twelve hours from AUTHENTICATION, so continuous activity cannot extend a
   * session indefinitely — which is the whole point of an absolute limit.
   */
  it('expires 12 hours after authentication however active the user has been', async () => {
    const authTime = new Date(Date.now() - (ABSOLUTE_LIFETIME_HOURS + 1) * 3600_000);
    const started = await sessions.start(signedIn({ authTime }));

    // Active one second ago.
    await sessions.touch(started.session, new Date());

    const lookup = await sessions.read(asRequestCookie(started.cookie));
    expect(lookup).toMatchObject({ status: 'expired', reason: 'absolute' });
  });

  /** Reported in the order that sends an operator to the right place. */
  it('reports the absolute limit ahead of inactivity when both have passed', () => {
    const authTime = new Date(Date.now() - 20 * 3600_000);
    expect(
      expiryOf({
        idHash: 'x',
        subject: 's',
        authTime,
        methods: [],
        createdAt: authTime,
        lastActivityAt: authTime,
        lastCheckedAt: authTime,
        csrfToken: 't',
        higherRisk: false,
      }),
    ).toBe('absolute');
  });

  it('deletes an expired session as it reads it', async () => {
    const started = await sessions.start(signedIn());
    expect(store.size).toBe(1);

    await sessions.read(
      asRequestCookie(started.cookie),
      new Date(Date.now() + 24 * 3600_000),
    );

    expect(store.size).toBe(0);
  });

  /**
   * §8.2: background polling is not activity. If READING a session extended
   * it, a page left open with a timer would never time out and the inactivity
   * limit would be enforced against nobody.
   */
  it('does not extend a session merely by reading it', async () => {
    const started = await sessions.start(signedIn());
    const before = started.session.lastActivityAt.getTime();

    await sessions.read(asRequestCookie(started.cookie), new Date(Date.now() + 30 * 60_000));

    const stored = await store.find(started.session.idHash);
    expect(stored!.lastActivityAt.getTime()).toBe(before);
  });

  it('extends it when the caller says there was activity', async () => {
    const started = await sessions.start(signedIn());
    const later = new Date(Date.now() + 30 * 60_000);

    await sessions.touch(started.session, later);

    const stored = await store.find(started.session.idHash);
    expect(stored!.lastActivityAt.getTime()).toBe(later.getTime());
  });

  it('warns 5 minutes before the end, on both limits', async () => {
    const ordinary = await sessions.start(signedIn());
    const risky = await sessions.start(signedIn(), { higherRisk: true });

    const minutesOut = (s: { session: { lastActivityAt: Date } }, warn: Date) =>
      Math.round((warn.getTime() - s.session.lastActivityAt.getTime()) / 60_000);

    expect(minutesOut(ordinary, expiryWarningAt(ordinary.session))).toBe(55);
    expect(minutesOut(risky, expiryWarningAt(risky.session))).toBe(10);
  });
});

describe('ending a session', () => {
  it('removes the record and clears the cookie', async () => {
    const started = await sessions.start(signedIn());

    const { cookie } = await sessions.end(asRequestCookie(started.cookie));

    expect(cookie).toContain('Max-Age=0');
    expect(store.size).toBe(0);
    expect(await sessions.read(asRequestCookie(started.cookie))).toMatchObject({ status: 'none' });
  });

  it('still clears the cookie when there was no session to remove', async () => {
    const { cookie } = await sessions.end('__Host-inventory_sid=never-existed');
    expect(cookie).toContain('Max-Age=0');
  });

  it('can end every session of an identity session, for revocation (§3.5)', async () => {
    await sessions.start(signedIn());
    await sessions.start(signedIn());
    await sessions.start(signedIn({ sessionId: 'a-different-identity-session' }));

    await store.deleteByIdentitySession('identity-session-1');

    expect(store.size).toBe(1);
  });

  /**
   * §8.6: "Sign out … Ends the identity session for this browser and every
   * application session derived from it."
   *
   * Ending only the application's own session is a sign-out that does not sign
   * anybody out — the identity session survives, the grant is still saved, and
   * the next authorization request issues a code with no interaction. Observed
   * in TeamDeck on 25 September 2026, in code that had been copied from the
   * same wrong assumption into every consumer.
   */
  it('tells the provider to end the identity session (§8.6)', async () => {
    const ended: string[] = [];
    sessions = createSessionManager({
      store,
      appName: 'inventory',
      endIdentitySession: async (reference) => {
        ended.push(reference);
      },
    });

    const started = await sessions.start(signedIn());
    await sessions.end(asRequestCookie(started.cookie));

    expect(ended).toEqual(['identity-session-1']);
  });

  /**
   * The reference lives on the record, so reading it after the delete finds
   * nothing and the provider is never told. That ordering is the entire bug,
   * and it is invisible from outside: the cookie clears either way.
   */
  it('reads the reference before deleting the record', async () => {
    const ended: string[] = [];
    sessions = createSessionManager({
      store,
      appName: 'inventory',
      endIdentitySession: async (reference) => {
        ended.push(reference);
      },
    });

    const started = await sessions.start(signedIn({ sessionId: 'still-findable' }));
    await sessions.end(asRequestCookie(started.cookie));

    expect(ended).toEqual(['still-findable']);
    expect(store.size).toBe(0);
  });

  /**
   * This browser's session is already gone by then. Reporting failure would
   * leave the page believing it is still signed in when it is not.
   */
  it('still signs out when the provider cannot be told', async () => {
    sessions = createSessionManager({
      store,
      appName: 'inventory',
      endIdentitySession: async () => {
        throw new Error('unreachable');
      },
    });

    const started = await sessions.start(signedIn());
    const { cookie } = await sessions.end(asRequestCookie(started.cookie));

    expect(cookie).toContain('Max-Age=0');
    expect(store.size).toBe(0);
  });

  /** A session that never had a reference has nothing to tell the provider. */
  it('says nothing when the session carries no reference', async () => {
    let called = false;
    sessions = createSessionManager({
      store,
      appName: 'inventory',
      endIdentitySession: async () => {
        called = true;
      },
    });

    const started = await sessions.start(signedIn({ sessionId: undefined }));
    await sessions.end(asRequestCookie(started.cookie));

    expect(called).toBe(false);
  });
});

describe('CSRF and Origin (§8.4)', () => {
  const allowed = [ORIGIN];

  async function session() {
    const started = await sessions.start(signedIn());
    return started.session;
  }

  it('lets a same-origin write through with the right token', async () => {
    const s = await session();
    expect(
      verifyCsrf({
        method: 'POST',
        origin: ORIGIN,
        token: s.csrfToken,
        session: s,
        allowedOrigins: allowed,
      }),
    ).toEqual({ ok: true });
  });

  it('refuses a write from another origin even with the right token', async () => {
    const s = await session();
    expect(
      verifyCsrf({
        method: 'POST',
        origin: 'https://not-us.example',
        token: s.csrfToken,
        session: s,
        allowedOrigins: allowed,
      }),
    ).toEqual({ ok: false, reason: 'foreign-origin' });
  });

  it('refuses a same-origin write with no token', async () => {
    const s = await session();
    expect(
      verifyCsrf({ method: 'POST', origin: ORIGIN, token: null, session: s, allowedOrigins: allowed }),
    ).toEqual({ ok: false, reason: 'missing-token' });
  });

  it('refuses another session’s token', async () => {
    const mine = await session();
    const theirs = await session();
    expect(
      verifyCsrf({
        method: 'POST',
        origin: ORIGIN,
        token: theirs.csrfToken,
        session: mine,
        allowedOrigins: allowed,
      }),
    ).toEqual({ ok: false, reason: 'bad-token' });
  });

  /** Absent Origin is refused, not waved through. */
  it('refuses a write with no Origin at all', async () => {
    const s = await session();
    expect(
      verifyCsrf({
        method: 'POST',
        origin: undefined,
        token: s.csrfToken,
        session: s,
        allowedOrigins: allowed,
      }),
    ).toEqual({ ok: false, reason: 'missing-origin' });
  });

  it('leaves reads alone — a token on a GET is a token in an access log', async () => {
    const s = await session();
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
      expect(
        verifyCsrf({ method, origin: undefined, token: null, session: s, allowedOrigins: allowed }),
      ).toEqual({ ok: true });
    }
  });

  it('checks every state-changing method §8.4 names', async () => {
    const s = await session();
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(
        verifyCsrf({ method, origin: ORIGIN, token: 'wrong', session: s, allowedOrigins: allowed }),
      ).toMatchObject({ ok: false });
    }
  });

  it('compares origins by scheme, host AND port', () => {
    expect(verifyOrigin('https://app.test:8443', ['https://app.test'])).toMatchObject({ ok: false });
    expect(verifyOrigin('http://app.test', ['https://app.test'])).toMatchObject({ ok: false });
    expect(verifyOrigin('https://APP.test', ['https://app.test'])).toEqual({ ok: true });
  });

  it('refuses an unparseable Origin rather than throwing', () => {
    expect(verifyOrigin('not a url', [ORIGIN])).toEqual({ ok: false, reason: 'foreign-origin' });
  });

  it('names the header a page sends its token in', () => {
    expect(CSRF_HEADER).toBe('x-rosor-csrf');
  });
});
