/**
 * The sign-in flow, end to end — standard v0.9 §3.4.
 *
 * Tokens are really signed and really verified; only the network is stubbed.
 * Most of what this library does is refuse things, so most of what follows is
 * about the refusals.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  clearDiscoveryCache,
  clearJwksCache,
  createLoginClient,
  RosorLoginConfigError,
  RosorLoginError,
  RosorLoginProviderError,
} from '../src/index.js';
import {
  CLIENT_ID,
  CLIENT_SECRET,
  INTERNAL_ISSUER,
  ISSUER,
  REDIRECT_URI,
  createStubProvider,
  type StubProvider,
} from './helpers/stubProvider.js';

let provider: StubProvider;

function client(overrides: Record<string, unknown> = {}) {
  return createLoginClient(
    {
      issuer: ISSUER,
      internalIssuer: INTERNAL_ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      ...overrides,
    },
    provider.fetch,
  );
}

beforeEach(async () => {
  clearDiscoveryCache();
  clearJwksCache();
  provider = await createStubProvider();
});

describe('beginning a sign-in', () => {
  it('builds an authorization request with everything §3.4 requires', async () => {
    const pending = await client().begin();
    const url = new URL(pending.url);
    const q = url.searchParams;

    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/oidc/auth`);
    expect(q.get('response_type')).toBe('code');
    expect(q.get('client_id')).toBe(CLIENT_ID);
    expect(q.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(q.get('code_challenge_method')).toBe('S256');
    expect(q.get('scope')).toContain('openid');
  });

  /** The challenge must actually be the hash, not merely present. */
  it('sends the S256 hash of the verifier, and keeps the verifier back', async () => {
    const pending = await client().begin();
    const expected = createHash('sha256').update(pending.codeVerifier).digest('base64url');

    expect(new URL(pending.url).searchParams.get('code_challenge')).toBe(expected);
    expect(pending.url).not.toContain(pending.codeVerifier);
  });

  it('never repeats a state, nonce or verifier', async () => {
    const a = await client().begin();
    const b = await client().begin();

    expect(a.state).not.toBe(b.state);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
  });

  it('passes prompt and max_age through for re-authentication', async () => {
    const pending = await client().begin({ prompt: 'login', maxAge: 900 });
    const q = new URL(pending.url).searchParams;

    expect(q.get('prompt')).toBe('login');
    expect(q.get('max_age')).toBe('900');
    // Echoed back so the callback can hold the provider to it.
    expect(pending.maxAge).toBe(900);
  });

  /** The browser goes to the public issuer, whatever the back channel is. */
  it('sends the browser to the public issuer, not the internal one', async () => {
    const pending = await client().begin();
    expect(pending.url.startsWith(ISSUER)).toBe(true);
    expect(pending.url).not.toContain(INTERNAL_ISSUER);
  });
});

describe('finishing a sign-in', () => {
  async function flow(overrides: { nonce?: string; maxAge?: number } = {}) {
    const c = client();
    const pending = await c.begin(overrides.maxAge ? { maxAge: overrides.maxAge } : {});
    provider.nextIdToken = await provider.mintIdToken({ nonce: overrides.nonce ?? pending.nonce });
    return { c, pending };
  }

  it('returns who signed in, when, and how', async () => {
    const { c, pending } = await flow();

    const user = await c.complete({
      code: 'the-code',
      state: pending.state,
      expected: pending,
    });

    expect(user.subject).toBe('account-1');
    expect(user.email).toBe('ada.lovelace@rosor.ca');
    expect(user.methods).toEqual(['pwd', 'otp']);
    expect(user.sessionId).toBe('identity-session-1');
    expect(user.authTime).toBeInstanceOf(Date);
  });

  /**
   * §3.4: the code exchange goes over rosor_internal and never through a
   * public hostname. The client secret is in that request.
   */
  it('exchanges the code over the internal network', async () => {
    const { c, pending } = await flow();
    await c.complete({ code: 'the-code', state: pending.state, expected: pending });

    const tokenCalls = provider.calls.filter((u) => u.endsWith('/oidc/token'));
    expect(tokenCalls).toHaveLength(1);
    expect(tokenCalls[0]!.startsWith(INTERNAL_ISSUER)).toBe(true);
    expect(provider.calls.every((u) => !u.startsWith(ISSUER))).toBe(true);
  });
});

describe('what it refuses', () => {
  /**
   * The ordering one. State is checked before the code is redeemed, so a
   * callback from somebody else's flow never reaches the provider at all.
   */
  it('refuses a mismatched state WITHOUT redeeming the code', async () => {
    const c = client();
    const pending = await c.begin();

    await expect(
      c.complete({ code: 'the-code', state: 'not-the-state', expected: pending }),
    ).rejects.toMatchObject({ code: 'state_mismatch' });

    expect(provider.calls.some((u) => u.endsWith('/oidc/token'))).toBe(false);
  });

  it('refuses a token minted for a different request (nonce)', async () => {
    const c = client();
    const pending = await c.begin();
    provider.nextIdToken = await provider.mintIdToken({ nonce: 'some-other-flows-nonce' });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'nonce_mismatch' });
  });

  /**
   * Algorithm confusion. The token is signed HS256 with the client secret,
   * which both parties hold — the classic way to forge one against a verifier
   * that trusts the header's `alg`.
   */
  it('refuses an HS256 token signed with the client secret', async () => {
    const c = client();
    const pending = await c.begin();
    provider.nextIdToken = await provider.mintHs256Token({ nonce: pending.nonce });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('refuses a token from another issuer', async () => {
    const c = client();
    const pending = await c.begin();
    provider.nextIdToken = await provider.mintIdToken({
      nonce: pending.nonce,
      issuer: 'https://auth.somewhere-else.test',
    });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('refuses a token minted for another application', async () => {
    const c = client();
    const pending = await c.begin();
    provider.nextIdToken = await provider.mintIdToken({
      nonce: pending.nonce,
      audience: 'some-other-app',
    });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('refuses an expired token', async () => {
    const c = client();
    const pending = await c.begin();
    provider.nextIdToken = await provider.mintIdToken({
      nonce: pending.nonce,
      expiresIn: '-1m',
    });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('refuses a token with no auth_time, since no session rule can be applied', async () => {
    const c = client();
    const pending = await c.begin();
    provider.nextIdToken = await provider.mintIdToken({
      nonce: pending.nonce,
      includeAuthTime: false,
    });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'no_auth_time' });
  });

  /**
   * §3.4: "The application SHALL reject a token whose auth_time is earlier
   * than its request." Re-authentication that is asked for and not enforced is
   * the same as not asking.
   */
  it('refuses a stale sign-in when re-authentication was requested', async () => {
    const c = client();
    const pending = await c.begin({ maxAge: 900 });
    provider.nextIdToken = await provider.mintIdToken({
      nonce: pending.nonce,
      authTime: Math.floor(Date.now() / 1000) - 3600,
    });

    await expect(
      c.complete({ code: 'the-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'stale_authentication' });
  });

  it('accepts a fresh sign-in when re-authentication was requested', async () => {
    const c = client();
    const pending = await c.begin({ maxAge: 900 });
    provider.nextIdToken = await provider.mintIdToken({
      nonce: pending.nonce,
      authTime: Math.floor(Date.now() / 1000) - 60,
    });

    const user = await c.complete({ code: 'the-code', state: pending.state, expected: pending });
    expect(user.subject).toBe('account-1');
  });

  it("repeats the provider's own error, which is the actionable part", async () => {
    const c = client();
    const pending = await c.begin();
    provider.failNextTokenRequest('invalid_grant');

    await expect(
      c.complete({ code: 'a-spent-code', state: pending.state, expected: pending }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });
});

describe('configuration and the provider it points at', () => {
  it('refuses a configuration with no client secret', () => {
    expect(() => client({ clientSecret: '' })).toThrow(RosorLoginConfigError);
  });

  it('refuses a relative issuer', () => {
    expect(() => client({ issuer: '/api/v1/auth-module' })).toThrow(RosorLoginConfigError);
  });

  /** The mix-up case: the instance answering is not the one configured. */
  it('refuses a provider that identifies itself as someone else', async () => {
    provider.discoveryIssuer = 'https://auth.production.test/api/v1/auth-module';

    await expect(client().begin()).rejects.toThrow(RosorLoginProviderError);
  });

  it('adds openid to a scope that omits it', async () => {
    const pending = await client({ scope: 'profile' }).begin();
    expect(new URL(pending.url).searchParams.get('scope')).toBe('openid profile');
  });

  it('reports a dark module as a provider problem, not a crash', async () => {
    const dark = createLoginClient(
      {
        issuer: ISSUER,
        internalIssuer: INTERNAL_ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
      },
      (async () => new Response('{"error":"Not found"}', { status: 404 })) as typeof fetch,
    );

    await expect(dark.begin()).rejects.toThrow(RosorLoginProviderError);
  });
});

describe('the error types are distinguishable', () => {
  it('separates a configuration mistake from a provider problem from a rejected token', async () => {
    expect(new RosorLoginConfigError('x')).toBeInstanceOf(Error);
    expect(new RosorLoginProviderError('x')).toBeInstanceOf(Error);
    expect(new RosorLoginError('code', 'x').code).toBe('code');
  });
});
