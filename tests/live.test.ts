/**
 * Against a REAL provider.
 *
 * The stub suite proves the library's own logic. This one proves the two
 * agree — and disagreement is where the surprises have been. Step 14 of the
 * migration turned up five behaviours of `oidc-provider` that no mock would
 * have contradicted: client metadata defaulting to RS256, consent needing an
 * explicit grant for a first-party client, `amr` being filtered out unless
 * declared, and so on. Every one of them was found by running the thing.
 *
 * SKIPPED when no provider is reachable, rather than failed: this cannot run
 * in a pipeline that has no TeamDeck, and a suite that is red for an
 * environmental reason trains people to ignore red.
 *
 *   ROSOR_LOGIN_LIVE_ISSUER=http://localhost:3001/api/v1/auth-module \
 *   ROSOR_LOGIN_LIVE_CLIENT_ID=inventory \
 *   ROSOR_LOGIN_LIVE_CLIENT_SECRET=... \
 *   ROSOR_LOGIN_LIVE_REDIRECT_URI=http://localhost:10000/auth/callback \
 *     npx vitest run tests/live.test.ts
 *
 * WHAT IT CANNOT DO is complete a sign-in: that needs a person, a password and
 * an authenticator code. What it can do is establish everything on either side
 * of that — which is most of what goes wrong.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { clearDiscoveryCache, createLoginClient, resolveConfig } from '../src/index.js';
import { discover } from '../src/discovery.js';

const ISSUER = process.env.ROSOR_LOGIN_LIVE_ISSUER;
const CLIENT_ID = process.env.ROSOR_LOGIN_LIVE_CLIENT_ID;
const CLIENT_SECRET = process.env.ROSOR_LOGIN_LIVE_CLIENT_SECRET;
const REDIRECT_URI = process.env.ROSOR_LOGIN_LIVE_REDIRECT_URI;

const configured = Boolean(ISSUER && CLIENT_ID && CLIENT_SECRET && REDIRECT_URI);

let reachable = false;

beforeAll(async () => {
  if (!configured) return;
  try {
    const response = await fetch(`${ISSUER}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(3000),
    });
    reachable = response.ok;
  } catch {
    reachable = false;
  }
  if (!reachable) {
    console.warn(`[live] No provider at ${ISSUER} — skipping the live suite.`);
  }
});

const live = configured ? describe : describe.skip;

live('against a running provider', () => {
  const config = () =>
    resolveConfig({
      issuer: ISSUER!,
      clientId: CLIENT_ID!,
      clientSecret: CLIENT_SECRET!,
      redirectUri: REDIRECT_URI!,
    });

  it('agrees with the provider about who it is, and what it will sign with', async () => {
    if (!reachable) return;
    clearDiscoveryCache();

    const endpoints = await discover(config());

    expect(endpoints.issuer).toBe(ISSUER);
    expect(endpoints.authorizationEndpoint).toContain('/oidc/auth');
    expect(endpoints.tokenEndpoint).toContain('/oidc/token');
  });

  it('can read the provider’s actual signing keys', async () => {
    if (!reachable) return;
    const endpoints = await discover(config());

    const jwks = (await (await fetch(endpoints.jwksUri)).json()) as {
      keys: { kty: string; crv?: string; alg?: string }[];
    };

    expect(jwks.keys.length).toBeGreaterThan(0);
    // EdDSA over Ed25519, and no private half served.
    expect(jwks.keys[0]!.kty).toBe('OKP');
    expect(jwks.keys[0]!.crv).toBe('Ed25519');
    expect(JSON.stringify(jwks)).not.toContain('"d"');
  });

  /**
   * The registration check. An authorization request that the provider
   * ACCEPTS redirects the browser onward to sign in; one it rejects answers
   * with an error instead. This is the step-14 failure mode — a client whose
   * metadata or redirect URI the provider will not have — and it is visible
   * without anybody signing in.
   */
  it('is a client the provider will actually start a flow for', async () => {
    if (!reachable) return;

    const pending = await createLoginClient({
      issuer: ISSUER!,
      clientId: CLIENT_ID!,
      clientSecret: CLIENT_SECRET!,
      redirectUri: REDIRECT_URI!,
    }).begin();

    const response = await fetch(pending.url, { redirect: 'manual' });

    expect([302, 303]).toContain(response.status);
    const location = response.headers.get('location') ?? '';
    // Onward to an interaction or the sign-in page — not back to us with an error.
    expect(location).not.toContain('error=');
  });

  /** §3.4: redirect URIs are matched exactly. */
  it('is refused when the redirect URI is not the registered one', async () => {
    if (!reachable) return;

    const pending = await createLoginClient({
      issuer: ISSUER!,
      clientId: CLIENT_ID!,
      clientSecret: CLIENT_SECRET!,
      redirectUri: `${REDIRECT_URI}/extra`,
    }).begin();

    const response = await fetch(pending.url, { redirect: 'manual' });
    const body = await response.text();
    const location = response.headers.get('location') ?? '';

    expect(`${location} ${body}`).toMatch(/redirect_uri|invalid_redirect_uri/i);
  });

  /**
   * THE CLIENT SECRET TEST, and the reason this suite is worth having.
   *
   * A deliberately invalid code is exchanged. The provider's answer says which
   * half failed:
   *
   *   invalid_grant   the CLIENT authenticated; the code was no good — which
   *                   is the expected result, and proves client_secret_basic,
   *                   the secret, and the endpoint are all correct
   *   invalid_client  the client did not authenticate — wrong secret, wrong
   *                   id, or an auth method the provider does not accept
   *
   * So a passing test here means the only untested part of the exchange is the
   * code itself, which only a real sign-in can produce.
   */
  it('authenticates as a client, proved by which error a bad code returns', async () => {
    if (!reachable) return;

    const client = createLoginClient({
      issuer: ISSUER!,
      clientId: CLIENT_ID!,
      clientSecret: CLIENT_SECRET!,
      redirectUri: REDIRECT_URI!,
    });
    const pending = await client.begin();

    const error = await client
      .complete({
        code: 'a-code-that-was-never-issued',
        state: pending.state,
        expected: pending,
      })
      .then(
        () => null,
        (e: { code?: string }) => e,
      );

    expect(error).not.toBeNull();
    expect(error!.code).toBe('invalid_grant');
    expect(error!.code).not.toBe('invalid_client');
  });
});
