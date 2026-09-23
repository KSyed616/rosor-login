/**
 * A stand-in provider with REAL keys.
 *
 * Only the transport is stubbed. The tokens are genuinely signed Ed25519 JWTs
 * served through a genuine JWKS document, so every verification the library
 * performs is the verification it will perform in production — a stub that
 * handed back a payload object would prove nothing about signature checking,
 * which is most of what this library does.
 */

import { exportJWK, generateKeyPair, SignJWT, calculateJwkThumbprint, type JWK } from 'jose';

export const ISSUER = 'https://auth.rosor.test/api/v1/auth-module';
export const INTERNAL_ISSUER = 'http://provider:3001/api/v1/auth-module';
export const CLIENT_ID = 'inventory';
export const CLIENT_SECRET = 'a-test-client-secret-of-reasonable-length';
export const REDIRECT_URI = 'https://inventory.rosor.test/auth/callback';

export interface MintOptions {
  audience?: string;
  issuer?: string;
  nonce?: string;
  authTime?: number;
  subject?: string;
  expiresIn?: string;
  includeAuthTime?: boolean;
  amr?: string[];
}

export interface StubProvider {
  fetch: typeof fetch;
  mintIdToken(options?: MintOptions): Promise<string>;
  /** An HS256 token signed with the client secret — the algorithm-confusion probe. */
  mintHs256Token(options?: MintOptions): Promise<string>;
  /** Every URL the library has requested, in order. */
  readonly calls: string[];
  /** Replaces the next token response with this error. */
  failNextTokenRequest(error: string, status?: number): void;
  /** What discovery reports as its issuer; changing it simulates a mix-up. */
  discoveryIssuer: string;
  nextIdToken: string | null;
}

export async function createStubProvider(): Promise<StubProvider> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  publicJwk.kid = kid;
  publicJwk.alg = 'EdDSA';
  publicJwk.use = 'sig';

  const calls: string[] = [];
  let tokenFailure: { error: string; status: number } | null = null;

  const state = {
    discoveryIssuer: ISSUER,
    nextIdToken: null as string | null,
  };

  async function mintIdToken(options: MintOptions = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const jwt = new SignJWT({
      nonce: options.nonce ?? 'the-nonce',
      email: 'ada.lovelace@rosor.ca',
      name: 'Ada Lovelace',
      amr: options.amr ?? ['pwd', 'otp'],
      sid: 'identity-session-1',
      ...(options.includeAuthTime === false ? {} : { auth_time: options.authTime ?? now }),
    })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setIssuedAt(now)
      .setIssuer(options.issuer ?? ISSUER)
      .setAudience(options.audience ?? CLIENT_ID)
      .setSubject(options.subject ?? 'account-1')
      .setExpirationTime(options.expiresIn ?? '5m');
    return jwt.sign(privateKey);
  }

  async function mintHs256Token(options: MintOptions = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      nonce: options.nonce ?? 'the-nonce',
      auth_time: options.authTime ?? now,
      amr: ['pwd'],
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(now)
      .setIssuer(options.issuer ?? ISSUER)
      .setAudience(options.audience ?? CLIENT_ID)
      .setSubject(options.subject ?? 'account-1')
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode(CLIENT_SECRET));
  }

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

  const stubFetch = (async (input: Parameters<typeof fetch>[0]): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push(url);

    if (url.endsWith('/.well-known/openid-configuration')) {
      return json({
        issuer: state.discoveryIssuer,
        authorization_endpoint: `${ISSUER}/oidc/auth`,
        token_endpoint: `${ISSUER}/oidc/token`,
        jwks_uri: `${ISSUER}/oidc/jwks`,
        id_token_signing_alg_values_supported: ['EdDSA'],
        code_challenge_methods_supported: ['S256'],
      });
    }

    if (url.endsWith('/oidc/jwks')) {
      return json({ keys: [publicJwk] });
    }

    if (url.endsWith('/oidc/token')) {
      if (tokenFailure) {
        const failure = tokenFailure;
        tokenFailure = null;
        return json({ error: failure.error }, failure.status);
      }
      return json({
        id_token: state.nextIdToken ?? (await mintIdToken()),
        access_token: 'an-access-token',
        token_type: 'Bearer',
      });
    }

    return json({ error: 'not_found' }, 404);
  }) as typeof fetch;

  return {
    fetch: stubFetch,
    mintIdToken,
    mintHs256Token,
    calls,
    failNextTokenRequest(error: string, status = 400) {
      tokenFailure = { error, status };
    },
    get discoveryIssuer() {
      return state.discoveryIssuer;
    },
    set discoveryIssuer(value: string) {
      state.discoveryIssuer = value;
    },
    get nextIdToken() {
      return state.nextIdToken;
    },
    set nextIdToken(value: string | null) {
      state.nextIdToken = value;
    },
  };
}
