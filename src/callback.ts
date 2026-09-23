/**
 * Finishing a sign-in — standard v0.9 §3.4.
 *
 * Three things happen here and the ORDER matters:
 *
 *   1. `state` is checked BEFORE anything else. It is the only check that can
 *      be made without talking to the provider, and its whole purpose is to
 *      establish that this callback belongs to a flow this application began.
 *      Redeeming the code first would mean acting on an attacker's flow and
 *      then noticing.
 *   2. The code is exchanged over the internal network, authenticating with
 *      the client secret.
 *   3. The ID token is verified. Nothing in the token response is trusted
 *      until this succeeds — a token endpoint's JSON is not evidence of
 *      anything on its own.
 */

import { jwtVerify, type JWTPayload } from 'jose';
import { timingSafeEqual } from 'node:crypto';
import type { ResolvedConfig } from './config.js';
import { SIGNING_ALG } from './config.js';
import { discover, RosorLoginProviderError } from './discovery.js';
import { createJwksResolver, type KeyResolver } from './jwks.js';

export class RosorLoginError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'RosorLoginError';
    this.code = code;
  }
}

export interface CallbackInput {
  /** `code` from the callback query string. */
  code: string;
  /** `state` from the callback query string. */
  state: string;
  /** What was stored when the flow began. */
  expected: {
    state: string;
    nonce: string;
    codeVerifier: string;
    maxAge?: number;
  };
}

/** What the application gets: who signed in, when, and how. */
export interface SignedInUser {
  /** The account's stable identifier at the provider. */
  subject: string;
  email?: string;
  name?: string;
  /** When the person actually authenticated — NOT when this token was issued. */
  authTime: Date;
  /** The method used, e.g. ["pwd", "otp"] or ["swk"] (§3.4). */
  methods: string[];
  /** The identity session this came from, when the provider sends one. */
  sessionId?: string;
  /** Every claim, for anything the library does not model. */
  claims: JWTPayload;
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

interface TokenResponse {
  id_token?: string;
  access_token?: string;
  token_type?: string;
  error?: string;
  error_description?: string;
}

/**
 * Exchange the code. `client_secret_basic`, which is the provider's default
 * and keeps the secret out of the request body and therefore out of anything
 * that logs bodies.
 */
async function exchangeCode(
  config: ResolvedConfig,
  tokenEndpoint: string,
  code: string,
  codeVerifier: string,
  fetchImpl: typeof fetch,
): Promise<TokenResponse> {
  const credentials = Buffer.from(
    `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`,
  ).toString('base64');

  let response: Response;
  try {
    response = await fetchImpl(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        Authorization: `Basic ${credentials}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });
  } catch (error) {
    throw new RosorLoginProviderError(
      `Could not reach the token endpoint at ${tokenEndpoint}: ${(error as Error).message}`,
    );
  }

  const body = (await response.json().catch(() => ({}))) as TokenResponse;

  if (!response.ok || body.error) {
    // The provider's own error is repeated because it is actionable —
    // invalid_grant means a spent or expired code, invalid_client a secret or
    // a redirect URI that does not match. Neither names anything secret.
    throw new RosorLoginError(
      body.error ?? 'token_request_failed',
      `The provider refused the code exchange: ${body.error ?? `HTTP ${response.status}`}` +
        (body.error_description ? ` — ${body.error_description}` : ''),
    );
  }

  if (!body.id_token) {
    throw new RosorLoginError('no_id_token', 'The token response carried no ID token.');
  }

  return body;
}

const jwksCache = new Map<string, KeyResolver>();

/**
 * One resolver per endpoint, kept for the life of the process so its key cache
 * survives between sign-ins. Keyed by URI alone: two clients pointed at the
 * same provider are reading the same public keys.
 */
function jwksFor(uri: string, fetchImpl: typeof fetch): KeyResolver {
  let resolver = jwksCache.get(uri);
  if (!resolver) {
    resolver = createJwksResolver(uri, fetchImpl);
    jwksCache.set(uri, resolver);
  }
  return resolver;
}

export async function completeAuthorization(
  config: ResolvedConfig,
  input: CallbackInput,
  fetchImpl: typeof fetch = fetch,
): Promise<SignedInUser> {
  // 1. State, first and always.
  if (!input.state || !input.expected.state || !safeEqual(input.state, input.expected.state)) {
    throw new RosorLoginError(
      'state_mismatch',
      'The callback state did not match the one this application issued. ' +
        'The sign-in was not started here, or the stored flow has expired.',
    );
  }

  const endpoints = await discover(config, fetchImpl);

  // 2. The exchange, over the internal network.
  const tokens = await exchangeCode(
    config,
    endpoints.tokenEndpoint,
    input.code,
    input.expected.codeVerifier,
    fetchImpl,
  );

  // 3. Verification. `algorithms` is the pin: without it, jose accepts
  // whatever the token's own header asks for, which is how algorithm
  // confusion works.
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(tokens.id_token!, jwksFor(endpoints.jwksUri, fetchImpl), {
      algorithms: [SIGNING_ALG],
      issuer: config.issuer,
      audience: config.clientId,
      clockTolerance: config.clockToleranceSeconds,
    }));
  } catch (error) {
    throw new RosorLoginError('invalid_id_token', `ID token rejected: ${(error as Error).message}`);
  }

  // jose does not check the nonce; nothing does unless the application does.
  if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, input.expected.nonce)) {
    throw new RosorLoginError(
      'nonce_mismatch',
      'The ID token was not minted for this sign-in request.',
    );
  }

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new RosorLoginError('no_subject', 'The ID token carries no subject.');
  }

  // §3.4: "require_auth_time" is set on the provider, so this is always
  // present. Treated as mandatory rather than optional because every session
  // rule downstream is expressed in terms of it (§8.1) — an application
  // session inherits this time, and one without it cannot honour the 12-hour
  // overall limit.
  if (typeof payload.auth_time !== 'number') {
    throw new RosorLoginError(
      'no_auth_time',
      'The ID token carries no auth_time, so the age of the sign-in cannot be established.',
    );
  }

  // §3.4: "The application SHALL reject a token whose auth_time is earlier
  // than its request." Asking for max_age and not checking the answer is the
  // failure this prevents — the provider is trusted to re-authenticate, and
  // the one thing proving it did is this claim.
  if (input.expected.maxAge !== undefined) {
    const ageSeconds = Math.floor(Date.now() / 1000) - payload.auth_time;
    if (ageSeconds > input.expected.maxAge + config.clockToleranceSeconds) {
      throw new RosorLoginError(
        'stale_authentication',
        `A sign-in within ${input.expected.maxAge}s was requested, but the token reports one ` +
          `${ageSeconds}s old. The provider did not re-authenticate.`,
      );
    }
  }

  const amr = Array.isArray(payload.amr) ? (payload.amr as string[]) : [];

  return {
    subject: payload.sub,
    email: typeof payload.email === 'string' ? payload.email : undefined,
    name: typeof payload.name === 'string' ? payload.name : undefined,
    authTime: new Date(payload.auth_time * 1000),
    methods: amr,
    sessionId: typeof payload.sid === 'string' ? payload.sid : undefined,
    claims: payload,
  };
}

/** For tests. */
export function clearJwksCache(): void {
  jwksCache.clear();
}
