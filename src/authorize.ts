/**
 * Beginning a sign-in — standard v0.9 §3.4.
 *
 * Returns the URL to send the browser to, and the three secrets the
 * application must hold until the callback. The application stores them; this
 * library deliberately keeps no state, because a module-level map of pending
 * flows would be wrong the moment an application runs more than one process —
 * which every deployed one does.
 */

import type { ResolvedConfig } from './config.js';
import { discover } from './discovery.js';
import { createNonce, createPkcePair, createState } from './pkce.js';

export interface BeginOptions {
  /**
   * Force a fresh sign-in even if the identity session is valid (§3.4).
   * Used before sensitive actions and after an application's own timeout.
   */
  prompt?: 'login';

  /**
   * Seconds. The provider must re-authenticate if the last sign-in is older,
   * and the resulting token's `auth_time` is checked against this on the way
   * back. Sending it without checking the answer would be theatre, so
   * `completeAuthorization` requires it again.
   */
  maxAge?: number;

  /** Pre-fills the email field. Not a security control; the provider re-checks. */
  loginHint?: string;

  /** Overrides the configured scope for this one request. */
  scope?: string;
}

export interface PendingAuthorization {
  /** Send the browser here. */
  url: string;
  /** All three must be stored against this browser and required back. */
  state: string;
  nonce: string;
  codeVerifier: string;
  /** Echoed back so the callback can check `auth_time` against what was asked. */
  maxAge?: number;
}

export async function beginAuthorization(
  config: ResolvedConfig,
  options: BeginOptions = {},
  fetchImpl: typeof fetch = fetch,
): Promise<PendingAuthorization> {
  const endpoints = await discover(config, fetchImpl);
  const { verifier, challenge } = createPkcePair();
  const state = createState();
  const nonce = createNonce();

  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    redirect_uri: config.redirectUri,
    scope: options.scope ?? config.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  if (options.prompt) params.set('prompt', options.prompt);
  if (options.maxAge !== undefined) params.set('max_age', String(options.maxAge));
  if (options.loginHint) params.set('login_hint', options.loginHint);

  return {
    url: `${endpoints.authorizationEndpoint}?${params.toString()}`,
    state,
    nonce,
    codeVerifier: verifier,
    maxAge: options.maxAge,
  };
}
