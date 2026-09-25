/**
 * @rosor/login — the relying-party half of Rosor sign-in.
 *
 * Authentication standard v0.9. v0.1.0 covered the FLOW — beginning an
 * authorization request, finishing it, and verifying the ID token (§3.4).
 * v0.2.0 adds the application session, its cookie, and the CSRF and Origin
 * checks (§8.1, §8.3, §8.4).
 *
 * NOT here yet: the activity heartbeat and the background-request marker
 * (§8.2), and the five-minute session check that carries revocations (§3.5).
 * Until that last one exists, a revocation at the provider does not reach an
 * application using this library.
 *
 * Usage:
 *
 *   const client = createLoginClient({
 *     issuer: 'https://auth.example.com/api/v1/auth-module',
 *     internalIssuer: 'http://provider:3001/api/v1/auth-module',
 *     clientId: 'inventory',
 *     clientSecret: process.env.ROSOR_LOGIN_CLIENT_SECRET!,
 *     redirectUri: 'https://app.example.com/auth/callback',
 *   });
 *
 *   // Starting a sign-in
 *   const pending = await client.begin();
 *   // store pending.state / nonce / codeVerifier / maxAge against this browser
 *   res.redirect(pending.url);
 *
 *   // The callback
 *   const user = await client.complete({ code, state, expected: stored });
 */

export { SIGNING_ALG, RosorLoginConfigError, resolveConfig } from './config.js';
export type { RosorLoginConfig, ResolvedConfig } from './config.js';

export { RosorLoginProviderError, discover, clearDiscoveryCache } from './discovery.js';
export type { ProviderEndpoints } from './discovery.js';

export { beginAuthorization } from './authorize.js';
export type { BeginOptions, PendingAuthorization } from './authorize.js';

export { completeAuthorization, RosorLoginError, clearJwksCache } from './callback.js';
export type { CallbackInput, SignedInUser } from './callback.js';

export { createPkcePair, createState, createNonce } from './pkce.js';
export type { PkcePair } from './pkce.js';

export {
  createSessionIdentifier,
  hashSessionIdentifier,
  createCsrfToken,
  constantTimeEquals,
  expiryOf,
  expiryWarningAt,
  inactivityLimitMinutes,
  DEFAULT_INACTIVITY_MINUTES,
  HIGHER_RISK_INACTIVITY_MINUTES,
  ABSOLUTE_LIFETIME_HOURS,
} from './session.js';
export type { SessionRecord, SessionStore, SessionLookup } from './session.js';

export { createSessionManager } from './sessionManager.js';
export type {
  SessionManager,
  SessionManagerOptions,
  StartedSession,
  VerifyOutcome,
} from './sessionManager.js';

export { InMemorySessionStore } from './memoryStore.js';

export { cookieName, sessionCookie, clearedSessionCookie, readCookie } from './cookie.js';
export type { CookieOptions } from './cookie.js';

export { verifyCsrf, verifyOrigin, isStateChanging, CSRF_HEADER } from './csrf.js';
export type { CsrfCheck, CsrfResult, CsrfFailure } from './csrf.js';

export {
  BACKGROUND_HEADER,
  HEARTBEAT_MAX_INTERVAL_MS,
  isBackgroundRequest,
  countsAsActivity,
} from './activity.js';

export { checkSession } from './sessionCheck.js';
export { endIdentitySession } from './sessionEnd.js';
export { listApplications } from './applications.js';
export type { RosorApplication } from './applications.js';
export type { SessionEndResult } from './sessionEnd.js';

// Freshness for sensitive actions (§8.1) and method changes (§6.2).
export {
  SENSITIVE_ACTION_SECONDS,
  METHOD_CHANGE_SECONDS,
  isFreshEnough,
  ageOfAuthentication,
  checkFreshness,
  stepUp,
} from './freshness.js';
export type { FreshnessVerdict } from './freshness.js';
export type { SessionCheckInput, SessionCheckResult, SessionStatus } from './sessionCheck.js';
export { checkIsDue, SESSION_CHECK_INTERVAL_MS } from './session.js';

import { resolveConfig, type RosorLoginConfig } from './config.js';
import { beginAuthorization, type BeginOptions, type PendingAuthorization } from './authorize.js';
import { completeAuthorization, type CallbackInput, type SignedInUser } from './callback.js';
import {
  checkSession as performSessionCheck,
  type SessionCheckInput,
  type SessionCheckResult,
} from './sessionCheck.js';
import { endIdentitySession as performSessionEnd, type SessionEndResult } from './sessionEnd.js';
import { listApplications as performListApplications, type RosorApplication } from './applications.js';

export interface LoginClient {
  begin(options?: BeginOptions): Promise<PendingAuthorization>;
  complete(input: CallbackInput): Promise<SignedInUser>;
  /** §3.5. Needs `sessionCheckUrl`; throws naming it when absent. */
  checkSession(input: SessionCheckInput): Promise<SessionCheckResult>;
  /**
   * §8.6. Needs `sessionEndUrl`. Never throws — see sessionEnd.ts for why this
   * is the opposite of `checkSession`.
   */
  endIdentitySession(reference: string): Promise<SessionEndResult>;
  /**
   * §1's app library. Needs `applicationsUrl`; returns an empty list without
   * it, because a launcher is a convenience and an empty grid is a smaller
   * failure than an exception in whatever page was rendering it.
   */
  listApplications(reference: string): Promise<RosorApplication[]>;
}

/**
 * The configuration is validated HERE, at construction, rather than on the
 * first sign-in. A bad issuer or a missing secret is a deployment mistake, and
 * a deployment mistake should be visible when the process starts rather than
 * when the first person tries to sign in.
 *
 * `fetchImpl` exists for tests and for an application that routes outbound
 * calls through its own agent. Applications normally omit it.
 */
export function createLoginClient(
  config: RosorLoginConfig,
  fetchImpl: typeof fetch = fetch,
): LoginClient {
  const resolved = resolveConfig(config);
  return {
    begin: (options) => beginAuthorization(resolved, options, fetchImpl),
    complete: (input) => completeAuthorization(resolved, input, fetchImpl),
    checkSession: (input) => performSessionCheck(resolved, input, fetchImpl),
    endIdentitySession: (reference) => performSessionEnd(resolved, reference, fetchImpl),
    listApplications: (reference) => performListApplications(resolved, reference, fetchImpl),
  };
}
