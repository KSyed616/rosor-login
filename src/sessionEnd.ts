/**
 * Telling the provider to end the identity session — standard v0.9 §8.6.
 *
 *   "**Sign out**, visible in every application's header — Ends the identity
 *    session for this browser and every application session derived from it."
 *
 * BOTH HALVES, and an application that does only the second has a sign-out
 * button that does not sign anybody out. Ending the application's own session
 * clears its cookie and nothing else: the identity session is still live, the
 * grant is still saved, and the next authorization request issues a code with
 * no interaction at all. The person presses sign out, presses sign in, and is
 * back where they were having proved nothing — which reads as a bug in the
 * button rather than a rule that was never implemented.
 *
 * Observed in TeamDeck on 25 September 2026, and the same omission was in
 * every consumer, because each had written its own sign-out from the same
 * wrong assumption: that the identity session is the provider's business and
 * outlives the application. It outlives an application session EXPIRING. It
 * does not outlive somebody pressing sign out.
 *
 * THE ENDPOINT IS A SIBLING OF THE OIDC MOUNT, like the session check, so it
 * cannot be derived from the issuer — and it is deliberately not derived from
 * `sessionCheckUrl` either. Building one URL by editing another is the kind of
 * cleverness that works until a deployment mounts things differently, and then
 * fails by POSTing a sign-out somewhere unexpected.
 *
 * WHAT IT DOES NOT DO is reach other applications directly. They learn about
 * it through §3.5's check, within five minutes. That is the mechanism the
 * standard specifies, and it is why the check exists.
 */

import type { ResolvedConfig } from './config.js';
import { RosorLoginProviderError } from './discovery.js';

export interface SessionEndResult {
  /** Whether the provider was asked. False when no URL is configured. */
  requested: boolean;
  /**
   * Why it was not, when it was not — for a caller that wants to log it.
   * `not-configured` is a deployment that never set the URL; `unreachable` is
   * a provider that could not be reached or refused.
   */
  reason?: 'not-configured' | 'unreachable';
}

/**
 * Ask the provider to end the identity session behind a reference.
 *
 * NEVER THROWS, which is the opposite of `checkSession` and deliberate. The
 * check refuses to decide on the caller's behalf because both readings of an
 * unreachable provider are dangerous. Here the dangerous reading is only one
 * way round: by the time this runs the application's own session is already
 * gone, so reporting failure would leave the page believing it is still signed
 * in when it is not. An unreachable provider means the identity session
 * outlives the sign-out until its own timers end it — worth logging, not worth
 * failing the sign-out over.
 */
export async function endIdentitySession(
  config: ResolvedConfig,
  reference: string,
  fetchImpl: typeof fetch = fetch,
): Promise<SessionEndResult> {
  if (!config.sessionEndUrl) return { requested: false, reason: 'not-configured' };

  // Raw, NOT form-encoded — the same client authentication as the session
  // check, and for the same reason: the provider splits the decoded string on
  // the first colon and compares bytes.
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

  try {
    const response = await fetchImpl(config.sessionEndUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Basic ${credentials}`,
      },
      body: JSON.stringify({ session: reference }),
    });

    if (!response.ok) {
      return { requested: false, reason: 'unreachable' };
    }
    return { requested: true };
  } catch {
    return { requested: false, reason: 'unreachable' };
  }
}

/** Exported so a caller can report the failure in its own words. */
export { RosorLoginProviderError };
