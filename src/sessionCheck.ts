/**
 * The five-minute session check — standard v0.9 §3.5.
 *
 *   "Each application checks every active session with TeamDeck at least every
 *    5 minutes, and before any sensitive action. The application reports
 *    whether the user was active since the last check. TeamDeck replies with
 *    the session's status. This is how revocations and timeouts reach every
 *    application within 5 minutes."
 *
 * It is the only thing that carries a revocation outward. Without it an
 * application session survives until its own timers run out, whatever the
 * provider has been told — so "signed out everywhere" is a button that signs
 * you out of one place and waits up to twelve hours for the rest.
 *
 * THE ENDPOINT IS NOT UNDER THE ISSUER. It is a sibling: the OIDC provider is
 * mounted at `{module}/oidc` and this lives at `{module}/internal/session-check`.
 * So it cannot be derived from `internalIssuer`, and `sessionCheckUrl` is a
 * separate configuration field rather than a guess. Convention is what put
 * discovery at a 404 in the first place.
 *
 * ITS CLIENT AUTHENTICATION IS NOT THE TOKEN ENDPOINT'S. Both are HTTP Basic,
 * but the token endpoint follows RFC 6749 and form-encodes each half, while
 * this endpoint splits the decoded string on the first colon and compares the
 * raw bytes. Encoding here would make a secret containing a reserved character
 * fail authentication, in a way that looks like a wrong secret.
 */

import type { ResolvedConfig } from './config.js';
import { RosorLoginError } from './callback.js';
import { RosorLoginProviderError } from './discovery.js';

export type SessionStatus = 'active' | 'expired' | 'revoked';

export interface SessionCheckResult {
  status: SessionStatus;
  /** Present only when active. */
  subject?: string;
  email?: string;
  /** The identity session's authentication time, which applications inherit. */
  authTime?: Date;
  amr?: string;
  aal?: string;
}

interface CheckResponseBody {
  status?: string;
  subject?: string;
  email?: string;
  authTime?: string;
  amr?: string;
  aal?: string;
}

export interface SessionCheckInput {
  /**
   * The identity session reference the provider issued to this application.
   *
   * NOT the browser's cookie, which an application never sees, and not the ID
   * token: a reference the provider recognises for this client.
   */
  reference: string;

  /**
   * Whether the user was active since the last check (§8.2, §3.5).
   *
   * The APPLICATION's to decide. Only it knows whether the traffic it saw was
   * a person or a poller, and the provider deliberately takes this as a field
   * rather than inferring it — a back-channel call is a server talking to a
   * server, with no X-Rosor-Background of its own.
   */
  active: boolean;
}

export async function checkSession(
  config: ResolvedConfig,
  input: SessionCheckInput,
  fetchImpl: typeof fetch = fetch,
): Promise<SessionCheckResult> {
  if (!config.sessionCheckUrl) {
    throw new RosorLoginError(
      'no_session_check_url',
      'sessionCheckUrl is not configured, so §3.5 session checks cannot be performed. ' +
        'It is the provider’s /internal/session-check on rosor_internal, and it cannot be ' +
        'derived from the issuer because it is a sibling of the OIDC mount, not a child.',
    );
  }

  // Raw, NOT form-encoded — see the note at the top of this file.
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

  let response: Response;
  try {
    response = await fetchImpl(config.sessionCheckUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Basic ${credentials}`,
      },
      body: JSON.stringify({ session: input.reference, active: input.active }),
    });
  } catch (error) {
    // §4: a failure of an external service SHALL NOT weaken a check. This one
    // is thrown rather than answered, because the two safe readings belong to
    // the caller: treating an unreachable provider as "still active" extends
    // every session through an outage, and treating it as "revoked" signs
    // everybody out of everything the moment the network hiccups. Neither is
    // this function's decision to make silently.
    throw new RosorLoginProviderError(
      `Could not reach the session check at ${config.sessionCheckUrl}: ${(error as Error).message}`,
    );
  }

  if (response.status === 401) {
    // The client secret, not the session. Distinguished because it is a
    // deployment fault and would otherwise read as "everyone signed out".
    throw new RosorLoginError(
      'invalid_client',
      'The provider refused this application’s credentials at the session check.',
    );
  }

  if (!response.ok) {
    throw new RosorLoginProviderError(
      `The session check answered HTTP ${response.status}.`,
    );
  }

  const body = (await response.json().catch(() => ({}))) as CheckResponseBody;

  if (body.status === 'active') {
    return {
      status: 'active',
      subject: body.subject,
      email: body.email,
      authTime: body.authTime ? new Date(body.authTime) : undefined,
      amr: body.amr,
      aal: body.aal,
    };
  }

  // Anything that is not explicitly active is treated as over. The provider
  // reports an unknown reference as `expired` deliberately, so that a stolen
  // client secret cannot be used to learn which references are real — and an
  // unrecognised status arriving from a future version should end the session
  // rather than extend it.
  return { status: body.status === 'revoked' ? 'revoked' : 'expired' };
}
