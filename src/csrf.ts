/**
 * Cross-site request forgery — standard v0.9 §8.4.
 *
 * Two independent checks, and §8.4 asks for both because each covers the
 * other's gap:
 *
 *   TOKEN   A value bound to the session, which a cross-site page cannot read
 *           and therefore cannot send. Holds even where Origin is absent.
 *   ORIGIN  The browser's own statement of where the request came from, which
 *           script cannot forge. Holds even if a token leaks.
 *
 * SameSite=Lax on the cookie is a third layer and not a substitute: it is the
 * browser's default-deny, and defaults are exactly what a library should not
 * rely on alone.
 */

import { constantTimeEquals, type SessionRecord } from './session.js';

/** §8.4 names these; GET, HEAD and OPTIONS are not state-changing. */
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function isStateChanging(method: string): boolean {
  return STATE_CHANGING.has(method.toUpperCase());
}

export type CsrfFailure = 'missing-token' | 'bad-token' | 'missing-origin' | 'foreign-origin';

export type CsrfResult = { ok: true } | { ok: false; reason: CsrfFailure };

/** The header a page sends its token in. */
export const CSRF_HEADER = 'x-rosor-csrf';

export interface CsrfCheck {
  method: string;
  /** The `Origin` header, if the browser sent one. */
  origin: string | null | undefined;
  /** The token the page sent, normally from CSRF_HEADER. */
  token: string | null | undefined;
  /** The session the cookie resolved to. */
  session: Pick<SessionRecord, 'csrfToken'>;
  /**
   * Origins this application answers to, e.g.
   * ["https://app.example.com"]. Compared exactly, after
   * normalising away a trailing slash and case in the host.
   */
  allowedOrigins: string[];
}

function normalizeOrigin(origin: string): string | null {
  try {
    const url = new URL(origin);
    // Port included: https://app:8443 is not https://app.
    return `${url.protocol}//${url.host}`.toLowerCase();
  } catch {
    return null;
  }
}

export function verifyOrigin(
  origin: string | null | undefined,
  allowedOrigins: string[],
): CsrfResult {
  if (!origin) {
    // A state-changing request with no Origin is refused rather than allowed.
    // Every browser has sent it on cross-origin requests for years, and on
    // same-origin POSTs too; absence means a client this application has no
    // reason to treat as a browser. Allowing it would make the check optional
    // for exactly the caller most likely to be avoiding it.
    return { ok: false, reason: 'missing-origin' };
  }

  const candidate = normalizeOrigin(origin);
  if (!candidate) return { ok: false, reason: 'foreign-origin' };

  const permitted = allowedOrigins
    .map(normalizeOrigin)
    .filter((value): value is string => value !== null);

  return permitted.includes(candidate) ? { ok: true } : { ok: false, reason: 'foreign-origin' };
}

/**
 * Both checks, in the order that fails cheapest.
 *
 * Non-state-changing methods pass untouched — §8.4 scopes the requirement to
 * writes, and a CSRF token on a GET is a token in a query string, which is a
 * token in an access log.
 */
export function verifyCsrf(check: CsrfCheck): CsrfResult {
  if (!isStateChanging(check.method)) return { ok: true };

  const origin = verifyOrigin(check.origin, check.allowedOrigins);
  if (!origin.ok) return origin;

  if (!check.token) return { ok: false, reason: 'missing-token' };
  if (!constantTimeEquals(check.token, check.session.csrfToken)) {
    return { ok: false, reason: 'bad-token' };
  }

  return { ok: true };
}
