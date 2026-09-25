/**
 * The app library — which Rosor applications this person can open.
 *
 * Standard v0.9 §1: "Each application runs in its own container, and a single
 * sign-in links them." This is what makes that visible: a grid, like Zoho's,
 * showing the applications somebody can actually use.
 *
 * ASKED THROUGH THE APPLICATION, not by the browser. The launcher renders
 * inside an application on its own origin; that application asks the provider
 * over `rosor_internal` and hands the answer to its own page. A browser-facing
 * version would need the identity session cookie sent cross-origin, with CORS
 * configured for every application's origin — more moving parts, and a cookie
 * travelling further than it needs to.
 *
 * THE PROVIDER DOES NOT DECIDE WHO MAY USE WHAT. It asks each application in
 * turn and returns the ones that said yes, because access is the
 * application's own question (Appendix A.3 decision 7). Nothing here needs to
 * know that; it is worth knowing only because it explains why this can be
 * slower than a local lookup, and why a missing tile is not a bug in the
 * launcher.
 */

import type { ResolvedConfig } from './config.js';

/** One tile. Deliberately only what a tile needs. */
export interface RosorApplication {
  id: string;
  name: string;
  url: string;
  /** A short name the application maps to its own icon set. Never a URL. */
  icon?: string;
}

/**
 * The applications this session's owner can open.
 *
 * NEVER THROWS, and returns an empty list when it cannot ask. A launcher is a
 * convenience: an empty grid costs somebody a bookmark, while an exception
 * takes down whatever page was rendering it. That is the opposite of
 * `checkSession`, which refuses to guess because both readings of its silence
 * are dangerous — here only one reading exists, and it is harmless.
 */
export async function listApplications(
  config: ResolvedConfig,
  reference: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RosorApplication[]> {
  if (!config.applicationsUrl) return [];

  // Raw, NOT form-encoded — the same client authentication as the session
  // check, and for the same reason: the provider splits the decoded string on
  // the first colon and compares bytes.
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

  try {
    const response = await fetchImpl(config.applicationsUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Basic ${credentials}`,
      },
      body: JSON.stringify({ session: reference }),
    });
    if (!response.ok) return [];

    const body = (await response.json().catch(() => ({}))) as {
      applications?: unknown;
    };
    if (!Array.isArray(body.applications)) return [];

    // Filtered rather than trusted: this ends up in a page, and an entry with
    // no url would render a tile that goes nowhere.
    return body.applications.filter(
      (app): app is RosorApplication =>
        typeof app === 'object' &&
        app !== null &&
        typeof (app as RosorApplication).id === 'string' &&
        typeof (app as RosorApplication).name === 'string' &&
        typeof (app as RosorApplication).url === 'string',
    );
  } catch {
    return [];
  }
}
