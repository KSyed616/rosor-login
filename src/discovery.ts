/**
 * Where the provider's endpoints are — read from the provider, not guessed.
 *
 * Deriving `${issuer}/oidc/auth` by convention would work today and break
 * silently the day a path moves. Discovery is one request, cached for the life
 * of the process.
 *
 * THE BACK-CHANNEL REBASE. Discovery is fetched over `rosor_internal` but the
 * document it returns describes PUBLIC endpoints, because that is what a
 * browser needs. The token and JWKS endpoints must not be used as published:
 * §3.4 requires the code exchange to go over the internal network. So the
 * public issuer prefix is swapped for the internal one on exactly those two,
 * and the authorization endpoint is left public, which is where the browser is
 * genuinely meant to go.
 *
 * THE ISSUER CHECK is not bookkeeping. If the document's `iss` does not match
 * the issuer this application was configured with, it is talking to a
 * different provider than it thinks — the mix-up case — and every later check
 * would then be performed against the wrong authority. It fails here instead.
 */

import type { ResolvedConfig } from './config.js';
import { SIGNING_ALG } from './config.js';

export interface ProviderEndpoints {
  issuer: string;
  /** Public — the browser is sent here. */
  authorizationEndpoint: string;
  /** Internal — the client secret goes here. */
  tokenEndpoint: string;
  /** Internal. */
  jwksUri: string;
}

export class RosorLoginProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RosorLoginProviderError';
  }
}

interface DiscoveryDocument {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
  id_token_signing_alg_values_supported?: string[];
  code_challenge_methods_supported?: string[];
}

/**
 * Move an endpoint onto the base that suits its purpose.
 *
 * A published endpoint may arrive on EITHER base, and which one depends on
 * where discovery was fetched from rather than on anything about the endpoint.
 * `oidc-provider` behind a proxy derives endpoint URLs from the host the
 * request came in on, while `issuer` stays the configured constant — so
 * reading discovery over the internal address returns internal endpoints, and
 * reading it publicly returns public ones.
 *
 * Neither is wrong; both need normalising. The browser must be sent to the
 * PUBLIC authorization endpoint whichever way discovery answered, and the code
 * exchange and key fetches must go over the INTERNAL one (§3.4).
 *
 * An endpoint under neither base is still refused. That is the case the guard
 * was written for: rebasing something unrelated would send the client secret
 * to wherever a provider happened to name.
 */
function rebase(url: string, config: ResolvedConfig, onto: string): string {
  for (const base of [config.issuer, config.internalIssuer]) {
    if (url.startsWith(base)) return onto + url.slice(base.length);
  }
  throw new RosorLoginProviderError(
    `The provider published ${url}, which is under neither its issuer ` +
      `${config.issuer} nor its internal address ${config.internalIssuer}. ` +
      'Refusing to guess where it belongs.',
  );
}

const cache = new Map<string, ProviderEndpoints>();

export async function discover(
  config: ResolvedConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<ProviderEndpoints> {
  const cacheKey = `${config.issuer}|${config.internalIssuer}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const url = `${config.internalIssuer}/.well-known/openid-configuration`;

  let document: DiscoveryDocument;
  try {
    const response = await fetchImpl(url, { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      throw new RosorLoginProviderError(
        `Discovery at ${url} answered HTTP ${response.status}. ` +
          'If this is 404 the sign-in module is not enabled on that instance.',
      );
    }
    document = (await response.json()) as DiscoveryDocument;
  } catch (error) {
    if (error instanceof RosorLoginProviderError) throw error;
    throw new RosorLoginProviderError(
      `Could not reach the provider's discovery document at ${url}: ${(error as Error).message}`,
    );
  }

  if (document.issuer !== config.issuer) {
    throw new RosorLoginProviderError(
      `Issuer mismatch. Configured ${config.issuer}, but the provider at ` +
        `${config.internalIssuer} identifies itself as ${document.issuer}. ` +
        'One of the two is pointed at the wrong instance.',
    );
  }

  for (const [field, value] of Object.entries({
    authorization_endpoint: document.authorization_endpoint,
    token_endpoint: document.token_endpoint,
    jwks_uri: document.jwks_uri,
  })) {
    if (!value) throw new RosorLoginProviderError(`Discovery document has no ${field}`);
  }

  // Fail here rather than at the first sign-in. A provider that cannot sign
  // with the pinned algorithm cannot serve this application at all, and an
  // error at startup names the problem while an error mid-flow does not.
  const algs = document.id_token_signing_alg_values_supported ?? [];
  if (algs.length > 0 && !algs.includes(SIGNING_ALG)) {
    throw new RosorLoginProviderError(
      `The provider does not offer ${SIGNING_ALG} for ID tokens (it offers ${algs.join(', ')}). ` +
        'Appendix A.4 step 5 pins this algorithm on both sides; it is not negotiable here.',
    );
  }

  const methods = document.code_challenge_methods_supported ?? [];
  if (methods.length > 0 && !methods.includes('S256')) {
    throw new RosorLoginProviderError(
      `The provider does not support S256 code challenges (it supports ${methods.join(', ')}).`,
    );
  }

  const endpoints: ProviderEndpoints = {
    issuer: document.issuer!,
    // Public: a browser goes here, and it cannot reach rosor_internal.
    authorizationEndpoint: rebase(document.authorization_endpoint!, config, config.issuer),
    // Internal: the client secret and the key fetches go here (§3.4).
    tokenEndpoint: rebase(document.token_endpoint!, config, config.internalIssuer),
    jwksUri: rebase(document.jwks_uri!, config, config.internalIssuer),
  };

  cache.set(cacheKey, endpoints);
  return endpoints;
}

/** For tests, and for a process that needs to re-read a moved provider. */
export function clearDiscoveryCache(): void {
  cache.clear();
}
