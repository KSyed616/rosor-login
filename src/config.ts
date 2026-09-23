/**
 * What an application has to tell the library, and what it must not get wrong.
 *
 * Standard v0.9 §3.4, §3.5.
 */

/**
 * The ID token signing algorithm, pinned.
 *
 * Appendix A.4 step 5 requires the algorithm to be pinned explicitly on BOTH
 * signing and verification. TeamDeck pins it in three places on the issuing
 * side; this is the verifying side, and it is a constant rather than a config
 * field on purpose. A configurable algorithm is a configurable downgrade: the
 * value of pinning is that no deployment can be talked out of it, and `none`
 * is never one keystroke away.
 */
export const SIGNING_ALG = 'EdDSA' as const;

export interface RosorLoginConfig {
  /**
   * The provider's PUBLIC issuer — exactly the `iss` every ID token carries,
   * and the origin the browser is sent to.
   *
   * e.g. https://auth.example.com/api/v1/auth-module
   */
  issuer: string;

  /**
   * The provider's address on `rosor_internal`, for the back channel.
   *
   * §3.4: "Code exchanges and session checks between applications and TeamDeck
   * go directly over rosor_internal. They never pass through public hostnames,
   * and the internal port is never exposed through the tunnel."
   *
   * This is a SEPARATE field rather than something derived, because the two
   * genuinely differ — `http://provider:3001/api/v1/auth-module` against a
   * public issuer — and because a library that quietly sent the client secret
   * to whatever origin the browser used would be doing the opposite of what
   * §3.4 asks. Defaults to `issuer`, which is right only in development.
   */
  internalIssuer?: string;

  /** This application's client id, as registered in AUTH_CLIENT_SECRETS. */
  clientId: string;

  /** Its secret. Confidential client (§3.4) — never reaches a browser. */
  clientSecret: string;

  /**
   * Where the provider sends the browser back. Matched EXACTLY by the provider
   * (§3.4), so a trailing slash is a different URI and will be refused.
   */
  redirectUri: string;

  /** Defaults to "openid profile". `openid` is always included. */
  scope?: string;

  /**
   * The provider's `/internal/session-check`, on `rosor_internal` (§3.5).
   *
   * A SEPARATE FIELD, not derived. The OIDC provider is mounted at
   * `{module}/oidc` and this endpoint is its SIBLING at
   * `{module}/internal/session-check`, so no amount of manipulating the issuer
   * produces it. Deriving endpoints by convention is what left discovery
   * pointing at a 404.
   *
   * Without it, §3.5 session checks are unavailable and a revocation at the
   * provider will not reach this application.
   */
  sessionCheckUrl?: string;

  /**
   * Seconds of tolerance for clock skew when checking `exp` and `iat`.
   * Deliberately small: these are 5-minute tokens (§3.4), and a generous
   * tolerance on a short-lived token is most of its lifetime.
   */
  clockToleranceSeconds?: number;
}

export interface ResolvedConfig
  extends Required<Omit<RosorLoginConfig, 'internalIssuer' | 'sessionCheckUrl'>> {
  internalIssuer: string;
  sessionCheckUrl?: string;
}

export class RosorLoginConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RosorLoginConfigError';
  }
}

function requireAbsoluteUrl(name: string, value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new RosorLoginConfigError(`${name} must be an absolute URL, got ${JSON.stringify(value)}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new RosorLoginConfigError(`${name} must be http or https, got ${parsed.protocol}`);
  }
  // A trailing slash changes an exactly-matched redirect URI and silently
  // changes every derived endpoint path, so it is normalised once, here.
  return value.replace(/\/+$/, '');
}

/**
 * Validate and fill in the configuration.
 *
 * Throws rather than warning. A misconfigured sign-in client does not degrade
 * into a less convenient sign-in; it either fails at the provider with an error
 * the user cannot act on, or — worse — succeeds against the wrong issuer.
 */
export function resolveConfig(config: RosorLoginConfig): ResolvedConfig {
  for (const field of ['clientId', 'clientSecret'] as const) {
    if (!config[field] || !config[field].trim()) {
      throw new RosorLoginConfigError(`${field} is required`);
    }
  }

  const issuer = requireAbsoluteUrl('issuer', config.issuer);
  const internalIssuer = config.internalIssuer
    ? requireAbsoluteUrl('internalIssuer', config.internalIssuer)
    : issuer;

  // Not normalised: it is compared byte for byte by the provider, so trimming
  // it here would hide the mismatch rather than prevent it.
  requireAbsoluteUrl('redirectUri', config.redirectUri);

  const scope = (config.scope ?? 'openid profile').trim();
  const withOpenId = scope.split(/\s+/).includes('openid') ? scope : `openid ${scope}`;

  if (config.sessionCheckUrl) requireAbsoluteUrl('sessionCheckUrl', config.sessionCheckUrl);

  return {
    issuer,
    internalIssuer,
    sessionCheckUrl: config.sessionCheckUrl?.replace(/\/+$/, ''),
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    scope: withOpenId,
    clockToleranceSeconds: config.clockToleranceSeconds ?? 5,
  };
}
