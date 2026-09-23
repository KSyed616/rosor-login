/**
 * The session cookie — standard v0.9 §8.3.
 *
 * Every attribute in that table, set here once so no application has to
 * remember them. The whole point of the table is that the defaults are wrong:
 * a cookie with none of these set is readable by script, sent cross-site, and
 * persists across browser restarts.
 *
 * | Attribute | Setting        | Why |
 * |-----------|----------------|-----|
 * | prefix    | `__Host-`      | browser enforces Secure, Path=/, no Domain |
 * | Domain    | omitted        | host-only; a Domain cookie reaches siblings |
 * | Path      | `/`            | required by the prefix |
 * | Secure    | set            | never sent in the clear |
 * | HttpOnly  | set            | script cannot read it, so XSS cannot lift it |
 * | SameSite  | `Lax`          | not sent on cross-site POSTs |
 * | Expiry    | none           | a browser-session cookie |
 *
 * NO EXPIRY IS DELIBERATE and is the attribute most often "fixed" by someone
 * adding a Max-Age. §8.3 says a session SHOULD NOT persist across browser
 * restarts, and §8.2 says cookie expiry SHALL NOT be what enforces a timeout.
 * The server decides when a session is over; the cookie just carries the
 * identifier until the browser closes.
 */

export interface CookieOptions {
  /** Application name, e.g. "inventory" — becomes `__Host-inventory_sid`. */
  appName: string;

  /**
   * Development escape hatch, and nothing more.
   *
   * `__Host-` REQUIRES Secure, so a browser silently drops the cookie when it
   * is served over plain http — which looks exactly like a sign-in that did
   * not work, with nothing in any log. Rather than emit a cookie the browser
   * will discard, `secure: false` also drops the prefix. The name therefore
   * differs between development and production, which is the honest trade: a
   * working development flow, and no pretence that the weaker cookie is the
   * same cookie.
   *
   * Browsers treat http://localhost as trustworthy, so localhost does NOT need
   * this — only a development host reached by some other name does.
   */
  secure?: boolean;
}

export function cookieName(options: CookieOptions): string {
  const base = `${options.appName}_sid`;
  return options.secure === false ? base : `__Host-${base}`;
}

function serialize(name: string, value: string, attributes: string[]): string {
  return [`${name}=${value}`, ...attributes].join('; ');
}

/** The `Set-Cookie` value that carries a new session. */
export function sessionCookie(identifier: string, options: CookieOptions): string {
  const attributes = ['Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (options.secure !== false) attributes.push('Secure');
  // No Domain, and no Max-Age or Expires. Both omissions are the requirement.
  return serialize(cookieName(options), identifier, attributes);
}

/**
 * The `Set-Cookie` value that removes it.
 *
 * Expires in the past AND an empty value: a browser that ignores one honours
 * the other, and a cookie that outlives its session record is a request that
 * gets a 401 for reasons the user cannot see.
 */
export function clearedSessionCookie(options: CookieOptions): string {
  const attributes = ['Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT'];
  if (options.secure !== false) attributes.push('Secure');
  return serialize(cookieName(options), '', attributes);
}

/**
 * Pull one cookie out of a `Cookie` header.
 *
 * Written out rather than pulled in as a dependency: this is the only parsing
 * the library needs, and a cookie parser is a surprisingly large surface to
 * take on for one lookup.
 *
 * Returns the FIRST match. A browser can send two cookies of the same name
 * from different paths, and taking the last would let a cookie set on a
 * narrower path shadow the real one.
 */
export function readCookie(header: string | undefined | null, name: string): string | null {
  if (!header) return null;

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() !== name) continue;

    const value = part.slice(separator + 1).trim();
    return value.length > 0 ? value : null;
  }
  return null;
}
