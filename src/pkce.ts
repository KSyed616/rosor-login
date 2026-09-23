/**
 * PKCE, state and nonce — standard v0.9 §3.4.
 *
 * Three different single-use random values, each answering a different
 * question, and it is worth being clear which is which because they are easy
 * to conflate:
 *
 *   code_verifier  proves the party redeeming the code is the party that
 *                  started the flow (RFC 7636)
 *   state          proves the callback belongs to a request this app made,
 *                  and not to one an attacker made in the user's browser (CSRF)
 *   nonce          binds the ID TOKEN to this request, so a token minted for
 *                  some other flow cannot be replayed into this one
 *
 * Losing any one of them loses a distinct property, so the library generates
 * all three and requires all three back.
 */

import { randomBytes, createHash } from 'node:crypto';

/** 32 bytes, base64url. Comfortably inside RFC 7636's 43-128 character range. */
function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

export interface PkcePair {
  /** Kept by the application until the callback. NEVER sent to the browser. */
  verifier: string;
  /** Sent to the provider with the authorization request. */
  challenge: string;
}

/**
 * S256 only.
 *
 * The provider advertises `code_challenge_methods_supported: ["S256"]` and
 * nothing else, and `plain` would make the challenge and the verifier the same
 * string — which is to say, no proof at all.
 */
export function createPkcePair(): PkcePair {
  const verifier = randomToken();
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function createState(): string {
  return randomToken();
}

export function createNonce(): string {
  return randomToken();
}
