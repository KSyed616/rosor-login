/**
 * The provider's public keys, fetched over the back channel.
 *
 * WHY NOT jose's createRemoteJWKSet. It fetches with its own client, which
 * cannot be given the `fetch` this library was constructed with. That is not a
 * testing inconvenience, it is a correctness problem: §3.4 puts back-channel
 * traffic on `rosor_internal`, and an application that routes outbound calls
 * through its own agent would have every other request honour that while its
 * key fetches quietly went somewhere else. All egress goes through one place
 * here, so there is one answer to "where does this library talk to".
 *
 * That means owning the caching, which is the part createRemoteJWKSet was
 * providing:
 *
 *   - Keys are cached, because fetching them per token would make every
 *     sign-in wait on a second round trip.
 *   - An UNKNOWN key id triggers exactly one refetch, because that is what a
 *     provider key rotation looks like from here and a rotation should not
 *     require restarting every application.
 *   - That refetch is rate-limited. Without a cooldown, a stream of tokens
 *     carrying invented key ids would be a way to make this application
 *     hammer the provider on demand.
 */

import { createLocalJWKSet } from 'jose';
import type { FlattenedJWSInput, JSONWebKeySet, JWSHeaderParameters, KeyLike } from 'jose';
import { RosorLoginProviderError } from './discovery.js';

/** Re-read the keys this often even when nothing has failed. */
const CACHE_MAX_AGE_MS = 10 * 60 * 1000;

/** The shortest gap between two fetches prompted by an unknown key id. */
const REFETCH_COOLDOWN_MS = 30 * 1000;

export type KeyResolver = (
  protectedHeader?: JWSHeaderParameters,
  token?: FlattenedJWSInput,
) => Promise<KeyLike | Uint8Array>;

export function createJwksResolver(uri: string, fetchImpl: typeof fetch): KeyResolver {
  let keys: JSONWebKeySet | null = null;
  let fetchedAt = 0;
  let inflight: Promise<void> | null = null;

  async function refresh(): Promise<void> {
    // One fetch at a time. A burst of sign-ins on a cold cache should cost the
    // provider one request, not one per sign-in.
    if (inflight) return inflight;

    inflight = (async () => {
      let response: Response;
      try {
        response = await fetchImpl(uri, { headers: { Accept: 'application/json' } });
      } catch (error) {
        throw new RosorLoginProviderError(
          `Could not fetch the provider's keys from ${uri}: ${(error as Error).message}`,
        );
      }
      if (!response.ok) {
        throw new RosorLoginProviderError(
          `The provider's JWKS endpoint at ${uri} answered HTTP ${response.status}.`,
        );
      }
      const body = (await response.json().catch(() => null)) as JSONWebKeySet | null;
      if (!body || !Array.isArray(body.keys)) {
        throw new RosorLoginProviderError(`The provider's JWKS at ${uri} is not a key set.`);
      }
      keys = body;
      fetchedAt = Date.now();
    })();

    try {
      await inflight;
    } finally {
      inflight = null;
    }
  }

  return async function resolve(protectedHeader, token) {
    if (!keys || Date.now() - fetchedAt > CACHE_MAX_AGE_MS) {
      await refresh();
    }

    try {
      return await createLocalJWKSet(keys!)(protectedHeader, token);
    } catch (error) {
      // No key matched. Either the provider rotated, or the token is naming a
      // key that has never existed. One refetch tells the two apart.
      if (Date.now() - fetchedAt < REFETCH_COOLDOWN_MS) throw error;
      await refresh();
      return createLocalJWKSet(keys!)(protectedHeader, token);
    }
  };
}
