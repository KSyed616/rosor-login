# @rosor/login

The relying-party half of Rosor sign-in. Applications use this to authenticate
people against TeamDeck's identity provider, per the **Rosor authentication
standard v0.9**, §3.4 and §3.5.

**v0.3.0** covers the flow, the application session, and §3.5’s session check. See
[What is not here yet](#what-is-not-here-yet).

## Why a library

Every application otherwise reimplements §8: cookie attributes, CSRF binding,
inactivity tracking, the five-minute session check. Two implementations drift,
and the drift is invisible until somebody audits both. The rules live here once.

## Installing

Pinned to a tag, straight from git — there is no registry to run and no extra
credential in any build:

```json
{
  "dependencies": {
    "@rosor/login": "github:CuriousTKG/rosor-login#v0.3.0"
  }
}
```

Ships **ESM and CommonJS**. TeamDeck's server is ESM, Inventory's is CommonJS,
and neither has to change.

## Using it

```ts
import { createLoginClient } from '@rosor/login';

const login = createLoginClient({
  issuer: 'https://auth.example.com/api/v1/auth-module/oidc',
  internalIssuer: 'http://provider:3001/api/v1/auth-module/oidc',
  clientId: 'inventory',
  clientSecret: process.env.ROSOR_LOGIN_CLIENT_SECRET!,
  redirectUri: 'https://app.example.com/auth/callback',

  // §3.5. Leave both out and sessions still expire on their own timers, but a
  // revocation never reaches this application — see "What is not here yet".
  sessionReferenceUrl: 'http://provider:3001/api/v1/auth-module/internal/session-reference',
  sessionCheckUrl: 'http://provider:3001/api/v1/auth-module/internal/session-check',
});
```

**Starting a sign-in.** Store all three secrets against the browser — a signed
cookie or a server-side record, not `localStorage`.

```ts
const pending = await login.begin();
await stash(req, {
  state: pending.state,
  nonce: pending.nonce,
  codeVerifier: pending.codeVerifier,
  maxAge: pending.maxAge,
});
res.redirect(pending.url);
```

**The callback.**

```ts
const user = await login.complete({
  code: String(req.query.code),
  state: String(req.query.state),
  expected: await unstash(req),
});
// user.subject, user.email, user.name, user.authTime, user.methods
```

`user.authTime` is when the person actually authenticated, not when the token
was issued. The application session inherits it, so that none outlives the
twelve-hour overall limit (§8.1).

**Before a sensitive action** (§8.1 — payroll approvals, administrator actions,
security settings):

```ts
const pending = await login.begin({ prompt: 'login', maxAge: 900 });
```

Pass `pending.maxAge` back in `expected` and `complete` enforces it. Asking for
re-authentication without checking the answer is theatre, so the check is not
optional.

## Two issuers, and why

`issuer` is public: the `iss` of every token, and where the browser is sent.
`internalIssuer` is the back channel on `rosor_internal`, and is where the code
exchange and key fetches go — §3.4 requires that traffic never pass through a
public hostname. Discovery is read over the internal address and the two
back-channel endpoints are rebased onto it; the authorization endpoint stays
public, which is where a browser genuinely belongs.

The library refuses to start if the provider's discovery document names a
different issuer than the one configured. That is the mix-up case: the
application is talking to a provider it does not think it is talking to, and
every later check would be made against the wrong authority.

## What it refuses

| | |
|---|---|
| A callback whose `state` does not match | **before** redeeming the code |
| A token whose `nonce` is not this request's | minted for another flow |
| A token signed with anything but EdDSA | algorithm confusion |
| A token from another issuer or for another audience | |
| An expired token | 5s clock tolerance, not more |
| A token with no `auth_time` | no session rule could be applied |
| A sign-in older than a requested `max_age` | the provider did not re-authenticate |

`SIGNING_ALG` is a constant, not configuration. A configurable algorithm is a
configurable downgrade.

## Testing

```bash
npm test          # the stub-provider suite: real keys, real signatures
npm run typecheck
npm run build     # ESM + CJS + types
```

The stub provider signs genuine Ed25519 tokens and serves a genuine JWKS. Only
the network is stubbed, because most of what this library does is verify
signatures and a stub returning payload objects would prove none of it.

**Against a real provider**, which is where the surprises are:

```bash
ROSOR_LOGIN_LIVE_ISSUER=http://localhost:3001/api/v1/auth-module/oidc \
ROSOR_LOGIN_LIVE_CLIENT_ID=inventory \
ROSOR_LOGIN_LIVE_CLIENT_SECRET=... \
ROSOR_LOGIN_LIVE_REDIRECT_URI=http://localhost:10000/auth/callback \
  npx vitest run tests/live.test.ts
```

It skips, rather than fails, when no provider is reachable. It cannot complete a
sign-in — that needs a person, a password and an authenticator code — but it
establishes everything on either side: discovery agrees, the keys are readable,
the provider will start a flow for this client, a wrong redirect URI is refused,
and client authentication works. That last one is read from *which* error a
deliberately invalid code returns: `invalid_grant` means the client
authenticated and only the code was bad, where `invalid_client` would mean the
secret or the auth method is wrong.

This suite has already earned itself. It found that TeamDeck advertised an
issuer whose discovery document answered 404 — the provider was mounted at
`/oidc` while its issuer named the parent path. TeamDeck's own client had been
built against the real paths instead of by discovery, so nothing internal
noticed, and every conformant client would have failed at the first request.

## The application session

```ts
import { createSessionManager, verifyCsrf, CSRF_HEADER } from '@rosor/login';

const sessions = createSessionManager({ store, appName: 'inventory' });

// after login.complete(...)
const { cookie, csrfToken, session } = await sessions.start(user);
res.setHeader('Set-Cookie', cookie);   // __Host-inventory_sid

// on every request
const lookup = await sessions.read(req.headers.cookie);
if (lookup.status !== 'active') return res.status(401).json({ error: 'Not signed in' });
```

The browser holds a 256-bit random identifier; the store holds only its
SHA-256. Anyone reading the session table cannot impersonate anybody — a stolen
backup is not a bag of live sessions.

**The cookie** is `__Host-`-prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`,
`Path=/`, with no `Domain` and **no expiry**. That last one is the attribute
most often "fixed" by adding a `Max-Age`: §8.3 wants a browser-session cookie,
and §8.2 forbids cookie expiry from being what enforces a timeout. The server
decides when a session is over.

**Timeouts** are 60 minutes idle (15 for `higherRisk`) and 12 hours absolute,
measured from the identity session's `authTime`, which the application session
inherits — so no application session can outlive the overall limit, however
active somebody has been.

**`read` does not extend a session.** §8.2 counts only requests caused by a user
action, so the caller decides when to `touch`. If reading extended it, a page
left open with a poll on a timer would never time out and the inactivity limit
would be enforced against nobody.

**CSRF and Origin** (§8.4) are both checked, because each covers the other's
gap. A token bound to the session that a cross-site page cannot read; and the
browser's own statement of where the request came from, which script cannot
forge. A write with no `Origin` at all is refused rather than allowed.

```ts
const result = verifyCsrf({
  method: req.method,
  origin: req.headers.origin,
  token: req.headers[CSRF_HEADER],
  session: lookup.session,
  allowedOrigins: ['https://app.example.com'],
});
if (!result.ok) return res.status(403).json({ error: result.reason });
```

`InMemorySessionStore` is for tests and local development — one process, lost
on restart, never purged. A real store is a table with an index on the hash and
another on `identitySessionId`, since §3.5's revocation has to reach every
session of an identity session.

## Activity, and the session check

§8.2 draws one line: activity is a request caused by a **user action**.
Background polling, auto-refresh and socket keep-alives carry
`X-Rosor-Background: 1` and never reset the timer.

```ts
import { countsAsActivity } from '@rosor/login';

const lookup = await sessions.read(req.headers.cookie);
if (lookup.status !== 'active') return res.status(401).json({ error: 'Not signed in' });

const active = countsAsActivity(req.headers);
if (active) await sessions.touch(lookup.session);
```

The marker is **opt-out**. A request is activity unless it says otherwise, so
forgetting the header makes a poll count — annoying, and visible, because
somebody's session stops timing out. The opposite default would log people out
mid-task, which is the failure people work around rather than report.

§3.5's check runs at least every five minutes and before any sensitive action:

```ts
const outcome = await sessions.verify(lookup.session, { active });
if (outcome.status !== 'active') {
  res.setHeader('Set-Cookie', (await sessions.end(req.headers.cookie)).cookie);
  return res.status(401).json({ error: outcome.status });
}
```

It calls the provider only when due, unless you pass `force` — which §3.5
requires before a sensitive action regardless of the timer. A session the
provider no longer recognises is deleted locally, which is the entire point.

**When it cannot confirm, it refuses rather than guessing.** A session with no
provider reference throws `no_session_reference`; an unreachable provider
throws too. Both tempting readings are wrong: "cannot confirm, so end it" signs
out every user of a working application, and "cannot confirm, so allow it"
silently disables §3.5.

## What is not here yet

- The browser-side heartbeat and the "Stay signed in" prompt (§8.1, §8.2)
- Sign-out at the provider, as opposed to locally

### How §3.5 became reachable

For a while it was not. `/internal/session-check` identified a session by the
identity session's own token — the value in the browser's `__Host-rosor_idp`
cookie, which goes nowhere else. It is not on the OIDC interaction result and
the ID token carries no `sid`, so no application could obtain what the endpoint
required, and the one mechanism that carries a revocation outward could not be
exercised by anyone. The endpoint's own tests passed, because they made a token
directly.

The provider now issues a per-client reference instead. Set
**`sessionReferenceUrl`** and the library exchanges the ID token for one during
the callback, on `rosor_internal`; `verify()` then works end to end.

**Configure it, or §3.5 does not run.** Without `sessionReferenceUrl` a session
is created with `sessionId: undefined`, and the first check that falls due
throws `no_session_reference` — five minutes after every sign-in, which is long
enough for tests to pass and short enough to break in front of somebody. If a
deployment cannot use the internal channel, leave `sessionCheck` unconfigured
as well and know what that costs: sessions still expire on their own timers,
but "signed out everywhere" is not true.
