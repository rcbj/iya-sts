# debugger/

**The embedded identity protocol debugger (2026-09-13).** The parent project's
browser client and api, served by this process as a feature of it: a listener of
its own, a sign-in through this service's authorization server, and an api
behind an access token only a console administrator is issued.

| File | What it is |
|---|---|
| `debugger_server.ts` | The listener's own express app: security headers, the sign-in callback, the landing paths, THE GATE, the forwarder to `/api`, the static site. A socket owner — bound from `server.js`'s `listen()`. |
| `debugger_api_process.ts` | The api as a forked child on a unix socket: the environment it is given, the allow-list, start, restart with backoff, give up, stop. |
| `debugger_access.ts` | Who may use it: `narrowScope()` at issuance and `isAdministrator()` at the gate. A library (rule 3). |
| `debugger_admin.ts` | `/admin/debugger`, and the view `GET /admin-api/debugger` answers (rule 7). |
| `embedded/` | **Not source.** The debugger project's embedded build output, gitignored and dockerignored — see *Where the built tree comes from*. |

## The eight decisions, and they were rcbj's

Asked with AskUserQuestion before anything was written; each took the
recommended answer except where noted. They are the design, and a change to
any of them is a change of design rather than a refactor.

1. **Its own listener and origin** (`debugger.port`, 8444), not `/debugger` on
   8081. The debugger's 52 pages carry inline `<script>` blocks and `on*=`
   handlers and render tokens and assertions from any identity provider. On
   the console's origin a flaw in either is a script that can drive the
   console with an administrator's cookies. On its own origin, `script-src
   'unsafe-inline'` is tolerable and every root-relative `/js`, `/css` and
   `window.location` in those pages works unedited.
2. **The api is a forked child**, not mounted in-process. The debugger is
   Express 5 and this service Express 4; this service reads every request body
   as text before any route; the api installs interceptors on a shared axios,
   sets `global.DOMParser`, reads `CONFIG_FILE`, keeps state in memory. Forked,
   none of that is anything — and a crash or hang there is a 502 on `/api`
   rather than an identity provider that stopped answering.
3. **The gate is always on.** No setting, no mode. The api dials what its
   caller names — token endpoints, KDCs, directories, TLS handshakes, gRPC.
4. **People only, console administrators only** — rcbj chose this over the
   recommended "administrators and declared applications". No
   `client_credentials` token ever carries the permission.
5. **The parent repo was edited** on `feature/embed-in-mock-sts`, additively:
   its standalone deployment is unchanged.
6. **The image takes the built tree from an image** (`COPY --from`), not a
   second build context (this machine's docker has no BuildKit) and not a
   submodule (this repository is already a submodule of that one).
7. **Enabled by default in development, off in product** — `debugger.enabled`
   `auto`, `mode.embedsProtocolDebugger()`.
8. **In product the api may dial ONLY this service** — rcbj chose this over
   the recommended "public addresses and this service". Plus
   `debugger.allowedDestinations`.

## The contract with the debugger project

It is written down over there in `embedded/CLAUDE.md` and this is the half this
side relies on. Everything crosses as environment variables and one IPC message,
never as a `require`:

| This side sets | Meaning |
|---|---|
| `CONFIG_FILE` | the api tree's own `env/embedded.js` |
| `DEBUGGER_LISTEN_SOCKET` | bind plain HTTP here, mode 0600, and send `{ type: 'debugger-api-listening' }` |
| `DEBUGGER_UI_URL` | the debugger origin (`debugger.publicBaseUrl`, or `https://localhost:<port>`) |
| `DEBUGGER_ALLOWED_ADDRESS_RANGES` | JSON list; non-empty is ALLOW-LIST mode in the api's address guard, which covers its raw relays too, and an allow-list with no usable entry refuses everything |
| `DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS` | `false` in development, `true` in product |
| `NODE_EXTRA_CA_CERTS` | this service's trust anchor, so the api can dial the main port over TLS |

And in the other direction: **every served `.html` and `.js` has the literal
`__STS_EMBED_STS_URL__` replaced** with this service's authorization base (the
same host the browser used, on the main port, or `global.publicBaseUrl`) — the
embedded build's prefills for its own issuer, SCIM, SPIFFE and WS-Trust URLs.
The `uiUrl` and `apiUrl` bundles need are `window.location.origin`, computed in
the browser.

**The environment is BUILT, not inherited.** PATH, HOME, LANG, TZ and the table
above. This process's environment holds a deployment's secrets; a child whose
job is making requests a caller describes holds none of them.

## The gate, and why each exemption passes the test

A request meets, in order: the security headers; `GET /_sts/callback` (ungated
— somebody arriving there has no session yet, which is `/admin/callback`'s
argument); FOUR LANDING PATHS; the gate; then `/api/*` forwarded, `/_sts/`
(account and sign-out), and the static site.

**The landing paths are `/callback`, and at the api `/samlacs`, `/samlslo`,
`/wsfed` (GET and POST) and `POST /ssf/receiver/{id}`.** Three of them receive a
cross-site form POST from an identity provider, and a `SameSite=Lax` cookie is
not sent on one — so gated they could only ever refuse. None dials anything a
request names: each stashes what arrived and redirects to a gated page, or
appends to an inbox a gated call created. The check MOVED — to the gated read
of what was stashed — which is the test `/admin/signals/receive`'s exemption
set, and a sixth landing needs that argument made again. **`isLanding()` matches
method AND path**, so reading an inbox or deleting one is gated.

**The token is verified in `/admin-api`'s order** (RFC 9068 section 4): the
DEFAULT realm's key, expiry, `typ at+jwt`, issuer (this service's default
authorization server at the request's authorization base or the pinned one),
audience `urn:sts:debugger-api:`, scope `debugger` — then
`isAdministrator()` AGAIN, so a role revoked after the token was minted stops
working before it expires. The session path verifies the session's own access
token the same way.

**Forwarding drops Cookie and Authorization** (the api must not hold an
administrator's session or token), adds `X-Forwarded-Proto`/`-Host`/`-Prefix:
/api`, drops the api's `Set-Cookie` and CORS headers, and rewrites a `Location`
naming the child's configured origin to the one this request arrived at — so a
SAML landing redirects to the host the browser is using.

## The listener ASKS for a client certificate, and the gate reads both schemes (#34, 2026-09-15)

Four changes, and only the third is one of #34's settings.

**The listener asks for a client certificate and requires none.**
`https.createServer()` gets `requestCert: true` with `rejectUnauthorized:
false` over `tlsServer.clientTruststoreOptions()` — exactly the posture the main
port takes (and 8443 took, until it was deleted on 2026-09-16 for being a second
socket with it), so the handshake succeeds either way and what a certificate
is worth is decided per request against the truststore. It was added because
`oauth2.accessTokenRequireMtls` covers this listener, and **a listener that
never asks makes a certificate-bound token impossible to present here rather
than merely unusual** — which would have been an exemption dressed up as a
refusal. `trustClientCertificatesOn()` was already registered for the leaf
`build-root` replaces; it now keeps the ANCHORS current too.

**The listener's TLS is the main port's, and tlsfuzzer holds it (#212).**
`clientTruststoreOptions()` carries `tls_server.js`'s whole `protocolOptions()`:
- the floor, the ciphers and the groups;
- the signature algorithms;
- the renegotiation refusal;
- through `trustClientCertificatesOn()`, the guard that closes a client
  certificate node cannot read. A brainpool certificate crashes node 24.16.0
  in `getPeerCertificate()` (`tls/CLAUDE.md`).

No test stack binds this listener, so `tests/tlsfuzzer_debugger.js` binds it
over TLS in process, with a stand-in site and the api child's start stubbed,
and runs the stack job's plan against it.

**A DPoP-bound token presented as a Bearer token is refused, in every mode.**
The gate had been given RFC 8705's `cnf["x5t#S256"]` check (`STS-DBG-0030`) and
never RFC 9449's, so a token carrying `cnf.jkt` — a token whose whole point is
that holding it is not enough — was accepted here as a bearer token. It is
`STS-DBG-0031` now, and a proof that fails with no code of its own is
`STS-DBG-0032`. This is not one of the settings: it is about honouring a
constraint the TOKEN already carries, so it runs whatever they say. **The same
hole `/admin-api` carried, closed the same way** — `mgmt-api/CLAUDE.md`, and
`oauth-oidc/CLAUDE.md` 3ao.

**`presentedTokenOf()` reads `Bearer` AND `DPoP`.** `bearerOf()` matched
`Bearer` alone, so a client doing the stricter thing was told it had presented
no token at all, which is the least useful answer available. `bearerOf()` is
kept as a wrapper over it; the scheme is carried beside the token because
refusing a BOUND token sent as Bearer is a different refusal from a token that
does not verify.

**`oauth2.accessTokenRequireDpop` and `oauth2.accessTokenRequireMtls` are
honoured here**, through the same `senderConstraints.accessTokenRefusal()` every
other surface asks, so an operator who turns one on cannot find that one door
out of nine kept its own opinion. The refusal's own code (one of
`STS-OAUTH-0527..0531`) is carried on the verdict and marked by `refuse()`.

**`dpop.proofClaims()` runs on this app**, registered below `inDefaultRealm`
(the reservation is per realm and this listener's realm is the default one) and
above the gate (which is what verifies the proof). It is the same middleware
`oauth2.js` registers on the main app: the proof's `jti` is reserved on arrival
and given back unless the proof was accepted, so a proof replayed against a
second node is refused there too.

**The session path is deliberately exempt from all of it.**
`verifyAccessToken()` takes `presented`, true only when the token came in on
THIS request's
`Authorization` header; the relying party's own session holds an access token
that nobody sent, and **a token nobody sent cannot prove possession of anything
on a request it was not part of**. Requiring it to would turn the two settings
into "the debugger's sign-in stops working", which is not what either of them
says. The session's token is still verified in `/admin-api`'s order, and
`isAdministrator()` is still asked again.

**And the debugger client is CONFIGURED, not exempted.** `sts-debugger-ui` is
not on `sender_constraints.js`'s `MTLS_EXEMPT_CLIENTS` — that list is the two
hosted surfaces, which redeem over a loopback call from this process to itself —
and because #34's own sixth decision was that the embedded debugger is an
ordinary client of this authorization server: an operator who makes a realm
strict is expected to make its client match rather than to discover a hole
shaped like a debugger.

## Why the permission's base is a URN

`applications.js` joins a resource's `oauthPermissionBaseUri` and a name into the
scope a client asks for, and that base becomes the token's `aud`. An ADDRESS
base would make the permission depend on the host name the debugger was reached
by — `localhost` and `127.0.0.1` would be two permissions and one would match
nothing. `urn:sts:debugger-api:` is the same everywhere. It is written out in
THREE files — `debugger_access.ts`, `common/applications.js`'s seed and
`common/oidc_rp.ts`'s surface — because the latter two are libraries every module
reads and must not require a feature directory; `tests/debugger_access.js`
compares them.

## Who may hold it — `debugger_access.ts`

**Administrator means a MEMBER of what the console means**: `admin_rbac.rolesOf()`
in the DEFAULT realm, either role — **and the empty-roster rule is NOT honoured**
(rcbj, 2026-09-13, reversing the first version, which matched the console).
`admin.openWhenEmpty` gives everybody who signs in both roles until the bootstrap
administrator first signs in (or, with none seeded, while neither group has a
member), so that the first grant can be made on the console; the debugger needs no
such bootstrap, so a role held only because nobody holds one is refused with
`STS-DBG-0024` and the debugger stays shut until somebody really is in a group.
That check runs BEFORE the role test, which everybody would otherwise pass. The
console and the debugger therefore disagree in exactly one state, on purpose, and
the "not an administrator" page says which state it is and where to grant a role.
**Since 2026-09-22 (#103) that state exists in development only** — product
never opens the window — **and product adds one more refusal the console makes
too**: until the bootstrap administrator has claimed the console with its
password, its roles are honoured at the console alone, from a password session.
This module sees a name (at issuance) or a token's claims (at the gate) and
never the session, so it refuses that account the permission until the claim
(`STS-DBG-0033`, `claimPending` from `rolesOf()`), and the page says to sign in
to `/admin` with the password first. A partner asserting `admin` is the case it
stops. `tests/console_bootstrap_product.js` holds it.
`tests/debugger_access.js` asserts it against the console's own answer (open,
Admin Write) and `tests/debugger_server.js` at the gate; removing the check fails
three assertions. **The policy is asked as well, never
instead**: a subject with neither role is refused BEFORE `access_gate.check()`
under `RESOURCE.DEBUGGER`, because that function answers "allowed" when no XACML
decider is loaded or `xacml.enforceAccess` is off, and a relay must not open
because a policy subsystem was switched off. `tests/debugger_access.js` section C
runs with no decider for exactly that reason.

**`narrowScope()` is asked at the two places a scope is granted** —
`issueAuthorizationResponse()` before a code carries it, and `tokenSet()`, which
every grant mints through, as the backstop. TAKEN OFF, not refused (RFC 6749
section 3.3); the debugger's gate then draws "the debugger is for
administrators" rather than an error from a flow the person did nothing wrong
in. In any realm but the default one it is taken off whoever asks — a person in
`acme` who shares an administrator's name is somebody else.

**The seeded entries carry `oauthGlobalConsent` for the permission**, the
console's reason: a question with one sensible answer in front of every sign-in.

## `oidc_rp.js` grew a surface that is not on this origin

The `debugger` surface is the first whose redirect URI and authorization
endpoint are on DIFFERENT origins, so `beginSignIn()` and `handleCallback()`
take `callbackBase` and `authorizationBase` options, and the back channel's
Host header is the authorization base's — the issuer the browser was sent to.
Both realms are the default realm's. **`poolPin`** carries the browser's
`sts_pool` cookie (a cookie is scoped to a host, not a port) into the back
channel from the front process, so under request dispatch the token request
reaches the worker that minted the code. **What is NOT verified under dispatch**
is the parent sign-on session lookup, which happens in the front process while
the session was minted in a worker and arrives by replication; see *Not done*.

## A new trust anchor replaces the child

The api trusts this service's main port through `NODE_EXTRA_CA_CERTS`, which node
reads once at start — so `build-root` on `/admin/pki` left a running child trusting
a Root that is gone, and every call it made to this service failed. Nothing inside
the child can be told, so `debugger_server.ts`'s `checkAnchor()` compares, at most
every five seconds and only on a forwarded call, the anchor `tls_server.js`
publishes now with the one the child was started with, and
`debugger_api_process.ts`'s `updateAnchor()` writes the new PEM and replaces the
child. **A replacement is a hand-over, not a failure**: it is not counted toward
`debugger.restartLimit`, the successor is forked at once, and the child is
not-ready from the moment it is told to exit, so the call that noticed gets the
ordinary 502 rather than being sent to a dying process. Verified against an
isolated instance: a token call from the api to the main port worked, `build-root`
was posted, the next `/api` call answered 502, and the same token call worked
within seconds. `tests/debugger_api_process.js` holds it with a stand-in child
(four mutants, all caught).

## Front process only

The listener, the child and the status are held by the front process.
`common/request_pool.js`'s `NEVER_DISPATCHED` pins `/admin/debugger` and
`/admin-api/debugger`, whose answers in a worker would report a listener that
never bound. A request worker never forks the api (`STS_REQUEST_WORKER`). The
api keeps SAML exchanges and SSF inboxes in memory, so there is ONE child —
the rule `common/CLAUDE.md` states about anything that is not a row in a store.

## Where the built tree comes from

* **A checkout:** `embedded/build.sh --out ../iya-sts/debugger/embedded` in the
  debugger project.
* **The image:** the Dockerfile's `ARG DEBUGGER_IMAGE` (default the empty stage
  `debugger-none`) and `COPY --from=debugger /debugger/ ./debugger/embedded/`.
  `docker-compose.yml` passes `DEBUGGER_IMAGE`. The indirection through a stage
  name is what makes "no debugger" a successful classic-builder build.

A missing tree is `STS-DBG-0015`, logged and shown on `/admin/debugger`, and
costs the rest of the service nothing.

## What was verified, and how

* In process: `tests/debugger_access.js` and `tests/debugger_server.js`.
* **By hand, against an isolated `node server.js` with a real embedded tree
  (2026-09-13)**: a console administrator signed in through the real sign-in
  screen and landed on the debugger; `/api/healthcheck`, `/api/tls/limits` and a
  proxied `/api/token` to the main port over TLS (the anchor handed down
  worked); a `client_credentials` request naming the permission came back
  without it and its token was refused 403; after the roster was made non-empty
  a second person was shown *The debugger is for administrators* and refused at
  `/api`; sign-out ended both sessions and `/api` answered 401. The socket
  directory was gone after the process stopped. The vendored `sts_metadata.js`
  and `admin_api.js` jobs passed against that instance.
* **That run found the gate's audience case**: when the permission is taken off,
  the token's AUDIENCE changes first, so `STS-DBG-0007` — not only `0008` — is
  what "signed in and not an administrator" arrives as.
* **The image**: built with `--build-arg DEBUGGER_IMAGE=` the debugger project's
  embedded image, run with its ports moved, and the listener and api child
  started under node 24.16.0.

## Not done, said plainly

* **No over-HTTP job** in `tests/vendored/` drives the full browser sign-in
  through a real embedded tree, because no launcher yet builds the debugger
  image; the parent project's own suite still runs against its standalone client
  and api.
* **A docker port mapping whose host and container numbers differ breaks the
  sign-in** unless `global.publicBaseUrl` is pinned: the authorization base is the
  browser's host on the MAIN PORT the process knows, which is the container's.
* **Dispatch mode is not verified** end to end (see the `oidc_rp.js` section).
* **No `/admin/sts-metadata` card**: the listener registers no route on the main
  router; its description is in the `/admin/debugger` row there.
