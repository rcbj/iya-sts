# debugger/

**The embedded identity protocol debugger (2026-09-13).** The parent project's
browser client and api, served by this process as a feature of it: a listener of
its own, a sign-in through this service's authorization server as one
confidential client, and a gate that admits a console administrator's session
and reads NOTHING ELSE the request carries (#1717, 2026-11-13).

| File | What it is |
|---|---|
| `debugger_server.ts` | The listener's own express app: security headers, the sign-in callback, the landing paths, THE GATE, the forwarder to `/api`, the static site. A socket owner — bound from `server.js`'s `listen()`. |
| `debugger_api_process.ts` | The api as a forked child on a unix socket: the environment it is given, the allow-list, start, restart with backoff, give up, stop. |
| `debugger_access.ts` | Who may use it: `isAdministrator()`, asked by the gate on every request. A library (rule 3). |
| `debugger_admin.ts` | `/admin/debugger`, and the view `GET /admin-api/debugger` answers (rule 7). |
| `web_debugger.ts` | The page's renderer since #446: a `web_` module a browser can load, drawing `/admin/debugger` from that view alone (`admin-ui/CLAUDE.md`, *The static console's renderers*). `debugger_admin.ts` calls it with the view passed through JSON until the console's cutover. |
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
   recommended "administrators and declared applications". Since #1717 there
   is no token a machine client could hold at all: the gate is a person's
   sign-in session.
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

**And a ninth, rcbj's in #1717 (2026-11-13):** the login and the tokens it
produces MUST NOT interfere with debugger operations, so nothing the browser
sends to `/api` may be read, consumed or removed by the gate except this
service's own session cookie — and the UI and its api are one application. He
suggested an OIDC confidential client in the api layer with a session of its
own; the confidential client and the server-side session already existed HERE
(`oidc_rp`'s `debugger` surface), and the question being decided — console
role membership, re-asked per request — is only answerable in this process, so
the sign-in stayed here and the token path was removed instead. The issue
records the reasoning.

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

**AND ONE PRELOAD, WHICH IS THIS SIDE'S AND NOT THE CONTRACT'S (#329,
2026-09-28).** Monitoring → Node Health lists every process of the node with
its `process.memoryUsage()`, which only the process itself can read, and the
api listens for no message — the channel carries `debugger-api-listening` out
and `disconnect` in, nothing else. So `debugger_api_process.ts` forks it with
`--require debugger/debugger_api_status.js` (compiled beside it; left off
where it is not there, so the fork is otherwise unchanged), which answers
`{ type: 'sts-memory-status', id }` on that same channel with the child's
`memoryUsage()`, `cpuUsage()` and uptime; `askMemory(ms)` asks, bounded, and
Node Health falls back to the child's `/proc` row when it gets no answer.
**Nothing is opened**: no socket, no route on the listener, no change to the
gate or the access token; it requires nothing, so this service's
configuration never loads into the api. The debugger project is not edited
for it. It carries no logger — it runs in that project's process — which is
the code style's exemption for code that is not this service's to run.
`tests/debugger_api_process.js` section F holds it.

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

**The credential is the session and nothing else (#1717, 2026-11-13).** The
gate reads this surface's relying-party session from its cookie (`oidc_rp`'s
`sessionFor()`, after `renewal()` has kept its tokens current or ended it) and
asks `isAdministrator()` for the session's person on EVERY request, so a role
revoked after somebody signed in stops working at their next request. It does
not read `Authorization`, `DPoP` or a client certificate, and it holds no
opinion about the access token the session keeps: that token is this client's
own and never leaves this process.

**Why there is no access-token path any more.** Until #1717 the gate took an
access token for the debugger api's permission, on the session or on the
request's own `Authorization` header, and the forwarder stripped that header.
But the debugger sends `Authorization` to its api AS ITS WORK — `/api/userinfo`
forwards a UserInfo Bearer token, `/api/introspection` Basic client
credentials, SCIM and GNAP their own — so the gate read the debugger's traffic
as its own credential (refusing Basic as a malformed token, refusing an IdP's
Bearer token as not ours) and what got through reached the api without the
header the operation needed. `dpop.proofClaims()` on this app reserved the
`jti` of every DPoP proof passing through, so a proof the debugger sent to THIS
service's token endpoint arrived there as a replay. All three are gone: no
token path, no proof reservation, nothing stripped but cookies. The
sender-constraint settings (`oauth2.accessTokenRequireDpop`,
`oauth2.accessTokenRequireMtls`) went with the token path — they constrain a
token PRESENTED, and nothing is presented here now.

**Forwarding drops Cookie** (the api must not hold an administrator's session)
and **passes `Authorization` and `DPoP` through untouched**, adds
`X-Forwarded-Proto`/`-Host`/`-Prefix: /api`, drops the api's `Set-Cookie` and
CORS headers, and rewrites a `Location` naming the child's configured origin to
the one this request arrived at — so a SAML landing redirects to the host the
browser is using.

## The listener ASKS for a client certificate (#34, 2026-09-15)

`https.createServer()` gets `requestCert: true` with `rejectUnauthorized:
false` over `tlsServer.clientTruststoreOptions()` — exactly the posture the main
port takes, so the handshake succeeds either way. It was added so a
certificate-bound access token could be presented here; since #1717 no token
is, and the request is kept only because the listener's TLS is the main port's
and tlsfuzzer holds it to that (#212): `clientTruststoreOptions()` carries
`tls_server.js`'s whole `protocolOptions()` — the floor, the ciphers and the
groups, the signature algorithms, the renegotiation refusal, and through
`trustClientCertificatesOn()` the guard that closes a client certificate whose
EC key is on a curve other than P-256/P-384/P-521 (`tls/CLAUDE.md`). No test
stack binds this listener, so `tests/tlsfuzzer_debugger.js` binds it over TLS
in process, with a stand-in site and the api child's start stubbed, and runs
the stack job's plan against it.

**The debugger client is CONFIGURED, not exempted.** `sts-debugger-ui` is not
on `sender_constraints.js`'s `MTLS_EXEMPT_CLIENTS` — that list is the two
hosted surfaces, which redeem over a loopback call from this process to itself
— and an operator who makes a realm strict is expected to make its client match
rather than to discover a hole shaped like a debugger.

## One application (#1717)

**The UI and its api are one client, `sts-debugger-ui`**, seeded in the default
realm of every install (#541), confidential (`private_key_jwt`), asking for
`openid profile email offline_access` with global consent. Until #1717 there
were two — `sts-debugger-api`, a resource server defining
`urn:sts:debugger-api:debugger`, and the client holding a grant of it — and
`narrowScope()` took the permission off any grant to a non-administrator at
issuance. With no token path there is nothing for a permission to admit to, so
the resource row, the permission, `narrowScope()` and the scope policy's
protection of it are gone. The id stayed `sts-debugger-ui` so registrations,
grants and sessions an install already holds survive.
`applications.retireDebuggerApiApplication()`, run by the default realm's seed,
deletes a SEEDED `sts-debugger-api` row and takes the permission off a SEEDED
client's grant, consent and declaration; a row an operator made or edited by
hand under either name is left alone. The nine error codes only the token path
emitted (`STS-DBG-0003`..`0008`, `0030`..`0032`) are retired, not reused.

## Who may use it — `debugger_access.ts`

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
This module is handed the session's user name and not how it signed in, so it
refuses that account the debugger until the claim (`STS-DBG-0033`, `claimPending` from `rolesOf()`), and the page says to sign in
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

**Anybody may complete the sign-in; only an administrator gets past the gate.**
Nothing is narrowed at issuance any more (#1717): a non-administrator who signs
in through `sts-debugger-ui` holds an ID Token and a session that admit them to
nothing, and the gate draws "the debugger is for administrators", with a
sign-out, rather than an error from a flow the person did nothing wrong in. The
session is the default realm's, so a person in `acme` who shares an
administrator's name is somebody else.

**The seeded entry carries `oauthGlobalConsent` for its scopes**, the console's
reason: a question with one sensible answer in front of every sign-in.

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

* In process: `tests/debugger_access.js` and `tests/debugger_server.js` — the
  latter, since #1717, with real relying-party sessions, an `Authorization`
  header that opens nothing, and `Authorization` and `DPoP` reaching the
  stand-in api unchanged.
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
* (That 2026-09-13 run predates #1717; its token-path findings — the
  permission taken off a `client_credentials` grant, the audience case — are
  about code that no longer exists.)
* **The image**: built with `--build-arg DEBUGGER_IMAGE=` the debugger project's
  embedded image, run with its ports moved, and the listener and api child
  started under node 24.16.0.

## Not done, said plainly

* **No over-HTTP job** in `tests/protocol/` drives the full browser sign-in
  through a real embedded tree, because no launcher yet builds the debugger
  image; the parent project's own suite still runs against its standalone client
  and api.
* **A docker port mapping whose host and container numbers differ breaks the
  sign-in** unless `global.publicBaseUrl` is pinned: the authorization base is the
  browser's host on the MAIN PORT the process knows, which is the container's.
* **Dispatch mode is not verified** end to end (see the `oidc_rp.js` section).
* **No `/admin/sts-metadata` card**: the listener registers no route on the main
  router; its description is in the `/admin/debugger` row there.
