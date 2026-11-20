# companion/ — the development-only companion (#594)

**Not part of the service.** A second container that plays the click-through
demonstrations a PERSON uses — and that the embedded debugger points a person
at — in front of iya-sts, as an outside party. rcbj's decision 1 on #591: the
demonstrations move out of the runtime into a development-only companion,
like the test peer (#586, `tests/peer/`) but for people rather than jobs, and
the service ships none of them. The service's own `Dockerfile` removes this
directory from its copy of the tree (`rm -rf … ./companion`), and the
companion is built from this directory alone (`context: ./companion`), so
nothing crosses in either direction.

`docs/v1.1.0/docker-compose.md` (*The companion*) is how a user starts it; this file
is why it is shaped the way it is.

## What it is

| File | What |
|---|---|
| `companion.js` | The shell: configuration from the environment, the bounded session store, the router every demonstration mounts on, `/`, `/companion.css`, `/healthz`, and the listener |
| `companion_util.js` | The logger, the one page layout and its policy, cookies, bodies, answers |
| `sts_client.js` | The ONE door into the service, and the only module that knows how |
| `demo_oid4vc.js` | The OpenID4VC demonstration: `/issuer`, `/issuer/offer`, `/verifier`, `POST /verifier/start`, `/verifier/wait`, `/verifier/done` |
| `demo_kerberos.js` | The Kerberos and SPNEGO demonstration (#595): `/spnego`, `/spnego/protected`, `/krb5/service`, and the protected TCP service on `COMPANION_KRB5_SERVICE_PORT` (8888) |
| `krb5_error.js` | The one Kerberos message the companion writes itself: the KRB-ERROR its TCP service answers a refusal with |
| `social_idps.js` | A dummy of each of the 39 named social providers (#1689), at `/social/{id}` |
| `pep_app.js` | The application the remote XACML PEP protects as a reverse proxy (#1760), at `/pep-app`: every page echoes what reached it as JSON |
| `pep_app_identity.js` | What `/pep-app` reads of the identity the proxy forwards (#1760, D11): a Bearer JWT decoded and checked, and the application's SAML ACS |

Node built-ins, `bunyan`, `qrcode`, `kerberos`, and since #1760 `xml-crypto`
and `@xmldom/xmldom` (the ACS's XML signature check, at the versions the
service uses, required lazily), pinned and installed from
the committed lockfile. Plain JavaScript and no build of its own: the
service's TypeScript conversion (#50) is about the service. `kerberos` is a
native module, built from source in the image's first stage against Debian's
MIT headers (no prebuilt binary is downloaded), and the final stage carries
only `libgssapi-krb5-2`.

**A DEMONSTRATION IS A MODULE WITH `describe()` AND `mount(router)`**, and a
line in `companion.js`'s `this.demos`; one with a socket of its own has an
optional `listen()`, which `Companion.listen()` calls once the pages listen —
where the service starts its own sockets and for the same reason: a bind can
fail, and a require must not. `demo_kerberos.js` (#595) is the second
demonstration and the first with a socket; a failed bind is recorded and
shown on `/krb5/service`, and the pages go on.

## How it reaches the service — as anybody would

**It requires no module of the service.** It reads what any party may read
(`/.well-known/openid-credential-issuer`) and does everything else through
`/admin-api`, holding an access token like any other client of that API:
`client_credentials`, `admin:read admin:write`, the API's base as the RFC 8707
`resource`, its own secret by `client_secret_basic`. `mgmt-api/CLAUDE.md`
argues why that needs both a declaration and role membership (an application
holds ADMIN_READ and ADMIN_WRITE by being a member).

**Its own client, or it registers itself.** `COMPANION_CLIENT_ID` /
`COMPANION_CLIENT_SECRET` name an application an operator registered.
Without them, `COMPANION_BOOTSTRAP_SECRET` — the seeded `sts-api-client`'s
secret (`sts-management-api`'s until #1139), the `ADMIN_API_CLIENT_SECRET` a stack pins — is used for
exactly three calls: create the `iya-sts-companion` application (declaring
the two scopes and listing the completion page as a redirect URI), add it to
the two roles, or after a restart mint it a new secret
(`regenerate-secret`), since the companion keeps nothing. From then on only
its own credentials are used. The registration is asked for at the first
request that needs the service, not at start, so a companion that came up
before the service does not fail; a failure is retried at the next request.

**Two URLs for the service.** `COMPANION_STS_URL` is where it DIALS
(`https://sts:8081` on the compose network); `COMPANION_STS_PUBLIC_URL` is
where a browser and a wallet reach it (`https://localhost:8081`, a realm's
prefix included). Every request is dialled at the first and carries the
second's host as its `Host`, because the service builds the addresses it
hands out — the Response URI, the `request_uri`, `/admin-api`'s audience —
from the request (`helpers.baseUrlOf()`), and the wallet has to reach them.

**TLS.** Verified against `COMPANION_STS_CA_FILE` when it is given. A
development stack makes its service Root when it starts, so no image can hold
the anchor: `COMPANION_STS_TLS_INSECURE=true` turns the check off, as the
remote PEP's `PEP_TLS_INSECURE` does, and the start logs a warning. The test
peer has no such switch because a job that proves TLS must not dial
anything; a person clicking through a demonstration on a laptop is the other
case.

## The two decisions #594 asked for

**THE OFFER: THE COMPANION MAKES THE ONE THAT AUTHORIZES NOTHING, AND SENDS A
PERSON TO THE PORTAL FOR THE ONE THAT DOES.** A pre-authorized code IS the
authorization for a credential about the person it names, so only somebody
who knows who that is may make one. rcbj's decision on #587 is that this is
the person's own self-service — `/portal/wallet` (#589) — and the companion is
not that person and holds no token of theirs; an `/admin-api` operation that
let an application mint pre-authorized codes for anybody would be exactly the
`oid4vci.offerUsername` test control #591 is removing, with a new door. What a
third-party issuer site can honestly make is the same-device offer: the
issuer, the configuration, and the authorization code grant with no
`issuer_state` (OpenID4VCI 1.0 section 4.1.1 makes it optional), so the
wallet signs the person in at the service's `/oauth2/authorize`. That is
what `/issuer/offer` here makes, by value, with an SVG QR code of the same
URI for a wallet on another device.

**THE COMPLETION PAGE: THE STARTER NAMES IT.** OpenID4VP 1.0 section 8.2: the
Response Endpoint MAY answer a `redirect_uri`, and the wallet sends the
browser there. The service named its own `/oid4vp/done?state=…` for every
verification — a demonstration page a product realm did not serve, so a
product verification sent the person to a 404. Since #594 `POST
/admin-api/verifications/start` takes `redirect_uri`: the starter's own page,
held where only registered addresses are accepted to the CALLING CLIENT's
registered redirect URIs (`applications.clientConfigOf()`, the register the
authorization endpoint holds return addresses to), matched whole, and refused
`STS-VC-0123` otherwise; a start that names none is answered with no
`redirect_uri` at all, which is what a cross-device wallet wants. The wire
format is unchanged otherwise: the 200 JSON body, with or without the
member. The alternative — the companion's page as a setting of the service —
would have put a demonstration's address back into the runtime.

The companion names `/verifier/done` for a same-device start and nothing for
another device (no browser waits for the wallet there; the QR page polls with
a `<meta>` refresh instead).

**THE VERDICT IS SHOWN ONLY TO THE BROWSER THAT STARTED IT.** The companion
keeps the verification's `state` in the browser's session and never puts it
in a URL, so `/verifier/done` opened anywhere else shows nothing — the
session fixation OpenID4VP section 13.3 warns of, handled by the party that
owns the page. (The service does not append a `response_code` to a starter's
page: binding the result to the browser is the starter's job, and the
companion does it with its cookie.)

## The Kerberos demonstration (#595)

rcbj's decision 1 on #591 moved the service's `/spnego`, `/spnego/protected`,
`/krb5/service` and the protected TCP service (`krb5.servicePort`) here. The
service's versions were answered by the service's own acceptor with a key the
service held for itself; here they are **a Kerberos service like any
customer's**:

* **ITS OWN PRINCIPAL AND KEYTAB, FROM THE KDC'S OPERATOR DOOR.**
  `COMPANION_KRB5_SPN`, by default `HTTP/<the host of COMPANION_PUBLIC_URL>`
  — the name a browser and `curl` derive from the URL. `sts_client.js`'s
  `serviceKeytab()` asks `POST /admin-api/kerberos/principals/create-service`
  (Admin Write, which the companion holds) for a random key and its MIT
  keytab, handed over once; refused (the principal holds a stored key from an
  earlier start, and the companion keeps nothing), it asks `rotate-service`,
  whose keytab carries the version it replaced for a ticket already issued
  under it. The keytab is written 0600 to a fresh temporary directory
  (`COMPANION_KRB5_KEYTAB_DIR`) and named to MIT as `KRB5_KTNAME`. It is
  asked for at the first request that needs it, and again after a failure,
  for the registration's reason: a companion that came up first does not fail.
* **MIT KERBEROS IS THE ACCEPTOR — DECIDED AGAINST PORTING ONE.** The `kerberos`
  package (MongoDB's, Apache-2.0) is a thin N-API binding over
  `gss_accept_sec_context()`; the companion calls `initializeServer('')`
  (GSS_C_NO_CREDENTIAL: any principal the keytab holds — its one) and
  `step()` once per request. The alternative was an acceptor ported from the
  service's `krb5_service.js`, or the parent project's codec copied in as
  vendored code; either would be the service agreeing with itself, which is
  how its KDC once shipped advertising no PA-ENC-TIMESTAMP with every test
  green (`kerberos/CLAUDE.md`). MIT checks what an acceptor checks — the
  ticket under the keytab's key and kvno, the Authenticator, the clock, its
  replay cache (`/var/tmp`), the GSS checksum — answers SPNEGO and the bare
  Kerberos mechanism both, and so exercises the KDC as `mod_auth_gssapi`, a
  JVM or a Windows service would. **It is required lazily**, so the pages and
  `tests/companion.js` (whose tests image has no MIT libraries) load without
  it; `deps.gss` is its stand-in there.
* **WHAT IT DOES NOT HAVE.** The service's pages drew its own acceptor's
  per-check table and took three knobs (`?mic=require`, `?mech=none`,
  `?mutual=off`); both were properties of an acceptor the service wrote.
  MIT's says whether the context was established and, if not, why in one
  sentence — what a real operator sees — and takes no knobs. A context is
  one request: a ticket's exchange completes in one round trip and nothing is
  kept between requests. The negotiation's own diagnostics stay in the
  service, at `/authn/spnego`. In development that door honours
  `?mutual=off`: it accepts the ticket, withholds the AP-REP and starts no
  session (#896). This acceptor still takes no such knob.
* **THE TCP SERVICE** speaks the framing the service's did: a 4-byte length,
  then a GSS InitialContextToken carrying an AP-REQ (RFC 4121 section 4.1).
  Accepted with mutual authentication, the GSS-wrapped AP-REP goes back;
  accepted without, the connection is closed cleanly; refused, a KRB-ERROR —
  which the binding does not hand over (it keeps MIT's error token and gives
  back MIT's message), so `krb5_error.js` writes one: the code read off MIT's
  message (`KRB_AP_ERR_SKEW`, `_REPEAT`, `_NOKEY`, … else `KRB_ERR_GENERIC`),
  the message as the e-text. More than 64 KiB, or a length with the reserved
  bit, closes the connection.
* **TWO SERVICES, ONE HOST NAME, IS THE ONE THING TO WATCH.** A browser on the
  laptop reaches both the service and the companion at `localhost`, and
  Kerberos names a service by host, not port: both would be
  `HTTP/localhost`. `docs/v1.1.0/docker-compose.md` tells a user to give the
  companion a host of its own.

## Dummy social identity providers (#1689)

The catalogue names 39 social providers, plus two generic profiles that are
not providers. A live sign-in needs an application and an account at each,
and none is kept. `social_idps.js` serves a dummy of each named one at
`/social/{id}`: one fixed person, and the client authentication and PKCE
that profile asks for. Steam's OpenID 2.0 check, DiscourseConnect and
Bluesky's DPoP push are the three that are not a code grant. The two
generic profiles are not served. The document each dummy follows is
`docs/v1.1.0/federation-consumer-providers.md` (*The companion dummy of each
provider*): the profile's recorded document, and the extra protocol
page where that document is not the whole answer.

Each page lists the relationship fields that point a development
relationship at that dummy. The addresses are this companion's public URL.
A service in another container dials the companion by that address, not
localhost. Enable the relationship last.

**THE SERVICE POSTS HERE, AND THOSE POSTS ARE NOT CSRF-BOUND.** The token
request, Steam's `check_authentication` and Bluesky's pushed authorization
request are the service, not a browser, so they carry no session cookie.
`Companion.handle()` dispatches `/social` before the CSRF check. Every
other POST stays bound. The dummy reads its own body, because two of those
requests can be in flight and the shell must not keep one body for both.

**A NEGATIVE FIXTURE REFUSES WHAT A PROVIDER WOULD (#1689's review,
2026-11-13).** A token request whose `redirect_uri` is not the one the code
was issued to, or names none, is `invalid_grant` and spends the code (RFC
6749 section 4.1.3), on every code-grant dummy and on Bluesky's pushed one.
Steam's `check_authentication` confirms a nonce once: a nonce that checked is
deleted, so a replayed assertion is `is_valid:false`; a check that failed
keeps it, so the right check after it still confirms.
`tests/social_idp_refusals.js` holds both.

No timer. The code, token, push and Steam-nonce maps are capped on insert
and nothing is swept.

## The application the remote PEP protects (#1760)

The remote PEP container can be a reverse proxy in front of one upstream
application (`xacml-pep/CLAUDE.md`). rcbj's direction on #1760: the dummy
application its protocol job drives is built INTO the companion, not into
the job or the test peer (`tests/peer/`). `pep_app.js` serves it at
`/pep-app`:

| Path | Page | What it is for |
|---|---|---|
| `GET /pep-app/_hits` | — | `{ total, byPath }`: how many requests reached each path. Not counted itself. The job reads it DIRECTLY, never through the proxy, to prove a refused or unrouted request never reached the application |
| `/pep-app/public[/…]` | `public` | the public route |
| `GET /pep-app/public/hop` | `hop` | answers `Connection: x-upstream-secret`, `X-Upstream-Secret` and `Keep-Alive` beside an end-to-end `X-Upstream-Visible`, so the job can assert the proxy drops a response's hop-by-hop headers (RFC 9110 section 7.6.1) |
| `/pep-app/protected[/…]` | `protected` | the session route |
| `GET /pep-app/api/items` | `items` | the OAuth 2.0 and Basic route's read |
| `GET /pep-app/whoami[/…]` | `whoami` | beside the echo, `whoami`: the identity headers the proxy forwarded and the listener the request came through (`via`: host, port and scheme of `X-Forwarded-Host` and `X-Forwarded-Proto`), for `sts_xacml_pep_proxy_cluster.js`'s route on a listener of its own (2026-11-16) |
| `POST /pep-app/api/items` | `item-created` (201) | the write: allowed and refused methods |
| `GET /pep-app/slow?ms=` | `slow` | answered after `ms`, at most 30 s: the proxy's upstream timeout (504) |
| `POST /pep-app/saml/acs` | `saml-acs` | the application's own SAML ACS, where the proxy POSTs the assertion in D11's `saml` mode |
| `POST /pep-app/saml/_setup` | — | `{ audience, metadataUrl?, certificates?, jwksUrl? }`: what the ACS and the JWT check trust. Not counted |
| anything else under `/pep-app` | `other` | e.g. the SAML route's pages |

Every page answers one JSON shape: `{ app: "pep-app", page, method, path,
query, headers, hit }`, plus `body: { length, sha256 }` when a body was
sent (always for POST, PUT and PATCH). **`path` is the RAW request
target**, dot segments as sent, so a traversal the proxy forwarded would
show; `headers` is every header node received, names lower-cased, so the
job reads the identity headers the proxy added and the `Authorization` and
proxy cookie it must have stripped. A body over 8 MiB is the application's
own 413, well past any `maxBodyBytes` the job sets.

**THE IDENTITY THE PROXY FORWARDS IS READ, NOT ONLY ECHOED (D11).** A
route sends it as headers it names, as a JWT access token the service
issued for the application, or as a SAML assertion the service issued for
it, which the proxy POSTs to this ACS server-side before forwarding the
request with the cookie it set. So every echo also carries `jwt` — the
header and payload of a `Bearer` JWT as sent, `verified` against the
realm's JWKS (`_setup`'s `jwksUrl`, else the token's `iss` +
`/oauth2/jwks`; RS, PS, ES and EdDSA with node's crypto) and `expired` —
and `saml` (`{ nameId, attributes, issuer, sessionIndex }`) when the
request's `pep_app_saml` cookie names a live ACS session. **The ACS reads
the assertion from what the signature COVERS** (xml-crypto's signed
references), never from the document around it, so a wrapped assertion is
not read; it checks the signature under the realm's certificate (from the
IdP metadata `_setup` named, or the certificates it was handed), the
audience against the configured SP entity, and the conditions' window.
**`_setup` is unauthenticated**, like everything in this container: the job
calls it once its realm exists, which no environment variable could name
when the stack started. Mutation-tested: the audience check removed fails
10f; ignoring `checkSignature()`'s answer is equivalent, because xml-crypto
6 throws on a signature that does not verify.

**DISPATCHED BEFORE THE SESSION AND THE CSRF CHECK**, by the raw path. The
proxy, not a browser, sends these requests, with no companion session; a
`companion_sid` set on every answer would be one more header for the job to
explain, and a write bound to a form token could not be proxied at all.
**Nothing here is authorization**: it trusts every header, because deciding
is the proxy's job and echoing is this one's. The counter is capped on
insert (2000 paths); the slow page's delay is one request's. It needs
nothing of the service, so the test stack's companion runs with no
bootstrap secret and its Kerberos TCP service off.

## The pages carry no script

The service's static-surface rule (root `CLAUDE.md`, *Pages with a script*)
binds the service, not this. Nothing here needs a script: links, one form, an
SVG QR code drawn on the server, and a `<meta>` refresh. So the policy is
`default-src 'none'; style-src 'self'; img-src 'self' data:; frame-ancestors
'none'; base-uri 'none'` — no `script-src`, and no `form-action`, because the
start's 303 to the wallet (another origin, or `openid4vp://`) is a redirect
after a submission that Chrome would hold to `form-action`.

Every POST is bound: the form's `csrf` must be the session's token
(constant-time), a fresh session is refused, and an `Origin`, when sent, must
be the companion's own. A POST under `/social` is the exception in the
section above: the service posts there with no session cookie. The session cookie is `HttpOnly; SameSite=Lax`, and
`Secure` when `COMPANION_PUBLIC_URL` is https. **`Referrer-Policy: same-origin`, not
`no-referrer`**: under `no-referrer` Chrome posts a form with `Origin: null`,
and the Origin check refused the companion's own start — found driving the
pages over CDP, which is why that drive is part of the change.

## Rules it keeps, and does not

* **The service's style rules, yes**: SPDX headers, every named function's
  Entering/Leaving lines, no swallowed exception, 80 columns.
* **The service's error codes, no**: a refusal here is the companion's own
  page, and `tests/error_codes.js` skips this directory.
* **No timer**: sessions (`MAX_SESSIONS`, an hour each) are evicted on insert
  and expired where they are read; `tests/no_periodic_timers.js` skips this
  directory, and it has nothing to skip.

## Tests

`tests/companion.js` (in process) runs the companion against a stand-in for
`sts_client.js` and holds the pages, the policy, the offer's shape, the
binding of a start, the `redirect_uri` a same-device start names and a
cross-device one does not, and the verdict shown to one browser only — and,
for #595, the Kerberos demonstration with a stand-in acceptor and
`sts_client.js`'s own provisioning over a stubbed `/admin-api` (create, then
rotate when held; the keytab's file and mode; the RFC 4559 exchange's
headers; the TCP framing; the KRB-ERROR, read back by the service's vendored
codec). `tests/social_idp_signins.js` signs in through each dummy social
provider as its own assertion, against this module on a loopback port, and
`tests/companion.js` holds that a token POST under `/social` is that dummy
and not the CSRF page; section 9 holds `/pep-app`'s echo, its raw path, the
write's digest, the hop-by-hop page, the slow page and the counter, and
section 10 the identity half: `_setup`, a JWT verified and a changed one
not, the ACS accepting a signed response for its audience and setting
`pep_app_saml`, the next echo carrying the session, and a tampered,
foreign-audience or unsigned response refused with no cookie.

**ONE PROTOCOL JOB NEEDS THE COMPANION SINCE #1760**, and so it is on the
test stack: `docker-compose-run-tests.yml`'s `companion`, in every local
mode, pinned at `.49`, with `XACML_PEP_UPSTREAM_URL=http://companion:9700`
handed to the runner. `tests/protocol/sts_xacml_remote_pep.js` section 10
puts the remote PEP's proxy in front of `/pep-app`; when that job starts
its own PEP (no launcher) it builds this image and starts it beside the
PEP. Every other job still uses the service's own doors. The companion
remains development-only on that stack too: the service image never
carries this directory. End to end the OpenID4VC half was driven over CDP
against a private stack, and the Kerberos half with MIT `kinit` and
`curl --negotiate` from a throwaway container against the companion and the
service's KDC.
