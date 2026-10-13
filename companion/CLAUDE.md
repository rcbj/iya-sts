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

`docs/docker-compose.md` (*The companion*) is how a user starts it; this file
is why it is shaped the way it is.

## What it is

| File | What |
|---|---|
| `companion.js` | The shell: configuration from the environment, the bounded session store, the router every demonstration mounts on, `/`, `/companion.css`, `/healthz`, and the listener |
| `companion_util.js` | The logger, the one page layout and its policy, cookies, bodies, answers |
| `sts_client.js` | The ONE door into the service, and the only module that knows how |
| `demo_oid4vc.js` | The OpenID4VC demonstration: `/issuer`, `/issuer/offer`, `/verifier`, `POST /verifier/start`, `/verifier/wait`, `/verifier/done` |

Node built-ins, `bunyan` and `qrcode`, pinned and installed from the committed
lockfile. Plain JavaScript and no build: the service's TypeScript conversion
(#50) is about the service, and this image has nothing to compile.

**A DEMONSTRATION IS A MODULE WITH `describe()` AND `mount(router)`**, and a
line in `companion.js`'s `this.demos`. #595 (P4, Kerberos and SPNEGO) is meant
to be the second: a `demo_kerberos.js` beside this one, and whatever socket
it needs (the protected service's TCP port) started from `listen()`, which is
where the service starts its own sockets and for the same reason — a bind
can fail, and a require must not.

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
Without them, `COMPANION_BOOTSTRAP_SECRET` — the seeded `sts-management-api`
client's secret, the `ADMIN_API_CLIENT_SECRET` a stack pins — is used for
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
be the companion's own. The session cookie is `HttpOnly; SameSite=Lax`, and
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
cross-device one does not, and the verdict shown to one browser only. No
protocol job needs the companion — every job uses the service's own doors
(`/admin-api`, `/account-api`, the protocol endpoints) — so it is not on the
test stack. End to end it was driven over CDP against a private stack.
