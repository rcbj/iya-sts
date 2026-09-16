---
title: Configuration
nav_order: 3
---

# Configuration

**There is exactly one place a setting is read**, `common/config.js`, and one
table inside it. That is not tidiness — it is what makes the next three sentences
possible.

From one row in that table, a setting appears in the admin console — on the page
for the protocol it configures — in `GET /admin-api/config`, in the management API's OpenAPI
document, and in the startup audit that logs what the appconfig file omitted and
what key it carried that the table does not know. None of those four has a list
of its own. A `process.env` read added anywhere else is invisible to all four,
which is the state this arrangement exists to end.

## How a value is resolved

Five levels, first match wins:

1. **A runtime override** — set on the console page for that setting's protocol, or through `POST /admin-api/config/set`
2. **The environment variable**
3. **A legacy environment variable** — there is exactly one, `STS_ISSUER`
4. **The appconfig file** named by `CONFIG_FILE`
5. **`env/defaults.js`** — the default appconfig file that 4 is unioned on top of

Environment beating the file is deliberate: it is what keeps existing containers
and test harnesses working when the shipped `env/*.js` files carry every key.

**There is no sixth level.** A setting with no value in 4 or 5 and no variable in
2 or 3 **stops this service from starting**, naming every such setting and both
places its value could go. A value that arrives from a constant buried in a
module is a value nobody can find, change or see on a page, which is the state
this arrangement exists to end — so there is no silent fallback underneath the
table to lead back into it.

**Levels 4 and 5 are one layer, unioned.** `env/defaults.js` carries a default
for every setting; the file `CONFIG_FILE` names is merged over it key by key and
**the operator's value wins wherever both carry a key**. So a config file may
carry as few keys as its author likes and still be complete, and a setting added
to the table tomorrow does not break every config file in the world on the day it
is added. `env/defaults.js` is GENERATED from the table — `node
env/generate_defaults.js` — and is not the file to edit; to configure a
deployment, edit the file `CONFIG_FILE` names or set the environment variable.

**Every setting has an environment variable**, and three settings are exempt from
the refusal above because their default is DERIVED from a neighbour rather than
written in a file: `global.https` from `oauth2.rfc9700`, `oid4vp.walletUrl` from
`oid4vci.walletUrl`, and `krb5.serviceDomains` from `krb5.realm`. Each still has
its own key and its own variable, and setting either replaces the derivation.

A DERIVED DEFAULT IS NOT THE SAME AS AN ABSENT VALUE, and `global.https` is the
one where the difference is visible: the appconfig files in `env/` all set it
explicitly, so the derivation is what a service reading some OTHER file falls
back to and not what any stack here runs on. See its own section below.

The README carries the full table: every appconfig key, its environment variable,
its default and whether it can be changed without a restart.

`STS_ISSUER` is the one legacy level because it used to be a single value serving
as the SAML assertion issuer, the WS-Trust token issuer AND the WS-Federation
entityID. Those are three different things that happened to share a default — an
entityID names an identity provider, an Issuer names whoever signed an assertion
— so they are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, all three
still fed by `STS_ISSUER` when it is set.

## Runtime versus restart-only

Every row declares whether it can change while the service is running. **A
restart-only setting is REFUSED rather than accepted**, with the reason, because
an accepted change that does nothing reads as having worked.

Three kinds are restart-only and it is worth knowing which:

- **A bound socket.** Every port above, and the main port's *scheme* — see
  `global.https` below.
- **Material derived at startup.** The TLS certificate is issued for
  `tls.hostnames` / `tls.ips` at boot; the Kerberos principal database and every
  long-term key in it come from the realm, the SIDs and the passwords at require
  time.
- **The directory tree**, which `ldap.baseDn` is the root of.

Everything else is live. That is why so much of the code reads a setting through
a function call rather than a module-level `const` — a `const` captured at
require time is the one thing a runtime override cannot change, and it fails in
the direction that looks like the console is broken.

## The settings worth knowing about first

### `oauth2.rfc9700` — the compliance mode

Off by default. On, it turns the OAuth 2.0 / OIDC authorization flow into an
RFC 9700-conforming one: registered redirect URIs, PKCE, no implicit grant, no
password grant, refresh token rotation with replay detection, sender-constrained
tokens, one-shot authorization codes.

**Sender-constrained does not mean required.** Section 2.2.1 makes it a SHOULD,
and the mode honours a DPoP or RFC 8705 binding wherever a client offers one
rather than refusing a client that offers none. The five settings under *Sender
constraints* below are how an operator asks for more than that.

**Off changes nothing.** Every existing caller of this mock uses an unregistered
`redirect_uri`, no PKCE, or the implicit grant, and both answers exercise a
client — so the flag has to be able to be off and the mode has to be complete.

It is **restart-only**, and only because of a socket: `global.https` derives its
default from it, so turning it on binds the main port as HTTPS. A flag that was
runtime for its checks and restart-only for its socket would report the mode as
on while every authorization response still went out over plain HTTP.

What it does and does not enforce is published at `GET /oauth2/rfc9700`, row by
row, with `enforced` as `yes`, `detected`, `always`, `deployment` or `no` — two
requirements are `no` because they are the *client's* and nothing this server
observes can tell a client that checks from one that does not.

### `oauth2.oauth21` — OAuth 2.1, and it turns the mode above on

Off by default. On, it enforces the OAuth 2.1 Authorization Framework
(draft-ietf-oauth-v2-1-16, still a draft) — which means RFC 9700 mode plus what
2.1 adds: PKCE for confidential clients too, a client that registered its own
redirect URI (**`oauth2.redirectUris` is not read**), a presented credential
that must verify, a JWT client assertion addressed to the issuer alone, no SAML
client authentication, no repeated parameters and a ten-minute code.

**It is not RFC 9700 mode renamed.** That mode requires `redirect_uri` at the
token endpoint, which OAuth 2.1 removed, and requires it at the authorization
endpoint even when the client registered one; a client written for 2.1 is
refused there and answered here.

Restart-only and settable on a trust realm, for exactly the reason above.
`GET /oauth2/oauth21` lists every requirement it adds, which it inherits, and
the grants it deliberately exempts.

### Sender constraints — five settings that ask for more than either mode

**Neither OAuth 2.1 nor RFC 9700 requires DPoP**, and that is worth saying once
before the five rows below. OAuth 2.1 section 4.3.1 gives a public client's
refresh token a *choice* of two treatments — sender-constrained, or rotated with
replay detection — and this service already takes the second. RFC 9700 section
2.2.1 makes a sender-constrained access token a SHOULD, and nothing anywhere
makes it a MUST.

So none of these five is implied by either mode and every one of them defaults
to off. They exist because a client under test should be able to meet a strict
authorization server here before it meets one in production. All five are
runtime settings and therefore per trust realm: one realm may demand a proof
while the next does not.

Four of the five **refuse**. Everywhere else this service prefers to answer with
something weaker rather than not answer at all; these do the opposite, and that
is the point of them. The fifth, `oauth2.refreshTokenRotation`, changes what is
issued rather than what is accepted.

### `oauth2.refreshTokenRotation`

Off. On, every refresh issues a NEW refresh token, the one that was spent is
refused, and a replay is treated as a compromise: the whole family descended
from the original grant is revoked rather than only the token replayed (OAuth
2.1 section 4.3.1, RFC 9700 section 4.14.2).

**RFC 9700 mode and OAuth 2.1 mode already do this for every client**, so this
setting is how to have it with both modes off. Turning it off while a mode is on
changes nothing — the mode is the stricter answer and wins.

**What it does not bring with it** is the rest of RFC 9700 section 2.2.2. The
idle timeout (`oauth2.refreshIdleSeconds`), the client binding and the scope
subset check stay behind `oauth2.rfc9700`, because none of them is what asking
for rotation asked for. What does come with it is replay detection, because
rotation without it is bookkeeping nobody reads.

A refresh token minted before it was turned on carries no family and is rotated
from its next use, so there is nothing to migrate.

### `oauth2.refreshTokenRequireDpop`

Off. On, a token request that would mint a refresh token and carries no DPoP
proof is **refused**, and the refresh grant is refused unless the presented
refresh token is bound (`cnf.jkt`) to the key that proves this request (RFC 9449
section 5).

**The whole token request is refused**, access token included. Minting the
access token and dropping the refresh token silently would leave a client that
believes it has a durable grant and discovers otherwise an hour later, which is
a worse failure than the error it gets instead.

**An unbound refresh token is refused rather than bound on first use.** Binding
it would be the friendlier answer and the wrong one: the token was handed out
with no constraint, anybody holding it could bind it to a key of their own, and
the operator who turned this on would have been told the tokens were constrained
at the moment a stolen one constrained itself. The message says to sign in again
for a bound one.

**Nothing is exempt from this setting, and nothing needs to be.** `/admin` and
`/portal` are OpenID Connect clients of this service, and since 2026-09-15 they
carry a DPoP key of their own and prove it on every back-channel token call — so
turning this on does not lock an operator out of either. The two clients named
under the next setting are exempt from **that setting only**.

### `oauth2.refreshTokenRequireMtls`

Off. The same refusal for RFC 8705: no refresh token is issued over a connection
carrying no verified client certificate, and the refresh grant requires the
presented token's `cnf["x5t#S256"]` to match the certificate on *this*
connection.

**RFC 8705 section 7.1 still passes** a client that authenticated with
`tls_client_auth` or `self_signed_tls_client_auth` on the same request and owns
the token, whether or not the token carries a thumbprint. That client's refresh
token is bound to the CLIENT rather than to the certificate, which is exactly
what the section is for: it may rotate its certificate without stranding the
grant.

**It needs `global.https`.** A listener that cannot ask for a client certificate
cannot be satisfied by one, so where the main port is plain HTTP every affected
request is refused with `STS-OAUTH-0527` rather than let through.

**Two clients are exempt, and from this setting only.** The seeded
`sts-admin-console` and `sts-user-portal` clients — this service's own relying
parties — redeem their codes and refresh tokens over a loopback call from this
process to itself, where there is no certificate to present and nobody on the
other end who is not already this process. `sts-debugger-ui` is deliberately not
exempt from anything: the embedded debugger is an ordinary client of this
authorization server and is configured to meet whatever the realm it points at
requires.

### `oauth2.accessTokenRequireDpop`

Off. On, a request presenting an access token as anything other than a proved,
DPoP-bound token is refused: the token must carry `cnf.jkt` and the request must
carry a proof for that key.

**It is a refusal at the RESOURCE and nowhere else.** The token endpoint goes on
minting Bearer tokens, which these surfaces then refuse — that is what lets a
client be driven against the refusal rather than merely told about it, and it is
why a 401 here is not a bug in the issuer.

What it covers is every surface that accepts a PRESENTED access token: UserInfo,
the RFC 9470 step-up resource, the three OpenID4VCI endpoints, `/scim/v2`, the
Shared Signals endpoints, `/admin-api` and the embedded debugger's listener.
What it does not cover is what is not an OAuth access token presented as a
credential: GNAP's own tokens, an RFC 7592 registration access token, and the
endpoints that take a token as a **parameter** (introspection, revocation, token
exchange).

**A token this service did not issue is held to it too.** The confirmation a
token carries can be read without trusting the token, and one carrying none
cannot satisfy a requirement that it be constrained — so unlike the binding
checks that run in every mode, this one does not step aside for a token that
cannot be verified.

**`/admin/api-explorer` stops working while it is on**, because its script sends
a plain `Bearer` header. Use `curl` with a DPoP proof, or turn the setting off
for that realm.

### `oauth2.accessTokenRequireMtls`

Off. The RFC 8705 half of the setting above, at the same surfaces: a presented
access token must carry `cnf["x5t#S256"]`, and the connection must present that
certificate.

**It needs `global.https`**, for the reason `oauth2.refreshTokenRequireMtls`
does, and it is refused with the same `STS-OAUTH-0527` where a certificate
cannot be asked for.

**The debugger's listener began asking for a client certificate on 2026-09-15**
so that a bound token can be presented there at all — `requestCert` with
`rejectUnauthorized: false`, the posture the main port already takes (as 8443
did, until that listener was deleted on 2026-09-16), so the handshake succeeds either way and what a certificate is worth is decided per
request. A listener that never asked would have made this setting an exemption
dressed up as a refusal.

### `oauth2.delegatedPermissionsEnforced` — the OTHER mode, and not part of the first

Off by default, runtime, and settable on a trust realm.

It refuses an authorization or token request that asks for a **delegated
permission** the client has not been granted. A resource application exposes an
API — a base URI and a list of permission names, joined into
`https://example.com/write` — and a client application is granted some of them;
the shape is Microsoft Entra ID's. `/admin/delegation` is where the RESOURCE
half is typed — the base URI and the permission names — and the GRANT is typed
on the client application's own page under *Directory › Applications*, where the
client half of the pair is the entry you are looking at rather than an option in
a list of every application in the service.

**It is deliberately NOT part of `oauth2.rfc9700`.** Every check in that mode
cites a section of a published Best Current Practice. A delegated permission
cites nothing, because no RFC says an authorization server must have one — it is
a product's design rather than a standard — so folding it in would make
`GET /oauth2/rfc9700` advertise a requirement no document contains.

**Off changes nothing about what is issued**, which is what makes the register
usable before anybody enforces anything: a permission scope still becomes the
token's audience and its scope claim, and the console still marks which requests
were not backed by a grant. On, the same request is `invalid_scope` at the
AUTHORIZATION endpoint — where the client can still be told — and at the token
endpoint for the grants that never reach it.

**It does not re-judge a grant already issued.** An authorization code redeemed
without a scope of its own carries what was authorized, and this service does not
go back and ask whether that is still allowed — so turning it on refuses the next
REQUEST rather than invalidating what is outstanding, which is what makes it safe
to turn on while something is running.

### `oauth2.consentRequired` — the one setting here that is ON by default

Runtime, settable on a trust realm, and **on unless you turn it off**, which no
other policy in this service is.

The first time a given username signs in to a given `client_id` for a given
scope, `/oauth2/consent` is drawn listing the scopes that are new. Nothing is
issued until they press **Allow**; **Deny** returns `access_denied` to the client
and records nothing at all.

**Why on, when everything else here is off.** Every other refusal is off by
default because this service exists to exercise clients and a refusal that
cannot be turned off removes a test case rather than adding one. Consent is not
a refusal — it is the screen every real authorization server draws on a first
sign-in, and a client that has never met one has never run the code that
survives it: the extra redirect, the second visit to the authorization endpoint,
the `access_denied` when somebody says no. Off by default would have meant the
interesting behaviour was the one nobody saw.

**OFF means what this service did before the screen existed** — nothing asked,
nothing recorded. It is *not* "everybody consented": no agreement is written
down, so turning it back on asks again.

#### Where the answer goes

`oauthConsent` on the person's own entry under `ou=users`, one value per
(person, application, scope):

```
oauthConsent: 20260901143000Z openid webapp1
oauthConsent: 20260901143000Z https://example.com/write webapp1
```

When it was agreed, the scope, and the application — **the `client_id` last,
because it is the only field with no rule about what it may contain**, so it
takes the remainder of the value. A delegated permission is recorded by its
WHOLE identifier and never by the bare permission name, because two resources
may each expose a `read`.

One value per triple and never one per request: a consent recorded against the
whole `scope` string would make `openid profile` and `profile openid` two
different agreements, and adding one scope would throw away the agreement to the
other four. A second visit asks about the *difference*, with what was already
agreed under a fold.

#### Consenting a scope for everybody

`oauthGlobalConsent` on the **client application's** entry, one value per scope,
typed at `/admin/consent` or through `POST /admin-api/consent/grant-global-consent`.
A scope named there is never asked about and **nothing is written about
anybody**.

Two things follow, and both are the difference between an *override* and a
*record*:

* **Removing one asks everybody again**, including the people who would have
  said yes. Removing a person's own answer asks one person.
* **It is keyed on the pair, not on the scope.** Consenting `read` consents it
  for *that* application; one registered five minutes later that spells the same
  word is still asked.

Both are ordinary attributes on ordinary directory entries, so an `ldapmodify`
is a configuration change here exactly as it is for a redirect URI, and they
persist wherever the directory does.

#### The two prompt values, and what is never re-judged

`prompt=consent` asks again whatever is on the entry and takes nothing away.
`prompt=none` with something outstanding is **`consent_required`** — OpenID
Connect Core section 3.1.2.6's own code rather than the general
`interaction_required`, because a client that gets the general one cannot tell a
missing session from a missing consent.

**Nothing already issued is touched, ever.** The token endpoint asks nobody
anything, so a refresh of a code obtained before this was turned on still works,
and revoking a consent leaves a token already minted valid. `/admin/tokens` is
where an issued credential is revoked.

### `oauth2.tokenExchangeRefreshToken` — three servers, one switch

Runtime, settable on a trust realm, and the only OAuth setting here whose value
is a WORD rather than a number or a yes/no.

An RFC 8693 token exchange trades one token for another. Whether the response
also carries a `refresh_token` is left to the authorization server by section
2.2.1, which names the case it is for: a client that must keep reaching a
resource *"even when the original credential is no longer valid"* — the
user-not-present case, where there is no session by design. Real authorization
servers differ, so this one can be any of them:

| Value | What an exchange gets back |
|---|---|
| `when-requested` | **The default.** Section 2.1 read literally: the client asks with `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` and gets a refresh token only if it did. |
| `never` | No refresh token from an exchange, whatever the request said. An exchange that asked still SUCCEEDS — the ask is a request and not an instruction — and the log says which setting swallowed it. |
| `always` | Every exchange response carries one, asked for or not. |

**Why three words and not a switch.** `false` would have had to mean `never`,
which leaves `true` meaning either of the other two and no way to reach the
third — and `always` is the interesting one to point a client at, because a
credential arrives that it never asked for and must not leak.

**What comes back is an ordinary refresh token of this service**, in every case
and by construction: it is minted by the one function every grant here mints one
through. It redeems at the refresh grant, reports at `/oauth2/introspect`, is
revocable at `/oauth2/revoke`, lives for `oauth2.refreshTokenTtlS`, rotates
wherever rotation is required (RFC 9700 mode, OAuth 2.1 mode or
`oauth2.refreshTokenRotation`), and is bound to the DPoP key or client
certificate the exchange was made with. It also remembers the RFC 8707 resources the exchange named, so a
renewal cannot widen the audience the exchange narrowed.

`issued_token_type` says `access_token` throughout. It describes the token in
the `access_token` member, and that member holds an access token whichever way
this is set.

#### One client at a time

`oauthTokenExchangeRefreshToken` on the **client application's** entry, holding
one of the same three words, overrides this for that client alone — typed on
`/admin/applications`, on `/admin/applications/new`, or through
`POST /admin-api/applications/set`.

The CLIENT performing the exchange and not the audience, for two reasons that
point the same way: the refresh token is handed to the client, so it is that
party's credential to hold and redeem; and in the interesting case the subject
the exchange is *about* has no entry here at all, the whole point of an exchange
being a `subject_token` from somewhere else.

**It is the one attribute in this registry that is REFUSED on an application of
the wrong kind.** It applies to the OAuth 2.0 and OpenID Connect families, and
writing it onto an entry declared for neither is turned away by the console and
by `/admin-api`, naming the family to tick first. Every other per-application
setting is a default something reads if it ever gets the chance, so writing one
onto an application that never reaches that protocol costs nothing; this one
decides what the *token endpoint* does for a `client_id`, so on an entry no
token request could ever name it would sit there reading like a policy that was
in force. Clearing it is never refused, and `ldapmodify` reaches it like every
other attribute.

A value that is not one of the three words is not an error either: the log says
which entry carries what, and the service-wide setting decides.

### `global.https` — TLS on the main port

**ON in every appconfig file this repository ships, since 2026-08-30.** That is
a statement about `env/local.js`, `env/test.js` and `env/docker-tests.js`, which
each carry `global.https: true`, and NOT about the setting's own default — that
still derives from `oauth2.rfc9700` and is still `false`, which is what a
service handed somebody else's appconfig file (the parent project's Kerberos
jobs, say) gets. Both compose files here set `STS_HTTPS` to the same answer, so
the container's healthcheck probes the scheme its service is actually bound in.

Why it was turned on: 8443, 9443 and LDAPS 636 were TLS and the main port —
the one every one of the seventeen protocol families actually answers on — was
not, so a caller who had already trusted this service's key for three sockets
still met an unencrypted fourth. One certificate, one trust decision, every
port. **The first two of those listeners were deleted on 2026-09-16**, which
makes the argument shorter rather than weaker: the port every protocol answers
on is also the port a client certificate is presented to, so it is the last
place that should be in the clear.

`STS_HTTPS=false` is the way back to a plain listener, and it is a supported
configuration rather than an escape hatch: a client that cannot be taught to
trust a certificate regenerated on every start is exactly what this service
exists to exercise.

When it is on there is **no plain HTTP listener in this process**, which costs
one thing that is stated on the page rather than left to be met as a handshake
failure: `POST /tls/trust` and `GET /tls/server-certificate` exist to be
reachable *before* anything is trusted, so the first call to each has to be made
with verification off:

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
export NODE_EXTRA_CA_CERTS=/tmp/sts.pem      # node trusts it from here on
```

It uses the same per-start certificate as LDAPS 636 and the embedded debugger's
listener, so a caller trusts this service once per start rather than three
times. `NODE_EXTRA_CA_CERTS`
accepts it despite its `basicConstraints CA:FALSE` — OpenSSL takes a self-signed
leaf found in the trust store as an anchor — and without it a node client fails
with `DEPTH_ZERO_SELF_SIGNED_CERT`, or, through `fetch()`, with a bare
`TypeError: fetch failed` that names nothing.

### `ldap.autocreateUsers`

On. Every identity that authenticates through any of the sixteen families gets an
entry under `ou=users`, seeded from a single funnel rather than sixteen call
sites. Turning it off gives you a directory holding only what somebody explicitly
wrote into it.

### `groups.claim` — and the reason it is safe to have on

On by default. It puts a claim naming somebody's group membership into every
access token, ID Token and both SAML assertions.

That is only defensible as a default because **the claim is omitted entirely for
somebody in no group** — absent, not an empty array. On a fresh start the only
people in a group are the three the directory seeds, so a caller who never
touched `ou=groups` gets exactly the tokens it got before the feature existed.

Nothing reads the claim back. No endpoint checks it and nothing decides anything
on it: carrying a group is not granting one. Two groups are the exception and are
not an exception to *that* sentence — `admin.readGroup` and `admin.writeGroup`
below are read from the directory by `/admin`, never from this claim, so a token
carrying `admin-write` still does nothing a token without it cannot.

### `global.mode` — and the four gate settings it replaced

**`scim.authRequired`, `spiffe.authRequired`, `admin.authRequired` and
`ssf.authRequired` are gone**, removed on 2026-09-06. They were one question
with four answers, and a deployment that required a credential at SCIM and not
at the console was not partly secured — it was unsecured with a longer
configuration file.

All four gates are now **unconditional**, in both modes: `/scim/v2` takes a
credential, the SPIRE Server API takes an X509-SVID over mutual TLS, `/admin`
takes a session and a role, and the Shared Signals endpoints take a credential.

What `global.mode` decides is whether what they ask for is **checked**.
`development` is the default and is every release of this service before that
date: a presented password is not verified, anything named is created, and there
are no public-client restrictions — which is what makes this a mock. `product`
runs the same protocol implementations with that permissiveness taken out, and
additionally gates `/admin-api`. It is settable per trust realm, so one process
can serve a development realm and a product realm at once.

**Switching a realm from `development` to `product` does not carry over the
return addresses development learnt.** A SAML ACS URL, a SAML 1.1 `shire`, a
WS-Federation `wreply` or a console/portal callback that a development-mode
request put on an application entry is marked *observed*, and product refuses it
until somebody confirms it on that application's page (or with
`POST /admin-api/applications/confirm-address`). Confirm or discard them before
the switch; addresses recorded before the marking existed carry no mark and need
reviewing by hand. See [what is not checked](what-is-not-checked.md).

Each gate is explained under [what is not checked](what-is-not-checked.md).

### `admin.readGroup`, `admin.writeGroup`, `admin.openWhenEmpty` and `admin.bootstrapUsername`

The console's two roles are two ordinary groups in the embedded directory —
`cn=admin-read` and `cn=admin-write` by default — so `/admin/rbac`, `POST
/admin-api/rbac/grant`, an `ldapmodify` and a SCIM `PATCH` all write the same
membership. **Write implies read.**

`admin.bootstrapUsername` (`admin`) names the default realm's bootstrap
administrator — and, since 2026-09-14, every trust realm's, where the account
and the two groups belong to that realm and administer it alone (see
[trust realms](trust-realms.md)). Startup creates it if it is absent and makes
it a member of both groups. A realm created at runtime gets one at once, and in
product mode the realm's password is shown once by the create. A newly created account must choose a new password at its first sign-in,
and the account cannot be deleted or renamed. In development any password
reaches that screen. In product mode the account gets the generated password
that is logged once.

`admin.openWhenEmpty` is on and keeps the console open to anybody who signs in
until that account first signs in to `/admin`; every page says so while it
lasts. Off, only members of the two groups may use the console from the start.
A process that never seeded the bootstrap administrator keeps the older rule:
open while *neither* group has a member. If the console is ever closed to
everybody, `/admin-api` is the way back out: it is gated by a credential of its own
(`adminApi.authRequired`, an OAuth 2.0 access token rather than a console
session), so getting back in means holding that token — or turning that one
setting off, which restores the open API this had until 2026-09-09.

Renaming a role group does not move anybody: the members stay in the old group,
which stops granting anything the moment the name changes.

All four are process-wide since 2026-09-14: a trust realm cannot carry its own
value, because they decide who administers the service.

### The federation settings, and the one that is stricter than a mock usually is

`federation.enabled` is ON, and that is safe in a way it would not be anywhere
else here, because the endpoints do **nothing** without a relationship: a partner
is created disabled, and one that is enabled and half-configured refuses rather
than half-working. Turning it off makes every `/federation` route 404 without
changing any relationship — the blunt instrument, for taking the feature away for
one test run.

`federation.usernamePrefix` is **empty by default, and that is a real decision
rather than a default nobody thought about.** Empty means a federated `alice` and
the local `alice` are ONE directory entry, which is right for a mock being
pointed at a partner to see what comes back — a prefixed name makes every
downstream token and assertion look unfamiliar. Set it to something like `fed-`
the moment the question is whether federated identities share a namespace with
local ones, which is the question it exists for. It is applied *after* the
username is chosen, so changing it cannot change which incoming value was used.

`federation.outbound` governs **the only outbound HTTP request this service
makes** — a partner's token endpoint, UserInfo or JWKS. Turn it off for a
deployment with no egress: SAML, SAML 1.1 and WS-Federation need no back channel
at all, and an OpenID Connect partner can still be used with
`fedResponseType: id_token` and its keys pasted into `fedJwks`.

`federation.outboundAllowInsecure` is **OFF by default, which is the one place
this service is stricter than a mock would ordinarily be.** What travels on those
requests is a client secret and an authorization code, at somebody else's
service. ON accepts an `http://` endpoint and a certificate nothing here trusts —
which is what federating against another mock on localhost needs — and every
request made under it is logged as insecure, rather than the setting being logged
once at startup and forgotten.

Everything else about a relationship is not a setting at all: it is an entry
under `ou=federations`, configured at `/admin/federation`, through `POST
/admin-api/federation/*`, or with an `ldapmodify`.

### Persistence

Since 2026-08-27 three things can survive a restart. **Nothing this service
mints ever does**, in any mode, and that is deliberate rather than unfinished:
the signing key is regenerated on every start, so a token or an assertion that
outlived it would verify against nothing.

| Persists when a store is on | Never persists |
|---|---|
| the embedded LDAP directory — which is also the applications registry, the federation register and the SPIFFE registry, because in this service those *are* directory entries | sessions, access tokens, ID Tokens, refresh tokens |
| the trust realm registry: names, descriptions, per-realm settings | authorization codes, pre-authorized codes, SAML artifacts |
| runtime setting changes — what the console and `POST /admin-api/config/set` write | Kerberos tickets, the replay caches (bar the RFC 7523 / 7522 used-assertion history, which a store keeps in both modes), the statistics, the audit log |

| Setting | Default | What it does |
|---|---|---|
| `persistence.mode` | `memory` | `memory` writes nothing. `ldif` writes an RFC 2849 file per realm plus two JSON files in `dataDir`, and needs no database. `postgres` writes three tables. |
| `persistence.dataDir` | `./data` | Where `ldif` writes. Relative paths resolve against the package root, not the working directory. |
| `persistence.databaseUrl` | `postgres://sts:sts@localhost:5432/sts` | The connection string `postgres` mode dials. Inert unless `mode` is `postgres`. **The default names an owner and the compose stack does not**: this value is for a local database with nothing in it, which the service builds for itself, while the stack dials the least-privileged `sts_app` that `postgres/schema.sql` creates — read/write on the rows, no `CREATE` on the schema. See [Persistence](persistence.md). |
| `persistence.writeDelay` | `1500` | How long a change waits before the `ldif` files are rewritten. Postgres ignores it and commits per request. |
| `persistence.realms` | `true` | Write the realm registry down too. |
| `persistence.appconfig` | `true` | Make a setting changed at runtime survive a restart. |

`memory` is the default, so a run that says nothing about persistence behaves
exactly as every run before this existed — which is why no test in the suite had
to be told about it.

**All but `writeDelay` are restart-only**, because the store is opened and read
before the HTTP listener binds. That ordering is also what makes restoring
settings safe: only a runtime-changeable setting can be overridden at all, and a
runtime setting is by definition one that is read per call rather than captured
at startup — so nothing in a saved override file can reach `global.https`,
`oauth2.rfc9700` or a bound port.

**A failed write is logged and never thrown.** If the database goes away, the
operation that triggered the write still succeeds, this service keeps answering
out of memory, and `/admin/persistence` and `GET /admin/ldap/service` both carry the error.
The next change recomputes the same difference and tries again, so a failure
loses nothing.

**Processes against one Postgres store coordinate, since 2026-09-06.** This
paragraph said the opposite before it. Every change goes into a monotonic log
inside the transaction that made it, and each process applies what the others
committed; a `LISTEN`/`NOTIFY` nudge only makes that prompt, so a missed
notification costs latency and never a change. `persistence.coordinate` turns it
off and `persistence.pollInterval` sets the worst-case lag. It shares **state and
not sockets** — the KDC, the LDAP listeners and SPIFFE's four are
per process — and the replay caches *converge* rather than synchronise, except
the RFC 7523 / RFC 7522 used-assertion history, which is claimed atomically. See
[Persistence](persistence.md).

### The TOTP settings, and the two that behave differently from the rest

Eight `totp.*` rows, drawn on `/admin/totp` under Protocols. Two things about
them are unlike every other setting in this service.

**Six of them affect NEW enrolments only.** The digest, the digit count, the
period and the secret length are all copied onto a person's enrolment when they
scan the QR code, because they are what the QR code TOLD the authenticator app —
and this service cannot change what an app was told after the fact. So changing
`totp.digits` from 6 to 8 does not invalidate anybody: the next person to enrol
gets eight, and everybody already enrolled goes on typing six. A setting that
silently locked out everybody who had already set an app up would be the worst
kind of knob.

**`totp.window` is the exception and applies to everybody.** How much a
deployment forgives a phone with a drifting clock is a policy rather than
something an app was told, so it is read live. The default is `1` — RFC 6238
section 5.2's recommended maximum, which makes a code good for about ninety
seconds. `0` demands a perfectly synchronised clock and is the setting to reach
for when demonstrating what happens without one.

**Leave `totp.algorithm` at `SHA1` unless that is exactly what you are
testing.** Several widely used authenticator apps — Google Authenticator among
them — ignore the `algorithm` parameter in the QR code and always compute SHA-1,
so any other value produces a code that scans perfectly and then generates codes
this service refuses, with nothing anywhere saying why. SHA-1 is not a weakness
here: what RFC 4226 uses it for is a keyed MAC over a counter, not a
collision-resistant digest.

**`totp.enabled=false` does not disable an existing enrolment.** It stops new
ones. A person who enrolled while it was on still holds the second factor their
account is configured for, and the sign-in screen still asks for the code — a
switch that silently downgraded every one of those accounts to a password alone
would be a security control whose off position does something other than what it
says. Clearing an enrolment is on that person's own row under `/admin/users`,
or `POST
/admin-api/mfa/clear-totp`.

### The recovery code settings, and the mechanism no specification defines

Four `backupCodes.*` rows, drawn on `/admin/backup-codes` under Protocols. They
configure the way back in when the second factor is not to hand — the phone is
lost or flat, the security key is at home.

**This is the only mechanism in this service with no document behind it.**
Everything else implements somebody's specification; nobody ever wrote one for a
recovery code. What every identity provider does converges anyway — a handful of
random strings, each accepted once — so the decisions that are left are this
service's own and `common/backup_codes.js` argues each.

**A set is issued by an ACT and not by a request.** There is no control
anywhere — not on `/portal`, not on `/admin`, not on `/admin-api` — that creates
one. A set is issued the first time a person enrols a second factor: a confirmed
authenticator app, or a security key in the `mfa` role. A recovery mechanism a
person has to remember to ask for produces exactly the population it exists to
protect, one at a time, because the people who did not ask are the people who
will need it.

**Once. Not once per enrolment.** Enrolling a different second factor later does
not reissue, and that is the rule to know before reading anything else here.
Somebody who printed a list in March and replaced their authenticator app in
June would otherwise be holding strings that had stopped working with nothing
having said so — a recovery credential that silently expires is worse than none,
because the person believes they have a way back. **An operator's Clear on that
person's row under `/admin/users` (or `POST
/admin-api/users/clear-backup-codes`) is the only route to a second set**, after
which the next second factor they enrol issues one.

**None of these four invalidates a set that exists**, which is the way the
`totp.*` rows above differ: those carry a paragraph about NEW enrolments because
their values were told to an app this service cannot reach. Nothing here is told
to anybody — a recovery code is a string compared against a stored string — so
shortening `backupCodes.length` changes what the next set looks like and leaves
an existing one matching exactly as it did. `backupCodes.enabled=false` likewise
stops a new set being issued and takes nothing away: a switch that removed the
only way back into an account whose phone is lost would be the worst one here.

**The codes are encrypted and not hashed.** This repository's rule is that a
secret the service VERIFIES is hashed and a secret it must PRESENT cannot be;
`userPassword` is scrypt for that reason. A recovery code is both, and what
decides it is whether a person may look at their remaining codes again — this
service says yes, on `/portal/mfa`, because a list shown exactly once at the end
of an enrolment somebody is rushing through is a list most people close without
reading, and the moment it matters is months later. They are sealed with
AES-256-GCM under the same key-encryption key as the signing keys wherever that
key outlives the process, and stored as the strings they were shown as where it
does not — sealing under development mode's per-run key would mean a printed
list that stopped working at the next restart, which is the precise failure this
mechanism exists to prevent.

**Nothing but the person sees them.** The console reports counts, the management
API reports counts, and neither has an operation that returns a code. Showing
them to whoever holds Admin Read would be an administrative door handing out a
working second factor — the same refusal this service already makes about
enrolling an authenticator app from the console.

### The WebAuthn settings, and the one of thirteen this service enforces

Thirteen `webauthn.*` rows, drawn on `/admin/webauthn` under Protocols.
**There were none of these until 2026-09-10**, and this page said so: WebAuthn
had *no settings at all — what a ceremony does is decided by the specification
and by the browser.* That is true of the cryptography and false of the ceremony.
The RP name, the algorithms offered, the user verification requirement, the
attestation conveyance and the timeout were literals in a string, so there was
no way to ask this service for a ceremony shaped any other way.

They are three kinds of thing and the page says which each is, because the kind
decides what it means:

* **THE CEREMONY** — `rpName`, `rpId`, `algorithms`, `userVerification`,
  `attestation`, `timeoutMs`. Handed to the browser in the options and no more.
* **CTAP2** — `authenticatorAttachment`, `residentKey`, `credProps`. Also handed
  to the browser, and translated by it into what it asks the AUTHENTICATOR for:
  which kind may answer, whether the credential is discoverable (a resident key,
  which is what a passkey is), and whether the browser is asked to report back
  which it made.
* **POLICY** — `enabled`, `primaryAllowed`, `mfaAllowed`, `maxKeysPerPerson`.
  Not WebAuthn at all: what THIS service will do with a key once the ceremony is
  over.

**`webauthn.userVerification` IS THE ONE THIS SERVICE CHECKS.** `required` is
sent to the browser AND the UV flag in the signed authenticator data is verified
when the ceremony comes back, so an authenticator that did not verify the person
is refused rather than quietly accepted. The other ceremony rows cannot be
checked at all: nothing signed says what the browser was asked for, so a check
would be a comparison against a value this service itself supplied. What it does
instead is RECORD what came back — the attachment the browser reported, and the
`credProps` answer about whether the credential is really discoverable.

**Raising it does not change what a session claims.** A passwordless sign-in
still records `amr ["hwk"]` and `acr "1"` under `required`. RFC 8176 has no
value for *the authenticator verified the user* that this service could honestly
assert, and claiming `mfa` because the ceremony was phishing-resistant would be
exactly the kind of fake this service refuses everywhere else.

**No attestation statement is verified whatever `webauthn.attestation` asks
for.** There is no metadata service here, no vendor trust anchor and no model
allow-list, so the statement is parsed, reported and believed. `direct` is the
default because this is a debugging service and the object is worth looking at;
a real deployment with no attestation policy sends `none`.

**`webauthn.rpId` may only WIDEN the RP ID**, to a registrable domain suffix of
the host this service was reached on — `example.com` at `sts.example.com`. That
is WebAuthn's own rule and browsers enforce it. This service enforces it too and
refuses anything else BY NAME in the log, because a browser refuses it with a
`SecurityError` that a ceremony reports as one of its several indistinguishable
failures — so a wrong value here would look like a broken authenticator.

**The four policy rows refuse an ENROLMENT and never an authentication.** A key
already on somebody's entry goes on working when the role that produced it is
switched off — the same contract `totp.enabled` keeps, and with a sharper edge
for `primaryAllowed`, where the person's ONLY credential would be the one being
switched off. Removing a key is on that person's own row under `/admin/users`,
or `POST /admin-api/users/clear-key`.

### `authn.mfaRequired` and `security.passwordResetTtlMinutes`

**`authn.mfaRequired`** (off by default, runtime, per realm) requires a second
factor of everybody who signs in at the realm's sign-in screen. Somebody who
holds none is sent to `/authn/mfa-setup` after their password is accepted and
chooses an authenticator app (the page shows the QR code and asks for a code)
or a security key; no session exists until one is enrolled. A passwordless
security-key sign-in is refused while it is on. An administrator can place the
same requirement on one person with **Require MFA** on their `/admin/users`
page, which writes `stsMfaRequired` on the entry.

**It is enforced at the sign-in screen and nowhere else.** A federated
assertion, a SPNEGO ticket, a TLS client certificate, the OAuth password grant,
an LDAP bind, WS-Trust and SCIM Basic authenticate somebody without that screen,
and a session that already exists is not ended. If both mechanisms are switched
off (`totp.enabled`, and `webauthn.enabled` or `webauthn.mfaAllowed`), the
screen refuses the sign-in and names those settings rather than silently not
asking.

**`security.passwordResetTtlMinutes`** (60) is how long a reset link issued with
**Send a reset link** on a person's `/admin/users` page stays usable at
`/portal/reset-password`. Issuing the link removes the current password and
signs the person out everywhere, so an expired link leaves nothing to sign in
with until an administrator issues another or resets the password.

### `oauth2.breakIdTokenNonce`

Off. On, it puts a deliberately wrong `nonce` in every ID Token and logs that it
did. It is **not** part of RFC 9700 mode and must not be folded into it — a
compliance flag that also breaks tokens is a flag nobody will turn on. It exists
because "the client must validate the nonce" is a requirement no server can
check, and a reachable negative is the only way to find out whether a client
does.

### The four token lifetimes

| Setting | Default | Allowed |
|---|---|---|
| `oauth2.accessTokenTtlS` | `3600` (one hour) | 30–2592000, in steps of 30 |
| `oauth2.idTokenTtlS` | `3600` (one hour) | 30–2592000, in steps of 30 |
| `oauth2.refreshTokenTtlS` | `86400` (twenty-four hours) | 30–2592000, in steps of 30 |
| `oauth2.clockSkewS` | `30` | 0–300, in steps of 30 |

All four are runtime settings, read per token, and they are drawn twice: with
the rest of the `oauth2.*` rows on `/admin/oauth2`, and on a page of their own at
`/admin/token-lifetimes` that puts them beside a count of what has already
expired. Both write through the same function — one store, two doors.

Set one low and the next token dies on cue, which is the reason to point a client
at a mock at all:

```bash
curl -s -X POST localhost:8081/admin-api/token-lifetimes/set \
  -H 'content-type: application/json' \
  -d '{"oauth2.accessTokenTtlS": 60}'
```

**A change reaches the next token and nothing already issued.** A lifetime is
stamped into a token as its `exp` when it is signed; to take one already in a
client's hands out of circulation, revoke it at `/oauth2/revoke` or on
`/admin/tokens`.

**Every lifetime is a whole number of thirty-second units**, and that is a
decision rather than a formatting rule: below half a minute a token expires
between the response being written and the client reading it, and the hour that
costs goes on debugging the wrong half of the exchange.

`oauth2.clockSkewS` is not a lifetime. It is the allowance applied to `exp` and
`nbf` wherever this service reads back a token it signed — introspection,
UserInfo, the refresh grant, token exchange, the DPoP-bound access token check —
**and** to the state every console screen reports, so the console and the
endpoints never disagree about what has expired. It never changes what goes into
a token. It is a different setting from `oauth2.clientAssertionSkewS`, which is
how far out a *client's* assertion may be (RFC 7523): one is somebody else's
clock, the other is this service's own.

> **`oauth2.refreshTokenTtlS` changed on 2026-08-24**, from thirty days to
> twenty-four hours. Set it to `2592000` for the old behaviour. It is not
> `oauth2.refreshIdleSeconds`, which is RFC 9700 mode's inactivity timeout on a
> refresh *chain* and is measured from the last redemption rather than from
> issuance.

## Reading the current configuration

```bash
curl -s localhost:8081/admin-api/config | jq
```

Every row, with its value, where the value came from, its type, its prose, and
whether it can be set at runtime — the whole table, whichever page edits it. It
also carries `homes`: which console page draws each group.

**In the console each group is on the page for the protocol it configures** —
`/admin/kerberos`, `/admin/ldap`, `/admin/saml2`, `/admin/scim`, and so on.
`/admin/config` holds the five settings that belong to no protocol and the index
of where the other 149 are. Every one of those forms posts to the same endpoint,
so there is one store however many pages draw the door.

## Changing one at runtime

```bash
curl -s -X POST localhost:8081/admin-api/config/set \
  -H 'content-type: application/json' \
  -d '{"key":"groups.claimName","value":"roles"}'
```

A restart-only key comes back refused, naming the reason. So does a value that
does not fit the setting's type.

The change applies to the next token, assertion, ticket or search; nothing
already issued changes, because a token is a signed document.

**Whether it survives a restart is `persistence.appconfig`.** In the default
`persistence.mode=memory` it does not — the override is in memory and is gone
with the process, which is what this service did until 2026-08-27. With a store
turned on it is written down and applied again at the next start, through the
same `setOverride()` a caller uses, so nothing about the layering changes: it is
still a runtime override sitting above the environment and the appconfig file,
and a *reset* is written down too.

**Nothing writes to the appconfig FILE in either mode**, deliberately, because a
service that edited a file checked into a repository would leave a test's
forgotten change behind permanently. The durable copy goes to the persistent
store instead, which is not a place anything is checked in from. See
[the persistence settings](#persistence) below.

`POST /admin-api/config/set-many` changes a whole section at once and is
all-or-nothing: every value is checked before any is written, so a body with one
bad field changes nothing and names it.
