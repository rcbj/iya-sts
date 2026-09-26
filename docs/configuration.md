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
table to lead back into it. The refusal looks like this:

```
config: FATAL — 2 setting(s) have no value in the appconfig layer and no environment variable:

  global.domain       STS_DOMAIN
  spiffe.trustDomain  STS_SPIFFE_TRUST_DOMAIN

Each must be set in ./env/local.js, in ./env/defaults.js (the default appconfig
file every other one is unioned on top of), or as the environment variable
beside it.
```

**Levels 4 and 5 are one layer, unioned.** `env/defaults.js` carries a default
for every setting; the file `CONFIG_FILE` names is merged over it key by key and
**the operator's value wins wherever both carry a key**. So a config file may
carry as few keys as its author likes and still be complete — a file carrying
only `logLevel` resolves everything else through the defaults, which is what lets
the parent project's in-process Kerberos jobs point `CONFIG_FILE` at their own
test config and still load these modules — and a setting added to the table
tomorrow does not break every config file in the world on the day it is added.
What the refusal above actually catches is the one case left: a setting added to
`common/config.js`'s table with no row in `env/defaults.js`, which is a setting
somebody added and did not finish adding.

`env/defaults.js` is GENERATED from the table — `node env/generate_defaults.js`
writes it from the `dflt` column, where each default is written down next to the
paragraph explaining why it is the default — and is not the file to edit. Two
copies of a default is one copy that will be wrong, and wrong in the quietest
possible way: the service running on one value while the console, the OpenAPI
document and the settings list all report the other. To configure a deployment,
edit the file `CONFIG_FILE` names or set the environment variable.

**`CONFIG_FILE` is the one environment variable with no appconfig key**, and it
cannot have one: it is what chooses the file. It names a JavaScript module,
resolved against the package root and then against the working directory, so
`./env/local.js` works from wherever the process was started. It defaults to
nothing: unset, every value comes from `env/defaults.js` or from the
environment. A file that cannot be loaded is fatal and says so, because
continuing would mean starting a service configured as nobody asked for.

**Every setting has an environment variable**, and four settings are exempt from
the refusal above and from both files, marked *(derived)* in
[Every setting](#every-setting), because their default is DERIVED from a
neighbour rather than written in a file: `global.https` from `oauth2.rfc9700`,
`oid4vp.walletUrl` from `oid4vci.walletUrl`, `krb5.serviceDomains` from
`krb5.realm`, and `adminApi.audience` — the base URL of the management API —
from `global.publicBaseUrl`, or from the main port's scheme, host and port where
that is empty. A literal in a file would freeze the derivation at whatever it
evaluated to the day the file was written. Each still has its own key and its
own variable, and setting either replaces the derivation.

A DERIVED DEFAULT IS NOT THE SAME AS AN ABSENT VALUE, and `global.https` is the
one where the difference is visible: the appconfig files in `env/` all set it
explicitly, so the derivation is what a service reading some OTHER file falls
back to and not what any stack here runs on. See its own section below.

[Every setting](#every-setting), below, lists every appconfig key, its
environment variable, its default and whether it can be changed without a
restart.

`STS_ISSUER` is the one legacy level because it used to be a single value serving
as the SAML assertion issuer, the WS-Trust token issuer AND the WS-Federation
entityID. Those are three different things that happened to share a default — an
entityID names an identity provider, an Issuer names whoever signed an assertion
— so they are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, all three
still fed by `STS_ISSUER` when it is set. `saml.issuer` is the `<saml:Issuer>` of
every SAML assertion (WS-Federation's included, since the same two functions
build them); `wstrust.issuer` is the `iss` of the JWT this STS returns;
`wsfed.entityId` is the `entityID` in the federation metadata. All three default
to `urn:wstrust:mock:sts`.

### An environment variable is a string, and the table knows what to do with it

A `bool` takes `1/true/yes/on` and `0/false/no/off` in either case; anything else
is warned about and falls back to that setting's own default, so
`LDAP_AUTOCREATE_USERS=treu` does not silently turn a feature off. A `csv` is a
comma-separated list, trimmed, and may be written as a real array in an appconfig
file. An `int` may narrow itself with a minimum, a maximum and a multiple-of —
the four token lifetimes do — and the same three numbers constrain the console's
form, the management API and the variable read at startup, because there is one
check rather than three.

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
- **The directory tree**, which `global.domain` is the root of (the default
  realm's; every other realm's is its own domain, fixed when it is created).

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

### `oauth2.fapi` — a FAPI security profile, and it turns RFC 9700 mode on

`off` by default. `1-baseline` enforces FAPI 1.0 Part 1: Baseline (final):
RFC 9700 mode, plus confidential clients authenticating by mutual TLS,
`private_key_jwt` or `client_secret_jwt`, key sizes, PKCE with S256 for every
client, an https `redirect_uri` always sent, `nonce` with `openid` and `state`
without it, the person's own consent, one client per request, and access
tokens of at most ten minutes unless sender-constrained.

Restart-only and settable on a trust realm, for the reason above. A **named
authorization server** may also carry its own value, or `off` to opt out of
its realm's (the `fapi` member on `/admin/authorization-servers`).
`GET /oauth2/fapi` lists every requirement. See
[OAuth security](oauth-security.md#fapi-10-baseline).

`1-advanced` is FAPI 1.0 Part 2: Advanced (final) on top of all of that: a
signed request object, `code id_token` or `code` with JARM, sender-constrained
access tokens only (`oauth2.fapiRequireMtls` makes that mutual TLS only),
`private_key_jwt` or mutual TLS client authentication, and PS256 or ES256 for
every signature. See [OAuth security](oauth-security.md#fapi-10-advanced).

`2-security` is the FAPI 2.0 Security Profile (final), a profile of its own:
confidential clients only, PAR required, `code` only, PKCE S256,
sender-constrained tokens by mutual TLS or DPoP, codes of 60 seconds, no
refresh-token rotation, and PS256, ES256 or EdDSA. See
[OAuth security](oauth-security.md#fapi-20-security-profile).

`2-message-signing` is FAPI 2.0 Message Signing on top of that: a signed
request object at PAR, JARM required, and signed introspection responses.
See [OAuth security](oauth-security.md#fapi-20-message-signing).

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

**What it changes for a confidential client.** With the setting off, RFC 9449
section 5 is followed as written: a refresh token issued to a public client is
bound to its DPoP key, and one issued to a client that *authenticated* on the
token request is not — "they are already sender-constrained with a different
existing mechanism", the client's authentication — so that client may prove a
new key at each refresh, and the access token it gets is bound to the new one.
On, every refresh token is bound, a confidential client's too. (Until
2026-09-24 a confidential client's was bound either way, and the OpenID
conformance suite's FAPI 2.0 refresh module failed on it — #176.)

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
`/portal` are OpenID Connect clients of this service, and they carry a DPoP key of their own and prove it on every back-channel token call — so
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

**The debugger's listener asks for a client certificate** so that a bound token can be presented there at all — `requestCert` with
`rejectUnauthorized: false`, the posture the main port already takes, so the
handshake succeeds either way and what a certificate is worth is decided per
request. A listener that never asked would have made this setting an exemption
dressed up as a refusal.

### `oauth2.delegatedPermissionsEnforced` — the OTHER mode, and not part of the first

Off by default, runtime, and settable on a trust realm. **It matters in
development only**: product mode refuses an ungranted permission whatever it
says (#110).

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

**Off, in development, changes nothing about what is issued**, which is what makes the register
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

#### The two prompt values

`prompt=consent` asks again whatever is on the entry and takes nothing away.
`prompt=none` with something outstanding is **`consent_required`** — OpenID
Connect Core section 3.1.2.6's own code rather than the general
`interaction_required`, because a client that gets the general one cannot tell a
missing session from a missing consent.

#### Withdrawing a consent ends what was issued under it (#172)

Revoking a consent — one scope, one application, a person's whole list, or a
global consent — revokes every access and refresh token issued under it, on
every node, and writes the instant down: `oauthConsentWithdrawn` on the
person's entry, `oauthGlobalConsentWithdrawn` on the application's. A refresh
token carries when its grant was made, and the refresh grant refuses it when a
consent it stood on was withdrawn at or after that — whatever the mode, and even
after the person consents again. Withdrawing one scope revokes the whole refresh
token. A person withdraws their own at `/portal/consents`.

### `oauth2.refreshRequiresConsent` — a grant nobody agreed to is not renewed

Runtime, settable on a trust realm, **on by default**. While consent is required
(`oauth2.consentRequired`, or a FAPI 1.0 profile), a refresh token issued at the
authorization endpoint is renewed only if every scope it carries was covered,
when it was granted, by the person's own recorded consent or by the
application's global consent. Otherwise the refresh is `invalid_grant`
(`STS-OAUTH-0616`). That is a token obtained while consent was off, or while
the directory could not record the answer; turning consent on sends each such
client back through the authorization endpoint once. A withdrawn consent is
refused whatever this says, and refresh tokens from the grants that never ask
anybody (the password grant, token exchange and the like) are held to
withdrawals only.

> **Warning.** Turning this off renews grants that nobody agreed to. A client
> that obtained a refresh token while consent was off keeps renewing it for the
> token's whole lifetime — while the person is away, if it holds
> `offline_access` — although this service now requires their consent.

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

**ON in every appconfig file this repository ships.** That is
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
port. **The first two of those listeners have since been deleted**, which
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
`ssf.authRequired` are gone**. They were one question
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
administrator — and every trust realm's, where the account
and the two groups belong to that realm and administer it alone (see
[trust realms](trust-realms.md)). Startup creates it if it is absent and makes
it a member of both groups. A realm created at runtime gets one at once, and in
product mode the realm's password is shown once by the create. A newly created account must choose a new password at its first sign-in,
and the account cannot be deleted or renamed. In development any password
reaches that screen. In product mode the account gets the generated password
that is logged once.

`admin.openWhenEmpty` is honoured **in development mode only**. There it is on
and keeps the console open to anybody who signs in until that account first
signs in to `/admin`; every page says so while it lasts. Off, only members of
the two groups may use the console from the start. A process that never seeded
the bootstrap administrator keeps the older rule: open while *neither* group
has a member.

**Product mode never opens the console to anybody**, whatever this setting
says: only the roster decides, which at first is the
bootstrap administrator alone. Until that account has claimed the console, its
roles are honoured only from a **password** sign-in through its own realm, and
only such a sign-in claims it — a federation partner asserting `admin`, a
certificate whose CN is `admin`, a wallet or a Kerberos ticket holds nothing.
The embedded debugger waits for the claim too. A realm with no bootstrap
administrator and nobody on its roster is closed, and says so in the log at
startup (`STS-ADMIN-0798`).

If the console is ever closed to everybody, `/admin-api` is the way back out:
it is gated by a credential of its own (`adminApi.authRequired`, an OAuth 2.0
access token rather than a console session), so getting back in means holding
that token and calling `POST /admin-api/rbac/grant`. In development, turning
that one setting off restores an open API; in
product it gates `/admin-api` by the console's own session and roles instead.

Renaming a role group does not move anybody: the members stay in the old group,
which stops granting anything the moment the name changes.

All four are process-wide: a trust realm cannot carry its own
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

**A partner's certificate is always verified in product mode, and plain http is
never used there** (#171). What travels on those requests is a client secret and
an authorization code, at somebody else's service. Three settings govern it, all
off or empty by default:

* `federation.outboundAllowHttp` accepts an `http://` endpoint — in development
  mode only;
* `federation.outboundSkipTlsVerification` accepts a certificate nothing here
  trusts — in development mode only, which is what federating against another
  mock on localhost needs. Product ignores it and refuses to set it;
* `federation.outboundCaFile` names a PEM file of CA certificates a partner may
  chain to, beside node's own store, which is how product reaches a partner
  certified by a private CA.

Every request made insecurely is logged as such, rather than the setting being
logged once at startup and forgotten. GNAP push (`gnap.push…`), Shared Signals
push (`ssf.push…`) and the XACML PEP nudge (`xacml.pepNotify…`) have the same
three settings each. The old single `…AllowInsecure` switches were removed and
a service whose configuration still names one refuses to start
(`STS-CORE-0105`).

Everything else about a relationship is not a setting at all: it is an entry
under `ou=federations`, configured at `/admin/federation`, through `POST
/admin-api/federation/*`, or with an `ldapmodify`.

### Persistence

Three things can survive a restart. **Nothing this service
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

**Processes against one Postgres store coordinate.** Every change goes into a monotonic log
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

**The authentication policy's TOTP row off (it was `totp.enabled=false` until
#64) does not disable an existing enrolment.** It stops new
ones. A person who enrolled while it was on still holds the second factor their
account is configured for, and the sign-in screen still asks for the code — a
switch that silently downgraded every one of those accounts to a password alone
would be a security control whose off position does something other than what it
says. Clearing an enrolment is on that person's own row under `/admin/users`,
or `POST
/admin-api/mfa/clear-totp`.

### The recovery code settings, and the mechanism no specification defines

Five `backupCodes.*` rows, drawn on `/admin/backup-codes` under Protocols. They
configure the way back in when the second factor is not to hand — the phone is
lost or flat, the security key is at home.

**This is the only mechanism in this service with no document behind it.**
Everything else implements somebody's specification; nobody ever wrote one for a
recovery code. What every identity provider does converges anyway — a handful of
random strings, each accepted once — so the decisions that are left are this
service's own and `common/backup_codes.ts` argues each.

**A person generates their own set, on `/portal/mfa`** — a set is not issued
automatically when a second factor is enrolled. The set is shown ONCE, and stored only when the person confirms they
have kept it. Until they do it waits apart from their entry for
`backupCodes.pendingTtlS`, and one that expires changes nothing about a set they
already held. A person who holds a second factor and no set is prompted to
generate one.

**Generating again REPLACES the set whole; a set is never topped up.** When it
runs low the person generates a new one. **An operator's Clear on that person's
row under `/admin/users` (or `POST /admin-api/users/clear-backup-codes`)
deletes a set**; no console or API operation creates one or shows a code.

**The codes are HASHED, one scrypt hash per code**, as `userPassword` is. A
secret this service only VERIFIES is hashed, and since the set is shown exactly
once and never again, nothing has to be able to present a code back — which is
what the earlier design, sealing the codes so the portal could show them again,
had to give up hashing for.

**None of these rows invalidates a set that exists**, which is the way the
`totp.*` rows above differ: those carry a paragraph about NEW enrolments because
their values were told to an app this service cannot reach. A stored code is
compared against its hash, so shortening `backupCodes.length` changes what the
next set looks like and leaves an existing one matching exactly as it did.
The recovery-code row off (it was `backupCodes.enabled=false`) likewise stops
a new set being generated and takes
nothing away: a switch that removed the only way back into an account whose
phone is lost would be the worst one here.

**Nothing but the person sees them, and only once.** The console reports
counts, the management API reports counts, and neither has an operation that
returns a code. Showing them to whoever holds Admin Read would be an
administrative door handing out a working second factor — the same refusal this
service already makes about enrolling an authenticator app from the console.

[Authentication](authentication.md#recovery-codes) describes the sign-in side:
where a code is typed, what the session records, and why a spend that cannot be
written refuses the sign-in.

### The WebAuthn settings, and the one of thirteen this service enforces

Thirteen `webauthn.*` rows, drawn on `/admin/webauthn` under Protocols.
The specification and the browser decide the cryptography, not the ceremony:
the RP name, the algorithms offered, the user verification requirement, the
attestation conveyance and the timeout are this service's choices, and these
rows are how to ask for a ceremony shaped another way.

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

**What is done with the attestation statement is `webauthn.attestationPolicy`
(#105).** `by-mode`, the default, verifies every statement in product mode
(`verify-if-present`: all eight WebAuthn Level 3 section 8 formats, the chain
against `webauthn.attestationTrustAnchors` and the FIDO Metadata Service's
roots, revocation, and MDS status reports) and nothing in development (`off`,
which product refuses to hold). `require-trusted` accepts only a statement that
chains to an anchor, which refuses every synced passkey. An AAGUID allow-list
(`webauthn.attestationAllowedAaguids`), a least certification level
(`webauthn.attestationMinCertificationLevel`) and FIPS
(`webauthn.attestationRequireFips`) each demand a trusted statement; a realm
that demands one asks the browser for `direct` whatever `webauthn.attestation`
says. `webauthn.attestationAllowSafetynet` and
`webauthn.attestationAndroidSoftwareKeys` are weaker options, off, each with a
warning in its description. `direct` is the conveyance default because this is
a debugging service and the object is worth looking at; a deployment with no
use for the authenticator's model sends `none`.

**`webauthn.rpId` may only WIDEN the RP ID**, to a registrable domain suffix of
the host this service was reached on — `example.com` at `sts.example.com`. That
is WebAuthn's own rule and browsers enforce it. This service enforces it too and
refuses anything else BY NAME in the log, because a browser refuses it with a
`SecurityError` that a ceremony reports as one of its several indistinguishable
failures — so a wrong value here would look like a broken authenticator.

**The four policy rows refuse an ENROLMENT and never an authentication.** A key
already on somebody's entry goes on working when the role that produced it is
switched off — the same contract the authentication policy's TOTP row keeps, and with a sharper edge
for `primaryAllowed`, where the person's ONLY credential would be the one being
switched off. Removing a key is on that person's own row under `/admin/users`,
or `POST /admin-api/users/clear-key`.

### A second factor required of everybody, and `security.passwordResetTtlMinutes`

**The authentication policy's `requireSecondFactor: always`** (Directory →
Policies, `if-held` by default, per realm, inherited from the default realm;
it was the `authn.mfaRequired` setting until #64) requires a second factor of
everybody who signs in at the realm's sign-in screen. Somebody who
holds none is sent to `/authn/mfa-setup` after their password is accepted and
chooses an authenticator app (the page shows the QR code and asks for a code)
or a security key; no session exists until one is enrolled. A passwordless
security-key sign-in is refused while it is on. An administrator can place the
same requirement on one person with **Require MFA** on their `/admin/users`
page, which writes `stsMfaRequired` on the entry.

**The sign-in screen is the one door that can ask for it.** In product mode
the five doors that take a password and nothing else — an LDAP bind, a WS-Trust
UsernameToken, SCIM, Shared Signals and EST Basic — refuse the person's own
password instead, answered as a wrong password, and accept an app password
scoped to the door. A federated assertion, a SPNEGO ticket or a Kerberos
AS-REQ, and a TLS client certificate authenticate somebody without that screen,
and a session that already exists is not ended. If both mechanisms are switched
off (the authentication policy's TOTP row, and `webauthn.enabled` or
`webauthn.mfaAllowed`), the
screen refuses the sign-in and names those settings rather than silently not
asking.

**`authn.passwordAloneDoors`** (empty, runtime, per realm; product only) lists
the password-only doors — `ldap`, `wstrust`, `scim`, `ssf`, `est` — that still
accept such a person's own password. **Every door listed lowers every such
person to one factor there** (NIST SP 800-63B section 4.2); prefer app
passwords. **`appPasswords.enabled`** (on) lets people make app passwords on
`/portal/app-passwords` and administrators make them on `/admin/users` and
`/admin-api`; turning it off stops new ones and leaves the made ones working.
**`appPasswords.maxPerPerson`** (10, 1–50) caps how many one person holds.

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

**It works in development mode only** (#104). A realm in product mode ignores
it where the ID Token is built — a value still stored from before the realm was
switched is logged once (`STS-CORE-0106`) — and refuses turning it on
(`STS-CORE-0103`). The same marker (`onlyWhile` on the row in
`common/config.js`) makes `ssf.breakSetSignature`, `ssf.legacySubClaim`,
`spiffe.acceptAssertedSelectors` and `spiffe.attestWorkloads` off development
only, and the four `…SkipTlsVerification` settings before them (#171). On
`oid4vp.requireStatusReference` it governs one value only: `off` is
development only, while `own-only` may be set in product (#165).

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

> **`oauth2.refreshTokenTtlS` is twenty-four hours**, not thirty days. Set it
> to `2592000` for thirty. It is not
> `oauth2.refreshIdleSeconds`, which is RFC 9700 mode's inactivity timeout on a
> refresh *chain* and is measured from the last redemption rather than from
> issuance.

### `saml.clockSkewS` — the skew added to what is issued

The one setting here that changes what goes INTO an assertion's validity window
rather than how long that window is. `saml.clockSkewS` is added to BOTH ENDS of
every assertion this service issues — `NotBefore` backdated, `NotOnOrAfter`
extended — which is the answer to a service provider whose clock is a few seconds
behind refusing a perfectly good assertion as not-yet-valid.

It is deliberately not `oauth2.clockSkewS`: that one is a TOLERANCE applied
wherever this service reads a document back, including an inbound federation
partner's assertion, and a deployment wanting a strict reading and a forgiving
issuance has to be able to say so. How LONG an assertion is valid is still per
profile — `saml2.assertionLifetimeMin` and `saml11.assertionLifetimeMin` —
because the two profiles are separate implementations consumed differently. All
three are drawn together on `/admin/saml-assertions`, which is the only page
where both lifetimes are visible at once.

## Reading the current configuration

```bash
curl -s localhost:8081/admin-api/config | jq
```

Every row, with its value, where the value came from, its type, its prose, and
whether it can be set at runtime — the whole table, whichever page edits it. It
also carries `homes`: which console page draws each group.
`GET /admin/config?format=json` answers the same whole table.

**In the console each group is on the page for the protocol it configures** —
`/admin/kerberos`, `/admin/ldap`, `/admin/saml2`, `/admin/scim`, and so on.
`/admin/config` holds the five settings that belong to no protocol — the bind
address, the port, the scheme, the proxy header and the log level — and is
otherwise the INDEX: every group, its size, what is overridden right now, and
the page that draws it. Every one of those forms posts to the same endpoint,
so there is one store however many pages draw the door. The console shows each
setting's effective value and **which of the five levels it came from** — the
question it exists to answer, since the five are indistinguishable once a value
has been read. The startup log line reports how many settings there are; that
count is the one to trust.

At log level `debug` the service logs every endpoint call — path, request and
response headers and bodies, status, elapsed time — and every assertion, JWT and
SD-JWT VC both before and after signing or encryption, which is the point of a
mock. The shipped appconfig files set `info`; `STS_LOG_LEVEL=debug` asks for the
whole record.

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
with the process. With a store
turned on it is written down and applied again at the next start, through the
same `setOverride()` a caller uses, so nothing about the layering changes: it is
still a runtime override sitting above the environment and the appconfig file,
and a *reset* is written down too.

**Nothing writes to the appconfig FILE in either mode**, deliberately, because a
service that edited a file checked into a repository would leave a test's
forgotten change behind permanently. The durable copy goes to the persistent
store instead, which is not a place anything is checked in from. See
[the persistence settings](#persistence) below.

So the file is what a person EDITS and the store is what the console WRITES, and
neither overwrites the other.

`POST /admin-api/config/set-many` changes a whole section at once and is
all-or-nothing: every value is checked before any is written, so a body with one
bad field changes nothing and names it — a section's Save on the console cannot
half-apply. `POST /admin-api/config/reset` puts one setting back and
`POST /admin-api/config/reset-all` puts them all back, which is what a test
should call to leave the service as it found it; in memory mode a restart does
the same thing.

## Per-application configuration

`/admin/applications/new` is where an application's own answers are typed, and
these settings can be answered there for one application rather than only
service-wide:

| Protocol | Settings a single application may overrule | Attributes |
|---|---|---|
| OAuth 2.0 / OIDC | the three token lifetimes, the refresh idle timeout, revoke-on-logout, and whether an RFC 8693 token exchange comes back with a refresh token | `oauthAccessTokenTtlS`, `oauthIdTokenTtlS`, `oauthRefreshTokenTtlS`, `oauthRefreshIdleSeconds`, `oauthRevokeRefreshOnLogout`, `oauthTokenExchangeRefreshToken` |
| SAML 2.0 | assertion lifetime, both signature switches, NameID format, artifact lifetime | `saml2AssertionLifetimeMin`, `saml2SignAssertion`, `saml2SignResponse`, `saml2NameIdFormat`, `saml2ArtifactTtlS` |
| SAML 1.1 | the same five | `saml11*` |
| WS-Federation | assertion lifetime | `wsfedAssertionLifetimeMin` |
| the groups claim | whether it is carried, its name, its value form, where it is read from | `appGroupsClaim`, `appGroupsClaimName`, `appGroupsClaimValue`, `appGroupsClaimFromMemberOf` |

They are also written with `POST /admin-api/applications/set` or an
`ldapmodify`. Where one is set, that answer wins for that application alone, and
the service-wide setting is the answer for every application that has not been
given one of its own. An **absent attribute means inherit** — there is no third
state — and a value that will not parse is ignored, logged and the setting used
instead. The defaults live on `/admin/token-lifetimes` and
`/admin/saml-assertions`, and each page names the attribute that overrides each
row; `GET /admin-api/saml-assertions` lists which setting each SAML attribute
overrides. The globals each protocol keeps — its issuer identity, its sockets,
its clock skews — stay on that protocol's own page.

**`oauthTokenExchangeRefreshToken` is the one attribute REFUSED rather than
merely inert on an entry of the wrong family** — see
[One client at a time](#one-client-at-a-time) above. The rule is declared on the
schema row itself (`families: ['oauth2', 'oidc']`) rather than written into
either door, so a second attribute that needs it costs a member and nothing
else. `ldapmodify` reaches the attribute either way, as it reaches every
attribute here: the refusal is the difference between offering an operation and
merely not preventing it.

**The New Application form shows a field only when its protocol is ticked**, so
an OAuth client is not asked for a SAML entityID. That is done in CSS with
`:has()` and no script; a browser without `:has()` shows every field, which the
page says on itself.

**An application declared for SAML 2.0 or SAML 1.1 gets a `samlEntityId`** — its
own identifier, if none was given — so its per-service-provider metadata at
`/saml2/metadata/{sp}` and `/saml11/metadata/{rp}` is publishable the moment the
entry exists.

**The scopes a client may be issued are declared here too (#110).**
`oauthAllowedScope` is RFC 7591 section 2's `scope` — a registration writes it
and returns it — and is edited like any other list attribute, on the console and
through `/admin-api/applications/add` and `remove`. This service's own protected
scopes (`admin:read`, `admin:write`, the SCIM and Shared Signals scopes, the
debugger permission) are issued only to a client that lists them, in both modes,
and `/admin-api`, SCIM and Shared Signals ask again on every call; in product
every other scope is held to the list, or, where there is none, to the default
set of OpenID Connect's six and the realm's OpenID4VCI scopes. `oauthScope`
beside it is only what the client has asked for.

## Behind an L4 load balancer — the PROXY protocol

**Put this service behind a Network Load Balancer, not an Application Load
Balancer**, and pass TLS through. An L7 balancer terminates TLS, and every
feature here that reads the client's certificate — RFC 8705
`tls_client_auth` and certificate-bound tokens, `GET /tls/sign-in`, the
XACML certificate gates, the SPIRE Server API — needs the handshake to happen on
the node; no forwarded certificate header is believed, in any mode. An L7
balancer also cannot carry LDAP, LDAPS or Kerberos at all.

At L4 the node sees the balancer as every connection's peer. `global.proxyProtocol`
set to `v2` is how the client's address still arrives: the balancer writes a
binary header at the front of each TCP connection, and this service takes it off
before TLS, LDAP or the KDC read a byte. For an **AWS Network Load Balancer**:

* **TCP listeners** (not TLS listeners) for 443→8081, 389, 636 and 88,
  each forwarding to a **TCP target group** on the node's port. A client
  certificate arrives on 443. The KDC's UDP 88 cannot carry a header; put
  Kerberos clients on TCP.
* **`proxy_protocol_v2.enabled = true`** on every one of those target groups.
  AWS documents that health checks then carry the header too, with no client
  information in it — they are accepted, and keep the balancer's address.
* **`preserve_client_ip.enabled = false`** (the default for IP targets, not for
  instance targets), so connections come from the balancer's own private
  addresses, and **`global.trustedProxies`** set to the CIDRs of the subnets the
  balancer is in. With client IP preservation on, the peer is the client and
  every connection is refused as untrusted.
* `global.publicBaseUrl` set to the name clients use, as for any deployment.

A connection from an address outside `global.trustedProxies` is **closed**, not
served — a node reachable around the balancer is a network fault, and closing it
makes the balancer the only way in. A trusted address that sends no header is
closed too (`STS-PROXY-0002`). The one exception is **this host**: loopback, or a
peer on the node's own address, is served plain, because the console's and the
portal's OpenID Connect back channel and the Shared Signals push dial the main
port on loopback without a header. `common/proxy_protocol.ts` argues each of
these; the refusals are `STS-PROXY-0001`–`0009` in
[Error codes](error-codes.md).

## Every setting

Generated from `common/config.js`'s table — the same rows the console renders
and `GET /admin-api/config` answers, so this list cannot describe a setting this
service does not have or miss one it does. The **Group** each setting belongs to
is also the console page that draws it: the *Kerberos* rows are on
`/admin/kerberos`, the *SCIM* rows on `/admin/scim`, and `/admin/config` lists
the mapping for every group.

How to read it. **The appconfig key is the dot path in the file**, so
`oid4vci.batchSize` is `oid4vci: { batchSize: … }`; `logLevel` is the one key
that sits at the top level rather than in a section, because it was there before
this table existed and moving it would have broken every config file for no
gain. **Every setting has an environment variable and it beats the file.**
**Change while running** says whether the console and `POST
/admin-api/config/set` will take it: *restart* means the value was consumed
before the service was listening — a bound socket, the TLS certificate's names,
the Kerberos principal database and its long-term keys, the directory tree's
root — and the reason is on the row. ***(derived)*** marks the four whose
default is computed from a neighbouring setting rather than written in a file
(see [How a value is resolved](#how-a-value-is-resolved)).

The *What it does* column is the first sentence or two of the setting's own
description. The full paragraph — with the reasoning, which is usually the
record of something having gone wrong once — is in `common/config.js` beside the
row, and beside the input on whichever console page draws it.

Four things about these settings do not fit in a cell and have cost real time:

* **`OID4VCI_WALLET_URL` is the base URL the BROWSER uses**, not one this
  service fetches. The Credential Offer pages and the verifier's request pages
  hand the End-User back by appending `/vc-issuance-1.html` or
  `/vc-presentation-1.html` to it (`oid4vci.walletIssuancePath` and
  `oid4vp.walletPresentationPath`), so its default of `http://localhost:3000` is
  right only when the browser and the wallet share a host. Get it wrong and the
  hand-off lands on an unreachable origin — and because the URL still *contains*
  the wallet page, a `urlContains` wait passes and the failure looks like an
  unrelated timeout.
* **`KRB5_KDC_PORT` is the TCP *and* UDP port.** Both transports are bound to the
  same number on purpose: a client that fails over from UDP after
  `KRB_ERR_RESPONSE_TOO_BIG` retries at the address it already had.
* **`LDAPS_PORT` is bound by a second server object**, not by an option on the
  first — ldapjs decides between a `net.Server` and a `tls.Server` at
  construction — so 389 and 636 fail independently and `GET /admin/ldap/service` reports each
  separately. There is no StartTLS to turn on instead: it is an extended
  operation, ldapjs implements none, and this repository does not patch that
  submodule. And each trust realm's naming context is DERIVED from its DNS
  domain — the default realm's from `STS_DOMAIN` (`global.domain`), `example.com`
  being `dc=example,dc=com` — with `ou=users`, `ou=groups`, `ou=applications`
  and `ou=spiffe` derived beneath it rather than configured, because two
  variables that could disagree with it would put entries in a tree nobody is
  searching.
* **There is no separate TLS or mutual-TLS port.** A client certificate is
  presented to the main port, which asks every connection for one and requires
  none — a server that *required* one could not also be the port every other
  protocol arrives at. A certificate that does not verify is refused where it is
  USED: RFC 8705 client authentication, `/xacml`, `/scim/v2`,
  `GET /tls/sign-in` and a GNAP key proved by mutual TLS under
  `gnap.mtlsTrust=pki`. `STS_TLS_PORT` and `STS_MTLS_PORT` are not settings, and
  a deployment that sets one gets an "unknown setting" warning at startup.


### Trust realms

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `realms.enabled` | `STS_REALMS_ENABLED` | `true` | yes | Whether the realms defined on `/admin/realms` answer on their path prefixes. Turning it OFF leaves every definition in place and stops the paths working, which is what to reach for when a realm is answering something it should not: nothing has to be deleted to find out whether a realm is the reason for something. It has no effect at all until at least one realm is defined. |
| `realms.pathSegment` | `STS_REALMS_PATH_SEGMENT` | `realm` | yes | The segment in front of a realm id, so that the realm `acme` is at `/realm/acme/oauth2/token`. Set it to the empty string for the bare `/acme/oauth2/token` shape. A realm may never be named after the first segment of a path this service already serves, WHATEVER this is set to, precisely so that clearing it cannot turn an existing realm into a shadow over the console or the authorization server. |

**Neither of these two can be set ON a realm.** A realm that could switch realms
off would be doing it from inside the request that found it, and a realm that
could move its own prefix would change the prefix already used to find it. They
are refused at both ends.

### Global

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `global.mode` | `STS_MODE` | `development` | yes — and it is **per trust realm**, so one process can serve a development realm and a product realm at once | What this service IS. `development` is what makes it a mock: no password is checked, anything named is created, and there are no public-client restrictions. `product` runs the SAME protocol implementations with the permissiveness taken out — a presented password is verified against the hashed `userPassword` on the person's own entry, nothing is created because it was named, every OAuth application that declared a confidential method authenticates with it, every development-only setting is ignored, and `/admin-api` is gated. `GET /admin/mode` and `GET /admin-api/mode` list what it changes. The console, SCIM, the SPIRE Server API and Shared Signals are gated in BOTH modes, with no setting to open them — what the mode changes is whether the credential they ask for is CHECKED. |
| `global.host` | `STS_HOST` | `0.0.0.0` | **restart** — the listener is bound when the process starts | The address the HTTP listener binds. 0.0.0.0 is every interface, which is what a container needs; 127.0.0.1 confines this service to the machine it runs on. |
| `global.port` | `STS_PORT` | `8081` | **restart** — the listener is bound when the process starts | The port everything HTTP here answers on: the protocol endpoints, the console and this API. The two TLS listeners are separate and are under TLS below. **Several nodes against one store must all use the same value**: the console's and portal's own Shared Signals receivers are seeded at `<loopback>:<global.port>` and every node pushes to that address on its own loopback (`ssf/CLAUDE.md`, *Several nodes*). |
| `global.https` *(derived)* | `STS_HTTPS` | `false`, but **`true` in every appconfig file shipped here** — see *Running it* | **restart** — the listener is bound when the process starts, and its scheme is decided there | Serve the main port over HTTPS, with the SAME certificate and key the LDAPS 636 listener and the embedded debugger's use — one self-signed pair generated per start, so a caller trusts this service once rather than three times. It is also what lets the main port ask for a client certificate, which is where mutual TLS happens. |
| `global.domain` | `STS_DOMAIN` | `example.com` | **restart** — the default realm's directory tree is built under it at startup | The DNS domain of the DEFAULT trust realm. Its directory is rooted at the RFC 2247 mapping of it (`example.com` is `dc=example,dc=com`), and a realm created without a domain of its own is given `<id>.<this value>`. It names what the realm invents, never where it is reached. |
| `global.trustProxy` | `STS_TRUST_PROXY` | `false` | yes | Believe X-Forwarded-Proto and X-Forwarded-Host — which is what a TLS-terminating reverse proxy sets to say what the CLIENT used. |
| `global.trustedProxies` | `STS_TRUSTED_PROXIES` | *(empty)* | yes | The addresses or CIDR ranges this deployment's own proxies connect from. Read for forwarded headers only with `global.trustProxy` on, and for a PROXY protocol header whenever `global.proxyProtocol` is `v2` — where empty trusts nobody and the service does not start. **Empty keeps the old rule** — forwarded headers believed from any caller, the rate limiter taking the left-most `X-Forwarded-For` entry. Set, they are believed only from a peer in a range and the client is the right-most hop outside them, so a caller reaching a node directly cannot choose its own rate-limit address or this service's URL. `common/CLAUDE.md`, *Several nodes*, also says why mutual TLS needs L4 passthrough. |
| `global.proxyProtocol` | `STS_PROXY_PROTOCOL` | `off` | **restart** — installed on each listener when it binds | `v2` reads a HAProxy PROXY protocol version 2 header at the front of every connection to the main port, 389, 636, the KDC's TCP 88 (not UDP), the debugger and 8082 **before TLS**, so the client's address reaches the rate limiter, LDAP and the request workers while TLS and mutual TLS still terminate on the node. A connection from `global.trustedProxies` must carry a valid header (a `LOCAL` one — a health check — keeps the balancer's address); any other address is closed, except this host's own, which is served plain. Version 1 is refused; the SPIFFE gRPC listeners are not covered. See [Behind an L4 load balancer](#behind-an-l4-load-balancer--the-proxy-protocol) above. |
| `global.proxyProtocolTimeoutMs` | `STS_PROXY_PROTOCOL_TIMEOUT_MS` | `5000` | yes | How long a trusted proxy may take to send its complete header before the connection is closed. |
| `global.corsOrigins` | `STS_CORS_ORIGINS` | *(empty)* | yes | Origins CORS treats as this deployment's OWN, comma-separated — allowed on every path whichever client a request names, beside this service's listeners, `global.publicBaseUrl` and the embedded debugger. **Empty adds none**; every other origin must be listed in an application's `appCorsOrigin`. A value that is not an origin is ignored and logged. |
| `global.logLevel` | `STS_LOG_LEVEL` | `info` | yes | debug is the useful level for a mock whose job is to show what it did: every endpoint call, and every token and assertion both before and after it was signed. |
| `workers.count` | `STS_WORKERS_COUNT` | `2` | yes — the pool is reconciled on the next signature | How many child processes the post-quantum signing, verification and key generation are handed to, so that the process holding the sockets is never the one computing an SLH-DSA signature — which takes SECONDS, during which node answers nothing at all, the KDC on port 88 included. `0` means compute in this process, which is what this service did before the pool existed: correct, identical byte for byte, and blocking for as long as each signature takes. Nothing is forked until the first post-quantum job, so a process that never signs one never pays for a pool. **A realm may not carry this**: a pool belongs to the OS process. |
| `workers.batch` | `STS_WORKERS_BATCH` | `/scim,/admin/signals/receive,/portal/signals/receive` | yes (per process — a realm may not carry it) | Path prefixes that are **batch traffic** when requests are dispatched to request workers: routed only to a share of each pool's workers and held to a number in flight, so a bulk load cannot take every worker. Empty turns the lane off. |
| `workers.batchWorkerShare` | `STS_WORKERS_BATCH_WORKER_SHARE` | `50` | yes (per process) | The percentage of a pool's workers batch traffic may use — at least one, and one fewer than the pool below 100. A request already bound to a worker (a write to one SCIM resource) keeps it. |
| `workers.batchConcurrency` | `STS_WORKERS_BATCH_CONCURRENCY` | `8` | yes (per process) | Batch requests in flight per lane worker, per pool; the rest wait in the front process in order. `0` keeps the lane and removes the cap. |
| `workers.batchQueueLimit` | `STS_WORKERS_BATCH_QUEUE_LIMIT` | `5000` | yes (per process) | How many batch requests may wait; past it they are answered 503 with Retry-After. |
| `workers.batchQueueTimeoutS` | `STS_WORKERS_BATCH_QUEUE_TIMEOUT_S` | `60` | yes (per process) | A batch request that waited this long is answered 503 with Retry-After. |

### GNAP

The Grant Negotiation and Authorization Protocol (RFC 9635) and its resource
server connections (RFC 9767), drawn on `/admin/gnap`. Every row is settable per
trust realm. [GNAP](gnap.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `gnap.enabled` | `STS_GNAP_ENABLED` | `true` | yes | Off makes every /gnap endpoint, the RS-facing discovery document and the resource-owner pages answer that GNAP is turned off in this realm. |
| `gnap.accessTokenFormat` | `STS_GNAP_ACCESS_TOKEN_FORMAT` | `jwt-signed` | yes | The RFC 9767 token format issued when nothing more specific decides. |
| `gnap.tokenFormats` | `STS_GNAP_TOKEN_FORMATS` | `jwt-signed,jwt-encrypted,macaroon,biscuit,zcap` | yes | RFC 9767 section 3.1's token_formats_supported. |
| `gnap.zcapCryptosuite` | `STS_GNAP_ZCAP_CRYPTOSUITE` | `eddsa-jcs-2022` | yes | The Data Integrity proof a zcap token is signed with, and the only one accepted back: `eddsa-jcs-2022`, or the post-quantum `mldsa44-jcs-2024` / `slhdsa128-jcs-2024`. **Warning:** `Ed25519Signature2020` is for compatibility only — it signs the RDF canonicalization rather than the JSON, and cannot be verified without a JSON-LD processor ([GNAP](gnap.md)). |
| `gnap.accessTokenLifetimeS` | `STS_GNAP_ACCESS_TOKEN_LIFETIME_S` | `3600` | yes | The expires_in of every access token, and the exp of the formats that carry one. |
| `gnap.interactionLifetimeS` | `STS_GNAP_INTERACTION_LIFETIME_S` | `600` | yes | How long the interaction start URIs and user codes of a pending grant stay usable (RFC 9635 section 3.3's expires_in). |
| `gnap.continueWaitS` | `STS_GNAP_CONTINUE_WAIT_S` | `5` | yes | The wait of every continuation response. |
| `gnap.maxPolls` | `STS_GNAP_MAX_POLLS` | `60` | yes | How many continuation polls a pending grant accepts before it is finalized with too_many_attempts (section 5.2). |
| `gnap.signatureMaxAgeS` | `STS_GNAP_SIGNATURE_MAX_AGE_S` | `300` | yes | How far a key proof's created time may be from now, either way (sections 7.3.1, 7.3.3 and 7.3.4). |
| `gnap.interactionStartModes` | `STS_GNAP_INTERACTION_START_MODES` | `redirect,app,user_code,user_code_uri` | yes | Section 9's interaction_start_modes_supported. |
| `gnap.finishMethods` | `STS_GNAP_FINISH_METHODS` | `redirect,push` | yes | Section 9's interaction_finish_methods_supported. |
| `gnap.keyProofs` | `STS_GNAP_KEY_PROOFS` | `httpsig,mtls,jwsd,jws` | yes | Section 9's key_proofs_supported. |
| `gnap.mtlsTrust` | `STS_GNAP_MTLS_TRUST` | `auto` | yes | How a key proved by mutual TLS is trusted (RFC 9635 sections 7.3.2 and 11.4): `pki` — a chain to the client truststore, the revocation check, and a certificate bound to the client's entry (issued to it here, or matching its one `oauthTlsClientAuth*` subject) — or `pinned` — the certificate the key names, self-signed allowed. A revoked certificate is refused in both. `auto` is `pki` in product and `pinned` in development. **Warning:** `pinned` gives up chain validation and rotation at the certificate authority. An application's `gnapMtlsTrust` may be stricter, never weaker. |
| `gnap.subIdFormats` | `STS_GNAP_SUB_ID_FORMATS` | `opaque,iss_sub,email,account,uri,phone_number,aliases` | yes | Section 9's sub_id_formats_supported, in RFC 9493's own spellings. |
| `gnap.assertionFormats` | `STS_GNAP_ASSERTION_FORMATS` | `id_token,saml2` | yes | Section 9's assertion_formats_supported: an OpenID Connect ID Token and a SAML 2.0 assertion, built by the same code the OIDC and SAML families use. |
| `gnap.assertionMaxAgeS` | `STS_GNAP_ASSERTION_MAX_AGE_S` | `300` | yes | Section 2.4 lets an AS "accept a recently expired assertion in order to help bootstrap a new session". |
| `gnap.keyRotation` | `STS_GNAP_KEY_ROTATION` | `true` | yes | Section 9's key_rotation_supported, and section 6.1.1. |
| `gnap.tokenManagement` | `STS_GNAP_TOKEN_MANAGEMENT` | `true` | yes | Whether access tokens carry a manage URI and management token (section 6). |
| `gnap.bearerTokens` | `STS_GNAP_BEARER_TOKENS` | `true` | yes | Off refuses the bearer flag with invalid_flag for every client (section 2.1.1). |
| `gnap.durableTokens` | `STS_GNAP_DURABLE_TOKENS` | `false` | yes | Section 3.2.1's durable flag: a token survives the grant being modified. |
| `gnap.revokeOnModify` | `STS_GNAP_REVOKE_ON_MODIFY` | `true` | yes | Section 5.3: "The AS MAY revoke previously issued access tokens after a modification has occurred" — unless they were issued durable. |
| `gnap.instanceIds` | `STS_GNAP_INSTANCE_IDS` | `true` | yes | Section 3.5: a client that sent its key by value is handed an instance_id it can send by reference next time. |
| `gnap.continueAfterApproval` | `STS_GNAP_CONTINUE_AFTER_APPROVAL` | `true` | yes | Whether an approved grant's response carries a continue member, so the client can modify (section 5.3) or revoke (section 5.4) it later. |
| `gnap.consentRequired` | `STS_GNAP_CONSENT_REQUIRED` | `true` | yes | Off approves every interactive grant as soon as the resource owner has signed in, with no approval page. |
| `gnap.rememberApprovals` | `STS_GNAP_REMEMBER_APPROVALS` | `true` | yes | Write what a resource owner approved into the consent register on their own entry (as gnap:<digest> values), so the same rights are not asked for again. |
| `gnap.allowCrossUser` | `STS_GNAP_ALLOW_CROSS_USER` | `false` | yes | Section 2.4: when the request named a user and somebody else signs in, the AS SHOULD answer unknown_user. |
| `gnap.userCodeLength` | `STS_GNAP_USER_CODE_LENGTH` | `8` | yes | Section 3.3.3: RECOMMENDED between six and eight characters. |
| `gnap.unknownAccessReferences` | `STS_GNAP_UNKNOWN_ACCESS_REFERENCES` | `accept` | yes | What an access reference string (section 8.1) that names no registered resource set, and is not in the client's gnapAllowedAccess, does: carried onto the token as it stands, or refused with request_denied. |
| `gnap.introspection` | `STS_GNAP_INTROSPECTION` | `true` | yes | RFC 9767 section 3.3. |
| `gnap.resourceRegistration` | `STS_GNAP_RESOURCE_REGISTRATION` | `true` | yes | RFC 9767 section 3.4. |
| `gnap.tokenDerivation` | `STS_GNAP_TOKEN_DERIVATION` | `true` | yes | RFC 9767 section 4: a resource server presents a token it was given as existing_access_token and receives a token for a downstream resource server. |
| `gnap.pushFinish` | `STS_GNAP_PUSH_FINISH` | `true` | yes | Section 4.2.2: an HTTP POST to a URI the CLIENT supplied. |
| `gnap.pushAllowHttp` | `STS_GNAP_PUSH_ALLOW_HTTP` | `false` | yes | Push to a plain http finish URI: any host in development, loopback only in product (RFC 9635 section 2.5.2.1). |
| `gnap.pushSkipTlsVerification` | `STS_GNAP_PUSH_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only.** Push to an https URI without verifying its certificate. Product ignores it (`STS-GNAP-0720`) and refuses to set it (`STS-CORE-0103`). |
| `gnap.pushCaFile` | `STS_GNAP_PUSH_CA_FILE` | `` | yes | A PEM file of CA certificates a push listener may chain to, beside node's store. |
| `gnap.pushAllowedHosts` | `STS_GNAP_PUSH_ALLOWED_HOSTS` | `` | yes | Host names a push finish may go to. |
| `gnap.pushTimeoutMs` | `STS_GNAP_PUSH_TIMEOUT_MS` | `5000` | yes | How long a push interaction finish may take. |
| `gnap.jweEnc` | `STS_GNAP_JWE_ENC` | `A256GCM` | yes | The enc of a jwt-encrypted token encrypted to a resource server's own key. |

### ACME

Automatic Certificate Management Environment (RFC 8555), drawn on `/admin/acme`. Every row is settable per trust realm. [ACME](acme.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `acme.enabled` | `STS_ACME_ENABLED` | `true` | yes | Off makes every /enroll/acme endpoint answer that ACME is turned off in this realm (HTTP 503, an RFC 7807 serverInternal problem naming the setting). |
| `acme.allowedProfiles` | `STS_ACME_ALLOWED_PROFILES` | `tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon` | yes | The /admin/pki profiles an order may name in its `profile` member (draft-ietf-acme-profiles) and the directory advertises. |
| `acme.defaultProfile` | `STS_ACME_DEFAULT_PROFILE` | `tls-client` | yes | Most ACME clients never name a profile. |
| `acme.certificateLifetimeDays` | `STS_ACME_CERTIFICATE_LIFETIME_DAYS` | `90` | yes | The validity of a certificate issued at finalize, shortened to the ACME Issuing CA's own notAfter. |
| `acme.maxRequestBytes` | `STS_ACME_MAX_REQUEST_BYTES` | `65536` | yes | A flattened JWS larger than this is refused (HTTP 413) before it is parsed. |
| `acme.attemptsPerIdentity` | `STS_ACME_ATTEMPTS_PER_IDENTITY` | `30` | yes | Refused requests one account (or EAB key id) may make in one web-security window before ACME answers rateLimited. |
| `acme.attemptsPerAddress` | `STS_ACME_ATTEMPTS_PER_ADDRESS` | `120` | yes | Refused requests one client address may make in one web-security window before ACME answers rateLimited. |
| `acme.nonceLifetimeS` | `STS_ACME_NONCE_LIFETIME_S` | `300` | yes | How long a Replay-Nonce may wait before it is presented. |
| `acme.orderLifetimeS` | `STS_ACME_ORDER_LIFETIME_S` | `86400` | yes | How long an order stays pending or ready before it expires with its authorizations. |
| `acme.eabLifetimeS` | `STS_ACME_EAB_LIFETIME_S` | `604800` | yes | How long an EAB key issued on the console, through /admin-api or on the user portal may wait before it binds an account. |

### EST

Enrollment over Secure Transport (RFC 7030), drawn on `/admin/est`. Every row is settable per trust realm. [EST](est.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `est.enabled` | `STS_EST_ENABLED` | `true` | yes | Off makes every /.well-known/est endpoint answer 503 in this realm. |
| `est.allowedProfiles` | `STS_EST_ALLOWED_PROFILES` | `tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon` | yes | The /admin/pki profiles an EST label may name (/.well-known/est/<profile>/…). |
| `est.defaultProfile` | `STS_EST_DEFAULT_PROFILE` | `tls-client` | yes | What /.well-known/est/simpleenroll issues, with no label. |
| `est.certificateLifetimeDays` | `STS_EST_CERTIFICATE_LIFETIME_DAYS` | `365` | yes | The validity of an EST certificate, shortened to the EST Issuing CA's own notAfter. |
| `est.maxRequestBytes` | `STS_EST_MAX_REQUEST_BYTES` | `65536` | yes | A PKCS#10 body larger than this is refused (HTTP 413) before it is decoded. |
| `est.attemptsPerIdentity` | `STS_EST_ATTEMPTS_PER_IDENTITY` | `10` | yes | Refused authentications or enrollments one username, client_id or certificate may make in one web-security window before EST answers 429. |
| `est.attemptsPerAddress` | `STS_EST_ATTEMPTS_PER_ADDRESS` | `60` | yes | Refused requests one client address may make in one web-security window before EST answers 429. |
| `est.basicAuthentication` | `STS_EST_BASIC_AUTHENTICATION` | `true` | yes | A person's directory password or an application's client_id and client_secret (RFC 7030 section 3.2.3). |
| `est.certificateAuthentication` | `STS_EST_CERTIFICATE_AUTHENTICATION` | `true` | yes | A client certificate THIS REALM issued, verified to its Intermediate and mapped to its entry by the urn:sts:person: or urn:sts:application: name in it (RFC 7030 section 3.3.2). |
| `est.serverKeyGeneration` | `STS_EST_SERVER_KEY_GENERATION` | `true` | yes | Whether this service generates the key pair (RFC 7030 section 4.4) — the one enrollment path in which it holds a private key, which it then keeps, sealed, on the entry the certificate names. |

### SCEP

The Simple Certificate Enrolment Protocol (RFC 8894), drawn on `/admin/scep`. Every row is settable per trust realm. [SCEP](scep.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `scep.enabled` | `STS_SCEP_ENABLED` | `true` | yes | Off makes every /enroll/scep request answer 503 in this realm. |
| `scep.allowedProfiles` | `STS_SCEP_ALLOWED_PROFILES` | `tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon` | yes | The /admin/pki profiles a challenge password may be issued for. |
| `scep.defaultProfile` | `STS_SCEP_DEFAULT_PROFILE` | `tls-client` | yes | The profile preselected when a challenge password is made. |
| `scep.certificateLifetimeDays` | `STS_SCEP_CERTIFICATE_LIFETIME_DAYS` | `365` | yes | The validity of a SCEP certificate, shortened to the SCEP Issuing CA's own notAfter. |
| `scep.maxRequestBytes` | `STS_SCEP_MAX_REQUEST_BYTES` | `262144` | yes | A pkiMessage larger than this — POSTed, or base64 in the GET binding's message parameter — is refused before it is decoded. |
| `scep.attemptsPerIdentity` | `STS_SCEP_ATTEMPTS_PER_IDENTITY` | `10` | yes | Refused PKIOperations one challenge id may cause in one web-security window before SCEP answers 429. |
| `scep.attemptsPerAddress` | `STS_SCEP_ATTEMPTS_PER_ADDRESS` | `60` | yes | Refused requests one client address may make in one web-security window before SCEP answers 429. |
| `scep.challengeLifetimeS` | `STS_SCEP_CHALLENGE_LIFETIME_S` | `3600` | yes | How long a challenge password may wait before it is redeemed. |
| `scep.raKeyAlgorithm` | `STS_SCEP_RA_KEY_ALGORITHM` | `rsa-2048` | yes | SCEP encrypts the request to the RA with RSA key transport (RFC 8894 section 3.1), so the RA certificate is RSA whatever the SCEP Issuing CA is. |
| `gnap.demoResourceServer` | `STS_GNAP_DEMO_RESOURCE_SERVER` | `true` | yes | GET/POST /gnap/rs/resource: judges a presented token in any of the five formats and answers the RS-first challenge of section 9.1. |
| `gnap.caepEvents` | `STS_GNAP_CAEP_EVENTS` | `true` | yes | A grant or token revoked sends session-revoked, and a grant modified onto different access sends token-claims-change, to every stream that takes them. |
| `gnap.scopedSignals` | `STS_GNAP_SCOPED_SIGNALS` | `true` | yes | A Shared Signals stream owned by a GNAP client application with a finish URI carries events only about people who approved a grant to that application. |

### Web security

Sessions, the sign-in clocks, this service's own OpenID Connect client, and
passwords.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `authn.sessionLifetimeS` | `STS_AUTHN_SESSION_LIFETIME_S` | `3600` | yes — applies to the next session | How long a sign-on session lasts from creation, and with it the console's and the portal's own sessions. ABSOLUTE for a browser; an API client's session is extended by this much on every call. |
| `authn.sessionIdleTimeoutS` | `STS_AUTHN_SESSION_IDLE_TIMEOUT_S` | `0` | yes — applies to sessions that already exist | How long a session may go unused before it ends, on top of the lifetime. **Zero means no idle timeout**, which is what this service has always done. A request to the console or the portal counts as use of the sign-on session behind it. |
| `authn.pendingTtlS` | `STS_AUTHN_PENDING_TTL_S` | `600` | yes | How long a sign-in waits at the screen — and the console's and portal's own authorization code flows, and an arrival session's inactivity window, which are the same clock on purpose. |
| `authn.mfaStepTtlS` | `STS_AUTHN_MFA_STEP_TTL_S` | `300` | yes | How long somebody past the password step has to present a security key, a one-time code or a recovery code. |
| `authn.passwordAloneDoors` | `STS_AUTHN_PASSWORD_ALONE_DOORS` | *(empty)* | yes | Product mode only. The password-only doors — any of `ldap`, `wstrust`, `scim`, `ssf`, `est` — at which a person who holds or must hold a second factor is STILL accepted with their own password. Empty refuses it at all five and accepts only an app password there. **Warning: every door listed lowers every such person to ONE factor at that door** (NIST SP 800-63B section 4.2), so a stolen password opens it without the second factor. |
| `appPasswords.enabled` | `STS_APP_PASSWORDS_ENABLED` | `true` | yes | Whether a person may make an app password on `/portal/app-passwords`, and an administrator one for them on their `/admin/users` page or `POST /admin-api/users/create-app-password`. Generated, shown once, stored as a scrypt hash, named and scoped to password-only doors; never accepted at the sign-in screen. Turning it off does not invalidate one already made. |
| `appPasswords.maxPerPerson` | `STS_APP_PASSWORDS_MAX` | `10` | yes | How many app passwords one person may hold at once (1–50). |
| `oidcRp.maxFlows` | `STS_OIDC_RP_MAX_FLOWS` | `200` | yes | Console and portal sign-ins in flight at once, per trust realm; past it the oldest is dropped. |
| `oidcRp.backChannelTimeoutS` | `STS_OIDC_RP_BACK_CHANNEL_TIMEOUT_S` | `10` | yes | How long the console and the portal wait for this service's own token endpoint and JWKS over the loopback interface. |
| `oidcRp.maxRedirectUris` | `STS_OIDC_RP_MAX_REDIRECT_URIS` | `20` | yes | The most redirect URIs `sts-admin-console` and `sts-user-portal` may carry before a sign-in at a new address stops adding its callback. **Learning happens only in development mode with `global.publicBaseUrl` empty**; in product mode an address the entry does not carry is REFUSED, and a pinned base is never learnt. |
| `oidcRp.renewBeforeExpiryS` | `STS_OIDC_RP_RENEW_BEFORE_EXPIRY_S` | `60` | yes | How long before their ID Token or access token runs out the console and the portal renew them with the refresh token grant, on the next request. **The renewal is inside the same session** — same cookie, same page, no sign-in — and a session renews for at most the refresh token's lifetime from its sign-in (`oauth2.refreshTokenTtlS`, or the client's `oauthRefreshTokenTtlS`). `0` renews only once they have run out. |
| `security.passwordHashLogN` | `STS_SECURITY_PASSWORD_HASH_LOG_N` | `15` | yes | log2 of scrypt's N for a NEWLY stored password, client secret, activation token or recovery code; 14 is the floor. A stored hash carries its own parameters and keeps verifying. |
| `security.passwordHashR` | `STS_SECURITY_PASSWORD_HASH_R` | `8` | yes | scrypt's block size for a new hash. |
| `security.passwordHashP` | `STS_SECURITY_PASSWORD_HASH_P` | `1` | yes | scrypt's parallelism for a new hash. |
| `security.passwordResetTtlMinutes` | `STS_SECURITY_PASSWORD_RESET_TTL_MINUTES` | `60` | yes | How long a password reset link an administrator issues from a person's `/admin/users` page stays usable at `/portal/reset-password`. Issuing one also removes the person's current password and signs them out everywhere, so the link is the only way back in until it is used or another is issued. |
| `credentials.factorScanLimit` | `STS_CREDENTIALS_FACTOR_SCAN_LIMIT` | `5000` | yes | How many directory entries the second-factor columns on `/admin/users` and `GET /admin-api/mfa` read before stopping; the reply says when it stopped. |

### OAuth 2.0 / OIDC

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `oauth2.issuer` | `STS_OAUTH2_ISSUER` | *(empty)* | yes | The `issuer` in the RFC 8414 and OpenID Provider metadata, and the `iss` of every token signed here. |
| `oauth2.rfc9700` | `STS_OAUTH2_RFC9700` | `false` | **restart** — it decides whether the main port is bound as HTTPS (global.https), and a listener is bound when the process starts. A **trust realm** may carry it even so: a realm binds no socket, so only the mode's checks change | Enforce RFC 9700 (OAuth 2.0 Security Best Current Practice) on the authorization flow: exact-string redirect URI matching with the loopback port exception, no open redirects, no http redirect URI off the loopback, PKCE required of public clients with S256 only, PKCE downgrade and value-reuse refused, a nonce required with any id_token, and no response type that issues an access token from the authorization endpoint. |
| `oauth2.oauth21` | `STS_OAUTH2_OAUTH21` | `false` | **restart** — it turns RFC 9700 mode on, which decides whether the main port is bound as HTTPS (global.https). A **trust realm** may carry it even so: a realm binds no socket | Enforce the OAuth 2.1 Authorization Framework (draft-ietf-oauth-v2-1-16, still an Internet-Draft). It turns RFC 9700 mode on and adds PKCE for confidential clients (unless one relies on the OpenID Connect nonce), `code_challenge_method` required, a client that registered its own redirect URI (`oauth2.redirectUris` is not read), a token request naming an undeclared client refused, a presented credential that must verify, one authentication method per request, client credentials for authenticated clients only, a JWT client assertion addressed to the issuer alone, no SAML client authentication, no repeated parameters, a ten-minute code and `error_description`'s grammar. A token request may omit `redirect_uri`, and an authorization request may omit it when the client registered one. `GET /oauth2/oauth21` lists every requirement. |
| `oauth2.fapi` | `STS_OAUTH2_FAPI` | `off` | **restart** — a profile turns RFC 9700 mode on, which decides whether the main port is bound as HTTPS (global.https). A **trust realm** may carry it even so, and so may a **named authorization server** (its `fapi` member, or `off` to opt out) | A FAPI security profile. `1-baseline` is FAPI 1.0 Part 1 (final): RFC 9700 mode on, and beyond it confidential clients authenticating with mTLS, `private_key_jwt` or `client_secret_jwt` (the secret methods refused at registration, the token and PAR endpoints), RSA keys of 2048 bits and EC keys of 160, PKCE S256 for every client, `redirect_uri` sent and https, `nonce` with `openid` and `state` without it, the person's own consent (a global consent does not count), one client per request, and unbound access tokens of at most 600 seconds. `1-advanced` is FAPI 1.0 Part 2 (final) on top: a signed request object (`exp` and `nbf` within 60 minutes, `aud` the issuer), `code id_token` or `code` with JARM, sender-constrained access tokens only, `tls_client_auth`, `self_signed_tls_client_auth` or `private_key_jwt` and no public client, PS256 or ES256 for every signature, and PKCE only for pushed requests. `2-security` is the FAPI 2.0 Security Profile (final), a profile of its own: confidential clients by mTLS or `private_key_jwt`, sender-constrained tokens by mTLS or DPoP, PAR required, `code` only, PKCE S256, codes of 60 seconds, request_uris under 600, no refresh-token rotation unless `oauth2.refreshTokenRotation` forces it, an `iat`/`nbf` over 60 seconds ahead refused, and PS256, ES256 or EdDSA. `2-message-signing` is FAPI 2.0 Message Signing (final) on top: a JAR-signed request object required at PAR (`exp`/`nbf` within 60 minutes, `aud` the issuer), JARM required, and signed RFC 9701 introspection responses. `GET /oauth2/fapi` lists every requirement. |
| `oauth2.fapiRequireMtls` | `STS_OAUTH2_FAPI_REQUIRE_MTLS` | `false` | yes | Under `oauth2.fapi=1-advanced`, accept only a TLS client certificate (RFC 8705) as the sender constraint. Off, a DPoP-bound token counts too. |
| `oauth2.accessTokenSigningAlg` | `STS_OAUTH2_ACCESS_TOKEN_SIGNING_ALG` | `default` | yes | The JWS algorithm of access and refresh tokens, by this realm's key for it: RS256, PS256, ES256, EdDSA and the rest of the classical table. `default` is RS256, or PS256 under FAPI 1.0 Advanced. A named authorization server may carry its own `access_token_signing_alg`. |
| `oauth2.jarmResponseLifetimeS` | `STS_OAUTH2_JARM_RESPONSE_LIFETIME_S` | `600` | yes | The `exp` of a JWT-secured authorization response (JARM), in seconds after it is signed; at most ten minutes. |
| `oauth2.delegatedPermissionsEnforced` | `STS_OAUTH2_DELEGATED_PERMISSIONS_ENFORCED` | `false` | yes | REFUSE an authorization or token request that asks for a permission the client has not been granted, IN DEVELOPMENT MODE — product mode always refuses one, whatever this says. A permission is defined on a resource application — a base URI and a name, joined into `https://example.com/write` — and granted to a client application on its own entry; `/admin/delegation` is the register and defines both. With this OFF (the default) in development an ungranted permission is still honoured: the token is audienced to the base URI and carries the permission name on its scope claim exactly as a granted one would, and the console marks it. With it ON the same request is refused `invalid_scope` at the AUTHORIZATION endpoint — where the client can still be told — and at the token endpoint for the grants that never reach it. A scope naming no defined permission is unaffected in both modes. It does NOT re-judge a grant already issued. |
| `oauth2.consentRequired` | `STS_OAUTH2_CONSENT_REQUIRED` | **`true`** — the one policy here that is on by default | yes | ASK THE PERSON before the authorization endpoint issues anything for a scope they have not already agreed to for that application. The first time a given username signs in to a given `client_id` for a given scope, `/oauth2/consent` is drawn listing the scopes that are new; nothing is issued until they press Allow, and Deny returns `access_denied` to the client. The answer is written to `oauthConsent` on that person's own entry under `ou=users` — one value per (person, application, scope), spelled `<when> <scope> <client_id>` — so the second sign-in is silent and an `ldapsearch` can read what somebody agreed to. A delegated permission is recorded by its WHOLE identifier (`https://example.com/write`) and never by the bare permission name, because two resources may each expose a `read`. `oauthGlobalConsent` on an APPLICATION's entry consents a scope for everybody who signs in to it and writes nothing about anybody — an override rather than a record, so removing it asks everybody again. `prompt=consent` asks again whatever is on the entry; `prompt=none` with something outstanding is `consent_required`. With this OFF nothing is asked and nothing is recorded, which is what this service did before the screen existed — it is NOT "everybody consented". Withdrawing a consent revokes what was issued under it and the refresh grant re-checks consent (#172). `/admin/consent` is the register. |
| `oauth2.refreshRequiresConsent` | `STS_OAUTH2_REFRESH_REQUIRES_CONSENT` | **`true`** | yes | WHETHER THE REFRESH GRANT REFUSES A GRANT NOBODY CONSENTED TO. While consent is required (`oauth2.consentRequired`, or a FAPI 1.0 profile), a refresh token issued at the authorization endpoint is renewed only if every scope it carries was covered, when it was granted, by the person's own recorded consent or the application's global consent; otherwise `invalid_grant` (`STS-OAUTH-0616`). A WITHDRAWN consent is refused whatever this says. **Warning: turning this off renews grants that nobody agreed to** — a client that obtained a refresh token while consent was off keeps renewing it, while the person is absent if it holds `offline_access`. |
| `oauth2.tokenExchangeRefreshToken` | `STS_OAUTH2_TOKEN_EXCHANGE_REFRESH_TOKEN` | `when-requested` | yes | WHETHER AN RFC 8693 TOKEN EXCHANGE HANDS BACK A `refresh_token` beside the exchanged access token. Section 2.2.1 makes it OPTIONAL and names the case it is for: a client that must keep reaching a resource "even when the original credential is no longer valid" — the user-not-present case, where there is no session by design. Three values. `when-requested` is the default and is section 2.1 read literally — the client asks with `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` and gets one only if it did. `never` refuses the ask silently: the exchange still succeeds, with no refresh token in it, which is what this service did before the parameter was implemented. `always` hands one to every exchange whether it asked or not, which is how several deployed authorization servers behave and is the path a client written against the other two has never run. What comes back is an ORDINARY refresh token of this service in every case — redeemable at the refresh grant, revocable, subject to `oauth2.refreshTokenTtlS`, rotated wherever rotation is required (either compliance mode, or `oauth2.refreshTokenRotation`), and bound to the DPoP key or client certificate the exchange was made with — and `issued_token_type` says `access_token` throughout, because it describes the token in the `access_token` member. `oauthTokenExchangeRefreshToken` on the CLIENT application's entry overrides it for that client alone. |
| `oauth2.breakIdTokenNonce` | `STS_OAUTH2_BREAK_ID_TOKEN_NONCE` | `false` | yes | Put a DELIBERATELY WRONG nonce in every ID Token that should carry one. DEVELOPMENT MODE ONLY: ignored in a product realm and refused there on write. |
| `oauth2.refreshIdleSeconds` | `STS_OAUTH2_REFRESH_IDLE_SECONDS` | `86400` | yes | In RFC 9700 mode, how long a refresh CHAIN may go unused before it stops working — section 2.2.2 says a refresh token SHOULD expire after a period of client inactivity, and says the period is deployment-dependent, which is why this is a setting rather than a constant. |
| `oauth2.revokeRefreshOnLogout` | `STS_OAUTH2_REVOKE_REFRESH_ON_LOGOUT` | `true` | yes | In every mode (#123), end a browser sign-on session and every refresh token issued ON that session without `offline_access` is revoked — OpenID Connect Back-Channel Logout 1.0 section 2.7's SHOULD. A token granted `offline_access` is kept. |
| `oauth2.sessionManagement` | `STS_OAUTH2_SESSION_MANAGEMENT` | `false` | yes | OpenID Connect Session Management 1.0 (#121). On: `check_session_iframe` in discovery, `session_state` on every OpenID Connect authentication response to an http(s) redirect URI, the OP iframe at `/oauth2/check_session` (framable only by the realm's registered redirect-URI origins), and the OP browser state as the script-readable cookie `sts_op_browser_state` (`SameSite=None` on an HTTPS port). Off by default: it adds a cross-site cookie, and browsers blocking third-party cookies defeat it anyway. |
| `oauth2.frontchannelLogout` | `STS_OAUTH2_FRONTCHANNEL_LOGOUT` | `true` | yes | OpenID Connect Front-Channel Logout 1.0: the two discovery members, the `sid` claim on an ID Token issued on a browser sign-on session, and a hidden iframe per registered `frontchannel_logout_uri` on every sign-out — with `iss` and `sid` where the client registered `frontchannel_logout_session_required`. Off, none of the three happens; `sid` stays while `oauth2.backchannelLogout` is on, so only both off restores the tokens issued before either feature existed. |
| `oauth2.frontchannelLogoutWaitS` | `STS_OAUTH2_FRONTCHANNEL_LOGOUT_WAIT_S` | `3` | yes | After an `/oauth2/logout` that notified relying parties by Front-Channel Logout, the seconds the sign-out page waits for their iframes to load before a `<meta>` refresh returns the browser to the checked `post_logout_redirect_uri` (section 4). The link stays beside it. `0` returns only when the link is followed. |
| `oauth2.backchannelLogout` | `STS_OAUTH2_BACKCHANNEL_LOGOUT` | `true` | yes | OpenID Connect Back-Channel Logout 1.0: `backchannel_logout_supported` and `backchannel_logout_session_supported` in discovery, the `sid` claim, and — whenever a session ends, by any door, by an account being disabled, or by EXPIRY — a signed (and where registered encrypted) Logout Token POSTed to every relying party on it that registered a `backchannel_logout_uri`. Each delivery is a persisted row sent once for the cluster and retried by any node; through the outbound policy (`federation.outbound`, https with the certificate verified, no internal address in product mode). |
| `oauth2.backchannelLogoutOnExpiry` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_ON_EXPIRY` | `true` | yes | Send the Logout Tokens when a session EXPIRES — its lifetime ran out, or it went idle — as well as when somebody signs out. Off for a deployment whose relying parties deliberately outlive the provider's idle timeout, or a test that wants an expiry silent. Front-channel logout cannot follow an expiry either way: it needs the browser. |
| `oauth2.backchannelLogoutTokenTtlS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_TOKEN_TTL_S` | `120` | yes | How far in the future a Logout Token's `exp` is — the specification's "at most two minutes". A token is signed once and resent unchanged while it is good; one that would expire before a retry is signed again with the same `jti`. |
| `oauth2.backchannelLogoutAttempts` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_ATTEMPTS` | `3` | yes | How many times one Logout Token is POSTed before the delivery becomes a dead letter. Only a timeout, a connection failure, a 5xx, 408 or 429 is retried; a 400 is final (section 2.8), and so is an outbound-policy refusal. |
| `oauth2.backchannelLogoutTimeoutMs` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_TIMEOUT_MS` | `5000` | yes | How long one POST may take. Nobody waits on it — the sign-out has already answered. |
| `oauth2.backchannelLogoutBackoffMs` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_BACKOFF_MS` | `1000` | yes | The wait before the second attempt, doubling before each one after. |
| `oauth2.backchannelLogoutLeaseMs` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_LEASE_MS` | `60000` | yes | How long one process holds its claim on one delivery attempt. A process that dies mid-attempt has it taken over after this, and the claim's time fences the stalled process out when it wakes. Never less than one request timeout and a second. |
| `oauth2.backchannelLogoutSweepS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_SWEEP_S` | `10` | yes | How often every process looks for deliveries that are due — a retry whose backoff has passed, a lease that lapsed, a row restored after a restart. |
| `oauth2.backchannelLogoutConcurrency` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_CONCURRENCY` | `8` | yes | How many due deliveries one process attempts at once. Per process, like every other cap here. |
| `oauth2.backchannelLogoutRetentionS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_RETENTION_S` | `86400` | yes | How long a delivery is kept after it was queued. A row still pending when this passes is dead-lettered, so nothing is pending for ever. |
| `oauth2.backchannelLogoutMaxRows` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_MAX_ROWS` | `2000` | yes | The most deliveries one realm keeps; past it the oldest FINISHED rows go first. |
| `oauth2.backchannelLogoutSummaryS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_SUMMARY_S` | `60` | yes | At most one log line per realm per interval, counting what was sent, retried, taken over and dead-lettered — never a line per attempt. |
| `oauth2.eddsaCurve` | `STS_OAUTH2_EDDSA_CURVE` | `Ed25519` | yes | Which Edwards curve an `EdDSA` signature is made on (`Ed25519` or `Ed448`). RFC 8037 registers ONE algorithm value for both curves and puts the curve in the key itself, so a client registering `id_token_signed_response_alg="EdDSA"` has no way to say which it wants — this is that way. BOTH keys are published in the JWKS whatever this is set to, with different kids, so a verifier follows the kid and needs to know nothing about this setting. |
| `oauth2.clientAssertionSkewS` | `STS_OAUTH2_CLIENT_ASSERTION_SKEW_S` | `60` | yes | How far out an assertion's exp, nbf and iat may be and still be accepted (RFC 7523 section 3). It applies to BOTH halves of that profile — the `client_assertion` of section 2.2 and the `assertion` of the section 2.1 grant — because it answers "how far out may somebody else's clock be" and this service has no reason to hold two opinions about that. Sixty seconds is the usual allowance for two machines that are not synchronised. |
| `oauth2.jwtBearerGrant` | `STS_OAUTH2_JWT_BEARER_GRANT` | `true` | yes | Whether the token endpoint performs `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 section 2.1). The metadata advertises the grant only while it is on, because a `grant_types_supported` member is a promise. It does NOT affect section 2.2 — client authentication by assertion — which is a different feature sharing a document format. |
| `oauth2.jwtBearerRequireRegisteredIssuer` | `STS_OAUTH2_JWT_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Whether that grant is refused when no application in the realm declares the assertion's `iss` on `oauthAssertionIssuer`. **ON, and it is one of only two refusals here that default to on** — federation is the other, for the same reason. Turning it off does not make the grant accept unsigned assertions; the signature still has to verify against a key registered for the issuer or a certificate this service issued. |
| `oauth2.jwtBearerMaxLifetimeS` | `STS_OAUTH2_JWT_BEARER_MAX_LIFETIME_S` | `300` | yes | The most seconds between an assertion's `iat` and its `exp` that this authorization server will accept in an RFC 7523 grant. RFC 7521 section 5.2 invites a server to refuse an assertion whose lifetime is unreasonable and leaves "unreasonable" to it; a short life is the whole difference between an assertion and a long-lived credential somebody has to be able to revoke. ZERO switches the check off, which is the way to exercise a client that mints day-long assertions. An assertion with no `iat` is measured from NOW to its `exp` — so leaving out the optional claim is not a way round the ceiling. IN PRODUCT MODE the same ceiling also applies to an RFC 7523 CLIENT assertion (private_key_jwt, client_secret_jwt), which there must carry an `exp` as well; development leaves client assertions uncapped, as it always did. |
| `oauth2.saml2BearerGrant` | `STS_OAUTH2_SAML2_BEARER_GRANT` | `true` | yes | Whether the token endpoint performs `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer` (RFC 7522 section 2.1). The metadata advertises the grant only while it is on. **It is a separate setting from `oauth2.jwtBearerGrant` and not the same switch**: RFC 7522 and RFC 7523 are two profiles of one framework and a deployment legitimately offers one and not the other, so a single switch would make "turn the JWT grant off" also turn off a grant a SAML deployment depends on. It does NOT affect section 2.2 — client authentication by SAML assertion. |
| `oauth2.saml2BearerRequireRegisteredIssuer` | `STS_OAUTH2_SAML2_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Whether that grant is refused when no application in the realm declares the assertion's `<Issuer>` on `oauthSamlAssertionIssuer`. **ON**, for the reason the JWT row above is on. Turning it off does not make the grant accept unsigned assertions, and it does not make it accept a certificate this service holds no registration for: a SAML assertion is only ever verified against a certificate registered against the asserting party under the RFC 7522 attributes, and there is no setting that changes that. |
| `oauth2.saml2BearerMaxLifetimeS` | `STS_OAUTH2_SAML2_BEARER_MAX_LIFETIME_S` | `300` | yes | The most seconds between a SAML assertion's `IssueInstant` and its expiry that this authorization server accepts. RFC 7522 section 3 item 6 says a server may reject an assertion whose `NotOnOrAfter` is unreasonably far in the future and leaves "unreasonable" to it. Zero switches the check off. The expiry it measures to is the `<Conditions>` `NotOnOrAfter` where there is one and the `<SubjectConfirmationData>` one otherwise, which is item 4's own ordering. |
| `oauth2.assertionReplayCacheSize` | `STS_OAUTH2_ASSERTION_REPLAY_CACHE_SIZE` | `1000` | yes | How many unexpired rows the USED-ASSERTION HISTORY holds per trust realm: every RFC 7523 JWT and RFC 7522 SAML assertion accepted, as client authentication or as a grant, in ONE history. The history persists in the ldif and postgres stores in both modes, so this bounds a file or a table as well as memory. **A FULL HISTORY REFUSES THE NEXT ASSERTION RATHER THAN FORGETTING A LIVE ONE**: dropping the oldest entry whether or not it had expired would let a captured assertion be replayed as soon as enough newer ones had pushed it out. Expired rows are swept first, so the refusal is reached only by that many assertions being live at once — raise this, or shorten oauth2.jwtBearerMaxLifetimeS, rather than accept a replay window. /admin/used-assertions lists what is held. |
| `oauth2.dpopNonceRequired` | `STS_OAUTH2_DPOP_NONCE_REQUIRED` | `false` | yes | Require every DPoP proof to carry a nonce this server supplied (RFC 9449 sections 8 and 9), which turns the first request of a session into a 401 or 400 and a retry. It makes proofs FRESHER and never makes them mandatory: a request with no DPoP header is still a Bearer request. PER TRUST REALM: a realm turning it on turns it on for that realm alone. In development POST /dpop/nonce-mode writes this setting for the realm it is reached in; in product that endpoint refuses and this row — through /admin/oauth2 or POST /admin-api/config/set, both behind a credential — is the only way to change it. |
| `oauth2.dpopIatSkewS` | `STS_OAUTH2_DPOP_IAT_SKEW_S` | `300` | yes | How far a DPoP proof's `iat` may be from now, either way (RFC 9449 section 11.1). It is how long a captured proof stays useful for the same method and URI, so it is short; the jti replay cache remembers a proof for twice this, so the two cover the same span. |
| `oauth2.dpopNonceTtlS` | `STS_OAUTH2_DPOP_NONCE_TTL_S` | `300` | yes | How long a server-supplied DPoP nonce is accepted after it was handed out. Only read while oauth2.dpopNonceRequired is on. |
| `oauth2.refreshTokenRotation` | `STS_OAUTH2_REFRESH_TOKEN_ROTATION` | `false` | yes | Issue a NEW refresh token on every refresh, refuse the one that was spent, and treat a replay as a compromise — the whole token family is revoked, not just the token replayed (OAuth 2.1 section 4.3.1, RFC 9700 section 4.14.2). **RFC 9700 mode and OAuth 2.1 mode already do this for every client**, so this row is how to have it with both modes off; turning it off while a mode is on changes nothing, because the mode is the stricter answer. What it does NOT bring with it is the rest of RFC 9700 section 2.2.2 — the idle timeout, the client binding and the scope subset check stay behind `oauth2.rfc9700`, because none of them is what asking for rotation asked for. A refresh token minted before it was turned on carries no family and is rotated from its next use, so there is nothing to migrate. |
| `oauth2.refreshTokenRequireDpop` | `STS_OAUTH2_REFRESH_TOKEN_REQUIRE_DPOP` | `false` | yes | REFUSE to issue a refresh token to a request carrying no DPoP proof, and refuse the refresh grant unless the presented refresh token is bound (`cnf.jkt`) to the key that proves this request (RFC 9449 section 5). With it on, a confidential client's refresh token is bound too; off, section 5 leaves one unbound, since its client authentication constrains it (#176). **Neither OAuth 2.1 nor RFC 9700 asks for this** — section 4.3.1 wants a public client's refresh token sender-constrained *or* rotated, and this service rotates — so it is off unless somebody sets it. An UNBOUND refresh token is refused rather than bound on first use: binding it here would let whoever is holding it choose the key, which is the opposite of the guarantee the setting was turned on for. The WHOLE token request is refused rather than the refresh token quietly dropped, so a client never receives an access token it can use beside a refresh token it cannot. **Nothing is exempt from this row and nothing needs to be**: `/admin` and `/portal` are OpenID Connect clients of this service and carry a DPoP key of their own, proving it on every back-channel token call, so turning this on does not lock an operator out of either. The two clients named on the row below are exempt from THAT row alone. |
| `oauth2.refreshTokenRequireMtls` | `STS_OAUTH2_REFRESH_TOKEN_REQUIRE_MTLS` | `false` | yes | The same refusal for RFC 8705: no refresh token is issued over a connection carrying no verified client certificate, and the refresh grant requires the presented token's `cnf["x5t#S256"]` to match the certificate on THIS connection. Section 7.1 still passes a client that authenticated with `tls_client_auth` or `self_signed_tls_client_auth` on the same request and owns the token — its refresh token is bound to the CLIENT, so it may rotate its certificate. **It needs the main port bound as HTTPS** (`global.https`), which is the only way a certificate can be asked for at all; with HTTP every affected request is refused instead. The seeded `sts-admin-console` and `sts-user-portal` clients are EXEMPT from this row and nothing else: they redeem over a loopback call from this process to itself, where there is no certificate to present and nobody on the other end who is not already this process. `sts-debugger-ui` is deliberately NOT exempt — the embedded debugger is an ordinary client and is configured to match the realm it points at. |
| `oauth2.accessTokenRequireDpop` | `STS_OAUTH2_ACCESS_TOKEN_REQUIRE_DPOP` | `false` | yes | Refuse any inbound request that presents an access token as anything other than a proved, DPoP-bound token — the token must carry `cnf.jkt` and the request must carry a proof for that key. It covers every surface that accepts a PRESENTED access token: UserInfo, the RFC 9470 step-up resource, the three OpenID4VCI endpoints, `/scim/v2`, the Shared Signals endpoints, `/admin-api` and the embedded debugger's listener. It does not cover what is not an OAuth access token presented as a credential: GNAP's own tokens, an RFC 7592 registration access token, or the endpoints that take a token as a PARAMETER (introspection, revocation, token exchange). **This is a resource-side refusal only**: the token endpoint goes on minting Bearer tokens, which those resources then refuse — which is exactly what lets a client be tested against the refusal. A token this service did not issue is held to it too, because the confirmation a token carries can be read without trusting the token. `/admin/api-explorer` stops working while it is on, because its script sends a plain `Bearer` header. |
| `oauth2.accessTokenRequireMtls` | `STS_OAUTH2_ACCESS_TOKEN_REQUIRE_MTLS` | `false` | yes | The RFC 8705 half of the row above, at the same surfaces: a presented access token must carry `cnf["x5t#S256"]` and the connection must carry that certificate. **It needs the main port bound as HTTPS** (`global.https`), and the debugger's listener ASKS for a client certificate so that a bound token can be presented there at all — asked for, never required, the posture the main port takes. Where a certificate cannot be asked for the affected request is refused with `STS-OAUTH-0527` rather than let through. |
| `oauth2.openRegistration` | `STS_OAUTH2_OPEN_REGISTRATION` | `false` | yes | Whether POST /oauth2/register (RFC 7591) accepts a registration from anybody who can reach it IN PRODUCT MODE. Development always does — it is how a client under test registers itself — and this setting changes nothing there. In product it is OFF, the endpoint refuses with `access_denied` naming this setting, and `registration_endpoint` is left out of both discovery documents: a published endpoint that refuses every caller is a promise broken. Create applications through /admin or /admin-api instead, which require a credential. Turning it on is a decision to let the internet mint confidential clients on this authorization server. |
| `oauth2.softwareStatementRequireTrustedIssuer` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRE_TRUSTED_ISSUER` | `true` | yes | Whether registration refuses a `software_statement` whose issuer nothing in this realm trusts, with `unapproved_software_statement`, in both modes. Off, such a statement is accepted UNVERIFIED: its claims lose to the JSON, the entry records it as untrusted, and it never opens a closed endpoint. A malformed, unsigned, badly signed or expired statement is refused either way. |
| `oauth2.softwareStatementOpensRegistration` | `STS_OAUTH2_SOFTWARE_STATEMENT_OPENS_REGISTRATION` | `true` | yes | Whether a registration carrying a TRUSTED software statement is accepted where `POST /oauth2/register` is otherwise closed (product mode, `oauth2.openRegistration` off). While on, `registration_endpoint` stays advertised, and a client registered this way must present a trusted statement from the same issuer with every RFC 7592 update. |
| `oauth2.softwareStatementRequired` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRED` | `false` | yes | Whether registration and RFC 7592 updates refuse a document carrying no `software_statement`, with `invalid_software_statement`. |
| `oauth2.authorizationDetailsMaxEntries` | `STS_OAUTH2_AUTHORIZATION_DETAILS_MAX_ENTRIES` | `20` | yes | How many objects one RFC 9396 `authorization_details` array may carry at the authorization, token and pushed authorization request endpoints. A longer array is refused `invalid_authorization_details` before any type's schema is run. |
| `oauth2.requireSignedRequestObject` | `STS_OAUTH2_REQUIRE_SIGNED_REQUEST_OBJECT` | `false` | yes | RFC 9101 section 10.5 for the whole realm: an authorization request with no request object, or with an unsigned one, is refused. Published as `require_signed_request_object`, and `none` leaves `request_object_signing_alg_values_supported`. A client's own `require_signed_request_object` and a named authorization server's member do the same for that client or that server. |
| `oauth2.requireRequestObjectType` | `STS_OAUTH2_REQUIRE_REQUEST_OBJECT_TYPE` | `false` | yes | Whether a request object must carry `typ: oauth-authz-req+jwt`. Off, a missing `typ` or `JWT` is accepted and only a JWT typed as something ELSE (section 10.8) is refused. |
| `oauth2.requireRequestObjectIssuerAudience` | `STS_OAUTH2_REQUIRE_REQUEST_OBJECT_ISSUER_AUDIENCE` | `false` | yes | Whether a request object must carry `iss` and `aud`. They are checked wherever present either way: `iss` must be the client and `aud` this authorization server's issuer or its authorization endpoint. |
| `oauth2.requestUriTimeoutMs` | `STS_OAUTH2_REQUEST_URI_TIMEOUT_MS` | `5000` | yes | How long fetching a registered `request_uri` may take before the request is refused `invalid_request_uri`. |
| `oauth2.requestUriMaxBytes` | `STS_OAUTH2_REQUEST_URI_MAX_BYTES` | `65536` | yes | The largest request object a `request_uri` may answer with; a longer answer is abandoned and refused. |
| `oauth2.requestObjectJtiOnce` | `STS_OAUTH2_REQUEST_OBJECT_JTI_ONCE` | `true` | yes | Whether a request object's `jti` is accepted once. It is spent when an authorization response is issued on the object or a pushed authorization request keeps it, and a replay after that is refused with `invalid_request_object`. An object with no `jti` is accepted either way. |
| `oauth2.requestObjectJtiRetentionS` | `STS_OAUTH2_REQUEST_OBJECT_JTI_RETENTION_S` | `3600` | yes | How long a spent `jti` is remembered when its request object has no `exp`. After this a replay of such an object is accepted; one with `exp` is remembered until then plus `oauth2.clientAssertionSkewS`. |
| `oauth2.clientJwksCacheS` | `STS_OAUTH2_CLIENT_JWKS_CACHE_S` | `300` | yes | How long a JSON Web Key Set fetched from a client's registered `jwks_uri` is reused (#120). The fetch takes the federation outbound policy. Zero keeps a set for a second. |
| `oauth2.clientJwksRefetchS` | `STS_OAUTH2_CLIENT_JWKS_REFETCH_S` | `30` | yes | A client assertion or request object naming a `kid` the cached set lacks fetches the `jwks_uri` again, at most this often, so a client that rotated its keys is picked up without a made-up `kid` forcing a fetch per request. |
| `oauth2.requestUriCacheS` | `STS_OAUTH2_REQUEST_URI_CACHE_S` | `0` | yes | How long a fetched request object is reused for the same `request_uri` (OpenID Connect Core section 6.2). Zero fetches on every request — and the authorization endpoint runs each request twice, before and after sign-in. A fragment names a version, so a changed fragment is a different entry. |
| `oauth2.requestObjectEncryptionKeyBits` | `STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_KEY_BITS` | `2048` | yes | The size of the realm's RSA request object encryption key, published in the JWKS with `use: "enc"`. Read when a key set is made. |
| `oauth2.requestObjectEncryptionCurve` | `STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_CURVE` | `P-256` | yes | The curve of the realm's EC request object encryption key (ECDH-ES), published beside the RSA one. Read when a key set is made. |
| `oauth2.pushedAuthorizationRequests` | `STS_OAUTH2_PUSHED_AUTHORIZATION_REQUESTS` | `true` | yes | RFC 9126: offer `POST /oauth2/par` and publish `pushed_authorization_request_endpoint`. Off, the member is removed and the endpoint answers 404; a `request_uri` already issued stays usable. |
| `oauth2.requirePushedAuthorizationRequests` | `STS_OAUTH2_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` | `false` | yes | RFC 9126 section 4 for the whole realm: an authorization request that was not pushed is refused `invalid_request`. Published as `require_pushed_authorization_requests`. A client's own member and a named authorization server's do the same for that client or server. |
| `oauth2.parRequestUriLifetimeS` | `STS_OAUTH2_PAR_REQUEST_URI_LIFETIME_S` | `60` | yes | The `expires_in` of a pushed `request_uri`, 5 to 600 seconds. It covers the whole sign-in: the `request_uri` is read again after the sign-in and consent screens and spent when the authorization response is issued. |
| `oauth2.parMaxRequests` | `STS_OAUTH2_PAR_MAX_REQUESTS` | `10000` | yes | How many live pushed requests one realm holds. Expired ones are swept first; a full store refuses the next push 503 rather than forgetting a live one. |
| `oauth2.parMaxBodyBytes` | `STS_OAUTH2_PAR_MAX_BODY_BYTES` | `65536` | yes | The largest body `/oauth2/par` accepts; a larger one is 413. |
| `oauth2.parRequestsPerMinute` | `STS_OAUTH2_PAR_REQUESTS_PER_MINUTE` | `600` | yes | Pushes one client_id may make from one address per `security.rateLimitWindowS` before a 429 (the address bucket is ten times this). |
| `oauth2.parAllowUnregisteredRedirectUris` | `STS_OAUTH2_PAR_ALLOW_UNREGISTERED_REDIRECT_URIS` | `false` | yes | RFC 9126 section 2.4: a client that authenticated at the push may name a redirect URI it never registered. A public client never may; asked again when the `request_uri` is used. |
| `oauth2.stepUpAcrValues` | `STS_OAUTH2_STEP_UP_ACR_VALUES` | *(empty)* | yes | RFC 9470 section 3 at this service's own resource server (UserInfo, the OpenID4VCI endpoints, SCIM, Shared Signals): space-separated acr values, most preferred first. A token meeting none is challenged 401 `insufficient_user_authentication`. Ordered `0` < `1` < `mfa`. Empty requires nothing. |
| `oauth2.stepUpMaxAgeS` | `STS_OAUTH2_STEP_UP_MAX_AGE_S` | `-1` | yes | RFC 9470's `max_age` at the same endpoints: a token whose `auth_time` is older, or absent, is challenged. `-1` requires nothing; `0` is a real requirement. |
| `oauth2.softwareStatementLifetimeS` | `STS_OAUTH2_SOFTWARE_STATEMENT_LIFETIME_S` | `31536000` | yes | The `exp` of a software statement this realm issues, as seconds after issue, unless the issue request names its own. Zero issues one with no `exp`. |
| `oauth2.registeredSecretLifetimeS` | `STS_OAUTH2_REGISTERED_SECRET_LIFETIME_S` | `0` | yes | The `client_secret_expires_at` RFC 7591 section 3.2.1 publishes for a client registered at POST /oauth2/register, as seconds after registration. ZERO, the default, is that section's own "never", which is what this service always said. It is stamped when the client registers and is not moved by a later change. |
| `oauth2.registeredClientIdPrefix` | `STS_OAUTH2_REGISTERED_CLIENT_ID_PREFIX` | `sts-client-` | yes | What a client_id minted by POST /oauth2/register starts with, before its random part. RFC 7591 leaves the shape to the server; a prefix is how an operator tells a dynamically registered client from one created by hand in a list. |
| `oauth2.registeredClientIdBytes` | `STS_OAUTH2_REGISTERED_CLIENT_ID_BYTES` | `8` | yes | How many random bytes follow the prefix in a registered client_id, base64url-encoded. A client_id is not a secret, so this is about collisions and not about guessing. |
| `oauth2.registeredSecretBytes` | `STS_OAUTH2_REGISTERED_SECRET_BYTES` | `48` | yes | How many random bytes make a registered client's `client_secret` and its RFC 7592 `registration_access_token`. Both ARE secrets, which is why the floor is 16 bytes (128 bits). 48 by default (#202): a `client_secret_jwt` client signs with the UTF-8 octets of its base64url secret, and RFC 7518 section 3.2 requires at least the hash output, which product mode enforces — 48 bytes are 64 characters, enough for HS512. **Warning: below 24 even HS256 is refused in product mode, and below 48 HS512 is.** |
| `oauth2.authorizationCodeTtlS` | `STS_OAUTH2_AUTHORIZATION_CODE_TTL_S` | `300` | yes | How long an authorization code may wait to be redeemed. RFC 6749 section 4.1.2 recommends at most ten minutes. It is ALSO what RFC 9700 mode's transaction memory is measured from — a PKCE challenge or nonce is remembered for twice this — so the two cannot drift apart. A code already issued keeps the expiry it was minted with. |
| `oauth2.maxPendingTransactions` | `STS_OAUTH2_MAX_PENDING_TRANSACTIONS` | `500` | yes | How many authorization transactions RFC 9700 mode remembers to refuse a reused PKCE challenge or nonce. Past it the oldest is forgotten, and a forgotten one is a reuse check NOT made rather than a false refusal — which is the safe direction for this cache, because what it protects against is a client bug and not a captured credential. |
| `oauth2.maxRefreshTokenFamilies` | `STS_OAUTH2_MAX_REFRESH_TOKEN_FAMILIES` | `2000` | yes | How many refresh tokens are tracked for rotation and replay detection wherever rotation is required — RFC 9700 mode, OAuth 2.1 mode or `oauth2.refreshTokenRotation`. When it is full, EXPIRED ones are forgotten first, then ROTATED ones (already revoked, so a replay of one is still refused — what is lost is the whole-family revocation that replay would trigger), and only then the oldest live one, with a warning. A live one forgotten still works; its next rotation starts a new family. Raise it for a deployment with more concurrently live refresh tokens than this. |
| `oauth2.signedMetadataAlgorithm` | `STS_OAUTH2_SIGNED_METADATA_ALGORITHM` | `RS256` | yes | The JWS algorithm of the `signed_metadata` member of the RFC 8414 document, the OpenID Provider Configuration and the OID4VCI issuer metadata. Every value is one this realm holds a key for, and every key is in /oauth2/jwks under its own kid. The post-quantum algorithms are deliberately not offered: discovery is the most-fetched endpoint here and is signed on the request thread. |
| `oauth2.signedMetadataCacheS` | `STS_OAUTH2_SIGNED_METADATA_CACHE_S` | `60` | yes | How long one signature over an unchanged metadata document is served before it is signed again. ZERO signs per request. The ceiling is half the signature's own hour, so a caller is never handed one about to expire. |
| `oauth2.maxSignedMetadataEntries` | `STS_OAUTH2_MAX_SIGNED_METADATA_ENTRIES` | `64` | yes | How many distinct signed metadata documents are cached. The key includes the base URL a request arrived on, which comes off the Host header, so it has to be bounded. |
| `oauth2.basicAuthRealm` | `STS_OAUTH2_BASIC_AUTH_REALM` | `sts` | yes | The `realm` in the `WWW-Authenticate: Basic` challenge the token endpoint answers a failed client_secret_basic with (RFC 7617 section 2). A browser shows it in its credential prompt, which is why a deployment names itself here. |
| `oauth2.maxAuthorizationServerProfiles` | `STS_OAUTH2_MAX_AUTHORIZATION_SERVER_PROFILES` | `200` | yes | How many path-selected authorization server profiles are RECORDED. A name past it is still served with the defaults and simply not recorded, because the name comes off a URL path and a load generator must not take the feature away from the names that matter. |
| `oauth2.maxRequestedClaims` | `STS_OAUTH2_MAX_REQUESTED_CLAIMS` | `64` | yes | The most claims one OpenID Connect Core section 5.5 claims request may name, across its members. The request rides inside the access token, so this also bounds the token. |
| `oauth2.maxDevicesPerPerson` | `STS_OAUTH2_MAX_DEVICES_PER_PERSON` | `20` | yes | How many device entries (ou=devices) one person holds. A Native SSO sign-in from a device not seen before makes one; at the bound it replaces the person's least recently used device whose sign-on session has ended. |
| `oauth2.ciba` | `STS_OAUTH2_CIBA` | `false` | yes | Answer OpenID Connect Client-Initiated Backchannel Authentication (CIBA Core 1.0) at /oauth2/bc-authorize: a client names a person by a hint, the person approves on /portal/ciba, and the client polls, is pinged or is pushed its tokens. OFF by default: a new way in is something a realm turns on. |
| `oauth2.cibaDefaultExpiryS` | `STS_OAUTH2_CIBA_DEFAULT_EXPIRY_S` | `120` | yes | How long a backchannel authentication request waits for the person when the client sends no requested_expiry. |
| `oauth2.cibaMaxExpiryS` | `STS_OAUTH2_CIBA_MAX_EXPIRY_S` | `600` | yes | The longest a client's requested_expiry may make a request wait; a longer one is cut to this. |
| `oauth2.cibaIntervalS` | `STS_OAUTH2_CIBA_INTERVAL_S` | `5` | yes | The interval a poll-mode or ping-mode client is told to wait between token requests. Polling sooner is answered slow_down, and the interval grows by five seconds. |
| `oauth2.cibaMaxPendingPerPerson` | `STS_OAUTH2_CIBA_MAX_PENDING_PER_PERSON` | `5` | yes | How many backchannel authentication requests may wait for one person at once; more are refused access_denied, so no client can flood somebody's sign-in requests page. |
| `oauth2.cibaNotifyTimeoutMs` | `STS_OAUTH2_CIBA_NOTIFY_TIMEOUT_MS` | `5000` | yes | How long one ping or push to a client's notification endpoint may take. |
| `oauth2.cibaNotifyAttempts` | `STS_OAUTH2_CIBA_NOTIFY_ATTEMPTS` | `5` | yes | How many times a ping or push is tried before it is given up (dead-lettered). |
| `oauth2.cibaNotifyBackoffMs` | `STS_OAUTH2_CIBA_NOTIFY_BACKOFF_MS` | `2000` | yes | The wait before a failed ping or push is tried again, doubling each time. |
| `oauth2.cibaSweepS` | `STS_OAUTH2_CIBA_SWEEP_S` | `30` | yes | How often the oauth2.ciba-sweep scheduler job retries due notifications and expires unanswered requests. |
| `oauth2.idaTrustFrameworks` | `STS_OAUTH2_IDA_TRUST_FRAMEWORKS` | `urn:sts:local` | yes | The trust frameworks (OpenID Connect for Identity Assurance section 5.1) an administrator may record a person's identity verification under, comma-separated, and what discovery publishes as trust_frameworks_supported. The first is the framework a sign-in's own verification is recorded under. `urn:sts:demo` is reserved for development mode's invented verification. |
| `oauth2.idaAutomaticVerifications` | `STS_OAUTH2_IDA_AUTOMATIC_VERIFICATIONS` | `true` | yes | ON: a wallet sign-in with a credential this realm issued records an electronic_record verification, and a client certificate sign-in an electronic_signature one, of the claims the entry agrees with. OFF: only what an administrator records is released as verified_claims. |
| `pki.keyAlgorithm` | `STS_PKI_KEY_ALGORITHM` | `rsa-2048` | yes | Which key algorithm a new certificate authority is built with when the form names none: `rsa-2048`, `rsa-3072`, `rsa-4096`, `ec-p256`, `ec-p384`, `ec-p521` or `ed25519`. RSA 2048 because the LEAF this chain exists to issue signs a client assertion somebody else's OAuth library has to verify. |
| `pki.signatureAlgorithm` | `STS_PKI_SIGNATURE_ALGORITHM` | *(empty)* | yes | Which signature algorithm the tiers sign each other with. **Empty means "the right one for the key algorithm"**, which is what almost every deployment wants: an EC key's digest is decided by its CURVE, and a fixed value here would hand a P-521 key SHA-256 — legal, verifying, and nobody's intention. `sha1-rsa` and `sha1-ecdsa` are development mode only: product uses the key's default instead and refuses setting either, or a build naming one (#181). |
| `pki.alternativeKeyAlgorithm` | `STS_PKI_ALTERNATIVE_KEY_ALGORITHM` | `ml-dsa-87` | yes | The post-quantum key every certificate authority this service builds holds beside its classical one, in ITU-T X.509 (2019) clause 9.8's non-critical alternative-key extensions; each authority signs everything it issues twice, and a certificate in this service's own hierarchy whose alternative signature is missing or wrong is refused (`STS-PKI-0196`, `STS-PKI-0195`). Read at the next build; a hierarchy keeps what it was built with. One of `ml-dsa-87`, `ml-dsa-65`, `ml-dsa-44`, `slh-dsa-sha2-256s`, `slh-dsa-sha2-192s`, `slh-dsa-sha2-128s` or `none`. **Warning:** `none` builds classical-only authorities a quantum-capable attacker can forge; SLH-DSA costs seconds per certificate issued. |
| `pki.organisation` | `STS_PKI_ORGANISATION` | `sts` | yes | The `O=` every tier of a new hierarchy carries, and what the tiers are named after when the form gives no common names. |
| `pki.leafLifetimeDays` | `STS_PKI_LEAF_LIFETIME_DAYS` | `365` | yes | How long a signing certificate issued to an application or a person is good for when the request names no lifetime — every door that issues one. **Clamped** to the Issuing CA's own expiry rather than refused where it would overshoot. |
| `pki.personSelfService` | `STS_PKI_PERSON_SELF_SERVICE` | `true` | yes | Whether `/portal/signing-key` lets a person issue **themselves** an RFC 7523 or RFC 7522 key pair (one switch for both). The key can only assert about its own holder, so it is a credential for an account they are already signed in to. **Turning it off takes nobody's key away** — one already on an entry goes on verifying — and it stops new ones from the PORTAL only; `/admin/pki` and `POST /admin-api/pki/issue` are an operator's door and are unaffected. |
| `pki.personSelfServicePerIdentity` | `STS_PKI_PERSON_SELF_SERVICE_PER_IDENTITY` | `5` | yes | How many self-issued key pairs one person may generate on `/portal/signing-key` per `security.rateLimitWindowS` window. |
| `pki.personSelfServicePerAddress` | `STS_PKI_PERSON_SELF_SERVICE_PER_ADDRESS` | `5` | yes | The same limit per client ADDRESS, counted across everybody behind it — its own row so a deployment reached through one NAT can raise it without raising what one person may do. |
| `pki.personTlsClientCertificateMax` | `STS_PKI_PERSON_TLS_CLIENT_CERTIFICATE_MAX` | `5` | yes | How many still-valid TLS client certificates one person may issue themselves on `/portal/signing-key` — one per browser or device. Revoked and expired ones do not count; past it the portal refuses rather than revoking one somebody may still use. |
| `pki.rootLifetimeYears` | `STS_PKI_ROOT_LIFETIME_YEARS` | `0` | yes | How long a Root CA is built for when the build names no lifetime. **Zero is the `root-ca` profile's own twenty years.** |
| `pki.intermediateLifetimeYears` | `STS_PKI_INTERMEDIATE_LIFETIME_YEARS` | `0` | yes | The same for an Intermediate CA — at startup, for a realm created at runtime, and for a branch rebuilt under a replaced Root. Zero is the profile's ten. |
| `pki.issuingLifetimeYears` | `STS_PKI_ISSUING_LIFETIME_YEARS` | `0` | yes | The same for each Issuing CA. Zero is the profile's five. |
| `pki.maxStoredObjects` | `STS_PKI_MAX_STORED_OBJECTS` | `200` | yes | How many objects the Certificate & Key Configuration pane keeps per realm. **A full store refuses the next one** rather than discarding the oldest, which may carry a private key somebody kept. |
| `pki.revocationCheck` | `STS_PKI_REVOCATION_CHECK` | `auto` | yes | Whether a certificate PRESENTED to this service — on the main port (XACML, SCIM, RFC 8705 client authentication, a GNAP key proved by mutual TLS and `GET /tls/sign-in`), at the SPIRE Server API or in an assertion's `x5c` — is checked for revocation: `off`, `soft-fail` (refuse a revoked one), `hard-fail` (refuse one whose status could not be established too). One this service issued is looked up in its own register; one from another authority against the CRL it names. **`auto` is hard-fail in product mode and soft-fail in development.** |
| `pki.revocationRequireDistributionPoint` | `STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT` | `auto` | yes | Under hard-fail, whether a CA-issued foreign certificate naming no CRL and no OCSP responder (and no RFC 9608 `noRevAvail`) is refused. `auto` is `mode.refusesUnrevocableCertificates()`: refused in product (`STS-PKI-0190`), accepted in development; `on` refuses in both. **`off` accepts certificates nobody can ever revoke** — a stolen key under such an authority is good until it expires. |
| `pki.revocationFetchTimeoutMs` | `STS_PKI_REVOCATION_FETCH_TIMEOUT_MS` | `3000` | yes | How long fetching a foreign CRL may take. |
| `pki.revocationMaxCrlBytes` | `STS_PKI_REVOCATION_MAX_CRL_BYTES` | `1048576` | yes | The largest CRL fetched; a bigger answer is refused as unreachable. |
| `pki.revocationCrlCacheEntries` | `STS_PKI_REVOCATION_CRL_CACHE_ENTRIES` | `256` | yes | How many verified foreign CRLs (and remembered failures) are held in memory. |
| `pki.revocationCrlMaxAgeS` | `STS_PKI_REVOCATION_CRL_MAX_AGE_S` | `3600` | yes | A cached CRL is used until its own `nextUpdate` or this long after it was fetched, whichever is sooner. |
| `pki.revocationFailureRetryS` | `STS_PKI_REVOCATION_FAILURE_RETRY_S` | `60` | yes | How long an unreachable or unusable CRL is remembered before it is dialled again. Zero retries on every request. |
| `pki.revocationOcsp` | `STS_PKI_REVOCATION_OCSP` | `first` | yes | Whether the OCSP responder a foreign certificate names is asked (RFC 6960): `first` (before the CRL, which is the fallback), `after-crl` (only when the CRL gave no answer) or `off`. A signed `unknown` is never upgraded to good by a CRL; a CRL that revokes still wins. |
| `pki.revocationOcspMaxAgeS` | `STS_PKI_REVOCATION_OCSP_MAX_AGE_S` | `3600` | yes | How long an OCSP response with no `nextUpdate` is fresh after its `thisUpdate`, and the longest any response is cached. |
| `pki.revocationOcspRequireNonce` | `STS_PKI_REVOCATION_OCSP_REQUIRE_NONCE` | `false` | yes | Every OCSP request carries a nonce and a response echoing a different one is always refused. Turn this on to refuse a response that echoes none too — off by default, because the pre-produced responses most large responders serve cannot carry one. |
| `pki.revocationClockSkewS` | `STS_PKI_REVOCATION_CLOCK_SKEW_S` | `300` | yes | How far a CRL's or OCSP response's `nextUpdate` may be in the past, and an OCSP `thisUpdate` in the future, before it is refused. Zero is legal. |
| `pki.revocationCrlIssuersFile` | `STS_PKI_REVOCATION_CRL_ISSUERS_FILE` | *(empty)* | yes | A PEM file of certificates that may sign an INDIRECT CRL a certificate's `cRLIssuer` names. Also looked for in the presented chain, among this service's own authorities, and at the caIssuers address the CRL itself names; in every case it must carry `cRLSign` and chain to an authority the presented chain passes through. |
| `pki.revocationLdap` | `STS_PKI_REVOCATION_LDAP` | `ldaps` | yes | Whether ldap: and ldaps: CRL distribution points and caIssuers addresses are dialled: `ldaps` (TLS only, the directory's certificate verified), `ldaps-and-ldap` or `off`. An address not dialled is refused under hard-fail when it is all a certificate names (`STS-PKI-0188`). |
| `pki.revocationLdapCaFile` | `STS_PKI_REVOCATION_LDAP_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates an ldaps directory's certificate may chain to, beside node's own CA store. |
| `pki.revocationLdapDirectory` | `STS_PKI_REVOCATION_LDAP_DIRECTORY` | *(empty)* | yes | The directory (`ldaps://host:port`) a distribution point named relative to its CRL issuer is looked up in. Empty: such a name is not dialled. |
| `oauth2.accessTokenTtlS` | `STS_OAUTH2_ACCESS_TOKEN_TTL_S` | `3600` | yes | How long an access token is good for: its `exp` is this many seconds after it was signed, and it is the `expires_in` of every token response that carries one. One hour by default. |
| `oauth2.idTokenTtlS` | `STS_OAUTH2_ID_TOKEN_TTL_S` | `3600` | yes | How long an ID Token is good for. |
| `oauth2.refreshTokenTtlS` | `STS_OAUTH2_REFRESH_TOKEN_TTL_S` | `86400` | yes | The ABSOLUTE lifetime of a refresh token — the `exp` on the token itself, enforced in both modes by the refresh grant. |
| `oauth2.refreshTokenEncryptionAlg` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ALG` | `RSA-OAEP-256` | yes | EVERY REFRESH TOKEN IS A SIGNED JWT ENCRYPTED TO ITS OWN TRUST REALM — a compact JWE with `cty: JWT` (RFC 7519 section 11.2), opaque to the client as RFC 6749 section 1.5 already makes it. This picks the key management algorithm a new token is sealed under: any the JWE module implements (RSA-OAEP, RSA-OAEP-256, ECDH-ES and its three key-wrap variants, A128KW–A256KW, A128GCMKW–A256GCMKW, PBES2, `dir`; RSA1_5 is not offered). Each realm holds its own RSA key, EC key and secret, so a change strands no token already issued. An UNENCRYPTED refresh token is refused (`invalid_grant`, and `active: false` at introspection). |
| `oauth2.refreshTokenEncryptionEnc` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ENC` | `A256GCM` | yes | The JWE content encryption algorithm for refresh tokens — A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384 or A256CBC-HS512. |
| `oauth2.refreshTokenEncryptionKeyBits` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_KEY_BITS` | `2048` | yes | The RSA modulus of each realm's refresh-token encryption key. Reaches key sets made after the change; rotate a realm's keys to apply it. |
| `oauth2.refreshTokenEncryptionCurve` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_CURVE` | `P-256` | yes | The curve of each realm's refresh-token encryption EC key (for ECDH-ES): P-256, P-384 or P-521. Reaches key sets made after the change. |
| `oauth2.clockSkewS` | `STS_OAUTH2_CLOCK_SKEW_S` | `30` | yes | The allowance applied to `exp` and `nbf` EVERYWHERE this service reads back a token it issued: introspection, UserInfo, the refresh grant, token exchange, the DPoP-bound access token check, and the expiry every console screen reports. |
| `oauth2.redirectUris` | `STS_OAUTH2_REDIRECT_URIS` | *(empty)* | yes | The redirect URIs RFC 9700 mode compares an authorization request against, by EXACT STRING MATCH — for every client that did not register its own redirect_uris at POST /oauth2/register, which is every client this service has only ever seen at the authorization endpoint. |
| `oauth2.loopbackPortWildcard` | `STS_OAUTH2_LOOPBACK_PORT_WILDCARD` | `true` | yes | In RFC 9700 mode, allow a registered LOOPBACK redirect URI (127.0.0.1, [::1] or localhost) to match on any port — RFC 8252 section 7.3, because a native application cannot reserve one. |

### Admin console

**There is no setting that opens this console.** Every page and every form
under `/admin` needs a browser sign-on session and one of the two roles below, in BOTH modes, and `mode.gatesConsole()`
is the one place that is decided. What the mode changes is whether the password
typed at that screen is CHECKED — in `development` it is not, so the gate is a
turnstile proving somebody typed a name that holds a role.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `admin.readGroup` | `ADMIN_READ_GROUP` | `admin-read` | yes | The cn of the directory group whose members may READ the console — every page, and every ?format=json view of one. It is an ordinary group under ou=groups, so an ldapmodify, a SCIM PATCH and the /admin/rbac screen are three doors onto the same membership. |
| `admin.writeGroup` | `ADMIN_WRITE_GROUP` | `admin-write` | yes | The cn of the directory group whose members may POST a console form — revoke a token, add a claim, change a setting, grant a role. |
| `admin.openWhenEmpty` | `ADMIN_OPEN_WHEN_EMPTY` | `true` | yes | **Development mode only** — product never opens the console to anybody, whatever this says, and until the bootstrap administrator has claimed the console its roles are honoured only from a password sign-in. In development: ON, anybody who signs in holds both roles UNTIL the bootstrap administrator (`admin.bootstrapUsername`) first signs in to `/admin`, and the console says so in a banner on every page; OFF, only members of the two role groups from the start. A process that never seeded the bootstrap administrator keeps the older rule: open while NEITHER role group has a member. |
| `admin.bootstrapUsername` | `STS_ADMIN_BOOTSTRAP_USERNAME` | `admin` | **restart** — the account is seeded once, before the listener binds | The default realm's bootstrap administrator: made at startup if absent, a member of both console roles, forced to choose a new password at its first sign-in, and impossible to delete or rename. In product mode it is also who gets the generated password, logged once, when nobody holds a credential. |

### Protocol debugger

**There is no setting that opens the debugger either.** Every request to it
needs an access token carrying `urn:sts:debugger-api:debugger`, which the
authorization server issues to members of the two console role groups and
leaves off for anybody else. These rows decide whether it is served, where, and
what its api may dial.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `debugger.enabled` | `STS_DEBUGGER_ENABLED` | `auto` | **restart** — the listener is bound and the api process forked when the service starts | Whether this process serves the identity protocol debugger on a listener of its own. `auto` is on in development mode and off in product mode. |
| `debugger.port` | `STS_DEBUGGER_PORT` | `8444` | **restart** — the listener is bound when the process starts | The port the debugger is served on, in the main port's scheme and with its certificate — a separate origin from the console on purpose. |
| `debugger.publicBaseUrl` | `STS_DEBUGGER_PUBLIC_BASE_URL` | *(empty)* | **restart** — the debugger client's redirect URI is seeded at startup | The scheme, host and port the debugger is reached at. Empty reads it off each request. |
| `debugger.uiDirectory` | `STS_DEBUGGER_UI_DIRECTORY` | `debugger/embedded/ui` | **restart** — the listener checks the directory when it starts | Where the debugger's built static site is. |
| `debugger.apiDirectory` | `STS_DEBUGGER_API_DIRECTORY` | `debugger/embedded/api` | **restart** — the api process is forked when the service starts | Where the debugger's api tree is — forked, never required. |
| `debugger.allowedDestinations` | `STS_DEBUGGER_ALLOWED_DESTINATIONS` | *(empty)* | **restart** — the allow-list is handed to the api process when it is forked | CIDR ranges the embedded api may dial IN PRODUCT MODE, beside this service's own addresses. |
| `debugger.startTimeoutS` | `STS_DEBUGGER_START_TIMEOUT_S` | `30` | yes | How long a forked api process has to report that it is listening. |
| `debugger.restartLimit` | `STS_DEBUGGER_RESTART_LIMIT` | `5` | yes | Failed starts in a row before the api is given up on until a restart. |
| `debugger.proxyTimeoutS` | `STS_DEBUGGER_PROXY_TIMEOUT_S` | `120` | yes | How long the gate waits on the api process for one response. |
| `debugger.maxRequestBytes` | `STS_DEBUGGER_MAX_REQUEST_BYTES` | `5242880` | yes | The largest request body forwarded to the api process. |

### Applications

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `applications.max` | `STS_APPLICATIONS_MAX` | `500` | yes | How many entries may live under ou=applications — an OAuth client_id, a WS-Federation wtrealm, a SAML entityID, a WS-Trust AppliesTo, a Kerberos SPN. |
| `portal.applicationScanLimit` | `STS_PORTAL_APPLICATION_SCAN_LIMIT` | `1000` | yes | How many registry entries `/portal/applications` asks the issuance policy about before it stops; the page says how many it did not look at. |
| `applications.seedInternal` | `STS_APPLICATIONS_SEED_INTERNAL` | `true` | **restart** — the two entries are written once, as ldap_server.js is required and fills the registry's directory slot | Create an application entry for the ADMIN CONSOLE at /admin and one for the MANAGEMENT API at /admin-api when this service starts, under ou=applications with everything else. |

### Federation

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `federation.enabled` | `STS_FEDERATION_ENABLED` | `true` | yes | Whether /federation answers at all. |
| `federation.max` | `STS_FEDERATION_MAX` | `50` | yes | How many entries may live under ou=federations. |
| `federation.usernamePrefix` | `STS_FEDERATION_USERNAME_PREFIX` | *(empty)* | yes | Put in front of every username a foreign identity provider supplies, so a federated `alice` and the local `alice` are two entries. |
| `federation.loginButtons` | `STS_FEDERATION_LOGIN_BUTTONS` | `true` | yes | Show a button per usable service-provider-side relationship on /authn/login, so a federated identity can satisfy ANY flow already in progress — an OAuth 2.0 authorization request, a WS-Federation sign-in, a SAML AuthnRequest, the admin console. |
| `federation.outbound` | `STS_FEDERATION_OUTBOUND` | `true` | yes | Whether this service may make an HTTP request OUT, to a partner's token endpoint, UserInfo endpoint or JWKS. |
| `federation.outboundTimeoutMs` | `STS_FEDERATION_OUTBOUND_TIMEOUT_MS` | `15000` | yes | How long to wait for a partner to answer before giving up. It is generous because the partner here is usually THIS process (a trust realm is a logical copy of this service), and the first thing anybody asks a brand-new realm for is its JWKS — which brings that realm's eleven post-quantum keys into being, one of them an SLH-DSA key generation of about five seconds. |
| `federation.outboundAllowHttp` | `STS_FEDERATION_OUTBOUND_ALLOW_HTTP` | `false` | yes | Accept an `http://` partner endpoint, in development mode only; product refuses plain http whatever it says (#171). What travels on these requests is a client secret and an authorization code, at somebody else's service. |
| `federation.outboundSkipTlsVerification` | `STS_FEDERATION_OUTBOUND_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only.** Dial a partner WITHOUT verifying its certificate, logged on every request. Product mode ignores it (logged once, `STS-FED-0113`) and refuses to set it (`STS-CORE-0103`). |
| `federation.outboundCaFile` | `STS_FEDERATION_OUTBOUND_CA_FILE` | `` | yes | A PEM file of CA certificates a partner may chain to, beside node's store — how a privately certified partner is reached with verification on. |
| `federation.requestTtlMin` | `STS_FEDERATION_REQUEST_TTL_MIN` | `10` | yes | How long this service remembers that it sent somebody to a partner. |
| `federation.maxContexts` | `STS_FEDERATION_MAX_CONTEXTS` | `500` | yes | Outbound federated sign-ins held per realm; past it the oldest is dropped. Was a constant. |
| `federation.maxApplicationLength` | `STS_FEDERATION_MAX_APPLICATION_LENGTH` | `256` | yes | The longest `?application=` a federated login carries across the round trip. |
| `federation.maxApplicationUse` | `STS_FEDERATION_MAX_APPLICATION_USE` | `64` | yes | Per-application counter rows (`fedApplicationUse`) kept on one relationship. |
| `federation.releaseIndexTtlMs` | `STS_FEDERATION_RELEASE_INDEX_TTL_MS` | `5000` | yes | How long the release-policy index is reused before the register is walked again; `0` rebuilds it per token. |
| `federation.maxResponseBytes` | `STS_FEDERATION_MAX_RESPONSE_BYTES` | `262144` | yes | The cap on a partner's token response, UserInfo document or JWKS. |
| `federation.jwtAlgorithms` | `STS_FEDERATION_JWT_ALGORITHMS` | `RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512` | yes | The algorithms a partner's ID Token or JWT access token may use. It NARROWS the family the partner's key admits and cannot add `none` or an HMAC. |
| `federation.spNameIdFormat` | `STS_FEDERATION_SP_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified` | yes | The `<md:NameIDFormat>` in `/federation/metadata/{id}`. |
| `federation.encryptionKeyGraceS` | `STS_FEDERATION_ENCRYPTION_KEY_GRACE_S` | `86400` | yes | How long a federation relationship's encryption key still decrypts after a rotation replaced it (#168); `0` ends it at the rotation. |

### SAML

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `saml.issuer` | `STS_SAML_ISSUER`<br>or `STS_ISSUER` | `urn:wstrust:mock:sts` | yes | The <saml:Issuer> of every SAML 2.0 assertion and the Issuer attribute of every SAML 1.1 one. WS-Federation's assertions are built by the same two functions, so this is their issuer too, and it is what /wsfed/rp checks a presented assertion against. |
| `saml.clockSkewS` | `STS_SAML_CLOCK_SKEW_S` | `0` | yes | How far to widen the validity window of every assertion this service ISSUES, at both ends: Conditions/NotBefore is backdated by this many seconds and NotOnOrAfter is extended by it. Both builders apply it, so it reaches SAML 2.0, SAML 1.1, WS-Trust and WS-Federation alike. IssueInstant and the authentication instant are NOT moved — those state when something happened. 0 to 300; 0 is what this service always did. It is NOT `oauth2.clockSkewS`, which is the tolerance applied when this service READS a document back. |
| `saml.signatureAlgorithm` | `STS_SAML_SIGNATURE_ALGORITHM` | `rsa-sha256` | yes | The SignatureMethod of every XML signature this service makes on a SAML assertion, response, LogoutRequest/Response, SAML or WS-Federation metadata and a signed federated AuthnRequest, and the Redirect binding's `SigAlg`: `rsa-sha256`, `rsa-sha384`, `rsa-sha512`, or the broken `rsa-sha1`. `rsa-sha1` is development mode only: product signs with `rsa-sha256` instead and refuses setting it (#181). |
| `saml.canonicalizationAlgorithm` | `STS_SAML_CANONICALIZATION_ALGORITHM` | `exclusive` | yes | `exclusive` or `exclusive-with-comments`. Inclusive c14n is not offered: an assertion is signed standalone and embedded, and inclusive c14n would fail at every relying party. |
| `saml.allowSha1Signatures` | `STS_SAML_ALLOW_SHA1_SIGNATURES` | `false` | yes | Whether an XML signature this service VERIFIES may use SHA-1 (SignatureMethod or any DigestMethod). Off in both modes: refused before any cryptography, on every path (SAML 2.0 and 1.1, federation, RFC 7522, WS-Trust, WS-Federation). On: verified and recorded `weak`. On is development mode only: product refuses SHA-1 whatever this says, and refuses turning it on (#181). |
| `saml.organizationName` | `STS_SAML_ORGANIZATION_NAME` | `sts` | yes | `<md:OrganizationName>` in `/saml2/metadata` and `/saml11/metadata`. Empty omits the whole `<md:Organization>`, in either mode. |
| `saml.organizationDisplayName` | `STS_SAML_ORGANIZATION_DISPLAY_NAME` | `Mock security token service` | yes | `<md:OrganizationDisplayName>`; empty omits the element. |
| `saml.organizationUrl` | `STS_SAML_ORGANIZATION_URL` | *(empty)* | yes | `<md:OrganizationURL>`; empty means this service's own base URL. |

### SAML 2.0

These are their own group and `saml.issuer` above is deliberately not one of
them: that setting names whoever SIGNED an assertion and is shared with WS-Trust
and WS-Federation, while every row here governs how this service behaves as an
identity provider in a browser profile.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `saml2.entityId` | `STS_SAML2_ENTITY_ID` | `urn:sts:idp` | yes | The entityID this identity provider publishes in its SAML 2.0 metadata, and the <saml:Issuer> of every Response and Assertion the Web Browser SSO profile issues. It is NOT the SAML issuer above: that one names whoever signed an assertion and is shared with WS-Trust and WS-Federation, and a service provider checks THIS one against the metadata it was configured from. They are separate for the reason wsfed.entityId is separate from it. |
| `saml2.perApplicationEntityId` | `STS_SAML2_PER_APPLICATION_ENTITY_ID` | `true` | yes | ON by default, and it is what makes the metadata at /saml2/metadata/{sp} UNIQUE PER APPLICATION: the identity provider names itself <entityID>:{sp} in that document and in everything it issues to that service provider, the way Okta and Ping give each application its own identity provider. OFF makes every document carry the entityID above and differ only in its endpoint URLs, which is what a service provider library that keys its trust store off the entityID expects. Both are real deployments, which is why it is a setting and not a decision. |
| `saml2.assertionLifetimeMin` | `STS_SAML2_ASSERTION_LIFETIME_MIN` | `60` | yes | How long an issued assertion is valid for: it becomes Conditions/NotOnOrAfter and the bearer SubjectConfirmationData/NotOnOrAfter alike. Set it to 1 to watch a service provider refuse a stale assertion, which is the check most of them get wrong. |
| `saml2.signAssertion` | `STS_SAML2_SIGN_ASSERTION` | `true` | yes | Sign the <saml:Assertion> itself. ON by default because a service provider that verifies anything verifies this, and because an assertion that travels on its own — out of an ArtifactResponse, say — has nothing else carrying a signature. Turning it OFF is a test case rather than a mistake: a service provider that accepts an unsigned assertion has a hole, and this is how to find out. Off is development mode only: product signs every assertion, and turning it off is refused, here and per application (#181). |
| `saml2.signResponse` | `STS_SAML2_SIGN_RESPONSE` | `true` | yes | Sign the <samlp:Response> around the assertion as well, which is what AD FS and Keycloak do by default. Both signatures are ordinary: the response is signed AFTER the assertion inside it, so the assertion's own signature is part of what the response signature covers. On the HTTP Redirect binding this ALSO controls the query-string signature of section 3.4.4.1, which is the one a redirect response is really verified by. |
| `saml2.nameIdFormat` | `STS_SAML2_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | yes | The Format on the NameID when the AuthnRequest's NameIDPolicy asks for none. A request that DOES name one is answered with the one it named — any of them, including a format this service has never heard of, because a service provider being told its own format back is the behaviour worth exercising and refusing with InvalidNameIDPolicy would remove the test case. |
| `saml2.artifactTtlS` | `STS_SAML2_ARTIFACT_TTL_S` | `300` | yes | How long a SAML artifact can be resolved for at the Artifact Resolution Service. An artifact is ALSO one-shot — resolving it destroys it, which section 3.6.4.1 requires and which no lifetime can express — so a second ArtifactResolve for the same artifact is refused however long this is. |
| `saml2.encryptAssertion` | `STS_SAML2_ENCRYPT_ASSERTION` | `false` | yes | Wrap the assertion in a `<saml:EncryptedAssertion>`. Needs a recipient certificate; with none the assertion is sent IN CLEAR and the reason is logged at WARN. Per application with `saml2EncryptAssertion`. |
| `saml2.encryptionAlgorithm` | `STS_SAML2_ENCRYPTION_ALGORITHM` | `aes256-gcm` | yes | The block cipher: `aes256-gcm`, `aes128-gcm`, `aes256-cbc`, `aes128-cbc`. The GCM pair is authenticated; the CBC pair is not, which is CBC's property and is offered because real service providers require it. Per application with `saml2EncryptionAlgorithm`. |
| `saml2.keyTransportAlgorithm` | `STS_SAML2_KEY_TRANSPORT_ALGORITHM` | `rsa-oaep-mgf1p` | yes | How the content key is wrapped: `rsa-oaep-mgf1p` or `rsa-1_5`. The second is Bleichenbacher-broken and is offered because many deployed service providers accept nothing else. Per application with `saml2KeyTransportAlgorithm`. `rsa-1_5` is development mode only: product wraps with `rsa-oaep-mgf1p` instead, here and per application, and refuses setting it (#181). |
| `saml2.encryptLogoutNameId` | `STS_SAML2_ENCRYPT_LOGOUT_NAMEID` | `false` | yes | Send `<saml:EncryptedID>` rather than `<saml:NameID>` in a LogoutRequest — the only encryptable thing in a SAML 2.0 request. Reading one is never gated. Per application with `saml2EncryptLogoutNameId`. |
| `saml2.autocreateApplications` | `STS_SAML2_AUTOCREATE_APPLICATIONS` | `true` | yes | ON by default: an entityID this service has not seen before gets an application entry under ou=applications the moment it appears in a valid AuthnRequest — or the moment somebody asks for its metadata — so nothing has to be provisioned before a service provider can be pointed here. OFF still ANSWERS the request; it simply records nothing, which is what somebody driving a fuzzer at this endpoint wants before their directory has ten thousand entries in it. |
| `saml2.requireSignedAuthnRequests` | `STS_SAML2_REQUIRE_SIGNED_AUTHN_REQUESTS` | `auto` | yes | Whether an UNSIGNED AuthnRequest — and an unsigned LogoutRequest from a service provider — is refused. `auto` is on in product mode and off in development; a service provider whose consumed metadata says `AuthnRequestsSigned="true"` is held to it regardless. A signature that is present is verified against the service provider's REGISTERED certificates in every mode, never against the one the request carries. It is also what the metadata's `WantAuthnRequestsSigned` says. |
| `saml2.defaultSingleLogoutService` | `STS_SAML2_DEFAULT_SLO_SERVICE` | *(empty)* | yes | Where a <samlp:LogoutResponse> goes when the service provider has no SingleLogoutService registered — neither from its consumed metadata nor declared on its entry. Without this the fallback is the assertion consumer service URL that application last used, which is stated on the page rather than done quietly. |
| `saml2.requestTtlMin` | `STS_SAML2_REQUEST_TTL_MIN` | `10` | yes | How long an AuthnRequest is held while the browser is at the sign-in screen. |
| `saml2.mockSpContextTtlMin` | `STS_SAML2_MOCK_SP_CONTEXT_TTL_MIN` | `30` | yes | How long the non-spec mock service provider at /saml2/sp remembers a RelayState it minted. |
| `saml2.redirectWarnLength` | `STS_SAML2_REDIRECT_WARN_LENGTH` | `8000` | yes | A Response on the HTTP Redirect binding longer than this is logged at WARN (and still sent). |
| `saml2.spMetadataMaxBytes` | `STS_SAML2_SP_METADATA_MAX_BYTES` | `524288` | yes | The cap on a service provider's metadata fetched by the refresh action or uploaded on the SAML 2.0 page. |
| `saml2.spMetadataRefresh` | `STS_SAML2_SP_METADATA_REFRESH` | `true` | yes | Whether the background refresher fetches a stale service provider metadata document again (past its `cacheDuration`, or halfway to `validUntil`) from its URL or the MDQ responder. A failed fetch changes nothing. Expiry is enforced either way. |
| `saml2.spMetadataRefreshIntervalS` | `STS_SAML2_SP_METADATA_REFRESH_INTERVAL_S` | `300` | yes | How often the refresher looks; one node per cluster refreshes each document. Also how long a failed MDQ lookup is remembered. |
| `saml2.metadataTrustAnchors` | `STS_SAML2_METADATA_TRUST_ANCHORS` | *(empty)* | yes | Base64 DER certificates, comma-separated, a consumed metadata document may be signed with (a federation operator's keys). Set, every document must verify against one of them or the entry's own certificate. |
| `saml2.mdqBaseUrl` | `STS_SAML2_MDQ_BASE_URL` | *(empty)* | yes | A Metadata Query Protocol responder: `<base>/entities/<entityID>`, asked by the `mdq-import` action, by the refresh of an entry with no URL, by the refresher, and — never awaited — for a service provider with no metadata. In product mode it registers an unknown service provider only on an answer that verifies against `saml2.metadataTrustAnchors`; with none, a request's lookup is not made. |
| `saml2.mdqImportWithoutAnchors` | `STS_SAML2_MDQ_IMPORT_WITHOUT_ANCHORS` | `false` | yes | Product mode only: lets an administrator's MDQ import register a service provider with no `saml2.metadataTrustAnchors` (refused by default, `STS-SAML-0084`). **Warning**: the document is then consumed with no signature check. A request's lookup still needs an anchor. |

### SAML 1.1

These nine are a group of their own for the reason the SAML 2.0 nine are, and for
one more besides. The shared reason: `saml.issuer` above names whoever SIGNED an
assertion and is read by WS-Trust and WS-Federation, while every row here governs
how this service behaves as an identity provider in a browser profile. The reason
peculiar to this group: **SAML 1.1 and SAML 2.0 are different specifications
rather than two dialects**, and a shared set of rows would make `signResponse`
mean two things — over there it is an XML signature or a signed query string
depending on the binding, and here there is no redirect binding for a response at
all. A relying party that trusts this service for 1.1 and not for 2.0 is also the
ordinary case, and one `entityId` between them would make that unexpressible.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `saml11.providerId` | `STS_SAML11_PROVIDER_ID` | `urn:sts:idp:saml11` | yes | What this identity provider calls itself in the SAML 1.1 browser profiles: the `Issuer` ATTRIBUTE of every assertion they issue, the `entityID` of the metadata document at /saml11/metadata, and the string whose SHA-1 becomes the SourceID inside every type 0x0001 artifact. SAML 1.1 calls it a providerID and SAML 2.0 metadata calls the same thing an entityID; they are one value and this row is it. It is deliberately NOT saml2.entityId — a relying party that trusts this service for 1.1 and not for 2.0 is the ordinary case, and one value would make that unexpressible. |
| `saml11.perApplicationProviderId` | `STS_SAML11_PER_APPLICATION_PROVIDER_ID` | `true` | yes | Give every relying party its own providerID — `{providerID}:{slug}` — and its own endpoints under the same path segment, which is what /saml11/metadata/{rp} publishes. Turn it off for a relying party whose trust store is keyed off the providerID and which is surprised to meet a new one per application. THE ENDPOINTS STAY PER-APPLICATION either way, because that is what makes the documents worth having separately. It also changes every artifact this service mints: the SourceID is a hash of the providerID, so turning this off makes one SourceID where there were many. |
| `saml11.assertionLifetimeMin` | `STS_SAML11_ASSERTION_LIFETIME_MIN` | `60` | yes | How long the browser profiles' assertions are valid for, in the NotBefore and NotOnOrAfter of <saml:Conditions>. It is separate from the WS-Federation lifetime for the same reason the SAML 2.0 one is: a browser profile assertion is consumed within seconds of being issued and a short lifetime here is a realistic test, where the same value would make a WS-Federation session expire while somebody was reading it. |
| `saml11.signAssertion` | `STS_SAML11_SIGN_ASSERTION` | `true` | yes | Sign the <saml:Assertion> itself, with ds:Signature as its LAST child and the reference naming AssertionID — which is where the 1.1 schema puts it and is not where SAML 2.0 does. ON by default because the Browser/POST profile REQUIRES a signed assertion (saml-profile-1.1 section 4.2.1.4): the assertion passes through the browser, so nothing else authenticates it. Turning it off is a test case rather than a mistake — a relying party that accepts it anyway has a hole in it, and this is how somebody finds that out. Off is development mode only: product signs every assertion, and turning it off is refused, here and per relying party (#181). |
| `saml11.signResponse` | `STS_SAML11_SIGN_RESPONSE` | `true` | yes | Sign the <samlp:Response> around the assertion as well, with the reference naming ResponseID. Real identity providers differ here and both are worth exercising, which is why it is a setting: the profile requires the RESPONSE to be signed in Browser/POST and says nothing about it for the assertion pulled back over the artifact channel, where the SOAP exchange is what a relying party is trusting. Off is development mode only: Browser/POST requires a signed Response, so product always signs it and refuses turning it off (#181). |
| `saml11.nameIdFormat` | `STS_SAML11_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | yes | The Format on the <saml:NameIdentifier> when the request asks for none — which in SAML 1.1 is ALWAYS, because the profile has no request message to carry a NameIDPolicy in. That is the difference from saml2.nameIdFormat, which is a default a request routinely overrides: this one is the answer unless the non-spec `format` parameter overrides it. |
| `saml11.defaultProfile` | `STS_SAML11_DEFAULT_PROFILE` | `post` | yes | Which profile the inter-site transfer service uses when the request does not say: Browser/POST (section 4.2), where the assertion travels through the browser in a form POST, or Browser/Artifact (section 4.1), where a reference travels through the browser and the relying party fetches the assertion over SOAP. POST is the default because it needs no server behind the relying party's assertion consumer, so it is the one that works when somebody points this at a URL and watches. A request naming `profile` or carrying `SAMLart` overrides it. |
| `saml11.artifactTtlS` | `STS_SAML11_ARTIFACT_TTL_S` | `300` | yes | How long an artifact can be resolved for at the SAML responder before it is swept. It is an UPPER bound and not the rule that matters: an artifact is resolvable exactly ONCE (saml-bindings-1.1 section 3.2.3), so resolving one destroys it whatever this says, and no lifetime setting can express that. Five minutes is what the profile recommends and is generous for an exchange that takes milliseconds. |
| `saml11.autocreateApplications` | `STS_SAML11_AUTOCREATE_APPLICATIONS` | `true` | yes | Create an application entry under ou=applications the first time a relying party is named — by a TARGET arriving, by a metadata document being fetched, or by an artifact being resolved. Off means the browser profiles still work and /admin/saml11 stays empty, which is what somebody driving a load test wants and nobody else does. |
| `saml11.requestTtlMin` | `STS_SAML11_REQUEST_TTL_MIN` | `10` | yes | How long a SAML 1.1 browser flow is held while the browser is at the sign-in screen. |
| `saml11.assertionCacheMax` | `STS_SAML11_ASSERTION_CACHE_MAX` | `500` | yes | Assertions the SAML 1.1 responder keeps per realm for `<samlp:AssertionIDReference>`. |

### WS-Trust

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `wstrust.issuer` | `STS_WSTRUST_ISSUER`<br>or `STS_ISSUER` | `urn:wstrust:mock:sts` | yes | The `iss` of the JWT this STS returns in a RequestSecurityTokenResponse, and the issuer named on GET /sts. A SAML token requested through WS-Trust is built by the SAML modules and carries the SAML issuer above. |
| `wstrust.tokenLifetimeMin` | `STS_WSTRUST_TOKEN_LIFETIME_MIN` | `60` | yes | How long an issued or renewed token is valid for when the RST carries no `wst:Lifetime`. |
| `wstrust.maxTokenLifetimeMin` | `STS_WSTRUST_MAX_TOKEN_LIFETIME_MIN` | `1440` | yes | The ceiling on a requested `wst:Lifetime`, in both modes; the RSTR states what was issued. |
| `wstrust.jwtAlgorithm` | `STS_WSTRUST_JWT_ALGORITHM` | `RS256` | yes | The `alg` of the JWT token type: `RS256`–`RS512`, `PS256`–`PS512`, `ES256`–`ES512` or `EdDSA`, with the key's `kid` in the header. |

### WS-Federation

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `wsfed.assertionLifetimeMin` | `STS_WSFED_ASSERTION_LIFETIME_MIN` | `60` | yes | How long the SAML 1.1 assertion inside a WS-Federation sign-in response is valid, and the wsu:Lifetime of the RequestSecurityTokenResponse around it. Per relying party with `wsfedAssertionLifetimeMin` on the application entry; the default is drawn on `/admin/saml-assertions`, because a WS-Federation response carries a SAML 1.1 assertion built by the same function. |
| `wsfed.entityId` | `STS_WSFED_ENTITY_ID`<br>or `STS_ISSUER` | `urn:wstrust:mock:sts` | yes | The entityID in the federation metadata at /FederationMetadata/2007-06/FederationMetadata.xml. Split from the SAML issuer because the two are different things that happened to share a value: this names the IdP, that names whoever signed an assertion. |
| `wsfed.mockRpContextTtlMin` | `STS_WSFED_MOCK_RP_CONTEXT_TTL_MIN` | `30` | yes | How long the non-spec mock relying party at /wsfed/rp remembers a wctx it minted. |

### TLS

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `tls.trustIssuedClientCertificates` | `STS_TLS_TRUST_ISSUED_CLIENT_CERTIFICATES` | `true` | **restart** — the service Root is put into the listeners' client truststore when their TLS context is built | Adds this service's own Root CA to the client truststore of the main port, so a TLS client certificate issued on the user portal signs its holder in, in the realm whose TLS client Issuing CA signed it. A chain through that Root is an identity only for a TLS client or enrollment (ACME, EST, SCEP) leaf with `clientAuth` and one `urn:sts:person:`/`urn:sts:application:` name; every other key pair this service issues is refused as one. |
| `tls.hostnames` | `STS_TLS_HOSTNAMES` | `localhost,sts,sts-mock,sts.example.com` | **restart** — the server certificate is issued at startup for these names | The subjectAltName DNS entries on the certificate both TLS listeners present. |
| `tls.ips` | `STS_TLS_IPS` | `127.0.0.1` | **restart** — the server certificate is issued at startup for these addresses | The subjectAltName IP entries on the same certificate. |
| `tls.certificateAlgorithms` | `STS_TLS_CERT_ALGS` | `rsa` | **restart** — the certificates are issued when the listeners are bound | Which server certificates the two TLS listeners present: `rsa` (the default), and any of `ml-dsa-44`, `ml-dsa-65` and `ml-dsa-87`. MORE THAN ONE IS THE INTERESTING SETTING — OpenSSL 3.5 serves whichever certificate matches the signature algorithms the CLIENT offered, so `rsa,ml-dsa-65` answers an ordinary client with RSA and a post-quantum one with ML-DSA over the same port. It is not the default because an ML-DSA certificate is refused by everything older than OpenSSL 3.5. |
| `tls.minVersion` | `STS_TLS_MIN_VERSION` | `TLSv1.2` | **restart** — the TLS contexts are built when the listeners are created | The lowest protocol version LDAPS, the main HTTPS port and the debugger's listener negotiate: `TLSv1`, `TLSv1.1`, `TLSv1.2` (node's own default, and what this service always did) or `TLSv1.3`. |
| `tls.ciphers` | `STS_TLS_CIPHERS` | BCP 195: `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384` | **restart** — the TLS contexts are built when the listeners are created | An OpenSSL cipher list for the same listeners, applied in the SERVER's order. The default is BCP 195 (RFC 9325 section 4.2): the TLS 1.3 suites first, then only the four ECDHE AES-GCM suites for TLS 1.2, which is what the FAPI 2.0 Security Profile requires (section 5.2.2). **Empty means node's default list, which allows suites BCP 195 recommends against**; widen it only to test an old client. A list matching no cipher stops the service at startup, naming this setting. |
| `tls.trustAnchorsFile` | `STS_TLS_TRUST_ANCHORS_FILE` | *(empty)* | **restart** — the anchors are read when the listeners are created | A PEM file of CA certificates that client certificates are verified against, read at startup. The product-mode way to fill the truststore: `POST /tls/trust` and `/tls/trust/clear` answer anybody in development mode and are refused (403, naming this setting) in product mode. A file that cannot be read stops the service. |
| `tls.selfSignedKeyBits` | `STS_TLS_SELF_SIGNED_KEY_BITS` | `2048` | **restart** — the certificate is generated when the process starts | The RSA key size of the self-signed listener certificate made when no other certificate is available. 2048–8192, in steps of 1024. |
| `tls.selfSignedValidityYears` | `STS_TLS_SELF_SIGNED_YEARS` | `2` | **restart** — the certificate is generated when the process starts | How long that certificate is valid. |
| `tls.selfSignedOrganization` | `STS_TLS_SELF_SIGNED_ORGANIZATION` | `sts` | **restart** — the certificate is generated when the process starts | The `O=` of its subject; the `CN` is the first of `tls.hostnames`. |

### OID4VCI

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `oid4vci.walletUrl` | `OID4VCI_WALLET_URL` | `http://localhost:3000` | yes | Where the wallet lives, as a URL the BROWSER can use. The Credential Offer pages send the End-User here, so it is the debugger's own address rather than anything this service serves. |
| `oid4vci.authorizationServer` | `OID4VCI_AUTHORIZATION_SERVER` | *(empty)* | yes | Set this to advertise a SEPARATE authorization server in the credential issuer metadata's authorization_servers. Empty — the default — means this service is its own, which is the arrangement every test here uses. |
| `oid4vci.batchSize` | `OID4VCI_BATCH_SIZE` | `4` | yes | batch_credential_issuance.batch_size in the issuer metadata: how many proofs one credential request may carry, and therefore how many credentials come back from it. |
| `oid4vci.deferredReadyMs` | `OID4VCI_DEFERRED_READY_MS` | `4000` | yes | How long a deferred credential stays issuance_pending before it is ready. Long enough that a wallet has to poll and short enough that a test does not time out. |
| `oid4vci.deferredIntervalS` | `OID4VCI_DEFERRED_INTERVAL_S` | `2` | yes | The `interval` this issuer asks a wallet to wait between deferred polls. |
| `oid4vci.offerUsername` | `OID4VCI_OFFER_USERNAME` | `diploma.student` | yes | Whose credential the issuer-initiated offer pages build. The claims come from that person's directory entry. |
| `oid4vci.requestEncryptionRequired` | `OID4VCI_REQUEST_ENCRYPTION_REQUIRED` | `false` | yes | When on, a credential request that is not a JWE is refused. The negative worth having: a wallet cannot prove it encrypts by encrypting when the issuer accepts plaintext too. |
| `oid4vci.sdJwtIssuerDid` | `OID4VCI_SD_JWT_ISSUER_DID` | `false` | **restart** — vc_did.js reads it once at require time, and the issuer metadata is built from what it read | Switch the PLAIN dc+sd-jwt credential configuration over to naming its issuer by did:web instead of by https URL — what a deployment that had gone to DIDs throughout would look like. |
| `oid4vci.ldpVcIssuerDid` | `OID4VCI_LDP_VC_ISSUER_DID` | `false` | **restart** — vc_did.js reads it once at require time, and the issuer metadata is built from what it read | The same for the PLAIN ldp_vc configuration. |
| `oid4vci.txCodeLength` | `OID4VCI_TX_CODE_LENGTH` | `5` | yes | How many digits the Transaction Code a pre-authorized offer shows on the issuer's screen has. Drawn from a CSPRNG whatever this is. |
| `oid4vci.txCodeMaxAttempts` | `OID4VCI_TX_CODE_MAX_ATTEMPTS` | `5` | yes | IN PRODUCT MODE, how many wrong Transaction Codes a pre-authorized code survives. The last one SPENDS it, so a five-digit code cannot be guessed at the token endpoint inside the offer's lifetime; the End-User asks the issuer for a new offer. Development counts nothing, so a wallet can be driven through its wrong-code path as often as a test likes. |
| `oid4vci.offerTtlS` | `OID4VCI_OFFER_TTL_S` | `600` | yes | How long a Credential Offer, its issuer_state, its pre-authorized code and a notification_id stay usable. |
| `oid4vci.preAuthorizedPollIntervalS` | `OID4VCI_PRE_AUTHORIZED_POLL_INTERVAL_S` | `5` | yes | The `interval` a pre-authorized_code grant in an offer names — the seconds a wallet waits between token requests. |
| `oid4vci.walletIssuancePath` | `OID4VCI_WALLET_ISSUANCE_PATH` | `/vc-issuance-1.html` | yes | The page under the wallet URL that a Credential Offer is handed to. The default is the debugger's own wallet page. |
| `oid4vci.allowedWalletUrls` | `OID4VCI_ALLOWED_WALLET_URLS` | `(empty)` | yes | IN PRODUCT MODE, the wallet URLs besides oid4vci.walletUrl that the `wallet` query parameter on /issuer/offer may name. Any other is refused, because an offer link that sends the End-User wherever its query string says is an open redirect carrying a pre-authorized code. Development accepts any URL, which is how a wallet on a laptop is pointed at this service. |
| `oid4vci.requestEncryptionKeyBits` | `OID4VCI_REQUEST_ENCRYPTION_KEY_BITS` | `2048` | yes | The RSA modulus of the key credential_request_encryption publishes. Each trust realm has its own key, made when the realm first needs one, so a change reaches keys made AFTER it and never a key that exists. |
| `oid4vci.requestEncryptionEncValues` | `OID4VCI_REQUEST_ENCRYPTION_ENC_VALUES` | `A128GCM,A256GCM` | yes | The content encryption algorithms credential_request_encryption advertises and accepts. Only A128GCM and A256GCM are implemented; anything else named here is ignored with a warning rather than advertised, because metadata that overstates is worse than metadata that says little. |
| `oid4vci.responseEncryptionEncValues` | `OID4VCI_RESPONSE_ENCRYPTION_ENC_VALUES` | `A128GCM,A256GCM` | yes | The content encryption algorithms credential_response_encryption advertises and accepts. Same rule as the request row: A128GCM and A256GCM are implemented and nothing else is advertised. The key transport is RSA-OAEP-256, which is the only one implemented and is not a setting. |
| `oid4vci.responseEncryptionRequired` | `OID4VCI_RESPONSE_ENCRYPTION_REQUIRED` | `false` | yes | When on, a credential request that does not ask for an encrypted response (credential_response_encryption) is refused, and the metadata says encryption_required: true. |
| `oid4vci.credentialLifetimeS` | `OID4VCI_CREDENTIAL_LIFETIME_S` | `2592000` | yes | How long every credential this issuer mints is valid — the `exp` of a dc+sd-jwt and a jwt_vc_json credential and the `validUntil` of an ldp_vc one. Thirty days by default. |
| `oid4vci.credentialSigningAlgorithm` | `OID4VCI_CREDENTIAL_SIGNING_ALGORITHM` | `RS256` | yes | The JWS algorithm dc+sd-jwt and jwt_vc_json credentials are signed with — the post-quantum ones (ML-DSA, SLH-DSA and the composites) included, signed in the worker pool — and the one this realm's status lists, the DID Configuration's Domain Linkage Credential and /did/generate's did:web credential use. The metadata's credential_signing_alg_values_supported names it, /oauth2/jwks and /.well-known/did.json publish the key, and the mock Verifier checks against it. ldp_vc is bbs-2023 and is not affected. A credential already issued keeps the algorithm it was signed with. |
| `oid4vci.statusListTtlS` | `OID4VCI_STATUS_LIST_TTL_S` | `300` | yes | The `ttl` this realm's status lists carry, and the HTTP `max-age`: how long a verifier may keep one before fetching it again, and so how long a revocation can take to be seen elsewhere. |
| `oid4vci.statusListLifetimeS` | `OID4VCI_STATUS_LIST_LIFETIME_S` | `86400` | yes | How long after it is signed a Status List Token says it is valid (its `exp`), and a Bitstring Status List credential's `validUntil`. |
| `oid4vci.keyAttestationRequired` | `OID4VCI_KEY_ATTESTATION_REQUIRED` | `false` | yes | Require a key attestation (OpenID4VCI Appendix D) of every credential request — in a `jwt` proof's `key_attestation` header, or as the `attestation` proof type — and advertise it. Off, an attestation that is sent is still verified and recorded; what it attests is what a wallet sign-in may claim (`hwk`, `acr "mfa"`). |
| `oid4vci.keyAttestationTrustedCertificates` | `OID4VCI_KEY_ATTESTATION_TRUSTED_CERTIFICATES` | `(empty)` | yes | PEM certificates, concatenated, of the Wallet Providers whose key attestations this issuer believes: one must verify against such a key, or be signed by a certificate (its `x5c`) one of them issued. Empty trusts none. |
| `oid4vci.proofIatWindowS` | `OID4VCI_PROOF_IAT_WINDOW_S` | `600` | yes | How far a wallet's openid4vci-proof+jwt `iat` may be from now, either way. The c_nonce is what makes a proof single use; this is what stops one minted long ago being used at all. |
| `oid4vci.cNonceTtlS` | `OID4VCI_C_NONCE_TTL_S` | `300` | yes | How long a c_nonce from the Nonce Endpoint may be quoted in a proof; `c_nonce_expires_in` says the same number. |
| `oid4vci.issuerDisplayName` | `OID4VCI_ISSUER_DISPLAY_NAME` | `IdP Tools Mock Credential Issuer` | yes | The `display.name` of the credential issuer metadata — what a wallet shows as who is offering the credential. The credential configurations' own display names and colours are part of the catalogue in oid4vc/vc_issuer.ts and are not settings. |
| `oid4vci.domainLinkageLifetimeS` | `OID4VCI_DOMAIN_LINKAGE_LIFETIME_S` | `31536000` | yes | How long the Domain Linkage Credential at /.well-known/did-configuration.json says it is valid. It is signed per request, so this is the window a cached copy may be believed for. |
| `oid4vci.generatedDidCredentialLifetimeS` | `OID4VCI_GENERATED_DID_CREDENTIAL_LIFETIME_S` | `3600` | yes | How long the SD-JWT VC that /did/generate signs with the DID it hands back is valid. |

### OID4VP

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `oid4vp.clientId` | `OID4VP_CLIENT_ID` | `sts-verifier` | yes | The client_id the mock Verifier presents in its Authorization Request, and the `aud` the Key Binding JWT must name. |
| `oid4vp.walletUrl` *(derived)* | `OID4VP_WALLET_URL` | `http://localhost:3000` | yes | Where the Verifier sends the holder to present. Falls back to the OID4VCI wallet URL, since it is the same wallet in every arrangement this service is used in. |
| `oid4vp.kbMaxAgeS` | `OID4VP_KB_MAX_AGE_S` | `600` | yes | How old a Key Binding JWT's `iat` may be before the Verifier rejects the presentation as a replay. |
| `oid4vp.signInSelfIssued` | `OID4VP_SIGN_IN_SELF_ISSUED` | `false` | yes | Offer "Sign in with a self-issued ID" (SIOPv2) on /authn/login and the enrolment on /portal/self-issued. It signs in only the person who ENROLLED the key, in every mode. |
| `oid4vp.siopIdTokenMaxAgeS` | `OID4VP_SIOP_ID_TOKEN_MAX_AGE_S` | `300` | yes | How old a self-issued ID Token's `iat` may be (SIOPv2 section 11.1). |
| `oid4vp.clientIdPrefix` | `OID4VP_CLIENT_ID_PREFIX` | `pre-registered` | yes | How a wallet is to authenticate a SIGNED request (OpenID4VP section 5.9): pre-registered, decentralized_identifier, verifier_attestation or openid_federation. An unsigned request always uses redirect_uri. |
| `oid4vp.verifierAttestation` | `OID4VP_VERIFIER_ATTESTATION` | *(empty)* | yes | A Verifier Attestation JWT whose `cnf` is this realm's request-signing key. Empty: with the verifier_attestation prefix this realm attests itself, which only a wallet that already trusts it accepts. |
| `oid4vp.claims` | `OID4VP_CLAIMS` | `given_name,family_name` | yes | The mock Verifier's STARTING request, and — this is the part worth knowing — the target its Reset returns to. It is not the live list: /admin/vc-verifier-config owns that, and copies this at startup. |
| `oid4vp.presentationRequestTtlS` | `OID4VP_PRESENTATION_REQUEST_TTL_S` | `600` | yes | How long a presentation request — its nonce, state and Request Object — may wait for a wallet's response. |
| `oid4vp.walletPresentationPath` | `OID4VP_WALLET_PRESENTATION_PATH` | `/vc-presentation-1.html` | yes | The page under the wallet URL a presentation request is handed to. The default is the debugger's own wallet page. |
| `oid4vp.allowedWalletUrls` | `OID4VP_ALLOWED_WALLET_URLS` | `(empty)` | yes | IN PRODUCT MODE, the wallet URLs besides oid4vp.walletUrl that the `wallet` query parameter on the Verifier's start page may name; any other is refused as an open redirect. Development accepts any URL. |
| `oid4vp.trustedIssuerCertificates` | `OID4VP_TRUSTED_ISSUER_CERTIFICATES` | `(empty)` | yes | PEM certificates, concatenated, whose keys the mock Verifier accepts an SD-JWT VC or jwt_vc_json credential signature from IN ADDITION to this realm's own issuer. Empty — the default — trusts this issuer alone, which is what it always did. A certificate is used as a KEY: no chain is built and no revocation is checked. |
| `oid4vp.expectedVct` | `OID4VP_EXPECTED_VCT` | `urn:idptools:sd-jwt-vc:identity` | yes | The `vct` the Verifier requires of a presented SD-JWT VC. The default is the type this issuer mints; set it to accept a credential another issuer mints under its own type. |
| `oid4vp.maxRequestedClaims` | `OID4VP_MAX_REQUESTED_CLAIMS` | `40` | yes | The most claims /admin/vc-verifier-config lets the Verifier's request name. |
| `oid4vp.signIn` | `OID4VP_SIGN_IN` | `true` | yes | Offer "Sign in with a wallet" on /authn/login and answer /authn/wallet: a verified presentation of a credential this realm issued — in any format `oid4vp.signInFormats` names, with a fresh holder proof — starts a session for the directory entry the credential was issued for. Any other credential still verifies and signs nobody in. See *Signing in with a wallet*. |
| `oid4vp.signInTtlS` | `OID4VP_SIGN_IN_TTL_S` | `300` | yes | How long a wallet sign-in waits for the wallet, and for the browser that started it to collect the session. |
| `oid4vp.signInPollS` | `OID4VP_SIGN_IN_POLL_S` | `3` | yes | How often the QR-code page reloads itself (a `<meta>` refresh, not a script). The Digital Credentials API page does not reload: a reload would close the browser's wallet dialog. |
| `oid4vp.signInCrossDevice` | `OID4VP_SIGN_IN_CROSS_DEVICE` | `false` | yes | Offer a plain QR code on the wallet sign-in page, for a wallet the browser's Digital Credentials API cannot reach. **Off by default in both modes**: it is the one wallet path somebody can relay to a victim. |
| `oid4vp.signInFormats` | `OID4VP_SIGN_IN_FORMATS` | `dc+sd-jwt,jwt_vc_json,ldp_vc` | yes | The credential formats a wallet sign-in asks for, in order of preference: one DCQL credential query each, and a credential set saying any one will do. |
| `oid4vp.signInDcApiResponseMode` | `OID4VP_SIGN_IN_DC_API_RESPONSE_MODE` | `dc_api.jwt` | yes | How a wallet answers through the Digital Credentials API: encrypted to a key only that sign-in holds, or `dc_api` in the clear for a wallet that cannot encrypt. |
| `oid4vp.statusListMaxCacheS` | `OID4VP_STATUS_LIST_MAX_CACHE_S` | `3600` | yes | The most the Verifier keeps a status list a trusted foreign issuer published, whatever its `ttl` says. Never past the list's own `exp`; 0 fetches for every presentation. |
| `oid4vp.requireStatusReference` | `OID4VP_REQUIRE_STATUS_REFERENCE` | `all` | yes | Whether a credential presented to the Verifier must name a status that resolves VALID (#165). `all` (the default, both modes) refuses any credential with none (`STS-VC-0088`) and an `ldp_vc` that withheld its `credentialStatus` (`STS-VC-0089`). `own-only` accepts a foreign credential with none — **warning:** it can never be shown revoked. `off` also accepts this realm's own, and is development only (refused on write in product, `STS-CORE-0103`, and read as `all`). |
| `oid4vp.statusOptionalIssuers` | `OID4VP_STATUS_OPTIONAL_ISSUERS` | *(empty)* | yes | SHA-256 thumbprints (hex, colon-hex or base64url) of certificates in `oid4vp.trustedIssuerCertificates` whose credentials may name no status under `all`. **Warning:** such a credential can never be shown revoked; one that names a status is still checked. |
| `oidfed.signingAlg` | `STS_OIDFED_SIGNING_ALG` | `ES256` | yes | The algorithm of the key each realm signs its federation statements with (OpenID Federation 1.1 section 3.1.1), kept apart from the protocol signing keys. A change takes effect at the next key minted; a rotation by hand makes it at once. ES256 by default because every federation implementation verifies it; the ML-DSA keys are post-quantum, and a federation whose members verify them is one that can choose them. |
| `oidfed.keyRotationDays` | `STS_OIDFED_KEY_ROTATION_DAYS` | `180` | yes | How long a Federation Entity Key signs before the oidfed.key-rotate job replaces it (product mode; development makes new keys at every start). |
| `oidfed.keyOverlapDays` | `STS_OIDFED_KEY_OVERLAP_DAYS` | `14` | yes | How long a next key is published before it signs, and a retired key after it stopped (11.2) — so an entity that refreshes this realm's Entity Configuration at least this often never meets a statement it cannot verify. |
| `oidfed.statementLifetimeS` | `STS_OIDFED_STATEMENT_LIFETIME_S` | `86400` | yes | The exp of the Entity Configuration and of every Subordinate Statement this realm signs: how long another entity may rely on them before fetching them again (11.1). |
| `oidfed.realmsAreSubordinates` | `STS_OIDFED_REALMS_ARE_SUBORDINATES` | `true` | yes | ON: the default realm is a Trust Anchor vouching for every other realm, and each other realm names it as its authority and trusts it — a whole federation in one service. OFF: each realm is only what its own register and oidfed.authorityHints make it. |
| `oidfed.authorityHints` | `STS_OIDFED_AUTHORITY_HINTS` | *(empty)* | yes | The Entity Identifiers of the Intermediates or Trust Anchors directly above this realm, published as authority_hints (3.1.2) beside the default realm when oidfed.realmsAreSubordinates is on. A realm that names none is a Trust Anchor. |
| `oidfed.organizationName` | `STS_OIDFED_ORGANIZATION_NAME` | *(empty)* | yes | organization_name in the federation_entity metadata (5.2.2), which the specification recommends every entity publish. Empty: omitted. |
| `oidfed.contacts` | `STS_OIDFED_CONTACTS` | *(empty)* | yes | contacts in the federation_entity metadata (5.2.2). |
| `oidfed.logoUri` | `STS_OIDFED_LOGO_URI` | *(empty)* | yes | logo_uri in the federation_entity metadata (5.2.2). |
| `oidfed.policyUri` | `STS_OIDFED_POLICY_URI` | *(empty)* | yes | policy_uri in the federation_entity metadata (5.2.2). |
| `oidfed.organizationUri` | `STS_OIDFED_ORGANIZATION_URI` | *(empty)* | yes | organization_uri in the federation_entity metadata (5.2.2). |
| `oidfed.trustMarkLifetimeS` | `STS_OIDFED_TRUST_MARK_LIFETIME_S` | `31536000` | yes | The lifetime a Trust Mark type is registered with when none is given. Every mark this service issues expires: 7.1 allows one without exp, and a mark that never expires outlives any decision to withdraw it. |
| `oidfed.maxAuthorityHints` | `STS_OIDFED_MAX_AUTHORITY_HINTS` | `5` | yes | How many of an entity's authority_hints a resolution follows — section 18.1's defence against an entity naming hundreds to make this service fetch them. |
| `oidfed.maxChainDepth` | `STS_OIDFED_MAX_CHAIN_DEPTH` | `6` | yes | How many statements deep a resolution walks before it gives up. |
| `oidfed.maxFetchesPerResolution` | `STS_OIDFED_MAX_FETCHES_PER_RESOLUTION` | `24` | yes | The most statements one resolution fetches, whatever the hints and the depth multiply to (18.1). |
| `oidfed.fetchTimeoutMs` | `STS_OIDFED_FETCH_TIMEOUT_MS` | `5000` | yes | How long one fetch of an Entity Statement may take. |
| `oidfed.fetchMaxBytes` | `STS_OIDFED_FETCH_MAX_BYTES` | `262144` | yes | The largest Entity Statement a fetch reads. |
| `oidfed.resolveCacheS` | `STS_OIDFED_RESOLVE_CACHE_S` | `3600` | yes | How long a resolved Trust Chain is kept for the resolve endpoint, at most — never past the chain's own expiry (10.4). 0 keeps nothing, and the endpoint then answers only for this service's own realms. |
| `oidfed.resolveCacheMax` | `STS_OIDFED_RESOLVE_CACHE_MAX` | `1000` | yes | How many resolved Trust Chains a realm keeps; the oldest is dropped for a new one. |
| `oidfed.clockSkewS` | `STS_OIDFED_CLOCK_SKEW_S` | `60` | yes | The leeway on iat and exp when a federation statement is read (3.2). |

### Kerberos

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `krb5.enabled` | `KRB5_ENABLED` | `true` | yes | Whether this realm's KDC answers. On the service as a whole it is on, and the sockets stay bound either way. **On a TRUST REALM it decides whether that realm has a Kerberos realm at all**, and a realm is created with it OFF: turning it on is refused until the realm has a `krb5.realm` of its own that no other realm answers to, and it builds that realm's principal database. |
| `krb5.realm` | `KRB5_REALM` | `EXAMPLE.COM` | **restart** for the process — the principal database and every long-term key in it are derived from the realm at startup; **settable on a trust realm**, whose database is built when its Kerberos is turned on | The realm this KDC serves. Its lower-cased form is the domain, which is where the default service domains and the PAC's domain name come from. On a trust realm it is the name port 88 routes that realm's requests by: no two realms may answer to one name, and it cannot be changed while that realm's Kerberos is on. |
| `krb5.kdcPort` | `KRB5_KDC_PORT` | `88` | **restart** — the TCP and UDP sockets are bound when the process starts | The KDC listens on TCP and UDP alike. 88 is privileged, so a host run that is not root fails to bind it — which is recorded rather than thrown, and reported by GET /krb5/principals. 0 asks for any free port. |
| `krb5.servicePort` | `KRB5_SERVICE_PORT` | `8888` | **restart** — the socket is bound when the process starts | The Kerberized test service that accepts an AP-REQ. |
| `krb5.servicePrincipal` | `KRB5_SERVICE_PRINCIPAL` | `HTTP/web.example.com` | **restart** for the process; **settable on a trust realm**, whose account is created when its Kerberos is turned on | The SPN that test service holds, in the usual service/hostname form. **A trust realm that sets none derives `HTTP/web.<its own domain>`** where this is still the value shipped here, so every name in a realm's database follows that realm's domain. |
| `krb5.clockSkew` | `KRB5_CLOCK_SKEW` | `300` | yes | How far apart the KDC will let its clock and a client's be. RFC 4120 suggests five minutes and this is where KRB_AP_ERR_SKEW comes from. |
| `krb5.clockOffset` | `KRB5_CLOCK_OFFSET` | `0` | yes | Moves this KDC's clock deliberately, so a skew failure can be produced on purpose rather than by changing the machine's time. Development mode only: anything but 0 is ignored in product (the KDC runs on the machine's clock), and setting it is refused (#181). |
| `krb5.userPassword` | `KRB5_USER_PASSWORD` | `password!` | **restart** — every user's long-term keys are derived from it at startup | The password every user account here has. It is PUBLISHED by GET /krb5/principals on purpose: a debugger whose accounts are unusable without reading the source is worse than one that says what they are. |
| `krb5.unknownUsers` | `KRB5_UNKNOWN_USERS` | `nosuchuser,nobody` | yes | Usernames this KDC refuses to create on demand, so KDC_ERR_C_PRINCIPAL_UNKNOWN stays reachable. |
| `krb5.serviceDomains` *(derived)* | `KRB5_SERVICE_DOMAINS` | `example.com,localhost,sts,127.0.0.1` | **restart** — the service accounts are created at startup | The host domains a service principal is created on demand for. Setting it to an empty string creates nothing, which is the behaviour this service had before the setting existed. |
| `krb5.autoServicePassword` | `KRB5_AUTO_SERVICE_PASSWORD` | `auto-service-password` | **restart** — those accounts' long-term keys are derived from it at startup | One password for every service created on demand, and it is published for the same reason the user password is: it is what lets a reader decrypt a service ticket this mock issued and read the PAC inside it. |
| `krb5.krbtgtPassword` | `KRB5_KRBTGT_PASSWORD` | `krbtgt-mock-password` | **restart** — the krbtgt keys are derived from it at startup | DEVELOPMENT MODE ONLY: the password the key that seals every Ticket-Granting Ticket is derived from. Product mode keys `krbtgt` at random, keeps it sealed on the directory entry `krbtgt/<REALM>@<REALM>` and ignores this setting (#169). |
| `krb5.domainSid` | `KRB5_DOMAIN_SID` | `S-1-5-21-1004336348-1177238915-682003330` | **restart** — every principal's PAC identity is built at startup | The domain SID every account's PAC is built under. A Kerberos ticket says who you are; a Windows service authorizes on the SIDs in the PAC. |
| `krb5.trustedRealm` | `KRB5_TRUSTED_REALM` | `PARTNER.COM` | **restart** — the second realm and the trust between them are built at startup | The second realm, for cross-realm referrals. A trust is not a flag: it is a shared key held by one principal in each realm. |
| `krb5.trustPassword` | `KRB5_TRUST_PASSWORD` | `inter-realm-trust-password` | **restart** — the inter-realm key is derived from it at startup | The shared secret both realms hold for the cross-realm trust. |
| `krb5.trustedDomainSid` | `KRB5_TRUSTED_DOMAIN_SID` | `S-1-5-21-2035427030-2118130302-1178042555` | **restart** — the trusted realm's principals are built at startup | The other realm's domain SID. It differs from this one on purpose: SID filtering across a trust is about whose domain a SID belongs to. |
| `krb5.trustedKrbtgtPassword` | `KRB5_TRUSTED_KRBTGT_PASSWORD` | `partner-krbtgt-password` | **restart** — that realm's krbtgt keys are derived from it at startup | The krbtgt password of the trusted realm. |
| `krb5.spnegoAuthentication` | `KRB5_SPNEGO_AUTHENTICATION` | `true` | yes | Whether `/authn/spnego` turns a Kerberos ticket into a browser session — integrated authentication, available to every application and registered for none. With it off that endpoint answers 403 saying which setting it was, and `/spnego/protected` still performs the whole handshake and shows both halves of it; what it will not do is give you a session. An application or a federation relationship naming the `spnego` mechanism while this is off is REPORTED on the sign-in screen rather than meeting a 403 halfway through a flow. |
| `krb5.spnegoLoginButton` | `KRB5_SPNEGO_LOGIN_BUTTON` | `true` | yes | Show a "Sign in with Kerberos" button on `/authn/login`, so a ticket can satisfy any flow already in progress — an authorization request, a `wsignin1.0`, an `AuthnRequest`, the console. Same reason `federation.loginButtons` exists, and it needs no registration at all: whether somebody can use a ticket is a fact about their machine, not about the relying party. Withheld from a request that demanded two factors, and it says so. |
| `krb5.s2kparams` | `KRB5_S2KPARAMS` | `omit` | yes | Whether PA-ETYPE-INFO2 carries s2kparams. Windows Server omits it and this mock sent it, which is the one difference the captured real-DC exchange found; omit is therefore the default and send is kept so a client that reads it can be exercised. |
| `krb5.servicePassword` | `KRB5_SERVICE_PASSWORD` | `service-account-password` | **restart** — the service account's long-term keys are derived from it at startup | The password of the account `krb5.servicePrincipal` names — the keytab equivalent. The account is built FROM that setting. **Product mode refuses the published default**: the account is not created, the acceptor and `/authn/spnego` accept no ticket, and `GET /krb5/service` says why. |
| `krb5.serviceSalt` | `KRB5_SERVICE_SALT` | *(empty)* | **restart** — the service account's long-term keys are derived from it at startup | The string-to-key salt for that account. Empty means this service's convention (`EXAMPLE.COMHTTPweb`); an account in a real Active Directory is salted with its sAMAccountName, so an acceptor for a real KDC's tickets needs it set. |
| `krb5.enctypes` | `KRB5_ENCTYPES` | `18,17,20,19,23` | **restart** — every principal's supported encryption types are fixed at startup | The encryption types the KDC and acceptor use at all, strongest first. **Warning:** `23` (rc4-hmac) is deprecated by RFC 8429 and is in the default for **development mode only**, so an RC4 client can be exercised; removing it is what a hardened domain does. **In product mode `23` is always removed** (#182): the list is read without it (`STS-CORE-0106`, said once), a write naming it is refused (`STS-CORE-0103`), no RC4 key is derived, stored or put in a keytab, and a request offering only RC4 is refused `KDC_ERR_ETYPE_NOSUPP`. A number the codec does not implement stops the service at startup. |
| `krb5.kvno` | `KRB5_KVNO` | `3` | **restart** — every principal's key version is fixed at startup | The key version number every account built from a password in the configuration holds (the acceptor, and in development krbtgt and every fixture and on-demand account); for those, rotation is not modelled. It is also the STARTING kvno of a directory person's first stored keys and of a service principal created at `/admin/kerberos/principals`, and of a product realm's random krbtgt key (#169) — and those do rotate: a password change or a Rotate adds one to the stored kvno, which changing this setting later does not move. |
| `krb5.personKeys` | `KRB5_PERSON_KEYS` | `true` | yes | PRODUCT MODE ONLY. Whether a person's Kerberos keys are derived from their password when it is set or verified, and stored sealed on their own directory entry, so the KDC authenticates them with that password. Off, nothing new is derived and the KDC refuses every person naming this setting; keys already stored stay until cleared at `/admin/kerberos/principals`. The keys are password-equivalent, which is why this can be switched off. Development mode never reads it. |
| `krb5.retainedKeyVersions` | `KRB5_RETAINED_KEY_VERSIONS` | `1` | yes | How many PREVIOUS key versions a stored Kerberos key keeps after a password change or a rotation (0–10). A kept version only opens a ticket already issued under it — the KDC issues under the current kvno and pre-authentication uses the current key only. 0 keeps none: a ticket under the previous kvno is refused `KRB_AP_ERR_BADKEYVER` at once. |
| `krb5.retainedKeyTtlS` | `KRB5_RETAINED_KEY_TTL_S` | `0` | yes | How long each previous key version is kept after it stops being current. 0 means `krb5.ticketLifetimeSeconds` plus `krb5.clockSkew`, the longest a ticket under it can still be presented — and for the `krbtgt` key the longer of that and `krb5.renewLifetimeSeconds`, plus the skew. Read at every use, so shortening it ends windows at once; lengthening it never revives a version past the bound it was retired under. |
| `krb5.krbtgtRotationIntervalDays` | `KRB5_KRBTGT_ROTATION_INTERVAL_DAYS` | `180` | yes | How old a trust realm's `krbtgt` key gets before the `krb5.krbtgt-rotate` scheduler job replaces it with a new random key at the next kvno, keeping the one it replaced for the TGTs already sealed under it — and never while that window is still open. 0 switches the schedule off. Product mode only (`mode.rotatesKerberosKeys()`); a rotation by hand at `/admin/kerberos/principals` works in both. Off too while `krb5.retainedKeyVersions` is 0. |
| `krb5.ticketLifetimeSeconds` | `KRB5_TICKET_LIFETIME_S` | `36000` | yes | The longest a ticket this KDC issues is valid for. |
| `krb5.renewLifetimeSeconds` | `KRB5_RENEW_LIFETIME_S` | `604800` | yes | How far renew-till reaches for a renewable ticket. |
| `krb5.logonServer` | `KRB5_LOGON_SERVER` | `DC01` | yes | The LogonServer name in every PAC. |
| `krb5.maxRequestBytes` | `KRB5_MAX_REQUEST_BYTES` | `131072` | yes | The most a client may send on one TCP connection to the KDC before it is closed. |
| `krb5.udpMaxReplyBytes` | `KRB5_UDP_MAX_REPLY_BYTES` | `1465` | yes | A reply larger than this over UDP is answered KRB_ERR_RESPONSE_TOO_BIG so the client retries over TCP. |
| `krb5.serviceMaxTokenBytes` | `KRB5_SERVICE_MAX_TOKEN_BYTES` | `65536` | yes | The largest AP-REQ the acceptor and SPNEGO read. |
| `krb5.replayCacheMaxEntries` | `KRB5_REPLAY_CACHE_MAX_ENTRIES` | `10000` | yes | How many Authenticators the acceptor holds inside the replay window. When it is full the acceptor refuses a NEW Authenticator rather than forgetting one that could still be replayed. |
| `krb5.spnegoPendingTtlSeconds` | `KRB5_SPNEGO_PENDING_TTL_S` | `120` | yes | How long an unfinished request-mic SPNEGO negotiation is held between its two requests. |
| `krb5.spnegoMaxPending` | `KRB5_SPNEGO_MAX_PENDING` | `64` | yes | How many of those are held at once. |

### LDAP

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `ldap.port` | `LDAP_PORT` | `389` | **restart** — the socket is bound when the process starts | The plain LDAP listener. 389 is privileged, so a host run that is not root fails to bind it — recorded rather than thrown, and reported by GET /admin/ldap/service. |
| `ldap.tlsPort` | `LDAPS_PORT` | `636` | **restart** — the socket is bound when the process starts | The LDAPS listener, which serves the certificate the TLS module generated. It binds independently of 389, so "389 is up and 636 is not" is an ordinary outcome and each reports itself separately. |
| `ldap.autocreateUsers` | `LDAP_AUTOCREATE_USERS` | `true` | yes | When on, an entry appears at uid=<name>,ou=users,<base> the first time anybody authenticates to this service through ANY protocol. On by default: a directory that fills up as you use the other protocols is the thing this one is here to show. |
| `ldap.maxEntries` | `LDAP_MAX_ENTRIES` | `2000` | yes | How large the directory may grow. A ceiling rather than a target: entries appear for anybody who authenticates through any protocol here. |
| `ldap.sizeLimit` | `LDAP_SIZE_LIMIT` | `500` | yes | The server-side size limit for a search, which is what produces LDAP_SIZE_LIMIT_EXCEEDED. |
| `ldap.plainListener` | `LDAP_PLAIN_LISTENER` | `true` | **restart** — the socket is bound when the process starts | Whether the unencrypted listener on `ldap.port` starts at all. Off leaves LDAPS as the only way in — what a product deployment, whose binds are verified, wants; product mode with it on logs a warning that 389 carries passwords in the clear. |
| `ldap.selfWritableAttributes` | `LDAP_SELF_WRITABLE_ATTRIBUTES` | `telephoneNumber,mobile,homePhone,displayName,preferredLanguage,postalAddress,street,l,st,postalCode,userPassword` | yes | In **product** mode, the attributes a connection bound as a person may change on that person's own entry with an LDAP modify. Every other write — another entry, any add, delete or rename, any attribute not listed — needs a connection bound as somebody holding Admin Write in the default realm, and an anonymous connection writes nothing (result code 50). `userPassword` still meets the password policy. Development authorizes no LDAP write. |
| `ldap.directoryReadableAttributes` | `LDAP_DIRECTORY_READABLE_ATTRIBUTES` | *(empty)* | yes | In **product** mode, the attributes a connection bound as a person may read on OTHER people's entries; a search filter sees these and nothing else of theirs. Empty — the default — means self-only: another person answers `noSuchObject` exactly as a missing DN. **Widening it exposes every person in the realm to every other** (usernames and addresses to phish or guess against; contact details; who the administrators are). Admin Read or Admin Write reads everything in scope; credentials are never readable. Development authorizes no LDAP read. |
| `ldap.groupMembersReadable` | `LDAP_GROUP_MEMBERS_READABLE` | `false` | yes | In **product** mode, whether a person may read the member list of a group they are in (they see a group only if they are in it, and then its `cn`, `description` and `objectClass`). **On the console role groups the list names every administrator.** Development authorizes no LDAP read. |

### SCIM

**There is no setting that opens SCIM.** Every endpoint under `/scim/v2`
requires a credential in BOTH modes — one of RFC 7644 section 2's six schemes,
with the OAuth ones needing `scim:read` or `scim:write` — because those
endpoints create and DELETE accounts. `global.mode` decides whether the
credential is CHECKED; `mode.gatesScim()` is the one place the gate is decided.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `scim.enabled` | `SCIM_ENABLED` | `true` | yes | When on, the SCIM 2.0 endpoints under /scim/v2 create, read, replace, patch and delete entries in the embedded directory. On by default, like every other protocol family here. |
| `scim.maxResults` | `SCIM_MAX_RESULTS` | `200` | yes | The largest page a list or a search will return, published as filter.maxResults in the ServiceProviderConfig and used as the page size when a client asks for none. |
| `scim.bulkMaxOperations` | `SCIM_BULK_MAX_OPERATIONS` | `100` | yes | How many operations one POST /scim/v2/Bulk may carry, published as bulk.maxOperations. A request carrying more is refused with 413 and the payloadTooLarge scimType, which is a reachable negative worth having. |
| `scim.bulkMaxPayloadSize` | `SCIM_BULK_MAX_PAYLOAD_SIZE` | `1048576` | yes | The largest BulkRequest body in bytes, published as bulk.maxPayloadSize and CHECKED against that number rather than against the express body parser's service-wide 5 MB. |
| `scim.authDiscovery` | `SCIM_AUTH_DISCOVERY` | `false` | yes | Whether /ServiceProviderConfig, /ResourceTypes and /Schemas need a credential as well. |
| `scim.authRealm` | `SCIM_AUTH_REALM` | `SCIM` | yes | The protection space named in every WWW-Authenticate challenge, and — for HTTP Digest and HOBA — a value that is hashed or signed OVER, so changing it invalidates every credential computed against the old one. |
| `scim.scopeRead` | `SCIM_SCOPE_READ` | `scim:read` | yes | The OAuth 2.0 scope an access token must carry to read at /scim/v2 — the first scope requirement anywhere in this service. |
| `scim.scopeWrite` | `SCIM_SCOPE_WRITE` | `scim:write` | yes | The scope needed to create, replace, patch, delete or bulk. |
| `scim.authBearer` | `SCIM_AUTH_BEARER` | `true` | yes | Whether an access token is accepted, as Bearer (RFC 6750) or — when it is bound — as DPoP (RFC 9449). |
| `scim.authBasic` | `SCIM_AUTH_BASIC` | `true` | yes | Any username with any password except the reserved "invalid", which is refused so that a 401 stays reachable. RFC 7644 section 2 DISCOURAGES this scheme in those words, and it is offered anyway because it is what a provisioning client most often meets. |
| `scim.authDigest` | `SCIM_AUTH_DIGEST` | `true` | yes | RFC 7616, with SHA-256, SHA-512-256 and MD5 offered in that order and the -sess variants accepted. |
| `scim.digestPassword` | `SCIM_DIGEST_PASSWORD` | `password!` | yes | The password every username shares for HTTP Digest — the same value KRB5_USER_PASSWORD defaults to, so that there is one fact to remember rather than two. |
| `scim.digestNonceSeconds` | `SCIM_DIGEST_NONCE_SECONDS` | `300` | yes | How long a Digest nonce stays usable. After it a credential is refused with stale=true, which RFC 7616 section 3.3 says a client should retry with the same credentials rather than prompting a person — a path most hand-written clients have never run. |
| `scim.digestMd5` | `SCIM_DIGEST_MD5` | `false` | yes | Whether Digest offers and accepts MD5 beside SHA-256 and SHA-512-256. **Warning:** MD5 is collision-broken, and RFC 7616 keeps it for backward compatibility only. Off (the default since #182), an MD5 credential is refused naming this setting. **Development mode only**: refused on write in a product realm (`STS-CORE-0103`) and ignored where it is read (`STS-CORE-0106`). **Digest itself is never offered in product mode**, whatever `scim.authDigest` says: RFC 7616 needs the server to hold each password or its digest hash, product mode holds only a scrypt hash, and the shared `scim.digestPassword` is not a credential a deployment can offer. The 401 names that password only in development. |
| `scim.maxDigestNonces` | `SCIM_MAX_DIGEST_NONCES` | `2000` | yes | How many issued Digest nonces are remembered. Forgetting a live one does not re-open a replay — its nonce-count record goes with it, so a credential naming it is refused with stale=true. |
| `scim.authHoba` | `SCIM_AUTH_HOBA` | `true` | yes | HTTP Origin-Bound Authentication (RFC 7486), the signature-based scheme RFC 7644 section 2 names and the only one of the six with no shared secret in it. Also turns POST /.well-known/hoba/register on or off. |
| `scim.hobaMaxAgeSeconds` | `SCIM_HOBA_MAX_AGE_SECONDS` | `600` | yes | The max-age published in the HOBA challenge and enforced on the signature. |
| `scim.maxHobaChallenges` | `SCIM_MAX_HOBA_CHALLENGES` | `2000` | yes | How many issued HOBA challenges are remembered; a signature over a forgotten one is refused with a fresh challenge. |
| `scim.maxHobaSeen` | `SCIM_MAX_HOBA_SEEN` | `5000` | yes | How many accepted (kid, challenge, nonce) triples are remembered for replay detection. Expired ones go first; past the bound the oldest goes **with its challenge**, so a copied signature is refused rather than accepted twice. |
| `scim.authCookie` | `SCIM_AUTH_COOKIE` | `true` | yes | Whether the browser sign-on session this service already has — the one /authn/login creates and WS-Federation shares — authenticates a SCIM request. RFC 7644 section 2 names cookies explicitly. |
| `scim.authClientCert` | `SCIM_AUTH_CLIENT_CERT` | `true` | yes | Mutual TLS, the first scheme RFC 7644 section 2 names. It applies only where the request arrived over TLS with a certificate that VERIFIED against an anchor POSTed to /tls/trust, so on the main port only when global.https is on. |

### Roles

Who holds a role, and what requires one. **A role is not a group**: a group here
grants nothing, and holding a role is what an ISSUANCE is decided on. It is also
not the two *Admin console* roles, which are directory groups granting `/admin`
and nothing else. Both halves of a role — who holds one, and which roles an
application demands — are edited on `/admin/roles` and on the application's own
page rather than in a setting.

| Setting | Environment | Default | Change while running | What it does |
|---|---|---|---|---|
| `roles.claim` | `STS_ROLES_CLAIM` | `true` | yes | When on, every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion names the roles its subject holds. The BUILT-IN roles are never carried — eight of them: `EVERYBODY` and `ALL_AUTHENTICATED_USERS` are true of almost every token this service issues, so carrying them would tell a relying party nothing it did not know from holding the token, and the two group-derived ones (`REMOTE_PEPS`, `XACML_USER`) say which of this service's own XACML endpoints the holder may reach, which is nobody else's business. |
| `roles.claimName` | `STS_ROLES_CLAIM_NAME` | `roles` | yes | What the claim is called: the JWT member name, the SAML 2.0 Attribute Name and the SAML 1.1 AttributeName. |
| `authn.unauthenticatedSessions` | `STS_AUTHN_UNAUTHENTICATED_SESSIONS` | `false` | yes | Show a third button on `/authn/login` — **Continue without signing in** — that starts a session for somebody who declines to authenticate. The session is real: it has a cookie, it satisfies a flow already in progress, tokens can be issued on it, and it appears on `/admin/sessions` in a section of its own. What it records is `authenticated: false`, so an application requiring `ALL_AUTHENTICATED_USERS` refuses it and one requiring `EVERYBODY` does not — **the only place in this service where the difference between those two built-in roles is visible**. The person is the stable `anonymous` principal, which gets a directory entry like anybody else and can therefore hold configured roles too. **Off by default**, unlike `roles.enforceIssuance` beside it, because this one changes a SCREEN: enforcement on by default changes nothing for an unedited service, and a third button on every sign-in screen would change what every existing caller's user sees. Cancel is unchanged and still answers `access_denied` without creating anything. |
| `roles.enforceIssuance` | `STS_ROLES_ENFORCE_ISSUANCE` | `true` | yes | Whether this service ASKS before it issues anything. On, each of the nine kinds of issuance is a XACML request decided by the embedded PEP against a policy; off, nothing is asked and everything is allowed. **On by default costs nothing until an application is narrowed**: one that names no required role requires `EVERYBODY`, everybody holds `EVERYBODY`, and the answer is Permit — so the machinery is always running and always visible, and turning enforcement on for an application is narrowing a list rather than switching on a subsystem that has never run. Off is the way back if a policy edit locks something out. |
| `roles.maxRoles` | `STS_ROLES_MAX` | `200` | yes | How many role entries `ou=roles` will hold, per trust realm. |
| `roles.remotePepGroup` | `STS_ROLES_REMOTE_PEP_GROUP` | `remote-peps` | yes | The directory group whose members hold the built-in `REMOTE_PEPS` role, which is what `POST /xacml/pep/register`, `GET /xacml/pep/policies`, `POST /xacml/pep/heartbeat` and `POST /xacml/pip` require. A remote Policy Enforcement Point presenting a client certificate this service VERIFIED is somebody it can NAME; membership of this group is what makes them somebody it lets IN, and the two are kept apart on purpose — **the certificate says who and the group says whether**, so a perfectly valid certificate for the wrong common name is refused while being fully authenticated. Setting it to the empty string means nobody holds the role, which closes those four endpoints to every caller including a correctly configured PEP. |
| `roles.xacmlUserGroup` | `STS_ROLES_XACML_USER_GROUP` | `xacml-users` | yes | The same arrangement for the built-in `XACML_USER` role, which is what the four XACML endpoints proper require — `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` and `GET /xacml/protected`. **It is a SECOND group and not the same one**, because `/xacml/pep/*` publishes the documents this service enforces its own access with and `POST /xacml/pip` publishes a named person's directory attributes; one group granting both would make admitting a caller to the demonstration surface silently admit it to those. A person is granted the role by being put in this group — one line on `/admin/ldap/directory` or one `ldapmodify` — and it takes effect on the very next request, because membership is resolved at decision time. Setting it to the empty string closes those four endpoints to everybody, which is how to take the XACML surface away without turning `xacml.enabled` off and losing the embedded issuance and access PEPs with it. `xacml.enforceAccess` is the other way, and it opens both sets at once. |

### TOTP MFA

RFC 6238 one-time passwords — the second factor a person enrols from
`/portal/mfa` or while spending an activation link, and the only credential
this service checks besides a Kerberos ticket. Drawn on **`/admin/totp`**,
under Protocols.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `totp.issuer` | `STS_TOTP_ISSUER` | *(empty)* | yes | The name an authenticator app shows beside the account — the `issuer` of the otpauth Key Uri Format, written both as a prefix on the label and as a parameter because older apps read one and newer ones the other. **Empty means this realm's own host**, with the realm id after it where there is one, which is deliberate: two realms of one process are two identity providers, and a phone showing two accounts with the same name beside them is a list nobody can use. |
| `totp.algorithm` | `STS_TOTP_ALGORITHM` | `SHA1` | yes | RFC 6238 section 1.2 defines all three and names HMAC-SHA-1 as the default. **LEAVE IT AT SHA1 UNLESS YOU ARE TESTING EXACTLY THIS.** Several widely used authenticator apps — Google Authenticator among them — IGNORE the `algorithm` parameter in the QR code and always compute SHA-1, so any other value produces a code that scans perfectly and then generates codes this service refuses, with nothing anywhere saying why. SHA-1 is not a weakness here: this is a keyed MAC over a counter, not a collision-resistant digest. Changing it affects NEW enrolments only — an existing secret is verified with the algorithm it was enrolled under, which is the one the app was told. |
| `totp.digits` | `STS_TOTP_DIGITS` | `6` | yes | Six is what every authenticator app shows and what RFC 4226 section 5.3 recommends; eight is defined and is worth setting only to find out what a client does with it. NEW enrolments only, for the reason the digest gives. |
| `totp.period` | `STS_TOTP_PERIOD` | `30` | yes | RFC 6238 section 4.1's time step X. Thirty seconds is the default and what every app assumes. NEW enrolments only. |
| `totp.window` | `STS_TOTP_WINDOW` | `1` | yes | How many steps either side of now are accepted. RFC 6238 section 5.2 recommends at most one, which is the default and makes a code good for about ninety seconds. **This one IS live** and applies to every existing enrolment — how much a deployment forgives a phone with a drifting clock is a policy rather than something the QR code told the app. Zero demands a perfectly synchronised clock and is the setting to reach for when demonstrating what happens without one. |
| `totp.secretBytes` | `STS_TOTP_SECRET_BYTES` | `20` | yes | RFC 4226 section 4 requirement R6 says at least 128 bits and recommends 160, which is the 20 bytes here and the length of an HMAC-SHA-1 key. Longer is allowed and is transcribed by hand by anybody who cannot scan the QR code — 20 bytes is already 32 base32 characters. |
| `totp.enrolmentTtlMinutes` | `STS_TOTP_ENROLMENT_TTL_MINUTES` | `10` | yes | How long a secret that has been SHOWN but not yet confirmed with a code stays available. It is held in memory and never written to the directory until a code proves the app really has it — an unconfirmed secret on somebody's entry would be a second factor they cannot produce, which is a lockout rather than a control. Ten minutes is long enough to find a phone and short enough that an abandoned enrolment does not sit in memory. |

Which of these affect only NEW enrolments, why `totp.window` applies to
everybody, why `totp.algorithm` should stay `SHA1`, and why switching TOTP off
in the authentication policy leaves existing enrolments in place are under
[The TOTP settings](#the-totp-settings-and-the-two-that-behave-differently-from-the-rest)
above.

### Backup codes

Recovery codes — the way back in when the second factor is not to hand. Drawn
on **`/admin/backup-codes`**, under Protocols.

**This is the only mechanism on that console that no specification defines.**
Everything else here implements somebody's document and can be checked against
it; there is no RFC for a recovery code. What every identity provider does
converges anyway — a handful of random strings, each accepted once — so the
decisions that are left are this service's own, and `common/backup_codes.ts`
argues each of them.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `backupCodes.count` | `STS_BACKUP_CODES_COUNT` | `10` | yes | How many codes are issued. Ten is what almost every identity provider settles on: enough that losing a printed copy of one does not end the account, few enough to fit on a card in a wallet. **A set is never topped up**: generating a new one replaces the old set whole. |
| `backupCodes.length` | `STS_BACKUP_CODES_LENGTH` | `10` | yes | Out of an alphabet of thirty-two, so ten characters is fifty bits — which is the number that matters rather than the length. |
| `backupCodes.groupSize` | `STS_BACKUP_CODES_GROUP_SIZE` | `5` | yes | Purely presentational: `A2CDE-FGH3J` rather than `A2CDEFGH3J`, so that a person transcribing one does not lose their place. Every door strips the dashes and the spaces back out before comparing, so a code typed either way is the same code. Zero prints it unbroken. |

How a person generates a set, why it is shown once and stored hashed, and why
none of these rows invalidates an existing set are under
[The recovery code settings](#the-recovery-code-settings-and-the-mechanism-no-specification-defines)
above. Two more things do not fit in a cell.

* **THE ALPHABET IS THE BASE32 CHARACTERS AND IS NOT SHARED WITH `totp.*`.**
  That one is base32 because the `otpauth` URI says so — an interoperability
  requirement. This one is the same thirty-two characters because none of them
  is confusable with another: no `0` beside `O`, no `1` beside `I`. A recovery
  code is the one credential here that somebody writes on paper and types back
  months later.
* **A CODE IS NEVER A FIRST FACTOR AND NEVER THE FACTOR A SIGN-IN ASKS FOR.**
  The screen asks for whichever mechanism the person is CONFIGURED for, and
  `/authn/backup-code` is reachable only as a link out of one of those two
  screens. Holding a set does not make a second factor required of anybody.

### WebAuthn

Security keys — W3C WebAuthn Level 3 over FIDO CTAP2 — as a second factor OR as
the only credential on an account. Drawn on **`/admin/webauthn`**, under
Protocols.

What a browser does with `navigator.credentials.create()` is decided almost
entirely by the options the relying party hands it, so these rows are how a
client author asks this service for a ceremony of a particular shape — with
`attestation: "none"`, say, or a discoverable credential.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `webauthn.enabled` | `STS_WEBAUTHN_ENABLED` | `true` | yes | Whether this service offers a WebAuthn ceremony at all — the two boxes on the sign-in screen, the enrolment on `/portal/keys`, and the `/authn/webauthn` screen itself. **Turning it off does NOT remove a key somebody already enrolled**, exactly as the authentication policy's TOTP row does not remove a shared secret. What it stops is new ceremonies. |
| `webauthn.rpName` | `STS_WEBAUTHN_RP_NAME` | `Mock authorization server` | yes | The `rp.name` handed to the browser — what a person and their password manager see while deciding whether to create a credential, and what a platform authenticator stores beside it. It has NO security meaning: WebAuthn binds a credential to the RP ID and to nothing else. |
| `webauthn.rpId` | `STS_WEBAUTHN_RP_ID` | *(empty)* | yes | **Empty means the host this service was reached on**, which is almost always right. A value may only WIDEN it to a registrable domain suffix of that host — `example.com` when reached at `sts.example.com` — which is WebAuthn's own rule; anything else is refused here by name in the log, because a browser refuses it with an error indistinguishable from a hardware failure. **In development mode** the host is then used instead; **in product mode the ceremony is refused**. Widening it means every host under that suffix can assert these credentials. |
| `webauthn.allowedOrigins` | `STS_WEBAUTHN_ALLOWED_ORIGINS` | *(empty)* | yes | The origins a ceremony's clientDataJSON may carry, comma-separated. **Empty derives the one origin from the address this service was reached at** (which `global.publicBaseUrl` pins); set, the list is the whole answer. |
| `webauthn.algorithms` | `STS_WEBAUTHN_ALGORITHMS` | `ES256,RS256` | yes | `pubKeyCredParams`, in preference order, as JOSE names: `ES256`, `ES384`, `ES512`, `EdDSA`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and RFC 9964's `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`. A credential whose algorithm was not offered is refused (section 7.1). A name outside that table is dropped with a warning rather than sent — offering an algorithm this service cannot verify produces a credential that enrols perfectly and then fails every assertion it is ever used for. |
| `webauthn.userVerification` | `STS_WEBAUTHN_USER_VERIFICATION` | `preferred` | yes | Whether the authenticator must verify the PERSON — a PIN, a fingerprint, a face — as well as prove possession. **THIS IS THE ONE CEREMONY SETTING THIS SERVICE ALSO ENFORCES**: `required` is sent to the browser and the UV flag in the signed authenticator data is then checked. **It does not change what a session CLAIMS** — a passwordless sign-in still records `amr ["hwk"]` and `acr "1"`, because RFC 8176 has no value for *the authenticator verified the user* this service could honestly assert. |
| `webauthn.attestation` | `STS_WEBAUTHN_ATTESTATION` | `direct` | yes | How much the browser is asked to say about the authenticator. `direct` is the default because this is a debugging service and the attestation object is worth looking at; a deployment with no use for the model should send `none`. What is DONE with the statement is `webauthn.attestationPolicy`; a realm that demands a trusted statement asks for `direct` whatever this says. |
| `webauthn.attestationPolicy` | `STS_WEBAUTHN_ATTESTATION_POLICY` | `by-mode` | yes | What a registration's attestation statement must be (#105). `verify-if-present` verifies every statement in all eight WebAuthn Level 3 section 8 formats and refuses one that does not verify; its chain is checked against the anchors below and the FIDO Metadata Service's roots, a model MDS lists must chain to its roots, a model MDS reports compromised is refused, and revocation is consulted; `none`, self attestation and an unanchored chain are accepted as untrusted. `require-trusted` refuses anything that does not chain to an anchor — and so every synced passkey. `by-mode` is `verify-if-present` in product and `off` in development. **`off` verifies nothing — WARNING: a forged statement is recorded as the authenticator's — and is development only.** |
| `webauthn.attestationTrustAnchors` | `STS_WEBAUTHN_ATTESTATION_TRUST_ANCHORS` | *(empty)* | yes | Root certificates, as PEM, an attestation certificate may chain to beside the roots MDS lists for each model — a corporate TPM CA, a vendor's root, a test root. Nothing is shipped. |
| `webauthn.attestationAllowedAaguids` | `STS_WEBAUTHN_ATTESTATION_ALLOWED_AAGUIDS` | *(empty)* | yes | The authenticator models a key may come from, as AAGUIDs. Set, it **requires a trusted attestation** — an AAGUID is otherwise the authenticator's claim. |
| `webauthn.attestationMinCertificationLevel` | `STS_WEBAUTHN_ATTESTATION_MIN_CERTIFICATION` | `none` | yes | The least FIDO certification level (`L1` … `L3plus`) the model must hold, from MDS status reports; anything but `none` requires a trusted attestation from a model MDS lists. |
| `webauthn.attestationRequireFips` | `STS_WEBAUTHN_ATTESTATION_REQUIRE_FIPS` | `false` | yes | Refuse a model MDS does not report as FIPS 140 certified; requires a trusted attestation from a listed model. |
| `webauthn.attestationAllowSafetynet` | `STS_WEBAUTHN_ATTESTATION_ALLOW_SAFETYNET` | `false` | yes | Whether a verified `android-safetynet` statement may count as trusted. **WARNING**: Google shut the SafetyNet Attestation API down and the format is deprecated; off records it as untrusted. |
| `webauthn.attestationAndroidSoftwareKeys` | `STS_WEBAUTHN_ATTESTATION_ANDROID_SOFTWARE` | `false` | yes | Read an `android-key` statement's origin and purpose from the software- and hardware-enforced lists, not the hardware list alone. **WARNING**: a key only Android's software vouches for may have been made by malware. |
| `webauthn.timeoutMs` | `STS_WEBAUTHN_TIMEOUT_MS` | `60000` | yes | The `timeout` in the options handed to the browser. It is a HINT and clients may clamp it. The pending step this service holds expires on its own five-minute clock regardless, so a longer timeout buys a ceremony that succeeds in the browser and is then refused here. |
| `webauthn.authenticatorAttachment` | `STS_WEBAUTHN_ATTACHMENT` | `any` | yes | Which kind of authenticator may answer — `platform` (Touch ID, Windows Hello, a screen lock) or `cross-platform` (a roaming CTAP2 key over USB, NFC or BLE). `any` sends no preference at all, because the options dictionary has no value meaning one. It is a FILTER IN THE BROWSER and not a check here. |
| `webauthn.residentKey` | `STS_WEBAUTHN_RESIDENT_KEY` | `discouraged` | yes | Whether the credential is stored ON the authenticator — a CTAP2 *resident key*, which is what a passkey is and what a usernameless sign-in needs. `discouraged` is the default because a resident key consumes one of the small number of slots a roaming authenticator has and cannot always be deleted from it. **This service offers no usernameless flow**, so `required` buys a slot and nothing else here. |
| `webauthn.credProps` | `STS_WEBAUTHN_CRED_PROPS` | `true` | yes | Asks the browser to report whether the credential it made is actually discoverable. It is the only way to find out — `residentKey: "preferred"` may or may not produce one and nothing in the attestation says which. The answer is recorded beside the key and decides nothing. |
| `webauthn.primaryAllowed` | `STS_WEBAUTHN_PRIMARY_ALLOWED` | `true` | yes | Whether a key may be the ONLY credential on an account — a passwordless sign-in. Off, keys still work as a second factor. **It does not disable a primary key somebody already holds**: an operator flipping a switch must not lock somebody out of their own account. |
| `webauthn.mfaAllowed` | `STS_WEBAUTHN_MFA_ALLOWED` | `true` | yes | Whether a key may be enrolled as a second factor beside a password. With this and the authentication policy's TOTP row both off, this service offers no second factor at all, which is a supported configuration and is what it did before either existed. An enrolled `mfa` key goes on being demanded. |
| `webauthn.maxKeysPerPerson` | `STS_WEBAUTHN_MAX_KEYS` | `10` | yes | How many security keys one person may hold. Several is the ordinary case and the specification expects it — an assertion NAMES the credential that produced it, so there is none of the ambiguity two shared secrets would have. It refuses the ENROLMENT and never an authentication. |

Which of these is enforced and which are only requests to the browser, why the
four policy rows refuse an enrolment and never an authentication, and how far
the RP ID may be widened are under
[The WebAuthn settings](#the-webauthn-settings-and-the-one-of-thirteen-this-service-enforces)
above.

### Group claim

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `groups.claim` | `STS_GROUPS_CLAIM` | `true` | yes | When on, every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion this service issues carries a claim naming the directory groups the person is a member of. |
| `groups.claimName` | `STS_GROUPS_CLAIM_NAME` | `groups` | yes | What the claim is called: the JWT member name, the SAML 2.0 Attribute Name and the SAML 1.1 AttributeName. `groups` is the conventional spelling and what most relying parties look for, but `roles` and a URI are both common and both worth being able to produce. |
| `groups.claimValue` | `STS_GROUPS_CLAIM_VALUE` | `cn` | yes | Whether each value is the group's common name (`developers`) or its whole DN (`cn=developers,ou=groups,dc=example,dc=com`). |
| `groups.claimFromMemberOf` | `STS_GROUPS_CLAIM_FROM_MEMBEROF` | `true` | yes | Whether a group named by the PERSON'S own `memberOf` counts as membership when the group entry does not list them back. |

### Audit log

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `audit.maxEvents` | `AUDIT_MAX_EVENTS` | `5000` | yes | How many audit events /admin/audit keeps before the oldest are dropped. What was dropped is COUNTED and shown, so a truncated log says it was truncated rather than implying the cap is all there ever was. |
| `audit.protocolCalls` | `AUDIT_PROTOCOL_CALLS` | `true` | yes | Whether every call into a protocol endpoint gets an audit event. |

### Delegation

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `delegation.maxRecords` | `DELEGATION_MAX_RECORDS` | `2000` | yes | How many delegation acts /admin/delegation keeps before the oldest are dropped. An act is one exchange in which somebody acted on somebody else's behalf — a Kerberos S4U request or forwarded ticket, a WS-Trust OnBehalfOf or ActAs, an RFC 8693 token exchange — and REFUSED attempts are recorded too. What was dropped is COUNTED and shown. |
| `logout.anyUser` | `LOGOUT_ANY_USER` | `true` | yes | Whether `/logout` honours a `username` naming somebody other than whoever the session cookie names. **In development mode** it grants nothing that was not already true — no password is checked at any sign-in screen there, so becoming that person takes one request — and what it buys is a headless test. **In product mode it is ignored**: a sign-out may name only the signed-in caller, because otherwise an anonymous request could end anybody's sessions and revoke their tokens. Off, `/logout` acts only on the caller's own session and 403s a request that names another name; `/admin/logout` and `/admin-api/logout` are unaffected. |
| `logout.kerberosSignOut` | `LOGOUT_KERBEROS_SIGN_OUT` | `true` | yes | Whether a logout stamps a sign-out instant on the Kerberos principal, after which a `TGS-REQ` carrying a ticket whose `authtime` is earlier is refused KDC_ERR_TGT_REVOKED (20). It does NOT stop a service ticket already in a cache — accepting one never contacts the KDC. An `AS-REQ` still succeeds and does not lift the instant: the older tickets, renewals included, stay refused until the latest could still be valid. Off, the KDC behaves exactly as it did before this feature existed. |
| `logout.ldapDisconnect` | `LOGOUT_LDAP_DISCONNECT` | `true` | yes | Whether a logout closes every connection to the embedded directory, 389 and 636 alike, whose bind DN names that person. RFC 4511 section 4.2 makes the bind the authorization state of a CONNECTION, so the connection is the session. Off, they are left alone and listed on `/logout` as untouched rather than hidden. |
| `logout.maxRows` | `LOGOUT_MAX_ROWS` | `500` | yes | How many live items `/logout` lists for one person. The cap is on what is DRAWN and offered as a checkbox, never on what a termination reaches — a global logout still ends all of them. |

### SPIFFE

**There is no setting that opens the SPIRE Server API.** Its TCP port is bound
as mutual TLS, always, because what comes out of that surface is a credential another service
will believe. Every method is authorized against SPIRE's own per-method table,
which `GET /spiffe` publishes in full. **The Workload API is deliberately not on
that list and must never be**: its specification says it MUST NOT authenticate a
caller, because a workload has no root of trust until that call gives it one.
What it lacks there is ATTESTATION, not authentication, and no mode changes it.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `spiffe.enabled` | `STS_SPIFFE_ENABLED` | `true` | yes | Whether the three SPIFFE surfaces answer. |
| `spiffe.trustDomain` | `STS_SPIFFE_TRUST_DOMAIN` | `example.org` | **restart**, and **settable on a REALM** — the process's authorities are generated at startup and every certificate they hold names this trust domain; a realm is created with SPIFFE off and builds its own when it is turned on | The trust domain this service is the issuing authority for: the authority part of every SPIFFE ID it mints, so spiffe://example.org/… by default. A realm created here is given **its own DNS domain** as its trust domain, the way it is given an entityID of its own. Set it on a realm to name that realm's trust domain outright. Once a realm's authorities are built the name is fixed, and a later change is reported as drift on `/admin/spiffe` rather than acted on. |
| `spiffe.x509KeyType` | `STS_SPIFFE_X509_KEY_TYPE` | `ec-p256` | **restart** — the X.509 authority is generated with this key type at startup | The key the trust domain's X.509 authority is generated with, and therefore the key type of every X509-SVID it signs. EC P-256 by default because that is what SPIRE issues and what the X509-SVID specification recommends. |
| `spiffe.jwtKeyType` | `STS_SPIFFE_JWT_KEY_TYPE` | `ec-p256` | **restart** — the JWT authority is generated with this key type at startup | The key the trust domain's JWT authority is generated with, which decides the `alg` of every JWT-SVID: ES256, ES384, ES512 or RS256. |
| `spiffe.caTtl` | `STS_SPIFFE_CA_TTL` | `86400` | **restart** — the authority certificate is issued for this long at startup | How long the X.509 authority's own certificate is valid. |
| `spiffe.svidTtl` | `STS_SPIFFE_SVID_TTL` | `3600` | yes | The default lifetime of an X509-SVID. A registration entry may name its own and that wins; this is what an entry with no `x509SvidTtl` gets. |
| `spiffe.jwtSvidTtl` | `STS_SPIFFE_JWT_SVID_TTL` | `300` | yes | The default lifetime of a JWT-SVID. Much shorter than the X.509 one on purpose and in both SPIRE and here: a JWT-SVID is a bearer credential — whoever holds it can present it — where an X509-SVID is bound to a private key. |
| `spiffe.refreshHint` | `STS_SPIFFE_REFRESH_HINT` | `300` | yes | The `spiffe_refresh_hint` published in the bundle: how often a consumer should come back for it. |
| `spiffe.svidSubject` | `STS_SPIFFE_SVID_SUBJECT` | `C=US,O=SPIRE` | yes | The X.501 subject written into every X509-SVID. The SPIFFE ID is in a URI subjectAltName and IS the identity; this is decoration, and it is SPIRE's own value by default so that an SVID from here looks like one from there. |
| `spiffe.caSubject` | `STS_SPIFFE_CA_SUBJECT` | `CN=sts SPIFFE {kind} ({trustDomain}),O=sts` | yes | The subject of a CA this service builds for SPIFFE itself — the self-signed fallback authority and every downstream CA. `{kind}` is `CA` or `downstream CA`. A realm under the certificate authority takes its Issuing CA's subject from `/admin/pki`. |
| `spiffe.retainedAuthorities` | `STS_SPIFFE_RETAINED_AUTHORITIES` | `4` | yes | How many authorities a rotation keeps published (self-signed X.509 and JWT), the new one included. At least 2. |
| `spiffe.agentSvidTtl` | `STS_SPIFFE_AGENT_SVID_TTL` | `0` | yes | The lifetime of an agent's X509-SVID from AttestAgent and RenewAgent. `0` means `spiffe.svidTtl`. |
| `spiffe.autoCreateEntries` | `STS_SPIFFE_AUTOCREATE_ENTRIES` | `true` | yes | THIS IS THE SETTING THAT MAKES THIS A MOCK. |
| `spiffe.requireSecurityHeader` | `STS_SPIFFE_REQUIRE_SECURITY_HEADER` | `true` | yes | The Workload Endpoint specification says a client MUST send `workload.spiffe.io: true` on every call and a server MUST refuse one without it. Off is development mode only: product always requires the header and refuses turning it off (#181). |
| `spiffe.trustLocalSocket` | `STS_SPIFFE_TRUST_LOCAL_SOCKET` | `true` | yes | A real SPIRE server trusts its private Unix socket outright — the access control is the socket's filesystem permissions — and a caller there is the `local` entity, which may do everything an admin may and two things an admin may not. In product mode the boundary is VERIFIED per connection: a 0600 socket in a private directory, and a caller whose kernel uid is the service's own. |
| `spiffe.adminIds` | `STS_SPIFFE_ADMIN_IDS` | *(empty)* | yes | SPIFFE IDs whose holders are administrators of the SPIRE Server API, separated by commas or spaces — SPIRE's own `admin_ids`, and like SPIRE's it needs NO registration entry behind it. |
| `spiffe.clockSkew` | `STS_SPIFFE_CLOCK_SKEW` | `60` | yes | How far out a caller's clock may be when its X509-SVID is checked for validity. |
| `spiffe.attestWorkloads` | `STS_SPIFFE_ATTEST_WORKLOADS` | `true` | yes | ON, a Workload API caller is answered with the registration entries whose selectors match what this service observed about it, which is what a real agent does. OFF (every entry to every caller) is DEVELOPMENT MODE ONLY. |
| `spiffe.acceptAssertedSelectors` | `STS_SPIFFE_ACCEPT_ASSERTED_SELECTORS` | `false` | yes | OFF by default, and it is the one setting here that is not attestation of any kind. DEVELOPMENT MODE ONLY: never believed in product, and refused there on write. |
| `spiffe.maxEntries` | `STS_SPIFFE_MAX_ENTRIES` | `500` | yes | How many entries may live under ou=spiffe. Past it a new one is REFUSED and the SVID request that would have created it is answered without one — the registry is a directory container and a container has a size, the same cap ou=applications has. |
| `spiffe.maxAgents` | `STS_SPIFFE_MAX_AGENTS` | `200` | yes | How many attested agents are held. The agent id comes off whatever the caller sent, so any caller can invent one; past the cap the oldest is dropped rather than the newest refused, because an agent that cannot attest is an agent that cannot do anything at all. |
| `spiffe.maxFederatedBundles` | `STS_SPIFFE_MAX_FEDERATED_BUNDLES` | `32` | yes | How many foreign trust domains' bundles are held. They are PASTED IN and never fetched — see /spiffe — so this bounds what an operator or the SPIRE Server API can add, not what any polling loop could accumulate. |
| `spiffe.joinTokenTtl` | `STS_SPIFFE_JOIN_TOKEN_TTL` | `600` | yes | A join token's lifetime when CreateJoinToken names none. |
| `spiffe.nodeAttestors` | `STS_SPIFFE_NODE_ATTESTORS` | `join_token` | yes | The node attestors AttestAgent accepts in this realm. Each is verified; a type not listed, or not one this server can verify, is refused with FAILED_PRECONDITION. |
| `spiffe.attestationChallengeTimeout` | `STS_SPIFFE_ATTESTATION_CHALLENGE_TIMEOUT` | `30` | yes | Seconds AttestAgent waits for a challenge_response once an attestor has challenged. |
| `spiffe.x509popMode` | `STS_SPIFFE_X509POP_MODE` | external_pki | yes | x509pop `mode`: external_pki verifies against `spiffe.x509popCaBundle`; spiffe against this realm's own SPIFFE bundle. |
| `spiffe.x509popCaBundle` | `STS_SPIFFE_X509POP_CA_BUNDLE` | (empty) | yes | PEM trust anchors for x509pop (SPIRE's ca_bundle_path). Empty refuses every x509pop agent. |
| `spiffe.x509popSpiffePrefix` | `STS_SPIFFE_X509POP_SPIFFE_PREFIX` | `/spire-exchange/` | yes | spiffe mode: the X509-SVID path must start with it. |
| `spiffe.x509popAgentPathTemplate` | `STS_SPIFFE_X509POP_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's agent_path_template; empty is SPIRE's default for the mode. Field references and sprig string/hash functions; other Go template syntax is refused. |
| `spiffe.x509popMaxIntermediates` | `STS_SPIFFE_X509POP_MAX_INTERMEDIATES` | `4` | yes | Most intermediates an x509pop attestation may carry. |
| `spiffe.x509popMaxRsaKeySize` | `STS_SPIFFE_X509POP_MAX_RSA_KEY_SIZE` | `8192` | yes | Largest RSA key accepted on any x509pop certificate. |
| `spiffe.x509popVerifyClientIp` | `STS_SPIFFE_X509POP_VERIFY_CLIENT_IP` | `false` | yes | The agent's address must be an IP SAN of its leaf. |
| `spiffe.x509popGroupTemplate` | `STS_SPIFFE_X509POP_GROUP_TEMPLATE` | (empty) | yes | Renders a `group:` selector when the result is in `spiffe.x509popAllowedGroups`. |
| `spiffe.x509popAllowedGroups` | `STS_SPIFFE_X509POP_ALLOWED_GROUPS` | (empty) | yes | The groups `spiffe.x509popGroupTemplate` may produce. |
| `spiffe.sshpopCertAuthorities` | `STS_SPIFFE_SSHPOP_CERT_AUTHORITIES` | (empty) | yes | SSH host CAs in authorized_keys form, one per line. Empty refuses every sshpop agent. |
| `spiffe.sshpopCanonicalDomain` | `STS_SPIFFE_SSHPOP_CANONICAL_DOMAIN` | (empty) | yes | The first principal must end in it; the Hostname is the principal without it. |
| `spiffe.sshpopAgentPathTemplate` | `STS_SPIFFE_SSHPOP_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's agent_path_template for sshpop. |
| `spiffe.sshpopVerifyClientIp` | `STS_SPIFFE_SSHPOP_VERIFY_CLIENT_IP` | `false` | yes | The agent's address must be in the certificate's source-address critical option. |
| `spiffe.tpmDevidCaBundle` | `STS_SPIFFE_TPM_DEVID_CA_BUNDLE` | (empty) | yes | PEM anchors for tpm_devid DevID certificates. Empty refuses every tpm_devid agent. |
| `spiffe.tpmEndorsementCaBundle` | `STS_SPIFFE_TPM_ENDORSEMENT_CA_BUNDLE` | (empty) | yes | PEM anchors for TPM endorsement key certificates. Empty refuses every tpm_devid agent. |
| `spiffe.k8sPsatClusters` | `STS_SPIFFE_K8S_PSAT_CLUSTERS` | (empty) | yes | k8s_psat clusters as JSON: allow list, audience, apiServer, caFile, tokenFile, label keys. The bearer token is always a FILE; no apiServer means in-cluster. |
| `spiffe.httpChallengeAllowedDnsPatterns` | `STS_SPIFFE_HTTP_CHALLENGE_ALLOWED_DNS_PATTERNS` | (empty) | yes | Regular expressions a host name must match BEFORE it is resolved or dialled. Empty refuses every http_challenge agent (stricter than SPIRE). |
| `spiffe.httpChallengeRequiredPort` | `STS_SPIFFE_HTTP_CHALLENGE_REQUIRED_PORT` | `0` | yes | The one port allowed; 0 allows any. |
| `spiffe.httpChallengeAllowNonRootPorts` | `STS_SPIFFE_HTTP_CHALLENGE_ALLOW_NON_ROOT_PORTS` | `true` | yes | Off, only ports below 1024. |
| `spiffe.httpChallengeTofu` | `STS_SPIFFE_HTTP_CHALLENGE_TOFU` | `true` | yes | A host name attests once until its agent is deleted. |
| `spiffe.httpChallengeVerifyClientIp` | `STS_SPIFFE_HTTP_CHALLENGE_VERIFY_CLIENT_IP` | `false` | yes | The agent's address must be one its host name resolves to. |
| `spiffe.awsIidPartition` | `STS_SPIFFE_AWS_IID_PARTITION` | `aws` | yes | The partition for the assume-role ARN. |
| `spiffe.awsIidAssumeRole` | `STS_SPIFFE_AWS_IID_ASSUME_ROLE` | (empty) | yes | A role name assumed in each node's account. Access keys are never a setting — the SDK chain supplies them. |
| `spiffe.awsIidSkipBlockDevice` | `STS_SPIFFE_AWS_IID_SKIP_BLOCK_DEVICE` | `false` | yes | Skip the root-volume / first-interface attach-time check. |
| `spiffe.awsIidDisableInstanceProfileSelectors` | `STS_SPIFFE_AWS_IID_DISABLE_INSTANCE_PROFILE_SELECTORS` | `false` | yes | No iamrole: selectors, and no IAM call. |
| `spiffe.awsIidLocalValidAccountIds` | `STS_SPIFFE_AWS_IID_LOCAL_VALID_ACCOUNT_IDS` | (empty) | yes | Accounts exempt from the block device check. |
| `spiffe.awsIidAgentPathTemplate` | `STS_SPIFFE_AWS_IID_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's agent_path_template for aws_iid. |
| `spiffe.awsIidVerifyOrganization` | `STS_SPIFFE_AWS_IID_VERIFY_ORGANIZATION` | (empty) | yes | JSON: an AWS Organizations check, or an account list. |
| `spiffe.awsIidEksClusterNames` | `STS_SPIFFE_AWS_IID_EKS_CLUSTER_NAMES` | (empty) | yes | EKS clusters the instance must be a node of. |
| `spiffe.awsIidEndpoint` | `STS_SPIFFE_AWS_IID_ENDPOINT` | (empty) | yes | An endpoint every AWS client is pointed at instead. |
| `spiffe.gcpIitProjectIdAllowList` | `STS_SPIFFE_GCP_IIT_PROJECT_ID_ALLOW_LIST` | (empty) | yes | Projects allowed; required. |
| `spiffe.gcpIitAgentPathTemplate` | `STS_SPIFFE_GCP_IIT_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's agent_path_template for gcp_iit. |
| `spiffe.gcpIitUseInstanceMetadata` | `STS_SPIFFE_GCP_IIT_USE_INSTANCE_METADATA` | `false` | yes | Read the instance from Compute Engine for tag/label/metadata selectors. |
| `spiffe.gcpIitAllowedLabelKeys` | `STS_SPIFFE_GCP_IIT_ALLOWED_LABEL_KEYS` | (empty) | yes | Instance labels made selectors. |
| `spiffe.gcpIitAllowedMetadataKeys` | `STS_SPIFFE_GCP_IIT_ALLOWED_METADATA_KEYS` | (empty) | yes | Instance metadata made selectors. |
| `spiffe.gcpIitMaxMetadataValueSize` | `STS_SPIFFE_GCP_IIT_MAX_METADATA_VALUE_SIZE` | `128` | yes | Longest allowed metadata value. |
| `spiffe.gcpIitServiceAccountFile` | `STS_SPIFFE_GCP_IIT_SERVICE_ACCOUNT_FILE` | (empty) | yes | A service account key FILE; empty uses application default credentials. |
| `spiffe.gcpIitCertsUrl` | `STS_SPIFFE_GCP_IIT_CERTS_URL` | Google's | yes | Where Google publishes the identity-token certificates. |
| `spiffe.azureImdsTenants` | `STS_SPIFFE_AZURE_IMDS_TENANTS` | (empty) | yes | azure_imds tenants as JSON: tenantId, tokenAuth (a token FILE), allowed VM tags, subscriptions. No app secret is ever a setting. |
| `spiffe.azureImdsAgentPathTemplate` | `STS_SPIFFE_AZURE_IMDS_AGENT_PATH_TEMPLATE` | (empty) | yes | SPIRE's agent_path_template for azure_imds. |
| `spiffe.azureImdsAllowedMetadataDomains` | `STS_SPIFFE_AZURE_IMDS_ALLOWED_METADATA_DOMAINS` | `metadata.azure.com` | yes | Domains the attested document's signing certificate must name. |
| `spiffe.azureImdsTrustBundle` | `STS_SPIFFE_AZURE_IMDS_TRUST_BUNDLE` | (empty) | yes | Extra PEM roots beside the DigiCert roots SPIRE embeds. |
| `spiffe.azureImdsIntermediateHost` | `STS_SPIFFE_AZURE_IMDS_INTERMEDIATE_HOST` | `www.microsoft.com` | yes | The only host a CA Issuers URL may name. |
| `spiffe.azureImdsDiscoveryUrl` | `STS_SPIFFE_AZURE_IMDS_DISCOVERY_URL` | Microsoft's | yes | Where a tenant domain's ID is looked up. |
| `spiffe.workloadAttestors` | `STS_SPIFFE_WORKLOAD_ATTESTORS` | `unix` | yes | Workload attestors run for a Workload API Unix-socket connection and a SPIFFE Broker API process reference: unix, docker, k8s, systemd. Once per connection; every call checks the process is unchanged; a failing attestor refuses the connection. TCP callers are never attested. `systemd` needs the optional package `dbus-next`, and a realm naming it without that package refuses every connection. |
| `spiffe.workloadProcRoot` | `STS_SPIFFE_WORKLOAD_PROC_ROOT` | `/proc` | yes | Where a caller's process is read. A peer in another pid namespace is attested on its kernel uid and gid only. |
| `spiffe.unixDiscoverWorkloadPath` | `STS_SPIFFE_UNIX_DISCOVER_WORKLOAD_PATH` | `false` | yes | unix: add `path:` and `sha256:` for the caller's executable. |
| `spiffe.unixWorkloadSizeLimit` | `STS_SPIFFE_UNIX_WORKLOAD_SIZE_LIMIT` | `0` | yes | unix: 0 hashes any size, above 0 refuses a larger executable, -1 emits no `sha256:`. |
| `spiffe.dockerSocketPath` | `STS_SPIFFE_DOCKER_SOCKET_PATH` | `unix:///var/run/docker.sock` | yes | docker: the Engine API socket. |
| `spiffe.dockerApiVersion` | `STS_SPIFFE_DOCKER_API_VERSION` | (empty) | yes | docker: the Engine API version; empty is the Engine's default. |
| `spiffe.dockerPodmanSocketPath` | `STS_SPIFFE_DOCKER_PODMAN_SOCKET_PATH` | `unix:///run/podman/podman.sock` | yes | docker: the rootful Podman API socket, asked when a container's cgroup says `libpod` (#170). |
| `spiffe.dockerPodmanSocketPathTemplate` | `STS_SPIFFE_DOCKER_PODMAN_SOCKET_PATH_TEMPLATE` | `unix:///run/user/%d/podman/podman.sock` | yes | docker: the rootless Podman socket; `%d` is the uid of the container's `user-<uid>.slice`, exactly once. |
| `spiffe.dockerUseRootlessPodman` | `STS_SPIFFE_DOCKER_USE_ROOTLESS_PODMAN` | `false` | yes | docker: attest rootless Podman containers. **WARNING**: that socket is in the caller's own runtime directory and answers what the caller likes; pair its entries with `unix:uid` or `unix:user`. Off, a rootless container gets no docker selectors. |
| `spiffe.dockerSigstoreEnabled` | `STS_SPIFFE_DOCKER_SIGSTORE_ENABLED` | `false` | yes | docker: require a cosign image signature that verifies, with its Rekor bundle, and add SPIRE's `image-signature…` selectors. A signature that does not verify refuses the connection (#170). |
| `spiffe.dockerSigstorePublicKeyFiles` | `STS_SPIFFE_DOCKER_SIGSTORE_PUBLIC_KEY_FILES` | (empty) | yes | docker sigstore: cosign public key FILES (ECDSA, RSA, Ed25519, ML-DSA, SLH-DSA, composite). |
| `spiffe.dockerSigstoreTrustedRootFile` | `STS_SPIFFE_DOCKER_SIGSTORE_TRUSTED_ROOT_FILE` | (empty) | yes | docker sigstore: a pinned sigstore `trusted_root.json` FILE — Fulcio CAs, Rekor and CT log keys — used while TUF is off. |
| `spiffe.dockerSigstoreAllowedIdentities` | `STS_SPIFFE_DOCKER_SIGSTORE_ALLOWED_IDENTITIES` | (empty) | yes | docker sigstore: `issuer=subject` pairs a keyless signer must match (regular expressions where they hold one of SPIRE's characters, unanchored as cosign's). Empty admits no keyless signer. |
| `spiffe.dockerSigstoreSkippedImages` | `STS_SPIFFE_DOCKER_SIGSTORE_SKIPPED_IMAGES` | (empty) | yes | docker sigstore: repository digests attested without verification. |
| `spiffe.dockerSigstoreAllowedRegistries` | `STS_SPIFFE_DOCKER_SIGSTORE_ALLOWED_REGISTRIES` | (empty) | yes | docker sigstore: the registry hosts (and token realms, and blob redirect hosts) signatures are fetched from; the image names the registry, so none other is dialled. Empty refuses every registry. Docker Hub is `index.docker.io`. |
| `spiffe.dockerSigstoreRegistryAuthFile` | `STS_SPIFFE_DOCKER_SIGSTORE_REGISTRY_AUTH_FILE` | (empty) | yes | docker sigstore: a Docker `config.json` FILE of registry credentials; empty is anonymous. |
| `spiffe.dockerSigstoreSkipTlog` | `STS_SPIFFE_DOCKER_SIGSTORE_SKIP_TLOG` | `false` | yes | docker sigstore: skip the Rekor transparency log. **WARNING**: a signature never logged — a stolen key's, or a keyless one past its certificate — then verifies. |
| `spiffe.dockerSigstoreIgnoreSct` | `STS_SPIFFE_DOCKER_SIGSTORE_IGNORE_SCT` | `false` | yes | docker sigstore: do not require the keyless certificate's embedded SCT. **WARNING**: a Fulcio certificate never logged is then accepted. |
| `spiffe.dockerSigstoreIgnoreAttestations` | `STS_SPIFFE_DOCKER_SIGSTORE_IGNORE_ATTESTATIONS` | `false` | yes | docker sigstore: do not require in-toto attestations; off (SPIRE's default) refuses an image that has none. |
| `spiffe.dockerSigstoreTufUrl` | `STS_SPIFFE_DOCKER_SIGSTORE_TUF_URL` | `https://tuf-repo-cdn.sigstore.dev` | yes (per process) | docker sigstore: the TUF repository the trust root is refreshed from. |
| `spiffe.dockerSigstoreTufRootFile` | `STS_SPIFFE_DOCKER_SIGSTORE_TUF_ROOT_FILE` | (empty) | yes (per process) | docker sigstore: the TUF `root.json` FILE first trusted; empty turns TUF off. A refresh that fails keeps the last verified set. |
| `spiffe.dockerSigstoreTufRefreshS` | `STS_SPIFFE_DOCKER_SIGSTORE_TUF_REFRESH_S` | `86400` | yes (per process) | docker sigstore: how often the scheduler job `spiffe.sigstore-tuf-refresh` runs; 0 is off. |
| `spiffe.k8sKubeletReadOnlyPort` | `STS_SPIFFE_K8S_KUBELET_READ_ONLY_PORT` | `0` | yes | k8s: above 0, the pod list is read over plain HTTP on loopback. |
| `spiffe.k8sKubeletSecurePort` | `STS_SPIFFE_K8S_KUBELET_SECURE_PORT` | `0` | yes | k8s: the kubelet's secure port, dialled; 0 is its own 10250. |
| `spiffe.k8sNodeName` | `STS_SPIFFE_K8S_NODE_NAME` | (empty) | yes | k8s: the kubelet host; empty reads the next setting's variable, and with neither the kubelet is 127.0.0.1 checked for its chain only. |
| `spiffe.k8sNodeNameEnv` | `STS_SPIFFE_K8S_NODE_NAME_ENV` | `MY_NODE_NAME` | yes | k8s: the environment variable holding the node name. |
| `spiffe.k8sCertificateFile` | `STS_SPIFFE_K8S_CERTIFICATE_FILE` | (empty) | yes | k8s: client certificate FILE for the kubelet; empty uses a token. |
| `spiffe.k8sPrivateKeyFile` | `STS_SPIFFE_K8S_PRIVATE_KEY_FILE` | (empty) | yes | k8s: its private key FILE. |
| `spiffe.k8sUseAnonymousAuthentication` | `STS_SPIFFE_K8S_USE_ANONYMOUS_AUTHENTICATION` | `false` | yes | k8s: no token and no certificate. |
| `spiffe.k8sTokenFile` | `STS_SPIFFE_K8S_TOKEN_FILE` | (empty) | yes | k8s: bearer token FILE; empty is the in-cluster service account's. |
| `spiffe.k8sSkipKubeletVerification` | `STS_SPIFFE_K8S_SKIP_KUBELET_VERIFICATION` | `false` | yes | k8s: do not verify the kubelet's certificate (SPIRE's `skip_kubelet_verification`). **Development only** since #171: product mode ignores it (`STS-SPIFFE-0116`) and refuses to set it (`STS-CORE-0103`). |
| `spiffe.k8sKubeletCaFile` | `STS_SPIFFE_K8S_KUBELET_CA_FILE` | (empty) | yes | k8s: the kubelet's CA FILE; empty is the in-cluster `ca.crt`. |
| `spiffe.k8sMaxPollAttempts` | `STS_SPIFFE_K8S_MAX_POLL_ATTEMPTS` | `60` | yes | k8s: pod list reads before a missing container fails. |
| `spiffe.k8sPollRetryIntervalMs` | `STS_SPIFFE_K8S_POLL_RETRY_INTERVAL_MS` | `500` | yes | k8s: between those reads. |
| `spiffe.k8sDisableContainerSelectors` | `STS_SPIFFE_K8S_DISABLE_CONTAINER_SELECTORS` | `false` | yes | k8s: pod selectors only. |
| `spiffe.k8sEnableNamespaceLabels` | `STS_SPIFFE_K8S_ENABLE_NAMESPACE_LABELS` | `false` | yes | k8s: add `ns-label:` selectors from the API server. |
| `spiffe.maxJoinTokens` | `STS_SPIFFE_MAX_JOIN_TOKENS` | `256` | yes | Unspent, unexpired join tokens a realm holds. At the bound a NEW token is refused with RESOURCE_EXHAUSTED; a token already handed to an agent is never evicted. |
| `spiffe.maxPageSize` | `STS_SPIFFE_MAX_PAGE_SIZE` | `1000` | yes | The cap on `page_size` for every SPIRE Server API `List*` method. |
| `spiffe.maxRecordedConnections` | `STS_SPIFFE_MAX_RECORDED_CONNECTIONS` | `512` | yes (per process — a realm may not carry it) | How many mTLS connections are remembered so an X509-SVID is one authentication per connection rather than per call. |
| `spiffe.bundlePath` | `STS_SPIFFE_BUNDLE_PATH` | `/spiffe/bundle` | **restart** — the route is registered once, at startup, by `common/protocol_stack.ts`, in the route order | Where the trust bundle is published. A real federation partner is configured with this URL and polls it. |
| `spiffe.workloadSocketEnabled` | `STS_SPIFFE_WORKLOAD_SOCKET_ENABLED` | `true` | **restart** — the listener is bound when the process starts | Whether the Workload API is served on a Unix domain socket. ON by default because that is what SPIFFE_ENDPOINT_SOCKET means to every real client — go-spiffe, spiffe-helper, the SPIRE agent — so without it nothing connects unconfigured. |
| `spiffe.workloadSocket` | `STS_SPIFFE_WORKLOAD_SOCKET` | `/tmp/spire-agent/public/api.sock` | **restart** — the listener is bound when the process starts | Where that socket lives. SPIRE's own default path, so a client that was pointed at a SPIRE agent needs no change. |
| `spiffe.workloadPort` | `STS_SPIFFE_WORKLOAD_PORT` | `8092` | **restart** — the listener is bound when the process starts | The Workload API over TCP, which the Workload Endpoint specification permits (tcp://host:port) only where the network authenticates the source address, and which is how this is reached from another container or from a host that cannot share the socket. 0 turns it off and leaves the Unix socket alone. **In product mode the port is not bound unless `spiffe.workloadTcpSourceAuthenticated` is on** (`STS-SPIFFE-0120`, #166). |
| `spiffe.workloadTcpSourceAuthenticated` | `STS_SPIFFE_WORKLOAD_TCP_SOURCE_AUTHENTICATED` | `false` | **restart**, and **settable on a REALM** — it decides whether the port is bound | **Product mode only.** Declares the SPIFFE Workload Endpoint specification's section 3 condition for TCP: that the network lets this server strongly authenticate a workload by its source IP address (a pod network with anti-spoofing, a host-only bridge). Without it product does not serve the Workload API over TCP; with it, a wildcard `spiffe.grpcHost` is still refused (`STS-SPIFFE-0121`) — name the address you vouch for. **WARNING**: every host that reaches the port from an address an entry selects (`peer:<address>`) is issued that entry's SVIDs, so an address that can be spoofed, shared behind a NAT or reassigned hands the identity to whoever holds it. Development serves TCP whatever this says. |
| `spiffe.serverPort` | `STS_SPIFFE_SERVER_PORT` | `8181` | **restart** — the listener is bound when the process starts | The SPIRE Server API — Entry, Agent, Bundle, SVID, TrustDomain and Debug — over gRPC. |
| `spiffe.serverSocketEnabled` | `STS_SPIFFE_SERVER_SOCKET_ENABLED` | `false` | **restart** — the listener is bound when the process starts | Whether the SPIRE Server API is also served on a Unix socket, which is where a real spire-server keeps its administrative API. |
| `spiffe.serverSocket` | `STS_SPIFFE_SERVER_SOCKET` | `/tmp/spire-server/private/api.sock` | **restart** — the listener is bound when the process starts | Where that socket lives when it is on. SPIRE's own default path, for the same reason the Workload API's is. |
| `spiffe.brokerPort` | `STS_SPIFFE_BROKER_PORT` | `0` | **restart**, and **settable on a REALM** — a realm's listener is bound when its SPIFFE is turned on | The SPIFFE Broker API (#170) over gRPC with mutual TLS on `spiffe.grpcHost`. A broker presents an X509-SVID naming it in `spiffe.brokers` and asks for the SVIDs of a workload it references — a process id or a Kubernetes pod — which this service attests. 0 binds nothing. |
| `spiffe.brokers` | `STS_SPIFFE_BROKERS` | *(empty)* | yes | The brokers: `<SPIFFE ID>=<types>` entries separated by spaces, the types from `pid`, `k8s` and `*`. Managed on `/admin/spiffe/brokers`. **WARNING**: the endpoint is TCP and a process id means something only on this host — allow `pid` only to a broker on it. |
| `spiffe.grpcHost` | `STS_SPIFFE_GRPC_HOST` | `0.0.0.0` | **restart**, and **settable on a REALM** — a realm's listeners are bound when its SPIFFE is turned on | The address every TCP gRPC listener binds — the Workload API's, the SPIRE Server API's and the SPIFFE Broker API's. 0.0.0.0 is every interface, which is what a container needs; 127.0.0.1 confines them to the machine this runs on. **THIS IS THE ROW THAT KEEPS TWO REALMS APART**: each takes an address of its own and keeps the ports, because the endpoint address is the only thing a SPIFFE client has to name a tenant with. A realm left on the wildcard collides with the default realm's listeners, and the refusal says so by name. |
| `ssf.authBasic` | `STS_SSF_AUTH_BASIC` | `true` | yes | Whether the Shared Signals endpoints accept HTTP Basic. Development accepts any name with any password but `invalid`; product mode verifies it against the person's hashed `userPassword`. A Basic principal holds both scopes either way — turn this off to enforce `ssf:read`/`ssf:write` for every caller. |
| `ssf.actOnSignalsInDevelopment` | `STS_SSF_ACT_ON_SIGNALS_IN_DEVELOPMENT` | `false` | yes | The console and portal end their own sessions for the person a verified received signal names, where the `signal-response` policy permits it, in development mode too. Product always does; an unverified signal is never acted on. |
| `ssf.pushAllowHttp` | `STS_SSF_PUSH_ALLOW_HTTP` | `false` | yes | Push to an `http://` receiver, in development mode only; product refuses plain http whatever it says (`STS-SSF-0108`). This service's own receivers are exempt. |
| `ssf.pushSkipTlsVerification` | `STS_SSF_PUSH_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only.** Push without verifying the receiver's certificate. Product ignores it (`STS-SSF-0109`) and refuses to set it (`STS-CORE-0103`). |
| `ssf.pushCaFile` | `STS_SSF_PUSH_CA_FILE` | `` | yes | A PEM file of CA certificates a receiver may chain to, beside node's store. |
| `ssf.pushMaxResponseBytes` | `STS_SSF_PUSH_MAX_RESPONSE_BYTES` | `65536` | yes | How much of a receiver's answer to a push is read before the push counts as failed. |
| `ssf.pushRetries` | `STS_SSF_PUSH_RETRIES` | `0` | yes | How many times a failed push is tried again. `0` is what this service always did. Only a connection failure, a timeout, a 5xx or a 429 is retried — never a receiver's 400 refusal. |
| `ssf.pushRetryDelayMs` | `STS_SSF_PUSH_RETRY_DELAY_MS` | `1000` | yes | The wait before a retry, times the attempt number. |
| `ssf.pushConcurrency` | `STS_SSF_PUSH_CONCURRENCY` | `8` | yes | How many pushes one process makes at once; the rest wait in order. `0` removes the cap. **Per process, not per cluster**: N nodes of P processes push up to N×P× this at once. |
| `ssf.pushBacklog` | `STS_SSF_PUSH_BACKLOG` | `2000` | yes | How many pushes may wait for a slot. Past it the SET goes to the stream's dead-letter queue instead of being pushed. Per process, like the cap. |
| `ssf.deadStreamTimeoutS` | `STS_SSF_DEAD_STREAM_TIMEOUT_S` | `300` | yes | A push stream whose pushes have all failed for this long is declared **dead**: nothing more is pushed, its SETs go to its dead-letter queue, and one is pushed as a probe each period — a success revives it (so does `POST /admin-api/ssf/revive`). `0` turns it off. |
| `ssf.deadLetterRetentionS` | `STS_SSF_DEAD_LETTER_RETENTION_S` | `3600` | yes | How long an undeliverable SET is kept on its stream's dead-letter queue, with the reason, for inspection on `/admin/ssf` and counted on Monitoring → Shared Signals → Dead letters (`/admin/ssf/dead-letters`). |
| `ssf.deadLetterMaxPerStream` | `STS_SSF_DEAD_LETTER_MAX_PER_STREAM` | `1000` | yes | The most dead letters one stream keeps; past it the oldest is deleted. |
| `ssf.deadLetterSweepS` | `STS_SSF_DEAD_LETTER_SWEEP_S` | `60` | yes | How often each process deletes expired dead letters, probes due dead streams and logs **one** summary line of what could not be delivered — never a line per SET. |
| `ssf.inactivityTimeoutS` | `STS_SSF_INACTIVITY_TIMEOUT_S` | `0` | yes | SSF 1.0 section 8.1.1's `inactivity_timeout`: a stream whose receiver has made no management call about it (and, for a poll stream, no poll) for this long is dealt with as `ssf.inactivityAction` says. `0`, the default, is no timeout. It is off by default because a push receiver never calls back. |
| `ssf.inactivityAction` | `STS_SSF_INACTIVITY_ACTION` | `pause` | yes | `pause`, `disable` or `delete`. A pause or disable is announced with a stream-updated event before the stream stops. |
| `ssf.verificationEveryS` | `STS_SSF_VERIFICATION_EVERY_S` | `0` | yes | Sends every enabled stream a transmitter-initiated verification event (no `state`) when it has had none for this long. `0` sends none on a schedule. |
| `ssf.streamMaintenanceSweepS` | `STS_SSF_STREAM_MAINTENANCE_SWEEP_S` | `60` | yes | How often the `ssf.stream-maintenance` scheduler job applies the two settings above. |
| `ssf.receiveAudiences` | `STS_SSF_RECEIVE_AUDIENCES` | *(empty)* | yes | The `aud` values `POST /ssf/receive` accepts. Empty means the endpoint's own URL. Anything else is recorded and refused with `invalid_audience`. |
| `ssf.receiveIssuers` | `STS_SSF_RECEIVE_ISSUERS` | *(empty)* | yes | The `iss` values `POST /ssf/receive` accepts. Empty means this realm's own transmitter issuer. Anything else is recorded and refused with `invalid_issuer`. |
| `caep.eventsPerSession` | `STS_CAEP_EVENTS_PER_SESSION` | `25` | yes | How many recent events a CAEP register row lists; the per-type counts beside it never forget. |
| `caep.historyPerSession` | `STS_CAEP_HISTORY_PER_SESSION` | `10` | yes | How many credential changes a CAEP row keeps. |
| `risc.eventsPerAccount` | `STS_RISC_EVENTS_PER_ACCOUNT` | `25` | yes | How many recent events a RISC register row lists. |
| `risc.historyPerAccount` | `STS_RISC_HISTORY_PER_ACCOUNT` | `10` | yes | How many credential-compromise and identifier-change records a RISC row keeps, each. |
| `risc.recycleWindowDays` | `STS_RISC_RECYCLE_WINDOW_DAYS` | `365` | yes | How long after an account released an email address or phone number another account taking it is reported as RISC `identifier-recycled` (#146). Bounded by `risc.maxAccountsTracked` too. `0` reports nothing. |
| `risc.optOutDelayHours` | `STS_RISC_OPT_OUT_DELAY_HOURS` | `24` | yes | How long an account holder's opt-out on `/portal/signals` stays in `opt-out-initiated` before the `risc.opt-out-effective` scheduler job makes it effective (RISC section 2.8, #146). |
| `risk.listsMatchSpecialPurpose` | `STS_RISK_LISTS_MATCH_SPECIAL_PURPOSE` | `true` | yes | On, a Tor, reputation or operator deny list matches a loopback, private, link-local or reserved address exactly as the list says (FireHOL level 1 lists the bogons). Off sets those matches aside and records it on the assessment — for a service tested on one machine, or where every person arrives through one private bridge, NAT or proxy address (#226). Monitoring → Risk. |
| `risk.datasetsDirectory` | `STS_RISK_DATASETS_DIRECTORY` | *(empty)* | yes | A directory the `risk.dataset-directory` job imports risk datasets from: each `<name>.json` manifest names a dataset, a format and the file beside it. How a GeoIP dataset of millions of rows arrives — an operator pipeline puts it there; this service fetches nothing. Empty turns the job off. |
| `risk.datasetsDirectoryScanS` | `STS_RISK_DATASETS_DIRECTORY_SCAN_S` | `300` | yes | How often that directory is read. A version already recorded is never loaded twice. |
| `risk.uploadDirectory` | `STS_RISK_UPLOAD_DIRECTORY` | `./data/risk-uploads` | yes | Where an uploaded dataset file is written while it is imported, and deleted from when the import ends. Relative to the package root. Every stack this repository ships mounts a volume here; give it room for the largest file you upload, compressed. |
| `risk.uploadMaxBytes` | `STS_RISK_UPLOAD_MAX_BYTES` | `2147483648` | yes | The largest file an upload may be, as sent. A declared length over it is refused before anything is read. |
| `risk.expandedMaxBytes` | `STS_RISK_EXPANDED_MAX_BYTES` | `8589934592` | yes | The most a `.gz` or `.zip` dataset file may expand to, from any door. Past it the version is refused as a decompression bomb. |
| `risk.expansionMaxRatio` | `STS_RISK_EXPANSION_MAX_RATIO` | `100` | yes | The most a compressed dataset file may expand per byte stored, once past 16 MiB. |
| `risk.importStallMinutes` | `STS_RISK_IMPORT_STALL_MINUTES` | `15` | yes | A version still loading with no progress for this long is refused by the `risk.stalled-imports` job, and an upload file untouched this long is deleted by `risk.upload-cleanup`. |
| `risk.uploadSweepS` | `STS_RISK_UPLOAD_SWEEP_S` | `60` | yes | How often those two jobs run. Keep it well under `risk.importStallMinutes`. |
| `risk.datasetShrinkLimitPercent` | `STS_RISK_DATASET_SHRINK_LIMIT_PERCENT` | `50` | yes | A new version with this many percent fewer rows than the active one is refused and the active one stays — a truncated download looks exactly like a smaller dataset. |
| `risk.supersededRetentionDays` | `STS_RISK_SUPERSEDED_RETENTION_DAYS` | `30` | yes | How long a superseded version's rows are kept for rollback; GeoLite2's licence says thirty. |
| `risk.geoStaleAfterDays` | `STS_RISK_GEO_STALE_AFTER_DAYS` | `45` | yes | How old a geolocation or ASN version may be before it counts for nothing. Stale data never refuses a sign-in. |
| `risk.ipListStaleAfterHours` | `STS_RISK_IP_LIST_STALE_AFTER_HOURS` | `24` | yes | The same for a Tor exit or reputation list; an operator's own lists are never stale. |
| `risk.recordFailures` | `STS_RISK_RECORD_FAILURES` | `true` | yes | Whether every refused password, at every door that checks one, is recorded with the person (or a keyed digest of a name that matched nobody), the network and the code — in the database only where the address can be sealed. |
| `risk.failureRetentionDays` | `STS_RISK_FAILURE_RETENTION_DAYS` | `30` | yes | How long a recorded failure is kept. |
| `risk.assessSignIns` | `STS_RISK_ASSESS_SIGN_INS` | `true` | yes | Whether every sign-in that starts or re-authenticates a session is scored — the Freeman et al. model plus the evaluators — recorded on Monitoring → Risk, and its facts handed to the issuance policy with every session and token that rests on it (#62 P3). Off, the policy decides on roles alone. |
| `risk.enforceInDevelopment` | `STS_RISK_ENFORCE_IN_DEVELOPMENT` | `false` | yes | Enforce the issuance policy's risk decisions in development mode too. Product mode always enforces them; development records them and lets the issuance through. |
| `risk.standingValidMinutes` | `STS_RISK_STANDING_VALID_MINUTES` | `720` | yes | How long a person's last assessed risk stands in for an issuance with no session to read it from — a Kerberos ticket, a WS-Trust token. |
| `risk.standingCacheSize` | `STS_RISK_STANDING_CACHE_SIZE` | `20000` | yes | How many people's standing each process holds; full, the oldest is dropped, which decides that person's next sessionless issuance on roles alone. |
| `risk.mediumScorePercent` | `STS_RISK_MEDIUM_SCORE_PERCENT` | `100` | yes | The score, in hundredths, from which a sign-in is MEDIUM (100 is a score of 1). |
| `risk.highScorePercent` | `STS_RISK_HIGH_SCORE_PERCENT` | `1000` | yes | The score, in hundredths, from which a sign-in is HIGH. |
| `risk.signalFactors` | `STS_RISK_SIGNAL_FACTORS` | *(empty)* | yes | Factors over the built-in ones, as `signal=factor`, comma-separated (`tor-exit=8,new-device=1.5`): what Monitoring → Risk Scoring's calibration suggests, applied without a release. A bad entry is ignored and logged (`STS-RISK-0026`). |
| `risk.calibrationMediumPercent` | `STS_RISK_CALIBRATION_MEDIUM_PERCENT` | `5` | yes | The share of sign-ins the calibration report aims to have at MEDIUM or worse; it suggests the score that share reaches. Advice only. |
| `risk.calibrationHighPercent` | `STS_RISK_CALIBRATION_HIGH_PERCENT` | `1` | yes | The same, for HIGH. |
| `risk.assessmentRetentionDays` | `STS_RISK_ASSESSMENT_RETENTION_DAYS` | `90` | yes | How long an assessment is kept. |
| `risk.historyRetentionDays` | `STS_RISK_HISTORY_RETENTION_DAYS` | `180` | yes | How long the model remembers a value nobody has signed in with since — an address, a network, a device. |
| `risk.fingerprinting` | `STS_RISK_FINGERPRINTING` | `false` | yes | OFF BY DEFAULT (#62 P6). The sign-in screen runs FingerprintJS (MIT; it sends nothing) and the service keeps a keyed digest of the browser's identifier, scoring a browser the person never used as `new-device`. Personal data: complete the privacy impact assessment in [Risk scoring](risk-scoring.md) first. |
| `risk.breachCheck` | `STS_RISK_BREACH_CHECK` | `on` | yes | In product mode, refuse a password known from a data breach: its SHA-1's first five characters go to the Pwned Passwords range API (k-anonymity) and the match is made here (#62 P6). An unreachable API sets the password unchecked. |
| `risk.breachCheckAtSignIn` | `STS_RISK_BREACH_CHECK_AT_SIGN_IN` | `true` | yes | Also check a correct password at the sign-in screen, and make a breached one be changed before the sign-in finishes. |
| `risk.breachApiUrl` | `STS_RISK_BREACH_API_URL` | `https://api.pwnedpasswords.com/range/` | yes | Where the prefix is sent — a mirror keeps the check inside your network. Through the outbound rules. |
| `risk.breachCacheMinutes` | `STS_RISK_BREACH_CACHE_MINUTES` | `60` | yes | How long a prefix's answer is reused. |
| `risk.breachCacheSize` | `STS_RISK_BREACH_CACHE_SIZE` | `5000` | yes | How many prefix answers each process keeps. |
| `risk.breachTimeoutMs` | `STS_RISK_BREACH_TIMEOUT_MS` | `3000` | yes | How long a password being set waits for the range API. |
| `risk.mdsTrustAnchors` | `STS_RISK_MDS_TRUST_ANCHORS` | *(empty)* | yes | The certificates a FIDO MDS3 BLOB's signing chain must end at (#62 P5), as PEM; empty uses the FIDO root, GlobalSign Root CA - R3, from node's own root store — nothing FIDO-specific is shipped. |
| `risk.mdsStaleGraceDays` | `STS_RISK_MDS_STALE_GRACE_DAYS` | `7` | yes | How long past its own `nextUpdate` the active MDS3 BLOB still answers; after it no authenticator's status is known. |
| `risk.mdsUrl` | `STS_RISK_MDS_URL` | *(empty)* | yes | Where the `risk.mds-refresh` job downloads the MDS3 BLOB from (#105; FIDO's is `https://mds3.fidoalliance.org/`). Empty dials nobody. Fetched through the outbound rules (`federation.outbound`, https, no internal address in product, no redirect) and imported only under a recorded acceptance of `fido-mds3`'s terms, after the full verification; a serial not above the active one is left alone. |
| `risk.mdsRefreshS` | `STS_RISK_MDS_REFRESH_S` | `86400` | yes | How often the job downloads it; hourly once the active BLOB is past its `nextUpdate`. |
| `risk.mdsMaxBytes` | `STS_RISK_MDS_MAX_BYTES` | `33554432` | yes | The most the job reads of a BLOB. |
| `risk.rescoreEveryS` | `STS_RISK_RESCORE_EVERY_S` | `300` | yes | How often the `risk.rescore` job re-checks every live sign-on session against the datasets and the failure history, raising (never lowering) one that became riskier (#62 P4). |
| `xacml.signalResponsePolicy` | `STS_XACML_SIGNAL_RESPONSE_POLICY` | `signal-response` | yes | The policy asked, when this service's own console or portal receives a verified CAEP or RISC event, whether it ends that surface's own sessions for the person named. Built in; a realm's entry of this name overrides it. |
| `xacml.riskResponsePolicy` | `STS_XACML_RISK_RESPONSE_POLICY` | `risk-response` | yes | The policy asked, once per reaction, what happens when a person's risk level changes: a CAEP risk-level-change, everything they hold ended, a RISC credential-compromise, the account disabled. Built in; a realm's entry of this name overrides it. |
| `persistence.mode` | `STS_PERSISTENCE_MODE` | `memory` | **restart** — the store is opened and READ before the HTTP listener binds, so a mode changed at runtime would leave a service whose directory came from one place and whose writes went to another | Where the embedded directory, the trust realm registry and the runtime setting changes are written down. `memory` writes nothing. `ldif` writes an RFC 2849 file per realm plus two JSON files into `dataDir` and needs no database. `postgres` writes six tables. What this service MINTS — sessions, tokens, codes, artifacts, Kerberos principals, the replay caches, the counters and the audit log — is persisted in PRODUCT mode on `postgres` and in no other configuration, each row encrypted under the same key-encryption key as the signing keys; development mode persists none of it, because the signing key is regenerated on every start there. See [Persistence](#persistence) above. |
| `persistence.dataDir` | `STS_PERSISTENCE_DATA_DIR` | `./data` | **restart** — same reason | Where `ldif` mode writes. A relative path resolves against the package root rather than the working directory, for the reason `CONFIG_FILE` does. Ignored in the other two modes. In a container this is what a volume mounts over. |
| `persistence.databaseUrl` | `STS_DATABASE_URL` | `postgres://sts:sts@localhost:5432/sts` | **restart** — the connection pool is opened before the listener binds | The connection string `postgres` mode dials. **The default names an OWNER and the compose stack does not**: the default is for a local database with nothing in it, which this service builds for itself, while the stack dials the least-privileged `sts_app` that `postgres/schema.sql` created — see *Building the schema*. The default is a LOCAL DEVELOPMENT one matching the Postgres service in this repository's `docker-compose.yml` (user, password and database all `sts`), so turning persistence on against a local database is one setting rather than two. **It is never dialled unless `persistence.mode` is `postgres`**, which is not the default, so it is inert on an ordinary run. The compose stack sets this variable itself with `postgres` as the host, that being the service name on its network. It carries a password, so this service never echoes it back — `/admin/persistence` reports the host, port, database and user parsed out of it. |
| `keys.vaultClientCert` | `STS_KEYS_VAULT_CLIENT_CERT` | *(empty)* | **restart** | A PEM certificate this service presents to Vault or OpenBao, authenticating through the `cert` auth method instead of with a token. Set with `keys.vaultClientKey`. **The certificate should be issued BY the store** — that is what makes the identity the store's to grant and revoke rather than a file somebody copied in. The stack this repository ships does exactly that; see `openbao/`. |
| `keys.vaultClientKey` | `STS_KEYS_VAULT_CLIENT_KEY` | *(empty)* | **restart** | The private key for that certificate. Read at startup, never logged. |
| `keys.vaultCaCert` | `STS_KEYS_VAULT_CA_CERT` | *(empty)* | **restart** | What this service verifies the store's TLS listener against. **A different question from who signed the client certificate**, and usually a different certificate: one is the connection, the other is the identity. |
| `keys.vaultCertRole` | `STS_KEYS_VAULT_CERT_ROLE` | *(empty)* | **restart** | Which `auth/cert` role to log in against. Empty lets the store try every trusted certificate, which is what a store with one of them wants. |
| `keys.vaultCertAuthMount` | `STS_KEYS_VAULT_CERT_AUTH_MOUNT` | `cert` | **restart** | Where the `cert` auth method is mounted; the login goes to `auth/<this>/login`. A value that is not a plain path is refused rather than put into a request. |
| `keys.kidFormat` | `STS_KEYS_KID_FORMAT` | `internal` | yes, per realm | What the `kid` header of every JWT the realm signs names its key by: `internal` is this service's own opaque `sts-…` name; `jwk-thumbprint-uri` is the RFC 9278 JWK Thumbprint URI, `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<RFC 7638 thumbprint>`. **While it is on, the JWKS lists every signing key twice**, under both names, so tokens signed before the switch still verify; turning it off again drops the second entries. It names the key, not its certificate — that is `x5c`/`x5u` ([PKI](pki.md)). |
| `keys.signerModel` | `STS_KEYS_SIGNER_MODEL` | `per-algorithm` | yes, per realm | How the realm's signing keys are divided (#68). `per-algorithm` is one key per JWS algorithm, shared by every JOSE use, and one RSA key for XML. `hybrid-groups` gives each of five signer groups (OAuth/OIDC tokens, verifiable credentials, Security Event Tokens, WS-Trust and GNAP, XML) keys of its own: RSA-3072, P-256 and P-384, each certified together with an ML-DSA key (65, 44, 87) in one hybrid certificate (ITU-T X.509 clause 9.8), and SLH-DSA-SHA2-128s alone — 35 key pairs, made in the background when the realm is switched or the service starts. Every key is a key pair of its own; the certificate is what is shared. A JOSE signature made for a group's use signs with that group's key for its algorithm (RS*/PS* → RSA-3072, ES256, ES384, ML-DSA-44/65/87, SLH-DSA-SHA2-128s); any other algorithm still signs with the per-algorithm key. The JWKS publishes the JOSE groups' keys after the per-algorithm ones — classical keys with their hybrid certificate in `x5c`, a partnered ML-DSA key without. *XML signing with the `xml` group, and rotation of group keys, are still being built (#68).* |
| `persistence.databasePasswordProvider` | `STS_DATABASE_PASSWORD_PROVIDER` | `none` | **restart** — the pool is opened before the listener binds | Read the database password from a secret store at startup and inject it into `persistence.databaseUrl` instead of the password that string carries. The five providers are `keys.kekProvider`'s and the mechanism is the same one: `file`, `aws`, `gcp`, `azure`, `vault`. `none` changes nothing — the connection string is dialled exactly as written. **A read that fails stops the service**, like any other store that was configured and cannot be opened. |
| `persistence.databasePasswordRef` | `STS_DATABASE_PASSWORD_REF` | *(empty)* | **restart** | Where the password is in that provider: a path for `file`, a name or ARN for `aws`, a resource name for `gcp`, a secret name for `azure`, a read path for `vault`. **Empty means the same place as the key-encryption key** (`keys.kekFile` / `keys.kekRef`) — one mounted file or one cloud secret holding both, which is the arrangement most deployments want. A SHARED location holding something that is not a JSON object is refused rather than read: what is there is the key itself, and handing that to a database as a password is the mistake the refusal exists to prevent. |
| `persistence.databasePasswordField` | `STS_DATABASE_PASSWORD_FIELD` | `databasePassword` | **restart** | The member to take when the stored secret is a JSON object — `{"kek": "…", "databasePassword": "…"}` in one file, or the `{"username": …, "password": …}` shape AWS Secrets Manager writes for a database credential (set it to `password` for one of those). A secret of its own that is not JSON is taken whole; empty takes the value whole even where it is JSON. |
| `persistence.databasePasswordVault` | `STS_DATABASE_PASSWORD_VAULT` | *(empty)* | **restart** | The Vault endpoint or Key Vault URL the database password is read from. **Empty means the key-encryption key's store** (`keys.kekVault`), which is the arrangement most deployments want. |
| `persistence.databasePasswordRegion` | `STS_DATABASE_PASSWORD_REGION` | *(empty)* | **restart** | The AWS region for the database password. Empty means `keys.kekRegion`. |
| `persistence.databasePasswordToken` | `STS_DATABASE_PASSWORD_TOKEN` | *(empty)* | **restart** | A Vault token for the database password. Empty means `keys.kekToken`; ignored where a client certificate is configured. |
| `persistence.writeDelay` | `STS_PERSISTENCE_WRITE_DELAY` | `1500` | yes | How long a change waits before the `ldif` files are rewritten, so a burst — a realm build writes thirteen entries — costs one file write. What it risks is that many milliseconds of writes on a `kill -9`, which no process can trap; SIGTERM and SIGINT flush first. **Postgres ignores it** and uses 0: the unit of writing there is a transaction, so every change made while handling one request commits as one transaction the moment that request is done. |
| `persistence.changeLogRetentionS` | `STS_PERSISTENCE_CHANGE_LOG_RETENTION_S` | `3600` | yes | How long a row of `sts_changes` is kept at least. A row is removed only when older than this AND below the lowest position every process still reading the change log has reported; a reader silent this long, or whose cluster node is gone, is taken to be gone. `0` never trims. |
| `persistence.realms` | `STS_PERSISTENCE_REALMS` | `true` | **restart** — the realm rows are restored before the listener binds | Whether trust realm definitions — names, descriptions and per-realm settings — are written down beside the directory. Turning it off is a half-persisted service rather than a smaller one: a realm holds its own directory, so its entries would be stored with no realm to restore them into, and the next run's first write would remove them. |
| `persistence.appconfig` | `STS_PERSISTENCE_APPCONFIG` | `true` | **restart** — the saved overrides are applied before the listener binds | Whether a setting changed through the console or the management API survives a restart. It adds NO LAYER: the saved values are re-applied at startup through the same `setOverride()` a caller uses, so the five layers above are unchanged and a runtime override is simply durable. Only a runtime-changeable setting can be saved, because only one can be set — which is what makes applying them after every module has loaded safe. |

### Mail

The one outbound mail channel (#63): the transport this service sends through,
which a trust realm may override, its secrets (each a provider, a location and
a field, read through `common/secrets.js` — never a value here), the outbox the
`mail.deliver` job sweeps, the ceilings, and the uses built on it.
[Mail](mail.md) is the operator's guide; Server configuration →
**Mail** (`/admin/mail`) draws these rows.

| Setting | Environment | Default | Change while running | What it does |
|---|---|---|---|---|
| `mail.transport` | `STS_MAIL_TRANSPORT` | `default` | yes | How a message this service sends leaves it. |
| `mail.from` | `STS_MAIL_FROM` | *(empty)* | yes | The address every message is sent from. |
| `mail.fromName` | `STS_MAIL_FROM_NAME` | *(empty)* | yes | The display name beside the From address. |
| `mail.defaultLanguage` | `STS_MAIL_DEFAULT_LANGUAGE` | `en` | yes | The language a message is written in when the recipient's entry names no preferredLanguage this realm has a template for. |
| `mail.smtpPreset` | `STS_MAIL_SMTP_PRESET` | `custom` | yes | A known relay, which fills in the host (and port) when mail.smtpHost is empty. |
| `mail.smtpHost` | `STS_MAIL_SMTP_HOST` | *(empty)* | yes | The relay's host name. |
| `mail.smtpPort` | `STS_MAIL_SMTP_PORT` | `587` | yes | The relay's port: 587 for STARTTLS (submission), 465 for implicit TLS (submissions, RFC 8314). |
| `mail.smtpTls` | `STS_MAIL_SMTP_TLS` | `starttls` | yes | How the connection is protected. |
| `mail.smtpCaFile` | `STS_MAIL_SMTP_CA_FILE` | *(empty)* | yes | A PEM file of the CA certificate(s) the relay's certificate must chain to. |
| `mail.smtpServerName` | `STS_MAIL_SMTP_SERVER_NAME` | *(empty)* | yes | The name the relay's certificate must carry, when it is not mail.smtpHost (an address, or a name behind a load balancer). |
| `mail.smtpAuth` | `STS_MAIL_SMTP_AUTH` | `none` | yes | SMTP AUTH (RFC 4954) after TLS is up: `plain` or `login` with mail.smtpUser and the password secret, `xoauth2` with an OAuth 2.0 bearer (the secret holds either an access token or a JSON object with clientId, clientSecret, refreshToken and accessUrl). |
| `mail.smtpUser` | `STS_MAIL_SMTP_USER` | *(empty)* | yes | The SMTP AUTH username (or the XOAUTH2 mailbox). |
| `mail.smtpPasswordProvider` | `STS_MAIL_SMTP_PASSWORD_PROVIDER` | `none` | yes | The secret store the SMTP AUTH password (or XOAUTH2 credential) is read from — the providers keys.kekProvider offers, through common/secrets.js. |
| `mail.smtpPasswordRef` | `STS_MAIL_SMTP_PASSWORD_REF` | *(empty)* | yes | A path for `file`, a name or ARN for `aws`, a resource name for `gcp`, a secret name for `azure`, a read path for `vault`. |
| `mail.smtpPasswordField` | `STS_MAIL_SMTP_PASSWORD_FIELD` | *(empty)* | yes | The member of a JSON value to take. |
| `mail.smtpClientCertFile` | `STS_MAIL_SMTP_CLIENT_CERT_FILE` | *(empty)* | yes | A PEM certificate this service presents to the relay, for a relay that authenticates its clients by certificate. |
| `mail.smtpClientKeyFile` | `STS_MAIL_SMTP_CLIENT_KEY_FILE` | *(empty)* | yes | The PEM private key of mail.smtpClientCertFile, as a mounted file the way a listener's key is. |
| `mail.dkimDomain` | `STS_MAIL_DKIM_DOMAIN` | *(empty)* | yes | The d= of a DKIM-Signature (RFC 6376) this service puts on every message it sends through the SMTP transport. |
| `mail.dkimSelector` | `STS_MAIL_DKIM_SELECTOR` | *(empty)* | yes | The s= of the signature: the public key is published at <selector>._domainkey.<domain>. |
| `mail.dkimAlgorithm` | `STS_MAIL_DKIM_ALGORITHM` | `rsa-sha256` | yes | `rsa-sha256` (RFC 6376; a 2048-bit key or larger, per RFC 8301) or `ed25519-sha256` (RFC 8463). |
| `mail.dkimKeyProvider` | `STS_MAIL_DKIM_KEY_PROVIDER` | `none` | yes | The secret store the PEM private key of the DKIM selector is read from. |
| `mail.dkimKeyRef` | `STS_MAIL_DKIM_KEY_REF` | *(empty)* | yes | Its location in that store; empty means the key-encryption key's, with mail.dkimKeyField naming the member. |
| `mail.dkimKeyField` | `STS_MAIL_DKIM_KEY_FIELD` | *(empty)* | yes | The member of a JSON value to take. |
| `mail.sesRegion` | `STS_MAIL_SES_REGION` | *(empty)* | yes | The AWS region of the SES v2 endpoint (and of the `aws-ses-smtp` preset). |
| `mail.sesConfigurationSet` | `STS_MAIL_SES_CONFIGURATION_SET` | *(empty)* | yes | An SES configuration set to send under, for its event destinations and suppression settings. |
| `mail.acsEndpoint` | `STS_MAIL_ACS_ENDPOINT` | *(empty)* | yes | https://<resource>.communication.azure.com — used with mail.acsAuth `managed-identity`. |
| `mail.acsAuth` | `STS_MAIL_ACS_AUTH` | `managed-identity` | yes | `managed-identity` (the default, and the one with no secret to hold) authenticates with @azure/identity's DefaultAzureCredential against mail.acsEndpoint. |
| `mail.acsConnectionStringProvider` | `STS_MAIL_ACS_CONNECTION_STRING_PROVIDER` | `none` | yes | The secret store the Communication Services connection string is read from, when mail.acsAuth is `connection-string`. |
| `mail.acsConnectionStringRef` | `STS_MAIL_ACS_CONNECTION_STRING_REF` | *(empty)* | yes | Its location; empty means the key-encryption key's. |
| `mail.acsConnectionStringField` | `STS_MAIL_ACS_CONNECTION_STRING_FIELD` | *(empty)* | yes | The member of a JSON value to take. |
| `mail.gmailSender` | `STS_MAIL_GMAIL_SENDER` | *(empty)* | yes | The Workspace mailbox the service account impersonates (domain-wide delegation of the gmail.send scope). |
| `mail.gmailKeyProvider` | `STS_MAIL_GMAIL_KEY_PROVIDER` | `none` | yes | The secret store the service account's JSON key (client_email and private_key) is read from. |
| `mail.gmailKeyRef` | `STS_MAIL_GMAIL_KEY_REF` | *(empty)* | yes | Its location; empty means the key-encryption key's. |
| `mail.gmailKeyField` | `STS_MAIL_GMAIL_KEY_FIELD` | *(empty)* | yes | The member of a JSON value to take. |
| `mail.deliverS` | `STS_MAIL_DELIVER_S` | `15` | yes | How often the scheduler job `mail.deliver` sends every message that is due — a retry whose backoff has passed, a lease that lapsed, a row restored after a restart. |
| `mail.attempts` | `STS_MAIL_ATTEMPTS` | `5` | yes | How many times one message is tried before it becomes a DEAD LETTER. |
| `mail.backoffS` | `STS_MAIL_BACKOFF_S` | `60` | yes | The wait before the second attempt, doubling after each. |
| `mail.timeoutMs` | `STS_MAIL_TIMEOUT_MS` | `30000` | yes | How long one attempt may take, connection and TLS included — for Azure, the whole long-running send. |
| `mail.leaseMs` | `STS_MAIL_LEASE_MS` | `120000` | yes | How long a node holds the claim on one attempt. |
| `mail.concurrency` | `STS_MAIL_CONCURRENCY` | `4` | yes | How many messages one process sends at once from a sweep. |
| `mail.retentionS` | `STS_MAIL_RETENTION_S` | `604800` | yes | How long a row stays in the outbox after it was queued, finished or not: a message still pending this long is dead-lettered, and a finished one is removed. |
| `mail.maxRows` | `STS_MAIL_MAX_ROWS` | `10000` | yes | The cap on the outbox, per realm: the oldest FINISHED row is dropped first, and a pending one never. |
| `mail.ratePerRecipient` | `STS_MAIL_RATE_PER_RECIPIENT` | `20` | yes | The ceiling on messages to one person in mail.rateWindowS, whatever their category — so that a storm of risk events or an attacker pressing a button cannot turn this service into a mail cannon. |
| `mail.ratePerCategory` | `STS_MAIL_RATE_PER_CATEGORY` | `5` | yes | The ceiling on one category (security, account, notification) to one person in mail.rateWindowS. |
| `mail.rateWindowS` | `STS_MAIL_RATE_WINDOW_S` | `3600` | yes | The window both ceilings count over. |
| `mail.dedupWindowS` | `STS_MAIL_DEDUP_WINDOW_S` | `600` | yes | A notice that names what it is about (the same act on the same account) is sent once in this window, however many doors reported it. |
| `mail.selfServiceReset` | `STS_MAIL_SELF_SERVICE_RESET` | `true` | yes | Offer "Forgot your password?" on the sign-in screen and at /portal/forgot-password: a person names their account and a single-use /portal/reset-password link is mailed to the address on its entry. |
| `mail.resetRequiresVerifiedAddress` | `STS_MAIL_RESET_REQUIRES_VERIFIED_ADDRESS` | `true` | yes | Mail a self-service reset link only to an address the person has VERIFIED (a link they followed from it). |
| `mail.resetRequiresBackupCode` | `STS_MAIL_RESET_REQUIRES_BACKUP_CODE` | `true` | yes | The forgot-password form asks for the username, the verified address on the account AND one of the person's recovery codes, and mails a reset link only when all three are right — the code is spent then (#64). Every combination is answered with the same sentence. **Turning it off is a weaker setting**: the form goes back to one field, and a reset is then as strong as the mailbox. |
| `mail.verificationTtlMinutes` | `STS_MAIL_VERIFICATION_TTL_MINUTES` | `1440` | yes | How long an address verification link works. |
| `mail.securityNotices` | `STS_MAIL_SECURITY_NOTICES` | `true` | yes | Tell a person, at the address on their entry, when their account is disabled, their sessions are ended by an administrator, their password is changed or reset, their credential is marked compromised or recovery is started. |
| `mail.notifyAdministrators` | `STS_MAIL_NOTIFY_ADMINISTRATORS` | `true` | yes | When the SERVICE, not a person, marks a credential compromised or disables an account (risk scoring), also mail every member of the realm's Admin Write roster that has an address. |
