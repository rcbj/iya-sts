---
title: WS-Federation
---

# WS-Federation

iya-sts is a **WS-Federation identity provider**: the Web (Passive) Requestor
Profile of
[WS-Federation 1.2](https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html)
(section 13) — sign-in, sign-out and sign-out cleanup — with signed federation
metadata at the path AD FS publishes it, and a mock relying party. Every trust
realm has its own, with its own entityID, signing key and mock relying party.

A relying party redirects a browser to `/wsfed?wa=wsignin1.0`; the person signs
in at the service's one sign-in screen; and the browser comes back **with a
form POST, not a redirect**, carrying a WS-Trust `RequestSecurityTokenResponse`
that wraps a signed SAML assertion. Because the token travels in a form body it
is not length-limited and never lands in a URL, a log or a `Referer` header.

That form POST (section 13.2.2) shapes the response page. It needs a script to
submit itself, so the page relaxes `script-src` to `'self'` naming one real
resource, `/wsfed/autopost.js` — an inline script would not run at all,
silently, leaving a page that looks as if it is working and never posts. Its
submit button is labelled for a person rather than hidden, because with
scripting off the button *is* the mechanism. And `form-action` stays out of the
content security policy: the form posts to `wreply`, which is by definition
another origin, and `form-action 'self'` would block the response from ever
reaching the relying party while the sign-in still appeared to succeed.

## Features

### Endpoints

| Path | What it is |
|---|---|
| `GET\|POST /wsfed` | the passive requestor endpoint, dispatched on `wa`; with no `wa` it describes itself and every parameter, the way `GET /sts` does |
| `GET /FederationMetadata/2007-06/FederationMetadata.xml` | the signed federation metadata |
| `GET\|POST /wsfed/rp` | a **mock relying party** (not part of any specification) |
| `GET /wsfed/autopost.js` | the one script the sign-in response page runs |

In a trust realm every path is under `/realm/{id}`. The full, current list is
at `/admin/sts-metadata`.

### `wa`: the actions

| `wa` | What happens |
|---|---|
| `wsignin1.0` | sign in and POST a token to `wreply` (13.2.1, 13.2.2) |
| `wsignout1.0` | end the session and send `wsignoutcleanup1.0` to every relying party it signed into (13.2.4) |
| `wsignoutcleanup1.0` | end the session and stop — no further cleanup requests |
| `wattr1.0`, `wpseudo1.0` | answered 501 with an explanation: the attribute and pseudonym services are not implemented |

### Sign-in parameters

| Parameter | What is done with it |
|---|---|
| `wtrealm` | required; the relying party's identifier and the assertion's audience |
| `wreply` | where the response is POSTed — see [the mode table](#development-and-product-mode) |
| `wctx` | echoed back **byte for byte** and never interpreted |
| `wct` | the request timestamp; its skew is recorded, not enforced |
| `wfresh` | the maximum age of the authentication, in **minutes** — the one place this profile and OIDC's `max_age` differ in unit, and reading it as seconds makes every request look fresh: `0` forces the sign-in screen, `N` re-shows it when the session is older; a value that is not a number is refused. It is dropped on the way back from the sign-in screen, as `prompt=login` is, or it would demand a fresh authentication forever |
| `wauth` | an authentication method the relying party demands — see [`wauth`](#wauth-a-step-up-never-a-fake) |
| `whr` | the home realm; recorded and shown, nothing is forwarded |
| `wreq` | an RST by value; its `TokenType` chooses the token, and an `AppliesTo` that disagrees with `wtrealm` is logged (`wtrealm` wins) |
| `wreqptr` | **refused** — see below |
| `wp`, `wencoding` | logged; no policy is enforced |
| `tokenType`, `trust` | **non-spec** test controls: `tokenType=saml2` for a SAML 2.0 assertion, `trust=1.3` for the ws-sx 200512 wrapper |

### The token

**The default token is a SAML 1.1 assertion**, because that is what AD FS
issues to a WS-Federation relying party and what the libraries written against
it (WIF, `Microsoft.Owin.Security.WsFederation`) read first. A SAML 2.0 assertion is issued when the `wreq` RST's `TokenType`
asks for one, or with the non-spec `tokenType=saml2`. Both are offered in the
metadata's `fed:TokenTypesOffered`.

The assertion is built by the same builders as the
[SAML 1.1](saml11.md) and [SAML 2.0](saml2-sso.md) identity providers: its
issuer is `saml.issuer`, it is signed with `saml.signatureAlgorithm`, its
validity window is widened by `saml.clockSkewS`, and it carries the matching
set of [custom SAML attributes](saml2-sso.md#custom-saml-attributes) — the
SAML 1.1 set by default, whose attributes default to the claim namespace
WS-Federation relying parties read. The built-in claims use the Microsoft claim
URIs, because WS-Federation defines a claim dialect and no vocabulary, and every
relying party in this ecosystem was written against those.

Its lifetime is `wsfed.assertionLifetimeMin` — separate from the SAML 1.1
browser profile's, because a WS-Federation session is read for longer — and a
relying party may overrule it with `wsfedAssertionLifetimeMin` on its entry (see
[the assertion settings](saml2-sso.md#the-assertion-settings-every-application-inherits)).
The RSTR's `wsu:Lifetime` states the lifetime without the skew.

**`ds:Signature` sits in three different positions** in the three documents
this profile involves — last in a SAML 1.1 assertion, second (after `Issuer`)
in a SAML 2.0 one, and first in the federation metadata's `EntityDescriptor` —
and all three are schema-mandated rather than stylistic. A client that looks
for it in one place will fail on the others. The SAML 1.1 spellings that
differ from 2.0 are listed on [SAML 1.1](saml11.md#the-assertion).

**The RSTR is WS-Trust February 2005** by default, as a single
`RequestSecurityTokenResponse` — what AD FS emits and WIF-era relying parties
parse. `trust=1.3` switches to a ws-sx 200512 RSTR Collection, the shape
[WS-Trust](ws-trust.md) at `/sts` uses, so a client can be driven through both.

**The authentication method is what happened**, in the token's own vocabulary:
a password, `multipleauthn` for two factors (in SAML 1.1 and SAML 2.0 alike,
the value AD FS emits), a hardware token for a passwordless security key in SAML
1.1 (`unspecified` in SAML 2.0, which has no honest class for it), and the
certificate, Kerberos or federated values where those were used.

### Signing in, and single sign-on

There is no WS-Federation sign-in screen: the person signs in at the
[authentication service](authentication.md) every protocol here uses, and lands
in the one session store. So a person who signed in for OAuth, SAML or the
console is not asked again, a security key or TOTP works at the screen, and a
relying party whose application entry names a
[federation](federation.md) partner sends the person to that partner. Sign in
at the OpenID Connect screen with a security key and arrive at `wsignin1.0`,
and the assertion's `AuthenticationMethod` reflects the `amr` the session
recorded; signing out of either protocol signs out of both.

One quirk is kept: WS-Federation section 13.2.1 allows the sign-in request to
arrive as a cross-site form POST, which `SameSite=Lax` keeps the session cookie
off, so such a request goes to the sign-in screen even when a session exists,
and the screen says so rather than looking like a broken session. A GET does
not have this problem. The alternative, `SameSite=None`, would be a decision
needing its own argument; `Lax` is deliberate.

### `wauth`: a step-up, never a fake

`wauth` is how a relying party **demands** an authentication type.

* A **password** method is honoured.
* A **hardware token** demand is met by a security key, used alone or after a
  password.
* A **multi-factor** demand is met only by two real factors — a password and a
  one-time code, or a password and a key. A passwordless key alone does not
  answer it.
* A demand the session does not meet is a **step-up**, in every mode — the
  same mechanism as `acr_values=mfa` in OAuth: the
  person is sent back through the sign-in screen with exactly what the demand
  needs — a hardware demand is offered only the key, a multi-factor demand a
  second factor — and the assertion then reports what actually happened. A
  person with no key is told to enrol one.
* **One attempt.** A demand still unmet on the way back is refused
  (`STS-WSFED-0009` for a hardware token, `STS-WSFED-0010` for multi-factor),
  so a demand the screen cannot satisfy does not loop.
* **An unknown `wauth` is refused** (`STS-WSFED-0006`) rather than answered
  with a method that did not happen.

### `wreqptr` is never dereferenced

`wreqptr` names a URL the identity provider is meant to fetch the request from.
Fetching an arbitrary URL taken from a query parameter is a server-side request
forgery, so the request is refused with a page saying to send the RST by value
in `wreq` instead.

### Signing out

`wsignout1.0` ends the session — the same one OAuth and SAML read, so they are
signed out too — and loads each relying party's `wreply` with
`wa=wsignoutcleanup1.0` as a one-pixel image, printing the same URLs as links so
a failed cleanup can be seen. With a `wreply` on the request, the page offers a
**link** back rather than redirecting, because a redirect would abandon the
cleanups. The cleanup images are what front-channel logout is, so that one
response widens `img-src` to `*`: a cleanup ping is by definition a third-party
origin, and the URLs are ones the relying parties themselves supplied as
`wreply`. `wsignoutcleanup1.0` arriving here ends the session and sends no
cleanups of its own, which would loop between two identity providers. The
protocol-independent `/logout` sends the same cleanups; see
[Signing out](signing-out.md).

### Federation metadata

`/FederationMetadata/2007-06/FederationMetadata.xml` is at **AD FS's path**,
because WS-Federation names none and that is where every relying party in this
ecosystem looks first. It is signed, names this identity provider by
`wsfed.entityId`, and holds a `fed:SecurityTokenServiceType` `RoleDescriptor`
with `fed:TokenTypesOffered`, `fed:ClaimTypesOffered`, the
`PassiveRequestorEndpoint` and the `SecurityTokenServiceEndpoint` — the latter
at `/sts`, the same service answering the active profile
([WS-Trust](ws-trust.md)). It describes what this realm's mode
actually emits. It carries no SAML `IDPSSODescriptor` — that is at
`/saml2/metadata`.

**`wsfed.entityId` and `saml.issuer` are two settings**: the metadata names the
identity provider by one, and every assertion is issued by the other. They
default to the same value; when they differ, `GET /wsfed` and the startup log
say so, because a relying party's issuer registry would refuse the token.

### The mock relying party

`/wsfed/rp` is the default `wreply` — so a request that names no return
address has somewhere real to go — and a test harness that shows every verdict
rather than one boolean. It sends a complete
sign-in request and verifies the response check by check: `wa`, `wresult`, the
RSTR and its token type, the assertion's signature against `/sts/cert`, the
issuer, the audience, the validity window, the subject, the claims — and that
its own `wctx` came back unaltered (remembered for `wsfed.mockRpContextTtlMin`).
There is one per trust realm, and a `wctx` minted in one realm is not recognised
in another.

### Not implemented

`wresultptr` (the response is always by value), the attribute and pseudonym
services (`wattr1.0`, `wpseudo1.0`, which answer 501 explaining what they would
have done), token encryption (a passive request carries no recipient
certificate to encrypt to — where `/sts?encrypt=1` has one, because a
WS-Security signature carries it), the metadata exchange over SOAP, and any
authorization or policy enforcement (`wp` and `wencoding` are logged and
nothing more). `wreqptr` is refused by design.

## Development and product mode

| | Development | Product |
|---|---|---|
| `wreply` | used as it stands; with none, the mock relying party | must be one of the `wsfedReplyUrl` values on the `wtrealm`'s application entry, exact match; with none, the registered one; no mock fallback. An address development merely observed is refused until an operator confirms it |
| Password at the sign-in screen | any password but `invalid` | verified |
| Given name, surname, mail, display name, UPN | invented, and described that way in the metadata | read off the directory entry, or omitted — and the signed metadata describes them that way |

The `wauth` step-up, the `wreqptr` refusal and `wctx` round trip behave the
same in both modes. See [What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `wsfed.entityId` | `STS_WSFED_ENTITY_ID` (or `STS_ISSUER`) | `urn:wstrust:mock:sts` | yes | The entityID in the federation metadata; the assertions' issuer is `saml.issuer`. |
| `wsfed.assertionLifetimeMin` | `STS_WSFED_ASSERTION_LIFETIME_MIN` | `60` | yes | The lifetime of the assertion and of the RSTR's `wsu:Lifetime`; per relying party with `wsfedAssertionLifetimeMin`. |
| `wsfed.mockRpContextTtlMin` | `STS_WSFED_MOCK_RP_CONTEXT_TTL_MIN` | `30` | yes | How long the mock relying party remembers a `wctx` it minted. |

The assertion's issuer, signature algorithm, skew and attributes are the shared
`saml.*` settings and the SAML attribute sets — see the
[SAML 2.0 configuration](saml2-sso.md#configuration). This table is a copy; the
live source is `/admin/wsfed` and `GET /admin-api/config`. See
[Configuration](configuration.md) for how a value is resolved; a setting is
changed on `/admin/wsfed`, `/admin/saml-assertions` or with
`POST /admin-api/config/set`.

## Design decisions

* **SAML 1.1 is the default token.** AD FS issues SAML 1.1 to a WS-Federation
  relying party unless told otherwise, and a mock defaulting to the rarer type
  would exercise the wrong half of those clients.
* **The February 2005 RSTR by default, ws-sx on request.** It is what AD FS
  emits; a relying party that has only ever seen one shape has usually
  hard-coded it, and `trust=1.3` shows that.
* **`wctx` is echoed byte for byte.** It is the relying party's state and the
  commonest thing an identity provider mangles; an altered `wctx` looks exactly
  like a lost session.
* **One session and one sign-in screen for every protocol.** A screen of its
  own once made federation, `fedAuthnMechanism` and the WebAuthn step inert for
  this profile alone; the shared screen makes single sign-on real.
* **`wauth` is a step-up, never a fake.** A relying party that demanded a
  factor is either given it, after the person provides it, or refused — never
  handed an assertion claiming a method that did not happen.
* **A passwordless key is not two factors.** Hardware-token and multi-factor
  demands are separate questions, and one session can answer the first and not
  the second.
* **`wreqptr` is refused.** Following a URL from a query parameter is
  server-side request forgery with a specification citation attached.
* **Sign-out offers a link back rather than redirecting**, so the cleanup
  images finish loading; a received cleanup does not fan out, so two identity
  providers cannot loop.
* **The metadata's name and the assertion's issuer are separate settings, and
  disagreement is reported rather than reconciled.**
* **The mock relying party is per realm**, so its `wctx` check cannot answer yes
  across a realm boundary.

## In the running service

* **Protocols → WS-Federation** (`/admin/wsfed`): the endpoint, the entityID,
  which setting is which, and the mock relying party. The assertion's issuer
  and contents are configured on the SAML pages —
  [SAML assertions](saml2-sso.md#the-assertion-settings-every-application-inherits)
  and [Custom SAML attributes](saml2-sso.md#custom-saml-attributes).
* A relying party is an application under **Applications**, where its
  `wsfedReplyUrl` values are registered and an observed one is confirmed or
  discarded.
* `GET /admin-api/wsfed` returns the same settings; the full API is in
  `/admin-api/openapi.json`.
* `GET /wsfed` describes the profile and every parameter as this realm treats
  them. Failures are shown as a page (there is no error response in this
  profile) and recorded under `STS-WSFED-NNNN` codes — see
  [Error codes](error-codes.md).

## Related

* [SAML 1.1 browser profiles](saml11.md) and
  [SAML 2.0 Web Browser SSO](saml2-sso.md), which build the assertion and hold
  the assertion settings and custom attributes
* [WS-Trust](ws-trust.md), whose RSTR this profile carries
* [Authentication](authentication.md), [Sessions](sessions.md),
  [Signing out](signing-out.md), [Federation](federation.md)
* [OAuth 2.0 security](oauth-security.md) — RFC 9470 step-up, the mechanism
  `wauth` shares
* [Trust realms](trust-realms.md), [What is not checked](what-is-not-checked.md),
  [Configuration](configuration.md)
