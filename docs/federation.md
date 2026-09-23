---
title: Federation
---

# Federation

iya-sts can be **either end of a federation relationship** with a foreign
identity service, in five protocols: SAML 2.0
([Web Browser SSO](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)),
SAML 1.1 (Browser/POST), WS-Federation 1.2 (the passive requestor profile),
[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) and
[OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749). As a **service provider**
it sends a person to a partner and consumes what comes back; as an **identity
provider** it marks a partner as a federation partner and decides which
attributes are released to it. Relationships are **per trust realm**: each
realm has its own register, and a relationship is verified against the
certificate configured in that realm.

It is the one feature in this service that **refuses by default** — nothing
federated happens until somebody configures a relationship, and what a
relationship configures is a key.

## Features

### One relationship is one direction

A relationship has a **role** (`service-provider` — this service consumes — or
`identity-provider` — this service asserts) and a **protocol** (`saml2`,
`saml11`, `wsfed`, `oidc`, `oauth2`). A partner this service both consumes from
and asserts to is **two relationships**, because every field differs by
direction: whose endpoints, whose certificate, an inbound attribute mapping or
an outbound release list. A field that belongs to the other direction is
refused by name rather than written and ignored.

Relationships live in the directory under `ou=federations`, one entry each, and
there are three doors onto that register: the console, the management API and
an `ldapmodify`.

### The endpoints

| Path | What it is |
|---|---|
| `GET /federation` | what federation is here, every relationship in both directions, and the URL to give each partner |
| `GET /federation/login/{id}` | **start**: sends the browser to the partner — an `<AuthnRequest>`, a SAML 1.1 inter-site transfer URL, `wa=wsignin1.0`, or an OAuth 2.0 authorization request. Takes `?returnTo=` (a path on this service) and `?application=` (a hint naming what the person is signing in to) |
| `GET\|POST /federation/acs/{id}` | **finish**: the assertion consumer service, the WS-Federation `wreply` and the OAuth 2.0 `redirect_uri`, all one path. **This is the URL to configure at the partner** |
| `GET /federation/link/{handle}` | where the linking sign-in of `link-at-first-sign-in` returns: after the person has signed in here as the account the partner named, this records the link and finishes the federated sign-in (#109) |
| `GET /federation/metadata/{id}` | this service's own SAML metadata (an `SPSSODescriptor`) for one SAML partner, unsigned — with its `SingleLogoutService` on the Redirect and POST bindings and, for SAML 2.0, its encryption key (`KeyDescriptor use="encryption"`, #168). For a WS-Federation partner, an `EntityDescriptor` with a `fed:ApplicationServiceType` role, its passive requestor endpoint and its encryption key |
| `GET /federation/jwks/{id}` | an OpenID Connect relationship's encryption key as a JWKS (`use: enc`), what the partner registers to encrypt its ID Token to (#168) |
| `GET\|POST /federation/slo/{id}` | **a partner's sign-out, in a browser** (#167): a SAML 2.0 `<LogoutRequest>` or `<LogoutResponse>`, a WS-Federation `wsignoutcleanup1.0` or `wsignout1.0`, and the browser coming back from an OpenID Provider's `end_session_endpoint`. The SAML `SingleLogoutService`, the WS-Federation sign-out URL and the OpenID Connect `post_logout_redirect_uri` to configure at the partner |
| `POST /federation/backchannel-logout/{id}` | the OpenID Connect `backchannel_logout_uri` to register at the partner |
| `GET /federation/frontchannel-logout/{id}` | the OpenID Connect `frontchannel_logout_uri` to register at the partner, with `frontchannel_logout_session_required` |
| `GET /authn/select-idp` | the chooser drawn when an application names several usable partners |

In a trust realm every path is under `/realm/{id}`. One path receives all five
protocols, so there is exactly one URL to configure at the partner.

### This service as service provider

The five protocols, and where each differs:

* **SAML 2.0** — an `<AuthnRequest>` out on HTTP-Redirect (default) or
  HTTP-POST (`fedBinding`), a `<Response>` back. The request always asks for
  the response on HTTP-POST. `fedSignRequest` signs the request with this
  service's key; on the Redirect binding the request goes unsigned and the log
  says so, because that binding signs the query string, a construction this
  service does not build.
* **SAML 1.1** — there is no request message. The browser goes to the
  partner's inter-site transfer service with a `TARGET`, and unsolicited
  responses are forced on for the relationship because there is nothing to be
  `InResponseTo`.
* **WS-Federation** — `wa=wsignin1.0` with this service's `wtrealm`; the
  `wresult` carries a SAML 1.1 or SAML 2.0 assertion inside an RSTR.
* **OpenID Connect** — the authorization code flow by default.
  `fedResponseType: id_token` with `response_mode=form_post` needs **no back
  channel at all**, which is the way to federate with an OIDC partner from a
  deployment with no egress. The `nonce` is checked. Attributes come off the ID
  Token and, when configured, UserInfo. **With the code flow, configure
  `fedUserinfoUrl`**: a provider that follows OpenID Connect Core section 5.4
  (this service among them, since #118) puts profile claims such as
  `preferred_username` and `email` in UserInfo, not in a code-flow ID Token.
* **OAuth 2.0** — the authorization code flow with no ID Token; attributes come
  off the access token when it is a JWT and otherwise from a configured
  userinfo-shaped endpoint. It is a distinct protocol rather than OIDC with a
  flag, and it **warns on every sign-in**, because an access token says a client
  was authorized, not that a person signed in.

**PKCE is always sent** in both OAuth-shaped protocols, whatever the partner
advertises, and cannot be turned off.

What is checked on the way in, in every mode:

* the signature, against **the certificate configured on the relationship**
  (`fedSigningCertificate`) — never one the document carries in its own
  `<ds:KeyInfo>` — and over the element being trusted, not the first signature
  in the document;
* an ID Token or JWT access token against the relationship's keys
  (`fedJwks`, or `fedJwksUri`), with `alg: none` refused by name and the
  algorithm family taken from the key, so HS256 cannot be verified with a
  public key;
* the **issuer** against `fedPeer`, which is required;
* the **audience**: every `AudienceRestriction` must name this service. A
  SAML 2.0 assertion with no restriction is refused; SAML 1.1 and WS-Federation,
  whose profiles make it optional, are accepted with a warning;
* the validity window, and that the response answers a request this service
  sent (`InResponseTo`, or the handle in `RelayState` / `wctx` / `state`),
  unless `fedAllowUnsolicited` is on;
* the partner's signing certificate for **revocation**, under
  `pki.revocationCheck`.

The request context — the request id, `nonce`, PKCE verifier and where the
person was going — is kept on the server, per trust realm; the partner carries
only an opaque handle. A handle minted in one realm cannot be spent in another.

### What a federated sign-in writes

A verified sign-in maps the partner's attributes onto a directory entry under
`ou=users` and starts **the same session** every other protocol reads, so a
federated identity then satisfies an OAuth 2.0 authorization request, a
`wsignin1.0`, a SAML `AuthnRequest` or the console with none of those knowing
federation exists.

* **The username** is the value `fedUsernameSource` names, or the subject
  (the NameID or `sub`). A partner's `urn:uuid:` subject becomes `sub-<uuid>`
  and is never looked up locally. `federation.usernamePrefix` is put in front
  of it.
* **Attributes** are mapped in three layers: the relationship's own
  `fedAttributeMap` (`<incoming name>=<LDAP attribute>`), then a default table
  covering the ordinary OIDC claims, SAML `urn:oid:` names and AD FS claim URIs,
  then **nothing** — an unrecognised name is listed as unmapped on the result
  page, on `/admin/federation` and in the log, not written under its own name.
* A partner's value **overwrites** an invented one; an attribute the partner
  stopped sending is **left alone**; `uid` is never written from an assertion.
  `federationAttribute` on the entry says which attributes came from the
  partner, beside `federationRelationship`, `federationIssuer`,
  `federationLink` and `federationLastSeen`.
* Nothing is written onto an entry until the subject has been admitted — see
  *Which people a partner may assert* below.
* The session's `amr` starts with `federated`, followed by what the partner
  said; a SAML partner's authentication context travels on `acr`.

### Which people a partner may assert

A partner signs in **only the person its subject is linked to**. The link is a
`federationLink` value on the person's entry, `<relationship> <issuer>
<subject>`: the relationship, the partner's issuer (its `fedPeer`, which every
response is already checked against) and the partner's stable identifier for
the person — OpenID Connect's `sub`, a SAML NameID. OpenID Connect Core section
5.7 makes `iss` and `sub` together the only identifier a relying party may rely
on, and says `email` and `preferred_username` must not be used as one; SAML 2.0
Core section 8.3.7 has a persistent NameID linked to a local account rather than
matched against one. So a name — however `fedUsernameSource` maps it — never
signs anybody in on its own. A **transient** NameID names nobody for longer than
one exchange and is refused (`STS-FED-0096`); configure the partner to send a
persistent (or other stable) NameID.

`fedSubjectPolicy` decides what happens to a subject nobody has linked yet:

| `fedSubjectPolicy` | An unlinked subject |
|---|---|
| `link-at-first-sign-in` (**default**; empty means it) | naming an existing person: that person is sent to **this service's own sign-in screen**, the name fixed, and must sign in as themselves — their password, and a second factor wherever they hold one or one is required. Only then is the link recorded, the partner's attributes written and the federated session started. Cancel links nothing (`STS-FED-0099`). Naming nobody: a new entry `<relationship>~<name>`, linked at creation, where provisioning allows it |
| `pre-linked` | refused 403 (`STS-FED-0091`). Links are made on the console, through `/admin-api` or SCIM |
| `jit-namespaced` | always a **new** entry `<relationship>~<name>`, linked at creation — never an existing person, whatever its name |
| `any-existing` | the name the partner sent is matched onto a local person, as this service did before #109. **Development only**: product refuses to set it (`STS-FED-0095`) and refuses a sign-in through a relationship that carries it (`STS-FED-0094`). **Warning:** it lets this partner sign in any local account it can name |

A linked subject signs in the person it is linked to under every policy — even
where the partner's name for them has changed.

On top of every policy, a link included:

* **`fedSubjectGroup`** — the person must be in one of these groups (cn or DN);
  a person a sign-in would create is in none, so nobody is created.
* **`fedSubjectDomain`** — the address the partner sent (the mapped `mail`, or
  a username that is an address) must be in one of these domains, and so must
  the entry's own `mail` where it has one.
* **`fedSubjectPattern`** — a regular expression the entry's DN must match
  whole (anchored for you); at most 256 characters, no backreference, no
  quantifier on a quantified group.
* **A console administrator** — a member of the Admin Read or Admin Write
  roster, or a holder of `REMOTE_PEPS` — is refused (`STS-FED-0093`) unless the
  relationship sets **`fedMayAssertAdministrators`**. **Warning:** turning it on
  makes this partner's signing key a key to the console for every administrator
  linked to it.

A refusal is the refusal page, 403, and an audit row naming the relationship,
the subject and the rule (`STS-FED-0092` for the three rules). **Nothing is
written onto the entry** — no attribute, no link, no counter.

**Linking and unlinking.** On a person's `/admin/users` page (*Federation
links*), through `POST /admin-api/users/federation-link` and
`/federation-unlink` (the person's links are `federationLinks` on
`GET /admin-api/users?user=`, paged; a relationship's are `links` on
`GET /admin-api/federation?relationship=`), and through SCIM's
`urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User` extension, whose
`federationLinks` is a list of `{ relationship, issuer, subject }` (issuer
optional: the relationship's `fedPeer`). A link names one person: one another
person carries is refused (`STS-FED-0107`). **Removing a link ends every session
that partner signed the person in to**, whichever door removed it — the
console, the API, SCIM or an `ldapmodify` — and their next sign-in through it
is treated as unlinked.

### Provisioning: dynamic or pre-provisioned

Two switches on each service-provider-side relationship:

| Switch | On (default) | Off |
|---|---|---|
| `fedAutocreateUsers` | the first sign-in creates the person's entry | the entry must already exist (SCIM, `/admin/users/new`, `/admin-api`); a sign-in for somebody with none is refused 403 *has not been provisioned* (`STS-FED-0090`) |
| `fedUpdateUserAttributes` | a returning person's attributes are overwritten from the latest assertion | the partner's values are written only when the sign-in creates the entry |

An entry a sign-in creates is named `<relationship>~<name>` and linked at
creation. A pre-provisioned person is linked to the partner's subject by an
administrator, the API or SCIM, or links themselves at their first federated
sign-in under `link-at-first-sign-in`.

### Home realm discovery

`appFederationRelationship` on an **application** entry names the partners that
application's people sign in through, and holds a list:

| What the entry names | What a person meets |
|---|---|
| nothing | the sign-in screen, with a button per usable partner under it (`federation.loginButtons`) |
| one usable relationship | nothing — the browser goes straight to that partner |
| several usable | `/authn/select-idp`: one button per partner, no password field |
| several, `appFederationAutoRedirect` FALSE | the sign-in screen, with those partners as its only buttons |
| only unusable values | the sign-in screen, with a banner naming what is wrong with each |

A relationship that is disabled, half-configured or on the wrong side is
**printed, not dropped** — a list of three with one disabled would otherwise
look exactly like a correct list of two.

### This service as identity provider

Every protocol endpoint here already answers any partner, so an
identity-provider-side relationship changes nothing about whether a partner is
answered. It names the partner's application entry (`fedApplication` — its
entityID, endpoints and certificate stay there) and adds two things:

* **A release policy.** `fedRelease` lists the claims or attributes released
  to this partner. It filters what the claim and SAML attribute configuration
  and the groups claim would add, and can never remove `sub`, `iss`, `exp`, a
  NameID or anything else a protocol puts in an artifact itself. **An empty list
  is no policy, not "release nothing"**, so registering a partner never stops it
  receiving what it received the day before.
* **How this service authenticates for the partner** (`fedAuthnMechanism`):

| Value | What the person meets |
|---|---|
| `password` | the sign-in screen |
| `password-mfa` | the sign-in screen with the second factor required (`amr ["pwd","hwk"]`, `acr "mfa"`) |
| `webauthn` | a passwordless security key alone — one factor |
| `spnego` | a Kerberos ticket the browser already holds, no screen (see [Kerberos](kerberos.md)) |
| `wallet` | a credential this realm issued, presented from the person's wallet (see [OpenID4VP](oid4vp.md)) |
| `federation` | on to another service-provider-side relationship in this realm, named by `fedAuthnRelationship` |
| *(empty)* | says nothing: falls through to the application entry and then the sign-in screen |

`federation` makes this realm an **identity bridge**: a SAML 2.0 partner can be
answered by consuming a WS-Federation token from somebody else, and nothing
bounds the depth. A request that demanded two factors (a
`RequestedAuthnContext`, a `wauth`) is never answered with a one-factor
mechanism because a relationship preferred one.

### Outbound requests

Federation is where this service first made an **outbound** request, and it
dials only URLs an administrator wrote on a relationship: the partner's token
endpoint (`fedTokenUrl`), UserInfo (`fedUserinfoUrl`) and JWKS (`fedJwksUri`).
The rules:

* `federation.outbound` turns every one of them off;
* **https only, with the partner's certificate verified.** In development,
  `federation.outboundAllowHttp` admits plain http and
  `federation.outboundSkipTlsVerification` turns verification off, each logged
  on every request. **In product mode neither is honoured** (#171): plain http
  is refused (`STS-FED-0112`), a stored skip is ignored (`STS-FED-0113`) and
  cannot be set. A partner certified by a private CA is reached by naming that
  CA in `federation.outboundCaFile`;
* **no redirect is followed** — a 302 from a token endpoint would hand the
  client credential to whatever `Location` said;
* the body is capped (`federation.maxResponseBytes`) and the request timed out
  (`federation.outboundTimeoutMs`), because a browser is waiting;
* nothing that comes back is trusted until it is verified.

SAML 2.0, SAML 1.1 and WS-Federation need no back channel at all, and an OIDC
partner can be used with no egress through `fedResponseType: id_token` and its
keys pasted into `fedJwks`.

### A partner's sign-out

The partner is the authority on the person's sign-on. When it ends a session
— a sign-out there, an account disabled at the source — its sign-out message
is the only signal that reaches this service, so it ends the session here that
the partner started (#167). **Only that session**: the federated session
carrying the partner's SAML NameID and SessionIndex, or its OpenID Connect
`sid` (or, with only a `sub`, that person's sessions from that partner) —
never a local sign-in of the same person, and never a session another partner
started. Ending it is the protocol-independent sign-out's own act, so this
service's own relying parties are told as for any sign-out: Back-Channel
Logout Tokens, CAEP `session-revoked`, and — where the message came through a
browser — front-channel notifications drawn before the answer goes back.

| Protocol | What the partner sends | What is checked |
|---|---|---|
| SAML 2.0 | a `<LogoutRequest>` to `/federation/slo/{id}`, Redirect or POST binding | signed (saml-profiles-2.0-os section 4.4.4.1) and verified against `fedSigningCertificate` and nothing else — the Redirect binding's detached signature over the query string, or an enveloped one; issued by `fedPeer`; `Destination` this endpoint; `IssueInstant` within `federation.requestTtlMin` and `NotOnOrAfter` not passed; its `ID` accepted once ever. Answered with a signed `<LogoutResponse>` to `fedSloUrl` on `fedSloBinding` — `Requester`/`UnknownPrincipal` where no session matched |
| OpenID Connect | a Logout Token POSTed to `/federation/backchannel-logout/{id}` | verified exactly as the partner's ID Token is (its keys, the key's algorithm family, `aud` = `fedClientId`, `iss` = `fedPeer`), then Back-Channel Logout 1.0 section 2.6: the `events` member, no `nonce`, `sub` or `sid`, a `jti` accepted once ever, `iat` within `federation.requestTtlMin`. 200, or 400 `invalid_request` |
| OpenID Connect | `/federation/frontchannel-logout/{id}?iss=…&sid=…` in the partner's iframe | `iss` must be `fedPeer` and `sid` is required. Only the partner's origin may frame the page (`frame-ancestors` narrowed, never dropped) and it runs no script. Best-effort by nature — the iframe is the partner's page — so Back-Channel Logout is the reliable path |
| WS-Federation | `wa=wsignoutcleanup1.0` or `wsignout1.0` at `/federation/slo/{id}` | unsigned by its specification, so it ends nothing by itself: it draws a page with a real button, and the session in **that** browser ends only when the button is pressed |
| SAML 1.1, OAuth 2.0 | — | **neither defines a sign-out**: SAML 1.1 has no logout protocol, and OAuth 2.0 authorizes a client rather than signing anybody in. A message for either is refused naming that |

**The partner's session bound.** A SAML 2.0 `AuthnStatement`'s
`SessionNotOnOrAfter` — including a SAML 2.0 token inside WS-Federation — is
the session's latest end here (with the `oauth2.clockSkewS` allowance an
assertion's own window gets), and an assertion whose bound has already passed
starts no session. An ID Token's `exp` is the token's lifetime, not the
session's, and bounds nothing.

**A sign-out here tells the partner.** `/logout` in the person's own browser
offers, for each session a partner signed in, that partner's sign-out: a signed
`<LogoutRequest>` naming the NameID and SessionIndex (to `fedSloUrl`, whose
`<LogoutResponse>` comes back to `/federation/slo/{id}` and is matched once by
`InResponseTo` and `RelayState`), RP-Initiated Logout to `fedEndSessionUrl`
with the partner's ID Token as `id_token_hint`, `client_id`, this
relationship's `post_logout_redirect_uri` and a `state` matched once on the way
back, or `wa=wsignout1.0` to a WS-Federation partner. Each is a link or a form
with a real button, never an automatic redirect. `/admin/logout` and the
management API list the partner and say it is told only from the person's own
sign-out, because it is their browser that goes there.

**Not used as a relying party: OpenID Connect Session Management.** Polling a
partner's `check_session_iframe` needs a script running in this service's page,
this service admits a script only where a page cannot work without one, and
Back-Channel Logout already tells it what that script would find out.

### A partner's encrypted assertion (#168)

Every SAML 2.0, WS-Federation and OpenID Connect relationship holds an
encryption key pair of its own, issued under the realm's Intermediate when the
relationship is created and published where the partner reads it: the
metadata's `KeyDescriptor use="encryption"` or `/federation/jwks/{id}`. The
relationship's page shows the certificate, the JWKS URL and, for OpenID
Connect, the `id_token_encrypted_response_alg` and `_enc` to register.

What arrives encrypted is decrypted with that key, under exactly the
algorithms the relationship publishes:

* a SAML `<EncryptedAssertion>` — its own signature is checked on what was
  inside it, a Response's on the ciphertext — and an `<EncryptedID>` or
  `<EncryptedAttribute>` inside the assertion, after that signature;
* a WS-Federation token encrypted in the `RequestedSecurityToken`;
* an OpenID Connect ID Token or Logout Token as a JWE, which must hold a
  **signed** token (signed, then encrypted — OpenID Connect Core section 10.2);
* an `<EncryptedID>` in a partner's `<LogoutRequest>`.

The defaults are RSA 3072 with XML Encryption 1.1's RSA-OAEP (SHA-256, MGF1
SHA-256) and AES-256-GCM for SAML 2.0 and WS-Federation, and P-256 with ECDH-ES
and A256GCM for OpenID Connect; EC key agreement for XML and RSA-OAEP-256 for
JOSE may be chosen instead. **AES-CBC, `rsa-1_5` and `RSA1_5` are refused in
every mode.** Every decryption failure is one code, `STS-FED-0138`, with one
sentence: which step failed is in the log, not on a page anybody can submit a
ciphertext to.

**Rotate the encryption key** on the relationship's page or with `POST
/admin-api/federation/rotate-key`: the new key is published at once, and the
key it replaced still decrypts for `federation.encryptionKeyGraceS` and then
nothing — the scheduler job `federation.encryption-key-retire` removes it.

There is no post-quantum key encapsulation: XML Encryption has no registered
ML-KEM method and JOSE's is a draft. The key table records a key type per key,
so a hybrid key can be added beside the classical one when one is registered.

### Not implemented

* Refreshing a partner's tokens, or re-checking a federated person with the
  partner while the session lasts — beyond the partner's own sign-out and its
  `SessionNotOnOrAfter`, above.
* Validating the partner's certificate against a CA or its validity dates — it
  is a pinned key; only its revocation is checked.
* Restricting **which** people a partner may assert.

## Development and product mode

The refusals above are the same in both modes — federation is not permissive in
development. What the mode changes:

| | Development | Product |
|---|---|---|
| A person with no directory entry | created on first sign-in as `<relationship>~<name>`, linked, unless `fedAutocreateUsers` is off | **never created**: the sign-in is refused `STS-FED-0090` |
| `fedSubjectPolicy` `any-existing` | the name match of old | refused, when set and at the sign-in |
| The password at the linking sign-in | not checked (the reserved `invalid` is refused) | verified, with the second factor |
| Revocation of the partner's signing certificate (`pki.revocationCheck=auto`) | soft-fail: a status that cannot be fetched is accepted | hard-fail: a status that cannot be established is refused |
| `fedRequireSignedLogout` off | an **unsigned** SAML logout message from the partner is accepted — a warning: anybody who can name a partner session can then end it | refused on the relationship (`STS-FED-0132`), and an unsigned logout message is refused whatever it says |
| A plaintext SAML 2.0 or WS-Federation assertion, or a signed-only `id_token` by form_post | accepted | **refused** (`STS-FED-0140`) unless the relationship sets `fedAllowUnencrypted` — a warning: the person's identifier and attributes then cross their browser in clear. An ID Token redeemed at the partner's token endpoint crosses no browser and is not asked about |

See [What is not checked](what-is-not-checked.md), *Federation inverts all of
this*.

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `federation.enabled` | `STS_FEDERATION_ENABLED` | `true` | yes | Whether `/federation` answers at all; off, every route 404s and no partner button appears, with no relationship changed. |
| `federation.max` | `STS_FEDERATION_MAX` | `50` | yes | How many relationships may exist under `ou=federations`; past it a new one is refused, never an old one evicted. |
| `federation.usernamePrefix` | `STS_FEDERATION_USERNAME_PREFIX` | *(empty)* | yes | Put in front of every federated username, so a federated `alice` and the local `alice` are two entries; empty makes them one. |
| `federation.loginButtons` | `STS_FEDERATION_LOGIN_BUTTONS` | `true` | yes | Show a button per usable service-provider-side relationship on `/authn/login`. |
| `federation.outbound` | `STS_FEDERATION_OUTBOUND` | `true` | yes | Whether this service may call a partner's token, UserInfo or JWKS endpoint at all. |
| `federation.outboundTimeoutMs` | `STS_FEDERATION_OUTBOUND_TIMEOUT_MS` | `15000` | yes | How long to wait for a partner before the sign-in fails with an error naming the timeout. |
| `federation.outboundAllowHttp` | `STS_FEDERATION_OUTBOUND_ALLOW_HTTP` | `false` | yes | Accept an `http://` partner endpoint, logged on every request. Development only: product refuses plain http. |
| `federation.outboundSkipTlsVerification` | `STS_FEDERATION_OUTBOUND_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only — a warning.** Accept a partner certificate nothing here trusts, logged on every request. Ignored in product, and refused on write there. |
| `federation.outboundCaFile` | `STS_FEDERATION_OUTBOUND_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates a partner may chain to, beside node's own store. How product reaches a privately certified partner. |
| `federation.requestTtlMin` | `STS_FEDERATION_REQUEST_TTL_MIN` | `10` | yes | How long an outbound sign-in's context is remembered; a later response is refused as unsolicited. |
| `federation.maxContexts` | `STS_FEDERATION_MAX_CONTEXTS` | `500` | yes | How many in-flight sign-in contexts are held per trust realm; past it the oldest is dropped. |
| `federation.maxApplicationLength` | `STS_FEDERATION_MAX_APPLICATION_LENGTH` | `256` | yes | The longest `?application=` a federated login carries across the round trip. |
| `federation.maxApplicationUse` | `STS_FEDERATION_MAX_APPLICATION_USE` | `64` | yes | How many per-application usage rows one relationship keeps; the busiest are kept. |
| `federation.releaseIndexTtlMs` | `STS_FEDERATION_RELEASE_INDEX_TTL_MS` | `5000` | yes | How long the index of release lists is reused before it is rebuilt; `0` rebuilds it for every token. |
| `federation.maxResponseBytes` | `STS_FEDERATION_MAX_RESPONSE_BYTES` | `262144` | yes | The cap on a partner's token response, UserInfo document or JWKS. |
| `federation.jwtAlgorithms` | `STS_FEDERATION_JWT_ALGORITHMS` | `RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512` | yes | The JWS algorithms a partner's ID Token or JWT access token may use; it only narrows, never admitting `none` or an HMAC. |
| `federation.spNameIdFormat` | `STS_FEDERATION_SP_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified` | yes | The `<md:NameIDFormat>` published in `/federation/metadata/{id}`. |
| `federation.encryptionKeyGraceS` | `STS_FEDERATION_ENCRYPTION_KEY_GRACE_S` | `86400` | yes | How long a relationship's encryption key still decrypts after a rotation replaced it; `0` ends it at the rotation (#168). |

What this service calls itself to a partner is derived from the URL the browser
reached it at; `global.publicBaseUrl` pins it for everything, and
`fedLocalEntityId` on one relationship pins it for that partner.

This table is a copy of rows in `common/config.js`; the live source is
`/admin/federation` and `GET /admin-api/config`.

See [Configuration](configuration.md) for how a value is resolved and where it
is changed: on `/admin/federation`, through `POST /admin-api/config/set`, or in
an appconfig file.

### The relationship's own fields

These are attributes of the relationship entry, set on `/admin/federation` or
`/admin-api/federation`, not settings.

| Field | Side | What it holds |
|---|---|---|
| `fedName`, `fedEnabled` | both | a display name; whether the relationship does anything (created `FALSE`) |
| `fedPeer` | both | the partner's own identifier — entityID, issuer or `wtrealm`; required and checked on the service-provider side |
| `fedLocalEntityId` | SP | what this service is called to this partner, when not the derived name |
| `fedSsoUrl` | SP | where the browser is sent |
| `fedTokenUrl`, `fedUserinfoUrl` | SP | the two URLs this service dials for an OAuth-shaped partner |
| `fedJwksUri`, `fedJwks` | SP | the partner's keys, fetched or pasted (pasted is read first and never refreshed) |
| `fedSigningCertificate` | SP | the partner's signing certificate, base64 DER — what every SAML and WS-Federation assertion is verified against |
| `fedClientId`, `fedClientSecret` | SP | this service's client credentials at the partner |
| `fedScope`, `fedResponseType` | SP | the scope asked for (`openid profile email` by default for OIDC); `code` or `id_token` |
| `fedBinding`, `fedSignRequest` | SP | the outbound SAML binding; whether the `AuthnRequest` is signed |
| `fedSloUrl`, `fedSloBinding` | SP | the partner's SAML `SingleLogoutService`, and the binding (`HTTP-Redirect`, the default, or `HTTP-POST`) this service's `LogoutRequest` and `LogoutResponse` go on |
| `fedEndSessionUrl` | SP | the partner's OpenID Connect `end_session_endpoint`; the ID Token is kept for `id_token_hint` only while this is set |
| `fedAcceptSignout` | SP | honour the partner's sign-out; `TRUE` by default, and off every one is refused (`STS-FED-0123`) |
| `fedRequireSignedLogout` | SP | require a SAML logout message to be signed; `TRUE` by default and always in product — **off is a warning**: an unsigned sign-out is anybody signing anybody out |
| `fedUsernameSource`, `fedAttributeMap` | SP | which incoming value is the username; extra attribute mappings |
| `fedAutocreateUsers`, `fedUpdateUserAttributes`, `fedAllowUnsolicited` | SP | the provisioning switches; accepting a response nobody asked for |
| `fedSubjectPolicy` | SP | what an unlinked subject may become: `link-at-first-sign-in` (default), `pre-linked`, `jit-namespaced`, `any-existing` (development only — see the warning above) |
| `fedSubjectGroup`, `fedSubjectDomain`, `fedSubjectPattern` | SP | the rules on top of the policy |
| `fedMayAssertAdministrators` | SP | let the partner sign in a console administrator; `FALSE` by default — see the warning above |
| `fedEncryptionKeyType`, `fedKeyManagementAlgorithm`, `fedContentEncryptionAlgorithm` | SP (SAML 2.0, WS-Federation, OIDC) | what a partner encrypts to: `rsa-3072` or `ec-p256`; `rsa-oaep`/`ecdh-es` (XML) or `RSA-OAEP-256`, `RSA-OAEP` (**a warning: SHA-1**), `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` (JOSE); `aes256-gcm`/`aes128-gcm` or `A256GCM`/`A128GCM`. A new key type issues a key of that type at once |
| `fedAllowUnencrypted` | SP (SAML 2.0, WS-Federation, OIDC) | accept a plaintext assertion in product; `FALSE` by default — **a warning**: the partner then sends the person's identifier and attributes in clear through the browser |
| `fedEncryptionKey` | SP | the key table: never editable, never shown with its private key |
| `fedApplication` | IdP | the partner's entry under `ou=applications` |
| `fedAuthnMechanism`, `fedAuthnRelationship` | IdP | how this service authenticates for the partner |
| `fedRelease` | IdP | the attributes released to the partner |

What each protocol requires before a relationship is usable: `fedSsoUrl` and
`fedPeer` always; `fedSigningCertificate` for the three SAML-shaped protocols;
`fedClientId` for OIDC; `fedTokenUrl` and `fedClientId` for OAuth 2.0. A missing
one is named on the page and the relationship refuses until it is filled.

## Design decisions

* **A relationship must be configured, and what it configures is a key.**
  `/federation/acs/{id}` receives an unauthenticated request claiming to be a
  person, and the session it produces is the one every protocol and the console
  read. "Accept any SAML Response" would be an authentication bypass for the
  whole process, so there is no permissive version to offer.
* **Created disabled; enabled as a second act; half-configured refuses.** A
  partner that half-worked would look finished from every angle except the one
  where it accepts something it should not.
* **Verified against the relationship's certificate, never the document's.** A
  signature carrying its own certificate proves only that somebody signed it;
  pinning the key is the difference between a check and a decoration.
* **Issuer and audience are refusals, not warnings.** An assertion a partner
  minted for another of its relying parties verifies against the same key, so
  accepting any audience would let anybody holding one sign in here.
* **The gate is on the signer and on the subject.** A verified assertion signs
  in only the person its subject is linked to, and a name never links anybody;
  until #109 any person the partner named was accepted and had the partner's
  attributes written onto their entry before anything could refuse.
* **The link is made by the person, or by an administrator — never by the
  partner.** Under `link-at-first-sign-in` the person proves here that they
  are the local account the partner named; a match by name alone is a way for
  any partner to sign in `admin`.
* **One path receives all five protocols.** A SAML ACS, a `wreply` and a
  `redirect_uri` are three names for "where the answer comes back"; five paths
  would be four more ways to configure the wrong one.
* **The return address is kept on the server.** `RelayState`, `wctx` and
  `state` carry only a handle, because a return URL in the parameter is an open
  redirect for anybody who can forge one.
* **A failure is shown, recorded and not redirected.** The person already
  signed in at the partner; the page names the check this service disliked, and
  the relationship records it as its last error.
* **Unmapped attributes are listed, not stored under their own names.** The
  directory has no schema, so a wrongly named attribute would be accepted
  silently forever.
* **An empty release list filters nothing.** "No policy" and "release nothing"
  must be different states, or registering a partner would silently change
  what it receives.
* **Only administrator-configured URLs are dialled.** A partner's token
  endpoint was written down by somebody configuring the partnership; a
  `jwks_uri` sent to dynamic registration or a WS-Federation `wreqptr` was
  chosen by a caller and is still never followed.
* **The outbound HTTP-POST binding is a real form with a real button.** A
  person leaving this service for a foreign identity provider is the moment a
  deliberate click is worth having, so federation adds no script to any page.
* **Federated identities share the local namespace unless told otherwise.**
  `federation.usernamePrefix` is empty so a mock pointed at a partner returns
  familiar names; set it when the question is whether the two namespaces
  should meet.

## In the running service

* **Protocols → Federation** (`/admin/federation`): every relationship in both
  directions with its state and readiness, the URL to give each partner, the
  unmapped attributes a partner sent, create and edit forms, and the
  `federation.*` settings.
* **`/admin/federation/map`**: the register drawn as a picture — applications
  and foreign service providers on the left, the trust realm in the middle,
  identity providers on the right; an arrow is a request. Lines are coloured
  green (ready), grey (disabled), red (enabled and not configured) and amber (a
  broker whose onward partner is unusable). It also shows per-application
  sign-in counts and names the remainder that belongs to no application.
  `?format=svg` and `?format=json` return the picture and the graph.
* **`GET /federation`**: the public description, with the URL to configure at
  each partner.
* **Management API**: `GET /admin-api/federation` and
  `POST /admin-api/federation/{action}` (`create` and its siblings) — see
  `/admin-api/openapi.json`.
* **Every federation failure** is recorded under an `STS-FED-NNNN` code on the
  audit row and in the log, never sent to the client — see
  [Error codes](error-codes.md).

## Related

* [Sessions](sessions.md) — the session a federated sign-in starts
* [Authentication](authentication.md) — the sign-in screen, the partner buttons
  and the chooser
* [SAML 2.0 Web Browser SSO](saml2-sso.md), [SAML 1.1](saml11.md),
  [WS-Federation](ws-federation.md), [OAuth 2.0 & OpenID Connect](oauth-oidc.md)
  — the same protocols with this service as the identity provider
* [Kerberos](kerberos.md) — the `spnego` mechanism
* [SCIM](scim.md) — pre-provisioning people a relationship will not create
* [Trust realms](trust-realms.md) — the register is per realm
* [PKI](pki.md) — revocation checking of a partner's certificate
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md)
