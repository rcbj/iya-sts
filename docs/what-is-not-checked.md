---
title: What is not checked
nav_order: 16
---

# What is not checked

This service **checks no password, validates no access token it did not issue,
and attests no workload**. Read this page before using it for anything, and read
it again before concluding that something here is a bug.

It is permissive on purpose. A client that has only ever met a permissive server
has never run its own refusal paths; a client that has only met a strict one
cannot reproduce the behaviour it is trying to detect. So the default is
permissive, several negatives are made deliberately *reachable*, and where the
service can be told to be strict, it can.

## The permissive list

| It does not | Notes |
|---|---|
| Check any end user's password | The username typed at `/authn/login` becomes the identity in every token and every assertion. **THREE credentials ARE checked and none of them is a password** — a Kerberos ticket, an RFC 6238 one-time code, and a single-use RECOVERY CODE, which is checked for the same reason the other two are: there is nothing left of a one-time credential once the comparison goes, and a client author would have no artifact to test against. The first two have sections of their own below |
| ISSUE WITHOUT ASKING — **this row runs the other way, and it is the only one here that does.** Since 2026-09-01 the authorization endpoint asks: the first time a given username signs in to a given `client_id` for a given scope, `/oauth2/consent` is drawn and nothing is issued until they answer. `oauth2.consentRequired` is ON by default, which no other policy here is, because consent is not a refusal — it is the screen every real authorization server draws on a first sign-in, and a client that has never met one has never run the code that survives it. **It still checks nothing**: the person was let in under any name they typed, one row above. See below |
| Refuse any LDAP bind — **in development mode** | Any DN, any password, anonymous included — on 389 and on LDAPS 636 alike. **Product mode refuses four kinds before a password is read**: an anonymous bind (result code 48, `inappropriateAuthentication`), a bind on the plain listener on 389 (13, `confidentialityRequired` — use LDAPS), a DN with an empty password (53, `unwillingToPerform`), and any bind from a DN or an address that has had too many FAILED binds within `security.rateLimitWindowS` (53) — a correct password during a lockout is refused like a wrong one, and a successful bind never counts. Then it verifies the password |
| Require a bind to READ the directory, or withhold a credential from a search — **in development mode** | Any connection may search and compare every entry and read every attribute but a Kerberos key. **Product mode requires a bind before a search or compare** (50, `insufficientAccessRights`; the root DSE is the exception), **never returns a credential attribute** — `userPassword`, `pwdHistory`, client secrets, registration access tokens, private keys, TOTP secrets, recovery codes, activation tokens, Kerberos keys — to anybody, administrators included, **hides them from search filters** so a filter cannot be used to guess one, and **refuses a compare against one**. It also refuses a write of `createTimestamp`, `modifyTimestamp` or `entryDN` by anybody (19, `constraintViolation`). What a bound connection may read beyond that is not yet narrowed per identity |
| Authorize an LDAP write — **in development mode** | Any connection, anonymous included, may add, modify, rename or delete any entry in any realm. **Product mode authorizes every write against the identity that bound**: an anonymous connection writes nothing, a connection bound as somebody holding Admin Write (in the default realm's directory) writes anything, and anybody else may modify only the attributes `ldap.selfWritableAttributes` names on their own entry — contact details and `userPassword` by default. A refusal is result code 50, `insufficientAccessRights`. Reads are the row above |
| Verify an access token it did not issue | Except at `/oauth2/userinfo`, which answers "who did *you* authenticate" and so must |
| Require DPoP or mutual TLS — **unless it is told to, which it can be since 2026-09-15** | This row read *nonce mode makes proofs fresher, not mandatory*, and that half stands: `oauth2.dpopNonceRequired` (**per trust realm**; `POST /dpop/nonce-mode` writes it in development and is refused in product) changes how fresh a proof must be and never whether one is sent, so with it on a request carrying no `DPoP` header is still a Bearer request. **What is new is four settings that make a constraint mandatory, and every one of them is off unless somebody sets it.** `oauth2.accessTokenRequireDpop` and `oauth2.accessTokenRequireMtls` refuse a presented access token carrying no `cnf.jkt` or no `cnf["x5t#S256"]` at every surface that takes one — UserInfo, the RFC 9470 step-up resource, the three OpenID4VCI endpoints, `/scim/v2`, the Shared Signals endpoints, `/admin-api` and the embedded debugger's listener — and hold a token this service did not issue to the same rule, because a confirmation can be read without trusting the token that carries it. `oauth2.refreshTokenRequireDpop` and `oauth2.refreshTokenRequireMtls` refuse to ISSUE a refresh token to a request that proved neither, and refuse an unbound one at the refresh grant rather than binding it to whichever key turns up holding it. **Neither OAuth 2.1 nor RFC 9700 asks for any of this** — section 4.3.1 wants a public client's refresh token sender-constrained *or* rotated with replay detection and this service rotates, and section 2.2.1 is a SHOULD — so no compliance mode turns one on and each is a deliberate act by an operator. Two limits worth knowing: the access-token pair refuses at the RESOURCE only, so the token endpoint goes on minting Bearer tokens that those surfaces then refuse, which is what lets a client be driven against the refusal; and the mutual TLS pair needs `global.https`, without which the affected request is refused rather than let through |
| Require a credential to introspect a token as JSON — **in development mode** | `POST /oauth2/introspect` answers RFC 7662 JSON to anybody holding the token string. **Product mode requires the caller to authenticate as a client** and refuses one that does not with 401 `invalid_client`. **An RFC 9701 JWT response is checked in both modes**: a request whose `Accept` names `application/token-introspection+jwt` must authenticate, because the JWT's `aud` is the resource server that asked, and is refused 400 `invalid_client` otherwise. **Wherever the caller authenticated, it learns only about tokens meant for it** — its own, ones with the default audience, or ones whose `aud` names its application; anything else is `active: false` |
| Require a request object to be signed — **in development mode** | An RFC 9101 request object with `alg: none` is accepted in development (OpenID Connect Core section 6.1) and **refused in product mode**, and refused in either wherever `oauth2.requireSignedRequestObject`, the client's `require_signed_request_object` or a named authorization server asks for a signed one. **A signed object is always verified**, and a `request_uri` is fetched only from an address the client registered, in both modes. A request object's `jti` is accepted once, in both modes (`oauth2.requestObjectJtiOnce`) |
| Refuse a pushed authorization request whose client credential did not verify — **in development mode** | `POST /oauth2/par` (RFC 9126) authenticates a client exactly as the token endpoint does: development OBSERVES the credential and accepts the push. **RFC 9700 mode, OAuth 2.1 mode and product mode refuse it 401.** What development never does is let an unverified client use what a verified one may: section 2.4's unregistered `redirect_uri` (`oauth2.parAllowUnregisteredRedirectUris`, off) needs a credential that VERIFIED, in every mode. The pushed request is always validated, the `request_uri` is always bound to its client and spent when a response is issued on it |
| Register a client only for an administrator — **in development mode** | `POST /oauth2/register` (RFC 7591) answers anybody. **Product mode closes it** — 403 — unless `oauth2.openRegistration` is on, or the registration carries a software statement this realm trusts (it issued it, or an application declares its issuer) while `oauth2.softwareStatementOpensRegistration` is on; with neither, `registration_endpoint` leaves the discovery documents. **A software statement is verified in both modes**: an invalid one is `invalid_software_statement` and one from an undeclared issuer `unapproved_software_statement` |
| Check the password on the OAuth 2.0 password grant — **in development mode** | Any password but `invalid` is accepted, exactly as at the sign-in screen. **Product mode verifies it** against the stored `userPassword`, rate-limits it with the sign-in screen, and refuses a person who holds a second factor, because the grant has nowhere to carry one |
| Hold a new password to a policy — **in development mode** | Any password is SET, at every door. **Product mode enforces the realm's password policy** (Directory → Policies, `/admin/policies`): a minimum length, a symbol count, an uppercase letter, a number, and none of the current password or the last five — on the console, `/admin-api`, `/portal/password`, `/portal/activate` and an LDAP modify of `userPassword` alike. The history is recorded in both modes, and a generated password meets the policy in both. Passwords already stored are not re-checked |
| ~~Turn a verified client certificate into a login~~ — **reversed 2026-09-05, and this row said *No session, no token, no privilege* until 2026-09-16** | `GET /tls/sign-in` starts a sign-on session for the holder of a certificate that verified — its common name, or its RFC 4514 subject where it has none — after consulting revocation. An application's certificate signs nobody in: it is an RFC 8705 client credential. The certificate is *recorded* as well, which is a different claim — see below |
| Turn a verified presentation into a sign-on | The OID4VP Verifier checks properly and then says yes on a web page and stops |
| Verify anything in an issued credential's values | They come off the directory entry, and — **in development mode** — what the entry lacks is *invented* from the username. **In product mode nothing is invented**: an attribute the entry does not hold is absent from the credential, from a claims request and from the ID Token and UserInfo profile claims, and `email_verified` is never asserted |
| Deactivate anybody on SCIM `active: false` | Stored as `scimActive` and read by nothing |
| Restrict WHICH people a federation partner may assert | Any username in a verified assertion is accepted, and an entry is created for them. What IS checked is the partner's signature — see below, where that inversion is argued |
| Verify a SAML `AuthnRequest`'s signature | Whether it was signed, and the certificate off its `ds:KeyInfo`, are both **recorded** on the service provider's directory entry and neither is checked. That is why `/saml2/metadata` advertises `WantAuthnRequestsSigned="false"`: asking service providers to sign something nothing verifies is worse than not asking |
| Check which entityID a SAML service provider claims | **Any entityID is accepted**, and the first valid `AuthnRequest` from one creates its application entry. Asking for its metadata does the same — the document is minted for anything asked for |
| Check where a SAML response or a WS-Federation token is delivered — **in development mode** | The `AssertionConsumerServiceURL`, SAML 1.1 `shire` or `wreply` a request names is used as it stands, and with none the response goes to the registered address or to a built-in mock. **In product mode it must be registered** on the application entry (`samlAssertionConsumerService`, `wsfedReplyUrl`), compared exactly, with no mock fallback. **An address development RECORDED does not count as registered**: every address a development-mode request writes onto an entry — and every callback the console and portal learn from a Host header — is marked *observed* (`appReturnAddressObserved`), and product refuses a marked address exactly as it refuses one that is not there, with a page saying how to confirm it. Before switching a realm to product, open each application under **Applications** and press **Confirm** on the addresses that really are that application's and **Discard** on the rest — or use `POST /admin-api/applications/confirm-address` and `/discard-address`, which list them as `returnAddressesObserved`. Adding the address by hand confirms it too. **Addresses recorded before this marking existed carry no mark and cannot be told apart from registered ones** — review those by hand |
| Authenticate a caller at the SAML 1.1 attribute authority — **in development mode** | Anybody may send an `AttributeQuery` about anybody. **Product mode refuses both query types.** In both modes an `AuthenticationQuery` is answered only from a live session, and an attribute answer carries no invented `AuthenticationStatement` |
| Require a credential at the WS-Trust STS — **in development mode** | A request with no credential gets a token for `anonymous`, an unsigned SAML assertion is believed, and an `OnBehalfOf` needs no requester. **Product mode refuses all three**, accepting only a directory-verified UsernameToken or an assertion this STS signed. A requested lifetime is clamped to `wstrust.maxTokenLifetimeMin` in both modes |
| Attest a workload or a node | See SPIFFE, below |
| Let a group grant anything, bar two | A token now *carries* one; no endpoint reads it. `cn=admin-read` and `cn=admin-write` are the exception and grant the admin console, nothing else |
| Decide who may delegate to whom IN THE ACT, in two of the three families that can | The KDC polices S4U properly, off the same two attributes a real domain uses, on every request and whatever anything is set to. WS-Trust `OnBehalfOf`/`ActAs` is unpoliced: anybody may ask for a token about anybody. **RFC 8693 and the OAuth families are the qualified case since 2026-09-01**: a DELEGATED PERMISSION can be configured between two application entries — a resource exposes permissions, a client is granted them, and a client asks for one as an ordinary scope — and `oauth2.delegatedPermissionsEnforced` turns an ungranted ask into `invalid_scope`. It is OFF by default, so an unconfigured service behaves exactly as this row always described. Every act says which — see below |

**Recorded is not the same claim as authenticated, and the two are kept apart
everywhere.** A verified TLS client certificate, a verified presentation and an
accepted SPIFFE credential all appear on `/admin/users` and seed a directory
entry — because an identity turned up here and something about it was accepted.
The recording is not what signs anybody in: it happens once per handshake,
wherever the certificate arrived and whatever it was presented for, while a
session is started only by asking for one at `GET /tls/sign-in`. A presentation
and an SVID start none at all. A mock that quietly promoted a record into a
session would teach a client something false about every real server it
will ever meet.

## Consent is ASKED, and it is the one thing here that is on by default

Everything else on this page is something this service declines to check.
Consent is the opposite: it is something it insists on, and the setting that
governs it — `oauth2.consentRequired` — is the only one in the service that
defaults to ON.

The argument is that consent is not a refusal. Every other policy here is off
because a mock exists to exercise clients and a refusal that cannot be turned
off removes a test case rather than adding one. A consent screen ADDS one: the
extra redirect, the second visit to the authorization endpoint, and the
`access_denied` a client gets when somebody says no are all code paths a client
that has never met a first-time sign-in has never run.

**It does not check anything.** The person reached the screen by typing any name
they liked at a sign-in screen that checks no password — the first row of the
permissive list is unchanged. What the screen establishes is that a human
pressed a button, not who they are.

Three things about it are worth knowing here:

* **The answer is a record, not a permission.** It is written to `oauthConsent`
  on the person's own entry — one value per (person, application, scope) — and
  it is read by exactly one thing: the authorization endpoint, deciding whether
  to draw the screen again. No endpoint anywhere consults it to allow or refuse
  anything else.
* **Nothing already issued is re-judged.** The token endpoint asks nobody
  anything, so a refresh of a code obtained before the setting was turned on
  still works, and revoking somebody's consent leaves a token already minted
  valid. That is the same rule delegated permissions follow and the same rule
  federation follows about not re-checking a person once the session exists.
* **`oauthGlobalConsent` on an application's entry turns the asking off for
  everybody who signs in to it**, without writing anything about anybody — so
  taking it away asks everybody again, including the people who would have said
  yes. It is keyed on (application, scope) and never on the scope alone.

Turning the setting off makes this service behave exactly as it did before the
screen existed: nothing asked, nothing recorded. It does **not** mean everybody
consented — no agreement is written down, so turning it back on asks again.

## Delegation is policed in one family out of three, and the page says which

`/admin/delegation` records every exchange in which somebody acted on somebody
else's behalf — Kerberos S4U2Self, S4U2Proxy (classic and resource-based) and a
forwarded ticket-granting ticket; WS-Trust `OnBehalfOf` and `ActAs`; RFC 8693
token exchange as impersonation and as delegation — against one model, with the
initial identity, the intermediary acting for them and the target being reached
on every row.

**Kerberos is the only one of the three that decides anything.** The KDC checks
`msDS-AllowedToDelegateTo` on the front-end account and
`msDS-AllowedToActOnBehalfOfOtherIdentity` on the back-end one, enforces the
asymmetries between them (classic needs forwardable evidence; resource-based
needs `PA-PAC-OPTIONS` and gets `KDC_ERR_BADOPTION` without it), and refuses with
a message naming both attributes and their current values. WS-Trust puts no
authorization on either element and this service adds none; RFC 8693 leaves the
policy to the authorization server and this one has none — `may_act` is neither
issued nor read here. Each act states which of the two it was in the field that
names an attribute for a Kerberos row, so the difference is visible rather than
inferred.

**Refusals are recorded, and they are the rows worth having.** A refused
delegation appears in no other list on this service — nothing was accepted, so
no authentication was recorded — which is why that page keeps a store of its
own.

One consequence worth stating on a page about what is not checked: under an
**impersonation** (S4U2Self, a forwarded TGT, `OnBehalfOf`, an RFC 8693 exchange
with no `actor_token`) nothing in the credential records that a middle tier was
involved, so the issuer is the only place that fact can ever be seen. That is not
this service being permissive — it is what impersonation *is* — but it is the
reason a page like that one belongs on an identity provider rather than on a
client.

## Kerberos is the exception, and cannot not be

The password there *is* the key: pre-authentication and the AS-REP's enc-part are
both encrypted under it, so a KDC accepting anything would still have to pick a
key the client could not guess. So it does the permissive equivalent — **any
username authenticates and every user account shares one password**
(`password!`, `KRB5_USER_PASSWORD`), with a name nobody configured created on
first sight.

Three things stay refusals on purpose, so the corresponding error codes are
reachable: a service-shaped name for a host this service is not willing to *be*
(`KDC_ERR_S_PRINCIPAL_UNKNOWN`), the names in `KRB5_UNKNOWN_USERS`
(`KDC_ERR_C_PRINCIPAL_UNKNOWN`), and a wrong password (`KDC_ERR_PREAUTH_FAILED`).

**That is development mode.** In product mode none of the fixture accounts exist,
nobody is created on first sight, no password is published, and the KDC holds only
`krbtgt` and the account `krb5.servicePrincipal` names — each only when its password
setting is not the default this repository publishes. **People in the directory DO
authenticate there since 2026-09-12**, with their own passwords: a person's Kerberos
keys are derived when their password is set or a sign-in verifies it, stored sealed on
their entry, and checked for real — a wrong password is `KDC_ERR_PREAUTH_FAILED`, and
somebody whose keys have not been derived yet is told to sign in once. Service
principals an operator creates at `/admin/kerberos/principals` get a random key and a
keytab. The acceptor still verifies tickets a real KDC issued to its service principal.
**A password change or a rotation keeps the previous key version for a bounded window**
(`krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS`) so a ticket already issued under it is
still accepted; the old PASSWORD is not — pre-authentication checks the current key only.
The `krbtgt` key is not rotated here and keeps no previous version.


## A one-time code is the other exception, for the same reason

RFC 6238, since 2026-09-10. A person enrols an authenticator app from
`/portal/mfa`, and from then on **the code they type is genuinely verified** —
against the shared secret this service generated, the clock, and a skew window
of one step either side. In development mode as well as in product mode.

The argument is Kerberos's, one row up, arriving at a different mechanism. A
one-time password verifier that accepted any six digits would not be a
*permissive* RFC 6238 — it would be a broken one. There would be no artifact to
inspect, no failure to demonstrate, and nothing at all for somebody testing an
authenticator integration to test against. And unlike a password it costs a
tester nothing to be strict: the person has already been let in under whatever
name they typed at a sign-in screen that checks no password, and the code is
checked against a secret this service showed them ninety seconds ago.

**What stays permissive is everything around it.** Any name may enrol, the
password in front of the code is not checked, and the name in the token is still
whatever was typed.

Three refusals it makes are worth knowing about, because each is a reachable
negative:

* **A code is accepted once** (RFC 6238 section 5.2). The step last accepted is
  stored, so the code that confirmed an enrolment cannot also sign anybody in,
  and signing in twice inside one thirty-second window asks for the next code.
  It is refused *as a repeat* and not as a wrong code — those are different
  things for a person to be told.
* **A code from more than one step away is refused**, and `totp.window` is the
  bound. Set it to `0` to demand a perfectly synchronised clock and watch what a
  drifting one does.
* **A person who has enrolled one cannot get in without it.** A password alone
  stops working, and no checkbox on the sign-in screen opts out of it.

**It can never be a first factor.** This service holds the same shared secret
the app does, which is fine for proving somebody still has the app and is not a
thing to hang an account on — so an authenticator is always a *second* factor
here, and an account whose only credential is one is a state every door refuses
to create.

**And there is no self-service reset**, which is the one place this service is
deliberately less convenient than it could be: a second factor anybody can
remove is no second factor. An operator's Clear on that person's row under
`/admin/users`, or `POST
/admin-api/mfa/clear-totp`, is the way back for a lost phone.

## A WebAuthn ceremony is verified and the AUTHENTICATOR behind it is not

The registration and every assertion are checked for real — the challenge, the
origin, the RP ID hash, the flags, the signature over `authenticatorData ||
SHA-256(clientDataJSON)` against the COSE public key the credential registered,
and the signature counter, which only ever goes up so one that went backwards is
a cloned key.

**What is NOT checked is the attestation STATEMENT.** Whatever
`webauthn.attestation` asks the browser for — `none`, `indirect`, `direct` or
`enterprise` — the object that comes back is parsed, reported and believed.
There is no FIDO metadata service here, no trust anchor for an authenticator
vendor and no model allow-list, so this service can tell you what an
authenticator *claimed to be* and never what it *is*. A relying party that
needed the second answer would have to bring the metadata with it.

**One ceremony option IS enforced, and it is the only one that could be.**
`webauthn.userVerification: required` is sent to the browser AND the UV flag in
the signed authenticator data is checked when the ceremony returns, so an
authenticator that did not verify the person is refused. Nothing signed says
what the browser was asked about attestation, the resident key or the
attachment, so a check on any of those would be a comparison against a value
this service itself supplied — what it does instead is RECORD what came back.

**Raising it does not change what a session claims.** A passwordless sign-in
still records `amr ["hwk"]` and `acr "1"` — one factor — even under `required`.
RFC 8176 has no registered value for *the authenticator verified the user* that
this service could honestly assert, and claiming `mfa` because the ceremony was
phishing-resistant would be exactly the kind of fake this page exists to rule
out.

## The reachable negatives

A permissive server that refuses nothing is not much use for testing error paths
either, so several refusals are kept deliberately reachable:

- **The literal password `invalid`** is rejected on the password grant, on
  WS-Trust, at the WS-Federation sign-in screen, and as an LDAP bind password —
  where it is the only thing that produces `LDAP_INVALID_CREDENTIALS` (49), the
  result code an LDAP client's error handling is built around.
- **`invalid` as a SCIM `userName`** is refused, as is a duplicate one.
- **`oauth2.breakIdTokenNonce`** puts a deliberately wrong `nonce` in every ID
  Token. Off by default, and *not* part of RFC 9700 mode: a compliance flag that
  also broke tokens is a flag nobody would turn on.
- **WS-Federation's `wauth`** is never faked. A relying party demanding
  multi-factor (or a hardware token) against a session that does not have it
  sends you back through the sign-in with the second factor required, and the
  assertion reports what you actually did. If that one attempt still does not
  produce the factor, the request is refused with two ways forward — never
  answered with a second factor that did not happen.
- **A SAML 2.0 `ProtocolBinding` this service does not implement is refused by
  name.** A service provider that asked for PAOS and received a form post would
  conclude that PAOS worked.
- **`IsPassive="true"` with no usable session** is answered with a
  `<samlp:Response>` carrying `NoPassive` rather than with a sign-in screen —
  which is one of the two SAML status codes a service provider is least likely
  to have handled. A cancelled sign-in gets `AuthnFailed` at the assertion
  consumer service, which WS-Federation's passive profile has nowhere to send.
- **A SAML artifact resolves exactly once.** Resolving destroys it, so a second
  `ArtifactResolve` for the same artifact is refused with a status naming the
  reason — the easiest thing in that profile to get wrong and the hardest to
  notice, because the happy path passes either way.
- **`wreqptr` is never dereferenced**, and neither is a client's registered
  `jwks_uri`, and neither is a foreign SPIFFE bundle URL. Fetching a URL somebody
  handed you in order to verify a credential is a server-side request forgery
  with a specification citation attached.

## Federation inverts all of this, and it is not a fourth turnstile

Everything above describes this service being **asked** for something. Federation
is the other direction — it CONSUMES what a foreign identity service issued — and
there the posture is reversed.

`/federation/acs/{id}` receives an unauthenticated HTTP request that claims to be
a person. The only thing between "alice signed in at the partner" and "somebody
POSTed some XML" is the signature check, and the browser sign-on session that
comes out is **the same session** `/oauth2/authorize`, `/wsfed`, `/saml2/sso`,
`/saml11/sso` and `/admin` all read.

So "accept any SAML Response" is not a permissive mock of federation. It is an
authentication bypass for every protocol in this process, reachable with `curl`,
and the tokens minted afterwards are indistinguishable from any others. There is
no version of that endpoint which is both useful and permissive, which is why
this is the one feature here that **has to be configured before it will do
anything**:

* nothing federated happens until a relationship is created;
* a relationship is created **disabled**, and enabling it is a second act;
* an enabled relationship missing a field its protocol needs **refuses and names
  the field** rather than half-working;
* an assertion is refused unless it verifies against the certificate configured
  on that relationship — **not** against a certificate the document brought with
  it, which is the difference between a signature check and a decoration;
* the assertion's issuer must be the partner the relationship names — and since
  2026-09-12 `fedPeer` is required, so there is always one to compare against —
  and the response must answer a request this service sent (unless
  `fedAllowUnsolicited` says otherwise, which is what
  identity-provider-initiated sign-on is);
* **since 2026-09-12, the assertion must be addressed to this service**: an
  `<Audience>` naming a different service provider is refused (it was a warning),
  on every protocol including WS-Federation, and a SAML 2.0 assertion with no
  audience restriction is refused. `fedLocalEntityId` says what this service is
  called to a partner that knows it by another name.

**The gate is on the SIGNER, not on the subject.** Past it, everything is as
permissive as the rest of this service: any username in a verified assertion is
accepted, any attribute is mapped, nothing about the person is checked, and a
directory entry is created for them.

**It is also the only thing here that makes an outbound request** — a partner's
token endpoint, UserInfo or JWKS, for the OpenID Connect and OAuth 2.0 flows.
That does not soften the refusals above it: `jwks_uri` on a client registration
and WS-Federation's `wreqptr` are **still never followed**. The difference is who
supplied the URL. Those come from an unauthenticated caller; a federation
endpoint was written down by an administrator, and the module that dials it will
not accept a URL at all — only the *name* of the relationship attribute holding
one. `federation.outbound` turns it off entirely, and four of the five protocols
need no back channel.

## An assertion grant inverts it the same way, and for the same reason

Added 2026-09-10 with RFC 7521 and RFC 7523. **`grant_type=…:jwt-bearer` is the
second thing here with no permissive answer available**, and the argument is
federation's word for word.

A trusted party signs a document saying *this is alice, issue a token for her*,
and a token comes back for alice. There is **no browser, no password and no
consent step anywhere in that grant** — the signature is the whole of it. So
"accept any signed assertion" means anybody who can reach this port getting an
access token as anybody, and the token that comes out is indistinguishable from
one somebody signed in for.

So the ISSUER has to be configured before anything is believed:

* an assertion is refused unless some application in the realm declares its
  `iss` on `oauthAssertionIssuer` — and `oauth2.jwtBearerRequireRegisteredIssuer`
  is **ON by default**, which only federation's refusal is besides;
* the signature must verify against a key registered for that issuer: a `jwks`
  by value, a JWKS this service ISSUED it from its own certificate authority, or
  an `x5c` chain the assertion carries **that builds a path to this realm's Root
  CA** — a certificate that arrives WITH the signature is not evidence on its
  own, which is the one check in the PKI family a security claim rests on;
* **and since 2026-09-13 the certificate behind that key has its WHOLE chain
  validated every time it verifies an assertion**, RFC 7522's included: every
  link in date and verifying, every issuer a CA permitted to sign within its
  path length, the signer not a CA, and the path ending in this realm or at a
  self-signed root registered with the certificate. A registered chain used to
  be checked once, when it was written down. A bare key has no chain and is
  unaffected;
* `jwks_uri` is still **never followed**, for the reason above: it is a URL a
  caller supplied.

**The gate is on the SIGNER, not on the subject** — the same sentence
federation's section ends with. Past it everything is as permissive as the rest
of this service: the `sub` need not be anybody this service has heard of, an
assertion for a name nobody has ever used mints that person exactly as typing
the name at the sign-in screen does, and the scope is not checked against
anything.

**And turning the requirement off does not make the grant credulous.** Without
it the signature must still verify against a key this service holds for the
issuer; what goes away is the requirement that somebody wrote the issuer down
first. `oauth2.jwtBearerGrant` is the switch that removes the grant altogether,
and the metadata stops advertising it in the same breath — a
`grant_types_supported` member is a promise.

## The certificate authority publishes revocation, and consults it — with a few limits

**This heading reversed on 2026-09-11 and half of it stayed.** It read *the
certificate authority revokes nothing, ever — this service publishes no CRL and
answers no OCSP*.

It publishes both now. Every certificate authority in `/admin/pki` signs an RFC
5280 CRL and answers RFC 6960 OCSP, at `/pki/crl/{scope}/{ca}` and
`/pki/ocsp/{scope}/{ca}` and in the embedded directory under `ou=crl`; every
certificate this service issues names its own over plain http and ldap; a pane on that
page revokes one by hand; and anything replaced or rotated goes on its issuer's
list as `superseded` with nobody asking.

**AND SINCE 2026-09-12 IT CONSULTS THEM.** This read *what this service does
NOT do is CONSULT one — its own included … a certificate revoked on this
service's own `/admin/pki` still authenticates to this service*. A certificate
presented on the main port (XACML, SCIM, RFC 8705 client authentication and
`GET /tls/sign-in`; it was 8443 and 9443 too until both listeners were deleted
on 2026-09-16), at the SPIRE Server API or in an assertion's `x5c` is now
checked under `pki.revocationCheck` — the register for one this service issued,
the OCSP responder and the CRL it names for one from anybody else, with delta
CRLs merged and indirect CRLs read per issuer — and `auto` is **hard-fail in
product mode and soft-fail in development**. See [the PKI page](pki.md).

What is still not checked:

* **A delegated OCSP responder carrying `id-pkix-ocsp-nocheck`** is not asked
  about, because its issuer said not to. Every other responder's own status is
  looked up on the CRL its certificate names; under soft-fail one whose status
  could not be established is believed, and the verdict says so.
* **An OCSP response that echoes no nonce** is believed unless
  `pki.revocationOcspRequireNonce` is on; its freshness window is then the
  replay bound.
* **A plain `ldap:` distribution point** is not dialled unless
  `pki.revocationLdap` is `ldaps-and-ldap`, and an OCSP responder is asked over
  http(s) only. A distribution point named relative to its CRL issuer is used only
  with `pki.revocationLdapDirectory` set and every RDN single-valued.
* **A certificate naming no CRL and no responder, under hard-fail**, is accepted
  unless `pki.revocationRequireDistributionPoint` is on.
* **A BARE registered key** — a JWK with no `x5c` in `jwks`, `fedJwks` or a
  SPIFFE bundle — names no issuer and no list, so nothing can be looked up; only
  taking it off the entry stops it verifying. A registered key that DOES carry a
  certificate is checked when it verifies something (`STS-PKI-0129`).
* **LDAPS 636** asks for no client certificate, so there is nothing to check.
* **Under soft-fail — development's default — a foreign CRL that cannot be
  fetched is accepted.** That is what an attacker who can block the fetch
  exploits, and why product mode hard-fails.

**AND THERE IS A THIRD ACT WITH THE SAME WORD IN IT.** The console has a
control labelled *Take the key pair off*, and it is not revocation either:

* what it does is clear the seven attributes from the application's entry, so
  **this service** will no longer accept an assertion signed with that key,
  because the key is no longer registered against that application;
* the certificate is still valid, still chains to this realm's Root, and would
  still verify anywhere that trusts that Root. Nothing consults this service
  when it is presented and nothing can be made to.

The reply says exactly that, in those words, rather than reporting a success
that would be read as more than it is. It is the same distinction the sign-out
page draws about an assertion already issued.

**The other honest limit is where the CA private keys live.** In development —
the default — they are held in memory only and die with the process, which is
the rule the signing key already follows and for its reason: a mock is
disposable and its credentials are meant to die with it. A hierarchy built now
is gone after a restart, and everything issued from it chains to nothing. In
**product** mode it survives, sealed under the same key-encryption key as the
signing keys. Both surfaces that report it say which of the two is in force
rather than describing the mode they wish they were in.

## The three surfaces that DO require a credential

### SCIM, at `/scim/v2`

These endpoints create, replace, patch and **delete** accounts, which is why. A
credential is required — unconditionally, in both modes — all six schemes RFC
7644 section 2 names are offered, and the OAuth ones must carry `scim:read` or `scim:write` —
the only scope requirement anywhere in this service.

**It is a turnstile rather than a lock**, and that is a different sentence.
Anybody can get a token with either scope from any grant, any password but
`invalid` passes Basic, any username passes Digest with the one shared password,
and anybody can register a HOBA key for any name. What it buys is that a client's
401, 403, challenge-response and scope handling can be exercised *at all* — none
of which an open endpoint can produce.

Two schemes really verify something. **Digest** hashes the password into the
response, so a server accepting anything would not be performing the exchange and
the client's own digest code would go unexercised. **HOBA**'s signature is
genuinely verified for the same reason; what is permissive there is the
registration, because that is how a caller *gets* a credential. Between them they
make five negatives reachable that no permissive server can produce — including a
replayed nonce count refused **without** `stale=true`, because `stale` means
"your credential was fine, try again" and a replay is the opposite claim.

The discovery endpoints are open by default (`scim.authDiscovery`): the
ServiceProviderConfig is where a client *reads* which schemes exist, so demanding
a credential to fetch it means a client must already know the answer to the
question it is asking.

**A credential that was presented and failed is always a refusal**, and was one
even while these endpoints could be left open, so a client testing its
expired-token path does not get a 200 because the endpoint would also have
accepted nobody.

### The SPIRE Server API

Its TCP port is **mutual TLS**. Callers present an X509-SVID verified against the
trust bundle, and every method is authorized against SPIRE's own per-method table
— copied row for row from `pkg/server/authpolicy/policy_data.json`, not reasoned
out, so that where a row looks surprising (`Debug.GetInfo` is local-only, so an
admin SVID over TCP is refused it) the surprise is SPIRE's answer and not this
service's invention.

What comes out of that surface is a credential another service will believe,
which is why. **There is no setting that turns it off**: `spiffe.authRequired`
was removed on 2026-09-06 when `global.mode` took over the question, and the TCP
port is bound as mutual TLS on every start.

### The admin console, at `/admin`

**There is no setting that opens this console.** Every page and every form under
`/admin` needs a browser sign-on session from `/authn/login` and one of two
roles: **Admin Read** (look at everything, change nothing) and **Admin Write**
(post every form). Write implies read.

It is the one surface that can change what every *other* surface does — it
revokes tokens through the same set `/oauth2/revoke` writes to, and it adds
claims to every token, ID Token and assertion issued from then on — which is why.

**It is a turnstile rather than a lock, and here that is sharper than it is for
SCIM: no password is checked at the sign-in screen either.** What the gate proves
is that somebody *typed* a name that holds a role. What it buys is a client, or a
person, being driven through a 302 to a sign-in screen, a 401 with no session, a
403 with the wrong role, and a role model that can be granted and revoked.

**The roles are two ordinary groups in the embedded directory** — `cn=admin-read`
and `cn=admin-write` by default (`admin.readGroup`, `admin.writeGroup`) — so
`/admin/rbac`, `POST /admin-api/rbac/grant`, an `ldapmodify` and a SCIM `PATCH`
are four doors onto one membership. (In product mode the `ldapmodify` has to be
bound as somebody who already holds Admin Write, and a person cannot write
`memberOf` onto their own entry.) A role no test can grant would be a role no
test can exercise.

**Until the bootstrap administrator (`admin`) first signs in to the console,
anybody who signs in holds both roles**, and every page says so. That account is
made at startup in both groups, must choose a new password at its first sign-in,
and cannot be deleted; its first console sign-in ends the open window.
`admin.openWhenEmpty` turns the window off. Without a seeded bootstrap
administrator the older rule holds: an empty roster opens rather than closes.

**`/admin-api` takes an access token, and it is a DIFFERENT credential from the
console's.** Not a session but an OAuth 2.0 access token audienced to that API,
carrying `admin:read` to read and `admin:write` to change anything — which
become the built-in `ADMIN_READ` and `ADMIN_WRITE` roles, so the requirement is
stated in the same access policy as every other decision here. It is still a
turnstile: this service mints that token for the asking, to the seeded
`sts-management-api` client whose secret is `adminApi.clientSecret`.

**`adminApi.authRequired=false` restores the open API exactly**, and that is
worth knowing rather than hidden: an ungated `/admin-api` is what a test drives
with no secret to hold, and it is the way back in when nobody holds a console
role. What it also means is that anybody who can reach the port can grant
themselves both roles through it. Do not put this service on a public address
either way.

## GNAP proves the key, and that is not a turnstile

Every GNAP request is proofed by the key the client instance presented — an
HTTP message signature, mutual TLS, or a detached or attached JWS — and there is
no setting that accepts one without its proof, because in GNAP the key IS the
client. What stays permissive is around it, and it is the usual list:

* **In development mode an unknown key is welcome.** A key this service has
  never seen gets an application entry on first sight (`mode.autoCreates()`).
  Product mode refuses it `invalid_client` until the key is registered.
* **The resource owner is whoever the authentication service let in**, which in
  development mode checks no password.
* **A self-signed client certificate proves itself.** Mutual TLS binds to the
  certificate the handshake completed with, as RFC 8705 does, and no chain or
  revocation is consulted.
* **A push finish may dial `http`** only with `gnap.pushAllowInsecure` on, and
  only hosts in `gnap.pushAllowedHosts` when that list is set.
* **Macaroon third-party caveats, Biscuit third-party blocks and ZCAP
  invocation proofs are not implemented**; a token that needs one is refused.

## A logout cannot recall what has already been issued

`/logout` ends every session and revokes every credential this service can still
reach — see [signing out](signing-out.md). Three things it **cannot** end, and
they are listed on the page with the reason rather than left off it:

* a **SAML assertion** already in a service provider's hands
* a **Kerberos service ticket** already in a cache
* an **X509-SVID** already minted

The reason is the same in all three cases and is not a limitation of this mock:
**nothing consults the issuer when they are presented.** A relying party verifies
a signature and some `Conditions`; a Kerberos service decrypts with its own key;
an SVID verifies against a bundle. A real identity provider cannot recall any of
them either.

What a KDC *can* do — and this one does — is refuse the next `TGS-REQ` that
presents a ticket-granting ticket authenticated before the sign-out, which is
`KDC_ERR_TGT_REVOKED` (20). That is the whole of what is available, and a
**service** ticket already issued is untouched by it.

## The Workload API is the opposite case

It authenticates nobody **because its specification says it MUST NOT**. A
workload has no secret and no root of trust until that call gives it one, so the
SPIFFE Workload Endpoint specification requires that the endpoint not demand
authentication and that TLS not be required. The mutual TLS the SPIRE Server API
requires deliberately does not reach it, and no mode changes that.

What it lacks there is **attestation, not authentication**, and the two must not
be merged. A real agent reads the peer credentials of its Unix socket —
`SO_PEERCRED`, giving pid and from that uid, gid, executable, container, pod —
and turns them into selectors. **Node has no portable way to read them.** So a
caller is identified by the transport it arrived on, the endpoint it reached and
its peer address, and by nothing else, and the selectors are spelt `transport:`,
`endpoint:` and `peer:` rather than `unix:` or `k8s:`. Writing `unix:uid:1000`
for a uid nothing read would be inventing an attested fact.

Selector matching still **decides** which entries answer a caller
(`spiffe.attestWorkloads`), which is narrowing without attesting; and
`spiffe.autoCreateEntries` **off** is the interesting setting, because a caller
matching no entry then gets an empty SVID list — what a real agent does for an
unregistered workload, and the only way to run a client's "I have no identity"
path.

## RFC 9700 mode

`oauth2.rfc9700` turns the OAuth 2.0 / OIDC flow into a conforming one. It is off
by default, changes nothing until it is set, and is restart-only because it also
binds the main port as HTTPS.

**In that mode this service checks exactly one credential**: a client that
registered *here* as confidential must present the `client_secret` this service
minted for it. Section 2.5 conditions its requirement on a process for issuing
credentials existing, and `POST /oauth2/register` is one. Nothing else changes —
a `client_id` this service never registered has no credential on file and is
untouched, a registered public client has nothing to authenticate with, and no
end user's password is checked in that mode or any other.

Everything the mode does and does not enforce is at `GET /oauth2/rfc9700`, row by
row. Two rows say `enforced: no` because the requirement is the *client's* — it
must validate the ID Token's nonce, and must not use a token before that succeeds
— and nothing this server observes separates a client that checks from one that
does not.

## OAuth 2.1 mode

`oauth2.oauth21` (draft-ietf-oauth-v2-1-16) turns RFC 9700 mode on, so
everything above applies, and it checks more: **a credential a client presents
must verify** against one on file — where RFC 9700 mode lets a secret from a
public or unknown client through unchecked — and the client credentials grant
requires a client that authenticated. A client must also have registered its
own redirect URI, and a token request naming a client whose entry declares
nothing is refused.

What it still does not check: no end user's password in development mode, a
client at `/oauth2/revoke`, or at `/oauth2/introspect` beyond what that endpoint
checks in every mode — an RFC 9701 JWT request must authenticate, and a JSON one
must in product mode — or the client of an
OpenID4VCI pre-authorized code or an assertion grant that names none. `GET
/oauth2/oauth21` says which requirements are enforced and which are inherited.
