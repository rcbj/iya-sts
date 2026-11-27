---
title: Phishing-resistant sign-in
---

# Phishing-resistant sign-in

This page lists what iya-sts implements against phishing, and the
specification behind each one. A phishing site tries to get a person to
hand over what is needed to sign in as them, or to hand over the
authorization or tokens that come after the sign-in. Each section below
says what it defends against, what the service does, how to turn it on or
require it, and where the detail is. The detail is on the linked pages, and
this page does not repeat it.

* TOC
{:toc}

## Overview

The defences come in four layers:

1. **A credential a phishing site cannot use.** A passkey, a security key,
   or a client certificate in a TLS handshake (a smart card among them).
   Each one is tied to this service's origin or to the TLS session, so
   whatever a look-alike site captures cannot sign in here.
2. **A way for an application to demand one.** OpenID Connect EAP ACR
   Values 1.0's `phr` and `phrh`, which OpenID Connect, SAML 2.0, SAML 1.1,
   WS-Federation and GNAP clients can ask for. An operator can also require
   them for an application, whatever its client asks for.
3. **Nothing weaker left around it.** Account recovery that cannot fall
   back to a phishable secret, a session cookie bound to the browser, and
   tokens bound to the client's key.
4. **Integrity of the protocol around the sign-in, and notice.** Pushed and
   signed authorization requests, signed responses, `iss` in every
   authorization response, exact redirect URIs and PKCE. Then risk scoring,
   mail to the person, and Shared Signals events to receivers.

**What "phishing-resistant" means here** is OpenID Connect EAP ACR Values
1.0 section 2: a party that may be under the relying party's control
cannot gain enough to sign in to the identity provider as the person.
`phrh` adds that what is needed is held in a hardware-protected device or
component. The service grants either value only from what the
authentication actually recorded. The table of what earns each one is in
[Security profiles → Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh).

## Passkeys and security keys (WebAuthn)

**Specifications:** W3C Web Authentication (WebAuthn) Level 3, FIDO CTAP
2.1.

### Origin and RP ID binding

**Defends against:** a look-alike site relaying the sign-in. A browser puts
the calling page's origin into the signed client data. A credential is
scoped to an RP ID, and the browser offers it only to pages under that
domain. An assertion obtained by a page on another origin does not verify
here.

**What iya-sts does:** it checks the challenge, the origin, the RP ID hash,
the user-presence and user-verification flags, the signature and the
signature counter on every registration and every sign-in, in development
and in product mode. A ceremony that fails a check is refused with the
code of the first check that failed (`STS-AUTHN-0030` is the origin,
`STS-AUTHN-0031` the RP ID).

**Settings** (**Protocols → WebAuthn**, `/admin/webauthn`):

| Setting | Default | What it does |
|---|---|---|
| `webauthn.rpId` | empty: the host the service was reached on | May only widen the RP ID to a registrable domain suffix of that host, which is WebAuthn's own rule. In product mode anything else refuses the ceremony (`STS-AUTHN-0023`). |
| `webauthn.allowedOrigins` | empty: the one origin the service was reached at | The full list of origins a ceremony's client data may carry, comma-separated. |

Widen either one only deliberately. Every host under the RP ID can use the
passkeys. See [Passkeys → Several host names](passkeys.md#several-host-names)
and [Authentication → WebAuthn](authentication.md#webauthn).

### User verification

**Defends against:** a stolen or borrowed authenticator used without its
PIN or biometric.

**What iya-sts does:** `webauthn.userVerification` (default `required`) is
sent to the browser. The UV flag in the signed authenticator data is then
checked, so this is the one ceremony option the service enforces rather
than only requests. A usernameless sign-in always requires it.

### Device-bound passkeys only

**Defends against:** a passkey copied off the device by its sync provider.
A synced passkey still resists phishing, but it is not held in one piece of
hardware.

**What iya-sts does:** the passkey policy's `backupEligibility` row set to
`disallow` refuses a passkey whose backup-eligible (BE) flag is set. It is
refused at registration (`STS-AUTHN-0312`) and at every sign-in
(`STS-AUTHN-0313`), so a synced passkey registered earlier stops working
too. The default is `allow`, because most passkeys people hold are synced.

**Where:** **Directory → Policies → Passkey policy**, or
`POST /admin-api/policies/save-passkey-policy`. A named profile can apply
the row only to some applications or groups. See
[Passkeys → Device-bound passkeys only](passkeys.md#device-bound-passkeys-only-or-one-kind-of-authenticator)
and [Different rules for different applications or groups](passkeys.md#different-rules-for-different-applications-or-groups).

### Approved authenticator models (attestation)

**Defends against:** a software authenticator, or a model that is not
approved, being registered as if it were a known security key.

**What iya-sts does:** it verifies the attestation statement in all eight
WebAuthn Level 3 formats. It checks the chain against
`webauthn.attestationTrustAnchors` and the FIDO Metadata Service (MDS3)
roots, and refuses models that MDS reports as revoked or compromised. A
key with a **trusted** attestation and BE clear is the only kind that earns
`phrh`.

| Setting | Default | What it does |
|---|---|---|
| `webauthn.attestationPolicy` | `by-mode`: `verify-if-present` in product, `off` in development | `require-trusted` refuses a passkey whose statement does not chain to a trusted root. |
| `webauthn.attestationAllowedAaguids` | empty | Only these models. Requires a trusted attestation. |
| `webauthn.attestationMinCertificationLevel` | `none` | The lowest FIDO certification level. |
| `webauthn.attestationRequireFips` | `false` | Only models MDS reports as FIPS 140 certified. |

The passkey policy's `enforceAttestationAtSignIn` row (off by default)
holds every sign-in to the rules in force now (`STS-AUTHN-0316`). See
[Passkeys → Only approved authenticator models](passkeys.md#only-approved-authenticator-models)
and [Risk scoring → The FIDO metadata](risk-scoring.md#the-fido-metadata).

### Enterprise attestation

**Defends against:** a security key that was not issued to the person
being registered to their account.

**What iya-sts does:** with `webauthn.attestation` set to `enterprise`, it
asks for enterprise attestation (WebAuthn Level 3 section 5.4.7), but only
at the RP IDs listed in `webauthn.attestationEnterpriseRpIds`. With the
passkey policy's `enterpriseSerialAttribute` set, a key registers only for
the person whose entry lists its serial number (`STS-AUTHN-0320`,
`STS-AUTHN-0321`). See
[Passkeys → Enterprise attestation](passkeys.md#enterprise-attestation).

### Credential protection on a security key (credProtect)

**Defends against:** a credential on a found or stolen security key being
discovered or used without its PIN.

**What iya-sts does:** the passkey policy's `credProtect` row (default
`none`) asks for CTAP 2.1 credential protection at registration. With
`enforceCredProtect` on, it refuses a key that reports a lower level
(`STS-AUTHN-0559`). See
[Passkeys → Credential protection](passkeys.md#credential-protection-on-a-security-key-credprotect).

### Hints and the kind of authenticator

The passkey policy's `passkeyHints`, `securityKeyHints` and `signInHints`
rows send WebAuthn Level 3 hints. `webauthn.authenticatorAttachment`
(default `any`) asks for a platform or a cross-platform authenticator.
**Both are filters in the browser, not checks by the service.** To enforce
the kind of key, use `backupEligibility` or attestation, above.

### Signing in with no username

**Defends against:** a sign-in screen that asks for a username first, which
a phishing page can copy before it asks for anything else.

**What iya-sts does:** *Sign in with a passkey* uses a discoverable
credential with user verification required, and records `amr`
`["hwk","user"]` and `acr` `mfa`. The passkey policy's `allowUsernameless`
is on by default. `requireUsernameless` (off by default) makes it the only
way in for an application whose named authentication policy allows only
`webauthn`. See
[Passkeys → Signing in with no username](passkeys.md#signing-in-with-no-username).

### Post-quantum (ML-DSA) passkeys

ML-DSA passkeys protect the signature against a future quantum computer. On
phishing they change nothing: a WebAuthn assertion earns `phr` whatever its
algorithm. They are covered in
[Passkeys → Algorithms](passkeys.md#algorithms-classical-and-post-quantum)
and [Requiring a post-quantum passkey](passkeys.md#requiring-a-post-quantum-passkey)
(`webauthn.pqcOnly`, default `false`; the passkey policy's
`postQuantumRequired`, default `off`). Most authenticators cannot make an
ML-DSA passkey yet.

## Asking for a phishing-resistant sign-in: `phr` and `phrh`

**Specification:** OpenID Connect EAP ACR Values 1.0.

**Defends against:** an application accepting a password or a one-time
code (both can be phished) when it needed a phishing-resistant sign-in.

**What earns each value**, in brief:

* A passkey or security key **already registered**, alone or after a
  password, earns `phr`. A TLS client certificate earns `phr`. A federation
  partner's reported `phr` or `phrh` earns that value.
* `phrh` is also earned by a passkey whose attestation this realm
  **trusts** and whose BE flag is clear. Under development's default
  attestation policy (`off`), no key is trusted, so `phrh` is never met
  there.
* A password, a one-time code, an emailed code or link, a recovery code, a
  wallet presentation and a Kerberos ticket earn neither. A key enrolled
  during the same sign-in on the strength of a password earns neither
  either (EAP section 4). The next sign-in with that key earns `phr`.
* The values are not rungs on the `0` < `1` < `mfa` ladder. `mfa` does not
  meet `phr`.

The full table is in
[Security profiles → Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh).

### How a client asks

| Protocol | How to ask | Refused, when the session still has not earned it |
|---|---|---|
| OpenID Connect | `acr_values=phr` or `phrh`; an essential `acr` claims request; or the client's registered `default_acr_values` (`oauthDefaultAcrValues` on the console) | `unmet_authentication_requirements` (`STS-OAUTH-0970`; `STS-OAUTH-0971` for `phrh` on a key that earned only `phr`) |
| SAML 2.0 | a `RequestedAuthnContext` naming only the EAP class URIs | `STS-SAML-0116` |
| SAML 1.1 | the non-spec `authnContextClassRef` parameter naming only those URIs | `STS-SAML-0117` |
| WS-Federation | `wauth` naming one of the URIs | `STS-WSFED-0030` |
| GNAP | `interact.acr` naming only `phr`, or only `phrh` | `request_denied` (`STS-GNAP-0905`) |

The two class URIs are
`http://schemas.openid.net/pape/policies/2007/06/phishing-resistant`
(`phr`) and
`http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware`
(`phrh`). A request naming only these values makes the sign-in screen ask
for a security key or passkey, once, before it refuses. With `phrh`, the
passkey step offers only the person's keys that can earn it, and says so
before the ceremony when none can (`STS-AUTHN-0459`). A request that also
names some other class is not a demand for a key, because that other class
can answer it. A client that asks for neither value sees no change.

See [Configuring OpenID Connect flows → Phishing-resistant sign-in](configure-oidc-flows.md#phishing-resistant-sign-in-phr-and-phrh),
[Configuring WS-Federation → wauth](configure-ws-federation.md#wauth-demand-a-sign-in-method)
and [GNAP → Who must be asked, and how strongly signed in](gnap.md#who-must-be-asked-and-how-strongly-signed-in).

### Requiring it for an application

A client can forget to ask. **The issuance policy's
`requirePhishingResistant` and `requireHardwareProtected` options** take
application handles, comma-separated. For an application listed in either
one, a browser issuance is refused when the authentication behind it did
not earn the value, whatever the client asked for. Set the application's
`oauthDefaultAcrValues` to `phr` (or `phrh`) as well. The sign-in screen
then asks for the key, rather than refusing a password afterwards.

Both are parameters of the `role-issuance` template, so they are set on an
override of the issuance policy: **Protocols → XACML**, **Policies** tab,
**Create an override** on the **Issuance** row. Or:

```bash
api xacml/create-from-template '{"template":"role-issuance","name":"role-issuance",
  "p_requirePhishingResistant":"payroll"}'
```

Read [Configuring XACML → Override a built-in policy in one realm](configure-xacml.md#override-a-built-in-policy-in-one-realm)
before you create one. An override replaces the built-in document.

### The XACML fact

A realm's own policy can decide on the same fact. The issuance request
carries `urn:sts:xacml:phishing-resistance`, which is `phr`, `phrh` or
`none`, so a rule can tell a sign-in that was not phishing-resistant from a
request that did not ask. See [XACML 3.0 and ALFA](xacml.md).

### Federation partners

When this service is the relying party of a federation partner, a sign-in
whose partner reported `acr` `phr` or `phrh` carries that value. The partner
applied the same definition at its own origin, and nothing this service
could check would add to it. See [Federation](federation.md).

## Smart cards and X.509 certificate sign-in

**Specifications:** TLS 1.3 client authentication (RFC 8446; TLS 1.2 works
the same way where a listener allows it), RFC 5280 path validation,
FIPS 201-3 (PIV).

**Defends against:** the same relay a passkey defeats. The client's
CertificateVerify signs the handshake transcript, which binds this
server's certificate, so a site in the middle can neither replay nor
forward it.

**What iya-sts does:** a sign-in with a client certificate at
`/tls/sign-in`, a PIV card, a CAC or another X.509 smart card among them,
earns `phr`. It is one factor (`acr "1"`). In product mode the person owes a
second factor after it unless `authn.allowOptionalSecondFactor` is on.
`requireAttestedHardware` on the authentication policy can require an
attested card or key of everybody
([Attested hardware for everybody](authentication.md#attested-hardware-for-everybody)).

See [Smart cards](smart-cards.md), the
[Smart-card guide](smart-cards-guide.md) and
[Configuring TLS → Smart-card and certificate sign-in](configure-tls.md#smart-card-and-certificate-sign-in).

## Account recovery no weaker than the passkey

**Defends against:** a phisher who cannot use a passkey asking for the
account to be "recovered" through a reset link, a recovery code or an
emailed code instead.

**What iya-sts does:** the passkey policy's `recoveryAssurance` row
decides, for a person who holds a passkey:

| Value | After a recovery that used no passkey |
|---|---|
| `any` (the development default) | access is restored at once |
| `not-weaker` (the product default) | the first session reaches no application until the person registers a new passkey and signs in with it (`STS-AUTHN-0381`) |
| `operator-only` | as `not-weaker`, and the self-service doors are refused (`STS-AUTHN-0380`). Only an administrator's link or generated password is left. |

There is no self-service reset of a second factor. See
[Passkeys → Losing a passkey, and account recovery](passkeys.md#losing-a-passkey-and-account-recovery)
and [Authentication → The passkey policy](authentication.md#the-passkey-policy).

## A session cookie bound to the browser (DBSC)

**Specification:** W3C Device Bound Session Credentials (draft).

**Defends against:** a phishing proxy or malware that steals the session
cookie after a sign-in, phishing-resistant or not, and replays it from
another machine.

**What iya-sts does:** with `authn.deviceBoundSessions` on (per realm, off
by default), a supporting browser binds the session to a key it holds. The
session is then honoured only beside a short-lived second cookie, which
only a proof of that key renews (`authn.deviceBoundCookieLifetimeS`,
default 600 seconds). A refresh signed by another key, or a replayed
challenge, ends the session. A browser without DBSC keeps an ordinary
session. A passkey profile's `deviceBoundRequired` row makes issuance to
its applications wait for a bound session.

**Where:** the setting is on `/admin/config`. See
[Sessions → Device Bound Session Credentials](sessions.md#binding-the-cookie-to-the-browser-device-bound-session-credentials).

## Tokens a thief cannot use (sender constraints)

**Specifications:** RFC 9449 (DPoP), RFC 8705 (mutual-TLS-bound tokens),
RFC 9700 section 2.2.

**Defends against:** an access token or refresh token taken after a phish
being used from somewhere else. A bound token is useless without the
client's private key.

**What iya-sts does:** it binds a token to a DPoP key (`cnf.jkt`) or to the
client certificate (`cnf["x5t#S256"]`) when the client asks. Neither mode
requires a binding. These settings do, and every one is **off by default**
(**Protocols → OAuth 2.0 / OIDC**, `/admin/oauth2`):

| Setting | What it requires |
|---|---|
| `oauth2.accessTokenRequireSenderConstraint` | the token endpoint issues an access token only to a request that binds it, by DPoP or the connection's certificate; the authorization endpoint refuses `response_type=token` |
| `oauth2.accessTokenRequireDpop`, `oauth2.accessTokenRequireMtls` | every protected resource refuses an access token that is not bound and proved |
| `oauth2.refreshTokenRequireDpop`, `oauth2.refreshTokenRequireMtls` | no refresh token without the binding |

In RFC 9700 mode, which product mode implies, refresh tokens rotate, and a
replay revokes the whole family. See
[Security profiles → DPoP](oauth-security.md#dpop-rfc-9449),
[Mutual TLS](oauth-security.md#mutual-tls-rfc-8705) and
[Requiring a sender constraint](oauth-security.md#requiring-a-sender-constraint--five-settings).

## Integrity of the authorization request and response

These stop a phishing site from changing an authorization request on its
way to the sign-in, or from capturing the response on its way back.

| Defence | Specification | What iya-sts does | How to turn it on or require it | Detail |
|---|---|---|---|---|
| Pushed authorization requests | RFC 9126 | the request goes from the client to `/oauth2/par` over the back channel, and the browser carries only a short-lived `request_uri` | on by default (`oauth2.pushedAuthorizationRequests`); require it with `oauth2.requirePushedAuthorizationRequests` (realm) or `oauthRequirePushedAuthorizationRequests` (client) | [PAR](configure-oidc-flows.md#pushed-authorization-requests) |
| Signed request objects | RFC 9101 (JAR) | verifies the request object's signature with the client's keys; a `request_uri` is fetched only when registered | `oauth2.requireSignedRequestObject` (realm, default `false`) or the client's `oauthRequireSignedRequestObject`; product mode refuses `alg: none` | [Request objects](configure-oidc-flows.md#request-objects-jar) |
| Signed authorization responses | JARM | `response_mode=jwt` and its variants, in every mode | the client asks for it | [Response modes](configure-oidc-flows.md#response-modes-query-fragment-formpost-jarm) |
| `iss` in the authorization response | RFC 9207 | `iss` on every authorization response, errors included, published as `authorization_response_iss_parameter_supported` | always on | [OAuth 2.0 and OpenID Connect](oauth-oidc.md) |
| Exact redirect URIs | RFC 9700 section 2.1 | exact string match, no patterns; a bad `redirect_uri` is answered on this server and never redirected to. A loopback URI may use any port (RFC 8252 section 7.3). | a client's own registered URIs in every mode; `oauth2.rfc9700`, which product mode implies, for the rest | [Redirect URIs](oauth-security.md#redirect-uris-section-21) |
| PKCE | RFC 7636 | `S256` only, `plain` refused; downgrade and reused challenges refused | RFC 9700 mode for every client not known to be confidential; product mode for confidential clients too (`oauth2.allowConfidentialWithoutPkce` opts out) | [The authorization code flow](oauth-security.md#the-authorization-code-flow-section-211) |
| No framing | RFC 9700 section 4.14 | `frame-ancestors 'none'`, so a sign-in or consent page cannot be framed by another site. The one page that may be framed is the OpenID Connect Session Management iframe, off by default. | always on | [Clickjacking](oauth-security.md#clickjacking-section-414) |
| No redirect after sign-in to anywhere | — | the address the sign-in screen returns to must be a path on this service | always on | [Authentication → The sign-in screen](authentication.md#the-sign-in-screen-and-the-session) |

### The device authorization grant (RFC 8628)

RFC 8628 section 5.4 describes remote phishing: an attacker starts a flow
on their own device and sends the user code to the victim. The grant is
**off by default** (`oauth2.deviceAuthorization`). With it on, a code,
typed or prefilled, only brings up the request on `/portal/device`, naming
the client and the scopes and asking the person to approve only a device
in front of them. Approving is a separate click. See
[Configuring OAuth 2.0 grants → Device authorization](configure-oauth2-grants.md#device-authorization-rfc-8628).

## Detection and notice

| What | Default | Detail |
|---|---|---|
| **Risk scoring** of every sign-in (new device, new country, anonymising networks, refused passwords), and the issuance policy's risk decisions | `risk.assessSignIns` on | [Risk scoring](risk-scoring.md) |
| **A cloned security key** (its signature counter went backwards) is reported as RISC `credential-compromise`, and the person's risk standing goes to HIGH | `risc.autoEmit` on | [Shared Signals](shared-signals.md) |
| **Sign-in alert mail**: an unusual successful sign-in, and a run of refused passwords, with a link to **Recent sign-ins** and **This wasn't me** | `mail.signInAlerts` on, with a mail transport and `mail.securityNotices` on | [Risk scoring → The person is told of an unusual sign-in](risk-scoring.md#the-person-is-told-of-an-unusual-sign-in) |
| **Credential-change mail**: a passkey, authenticator app, app password, one-time code token or recovery codes added or removed | `mail.credentialChangeNotices` on | [Mail](mail.md) |
| **CAEP and RISC events** to receivers: `credential-change` when a credential is added, changed or removed, `session-revoked` when a session ends, RISC account events | `ssf.enabled` on | [CAEP events](caep-events.md), [Shared Signals](shared-signals.md) |

## I want to …

| I want to … | Do this | Read |
|---|---|---|
| let an OpenID Connect client demand a phishing-resistant sign-in | `acr_values=phr` (or `phrh`), or `oauthDefaultAcrValues` | [Phishing-resistant sign-in](configure-oidc-flows.md#phishing-resistant-sign-in-phr-and-phrh) |
| require it for an application, whatever the client asks | the issuance policy's `requirePhishingResistant` (or `requireHardwareProtected`) | [Requiring it for an application](#requiring-it-for-an-application) |
| make a SAML or WS-Federation application demand it | `RequestedAuthnContext` or `wauth` with the EAP class URIs | [How a client asks](#how-a-client-asks) |
| allow only device-bound passkeys | passkey policy `backupEligibility` = `disallow` | [Device-bound passkeys only](passkeys.md#device-bound-passkeys-only-or-one-kind-of-authenticator) |
| allow only approved security key models | `webauthn.attestationPolicy` = `require-trusted`, and `webauthn.attestationAllowedAaguids` | [Only approved authenticator models](passkeys.md#only-approved-authenticator-models) |
| make `phrh` reachable | a trusted attestation (`verify-if-present` or `require-trusted`, with MDS or an anchor) and device-bound keys | [Security profiles](oauth-security.md#phishing-resistant-sign-in-phr-phrh) |
| use one passkey across sibling hosts | `webauthn.rpId` and `webauthn.allowedOrigins` | [Several host names](passkeys.md#several-host-names) |
| stop account recovery bypassing the passkey | passkey policy `recoveryAssurance` = `not-weaker` or `operator-only` | [Account recovery](passkeys.md#losing-a-passkey-and-account-recovery) |
| let people sign in with a smart card | see the guide's recipes | [Smart-card guide](smart-cards-guide.md) |
| stop a stolen session cookie working elsewhere | `authn.deviceBoundSessions` | [Sessions](sessions.md#binding-the-cookie-to-the-browser-device-bound-session-credentials) |
| stop a stolen access token working elsewhere | `oauth2.accessTokenRequireSenderConstraint`, or the DPoP and mTLS settings | [Requiring a sender constraint](oauth-security.md#requiring-a-sender-constraint--five-settings) |
| keep the authorization request out of the browser | `oauth2.requirePushedAuthorizationRequests` | [PAR](configure-oidc-flows.md#pushed-authorization-requests) |
| tell people about an unusual sign-in | `mail.signInAlerts`, with a mail transport | [Risk scoring](risk-scoring.md#the-person-is-told-of-an-unusual-sign-in) |

## What is not implemented

* **A smart card never earns `phrh`**, even an attested YubiKey. Only a
  WebAuthn assertion earns it, because nothing a TLS handshake carries says
  where the certificate's private key lives. Nor does any TLS client
  certificate.
* **A request asking only for `phr` or `phrh` is offered a security key or
  passkey, not the card's certificate**, although a card sign-in earns
  `phr`.
* **An outside PIV or CAC card gets no Kerberos ticket.** PKINIT takes only
  certificates this realm issued (`STS-KRB-0184`). A federal card holder
  signs in over TLS instead. See
  [Kerberos PKINIT](smart-cards-pkinit.md#what-it-does-not-implement).
* **WebAuthn Related Origin Requests** (`/.well-known/webauthn`) are not
  served. A passkey works across hosts only under one RP ID, through
  `webauthn.rpId` and `webauthn.allowedOrigins`.
* **No `topOrigin` check.** The client data's `crossOrigin` and `topOrigin`
  are not read, so a passkey ceremony in a cross-origin iframe is not
  supported. The sign-in pages refuse to be framed
  (`frame-ancestors 'none'`).
* **`acr_values` is not read on the device authorization and
  token-exchange grants**, so neither can demand `phr` or `phrh`. Use the
  issuance policy's options to require it for the application.
* **The authenticator attachment and the WebAuthn hints are not enforced.**
  They are requests to the browser.
* **Federated device-bound sessions**, where one origin's DBSC key is used
  at another, are not implemented.

## Related

* [Passkeys and WebAuthn](passkeys.md)
* [Authentication](authentication.md)
* [Security profiles](oauth-security.md)
* [Smart cards](smart-cards.md)
* [Sessions](sessions.md)
* [Security in product mode](product-security.md)
* [Risk scoring](risk-scoring.md)
* [Shared Signals](shared-signals.md)
* [Specifications](specifications.md)
