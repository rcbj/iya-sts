---
title: SAML 2.0 Web Browser SSO
---

# SAML 2.0 Web Browser SSO

iya-sts is a **SAML 2.0 identity provider**: the Web Browser SSO profile and
Single Logout of
[saml-profiles-2.0-os](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
over the Redirect, POST, POST-SimpleSign and Artifact bindings of
[saml-bindings-2.0-os](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
and the
[HTTP POST "SimpleSign" binding](https://docs.oasis-open.org/security/saml/Post2.0/saml-binding-simplesign-cs-02.pdf),
with signed [metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
published per service provider. It consumes service provider metadata, verifies
a service provider's signatures, and encrypts assertions. Every trust realm has
its own identity provider, with its own entityID, signing key, service
providers and metadata.

This page is about the **browser profile**. Presenting a SAML 2.0 assertion at
the OAuth token endpoint (RFC 7522) is a different feature, documented in
[SAML 2.0 assertions](saml-assertions.md) despite the similar name. This page
also covers the two console pages that shape **every** assertion this service
issues — [SAML assertion settings](#the-assertion-settings-every-application-inherits)
and [custom SAML attributes](#custom-saml-attributes) — which apply to SAML 1.1,
WS-Trust and WS-Federation as well.

```
  browser                     service provider                    iya-sts
     │  GET /app ──────────────────▶│                                   │
     │  ◀── 302 AuthnRequest ───────│                                   │
     │  GET /saml2/sso/{sp}?SAMLRequest=… ─────────────────────────────▶│
     │                              │         sign in at /authn/login   │
     │  ◀──────────── auto-posting form (Response, signed) ─────────────│
     │  POST ACS ──────────────────▶│                                   │
```

## Features

### Endpoints

| Path | What it is |
|---|---|
| `GET\|POST /saml2/sso[/{sp}]` | the Single Sign-On service — GET is the HTTP Redirect binding, POST is HTTP POST or POST-SimpleSign |
| `POST /saml2/ars[/{sp}]` | the Artifact Resolution Service, SOAP over HTTP — a back channel the browser never touches |
| `GET\|POST /saml2/slo[/{sp}]` | Single Logout, in both directions |
| `GET /saml2/metadata[/{sp}]` | the signed identity provider metadata, one document per service provider |
| `GET\|POST /saml2/sp` | a **mock service provider** (not part of any specification) |
| `GET /saml2` | a page describing all of the above, including every AuthnRequest parameter and what is done with it |

In a trust realm every path is under `/realm/{id}`. The full, current list is
at `/admin/sts-metadata`.

### Metadata, one document per service provider

`/saml2/metadata/{sp}` publishes an identity provider **of its own for that
service provider** — its entityID is `saml2.entityId` followed by `:{sp}`, and
its SSO, SLO and artifact endpoints sit under the same `{sp}` segment. That is
what Okta and Ping give each application, and it means two service providers
are configured from two documents that share nothing but a signing
certificate. `saml2.perApplicationEntityId` off gives every document the one
entityID; the endpoints stay per application either way.

`{sp}` is the service provider's entityID percent-encoded, or a **slug** — the
entityID where it is safe in a URL path, otherwise `app-` and twelve hex
characters of its SHA-256. A slug is not reversible, so `/admin/saml2` lists the
metadata URL for every service provider rather than leaving you to derive it.

**The metadata is minted for any entityID asked for** and never 404s. In
development, with `saml2.autocreateApplications` on (the default), asking for
it — or a valid AuthnRequest — creates the application entry; in product mode
nothing is created because something named it. The document publishes a
`use="encryption"` key, the NameID formats this identity provider advertises,
`WantAuthnRequestsSigned` according to the signing policy below, the
bindings it speaks, and an `<md:Organization>` from `saml.organization*`.

### Signing in: the Single Sign-On service

The AuthnRequest arrives on the Redirect binding (DEFLATE, base64, and an
optional detached query-string signature), on HTTP POST (an optional enveloped
signature) or on POST-SimpleSign. The **Response goes back** on the binding its
`ProtocolBinding` names: HTTP-POST (the default), HTTP-Redirect, HTTP-Artifact
or POST-SimpleSign. Anything else — PAOS included — is refused by name.

**There is no SAML sign-in screen.** The person signs in at the
[authentication service](authentication.md) every protocol here shares, so a
person already signed in for OAuth, WS-Federation or SAML 1.1 is not asked
again, and WebAuthn, TOTP, SPNEGO, a client certificate or a federated partner
are all available at that screen. An AuthnRequest that arrives by cross-site
POST is held and the browser is sent to a GET on the same endpoint, because
`SameSite=Lax` keeps the session cookie off a cross-site POST but not off a
top-level GET. The request is held for `saml2.requestTtlMin`.

The AuthnRequest controls that change what happens:

* **`ForceAuthn="true"`** shows the sign-in screen once even with a session; the
  re-authentication moves the `AuthnInstant`. A trip that comes back without a
  fresh sign-in is answered `AuthnFailed`, never sent round again.
* **`IsPassive="true"`** with no usable session is answered with a `NoPassive`
  status rather than a screen.
* **`RequestedAuthnContext`** naming a multi-factor class sends the person to
  the screen with a second factor required; a context still unmet after that
  one attempt is answered `NoAuthnContext`.
* **`NameIDPolicy/@Format`** chooses the NameID format. Any format asked for is
  answered — unless the service provider's consumed metadata declares its
  formats and this is not one, which is `InvalidNameIDPolicy`. With no format,
  `saml2.nameIdFormat` decides. `transient` is an opaque per-session value;
  `emailAddress` is the person's mail address; the others carry the username.
* A **cancelled** sign-in is reported to the service provider as a failure
  Response.

**The `AuthnContextClassRef` says how the session really authenticated**:
`PasswordProtectedTransport` for a password, `multipleauthn` for two factors,
`TLSClient` for a client certificate, `Kerberos` for SPNEGO, a federation
partner's own class for a federated sign-in, and `unspecified` for a security
key alone or no authentication.

### The Response and the assertion

The assertion carries a bearer `SubjectConfirmationData` with `Recipient`,
`InResponseTo` and `NotOnOrAfter`, an audience restriction naming the service
provider, a session index, and an attribute statement: the person's name, given
name, surname, mail and identifier as claim URIs, and the same facts under the
short names many service providers are configured with (`uid`, `mail`,
`givenName`, `sn`, `displayName`), plus any [custom SAML
attributes](#custom-saml-attributes). Both the assertion and the Response are
signed by default (`saml2.signAssertion`, `saml2.signResponse`); on the Redirect
binding `signResponse` means the query-string signature. The signature algorithm
and canonicalization are `saml.signatureAlgorithm` and
`saml.canonicalizationAlgorithm`.

A Response on the Redirect binding longer than `saml2.redirectWarnLength` is
logged at WARN and sent anyway — bindings section 4.1.2 says a response should
not travel that way at all.

### The Artifact binding

An artifact is the 44 bytes bindings section 3.6.4 specifies (type `0x0004`,
an endpoint index, the SHA-1 of the issuer's entityID, twenty random bytes) and
stands for the whole Response. The service provider resolves it with an
`ArtifactResolve` at `/saml2/ars`:

* **it resolves exactly once**, across every node of a cluster; a second
  resolution is refused with a status naming the reason. `saml2.artifactTtlS` is
  only the upper bound on how long an unresolved one lives;
* the resolver must be **the service provider the artifact was issued to**;
* where signed requests are required, the resolver must **prove it** — by
  signing the `ArtifactResolve` or by presenting one of its registered
  certificates as the TLS client certificate. A refused caller does not spend
  the artifact.

### Single Logout

`/saml2/slo` answers a `LogoutRequest` from a service provider — ending the
session and returning a `LogoutResponse` — and accepts a `LogoutResponse`. An
`<saml:EncryptedID>` in an incoming request is always decrypted. A bare
`GET /saml2/slo` is identity-provider-initiated: it ends the session and names
every service provider signed into, with a signed `LogoutRequest` for each,
offered as links rather than fired blind into hidden frames, because a
`LogoutRequest` expects an answer the page could not observe. The
protocol-independent sign-out at `/logout` does the same; see
[Signing out](signing-out.md).

A `LogoutRequest` carries no return address, so the `LogoutResponse` goes to,
in order: the consumed metadata's `SingleLogoutService`, the
`samlSingleLogoutService` on the application entry,
`saml2.defaultSingleLogoutService`, and finally the ACS URL the service provider
last used — which is a guess, and is logged as one. Logout messages follow the
same signature policy as an AuthnRequest, and a refused `LogoutRequest` ends no
session.

### A service provider's signatures

A signature that is present — the Redirect query-string signature over the
parameters exactly as they arrived, the SimpleSign signature over the form
values, or an enveloped one on POST — on an AuthnRequest, LogoutRequest,
LogoutResponse or ArtifactResolve is **verified in every mode**:

| A request that is… | Development | Product |
|---|---|---|
| signed, and verifies against a **registered** certificate | accepted | accepted |
| signed, and does not verify | refused | refused |
| signed, and not checkable (MD5, a MAC, HSS/LMS, XMSS, signature wrapping) | refused | refused |
| signed with SHA-1, `saml.allowSha1Signatures` off | refused | refused |
| from a service provider whose consumed metadata has expired | refused | refused |
| signed, with no certificate registered | accepted, not verified | refused |
| unsigned | accepted | refused |

The last two rows follow `saml2.requireSignedAuthnRequests` (`auto` is on in
product and off in development), and a service provider whose metadata says
`AuthnRequestsSigned="true"` is held to it whatever the setting. RSA (PKCS#1
v1.5 and PSS), ECDSA, EdDSA, DSA, ML-DSA and SLH-DSA are verified. A refusal is
a page, not a Response, because the address a Response would go to is part of
what the signature protected.

**The certificate a request carries in `ds:KeyInfo` is never trusted.** It is
recorded on the entry as *observed*; an operator **confirms** it (it becomes a
registered certificate) or **discards** it on `/admin/saml2`. The mock service
provider at `/saml2/sp` signs its requests with this service's own key.

### Consuming service provider metadata

A service provider's metadata is consumed from its `samlSpMetadataUrl` (the
**Refresh** action), by upload on `/admin/saml2`, from an MDQ responder, or by
the background refresher — **never while a sign-in is being answered**.
Consuming registers:

* its AssertionConsumerService and SingleLogoutService endpoints — a request is
  then answered only at one of them, chosen by `AssertionConsumerServiceIndex`,
  by `AssertionConsumerServiceURL`, or by default, **in every mode**;
* its signing certificates (the registered set is replaced) and its encryption
  certificate;
* its NameIDFormats, `AuthnRequestsSigned` and `WantAssertionsSigned`;
* its `validUntil` and `cacheDuration`.

**Expiry is enforced**: past the earliest `validUntil` in the document, every
request from that service provider is refused until newer metadata is consumed.
**Past its `cacheDuration`** (or halfway to `validUntil`) the background
refresher fetches it again (`saml2.spMetadataRefresh`); a failed fetch changes
nothing, so the last good document keeps working until it expires.

**A metadata signature is verified only against a trust anchor** — the entry's
`samlSpMetadataSigningCertificate` or the realm's `saml2.metadataTrustAnchors`.
With either set, an unsigned or unverifiable document is refused. An
`EntitiesDescriptor` aggregate is read for the one entity the application is.
Every fetch goes through the federation outbound policy: HTTPS, the
`federation.outbound` switch, the timeout, no redirects,
`saml2.spMetadataMaxBytes`, and — in product — no internal addresses.

### Metadata Query Protocol (MDQ)

With `saml2.mdqBaseUrl` set, metadata is fetched from
`<base>/entities/<percent-encoded entityID>`
([draft-young-md-query](https://datatracker.ietf.org/doc/draft-young-md-query/)).
**Import from MDQ** on `/admin/saml2` creates an application from the answer;
an entry with no URL refreshes from MDQ; and a request from a service provider
with no consumed metadata **starts** a lookup without waiting for it, so that
request is answered as unknown and the next one finds the registration.

### Encryption

This service encrypts the assertion (`<saml:EncryptedAssertion>`) and, in a
`LogoutRequest` it sends, the NameID (`<saml:EncryptedID>`). There is no
encrypted AuthnRequest in SAML 2.0, so that is all a request can carry. The
assertion is **signed first, then encrypted**, so the signature is inside the
ciphertext.

The recipient certificate is taken, most specific first, from
`samlEncryptionCertificate` on the entry (which consuming metadata writes), a
registered `samlSigningCertificate`, and — in development only — the observed
certificate off a signed AuthnRequest. Encryption happens when
`saml2.encryptAssertion` (or the application's override) says so, **or** when
the service provider's consumed metadata publishes an encryption key.

Four block ciphers (`aes256-gcm`, `aes128-gcm`, `aes256-cbc`, `aes128-cbc`) and
two key transports (`rsa-oaep-mgf1p`, `rsa-1_5`). CBC is unauthenticated and
`rsa-1_5` is Bleichenbacher-broken; both are offered because deployed service
providers require them.

### The mock service provider

`/saml2/sp` is the default assertion consumer service and a test harness. It
sends a signed AuthnRequest, receives the Response on any binding, and verifies
it **check by check** — signature, issuer, audience, recipient, `InResponseTo`,
the validity window — and checks that its own `RelayState` came back unaltered
(remembered for `saml2.mockSpContextTtlMin`). It is not part of any
specification.

### The assertion settings every application inherits

**Protocols → SAML → SAML assertions** (`/admin/saml-assertions`) holds the
defaults for what goes into an assertion — for this profile, SAML 1.1, WS-Trust
and WS-Federation alike, because all four are built by the same two assertion
builders:

| For each of SAML 2.0 and SAML 1.1 | Overridden on an application by |
|---|---|
| assertion lifetime | `saml2AssertionLifetimeMin` / `saml11AssertionLifetimeMin` |
| sign the assertion | `saml2SignAssertion` / `saml11SignAssertion` |
| sign the response | `saml2SignResponse` / `saml11SignResponse` |
| NameID format | `saml2NameIdFormat` / `saml11NameIdFormat` |
| artifact lifetime | `saml2ArtifactTtlS` / `saml11ArtifactTtlS` |

Beside them are the four SAML 2.0 encryption settings (overridden by
`saml2EncryptAssertion`, `saml2EncryptionAlgorithm`,
`saml2KeyTransportAlgorithm`, `saml2EncryptLogoutNameId`), the WS-Federation
assertion lifetime (`wsfedAssertionLifetimeMin`), and the clock skew — which
**cannot** be overridden per application, because it is a fact about the clocks
in the estate rather than about one relying party.

An override is an attribute on the application's entry, set on
`/admin/applications`; an **absent attribute means inherit**, and a value that
does not parse is ignored and logged. The application is identified by the
**service provider's** entityID (or SAML 1.1 relying party identifier).

**The clock skew widens the validity window at both ends**: `NotBefore` is
backdated and `NotOnOrAfter` extended by `saml.clockSkewS`, while
`IssueInstant` and `AuthnInstant` are never moved — they state when something
happened. So the window a relying party sees is the lifetime plus **twice** the
skew, and the page reports that figure as `saml2WindowS` and `saml11WindowS`.
At the default `0` nothing is widened. This is not `oauth2.clockSkewS`, which is
the tolerance applied when this service **reads** a document.

A change reaches the next assertion; nothing already issued changes.

### Custom SAML attributes

**Protocols → SAML → Custom SAML attributes** (`/admin/saml-attributes`) adds
attributes to every assertion issued from now on by this profile, SAML 1.1,
WS-Trust and WS-Federation. There are two sets, because the two vocabularies
differ:

| Set | Element | Reaches |
|---|---|---|
| **SAML 2.0 Attribute** | `Name` and an optional `NameFormat` | this profile, and WS-Trust's SAML 2.0 assertions |
| **SAML 1.1 Attribute (WS-Federation)** | `AttributeName` and a **required** `AttributeNamespace` | SAML 1.1's browser profiles and WS-Federation's sign-in response |

A SAML 1.1 attribute given no namespace gets
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims`, the claim namespace
WS-Federation relying parties read. Each set has two halves:

* **typed attributes** — a name and a value, the same for everybody, where
  `${subject}` and `${audience}` expand (another placeholder names itself);
* **directory attributes** — LDAP attribute types whose values are read off the
  person's entry, so an `ldapmodify` changes the next assertion.

Attributes are **additive**: one cannot displace an attribute the profile
already sends, and a multi-valued value becomes several `<AttributeValue>`
children of one `<Attribute>`. The JWT reserved-claim list does not apply
here — an attribute called `exp` collides with nothing. The page previews the
result for a person. Custom JWT claims are on `/admin/claims`; the store behind
both pages is one.

### Not implemented

Identity-provider-initiated SSO (an unsolicited Response), the ECP profile and
its PAOS binding (refused by name), Name Identifier Management, and the
Assertion Query and Request profile. No MAC, MD5, HSS/LMS or XMSS signature is
verified. A service provider's metadata URL is never fetched while a request is
being answered.

## Development and product mode

| | Development | Product |
|---|---|---|
| Unsigned request, or signed with no registered certificate | accepted (`saml2.requireSignedAuthnRequests=auto`) | refused |
| `AssertionConsumerServiceURL` with no consumed metadata | used as it stands; with none, the registered address or `/saml2/sp` | must be a registered `samlAssertionConsumerService`, exact match, no mock fallback; an address development merely observed is refused until confirmed |
| An unknown entityID's request, or a metadata request for one | accepted, and its application entry created | answered without creating an entry; its AuthnRequest is refused — no registered return address and no signature (an MDQ lookup can register it) |
| Encryption wanted and no certificate | sent **in clear**, with a WARN | refused with a `Responder` status and no assertion |
| Encryption to an observed request certificate | yes | only once an operator confirms it |
| `WantAssertionsSigned` in the SP's metadata with `saml2.signAssertion` off | the setting wins, and the request is logged | the assertion is signed |
| Given name, surname, mail, display name | invented | read off the directory entry, or omitted |
| Empty `saml2.entityId` | replaced with `urn:sts:idp` | SSO and metadata refuse, naming the setting |
| Artifact resolver authentication | not required (follows `requireSignedAuthnRequests`) | required |

A present signature, metadata expiry, a consumed ACS endpoint list and the
one-shot artifact are enforced in **both** modes. See
[What is not checked](what-is-not-checked.md).

## Configuration

### SAML (shared with SAML 1.1, WS-Trust and WS-Federation)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `saml.issuer` | `STS_SAML_ISSUER` (or `STS_ISSUER`) | `urn:wstrust:mock:sts` | yes | Who signed an assertion: the issuer of the SAML assertions WS-Trust and WS-Federation carry, and what `/wsfed/rp` checks one against. The browser profiles name themselves with `saml2.entityId` and `saml11.providerId`. |
| `saml.clockSkewS` | `STS_SAML_CLOCK_SKEW_S` | `0` | yes | Seconds added to both ends of every issued assertion's validity window (at most 300). |
| `saml.signatureAlgorithm` | `STS_SAML_SIGNATURE_ALGORITHM` | `rsa-sha256` | yes | The XML signature algorithm and Redirect `SigAlg`: `rsa-sha256`, `rsa-sha384`, `rsa-sha512`, or the broken `rsa-sha1`. |
| `saml.canonicalizationAlgorithm` | `STS_SAML_CANONICALIZATION_ALGORITHM` | `exclusive` | yes | `exclusive` or `exclusive-with-comments`; inclusive c14n is not offered. |
| `saml.allowSha1Signatures` | `STS_SAML_ALLOW_SHA1_SIGNATURES` | `false` | yes | Whether an XML signature this service verifies may use SHA-1; if allowed it is recorded as weak. |
| `saml.organizationName` | `STS_SAML_ORGANIZATION_NAME` | `sts` | yes | `<md:OrganizationName>` in the SAML metadata; empty omits `<md:Organization>`. |
| `saml.organizationDisplayName` | `STS_SAML_ORGANIZATION_DISPLAY_NAME` | `Mock security token service` | yes | `<md:OrganizationDisplayName>`; empty omits the organisation. |
| `saml.organizationUrl` | `STS_SAML_ORGANIZATION_URL` | *(empty)* | yes | `<md:OrganizationURL>`; empty means this service's base URL. |

### SAML 2.0

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `saml2.entityId` | `STS_SAML2_ENTITY_ID` | `urn:sts:idp` | yes | The identity provider's entityID and the `Issuer` of every Response and assertion this profile issues. |
| `saml2.perApplicationEntityId` | `STS_SAML2_PER_APPLICATION_ENTITY_ID` | `true` | yes | Give each service provider its own entityID, `<entityID>:{sp}`. |
| `saml2.assertionLifetimeMin` | `STS_SAML2_ASSERTION_LIFETIME_MIN` | `60` | yes | Assertion lifetime; per application with `saml2AssertionLifetimeMin`. |
| `saml2.signAssertion` | `STS_SAML2_SIGN_ASSERTION` | `true` | yes | Sign the assertion; per application with `saml2SignAssertion`. |
| `saml2.signResponse` | `STS_SAML2_SIGN_RESPONSE` | `true` | yes | Sign the Response (the query string on the Redirect binding); per application with `saml2SignResponse`. |
| `saml2.nameIdFormat` | `STS_SAML2_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | yes | The NameID format when the request names none; per application with `saml2NameIdFormat`. |
| `saml2.artifactTtlS` | `STS_SAML2_ARTIFACT_TTL_S` | `300` | yes | How long an unresolved artifact lives (it is one-shot regardless); per application with `saml2ArtifactTtlS`. |
| `saml2.encryptAssertion` | `STS_SAML2_ENCRYPT_ASSERTION` | `false` | yes | Encrypt the assertion; per application with `saml2EncryptAssertion`. |
| `saml2.encryptionAlgorithm` | `STS_SAML2_ENCRYPTION_ALGORITHM` | `aes256-gcm` | yes | The block cipher: `aes256-gcm`, `aes128-gcm`, `aes256-cbc`, `aes128-cbc`. |
| `saml2.keyTransportAlgorithm` | `STS_SAML2_KEY_TRANSPORT_ALGORITHM` | `rsa-oaep-mgf1p` | yes | The key wrap: `rsa-oaep-mgf1p` or the broken `rsa-1_5`. |
| `saml2.encryptLogoutNameId` | `STS_SAML2_ENCRYPT_LOGOUT_NAMEID` | `false` | yes | Send `<saml:EncryptedID>` in the LogoutRequests this service sends. |
| `saml2.autocreateApplications` | `STS_SAML2_AUTOCREATE_APPLICATIONS` | `true` | yes | Create an application entry for a new entityID on its first valid AuthnRequest or metadata request. |
| `saml2.requireSignedAuthnRequests` | `STS_SAML2_REQUIRE_SIGNED_AUTHN_REQUESTS` | `auto` | yes | Refuse unsigned requests: `auto` (on in product), `on` or `off`; also sets `WantAuthnRequestsSigned`. |
| `saml2.defaultSingleLogoutService` | `STS_SAML2_DEFAULT_SLO_SERVICE` | *(empty)* | yes | Where a LogoutResponse goes when the service provider registered no SingleLogoutService. |
| `saml2.requestTtlMin` | `STS_SAML2_REQUEST_TTL_MIN` | `10` | yes | How long an AuthnRequest is held while the person signs in. |
| `saml2.mockSpContextTtlMin` | `STS_SAML2_MOCK_SP_CONTEXT_TTL_MIN` | `30` | yes | How long the mock service provider remembers a RelayState it minted. |
| `saml2.redirectWarnLength` | `STS_SAML2_REDIRECT_WARN_LENGTH` | `8000` | yes | A Redirect-binding Response longer than this is logged at WARN (and still sent). |
| `saml2.spMetadataMaxBytes` | `STS_SAML2_SP_METADATA_MAX_BYTES` | `524288` | yes | The size cap on a fetched or uploaded service provider metadata document. |
| `saml2.spMetadataRefresh` | `STS_SAML2_SP_METADATA_REFRESH` | `true` | yes | Refetch stale service provider metadata in the background; expiry is enforced either way. |
| `saml2.spMetadataRefreshIntervalS` | `STS_SAML2_SP_METADATA_REFRESH_INTERVAL_S` | `300` | yes | How often the refresher looks, and how long a failed MDQ lookup is remembered. |
| `saml2.metadataTrustAnchors` | `STS_SAML2_METADATA_TRUST_ANCHORS` | *(empty)* | yes | Base64 DER certificates, comma-separated, that consumed metadata must be signed with. |
| `saml2.mdqBaseUrl` | `STS_SAML2_MDQ_BASE_URL` | *(empty)* | yes | The base URL of a Metadata Query Protocol responder. |

The per-application attributes are listed in
[the assertion settings](#the-assertion-settings-every-application-inherits).
Metadata fetches also obey the `federation.outbound*` settings. These tables
are a copy; the live source is the console pages (`/admin/saml2`,
`/admin/saml-assertions`) and `GET /admin-api/config`. See
[Configuration](configuration.md) for how a value is resolved; a setting is
changed on those pages or with `POST /admin-api/config/set`.

## Design decisions

* **SAML 2.0 and SAML 1.1 are separate implementations.** SAML 1.1 has no
  request message, no Single Logout and different artifact semantics, so a
  merged identity provider would branch in every function. They share the
  application registry, the session and the service provider slug.
* **No sign-in screen of its own.** A POST-binding request is held and turned
  into a GET so the `SameSite=Lax` session cookie is visible; the person meets
  the one sign-in screen, and single sign-on works across every protocol.
* **Metadata is per service provider and minted on request.** Each service
  provider gets its own identity provider entityID and endpoints, the way
  commercial identity providers do, and nothing has to be provisioned before a
  service provider can be pointed here.
* **A request's own certificate is never a trust anchor.** Verifying a
  signature against the key the message brought proves nothing; an observed
  certificate waits for an operator, the way an observed return address does.
* **Consuming metadata is an operator's act.** It dials only a URL an
  administrator wrote down or an MDQ responder they configured, and nothing
  issuing waits on somebody else's web server.
* **An artifact is one-shot, across the cluster.** Bindings section 3.6.4.1
  requires it, the happy path passes either way, and a race between two nodes
  would otherwise answer twice.
* **One trip to the sign-in screen per request.** `ForceAuthn`, an unmet
  `RequestedAuthnContext` and a cancellation are answered with a status after
  one attempt rather than looping.
* **Encryption without a key is a mode.** Development sends plaintext and says
  so, because a mock that stops issuing is useless while it is being set up;
  product refuses, because plaintext is what encryption was asked to prevent.
* **Broken algorithms are offered on purpose.** `rsa-1_5`, CBC and `rsa-sha1`
  exist because deployed service providers demand them, and a client library is
  entitled to be tested against them. SHA-1 is refused when **verifying** unless
  `saml.allowSha1Signatures` is on.
* **A refusal about the return address is a page, not a Response.** Sending a
  failure Response to the address in question would be delivering to it anyway.
* **The clock skew moves `Conditions` only.** Backdating `IssueInstant` or
  `AuthnInstant` would misstate when the person authenticated.
* **Custom attributes are additive and multi-valued.** One element per value
  would make a relying party read the first and miss the rest.
* **PAOS is refused by name.** A service provider that asked for PAOS and got a
  form post would conclude PAOS worked.

## In the running service

* **Protocols → SAML → SAML 2.0 identity provider** (`/admin/saml2`): every
  service provider, its metadata URL, what it was sent and over which binding,
  its signature verification outcome, its registered and observed certificates
  with **Confirm** and **Discard**, its metadata state (fresh, stale, expired)
  with **Refresh**, **Upload** and **Import from MDQ**, and its logout address.
* **Protocols → SAML → SAML assertions** (`/admin/saml-assertions`) and
  **Custom SAML attributes** (`/admin/saml-attributes`), described above.
* `GET /admin-api/saml2` and `POST /admin-api/saml2/{action}` — `register`,
  `set-logout-service`, `remove-logout-service`, `set-signing-certificate`,
  `remove-signing-certificate`, `confirm-signing-certificate`,
  `discard-signing-certificate`, `set-metadata-signing-certificate`,
  `refresh-metadata`, `mdq-import`, `upload-metadata`.
* `GET /admin-api/saml-assertions` and `POST /admin-api/saml-assertions/set`;
  `GET /admin-api/saml-attributes` and `POST /admin-api/saml-attributes/{action}`.
  The full shape is in `/admin-api/openapi.json`.
* `GET /saml2` describes the profile and every request parameter as this realm
  treats it; `/admin/sts-metadata` lists every endpoint.
* Every checked request signature writes a `saml2.request.signature` audit row.
  Failures are recorded under `STS-SAML-NNNN` codes — see
  [Error codes](error-codes.md).

## Related

* [SAML 1.1 browser profiles](saml11.md)
* [WS-Federation](ws-federation.md) and [WS-Trust](ws-trust.md), which carry
  assertions from the same builders
* [SAML 2.0 assertions](saml-assertions.md) — RFC 7522 at the token endpoint, a
  different feature
* [Federation](federation.md) — this service as a SAML service provider of
  another identity provider
* [Authentication](authentication.md), [Sessions](sessions.md),
  [Signing out](signing-out.md)
* [Trust realms](trust-realms.md), [PKI](pki.md),
  [What is not checked](what-is-not-checked.md), [Configuration](configuration.md)
