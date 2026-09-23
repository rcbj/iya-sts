---
title: SAML 1.1 browser profiles
---

# SAML 1.1 browser profiles

iya-sts is a **SAML 1.1 identity provider**: the Browser/POST and
Browser/Artifact profiles of the OASIS SAML 1.1 profiles and bindings
specifications ([OASIS Security Services TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=security)),
the SOAP **SAML responder** behind the artifact profile — which is also an
**attribute authority** — and Shibboleth 1.x's request profile. Every trust
realm has its own identity provider, with its own providerID, signing key,
relying parties and metadata.

It is **not** the SAML 2.0 identity provider with the version turned down.
**SAML 1.1 has no request message**: there is no `<AuthnRequest>`, a flow begins
when a browser arrives carrying a `TARGET`, and almost everything that reads
oddly on this page follows from that. The SAML 2.0 profile is
[SAML 2.0 Web Browser SSO](saml2-sso.md).

## Features

### Endpoints

| Path | What it is |
|---|---|
| `GET\|POST /saml11/sso[/{rp}]` | the **inter-site transfer service** — SAML 1.1's name for the single sign-on service |
| `POST /saml11/responder[/{rp}]` | the **SAML responder**, SOAP over HTTP (bindings section 3.1) |
| `GET /saml11/metadata[/{rp}]` | signed metadata, one document per relying party |
| `GET\|POST /saml11/rp` | a **mock relying party** (not part of any specification) |
| `GET /saml11` | a page describing all of the above and every parameter this realm reads |

In a trust realm every path is under `/realm/{id}`. The full, current list is
at `/admin/sts-metadata`.

### Starting a flow

A browser arrives at `/saml11/sso` with:

| Parameter | What is done with it |
|---|---|
| `TARGET` | the resource the person wants; echoed back byte for byte — SAML 1.1's RelayState |
| `shire` | Shibboleth's name for the assertion consumer URL, the only thing in the protocol that carries one |
| `providerId` | who the assertion is **for** — its audience |
| `time` | read and logged, not enforced |
| `profile` | **non-spec**: `post` or `artifact` |
| `format` | **non-spec**: the NameIdentifier format to answer with |

**Shibboleth's request profile** (`shire`, `target`, `providerId`, `time`,
identified as `urn:mace:shibboleth:1.0:profiles:AuthnRequest`) is supported and
advertised in the metadata, although it is not a standard — it is what every
real SAML 1.1 service provider sends.

**The relying party cannot name itself in the protocol**, so the audience comes
from `providerId`, from the `{rp}` path segment of a scoped endpoint, or —
failing both — **is guessed from the origin of the `TARGET`**. The guess is
logged, and `/admin/saml11` marks an identifier that looks like a bare origin as
probably guessed. A relying party expecting `urn:example:app` and handed an
assertion for `https://app.example.com` refuses it with nothing saying why:
send `providerId`.

The person signs in at the same [authentication service](authentication.md)
every protocol here uses, so a session from OAuth, SAML 2.0 or WS-Federation is
reused. A flow is held for `saml11.requestTtlMin` while the person is at the
screen.

### Browser/POST and Browser/Artifact

Nothing in SAML 1.1 lets a relying party choose, so `saml11.defaultProfile`
decides, and the non-spec `profile` parameter (or an arriving `SAMLart`)
overrides it.

* **Browser/POST** (profiles section 4.2) puts the whole signed Response in a
  self-submitting form. The assertion is confirmed
  `urn:oasis:names:tc:SAML:1.0:cm:bearer` and carries a `DoNotCacheCondition`,
  because it passed through the browser.
* **Browser/Artifact** (section 4.1) sends a 42-byte artifact (type `0x0001`,
  with a SourceID that is the SHA-1 of the providerID) on a redirect, and the
  relying party fetches the assertion from the responder over SOAP — **the
  assertion never passes through the browser**. It is confirmed
  `urn:oasis:names:tc:SAML:1.0:cm:artifact`.

**The confirmation method is the profile.** It is the assertion's own statement
of how it reached the relying party, so the two are not interchangeable, and
the mock relying party checks it.

An artifact here stands for an **assertion**, not a message: the
`<samlp:Response>` around it is built at resolution time, so its `InResponseTo`
names the SOAP request and its `Recipient` names whoever asked.

### The SAML responder and attribute authority

`/saml11/responder` answers four request types:

| Request | Answer |
|---|---|
| `AssertionArtifact` | the assertion — **exactly once**, across every node of a cluster; a second attempt is refused with a status naming the reason. `saml11.artifactTtlS` only bounds how long an unresolved one lives |
| `AssertionIDReference` | an assertion this realm issued, from a cache of `saml11.assertionCacheMax`; not one-shot, since holding the reference means already holding the assertion |
| `AttributeQuery` | an assertion carrying the person's attributes and **no** `AuthenticationStatement` — **development mode only** |
| `AuthenticationQuery` | answered from a live, authenticated session for that name, with its real method and instant; with no such session, Success and no assertion — **development mode only** |

The fifth type, `AuthorizationDecisionQuery`, is refused by name: this service
makes no authorization decisions.

**Resolving an artifact asks who is calling.** The caller must be the relying
party the artifact was issued to (named by the responder path segment), and
where signed requests are required it must prove it — by signing the request,
or by presenting its registered certificate as the TLS client certificate. A
refused caller does not spend the artifact.

### The assertion

The assertion's `Issuer` is an **attribute**, its id is `AssertionID` (the
Response's is `ResponseID`), its status codes are QNames (`samlp:Success`), and
`ds:Signature` goes **last** in an assertion and **first** in a response. It
carries an `AuthenticationStatement` whose `AuthenticationMethod` says how the
session really authenticated — `am:password` for a password, `multipleauthn` for
two factors, `am:HardwareToken` for a security key alone, `urn:ietf:rfc:2246`
for a TLS client certificate, `urn:ietf:rfc:1510` for Kerberos, a federation
partner's own method where it gave one, and `am:unspecified` otherwise — an
audience restriction, and an attribute statement including any SAML 1.1
[custom SAML attributes](saml2-sso.md#custom-saml-attributes).

Both the assertion (`saml11.signAssertion`) and the Response
(`saml11.signResponse`) are signed by default. Browser/POST requires the
**Response** signature (oasis-sstc-saml-bindings-1.1 section 4.1.2.4) and lets
the assertions in it be signed; this service signs the assertion as well, so
one that leaves its Response — over the artifact channel, or by
`AssertionIDReference` — still carries a signature. **Turning either off is
development mode's alone** (#181): product signs both whatever the setting or
the relying party's override says, and refuses to turn either off. The algorithm and canonicalization are the shared
`saml.signatureAlgorithm` and `saml.canonicalizationAlgorithm`. Lifetime,
signing, NameID format and artifact lifetime are the SAML 1.1 half of the
[assertion settings every application inherits](saml2-sso.md#the-assertion-settings-every-application-inherits),
each overridable per relying party (`saml11AssertionLifetimeMin`,
`saml11SignAssertion`, `saml11SignResponse`, `saml11NameIdFormat`,
`saml11ArtifactTtlS`).

### Metadata

SAML 1.1 has no metadata specification, so `/saml11/metadata/{rp}` is a SAML
2.0 `<EntityDescriptor>` whose `protocolSupportEnumeration` is
`urn:oasis:names:tc:SAML:1.1:protocol` — what every SAML 1.1 relying party reads
today. It holds **two descriptors**: an `IDPSSODescriptor` for the browser
profiles and an `AttributeAuthorityDescriptor` for the responder, where a
Shibboleth service provider looks for its attribute authority.

As with SAML 2.0 it is **per relying party and, in development, minted for
anything asked for** — in product mode `/saml11/metadata/{rp}`,
`/saml11/sso/{rp}` and `/saml11/responder/{rp}` answer 404 for a name that is
not a registered SAML 1.1 relying party:
the providerID becomes `{providerID}:{slug}` and the endpoints sit under the
same segment (`saml11.perApplicationProviderId`). The slug is the same one the
SAML 2.0 profile uses for the same application. In development, a relying
party named for the first time — by a `TARGET`, a metadata request or an
artifact resolution — gets an application entry when
`saml11.autocreateApplications` is on; product mode creates nothing because
something named it.

### The mock relying party

`/saml11/rp` is the default assertion consumer and a test harness. It starts a
flow on either profile, accepts a Browser/POST response or an artifact (which it
resolves under the same one-shot rule, so reloading the result page shows the
second attempt refused), and verifies the Response check by check: SAML version,
status, `Recipient`, `InResponseTo`, both signatures, `AssertionID`, issuer,
audience, validity window, the confirmation method against the profile, the
`DoNotCacheCondition` against the profile, the authentication statement, the
subject and the attributes.

### Not implemented

* **Single Logout** — SAML 1.1 has none; it arrived with SAML 2.0. A signed-in
  relying party is still recorded, so `/admin/saml11` can show who holds an
  assertion nothing here can recall.
* `ForceAuthn`, `IsPassive` and `RequestedAuthnContext` — no spelling exists in
  the protocol.
* **An error response** — with no request there is nothing to answer, so a
  failure is a page.
* `AuthorizationDecisionQuery`, and assertion encryption (there is no request
  to carry a recipient certificate).

## Development and product mode

| | Development | Product |
|---|---|---|
| `shire` | used as it stands; with none, the mock relying party | must be a registered `samlAssertionConsumerService`, exact match, no mock fallback; an address development merely observed is refused until confirmed |
| `AttributeQuery`, `AuthenticationQuery` | answered, to anybody who can reach the port — logged as such | refused outright |
| Artifact resolver authentication | not required (follows `saml2.requireSignedAuthnRequests`) | required |
| Given name, surname, mail, display name | invented | read off the directory entry, or omitted |
| Empty `saml11.providerId` | replaced with `urn:sts:idp:saml11` | SSO and metadata refuse, naming the setting |

The query refusal in product is not a client-certificate gate on purpose:
there is no attribute release policy, so a gate would answer any holder of any
trusted certificate about anybody. The one-shot artifact, the resolver being
the right relying party, and the authentication statement reflecting a real
session hold in **both** modes. See [What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `saml11.providerId` | `STS_SAML11_PROVIDER_ID` | `urn:sts:idp:saml11` | yes | This identity provider's name: the assertion `Issuer`, the metadata `entityID`, and what every artifact's SourceID is a hash of. |
| `saml11.perApplicationProviderId` | `STS_SAML11_PER_APPLICATION_PROVIDER_ID` | `true` | yes | Give each relying party its own providerID, `{providerID}:{slug}`; this also changes every artifact's SourceID. |
| `saml11.assertionLifetimeMin` | `STS_SAML11_ASSERTION_LIFETIME_MIN` | `60` | yes | Assertion lifetime; per relying party with `saml11AssertionLifetimeMin`. |
| `saml11.signAssertion` | `STS_SAML11_SIGN_ASSERTION` | `true` | yes | Sign the assertion (required by Browser/POST); per relying party with `saml11SignAssertion`. Off is development mode only: product signs every assertion, and turning it off is refused, here and per relying party (#181). |
| `saml11.signResponse` | `STS_SAML11_SIGN_RESPONSE` | `true` | yes | Sign the Response; per relying party with `saml11SignResponse`. Off is development mode only: Browser/POST requires a signed Response, so product always signs it and refuses turning it off (#181). |
| `saml11.nameIdFormat` | `STS_SAML11_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | yes | The NameIdentifier format, unless the non-spec `format` overrides it; per relying party with `saml11NameIdFormat`. |
| `saml11.defaultProfile` | `STS_SAML11_DEFAULT_PROFILE` | `post` | yes | `post` or `artifact`, when the request does not say. |
| `saml11.artifactTtlS` | `STS_SAML11_ARTIFACT_TTL_S` | `300` | yes | How long an unresolved artifact lives (it is one-shot regardless); per relying party with `saml11ArtifactTtlS`. |
| `saml11.autocreateApplications` | `STS_SAML11_AUTOCREATE_APPLICATIONS` | `true` | yes | Create an application entry the first time a relying party is named. |
| `saml11.requestTtlMin` | `STS_SAML11_REQUEST_TTL_MIN` | `10` | yes | How long a flow is held while the person signs in. |
| `saml11.assertionCacheMax` | `STS_SAML11_ASSERTION_CACHE_MAX` | `500` | yes | Assertions kept per realm for `AssertionIDReference`, oldest out first. |

The shared `saml.*` settings — signature algorithm, canonicalization, SHA-1
verification, clock skew, the metadata organisation — are in the
[SAML 2.0 configuration table](saml2-sso.md#configuration); artifact resolver
authentication follows `saml2.requireSignedAuthnRequests`. This table is a copy;
the live source is `/admin/saml11` and `GET /admin-api/config`. See
[Configuration](configuration.md) for how a value is resolved; a setting is
changed on `/admin/saml11` or `/admin/saml-assertions`, or with
`POST /admin-api/config/set`.

## Design decisions

* **A separate implementation from SAML 2.0.** No request message, no Single
  Logout, a different artifact and a different set of spellings mean a merged
  identity provider would branch in every function. The two share the
  application registry, the session and the application slug.
* **A guessed audience is guessed out loud.** With no `Issuer` to read, falling
  back to the `TARGET`'s origin keeps a relying party working, and logging it
  and marking it on the console keeps the guess from being mistaken for a
  registration.
* **The confirmation method follows the profile.** An artifact-profile
  assertion confirmed as `bearer` would claim to have travelled through the
  browser; a relying party that does not check never notices, which is why the
  mock checks.
* **An artifact resolves into a Response built at that moment**, so
  `InResponseTo` and `Recipient` name the SOAP caller rather than the browser's
  destination.
* **The responder answers all four request types.** It has to exist for the
  artifact profile, and the attribute authority is the half of SAML 1.1 that
  Shibboleth deployments leaned on.
* **Queries sign nothing that did not happen.** An `AuthenticationQuery` about
  somebody with no session gets no assertion, and an `AttributeQuery` answer
  carries no invented `AuthenticationStatement`.
* **No release policy, so product refuses queries rather than gating them.**
* **The metadata is a SAML 2.0 document**, because that is what every SAML 1.1
  relying party consumes.
* **A separate providerID from the SAML 2.0 entityID.** A relying party that
  trusts this service for 1.1 and not for 2.0 is the ordinary case.
* **No POST-to-GET step.** A SAML 1.1 flow arrives as a top-level GET, which
  carries the `SameSite=Lax` session cookie, so there is nothing to hold.

## In the running service

* **Protocols → SAML → SAML 1.1 identity provider** (`/admin/saml11`): every
  relying party, its metadata URL, which profile it used and where the
  assertion went, and which identifiers look guessed.
* **SAML assertions** (`/admin/saml-assertions`) and **Custom SAML attributes**
  (`/admin/saml-attributes`) in the same group — see
  [SAML 2.0 Web Browser SSO](saml2-sso.md#the-assertion-settings-every-application-inherits).
* `GET /admin-api/saml11` and `POST /admin-api/saml11/register` (register a
  relying party by identifier); the full shape is in `/admin-api/openapi.json`.
* `GET /saml11` describes the profiles and every parameter as this realm treats
  them. Failures are recorded under `STS-SAML-NNNN` codes — see
  [Error codes](error-codes.md).

## Related

* [SAML 2.0 Web Browser SSO](saml2-sso.md), including the assertion settings
  and custom attributes shared with this profile
* [WS-Federation](ws-federation.md), whose default token is a SAML 1.1 assertion
  from the same builder
* [WS-Trust](ws-trust.md)
* [Authentication](authentication.md), [Sessions](sessions.md),
  [Signing out](signing-out.md)
* [Trust realms](trust-realms.md), [What is not checked](what-is-not-checked.md),
  [Configuration](configuration.md)
