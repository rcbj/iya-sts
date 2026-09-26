# saml/

The two assertion builders — and, since 2026-08-24, **a browser-facing identity
provider for each of them**.

| File | What it is |
|---|---|
| `saml2.ts` | A SAML 2.0 assertion: build, sign, encrypt, and the attribute statement. Registers nothing. |
| `saml11.ts` | The same for SAML 1.1, whose profile splits a claim URI into a namespace and a name. Registers nothing. |
| `saml2_sso.ts` | **The SAML 2.0 Web Browser SSO profile**: the Single Sign-On service over both request bindings, the Response over all three, the SOAP Artifact Resolution Service, Single Logout, identity-provider-initiated SSO and the SOAP attribute authority (#189), the per-service-provider metadata, and a mock service provider. **This one registers routes.** |
| `saml11_sso.ts` | **The SAML 1.1 browser profiles**: the inter-site transfer service, Browser/POST and Browser/Artifact, the SOAP SAML responder behind the second (which is also an attribute authority), the per-relying-party metadata, and a mock relying party. **This one registers routes.** |
| `sp_metadata.ts` | A service provider's metadata: parsing it (an EntitiesDescriptor aggregate included), fetching it — through `../federation/federation_http.ts`'s outbound policy, product-mode address check included — by an explicit refresh, the Metadata Query Protocol or the BACKGROUND REFRESHER, CONSUMING it (`consume()`, against the realm's trust anchors), and saying how current it is (`freshness()`: fresh, stale, expired). Registers nothing; the refresher is the scheduler job `saml2.sp-metadata-refresh` (#49), which `startRefresher()` registers. What a Metadata Query answer may REGISTER is decided by who started the lookup (#112). |
| `request_signature.ts` | **Whether a service provider's request is signed by that service provider** (2026-09-17, #37): the verification policy for an AuthnRequest, LogoutRequest or LogoutResponse on the Redirect, POST and POST-SimpleSign bindings, whether a signature may be absent, and who is calling a SOAP responder that hands out an artifact (`authenticateSoapCaller()`). Registers nothing. |
| `authn_context.ts` | **How a session authenticated, in both SAML vocabularies, once** (2026-09-12). Read by both SSO profiles, WS-Federation and WS-Trust. Registers nothing. |
| `document_settings.ts` | **The signature algorithm, the canonicalization and `<md:Organization>`** every signed document here asks the configuration for (2026-09-12). Registers nothing. |
| `return_address.ts` | **Where a response may be delivered**: anything in development, a registered address in product (2026-09-12). Shared with WS-Federation. Registers nothing. |
| `person_attributes.ts` | **The persona facts an assertion carries**, invented in development and read off the directory entry (or omitted) in product (2026-09-12). Registers nothing. |
| `listener_keys.ts` | **The certificate the back channel presents, as a metadata key** (#248): every leaf the main port presents — every live cluster node's — as a `use="signing"` KeyDescriptor for both profiles' metadata. Registers nothing; reaches `tls/tls_server.js` lazily. See *THE BACK CHANNEL'S TLS CERTIFICATE IS IN THE METADATA*, at the end. |

## THE TWO PROFILES ARE SEPARATE IMPLEMENTATIONS, NOT ONE WITH A VERSION FLAG

This is the first thing to know before reading either file, because everything
else follows from it and because "surely most of that is shared" is the change
somebody will propose. It was considered and it is wrong: **SAML 1.1 has no
request message at all.** There is no `<AuthnRequest>` — the browser profiles are
identity-provider-initiated, and a flow begins when a browser arrives carrying a
`TARGET`.

Six things follow, and each is a branch that would have had to exist in every
function of a merged implementation:

| | SAML 2.0 (`saml2_sso.ts`) | SAML 1.1 (`saml11_sso.ts`) |
|---|---|---|
| the relying party names itself | `<saml:Issuer>` on the request | it cannot — `providerId`, the path segment, or GUESSED from the TARGET's origin |
| a failure goes | to the service provider, as a Response with a status | to a PAGE — there is nothing to answer |
| Single Logout | both directions | **does not exist in the protocol** |
| `ForceAuthn`, `IsPassive`, `RequestedAuthnContext` | all three implemented | **no spelling in the protocol** |
| the artifact | 44 bytes, type 0x0004, stands for a MESSAGE | 42 bytes, type 0x0001, stands for an ASSERTION |
| the SOAP endpoint answers | ArtifactResolve | four request types, including an attribute authority |

And the spellings differ almost everywhere the two overlap: `AssertionID` not
`ID`, an `Issuer` ATTRIBUTE not an element, a status code that is a **QName**
(`samlp:Success`) not a URI, `AudienceRestrictionCondition` not
`AudienceRestriction`, and a signature that goes LAST in an assertion and FIRST
in a response.

What IS shared is shared deliberately and is exactly three things: the
application registry, the session, and `slugOf()` — which `saml11_sso.ts`
requires FROM `saml2_sso.ts` rather than reimplementing, because the slug is a
handle for an application and two spellings of it would make
`/saml2/metadata/app-1a2b3c` and `/saml11/metadata/app-9f8e7d` name one entry in
one directory.

## THE SENTENCE THIS FILE USED TO OPEN WITH IS GONE, AND THAT IS THE HEADLINE

It said **THERE IS NO SAML 2.0 WEB SSO PROFILE** — no SingleSignOnService, no
AuthnRequest, no Response — and that it was deliberate rather than an omission.
That was true for years and it is not true now. The same claim was asserted in
seven other places and every one of them was **qualified rather than deleted**,
because the reason each existed is still worth a reader's attention:

| Where | What it says now |
|---|---|
| `README.md` | the profile, its three bindings, and what is still absent |
| the root `CLAUDE.md` | the non-goals table row is gone; the require-order table has 10a |
| `../ws-federation/wsfed.ts` | its federation metadata still publishes no `IDPSSODescriptor`, which is now a fact about THAT document — the IDPSSODescriptor is at `/saml2/metadata` |
| `../sts_metadata.ts` | the `saml2` coverage note, and the protocol card that said NO ROUTE OF ITS OWN |
| `docs/` | the user-facing half |

If any of them still reads as though this service has no browser SAML profile,
that one is the bug. See `reversing-a-documented-non-goal` — the shape of this
change was mostly a prose sweep.

---

## What is still absent, and each is stated rather than left to be discovered

* ~~**No assertion is encrypted.**~~ **REVERSED 2026-08-27** — see *SAML 2.0
  encryption* below. The reason this said no was that there was no recipient
  certificate to encrypt to unless SP metadata was consumed; the answer was to
  consume it, in one direction and for one value, and to fall back to the
  signing certificate off a signed AuthnRequest when there is none.
* ~~**No AuthnRequest signature is verified.**~~ **REVERSED 2026-09-17 (#37)** —
  see *A SERVICE PROVIDER'S SIGNATURE, AND ITS METADATA* below. A present
  signature is verified against the service provider's REGISTERED certificate in
  every mode; the certificate off `ds:KeyInfo` is OBSERVED, never trusted.
* ~~**No SP metadata is consumed** beyond the encryption certificate an explicit
  refresh writes.~~ **REVERSED 2026-09-17 (#37)** — the same section. The
  SPSSODescriptor's endpoints, keys, NameIDFormats and the two flags are
  consumed by the refresh and by an upload, and used.
* ~~**No ECDSA request signature is verified**~~ **REVERSED 2026-09-17 (#37
  follow-up)** — every family `common/crypto.js` section 1a verifies, EC,
  EdDSA and the post-quantum ones included; see *THE #37 FOLLOW-UP* below.
* ~~**A consumed document's `validUntil` and `cacheDuration` are not
  ENFORCED**~~ **REVERSED 2026-09-17 (#37 follow-up)** — past the effective
  validUntil the service provider's requests are refused, and past the
  cacheDuration the background refresher fetches the document again.
* ~~**No POST-SimpleSign binding**~~ **REVERSED 2026-09-17 (#37 follow-up)** —
  accepted and sent, and published.
* **No service provider's metadata URL is dialled WHILE ISSUING** — a fetch is
  an operator's action, the background refresher's, or an MDQ lookup a request
  STARTS and never waits on, so no sign-in waits on somebody else's web
  server.
* ~~**No identity-provider-initiated SSO**~~ **REVERSED 2026-09-24 (#189)**:
  `/saml2/unsolicited[/{sp}]` sends an unsolicited Response — see *What four
  independent service providers found*, below. ~~**No Assertion Query and
  Request profile**~~ **its attribute query is answered since #189**, at
  `/saml2/aa`, under a release policy (same section).
* **No ECP profile and its PAOS binding, no Name Identifier Management, and no
  AuthnQuery or AuthzDecisionQuery.** PAOS is refused BY NAME rather than
  quietly answered over HTTP POST — a service provider that asked for PAOS and
  got a form post would conclude that PAOS worked.

**And what `saml11_sso.ts` does not do**, which is a shorter list because most
of what is missing there is missing from the PROTOCOL rather than from this
implementation:

* **No AuthorizationDecisionQuery**, the fifth SAML 1.1 request type. Refused by
  name at the responder: this service makes no authorization decisions, and
  answering one would be inventing a policy nothing here has.
* **No assertion is encrypted**, the same as 2.0 and for a stronger reason:
  there is no request to carry a recipient certificate in even in principle.
* **Nothing authenticates a caller at the responder**, which matters more than
  the equivalent sentence about `/saml2/ars`. An artifact is protected by its
  twenty random bytes and the one-shot rule, but **an AttributeQuery is protected
  by nothing at all** — in development mode anybody who can reach the port can ask
  for an assertion about anybody, by name. A real attribute authority uses mutual
  TLS and an attribute release policy. Every query is logged saying so. **Product
  mode refused both query types outright** from 2026-09-12 — not gated on a
  client certificate, because with no release policy a certificate gate answers
  any holder of any trusted certificate about anybody — **and since #189 it
  answers under the release policy that was missing**: a registered relying
  party, authenticated (a signed Request or its registered certificate at the
  TLS handshake), asking about a subject it holds a live session for from this
  service, by the NameIdentifier it was given (`STS-SAML-0039`, `0096`).
* **No Single Logout, and it is not a gap.** SAML 1.1 has none.
  `session.saml11RelyingParties` is still recorded, and nothing reads it — it is
  there so `/admin/saml11` can show which relying parties hold an assertion
  nothing here can recall.

---

## Six decisions in `saml2_sso.ts`, and the two most likely to be undone

The file's own header argues all six at length. Two of them are the ones somebody
will try to "fix":

**1. THERE IS NO SIGN-IN SCREEN IN THIS DIRECTORY, and that was once the
deliberate difference from `../ws-federation/wsfed.ts`.** That module had a
screen of its own because section 13.2.1 lets a WS-Federation sign-in request
arrive as a cross-site form POST, which `SameSite=Lax` keeps the session cookie
off — so it could not read the session it would need in order to skip the
screen. The HTTP POST binding has exactly the same problem and this profile
answers it differently: **hold the request and 303 to a GET on the same
endpoint**, which is a top-level GET navigation and therefore DOES carry a Lax
cookie. What follows is single sign-on with OAuth in one session, a WebAuthn
ceremony available at the screen, and one fewer place asking for a username.
**WS-Federation gave up its own screen for the same funnel on 2026-08-26**
(`wsfed.ts` says why), so the asymmetry is gone the right way round. Do not give
this profile a screen of its own.

**2. THE METADATA IS PER SERVICE PROVIDER AND, IN DEVELOPMENT, IS MINTED FOR
ANYTHING ASKED FOR.** `/saml2/metadata/{sp}` names an identity provider of its
own — `urn:sts:idp:{slug}` — with endpoints under that same segment, which is
what Okta and Ping do. In development it **404s for nothing**: an entityID
nobody registered is registered by the ask. **In product (#112) every `{sp}`
path of both profiles is a 404 for a name that is not a registered provider of
that profile** — see *AN UNREGISTERED SERVICE PROVIDER IN PRODUCT* at the end
of this file. `saml2.perApplicationEntityId` turns the separate entityID
off for a service provider library that keys its trust store off the entityID;
the ENDPOINTS stay per-application either way, because that is what makes the
documents worth having separately.

The slug is the entityID where it is safe in a URL path segment and
`app-<12 hex of its sha256>` where it is not — the same device
`../common/applications.js`'s `shortName()` uses on an RDN, with the same
consequence: **a slug is not reversible**, so resolving one means asking the
registry which application has it. That is a scan of a mock's in-memory
directory, and it is why `/admin/saml2` exists — nobody derives that digest by
hand.

**AND THE PARENT PROJECT'S LAUNCHERS COMPUTE THAT SEGMENT THEMSELVES, WITH
`sha256sum`.** The metadata URL carries the digest because the document is
published per service provider, and three shell scripts over there build it
rather than guessing it — so **a change to `slugOf()` breaks three files nothing
in this repository can see**, and it breaks them in the parent's suite rather
than here. That is the same standing obligation the root `CLAUDE.md`'s last
section describes for the Kerberos COPY set: this repository moves, and the
other one has to be moved with it in the same change. Nothing is provisioned for
the `sts` side of those jobs — any entityID is accepted, the metadata is minted
on the ask, and the application entry is created by the first valid AuthnRequest
— which is why there is no `configureX` step for it anywhere in those launchers,
and why the digest is the only thing they have to know.

The other four: any entityID is accepted — and, since 2026-09-17, a service
provider's signature IS verified (decision 3 was "nothing is verified" until
#37); the assertion is built by `saml2.ts` and not by that file; the Response is
signed as well as the assertion and both are settings; and an artifact is
one-shot.

### An artifact is one-shot ACROSS THE CLUSTER (2026-09-14, #46) — capability `saml.artifacts-once`

The one-shot rule was a `get` and a `delete` on `artifacts`, a
`realms.map({ persist })`: once in one process, and once PER NODE against one
store, because the delete reaches another node through the change log a moment
later. A service provider retrying its ArtifactResolve through a load balancer,
or anybody racing it with an artifact read out of a browser history, landed both
requests inside that moment on two nodes and got the assertion twice.

Both profiles now keep the map check first and unchanged, delete, and then SPEND
the artifact through `cluster/cluster_claims.js` (scopes `saml2.artifact` and
`saml11.artifact`) before answering. `resolveArtifact()` → `spendArtifact()` in
`saml2_sso.ts` and the artifact branch of `respond()` in `saml11_sso.ts`, both
now asynchronous at that point. What is decided, and why:

* **The claim lives for the artifact's remaining lifetime plus 60 s** of clock
  disagreement between nodes — as long as a node that has not caught up could
  still find it.
* **Nothing releases it.** The delete has already spent the artifact in this
  process whatever the answer, and a claim given back without the map restored
  would only license another node to resolve it.
* **A store that cannot be asked refuses** (fail closed) with `StatusCode
  Responder`, where a used artifact is `Requester` as before.
* Codes: `STS-SAML-0057` (2.0, resolved elsewhere), `0058` (1.1), `0059` (the
  store), `0060` (the answer failed after the spend) — renumbered from
  0055–0058 when feature/46 was rebased onto develop, which had taken 0055 and
  0056 for the ForceAuthn and RequestedAuthnContext refusals. The capability is provided
  from `saml2_sso.ts` for both profiles, because the row names it and
  `saml11_sso.ts` requires that module.

`tests/cluster_single_use_protocols.js` section 1 holds both profiles: a node
still holding a resolved artifact is refused, the same restore against an empty
claim store resolves (the control), a store that throws refuses, and two
concurrent resolutions answer once.

---

## `buildSamlAssertion()` GREW SEVEN OPTIONS AND IS STILL ONE BUILDER

The Web Browser SSO profile needs things WS-Trust and WS-Federation genuinely do
not: a NameID format and value, a bearer `SubjectConfirmationData` (section
4.1.4.2 makes it a MUST — a service provider that checks it, and most do, refuses
an assertion without one, and the refusal reads as a signature problem), a
session index, an authentication instant, an issuer, and the ability to return
unsigned.

They are **options rather than a second builder**, and the reason is the one this
directory always gave: one assertion writer means one place where the element
order, the namespace and the signature location are decided, and those are
exactly what a service provider's parser is strict about. It also means **the
custom SAML 2.0 attributes configured on `/admin/saml-attributes` reach an
assertion issued by this profile with no wiring at all** — the same
`stats.samlAttributes('saml2', …)` line that puts them in a WS-Trust or
WS-Federation assertion puts them in this one. A second builder would have
silently lost that, and nothing would have said so.

**`issuer` is the option most easily thought unnecessary.** It defaults to
`saml.issuer` and the two older callers want that. The Web SSO profile MUST
override it, because it publishes an entityID per service provider and a service
provider checks the assertion's `Issuer` against the entityID in the metadata it
was configured from. An assertion issued by a name that is not in that document
is refused, and the refusal reads as a trust-store problem.

---

## `buildSaml11Assertion()` GREW OPTIONS TOO, AND ONE OF THEM IS THE PROFILE

The same growth `buildSamlAssertion()` took, for the same stated reason — one
assertion writer means one place where the element order, the attribute spelling
and the signature location are decided — and with the same payoff: **the custom
SAML 1.1 attributes configured on `/admin/saml-attributes` reach a browser-profile
assertion with no wiring at all.**

They are `issuer`, `nameIdFormat`, `nameIdValue`, `nameQualifier`,
`confirmationMethod`, `subjectLocality`, `doNotCache` and `sign`, and — since
2026-09-12, for the attribute authority — `authenticationStatement`. Every
default reproduces what WS-Trust and WS-Federation were already getting.

**`confirmationMethod` is the one that is not a preference.**
saml-profile-1.1 section 4.1.1.4 requires `urn:oasis:names:tc:SAML:1.0:cm:artifact`
for Browser/Artifact and 4.2.1.4 requires `...:cm:bearer` for Browser/POST. The
confirmation method is the assertion's own statement of HOW it reached the
relying party, so an artifact-profile assertion confirmed as `bearer` claims to
have travelled through the browser when it did not. A relying party that checks
refuses it; one that does not check works perfectly with either — which is why
this needed a decision rather than a line of code, and why the mock relying party
checks it.

---

## THE `Id="_0"` BUG THAT WAS THERE ALL ALONG, AND WHAT SURFACED IT

Worth reading before touching either signer, because the file said the opposite
in a comment for a long time and the comment was persuasive.

`signSaml11Assertion()` used to say that SIGNING does not care that SAML 1.1's id
attribute has an unusual name and that only verification does. That is true of
the DIGEST and false of the DOCUMENT. xml-crypto's `ensureHasId()` looks for the
first of `Id`, `ID`, `id` on the node being signed; finding none — and
`AssertionID` is none of them — it **invents `Id="_0"` and rewrites the reference
URI to match**. So every SAML 1.1 assertion this service ever issued carried an
attribute the schema does not have, and a signature reference naming it instead
of the AssertionID.

It verified anyway, which is why it survived: a verifier resolving `#_0` finds
the injected attribute. **The browser profiles broke it**, because a
Browser/POST response is TWO signed documents in one — the Response and the
assertion inside it — and both got `Id="_0"`. xml-crypto then refuses to verify
either, reporting *"multiple elements with the same value for the ID / Id / Id
attributes"*: its signature-wrapping guard, firing on a document this service
built itself.

The fix WAS one option in each signer — `idAttribute: 'AssertionID'` in
`saml11.ts`, `'ResponseID'` in `saml11_sso.ts`'s `signDocument()`. Then the real
attribute is found, nothing is injected, and the reference names the id a SAML
1.1 relying party expects. **WS-Federation's assertions changed as a result and
are more correct for it**; `/wsfed/rp` verifies them check by check and was used
to prove it.

**It was only safe because neither name was already on that default list.** The
opposite case was recorded in `saml2_sso.ts`: naming `ID` for SAML 2.0 unshifts a
DUPLICATE onto the list and trips the very same guard on a document that has
nothing wrong with it. Two spellings of one argument, each of which had to be
got exactly right in opposite directions at six call sites.

---

**ON 2026-08-27 THAT ARGUMENT STOPPED EXISTING, AND THAT — NOT THE LINE COUNT —
IS WHAT `common/crypto.js` BOUGHT.** Every signer and verifier here now goes
through one module over `common/vendored/xmldsig.js`, which resolves `ID`,
`AssertionID`, `ResponseID` and `RequestID` from the document itself. There is
no list to be told about, nothing is ever invented, and **there is no longer a
parameter to get wrong** — `signDocument()` in `saml11_sso.ts` and
`verifyAssertionSignature()` in `wsfed.ts` both lost theirs.

The story is kept rather than deleted because it is the best argument this
repository has for a single signer: a defect that produced a schema-invalid
attribute in every SAML 1.1 assertion for months, verified anyway, and then had
to be fixed six times. **Do not read the paragraphs above as instructions** — the
option they describe is gone. `tests/crypto_module.js` asserts that no document
this service signs carries an invented `Id="_0"`, and that its reference names
the element's real id, for all seven document shapes.

---

## SAML 2.0 ENCRYPTION: WHAT IS ENCRYPTED, WHOSE KEY, AND WHAT HAPPENS WITHOUT ONE

Added 2026-08-27, and it reverses the first line of *What is still absent*.

**WHAT CAN BE ENCRYPTED IS TWO THINGS, AND THE SECOND IS THE WHOLE OF "REQUEST
ENCRYPTION" IN THIS PROTOCOL.** There is no `EncryptedAuthnRequest` in SAML 2.0
— a request is SIGNED, not sealed — so the only encryptable thing in a request
is `<saml:EncryptedID>` where a `<saml:NameID>` would go, which saml-core-2.0-os
section 3.7.1 allows in a LogoutRequest. Both directions:

| | Outbound | Inbound |
|---|---|---|
| Response | `<saml:EncryptedAssertion>`, per application | as a federation SERVICE PROVIDER only (#168): `federation/CLAUDE.md`, *A PARTNER'S ENCRYPTED ASSERTION* |
| LogoutRequest | `<saml:EncryptedID>`, per application | `<saml:EncryptedID>`, **always** decrypted |

**THE INBOUND HALF HAS NO SETTING AND THAT IS DELIBERATE.** Every switch here
governs what this service SENDS, because a service provider may be unable to
read what we send. Nothing equivalent applies in the other direction: this
service publishes an encryption key in its metadata, and refusing to understand
a message somebody encrypted to that key would make the key a lie.

**SIGNED FIRST, THEN ENCRYPTED.** The signature lives inside the ciphertext, so
what a service provider verifies is what it decrypted. The other order produces
a document that verifies without anybody being able to say what was signed.

**THE CERTIFICATE COMES FROM FOUR PLACES, MOST SPECIFIC FIRST**:
`samlEncryptionCertificate` (which consuming the metadata writes, or a person
types), then a REGISTERED `samlSigningCertificate`, then — **in development mode
only since 2026-09-17** (`mode.encryptsToObservedCertificates()`) — the OBSERVED
`samlObservedSigningCertificate` off a signed AuthnRequest, so a service provider
that signs its requests needs no configuration there, then nothing. Until #37 the
third was the second: the request's own certificate was written straight onto
`samlSigningCertificate`, and product encrypted to a key anybody could have put
in a request.

**AND "NOTHING" IS THE CASE THE DESIGN TURNS ON, AND IT IS A MODE.** In
DEVELOPMENT, with encryption turned on and no certificate, the document goes out
IN CLEAR and is logged at WARN, every time, naming the application and what to
do — a mock that stopped issuing when a key was missing is useless exactly when
somebody is setting this up, and silently sending plaintext would be worse. In
PRODUCT (since 2026-09-12) it is REFUSED: a Response carrying Responder and no
assertion (`STS-SAML-0011`). **WHEN ENCRYPTION IS WANTED is the setting OR the
service provider** (#37 follow-up): consumed metadata that publishes a
`use="encryption"` KeyDescriptor sets `samlSpWantAssertionsEncrypted`, and the
assertion is encrypted to that key in both modes whatever
`saml2.encryptAssertion` says — SAML 2.0 metadata has no attribute for the
request, and the key is how the interoperability profiles read it.

### The algorithms are a choice, and one of them is broken on purpose

Four block ciphers (`aes256-gcm`, `aes128-gcm`, `aes256-cbc`, `aes128-cbc`) and
three key transports (`rsa-oaep-mgf1p`, `rsa-oaep`, `rsa-1_5`), service-wide
with per-application overrides. `rsa-oaep` (#168) is XML Encryption 1.1's with
SHA-256 and MGF1-SHA-256 — what a federation relationship of this service
publishes and requires — performed by node rather than forge, which has no
named-digest OAEP. **A service provider whose encryption certificate is EC is
encrypted to by ECDH-ES key agreement** (ConcatKDF, `kw-aes256`; XML Encryption
1.1 section 5.6.4) whatever the key transport says; until #168 that certificate
made the encryption throw and the assertion went out in clear
(`STS-SAML-0012`). The default key transport is still `rsa-oaep-mgf1p`, which
is what most deployed service providers read.

**`rsa-1_5` IS BLEICHENBACHER-BROKEN AND IS OFFERED ANYWAY — IN DEVELOPMENT
MODE**, because a great many deployed service providers accept nothing else and
a client library is entitled to be tested against the world as it is.
**Since #181 (2026-09-23) product never uses it**: the row carries
`onlyWhile: 'usesBrokenAlgorithms'` with `onlyWhileValues: ['rsa-1_5']`, so a
product realm refuses the write (`STS-CORE-0103`, and `STS-REG-0193` on an
application's `saml2KeyTransportAlgorithm`) and reads a stored one as
`rsa-oaep-mgf1p` — `applications.settingFor()` is the one funnel, so the
setting and the override are guarded in one place. The INBOUND half is
`common/crypto.js`'s: an `EncryptedID` whose key is wrapped `rsa-1_5` is
refused before any RSA operation (`STS-KEYS-0070`, recorded on the logout in
place of `0020`), because the unwrap is the oracle, and XML Encryption 1.1
section 6.1.3 adds that decrypting PKCS#1 v1.5 under a key that also signs —
this realm's XML key does both — lets signatures be forged.
`saml.signatureAlgorithm`'s `rsa-sha1` is held the same way
(`saml/document_settings.ts` reads it as in force).

**CBC IS UNAUTHENTICATED AND THAT IS NOT A DEFECT HERE.** It was MEASURED, not
assumed: flipping one character of a CBC cipher value produces a plaintext that
`finish()` accepts and that comes back TRUNCATED mid-tag, with no error
anywhere. GCM's tag catches the same edit. `decryptElement()` therefore parses
its output and refuses anything that is not well-formed XML — which is not
integrity, cannot be, and turns the ordinary corruption into one refusal with a
sentence instead of a crash two frames later.

### Two bugs this feature found in itself, both by decrypting its own output

**A DECRYPTED FRAGMENT HAS NO PARENT.** The first `<saml:EncryptedID>` this
service emitted wrapped a `<saml:NameID>` that relied on the LogoutRequest three
levels up for its `saml:` prefix. Once encrypted there is no LogoutRequest — the
service provider decrypts a standalone fragment — so it parsed as a
NamespaceError on the other side. What this service emits now declares its own
namespace, and `parsesAsFragment()` tries a wrapped parse before calling
somebody else's fragment corrupt, because their document is not ours to dictate.

**A CATCH THAT NAMED THE WRONG CAUSE.** That NamespaceError was reported as "the
wrapped key could not be unwrapped… fetch the metadata again", because one
`catch` covered the decryption and the parse and assumed every failure was the
key. It sends somebody to re-fetch a certificate over a bug in a parser three
lines away. The message is now chosen from the error.

---

## FOUR SETTINGS GROUPS, AND `saml.issuer` IS NOT ONE OF THE PROFILES'

The *SAML* group held TWO rows from 2026-08-27 — `saml.issuer` and
`saml.clockSkewS` — and five more since 2026-09-12: `saml.signatureAlgorithm`,
`saml.canonicalizationAlgorithm` and the three `saml.organization*` rows
(`document_settings.ts`). What they have in common is the entry test for that
group: each is read by what BOTH profiles sign and therefore reaches WS-Trust
or WS-Federation as well. See *The validity window* below for
`saml.clockSkewS`.

`saml.issuer` (group *SAML*) governs who SIGNED an assertion and is shared by
WS-Trust and WS-Federation. The `saml2.*` rows (group *SAML 2.0*) and the
`saml11.*` rows (group *SAML 1.1*) govern how this service behaves as an
identity provider in each browser profile. Folding any of them together would
make a change to one look like a change to the assertions WS-Trust hands out,
which it is not. `wsfed.entityId` is separate from all of them for the same
reason and always was.

**The two profile groups are separate from EACH OTHER for a reason of their
own**, and it is not symmetry: a relying party that trusts this service for SAML
1.1 and not for SAML 2.0 is the ordinary case rather than an exotic one, and one
`entityId` shared between them would make that unexpressible. It also has a
consequence worth knowing: `saml11.providerId` is what every type 0x0001
artifact's SourceID is a SHA-1 of, so changing it changes every artifact this
service mints.

---

## FOURTEEN OF THESE SETTINGS ARE PER APPLICATION, AND `settingFor()` IS THE ONLY PLACE THAT IS DECIDED

Since 2026-08-27 five settings in each profile, and the four SAML 2.0
encryption settings, are DEFAULTS rather than decisions. An application entry may carry its own answer, and where it does,
that answer wins for that application alone:

| Setting | Attribute on the application entry |
|---|---|
| `saml2.assertionLifetimeMin` | `saml2AssertionLifetimeMin` |
| `saml2.signAssertion` | `saml2SignAssertion` |
| `saml2.signResponse` | `saml2SignResponse` |
| `saml2.nameIdFormat` | `saml2NameIdFormat` |
| `saml2.artifactTtlS` | `saml2ArtifactTtlS` |
| `saml11.*` | `saml11*`, the same five |
| `saml2.encryptAssertion`, `saml2.encryptionAlgorithm`, `saml2.keyTransportAlgorithm`, `saml2.encryptLogoutNameId` | `saml2EncryptAssertion`, `saml2EncryptionAlgorithm`, `saml2KeyTransportAlgorithm`, `saml2EncryptLogoutNameId` |

`saml.clockSkewS` is NOT among them, and the section below says why.

**BOTH MODULES HAVE A LOCAL `settingFor()` AND NEITHER READS THESE SETTINGS ANY
OTHER WAY.** It delegates to `applications.settingFor(id, key, config)`, which
finds the attribute from the SCHEMA row's own `overrides` member, parses it with
`config.parseAs()` — the same type check the console form and the management API
run — and falls back to the setting when the entry says nothing. A
`config.value('saml2.signAssertion')` left anywhere in either file is a bug: it
is an application's setting read as though it were the service's.

**WHICH STRING IDENTIFIES THE APPLICATION IS THE THING TO GET RIGHT, AND IT IS
NOT THE OBVIOUS ONE.** It is the SERVICE PROVIDER's entityID (`spEntityId`, or
`rpId` in 1.1) and never `idpEntityId` / `providerId`. Those two are THIS
service's own name for that application and differ per application when
`saml2.perApplicationEntityId` is on — so passing one would have compiled, found
no entry, and silently used the service-wide default every time. Both
`buildResponse()` implementations take the service provider as its own member
(`opts.sp` / `opts.rp`) for exactly this reason, rather than reusing the issuer
that was already there.

**THREE FUNCTIONS HAD TO BE HANDED THE APPLICATION**, and that is the whole cost
of this feature in these two files: `buildResponse()`, `redirectUrlFor()` and
`stashArtifact()` were reached from paths that knew the service provider and
were not carrying it. `deliver()` already had `opts.spEntityId`, which is what
made the artifact and redirect cases cheap. A caller with nothing to pass passes
`''` and gets the service-wide value — which is what this service did everywhere
before this existed, and is what keeps an autocreated service provider working.

**AN UNPARSEABLE VALUE IS IGNORED AND LOGGED, NEVER REFUSED.** An `ldapmodify`
can put `"yes"` on `saml2SignAssertion`. The resolver warns — naming the entry,
the attribute and the reason — and uses the setting. This follows
`applications.js`'s own rule that the directory here is a VOCABULARY rather than
a constraint; an identity provider that stopped issuing because somebody typed
the wrong word would be a mock that stopped answering. It also means the write
is accepted at `POST /admin-api/applications/set` and only complained about when
it is read, which is deliberate and is the same bargain every other attribute in
that directory makes.

**SINGLE LOGOUT FOLLOWS THE ASSERTION.** `buildLogoutRequest()` and
`buildLogoutResponse()` take the service provider too, so a LogoutRequest for an
application whose assertions are unsigned is unsigned as well. One application,
one answer.

---

## THE VALIDITY WINDOW: TWO LIFETIMES, ONE SKEW, AND WHY THAT IS NOT AN INCONSISTENCY

`buildSamlAssertion()` and `buildSaml11Assertion()` each compute three instants,
and only one of them moved when `saml.clockSkewS` arrived on 2026-08-27:

```
IssueInstant  = now                          <- NOT moved
AuthnInstant  = the session's authTime        <- NOT moved
NotBefore     = now - saml.clockSkewS
NotOnOrAfter  = now + lifetime + saml.clockSkewS
```

**THE TWO THAT DID NOT MOVE ARE THE POINT.** `IssueInstant` and the
authentication instant state WHEN SOMETHING HAPPENED. Backdating those would be
a lie about an event rather than an allowance about a clock, and a relying party
that reads `AuthnInstant` to enforce a re-authentication age — WS-Federation's
`wfresh` does exactly that — would be told the person authenticated earlier than
they did. Only the `Conditions` move.

**So the window an assertion states is the lifetime plus TWICE the skew**, which
is why `/admin/saml-assertions` and `GET /admin-api/saml-assertions` both report
`saml2WindowS` and `saml11WindowS`: no single setting states the figure a
relying party actually experiences, and somebody setting a one-minute lifetime
with a five-minute skew to watch an assertion go stale would otherwise wait
eleven minutes and conclude the lifetime does not work.

**AT THE DEFAULT 0 THE DOCUMENTS ARE BYTE-FOR-BYTE WHAT THIS SERVICE ALWAYS
ISSUED**, `NotBefore` equal to `IssueInstant`. That is the contract to preserve
if either builder is touched.

**WHY ONE SKEW AND TWO LIFETIMES.** The lifetimes are per profile because 2.0
and 1.1 are consumed differently — the section above argues why the two groups
are separate at all — and a browser-profile assertion consumed in seconds wants
a different number from one a WS-Federation session is read under. The skew is
not about a profile: it is how far out the clocks in the estate this service
issues into are allowed to be, which a deployment decides once. Putting it in
the *SAML* group rather than in either profile's is that fact expressed in the
table.

**IT IS APPLIED IN THE BUILDERS, NOT AT THEIR CALLERS**, which is the same
choke-point argument `recordAssertion()` makes: WS-Trust, WS-Federation and both
browser profiles come through these two functions, so the setting reaches all
four without any of those modules knowing it exists. What the two WS-* modules
wrap an assertion in — `wsu:Lifetime` — still states the lifetime WITHOUT the
skew. That is deliberate and conservative: the envelope describes what was asked
for, the assertion states what it is actually valid for, and a relying party
trusting the envelope discards early rather than late.

**ONE CALLER HAD TO BE EDITED ANYWAY**, and it is the exception that proves the
choke point. `saml2_sso.ts` passes its own
`SubjectConfirmationData/NotOnOrAfter`, because the Web Browser SSO profile
requires the bearer confirmation to carry one; it now adds the same skew. Two
expiries inside one assertion that disagree is a defect a service provider
reports as *assertion expired* while this console shows a window that has not
closed. **A future caller that passes its own expiry has to do the same** — that
is the one thing about this feature that is not automatic.

**AND IT IS NOT `oauth2.clockSkewS`.** That one is a TOLERANCE applied wherever
this service READS a document back, including an inbound partner assertion at
`/federation/acs/{id}` — where `federation/federation_sp.ts` argues that a
reading tolerance is decided once and reuses it on purpose. `saml.clockSkewS` is
what this service WRITES into a document it issues. Merging them would take away
a deployment's ability to read strictly and issue forgivingly, which are
independent choices.

---

## A SAML ATTRIBUTE IS MULTI-VALUED and both builders say so

`values` is an array of `<AttributeValue>` children under one `<Attribute>`;
`value` is untouched and is what every existing caller passes. One element per
value with the same name is not a multi-valued attribute — it is a relying party
reading the first and silently seeing one where there are four. That is also why
the precedence rules in `../common/claim_attributes.ts` and
`../common/group_claims.ts` are written as a FILTER in these two builders rather
than as an assignment order: an assertion is a list of elements, so a duplicate
name is not an overwrite.

**WHAT EACH BUILDER PUTS IN IS CONFIGURED ON `/admin/saml-attributes`** — *Custom
SAML attributes*, under the console's SAML group; it was four sections of
`/admin/claims` before 2026-08-24. Neither file changed when it moved. Two things
about the context are worth knowing before writing prose about it anywhere: **it
is `{ subject, audience }`**, so a value carrying `${username}` reaches the
assertion as the characters it was written as — `${subject}` and `${audience}`
are the two that expand, and an unknown placeholder names itself (see
`expandValue()`) — and the RESERVED CLAIM NAMES enforced for a JWT set are **not**
enforced for these two, because `exp` collides with nothing in an assertion.

---

## The require order

`saml2.ts` and `saml11.ts` require only libraries — `../common/helpers`,
`../common/config`, `../common/crypto`, `../common/error_codes`,
`../common/admin_stats`, and this directory's `document_settings.ts` and
`authn_context.ts` — none of which requires them back, so they cannot join a
cycle and their position is not a position at all.

**`saml2_sso.ts` is position 10a in `common/protocol_stack.ts` (the require
order `server.js` loads) and has one real constraint**: it
must come after `../authn/authn.ts`, and it is a STRONGER dependency than
WS-Federation's rather than a weaker one — that module signs users into the
session `authn.js` owns, and this one has no sign-in screen at all and reaches
that service's through `beginAuthentication()`. It has no constraint against
`wsfed.ts` in either direction; the two share the session and know nothing about
each other. It sits between them and OID4VC so that the two browser SSO profiles
read together in the route order and on `/admin/sts-metadata`.

`../admin-ui/admin.ts` (and `../admin-core/`) require it in the ORDINARY
direction — a plain require, not another inverted slot — and rule 3e's test is
why: `common/protocol_stack.ts` requires this module at 10a and those at 18 or
later, so a require from there closes no cycle and moves no route.

**`saml11_sso.ts` is position 10b and has TWO constraints**, the second of which
is the only require between the two profiles. It must come after
`../authn/authn.ts`, for exactly the reason 10a must — no sign-in screen of its
own, and `beginAuthentication()` is how it reaches one. And **it must come after
`saml2_sso.ts`**, because it takes `slugOf()` from it: one application must have
one handle across both profiles, or the console shows one directory entry as two.
That require is in the ordinary direction, so it closes no cycle and moves no
route. Nothing else passes between the two modules.

**It needs no POST-to-GET dance, and that is worth knowing before somebody adds
one for symmetry.** Decision 2 of the 2.0 module is one of the most load-bearing
paragraphs in this directory: the HTTP POST binding delivers an AuthnRequest as a
CROSS-SITE form POST, which `SameSite=Lax` keeps the session cookie off, so that
module holds the request and 303s to a GET. A SAML 1.1 flow arrives as a
top-level GET navigation, which Lax does carry — so the session is visible on the
first request and there is nothing to stash. The POST route exists only because
somebody's relying party will post a form at it anyway.

---

## `/saml2/autopost.js` IS THE FIFTH SCRIPTED PAGE

`../common/app.js` sets `script-src 'none'` on every response. The HTTP POST
binding (bindings section 3.5) **is** a self-submitting form — that is what keeps
a response of several kilobytes of signed XML out of a URL, a log and a Referer
header — so there is no version of this binding without a script. The exception
is the same shape as the other four and no wider: `script-src 'self'` naming ONE
resource, never `'unsafe-inline'`, and the page carries a **real submit button**
because with scripting off the button is the whole mechanism. `form-action` stays
out of the policy, here as everywhere: the form posts to the assertion consumer
service, which is by definition another origin.

The root `CLAUDE.md` asks for that argument to be made again rather than by
analogy for each new scripted page. It is made in `saml2_sso.ts`, above
`AUTOPOST_SCRIPT`.

## `/saml11/autopost.js` IS THE SIXTH, AND THE ARGUMENT IS MADE A SIXTH TIME

This is the case where the rule earns its keep, because the fifth scripted page
is the one next door and "the same as that" is the most tempting and least useful
thing that could be said. It is made again in `saml11_sso.ts` and it stands on
its own: the **Browser/POST profile IS a self-submitting form in its own older
specification** — saml-bindings-1.1 section 4.1.2 describes the identity provider
returning a document containing a form whose action is the assertion consumer and
which submits itself. That is a separate specification that arrived at the same
shape independently, and it would still be here if SAML 2.0 had never been
written. Same exception, same width, same real submit button.

---

## SAML 1.1 has a test of its own; SAML 2.0 has only the browser pair

Hand-verified end to end on 2026-08-24 against a throwaway instance: 90 checks
over all three bindings, the SOAP back channel, the one-shot artifact rule, the
per-application metadata, the registry entry, the custom-attribute path, the
NameID formats, `ForceAuthn`, `IsPassive`/`NoPassive`, the PAOS refusal, Single
Logout and the mock service provider's own verification. The parent project's
`tests/saml_sso.js` and `tests/saml_logout.js` now take `SAML_IDP=sts` and drive
this profile with the same assertions they drive Keycloak with, which is the
arrangement `tests/wsfed_sso.js` already had — and the one that catches a mock
being quietly more permissive than the real thing.

**The request-signature and metadata negatives are covered in process** since
2026-09-17: `tests/saml_request_signatures.js` (see the section at the end of
this file). What is still missing for **2.0** is the other negatives that are
awkward from a browser: an artifact resolved twice, an artifact minted for one service provider
and resolved by another, a RelayState past 80 bytes, a Response over the Redirect
binding long enough to be truncated, and the `saml2.*` settings turned off one at
a time — especially `signAssertion`, since an unsigned assertion being ACCEPTED
by a service provider is the finding that matters and no happy path shows it.

**The parent project's `../id-proto-debugger/local-run-tests.sh --saml-only=sts`
IS THE FAST LOOP** (that launcher, not this repository's of the same name,
which was removed on 2026-09-16) and needs no Keycloak at all — four SAML 2.0 jobs and the SAML 1.1 one, against this service
alone.

**`tests/saml_encrypted_sso.js` IS DELIBERATELY NOT PAIRED**, and that is a
decision rather than a gap: that job's profile encrypts no assertion, so an
`sts` half of it could only ever fail or skip. Pairing a job with
`SAML_IDP=keycloak|sts` is worth doing when both identity providers can be held
to the SAME assertions; where they cannot, a skipping half is a job that reports
green having checked nothing.

**AND THE PAIRING HAS NO SAML 1.1 EQUIVALENT, WHICH IS WHY THAT TEST WRITES ITS
OWN RELYING PARTY.** Keycloak has spoken no SAML 1.1 for years, and **the
debugger has no SAML 1.1 service provider either** — `saml_tools.html` composes
and signs a 1.1 assertion, and the WS-Trust and WS-Federation response pages
consume one, but that project's SAML workflow is SAML 2.0 SP-initiated and
returns an XML comment where a 1.x request would be. So the relying party in
`tests/saml11_sso.js` is the only one there is.

**SAML 1.1 already has exactly that test and it is the model for this one.**
`tests/saml11_sso.js` in the parent project drives `/saml11` over HTTP with a
relying party it writes itself and no browser at all — 131 checks, mostly
negatives, the settings one at a time, the one-shot artifact rule, and the
confirmation method neither profile's happy path can show. It goes THERE rather
than here for the reason the root `CLAUDE.md`'s *Tests* section gives: a second
suite in this repository is a second runner, a second report and a second place
to forget. The 2.0 equivalent should be written the same way and in the same
directory, and it can borrow that file's whole harness.

---

## THE 2026-09-12 SWEEP FOR HARD-CODED VALUES, AND WHAT IT CHANGED HERE

An audit found development-mode behaviour written as literals with no mode
check, so product mode shipped it. Four new libraries in this directory carry
what was fixed, each a leaf that registers no route; `tests/saml_family_hardcoded.js`
pins all of it (ten mutants, all caught) and the rest of this section is the
record of the decisions.

### Fixed in EVERY mode, because each was wrong in every mode

* **THE AUTHENTICATION CONTEXT LIED.** Three copies — `saml2_sso.ts`,
  `saml11_sso.ts`, `wsfed.ts` — plus both builders' defaults called every
  session that was not two factors or a key alone a PASSWORD: a TLS client
  certificate (amr `swk`), a Kerberos ticket over SPNEGO, a federated sign-in and
  the unauthenticated session. `authn_context.ts` is the one reading now, in this
  directory rather than `common/` because both vocabularies are SAML's, and in
  this direction because `wsfed.ts` already required `saml/`. **An ordinary
  password sign-in, a key alone and two factors produce byte-for-byte what they
  did** — the contract the parent's paired SAML jobs rest on. The builders'
  defaults are `unspecified` now; every caller passes a class.
* **THE SAML 1.1 RESPONDER SIGNED SIGN-INS THAT NEVER HAPPENED.** An
  AuthenticationQuery about anybody answered `am:password` at the instant of the
  query; an AttributeQuery's assertion carried the same invented
  AuthenticationStatement. Now an AuthenticationQuery is answered from a live,
  authenticated session (`authn.sessionsOf()`) or with Success and NO assertion,
  and an AttributeQuery omits the AuthenticationStatement
  (`buildSaml11Assertion`'s new `authenticationStatement: false`). The vendored
  `tests/vendored/sts_saml11.js` asserted the old AuthenticationQuery answer
  about a person who never signed in; the parent has since updated it to ask
  about a user who really signed in.
* **NO SIGNER PASSED AN ALGORITHM.** `saml.signatureAlgorithm` and
  `saml.canonicalizationAlgorithm` reach all ten signers across `saml/`,
  `ws-federation/` and `federation/` through `document_settings.ts`, and the
  Redirect binding's `SigAlg` is read ONCE per message for both the parameter
  and the signature. Exclusive c14n only — the verifier here refuses inclusive
  c14n on a nested element, and every assertion is nested.
* **`sp_metadata.ts` HAD ITS OWN COPY OF THE OUTBOUND POLICY AND IT WAS WRONG**
  four ways: `federation.outbound` ignored, `outboundAllowInsecure` applied to the
  scheme but not the certificate, no User-Agent, and a `|| 5000` timeout fallback
  that disagreed with the setting's 15000. It asks `federation_http.ts` now —
  since #171 its `tlsFor()`, so the certificate is verified in product whatever
  `federation.outboundSkipTlsVerification` says, and a private CA is reached
  through `federation.outboundCaFile`.

### Product mode only, each behind the predicate that names the question

| What | Predicate | Development |
|---|---|---|
| ACS URL / `shire` must be a registered `samlAssertionConsumerService`, exact match, no mock fallback — and an address a development sighting wrote is still marked OBSERVED and does not count until confirmed (`applications.returnAddressesOf()`, `STS-REG-0049`) | `acceptsUnregisteredAddresses()` | unchanged, and the sighting is marked |
| An empty `saml2.entityId` / `saml11.providerId` is not replaced with `urn:sts:idp[:saml11]`; SSO and metadata refuse, naming the setting | `inventsClaimValues()` | unchanged |
| Given name, surname, mail, display name come off the directory entry or are omitted | `inventsClaimValues()` (via `userFor()` and `person_attributes.ts`) | unchanged |
| SAML 1.1 AttributeQuery / AuthenticationQuery refused | `opensTestControls()` | answered |
| SAML 2.0: an assertion configured to be encrypted that cannot be is a Responder status, not plaintext | `sendsWeakerThanAsked()` — it used `opensTestControls()` for an hour, for want of a predicate that named the question | plaintext + WARN |

**A refusal for an unregistered address is a PAGE and not a SAML Response**: the
address a Response would go to is the address in question.

### The literals that became settings (default = the old literal)

`saml2.requestTtlMin` (10), `saml2.mockSpContextTtlMin` (30),
`saml2.redirectWarnLength` (8000), `saml2.spMetadataMaxBytes` (524288),
`saml11.requestTtlMin` (10), `saml11.assertionCacheMax` (500),
`saml.organizationName` / `saml.organizationDisplayName` / `saml.organizationUrl`
— an emptied name OMITS `<md:Organization>` in either mode, because half an
Organization is schema-invalid and a setting silently ignored in one mode would
be a setting that lies on the console. The two "ten minutes" refusal pages are
built from the value.

## ONE TRIP TO THE SIGN-IN SCREEN PER REQUEST (2026-09-14)

**`ForceAuthn="true"` LOOPED FOR EVER, AND SO DID CANCEL.** `singleSignOn()` holds an
AuthnRequest while the person is at the sign-in screen, and the return address
(`?rid=`) reads the request again from its XML — so on the way back `ForceAuthn` was
exactly as true as on the way in, the session the person had just made changed nothing,
and they were sent to the screen again. A RequestedAuthnContext the sign-in could not
meet (a federated partner that authenticated with one factor) had the same shape. Cancel
looped for a different reason: `authn_error` was checked AFTER the session, and a person
who cancels has no session, so step 4 sent them back to the screen before the
cancellation was ever read. An in-process probe counted twelve redirects and still going
for both; the section above calling `ForceAuthn` hand-verified was true of the first leg
only.

**The fix is the RFC 9470 step-up shape** (`oauth-oidc/step_up.ts`'s `step_up_honoured`),
with the marker on the SERVER's copy of the request so a browser cannot claim the trip:

* the redirect to the screen stamps `forcedAt` on the held request;
* a request back from that trip is **never redirected again**. It is answered from a
  session authenticated at or after `forcedAt` (whole seconds, because `authTime` is one),
  and otherwise a Response goes to the service provider: **`NoAuthnContext`**
  (`STS-SAML-0056`) where the context is still unmet, **`AuthnFailed`**
  (`STS-SAML-0055`) where no fresh authentication happened or there is no session;
* **`authn_error` is read before step 4**, so a cancellation is reported as one
  (`STS-SAML-0009`, with the screen's own reason) — the rule above would also answer
  `AuthnFailed`, but as "came back with no session", which is a different fact.

`ForceAuthn` with an existing session still shows the screen, once; the re-authentication
keeps the session and moves `auth_time` (`authn/CLAUDE.md`), which is what the fresh
`AuthnInstant` in the Response comes from. `tests/saml2_force_authn.js` pins all of it
over HTTP; four mutants, all caught — the cancellation one only after the test asserted
HOW the cancellation was reported.

---

## A SERVICE PROVIDER'S SIGNATURE, AND ITS METADATA (2026-09-17, #37)

**THIS REVERSED A DOCUMENTED NON-GOAL**, and the root `CLAUDE.md`'s row *Verify
a SAML AuthnRequest's signature, or consume SP metadata — both recorded, neither
checked* is struck for it. rcbj's direction was that the list of things this
project does not do is being eliminated. `request_signature.ts` is the policy
and its header argues it; `sp_metadata.ts`'s `consume()` is the metadata half.
What follows is what a reader needs before changing either.

### The signature: verify when a certificate is known, in every mode

| A request that is… | Development | Product |
|---|---|---|
| signed, and verifies against a REGISTERED certificate | accepted, `verified` | accepted, `verified` |
| signed, and verifies against none of them | **refused**, `STS-SAML-0061` | **refused**, `STS-SAML-0061` |
| signed, and not checkable (an algorithm nothing verifies, wrapping, no octets) | **refused**, `STS-SAML-0062` | **refused**, `STS-SAML-0062` |
| signed with SHA-1, `saml.allowSha1Signatures` off (the default) | **refused**, `STS-SAML-0073` | **refused**, `STS-SAML-0073` |
| from a service provider whose consumed metadata has EXPIRED | **refused**, `STS-SAML-0074` | **refused**, `STS-SAML-0074` |
| signed, and nothing registered | accepted, `no-certificate` | **refused**, `STS-SAML-0063` |
| unsigned | accepted, `unsigned` | **refused**, `STS-SAML-0063` |

The last two rows are `saml2.requireSignedAuthnRequests` — `auto` (the default,
`mode.acceptsUnsignedSamlRequests()`), `on`, `off` — and a service provider whose
consumed metadata says `AuthnRequestsSigned="true"` is in the product column
whatever the setting says. **The same table governs a LogoutRequest and a
LogoutResponse from a service provider** (saml-profiles-2.0-os section 4.4.3.1),
and a refused LogoutRequest ends no session. A refusal is a PAGE (403), not a
Response: the AssertionConsumerServiceURL a Response would go to is part of what
the signature protected. **This was judged in scope rather than deferred**,
because "the service provider's signatures are checked" is not true while a
forged LogoutRequest can end somebody's session.

**Four things to keep, and each is the thing somebody will propose changing:**

* **The anchor is `samlSigningCertificate` and never the request's `ds:KeyInfo`.**
  `common/crypto.js`'s verifier falls back to the document's own certificate when
  it is given none, so every call here passes `certPem`. The one implicit anchor
  is this service's own certificate for its own mock service provider
  (`<base>/saml2/sp`), which signs its requests with this service's key — only
  this process can make such a signature, and the key changes on every
  development start, so it is not stored.
* **The Redirect binding's octets are the RAW query string**, read off
  `req.originalUrl` — section 3.4.4.1 signs the parameters as they arrived,
  URL-encoded, and a service provider that percent-encodes in lower case would
  otherwise fail every time. RelayState is in the octets when the parameter is
  present. The check runs ONCE, on the first arrival — the only moment the raw
  query exists — and its outcome rides on the held request (`pendingRequests`),
  which is the server's copy.
* **SHA-1 is a setting, `saml.allowSha1Signatures`, off in both modes, and ON
  is development's (#181)** — a product realm refuses SHA-1 whatever is
  stored. It is enforced in `common/crypto.js` rather than here, so this family and every
  other XML signature path give one answer; with it on, SHA-1 verifies and is
  marked `weak`. Every family that file verifies is accepted, with either
  canonicalization (`STS-SAML-0064`, which refused inclusive c14n, is retired:
  the signed element is the message root).
* **The outcome is recorded three ways**: `samlAuthnRequestVerification` on the
  entry (`<outcome> <binding> <SigAlg> [weak]`, AuthnRequests only), an audit
  row `saml2.request.signature` for EVERY checked message (with the code on a
  refusal), and the detail on the sign-in screen and `/admin/saml2`.

### The observed certificate, and the storage shape

`samlSigningCertificate` was single-valued and written from every signed
request's `ds:KeyInfo`. **It is multi-valued now and nothing a request carries is
written to it.** The certificate a request brings goes on
`samlObservedSigningCertificate` — ONE value, the last, so a stream of requests
carrying invented keys cannot grow the entry — and verifies nothing in either
mode. An operator CONFIRMS it (it moves onto `samlSigningCertificate` in one
save; an explicit add of the same value does the same) or DISCARDS it, on
`/admin/saml2` or `/admin-api/saml2/confirm-signing-certificate` and
`/discard-signing-certificate`. **This mirrors the observed return address**
(`appReturnAddressObserved`) and differs from it in one deliberate way: the
return-address mark sits on a value in the trusted attribute and development
believes it anyway, while an observed certificate lives in an attribute of its
own and development does NOT verify against it — a return address a mock
believes is a test case, and a signing key a mock believes is a forgery nobody
can see.

**What changed for encryption**: the observed certificate is still the
zero-configuration encryption fallback in DEVELOPMENT; product encrypts to it
only once it is confirmed (`mode.encryptsToObservedCertificates()`).


### Consuming the metadata, and why an operator's refresh is the trust act

`consume()` writes, in ONE save through `applications.replaceSamlMetadataFields()`
(whose attribute list is closed, because it writes derived attributes no door may
edit): the document, every AssertionConsumerService (`samlAcsEndpoint`, and its
location on `samlAssertionConsumerService`), every SingleLogoutService
(`samlSloEndpoint`, and `samlSingleLogoutService`), every signing certificate
(`use="signing"` or no `use`) as the REPLACEMENT registered set, the encryption
certificate, `samlSpNameIdFormat`, `samlSpAuthnRequestsSigned`,
`samlSpWantAssertionsSigned`, `samlSpMetadataValidUntil`,
`samlSpMetadataCacheDuration`, `samlSpMetadataConsumedAt` and
`samlSpMetadataSignature`. A later consumption retires the endpoint locations
the previous one wrote and leaves the ones an operator added by hand.

**It is a trust act because only an operator can cause it**: a refresh dials the
URL an administrator put on the entry (never one from a request), when an
administrator presses the button, through the federation outbound policy; an
upload is a document an administrator chose. That is what pasting a certificate
into the entry is, and what every identity provider's "import metadata" is. No
request reaches `consume()`, and nothing issuing dials anything.

**A metadata signature is verified only against a TRUST ANCHOR** — the entry's
`samlSpMetadataSigningCertificate` or the realm's `saml2.metadataTrustAnchors`
(a federation operator's keys, since the #37 follow-up) — and with any anchor
set, an unsigned document is refused too. Without one a signed document is
recorded `signed-not-verified`: verifying it against a key inside the same
document would be the decoration the request check refuses.

**Refused, writing nothing**: not an EntityDescriptor (or an
EntitiesDescriptor holding exactly one for this entity) with a SAML 2.0
SPSSODescriptor; an entityID that is not this application's (`STS-SAML-0066`); a
passed validUntil (`0068`); an unusable encryption certificate (`0053`, as
before); a metadata signature that does not verify (`0065`); an upload over
`saml2.spMetadataMaxBytes` (`0067`). **A document with no encryption certificate
is no longer refused** — it was, while the encryption certificate was the only
thing a refresh wrote — and it leaves `samlEncryptionCertificate` as it was; an UNQUALIFIED key that
is not RSA is a signing key and is simply not used for encryption.

### What the SSO and SLO services do with it

* **The assertion consumer service** (`registeredAcsFor()`): once metadata is
  consumed, an `AssertionConsumerServiceIndex` selects an endpoint and its
  binding (`0069` for an unknown one); an `AssertionConsumerServiceURL` must be
  a registered location **in every mode** (`0070`) — the operator registered the
  endpoints, so development's "anything goes" no longer applies to this service
  provider; neither selects the default (isDefault, else the first not marked
  false, else the first; `0072` when none is deliverable). The chosen address
  then passes `return_address.ts` like any other.
* **NameIDPolicy**: a Format the consumed metadata does not declare is a Response
  with `InvalidNameIDPolicy` (`0071`); `unspecified` always passes. With no
  Format asked for, the default comes from the declared list when the setting's
  value is not in it.
* **WantAssertionsSigned** signs the assertion even with `saml2.signAssertion`
  off — in product (`mode.sendsWeakerThanAsked()`); development honours the
  setting, which is the test case, and logs that the service provider asked.
  **Since #181 product signs EVERY assertion**, asked or not:
  `saml2.signAssertion`, `saml11.signAssertion` and `saml11.signResponse` off
  are development's (`mode.issuesUnsignedAssertions()`), read as ON through
  `applications.settingFor()` and refused on write. The decision is the
  profiles' text: saml-profiles-2.0-os 4.1.3.5 and 4.1.4.5 require the
  assertions in a POST-delivered Response to be signed (the errata let a
  Response signature stand in, and over Artifact they MAY be), and
  oasis-sstc-saml-bindings-1.1 4.1.2.4 requires the SAML 1.1 Browser/POST
  RESPONSE to be signed (its assertions MAY be). Signing the assertion in every
  binding satisfies both texts and protects one that leaves its Response;
  `saml2.signResponse` off stays allowed in product because the profile asks
  no more once the assertion is signed. `mode.js`'s predicate argues it.
* **WantAuthnRequestsSigned** in `/saml2/metadata[/{sp}]` is the table above's
  product column: true when the setting (or, per service provider, its metadata)
  requires signed requests.
* **Single Logout** answers at the consumed SingleLogoutService — its
  ResponseLocation for a response, on the arrival binding where published —
  before the declared one, the setting and the guess.

### The tests

`tests/saml_request_signatures.js`, in process — a Redirect signature verified
and recorded, RelayState and SigAlg tampering refused, a POST enveloped
signature verified, an altered request and a wrapping attempt refused, a
KeyInfo-only certificate observed and not trusted (and confirmable), the setting
in both modes and its product default, `WantAuthnRequestsSigned` following it,
metadata consumed into the entry with index, URL and default selection, the
NameIDPolicy refusal, and a LogoutRequest's signature. No parent-owned vendored
job signs an AuthnRequest or relies on the KeyInfo certificate:
`sts_saml_encryption.js` sets `samlEncryptionCertificate` directly and sends
unsigned requests, which development still accepts.

---

## THE #37 FOLLOW-UP (2026-09-17): EVERY ALGORITHM, SHA-1, METADATA OVER TIME, THE ARTIFACT'S CALLER, SIMPLESIGN

rcbj's review of #37 found three gaps — RSA-only verification, SHA-1 accepted,
and metadata expiry unenforced after consumption — and widened the change to
five more. What each is, and what to keep:

### Every signature family, and SHA-1 as a setting

`common/crypto.js` section 1a (argued in `common/CLAUDE.md`, rule 3r) verifies
RSA PKCS#1 v1.5 and PSS, ECDSA, EdDSA Ed25519/Ed448, DSA, ML-DSA and SLH-DSA
with node's OpenSSL, behind the vendored canonicalizer; this directory only
reads its answer. So a registered or consumed signing certificate may carry any
of those keys (`applications.samlCertificateProblem()` asks that file), and the
Redirect, POST and SimpleSign signatures, the metadata signature and the
ArtifactResolve signature all verify in every family. **The post-quantum
identifiers are a DRAFT's** (draft-eastlake-rfc9231bis-xmlsec-uris, as the
vendored registry names them); no W3C or IETF standard has any. **HSS/LMS, XMSS,
the MACs, MD5, Whirlpool, ESIGN and pre-hashed EdDSA are not verified** and are
refused as not checkable (`STS-SAML-0062`), each with its reason.

`saml.allowSha1Signatures` (off, both modes; on only in development, #181)
refuses a SHA-1 SignatureMethod or
DigestMethod before any cryptography — `STS-SAML-0073` here, `STS-KEYS-0062`
underneath — on every XML signature path in the service, because the rule is in
the one verifier. The setting is in the `SAML` group, so it is drawn on both
this directory's console pages.

### Metadata over time

`sp_metadata.ts`'s `freshness()` is the one reading: **expired** (the effective
validUntil — the earliest on every enclosing EntitiesDescriptor, the
EntityDescriptor and the SPSSODescriptor — has passed), **stale** (the
effective cacheDuration, the shortest in the chain, has elapsed since
consumption; with none, halfway to validUntil), or **fresh**.

* **Expired refuses, in every mode** (`STS-SAML-0074`): `saml2_sso.ts`'s
  `checkSignature()` asks first, so an AuthnRequest, a LogoutRequest, a
  LogoutResponse and an ArtifactResolve are all refused on a page (or a SOAP
  Requester status) that says the metadata expired. The console and
  `GET /admin-api/saml2?sp=` show `state`.
* **Stale is refreshed in the background** where it can be — a
  `samlSpMetadataUrl`, or an entry imported by MDQ — by the CLUSTER scheduler
  job `saml2.sp-metadata-refresh` (#49 P5; `cluster/CLAUDE.md`, *The
  scheduler*), every `saml2.spMetadataRefreshIntervalS` on the leader, switched
  by `saml2.spMetadataRefresh`. It was a timer `server.js`'s `announce()`
  started in every process until #49; `server.js` still calls
  `startRefresher()`, which now only registers the job. The `cluster_claims`
  claim keyed by realm, entity and the consumption it replaces stays, as the
  guard against a refresh asked for by hand at the same moment. **A failed refresh changes nothing**, so the old
  document works until it expires; the failure is a STATE
  (`refreshStatus()`, drawn on the page), logged on the change and summarised
  hourly (`STS-SAML-0076`) — never a line per attempt. An UPLOADED stale
  document is shown stale and keeps working.
* **Nothing is dialled while a request is answered.** A request from a
  service provider with no consumed metadata STARTS an MDQ lookup on the next
  turn of the event loop and is answered with what is known now; one lookup
  per entity at a time, and a failure is not retried inside the interval.

### Whose signature a metadata document may carry, and where it comes from

* **Realm trust anchors** (`saml2.metadataTrustAnchors`, per realm): with any
  set, every consumed document must verify against one of them or the entry's
  own `samlSpMetadataSigningCertificate` (`STS-SAML-0065`).
* **Aggregates**: an EntitiesDescriptor is read for the ONE entity the
  application is (refused when it holds none or several), verified by its own
  signature where it has one and otherwise by the entity's — never by
  whichever signed entity comes first.
* **MDQ** (draft-young-md-query and its SAML profile): `saml2.mdqBaseUrl`;
  `<base>/entities/<percent-encoded entityID>`; the `mdq-import` action on the
  console and `/admin-api/saml2/mdq-import` creates the entry only when the
  answer describes that entity, and removes it again if consuming fails; an
  entry with no URL refreshes from MDQ. **In product what an answer may
  REGISTER depends on who started the lookup** (#112) — see the last section.
* **The address rule now applies here too**: every fetch asks
  `federation_http.ts`'s `vetHost()`, so product mode refuses a host that
  resolves to an internal address (`STS-SAML-0079`) and pins the connection to
  the address it checked. The SP-metadata fetcher had never asked.

### The artifact's caller (SAML 2.0 and 1.1)

`/saml2/ars` and `/saml11/responder` hand an assertion to whoever presents the
artifact, and until the follow-up they asked nobody who that was — and SAML 2.0
logged, then ANSWERED, a resolver that was not the service provider the
artifact was minted for. Now, before the artifact is spent (a refused caller
leaves it resolvable by the right one):

* the resolver must be the artifact's party — the ArtifactResolve's Issuer,
  or for SAML 1.1 (whose Request names nobody) any responder path segment —
  in every mode (`STS-SAML-0078`);
* its metadata must not have expired (`STS-SAML-0074`, SAML 2.0);
* it must be AUTHENTICATED where signed requests are required
  (`saml2.requireSignedAuthnRequests`; product by default) — an enveloped
  signature on the message verifying against its registered certificates, or
  one of those certificates as the TLS client certificate (the handshake is the
  proof of possession, and metadata `use="signing"` keys are what SAML names
  for TLS client authentication, self-signed as a rule, so no chain is asked
  for; a revoked chain counts as none) — else `STS-SAML-0077`. A signature
  that is present and wrong is refused in every mode.

### HTTP-POST-SimpleSign

Accepted for AuthnRequest, LogoutRequest and LogoutResponse — detected by a
POST carrying `Signature` and `SigAlg`, verified over
`SAMLRequest=<value>[&RelayState=<value>]&SigAlg=<value>` built from the FORM
VALUES (form-decoded, not base64-decoded), a repeated control making it
uncheckable — and SENT when a request's ProtocolBinding or a consumed ACS
endpoint names it: the POST form, the Response's own enveloped signature taken
off, and `SigAlg`/`Signature` over the same octets where
`saml2.signResponse` holds. Published for SingleSignOnService and
SingleLogoutService in `/saml2/metadata`. The optional `KeyInfo` form field is
ignored: it is a key the message brought with it, which is exactly what this
service never trusts.

### The tests

Three in-process files, sharing `tests/tools/saml_signing_kit.js` (keys and
hand-built certificates in every family, a signer written independently of the
verifier's table, and the route plumbing):

* `tests/saml_signature_algorithms.js` — every family on POST and Redirect,
  single logout for a subset, metadata signatures, registration and
  consumption of the certificate; SHA-1 by method and by digest, refused then
  accepted-and-weak, in both modes; the other paths (federation ACS, RFC 7522
  with EC, Ed25519 and ML-DSA certificates this realm issued, and WS-Trust,
  WS-Federation, SAML 1.1 and GNAP for SHA-1 — those four verify against this
  service's own RSA key, so a non-RSA signature cannot be theirs to accept);
  and the refusals by name.
* `tests/saml_metadata_lifecycle.js` — expiry (SSO, SLO, product, the chain
  minimum, the view), the background refresh against a local HTTP server
  (success, failure recorded and harmless, the switch), uploaded stale
  documents, realm anchors and aggregates, MDQ (success, 404, the product
  address refusal, the lazy lookup and its deduplication), and encryption by
  mode and by metadata.
* `tests/saml_artifact_and_simplesign.js` — the artifact's caller on both
  profiles (unsigned, wrong key, SHA-1, wrong party, no Issuer, TLS mapped and
  not, expired, development and product defaults, not spent by a refusal) and
  SimpleSign both ways and in the metadata.

`tests/saml_request_signatures.js` changed where the behaviour did: an ECDSA
SigAlg swapped onto an RSA signature is now a WRONG signature (0061), RSA-MD5 is
the not-checkable case, SHA-1 is refused unless the setting is on, and an
inclusive-c14n signature verifies.

---

## AN UNREGISTERED SERVICE PROVIDER IN PRODUCT (2026-09-23, #112)

Two things answered for any name in product until #112: the per-provider
paths of both profiles, and an MDQ lookup an anonymous AuthnRequest started,
whose answer created the application entry signed or not. Two predicates,
because they answer different questions — one about CREATING something, one
about PUBLISHING something:

| Predicate | Development | Product |
|---|---|---|
| `registersFromMetadataQuery()` | an MDQ answer registers an unknown entity (held to `saml2.metadataTrustAnchors` only when set) | see below |
| `publishesMetadataForUnregisteredProviders()` | `/saml2/{metadata,sso,slo,ars}/{sp}` and `/saml11/{metadata,sso,responder}/{rp}` answer for any name | 404, text/plain, `no-store`, for a name that is not a registered provider OF THAT PROFILE (`STS-SAML-0082`, `0083`) |

**What an MDQ answer may do in product**, decided in `sp_metadata.ts`'s
`mdqImport()` by `options.origin` — `'request'` (the default, the stricter)
from `queueMdqLookup()`, `'operator'` from the console and the API:

* a REQUEST's lookup for an unknown entity with no realm anchor is **not
  made** (`STS-SAML-0080`) — an unverifiable answer could only be refused;
* with anchors, the answer is **verified against a realm anchor before the
  entry exists** (`STS-SAML-0081` otherwise) — create-then-delete would be a
  registration an anonymous request made, however briefly;
* an OPERATOR's import with no realm anchor is **refused** (`STS-SAML-0084`)
  unless `saml2.mdqImportWithoutAnchors` is on — the most-secure default rcbj's
  decision on #112 chose over the plan's "allow with a warning". With it on,
  the reply carries `warnings` and the log says so every time;
* an entry that EXISTS is refreshed from MDQ as before, in both modes.

The spec basis is thin and stated as such: draft-young-md-query-25 section
6.1 RECOMMENDS integrity checking and draft-young-md-query-saml-25 section 4.1
RECOMMENDS a signature embedded in the document; neither asks a requester to
trust an unsigned answer to a lookup nobody authenticated.

**The refused entityIDs are STATE, not log lines** (the standing rule against
a line per event, since the requests are anybody's): a bounded per-realm store
(`MDQ_REFUSALS_MAX`, the oldest dropped at the insert), one row per entityID
with a count, drawn on `/admin/saml2` (*Metadata Query lookups
refused*) and as `mdqRefused` / `mdqRefusedPaging` in `GET /admin-api/saml2`
(`mdqRefusedPage`). A realm is logged once when it starts refusing, an audit
row is written the first time an entityID is refused, and a summary is logged
at most hourly (on the next refusal, or from the refresher's sweep). **Unlike
the refresher's state the list is a persisted `realms.map()`
(`saml2.mdqRefusals`, 2026-09-23)**: a refusal is recorded by the request worker
that answered the AuthnRequest and read by whichever answers `GET
/admin-api/saml2`, and as a map per process it was empty on the others
(`sts_saml_unregistered`, single-node). The log-once and hourly-summary state
stays per process.

**"Registered" means a provider of that profile** — an entry of the kind, or
one declared for the family in `appAllowedProtocol` — not any application whose
slug matches: an OAuth client's name is not somebody this identity provider
has agreed to publish itself to, and a SAML 2.0 service provider is not a SAML
1.1 relying party.

**The parent project's paired SAML jobs** (decision 2 above) run against a
development service, where nothing changed. `tests/vendored/sts_saml11.js` (a
parent copy) asserts a document is minted for an identifier nobody registered;
in product that is now a 404, which is owed to the parent.

Tests: `tests/saml_metadata_lifecycle.js` section F (both modes, every
refusal, the positive product case against a realm anchor — its transport
stubbed, because product refuses the loopback responder before any
connection) and `tests/vendored/sts_saml_unregistered.js` over HTTP, in a
product realm and a development realm of one service, with an MDQ responder
the job serves itself.

## WHAT FOUR INDEPENDENT SERVICE PROVIDERS FOUND (#189–#192, 2026-09-24)

The Shibboleth SP 3, pysaml2, SimpleSAMLphp and Keycloak's SAML broker are
driven against this directory by four jobs (`tests/CLAUDE.md`, *The SAML
peers*), in a development and a product realm, with each peer's own log as
the error source. A round trip between two copies of this service's own
understanding could not have found any of this. Every fix is held in process
by `tests/saml_interop_findings.js` (the SimpleSign one by
`saml_artifact_and_simplesign.js`):

| Found by | What | Where it is fixed |
|---|---|---|
| Shibboleth | **HTTP-POST-SimpleSign signed the base64 text** where the binding (section 2.5) signs the RAW XML — in both directions, so it agreed only with itself and Shibboleth refused every SimpleSign Response | `request_signature.ts` `simpleSignOctets()`, `saml2_sso.ts` `simpleSignFields()` |
| Shibboleth | **SAML 1.1 metadata did not name `urn:mace:shibboleth:1.0`** in the IDPSSODescriptor's protocolSupportEnumeration, so no Shibboleth SP would start a SAML 1.1 sign-in from it | `saml11_sso.ts` (`PROTOCOL_SHIB1`) |
| Shibboleth | **Shibboleth's request profile spells `target` in lower case**; the Browser/POST form went without a TARGET, which Shibboleth refuses | `saml11_sso.ts` `interSiteTransfer()` |
| Shibboleth | **The SAML 1.1 profile ignored the shire**: an artifact consumer got a POST form. The shire's registered binding now chooses | `saml11_sso.ts` `profileFor()` |
| Shibboleth | **No attribute reached a stock attribute map**: SAML 2.0 sent Keycloak's and AD FS's names only, and SAML 1.1 split `urn:mace:dir:attribute-def:uid` into namespace and name. SAML 2.0 now also sends the X.500/LDAP attribute profile's `urn:oid:` names (with FriendlyName); SAML 1.1 sends the whole URN under `urn:mace:shibboleth:1.0:attributeNamespace:uri` | `saml2_sso.ts`, `saml2.ts`, `saml11_sso.ts` `attributesFor()` |
| Shibboleth | **`<DoNotCacheCondition/>`**, which the Browser/POST profile does not ask for (its single-use policy is the relying party's), is refused by Shibboleth's stock policy — a setting, `saml11.doNotCacheCondition`, **default OFF (decided 2026-09-26 on #189: spec first — the condition is optional and single use is the relying party's; a default kept only for a test is a shim)**. The parent-owned `sts_saml11.js` accepts its absence (rcbj/id-proto-debugger#307) | `saml11_sso.ts`, `common/config.js` |
| Shibboleth | **No identity-provider-initiated SSO** and **no SAML 2.0 attribute authority** — both now exist (below) | `saml2_sso.ts` |
| Shibboleth | **An attribute query answer must STRONGLY match the query's Subject** (saml-core 3.3.4), qualifiers included | `attributeQuery()` echoes NameQualifier and SPNameQualifier |
| pysaml2 | **An AuthnRequest addressed elsewhere, stale, of another Version, or REPLAYED was answered.** Now refused: `STS-SAML-0085` (and a SIGNED request with no Destination, bindings 3.4.5.2/3.5.5.2), `0086`, `0087`, `0088` — the issuer and ID claimed through the cluster's claim store for the freshness window (`saml2.requestTtlMin`), fail-closed `0089`. A LogoutRequest's envelope is held to the same rule | `saml2_sso.ts` `singleSignOn()`, `envelopeProblem()`; `cluster/cluster_claims.js` `claimInProcess()` |
| SimpleSAMLphp | **An HTTP-Artifact SingleSignOnService was advertised** that no request can arrive on; SimpleSAMLphp reads it literally and sent its AuthnRequest AS an artifact. It is no longer published | `saml2_sso.ts` `metadataFor()` |
| Keycloak | **A back-channel LogoutRequest ended nothing** and answered Success. It now ends the session its SessionIndex names when that session gave the service provider that NameID; otherwise UnknownPrincipal (`STS-SAML-0090`) and nothing ends | `saml2_sso.ts` `singleLogout()`, `sessionNamedBy()` |
| Keycloak | **Identity-provider-initiated LogoutRequests went over HTTP-Redirect with only an enveloped signature** — no SigAlg, no Signature. The Redirect binding now strips the XML signature and signs the query string (3.4.4.1), for every message it carries | `saml2_sso.ts` `redirectUrlFor()`, `logoutTargetsFor()` |
| Keycloak | **They also named the username in the configured format** whatever NameID the service provider had been given; the session now records each service provider's NameID | `issueSignInResponse()`, `logoutTargetsFor()` |
| (found while fixing the above) | **A LogoutResponse's second-level status (PartialLogout) was computed and never sent** | `buildLogoutResponse()` |

**IDENTITY-PROVIDER-INITIATED SSO** (`/saml2/unsolicited[/{sp}]`,
saml-profiles-2.0-os 4.1.5): `providerId` (or the path segment), `shire`,
`target` and `binding`, the Shibboleth identity provider's parameter names.
Held to what a solicited request is: a registered service provider in
product, an ACS its consumed metadata or entry registered, the endpoint's own
binding (never HTTP-Redirect), the issuance policy; `saml2.unsolicitedSso`
turns it off for a realm. The Response and assertion carry no InResponseTo.

**THE ATTRIBUTE AUTHORITY** (`/saml2/aa[/{sp}]`, an
AttributeAuthorityDescriptor in the per-SP metadata): the Assertion Query and
Request profile's AttributeQuery over SOAP. The release policy SAML 1.1 never
had: the caller authenticated as its Issuer (the artifact resolver's rule);
the subject one a LIVE SESSION here gave that service provider, by the NameID
it was given — which is also what makes a transient NameID answerable; the
issuance policy; and what that sign-in released, narrowed to what the query
names. No AuthnStatement, no SubjectConfirmation (`attributeQuery` in
`saml2.ts`). The SAML 1.1 responder's product policy is the same rule.

**Exceptions recorded on the tickets, not fixed here**: a SimpleSAMLphp SP
cannot use the artifact profile at all (it sends an artifact-ProtocolBinding
request over the artifact binding and publishes no ArtifactResolutionService
— #191); ECP is not claimed (#190). ~~SimpleSAMLphp's SOAP client pins the
back channel's TLS certificate to the metadata's signing keys, which this
service's listener certificate is not~~ — **decided and built on #248**: the
metadata carries it now (the next section), so that pin would pass; with the
artifact profile out of SimpleSAMLphp's reach there is still nothing of its
to exercise it with.

## EVERY DOCUMENT HERE IS VALIDATED AGAINST THE PUBLISHED SCHEMAS (#188, 2026-09-24)

`tests/vendored/sts_xml_schema_validation.js` makes both profiles emit
everything they emit — the metadata, the Response on each binding with and
without an EncryptedAssertion, the ArtifactResponse, the error Responses,
logout in both directions (with an EncryptedID), the mock service provider's
AuthnRequests, the SAML 1.1 Browser/POST Response and every answer of the
responder — in a development and a product realm, and validates each with
`xmllint` against the OASIS SAML 2.0 / 1.1 and W3C XML Signature and
Encryption schemas (`tests/CLAUDE.md`, *The published XML Schemas*). The
first run found nothing wrong in this directory. The one thing it found in a
SAML document was a schema's, not the document's: `cm:CryptoMetadataLocation`
in the metadata's `md:Extensions` (#42) was declared by no schema, and
`/crypto/metadata.xsd` declares it now. **A new SAML document owes a
scenario in that job.**

## THE BACK CHANNEL'S TLS CERTIFICATE IS IN THE METADATA (#248, 2026-09-26)

rcbj's decision on #189: **both identity providers' metadata publish the TLS
certificate the SOAP endpoints present** — the ArtifactResolutionService and
the AttributeService of SAML 2.0 (`/saml2/ars`, `/saml2/aa`) and the SAML 1.1
responder, which is both. A service provider that authenticates the
back-channel peer from metadata — the Shibboleth SP's ExplicitKey engine,
SimpleSAMLphp's SOAP client — then needs no key handed to it some other way.
`listener_keys.ts` is the rule and its header the argument; what a reader
needs before changing it:

* **`use="signing"`, in a KeyDescriptor of its own, LAST in the role.**
  saml-metadata-2.0-os 2.4.1.1 has two uses and "omitted" means both; a TLS
  key is not one anybody may encrypt to — nothing here decrypts with it — so
  omitting `use` would invite an EncryptedID under a key whose holder does not
  open XML Encryption. TLS server authentication is a signing use of a key and
  is where every metadata-reading TLS engine looks. Last, so a consumer that
  takes the first signing certificate for XML signatures still takes the XML
  key (`tests/vendored/sts_xml_schema_validation.js` is one such consumer).
* **In BOTH roles**: the IDPSSODescriptor (artifact resolution) and the
  AttributeAuthorityDescriptor (the attribute query), because a service
  provider looks up the keys of the role whose endpoint it is calling.
* **What the cost is**: a consumer that verifies XML signatures against every
  signing key will accept one made with the listener's key. That key is held by
  the process that holds the XML key — except a `tls.certificateFile` an
  operator supplied and shares with something in front of this service, which
  then holds a key this metadata vouches for.
* **Which certificates**: every leaf the main port presents
  (`tls.certificateAlgorithms` may name two, and OpenSSL picks per client), AS
  THE SOCKET PRESENTS THEM — `tls_server.presentedCertificatePems()`, which in
  a request worker answers the front process's leaves (the extra ones now
  travel with the hand-off and each re-issue's bundle) rather than the
  certificates that worker made for itself; and in a cluster every LIVE node's
  (`cluster/cluster.js` carries each node's on its membership row's `info`,
  read back at most a heartbeat behind), because each node presents a leaf of
  its own and a balancer sends a service provider to any of them. **None when
  the main port is plain HTTP** (`global.https` off).
* **It follows the certificate**: nothing is cached, every document asks at
  request time, so after `build-root` re-issues the listener (`tls/CLAUDE.md`)
  the next document names the new leaf. A service provider that cached the
  old document has to fetch it again — which `no-store` already tells it.
* **Nothing is refused**: a certificate that cannot be read is a document
  without that key, logged under `STS-SAML-0097`.

**What authenticates the back channel in each peer harness now**: Shibboleth
from the metadata ALONE — its StaticPKIX engine and the anchor the job handed
it are gone, the job checks the published key is the one the service
presents, and a development-realm control strips the key and sees the SP
refuse to resolve an artifact or run an attribute query. **pysaml2 and
Keycloak still get the anchor**, as documented exceptions: pysaml2 verifies
TLS with `requests` against `ca_certs`, Keycloak with its Java truststore, and
neither reads a metadata key for TLS. Held in process by
`tests/saml_listener_key.js`.
