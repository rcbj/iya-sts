---
title: OpenID4VP
---

# OpenID for Verifiable Presentations, wallet sign-in and DIDs

iya-sts is a **Verifier** for
[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html),
using DCQL queries. It verifies what a wallet presents, check by check, in all
three credential formats its [issuer](oid4vci.md) mints. Since 2026-09-17 a
verified presentation is also **a way to sign in**: *Sign in with a wallet* on
the sign-in screen, including through the
[W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/). The
issuer has a [DID](https://www.w3.org/TR/did-core/) of its own, published as a
`did:web` document and linked to its origin by a
[DIF Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/).
Every [trust realm](trust-realms.md) has its own Verifier, sign-in register,
DID and settings.

## Features

### Two Verifiers, one set of checks

There are two ways into the Verifier, and they differ in what a presentation
that verifies leads to.

* **The bar door** at `/oid4vp/verifier` is a mock relying party's web page. A
  presentation there is verified, the verdict is shown, and nobody is signed
  in, because nobody there asked to be. The holder is still recorded on
  `/admin/users`, as every accepted credential is.
* **The wallet sign-in** at `/authn/wallet` builds its request through the same
  Verifier and starts a session when the presentation passes its extra rules
  (see *Signing in with a wallet*).

The bar door's endpoints:

| Path | What it is |
|---|---|
| `GET /oid4vp/verifier` | the Verifier's page, where a presentation starts |
| `GET /oid4vp/start` | builds an Authorization Request and sends the browser to the wallet (same device) or draws a QR code (`mode=cross-device`) |
| `GET /oid4vp/request/{id}` | the signed Request Object, fetched by reference (`request_uri`) |
| `POST /oid4vp/response` | the Response URI (`response_mode` `direct_post`), where the `vp_token` arrives and is verified |
| `GET /oid4vp/result/{state}` | non-standard: the verdict, so a wallet page or a test can read it |
| `GET /oid4vp/done` | the Verifier's closing page |

A request **by value** uses the `redirect_uri:` client identifier prefix. A
request **by reference** uses the configured `oid4vp.clientId` and a Request
Object ([RFC 9101](https://www.rfc-editor.org/rfc/rfc9101)) signed with this
realm's key, whose certificate chain is named as
`oid4vp.requestObjectCertificateHeader` says. The `client_metadata` advertises
all three formats. The `dcql_query` states what this request wants.

### What the Verifier checks

For an **SD-JWT VC** (`dc+sd-jwt`, [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)
section 7.3 and OpenID4VP's Key Binding rules):

* the issuer-signed JWT verifies against the issuer's key, and its `typ` is an
  SD-JWT VC media type;
* every Disclosure presented hashes to a digest in `_sd`;
* the Key Binding JWT has `typ` `kb+jwt`, is not `alg: none`, and verifies
  against the `cnf` key **in the credential**;
* its `sd_hash` covers exactly the bytes presented;
* its `nonce` is this request's, its `aud` is this Verifier, and its `iat` is
  no older than `oid4vp.kbMaxAgeS`;
* the credential is inside its validity window, its `vct` is
  `oid4vp.expectedVct`, and every claim the query asked for is present. A claim
  asked for and not presented fails by name.

For **`jwt_vc_json`** the Verifiable Presentation JWT must be signed by the
credential's `cnf` key and carry this request's `nonce`, `aud`, and a fresh
`iat`. For **`ldp_vc`** the `bbs-2023` derived proof is verified against the
issuer's BBS key, and, where the query asks for holder binding, a W3C
`VerifiablePresentation` around it must carry a
Data Integrity proof (`challenge` = the nonce, `domain` = the audience) made by
the holder's `did:jwk`. Three cryptosuites are accepted for that proof:
`ecdsa-jcs-2019`, `eddsa-jcs-2022` and `mldsa44-jcs-2024`.

The Key Binding JWT accepts every asymmetric algorithm the issuer binds
credentials to. A holder may bind a credential to an ML-DSA-44 key, and this
realm may sign credentials with ML-DSA, SLH-DSA or a composite; the Verifier
checks all of them.

### Trusted issuers

By default the Verifier trusts **this realm's own issuer** alone. PEM
certificates in `oid4vp.trustedIssuerCertificates` add issuers whose SD-JWT VC
or `jwt_vc_json` signatures are accepted. A certificate is used as a key. No
chain is built, but the certificate's revocation is consulted when it verifies
a credential, under `pki.revocationCheck` (see [PKI](pki.md)).

### Status checks

For every presentation that otherwise verified, the Verifier reads the
credential's status (see [status lists](oid4vci.md#status-lists)):

* a credential **this realm** signed is looked up in the realm's own store;
* a credential a **trusted foreign issuer** signed has its status list fetched,
  verified against the same certificate that verified the credential, and
  cached for its `ttl`, bounded by `oid4vp.statusListMaxCacheS`.

A credential whose status is not VALID is refused. So is one whose status
cannot be established, because a list that cannot be fetched or verified means
no statement can be made (`STS-VC-0072`).

**A credential must name its status** (#165). `oid4vp.requireStatusReference`
says what a credential with no status reference means, and it is `all` by
default in both modes:

* `all` refuses any credential that names no status (`STS-VC-0088`) — a
  credential with no reference can never be shown to have been revoked;
* `own-only` accepts a **foreign** credential with no reference. **Warning:**
  a credential its issuer has taken back then goes on being accepted here;
* `off` also accepts this realm's own credential with no reference, and an
  `ldp_vc` that withheld its status. It is for development only: product mode
  refuses to set it (`STS-CORE-0103`) and reads a stored `off` as `all`.

A trusted issuer that publishes no status is exempted one at a time, by the
SHA-256 thumbprint of its certificate in `oid4vp.statusOptionalIssuers` (hex,
colon-hex as `openssl x509 -fingerprint -sha256` prints it, or base64url).
The exemption covers a missing reference only: a credential that does name a
status is still checked against it.

An `ldp_vc` is a bbs-2023 derived proof, which discloses only what the holder
chooses. The bar door's DCQL query therefore asks for `credentialStatus`, and
a presentation that does not disclose it is refused (`STS-VC-0089`): every
`ldp_vc` this realm issues carries it, so its absence means it was withheld. A
wallet sign-in asks for it too, and reads that credential's status from the
sign-in register whether or not it was disclosed.

### What the bar door asks for

What the bar door asks for, and in which format, is configuration, set on
`/admin/vc-verifier-config`. Two properties of it matter:

* It is **separate** from what the issuer mints (`/admin/vc`). Asking for a
  claim no credential here carries is how a wallet's *I cannot satisfy this
  request* path is reached. Asking for no claim at all is also a valid choice,
  and DCQL reads it as the whole credential.
* The claims a request asks for are **frozen onto that request** when it is
  built. A change made while a presentation is in flight does not change how
  that presentation is judged.

`oid4vp.claims` is the list the page starts with and the list its **Reset**
returns to. It is not the live list.

### Signing in with a wallet

The sign-in screen offers **Sign in with a wallet** to every request that
reaches it: an OAuth authorization request, a SAML `AuthnRequest`, a
`wsignin1.0`, the console, the portal. After the sign-in the waiting flow
continues. The door needs a pending sign-in; `/authn/wallet` reached with
nothing pending is refused (`STS-VC-0053`).

```
GET  /authn/wallet?authn={id}          Set-Cookie: sts_wallet_binding=…
  303 -> /authn/wallet/wait?…          the Digital Credentials API page
       browser: navigator.credentials.get({ digital: … })
POST /authn/wallet/dc-api              the answer, verified; session started
  303 -> the original request
```

**Whom it signs in.** Only a **credential this realm issued, recorded in the
issued-credentials register**, and only as **the directory entry it was issued
for**. The [issuer](oid4vci.md#the-issued-credentials-register) writes that
record when the access token verified, was not revoked, named an existing entry
and was granted for credential issuance. The credential's own `sub` is never
trusted to name somebody. In order, a sign-in needs:

1. the presentation verified, including a fresh holder proof for this nonce and
   audience;
2. this realm's key signed it, not a trusted foreign issuer
   (`STS-VC-0058`);
3. the register holds it (`STS-VC-0059`), with the same subject and holder key
   (`STS-VC-0066`);
4. the subject still names that entry (`STS-VC-0060`);
5. the account is not disabled, and the issuance policy allows the session.

A credential from another realm, a trusted partner, a foreign token, or a
deleted entry still verifies and signs nobody in. The page says why.

**Every format signs in**, each with its own proof of the holder key:

| Format | The holder proof |
|---|---|
| `dc+sd-jwt` | a Key Binding JWT: `nonce`, `aud`, `iat` within `oid4vp.kbMaxAgeS`, `sd_hash` |
| `jwt_vc_json` | a VP JWT signed by the credential's `cnf` key, with `nonce`, `aud` and `iat` |
| `ldp_vc` | a `VerifiablePresentation` with a Data Integrity proof by the `did:jwk` the credential names |

The DCQL query carries one credential query per format in
`oid4vp.signInFormats`, and a `credential_sets` entry that accepts any one. The
request is always signed and by reference.

**The Digital Credentials API is the way in.** The wait page asks the browser
for a credential with a signed `openid4vp-v1-signed` request (OpenID4VP
Appendix A) whose `expected_origins` names this service. A wallet refuses such
a request if it is handed over by a page on another origin. The answer comes
back through the page, encrypted by default (`dc_api.jwt`, ECDH-ES to a P-256
key made for this one sign-in; `oid4vp.signInDcApiResponseMode` can ask for
`dc_api` in the clear). For this path the audience is `origin:<origin>`, so a
presentation made for another path does not sign in here.
`/authn/wallet/dc-api` also requires the `Origin` header to be this service's
own (`STS-VC-0074`).

**The page has one script**, `/authn/wallet.js`, because no markup can make a
browser ask a wallet. The form has a real submit button. With the script
blocked, the answer is a page saying the API did not run, with a same-device
link.

**A plain QR code for a wallet on another device is off by default**
(`oid4vp.signInCrossDevice`). The QR code is the one path that can be relayed:
an attacker shows their own code to a victim, the victim scans it, and the
attacker's browser is signed in. Where it is turned on, the QR page has no
script and polls with a `<meta>` refresh every `oid4vp.signInPollS` seconds.

**The session goes to the browser that started it.** An `sts_wallet_binding`
cookie (HttpOnly, SameSite=Lax) is bound to the transaction and compared in
constant time (`STS-VC-0055`). A same-device wallet is also given a one-time
`response_code` (OpenID4VP section 8.2), which it must bring back
(`STS-VC-0065`). A transaction lives `oid4vp.signInTtlS` seconds and is
answered once and finished once, across the cluster.

### What the session says

* A presentation alone: `amr ["pop"]`, `acr "1"`. It proves possession of one
  key whose storage is unknown.
* Where the issuer verified a **key attestation** at issuance saying the key
  storage resists ISO 18045 Moderate attack potential, `hwk` is added. Where
  the user authentication guarding the key is attested too, `mfa` is added and
  `acr` is `"mfa"`. Only what the issuer recorded is believed, never what a
  presentation says about itself.
* **A wallet, then a second factor.** When the request, the realm
  (the authentication policy's `requireSecondFactor`) or the account demands two factors, the person is then
  asked for their authenticator app, their security key, or their password at
  `/authn/password-factor`. The session then says, for example,
  `amr ["pop","otp"]` and `acr "mfa"`.
* **A password, then a wallet.** Every second-factor screen links to *Use your
  wallet instead*. It accepts only a credential issued to the same person
  (`STS-VC-0084`).

See [Authentication](authentication.md) for the second factors.

### Disowning a credential

A credential stops signing anybody in after any of these:

* a **global** sign-out (`/logout`, `/admin/logout`, `/admin-api/logout`),
  which disowns every credential issued up to that moment;
* an administrator's revocation on `/admin/tokens`;
* a status that is not VALID, set on `/admin/vc-status` or by either of the
  above.

An ordinary sign-out of one application disowns nothing, and the person signs
back in with the wallet they hold. A credential minted on an access token that
had already been disowned is never put in the register.

### DID Core and domain linkage

| Path | What it is |
|---|---|
| `GET /.well-known/did.json` | the issuer's `did:web` document (DID Core 1.0) |
| `GET /did.json` | the same for a DID with a path, which is what a trust realm's DID is: `did:web:host%3A8081:realm:acme` resolves at `/realm/acme/did.json` |
| `GET /.well-known/did-configuration.json` | the DIF Well Known DID Configuration: a Domain Linkage Credential, in the JWT form, signed by the DID and naming this origin |
| `GET /did/generate?method=jwk\|web` | a test helper: a fresh `did:jwk` (or this realm's own `did:web`) and an SD-JWT VC signed under it |

The DID is derived from the address the service was reached at, and honours
`global.publicBaseUrl`. The document publishes the credential signing key and
every live generation of the BBS key. Both documents are served
`Cache-Control: no-store`, because in development the keys behind them are new
on every start. `did:key` is not generated here.

### Self-issued ID Tokens (SIOPv2)

This service is also a **relying party of a Self-Issued OpenID Provider**
(SIOPv2): a wallet answers with an ID Token it signs with its own key. It is
never the Self-Issued OP itself.

* **Signing in.** With `oid4vp.signInSelfIssued` on (off by default), the
  sign-in screen offers *Sign in with a self-issued ID*. It starts a signed
  request with `response_type=id_token` and `scope=openid`, carrying
  `subject_syntax_types_supported` (the JWK Thumbprint syntax, `did:jwk`,
  `did:key`, `did:web`) in `client_metadata`, answered by `direct_post` at
  `/oid4vp/response`. A QR code uses the `siopv2://` scheme.
* **Only an enrolled key signs anybody in, in both modes.** Nobody vouches
  for a self-issued key, so it signs in only the person who enrolled it:
  * **the person**, on `/portal/self-issued`, by answering a SIOPv2 request
    from the session they already hold — the key is proved, never typed;
  * **an administrator**, on the person's page under Directory → Users, or
    with `POST /admin-api/users/enrol-self-issued-subject` (and
    `remove-self-issued-subject`, `GET /admin-api/users/self-issued-subjects`).

  A subject belongs to one person per realm, and a person may hold ten.
* **What is checked** (SIOPv2 section 11.1): `iss` equals `sub`; a JWK
  Thumbprint subject is the thumbprint of `sub_jwk` (a private key there is
  refused); a DID subject's `kid` is one of its authentication methods; the
  signature (never `none`); `aud` is this Verifier's Client Identifier;
  `nonce`; `exp`; and `iat` no older than `oid4vp.siopIdTokenMaxAgeS`. A
  `did:web` is fetched only once it is enrolled, through the outbound policy
  every fetch here obeys.
* **With a presentation** (`response_type=vp_token id_token`), the ID Token
  must be signed by the presentation's holder key.
* **The bar door** takes `?response_type=id_token` (or `vp_token id_token`)
  and `?response_mode=form_post` on `/oid4vp/start`, to exercise a Self-Issued
  OP without signing anybody in.

Not offered: the `fragment` response mode (a Verifier chooses its response
mode, and reading a fragment would need a script on a page here), and dynamic
discovery of a Self-Issued OP's metadata — the static `siopv2:` configuration
is assumed.

### How a signed request names its Verifier

`oid4vp.clientIdPrefix` chooses the Client Identifier of a signed request
(OpenID4VP section 5.9). An unsigned request always uses `redirect_uri:`.

| Value | Client Identifier | How the wallet finds the key |
|---|---|---|
| `pre-registered` (default) | `oid4vp.clientId` | out of band |
| `decentralized_identifier` | `decentralized_identifier:` + the realm's `did:web` | the `kid` is a DID URL into the realm's DID document |
| `verifier_attestation` | `verifier_attestation:` + the attestation's `sub` | the Verifier Attestation JWT in the request's `jwt` header, whose `cnf` is the signing key. `oid4vp.verifierAttestation` holds one an attestation issuer signed; empty, this realm attests itself, which only a wallet that already trusts this realm accepts |
| `openid_federation` | `openid_federation:` + the realm's base URL | the realm's Entity Configuration at `/.well-known/openid-federation`, with the `authority_hints` in `oid4vp.federationAuthorityHints` |

### Not implemented

* The unsigned and multi-signed request forms of the Digital Credentials API
  (Appendix A.3.1, A.3.2.2), and `transaction_data`.
* A trusted issuer certificate with a post-quantum key, and an `ldp_vc` holder
  key of any post-quantum kind other than ML-DSA-44.

## Development and product mode

| | Development | Product |
|---|---|---|
| The `wallet` parameter on the bar door's start page | Any URL | Only `oid4vp.walletUrl` or one in `oid4vp.allowedWalletUrls`; anything else is an open redirect and refused |
| The password offered as a second factor after a wallet | Not checked, like every password in development | Verified |
| Which credentials can sign in | Only those in the register, so only ones issued on a token this realm verified | The same; and since `/issuer/offer` needs a sign-in in product, the token belongs to someone who already signed in |

The Verifier's checks, the sign-in rules, the browser binding and the status
check are the same in both modes. See
[What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oid4vp.clientId` | `OID4VP_CLIENT_ID` | `sts-verifier` | yes | The `client_id` the Verifier presents, and the `aud` a Key Binding JWT must name. |
| `oid4vp.walletUrl` | `OID4VP_WALLET_URL` | *(`oid4vci.walletUrl`)* | yes | Where the Verifier sends a holder to present; falls back to the OID4VCI wallet URL. |
| `oid4vp.walletPresentationPath` | `OID4VP_WALLET_PRESENTATION_PATH` | `/vc-presentation-1.html` | yes | The page under the wallet URL a presentation request is handed to. |
| `oid4vp.allowedWalletUrls` | `OID4VP_ALLOWED_WALLET_URLS` | *(empty)* | yes | In product mode, the other wallet URLs the start page's `wallet` parameter may name. |
| `oid4vp.requestObjectCertificateHeader` | `OID4VP_REQUEST_OBJECT_CERTIFICATE_HEADER` | `x5u` | yes | Whether the signed Request Object names its key's chain: `x5u`, `x5c`, `both` or `none`. |
| `oid4vp.kbMaxAgeS` | `OID4VP_KB_MAX_AGE_S` | `600` | yes | How old a Key Binding JWT's `iat` may be. |
| `oid4vp.claims` | `OID4VP_CLAIMS` | `given_name,family_name` | yes | The bar door's starting request, and what its Reset returns to. |
| `oid4vp.maxRequestedClaims` | `OID4VP_MAX_REQUESTED_CLAIMS` | `40` | yes | The most claims the Verifier request page lets a request name. |
| `oid4vp.expectedVct` | `OID4VP_EXPECTED_VCT` | `urn:idptools:sd-jwt-vc:identity` | yes | The `vct` required of a presented SD-JWT VC. |
| `oid4vp.trustedIssuerCertificates` | `OID4VP_TRUSTED_ISSUER_CERTIFICATES` | *(empty)* | yes | PEM certificates of other issuers whose signatures are accepted. |
| `oid4vp.presentationRequestTtlS` | `OID4VP_PRESENTATION_REQUEST_TTL_S` | `600` | yes | How long a presentation request waits for a wallet's response. |
| `oid4vp.maxTransactions` | `OID4VP_MAX_TRANSACTIONS` | `5000` | yes | How many waiting requests a realm keeps; past it the oldest is dropped. |
| `oid4vp.statusListMaxCacheS` | `OID4VP_STATUS_LIST_MAX_CACHE_S` | `3600` | yes | The longest a foreign issuer's status list is kept; `0` fetches every time. |
| `oid4vp.requireStatusReference` | `OID4VP_REQUIRE_STATUS_REFERENCE` | `all` | yes | Whether a presented credential must name its status: `all`, `own-only` (foreign credentials exempt — **warning:** one its issuer revoked is accepted), or `off` (development only). |
| `oid4vp.statusOptionalIssuers` | `OID4VP_STATUS_OPTIONAL_ISSUERS` | *(empty)* | yes | SHA-256 thumbprints of trusted issuer certificates whose credentials may name no status. **Warning:** such a credential can never be shown revoked. |
| `oid4vp.signIn` | `OID4VP_SIGN_IN` | `true` | yes | Offer *Sign in with a wallet* and answer `/authn/wallet`. |
| `oid4vp.signInTtlS` | `OID4VP_SIGN_IN_TTL_S` | `300` | yes | How long a wallet sign-in waits for the wallet and for the browser to collect the session. |
| `oid4vp.signInPollS` | `OID4VP_SIGN_IN_POLL_S` | `3` | yes | How often the QR-code page reloads itself. |
| `oid4vp.signInCrossDevice` | `OID4VP_SIGN_IN_CROSS_DEVICE` | `false` | yes | Offer a plain, relayable QR code for a wallet on another device. |
| `oid4vp.signInFormats` | `OID4VP_SIGN_IN_FORMATS` | `dc+sd-jwt,jwt_vc_json,ldp_vc` | yes | The formats a sign-in asks for, in order of preference. |
| `oid4vp.signInDcApiResponseMode` | `OID4VP_SIGN_IN_DC_API_RESPONSE_MODE` | `dc_api.jwt` | yes | Whether a Digital Credentials API answer is encrypted (`dc_api.jwt`) or in the clear (`dc_api`). |
| `oid4vp.signInSelfIssued` | `OID4VP_SIGN_IN_SELF_ISSUED` | `false` | yes | Offer *Sign in with a self-issued ID* (SIOPv2) and the enrolment on `/portal/self-issued`. |
| `oid4vp.siopIdTokenMaxAgeS` | `OID4VP_SIOP_ID_TOKEN_MAX_AGE_S` | `300` | yes | How old a self-issued ID Token's `iat` may be. |
| `oid4vp.clientIdPrefix` | `OID4VP_CLIENT_ID_PREFIX` | `pre-registered` | yes | How a signed request names this Verifier: `pre-registered`, `decentralized_identifier`, `verifier_attestation` or `openid_federation`. |
| `oid4vp.verifierAttestation` | `OID4VP_VERIFIER_ATTESTATION` | *(empty)* | yes | A Verifier Attestation JWT for the `verifier_attestation` prefix. **Warning:** empty, this realm attests itself. |
| `oid4vp.federationAuthorityHints` | `OID4VP_FEDERATION_AUTHORITY_HINTS` | *(empty)* | yes | The `authority_hints` of the realm's Entity Configuration. |
| `oid4vp.signInRegisterMaxEntries` | `OID4VP_SIGN_IN_REGISTER_MAX_ENTRIES` | `100000` | yes | Rows the sign-in register keeps per realm; past it the oldest is dropped, which fails closed. |

The DID documents' lifetimes and signing algorithm are `oid4vci.*` settings;
see [OpenID4VCI](oid4vci.md#configuration). See
[Configuration](configuration.md) for how a value is resolved. Every `oid4vp.*`
setting is on `/admin/oid4vp` in the realm it applies to, and can be changed
with `POST /admin-api/config/set`.

## Design decisions

* **The Verifier checks everything it can, in every mode.** A verifier that
  accepted anything would leave a wallet author nothing to test against. It
  also verifies from first principles and does not ask the issuer's code what
  it produced, so the two cannot share a mistake.
* **The bar door signs nobody in.** A session started because a bar door was
  shown a credential would be one nobody asked for. Recording the holder, which
  it does, is a different claim.
* **Whom a presentation signs in is decided by the issuance register, never by
  the credential.** In development the credential endpoint accepts tokens it
  did not issue, so a credential's `sub` could name anyone. Only this realm's
  record of a verified issuance can.
* **A credential issued on a disowned token gets no register row.** Otherwise
  whoever still held a signed-out person's access token could mint a credential
  and sign that person back in.
* **The wallet door needs a pending sign-in.** The transaction must be bound to
  something the browser started, so unlike SPNEGO it cannot be used on its own.
* **The Digital Credentials API is the default and the QR code is off.** A
  signed request with `expected_origins` lets the victim's wallet refuse a
  relayed request, and the answer arrives only in the page that asked. The
  plain QR code cannot prevent a relay, so it is off in both modes.
* **The audience on the Digital Credentials API path is the origin.**
  Appendix A.4 fixes it even for a signed request, so the holder proof is
  checked against `origin:<origin>` and not against the client identifier.
* **A wallet is one factor, unless an attestation says more.** `pop` is the
  honest RFC 8176 value for a key whose storage nobody here knows. `hwk` or
  `mfa` would claim something nobody checked, so they come only from a key
  attestation the issuer verified. A second factor can follow a wallet, and a
  wallet can be the second factor after a password.
* **`ldp_vc` needed a presentation around its proof.** A `bbs-2023` derived
  proof binds the nonce and nothing about who derived it, and anyone holding the
  base credential can derive one. The sign-in therefore requires a Data
  Integrity proof by the holder's `did:jwk`. The bar door still accepts a bare
  derived proof and says so in its query
  (`require_cryptographic_holder_binding: false`).
* **An unknown status is a refusal.** If a status list cannot be fetched or
  verified, the credential is refused rather than let through.
* **What the Verifier asks for is a separate setting from what the issuer
  mints.** Otherwise the "request cannot be satisfied" path could never be
  produced.
* **The domain linkage is served because `did:web` alone is circular.**
  Resolving `did:web:example.com` means fetching from `example.com`, so the DID
  document cannot vouch for the origin. The Domain Linkage Credential is signed
  by the DID's own key, so a verifier can check it independently.
* **Fetching a status list is one of the few outbound fetches, and it is
  bounded.** The address sits inside a credential whose signature verified
  against a certificate an administrator trusted, and this realm's own lists
  are never fetched.

## In the running service

* **Protocols → Verifiable Credentials → OpenID4VP** (`/admin/oid4vp`): the
  Verifier's settings — client identifier, wallet address, Key Binding age,
  default claims — and the wallet sign-in settings. API:
  `GET /admin-api/oid4vp-settings`.
* **Protocols → Verifiable Credentials → Verifier request**
  (`/admin/vc-verifier-config`): what the bar door asks for and in which format,
  as the `dcql_query` of the next Authorization Request, with each catalogue row
  showing whether the issuer mints that claim. API:
  `GET /admin-api/verifier-request` and
  `POST /admin-api/verifier-request/{select,add,remove,defaults,format}`.
* **Protocols → Verifiable Credentials → Credential status**
  (`/admin/vc-status`): suspend, reinstate or revoke a credential, which stops
  it signing in.
* **Sessions** (`/admin/sessions`): wallet sign-ins appear as any other
  session, and end through the same sign-out doors.
* **Users** (`/admin/users`): every holder whose presentation verified.
* `/admin/sts-metadata` lists every endpoint; see [Endpoints](endpoints.md).
  Failures are recorded under `STS-VC-NNNN` codes; see
  [Error codes](error-codes.md).

## Related

* [OpenID4VCI and status lists](oid4vci.md)
* [Authentication](authentication.md), for the sign-in screen and second
  factors
* [Sessions](sessions.md) and [Signing out](signing-out.md)
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md)
* [PKI](pki.md), for revocation of trusted issuer certificates
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
