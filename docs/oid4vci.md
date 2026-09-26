---
title: OpenID4VCI
---

# OpenID for Verifiable Credential Issuance

iya-sts is a **Credential Issuer** for
[OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
and its own authorization server is the one the issuer metadata names by
default. It mints three credential formats — SD-JWT VC
([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) and
[draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)),
`jwt_vc_json` and `ldp_vc` with `bbs-2023` — and publishes a status for every
credential it issues, in an IETF
[Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
and two W3C [Bitstring Status Lists](https://www.w3.org/TR/vc-bitstring-status-list/).
Every [trust realm](trust-realms.md) is an issuer of its own, with its own
metadata, keys, offers, status lists and settings.

The other half — asking a wallet to present a credential, and signing in with
one — is [OpenID4VP](oid4vp.md).

## Features

### The issuer metadata

`GET /.well-known/openid-credential-issuer` is the Credential Issuer Metadata.
It names the credential, nonce, deferred credential and notification
endpoints, the batch size, the request and response encryption parameters,
five credential configurations, and a `signed_metadata` JWT of the same
document. `GET /.well-known/jwt-vc-issuer` is the SD-JWT VC key-resolution
document (`issuer` and `jwks_uri`). Both also carry an `issuer_did` member,
which is an extension: see *The issuer named by a DID* below.

The `claims` each configuration advertises are built from the same selection
the credentials are built from (`/admin/vc`), so the metadata cannot describe a
credential this issuer no longer mints. As OpenID4VCI 1.0 section 12.2.4 has
it, a configuration's `display` and `claims` sit inside its
`credential_metadata` object, not at the top of the configuration.

A realm's issuer is `https://host/realm/<id>`, and its metadata is at the
path-inserted form section 12.2.2 gives,
`/.well-known/openid-credential-issuer/realm/<id>` (and likewise
`/.well-known/jwt-vc-issuer/realm/<id>`); the document at that path is the
realm's own, whose `credential_issuer` is exactly that identifier.

An issued credential's `nbf` is rounded down to the hour and its `exp` up to
the hour, so the credentials of one batch do not share a precise issuance
instant that would let verifiers link them (RFC 9901 section 10.1).

### Five credential configurations, three formats

| Configuration | Format | Scope | Holder binding |
|---|---|---|---|
| `IdentityCredential` | `dc+sd-jwt`, `vct` `urn:idptools:sd-jwt-vc:identity` | `identity_credential` | `jwk` |
| `IdentityCredentialJwtVcJson` | `jwt_vc_json` | `identity_credential_jwt` | `jwk` |
| `IdentityCredentialLdpVc` | `ldp_vc`, secured with `bbs-2023` | `identity_credential_ldp` | `did:jwk` |
| `IdentityCredentialDid` | `dc+sd-jwt`, issuer named by `did:web` | `identity_credential_did` | `jwk` |
| `IdentityCredentialLdpVcDid` | `ldp_vc`, issuer named by `did:web` | `identity_credential_ldp_did` | `did:jwk` |

The two `…Did` configurations are cloned from their plain siblings and differ
only in how the issuer names itself, so both routes can be compared against
one issuer.

`dc+sd-jwt` and `jwt_vc_json` credentials are signed with
`oid4vci.credentialSigningAlgorithm` (RS256 by default; ML-DSA, SLH-DSA and
the composites are allowed and are signed in the worker pool). `ldp_vc` is
signed with the realm's BBS key, which is published at `/bbs/keys/{kid}` and in
the DID document, and which rotates like any other signing key. A credential
names the certificate chain of its signing key in `x5u` or `x5c`, as
`oid4vci.credentialCertificateHeader` says. The `x5c` of a credential and of
a Status List Token stops short of the service Root, the trust anchor, which
HAIP 1.0 sections 6.1 and 6.1.1 forbid there; a HAIP deployment sets the
header to `x5c`, because HAIP's verifier holds only the anchor.

### What a credential says

A credential carries claims chosen from a catalogue of **LDAP attribute
types**, and each value is read from the person's own directory entry. What
`/admin/vc` selects applies to all five configurations. An `ldp_vc` credential
can carry only the terms its JSON-LD context defines, and the page names the
claims it cannot express.

A wallet may ask for a **subset** of the claims, in the `claims` member of an
`openid_credential` entry of `authorization_details` (section 5.1.1). The
selection travels inside the access token, so a wallet cannot widen it later.
A malformed `claims`, a claim described twice, or a path this issuer does not
advertise is refused with `invalid_authorization_details`. No `claims` member
means the whole configured set.

### Wallet-initiated and issuer-initiated issuance

* **Authorization code flow.** The wallet asks `/oauth2/authorize` for a
  configuration's scope or for `authorization_details` of type
  `openid_credential`. This is the flow described on
  [OAuth 2.0 and OpenID Connect](oauth-oidc.md).
* **Credential Offers** (section 4, Appendix H). `GET /issuer` is a mock
  issuer web page. `GET /issuer/offer` builds an offer and sends the browser to
  the wallet (`oid4vci.walletUrl` plus `oid4vci.walletIssuancePath`):
  * `mode=same-device` (the default, H.1): an `authorization_code` grant
    carrying an `issuer_state`, by value, or by reference with `by=reference`,
    served at `/oid4vci/credential-offer/{id}`;
  * `mode=cross-device` (H.2): a QR code and a **pre-authorized code** with a
    **Transaction Code** (`tx_code`) shown on the issuer's screen;
  * `mode=deferred` (H.3): the same, for a credential that takes time to
    produce.
* **Pre-authorized code grant.** The token endpoint redeems a pre-authorized
  code once. The Transaction Code has `oid4vci.txCodeLength` digits, drawn from
  a CSPRNG and compared in constant time. The token request may carry
  `authorization_details`, because the pre-authorized flow has no authorization
  request to send them in.

### The Credential Request

* `POST /oid4vci/nonce` hands out a `c_nonce`, valid `oid4vci.cNonceTtlS`.
* `POST /oid4vci/credential` takes the access token as a Bearer or DPoP token
  and a `credential_configuration_id` or a granted `credential_identifier`.
  A batch of up to `oid4vci.batchSize` proofs returns that many credentials.
  The errors are section 8.3.1.2's: `unknown_credential_configuration`,
  `unknown_credential_identifier`, `invalid_proof`, and `invalid_nonce` for a
  proof whose `c_nonce` this issuer does not hold (the wallet fetches a new
  one).
* **Proofs** (section 8.2.1, Appendix F): the `jwt` proof type
  (`openid4vci-proof+jwt`, every asymmetric algorithm this service signs with,
  post-quantum included) and the `attestation` proof type. A `c_nonce` is spent
  once across the whole cluster. A proof's `iat` must be within
  `oid4vci.proofIatWindowS` of now.
* **Key attestations** (Appendix D). An attestation in a `jwt` proof's
  `key_attestation` header, or as an `attestation` proof, is verified against
  `oid4vci.keyAttestationTrustedCertificates` and recorded.
  `oid4vci.keyAttestationRequired` requires one and says so in the metadata.
  What it attests decides what a wallet sign-in may later claim (see
  [OpenID4VP](oid4vp.md#what-the-session-says)).
* **Encryption.** A request may be a JWE to the realm's own RSA-OAEP-256 key
  (`credential_request_encryption`), and a wallet may ask for an encrypted
  response (`credential_response_encryption`): RSA-OAEP-256 to an RSA key,
  ECDH-ES to an EC key on P-256, P-384 or P-521 (#187). The `enc` values
  offered are A128GCM and A256GCM. Either direction can be made mandatory.
* **Deferred issuance.** A credential request on the access token from a
  deferred offer is answered with a `transaction_id` instead of a credential.
  `POST /oid4vci/deferred_credential` answers `issuance_pending` until
  `oid4vci.deferredReadyMs` have passed, with the `interval` set by
  `oid4vci.deferredIntervalS`.
* **Notifications.** `POST /oid4vci/notification` takes the wallet's
  `notification_id` events. `GET /oid4vci/notification/{id}` and
  `GET /oid4vci/last_request` are non-standard read-backs for tests: what the
  issuer was told, and how the last credential request arrived.

### Status lists

Every credential carries a status reference. The JOSE formats carry a Token
Status List claim (`status.status_list`), the W3C formats carry a Bitstring
Status List entry per purpose, and a `jwt_vc_json` credential carries both.

| Document | Path | Media type |
|---|---|---|
| Status List Token | `/oid4vci/status-lists/1` | `application/statuslist+jwt`, or `application/statuslist+cwt` (a COSE_Sign1) when `Accept` asks for it |
| Status List Aggregation | `/oid4vci/status-lists` | `application/json` |
| Bitstring Status List credentials | `/oid4vci/status-lists/bitstring/revocation` and `…/suspension` | `application/vc+jwt`, or JSON-LD with an `eddsa-rdfc-2022` proof when `Accept` asks for JSON-LD or JSON ([more](vc-api.md)) |

The Token Status List uses two bits per credential and carries `ttl` and `exp`.
Each Bitstring Status List has 131,072 entries, the specification's minimum.
Every credential gets **one index, the same in every list**. It is chosen at
random and freed when the credential expires.

A credential's status is VALID, INVALID or SUSPENDED. It is **computed** from
the credential's own status and from whether an administrator revoked it, so
every page that shows it agrees. Four things change it: a suspension,
reinstatement or revocation on `/admin/vc-status`, a revocation or restore on
`/admin/tokens`, a global sign-out, and a disabled account.

`oid4vci.statusListTtlS` is how long a verifier may keep a list (it is also the
HTTP `max-age`), and `oid4vci.statusListLifetimeS` how long the list says it is
valid. This realm's own [Verifier](oid4vp.md#status-checks) consults the lists
for every presentation — this realm's from its own store, a trusted foreign
issuer's by fetching it and verifying it against the certificate that verified
the credential — and refuses a credential whose status cannot be established.

### The issued-credentials register

When a credential is issued for a person, the realm records it in a register:
the subject, the holder key's thumbprint, the format and the expiry, never the
credential itself. A row is written only when the access token:

* verified against this realm's key and was not revoked,
* named a `urn:uuid:` subject whose directory entry exists, and
* was granted for credential issuance.

This register, and not the credential's own `sub`, is what decides whom a
presentation may [sign in](oid4vp.md#signing-in-with-a-wallet). A credential
issued on any other token is still issued, but it signs nobody in.

### The issuer named by a DID

Two configurations name the issuer by `did:web`. The DID document, the DIF
domain linkage and `/did/generate` are on the [OpenID4VP](oid4vp.md#did-core-and-domain-linkage)
page. `oid4vci.sdJwtIssuerDid` and `oid4vci.ldpVcIssuerDid` move the **plain**
configurations to the DID as well — what a deployment that had gone to DIDs
throughout would look like. Both are off: SD-JWT VC defines no DID-based
issuer key resolution, so for `dc+sd-jwt` the DID route is an extension, and
the specification's own route has to go on being exercised.

**The two formats stand differently.** `ldp_vc` is DID-native: VC Data Model
2.0 and Data Integrity assume a DID issuer. `dc+sd-jwt` is not:
draft-ietf-oauth-sd-jwt-vc says that "a DID-based mechanism is not explicitly
provided herein but still possible via profile/extension", and defines only
`/.well-known/jwt-vc-issuer` and inline x509. So for SD-JWT VC a DID issuer is
an **extension, and is labelled as one everywhere it appears**. The DID
identifies the **issuer only**: holder binding stays `cnf.jwk`, because a DID
there would be nobody's convention. (RFC 9101 is JWT-Secured Authorization
Request and has nothing to do with DIDs; it is used here only for OpenID4VP's
request by reference.)

One decision per configuration says which identifier its credentials carry, and
both the metadata and the credential read it, so they cannot disagree about
who issued a credential. The `…Did` configurations are cloned from their plain
siblings when the metadata is built, so a claim or proof type added to one
cannot go missing from the other.

**Three documents make the DID discoverable rather than merely asserted**, and
they answer different questions:

| Document | Member | Answers |
|---|---|---|
| `/.well-known/openid-credential-issuer` | `issuer_did`, and `issuer_identifier` per configuration | which DID this issuer answers to, and which identifier *this* configuration's credentials carry. Both are **extensions**; OpenID4VCI registers neither |
| `/.well-known/jwt-vc-issuer` | `issuer_did` beside `jwks_uri` | the same DID, named from SD-JWT VC's own key-resolution document. Its `issuer` **stays the https identifier**: a verifier inserts the well-known path into the credential's `iss` and requires this document's `issuer` to equal what it started from, and a DID cannot be the subject of that rule — which is exactly why the DID route is an extension |
| `/.well-known/did-configuration.json` | the DIF Well Known DID Configuration | why the DID should be believed to be the same entity as the origin. The only one of the three that is a real specification and is *checkable* |

The third is the point. For `did:web` the other two only look like an answer:
resolving `did:web:example.com` means fetching from `example.com`, so reading a
DID document off that origin to decide whether the DID belongs to it is
**circular**. The Domain Linkage Credential is not: the DID signs, with its own
key, a credential naming the origin, and a verifier resolves the DID
independently, checks the signature against the keys the DID authorises to
**assert**, and requires `credentialSubject.origin` to be the origin the
document came from. A verifier must also insist the linkage is for **the DID
it asked about**: an origin that links its own DID has not vouched for anybody
else's, and without that check "linked" would be a property of the file
existing rather than of what it says. (That consumer-side check is the parent
project's wallet's; this service publishes a document that survives it.)

**The Domain Linkage Credential is served in the JWT form**, not the Linked
Data Proof form (the specification allows either): it is signed with the same
key and algorithm as the credentials (`oid4vci.credentialSigningAlgorithm`) and
verifies against the same keys, where the LD form would need
JsonWebSignature2020 over URDNA2015 canonicalization for nothing more learned.
Two details of the JWT form are what a JWT library gets wrong *for* you, and
both produce a document that looks right: the header **must not** carry `typ`
(it carries only `alg` and a `kid` that is a DID URL, so no `x5c` or `x5u`
either), and the payload permits **no member beyond `iss`, `sub`, `nbf`, `exp`
and `vc`** — no `iat`. A verifier meeting an LD-proof entry should report it as
unverifiable, not invalid: it is somebody else's conforming document.

### Not implemented

* No historical status lists: `?time=` on the status list endpoint answers 501.
* A key attestation or trusted issuer **certificate** with a post-quantum key,
  because such certificates cannot be read here.

## Development and product mode

| | Development | Product |
|---|---|---|
| Access token at the credential, deferred and notification endpoints | Any token is accepted and its claims read unverified, because OpenID4VCI lets the authorization server be somebody else | A token that does not verify against this realm's key, or that this realm revoked, is refused `invalid_token` (401) |
| Claim values | What the entry lacks is invented from the username, deterministically, in fictional ranges | Nothing is invented; an attribute the entry does not hold is absent |
| `/issuer/offer` for a cross-device or deferred offer | Mints a pre-authorized code for `oid4vci.offerUsername`, for anybody | Mints for the **signed-in person** only; an unsigned-in browser goes through the sign-in screen. A same-device offer grants nothing and is not gated |
| Wrong Transaction Codes | Not counted | Counted across the cluster; the `oid4vci.txCodeMaxAttempts`th spends the code |
| The `wallet` query parameter | Any URL | Only `oid4vci.walletUrl` or one in `oid4vci.allowedWalletUrls`; anything else is an open redirect and refused |
| The credential signing keys | Regenerated on every start; nothing is rotated | Kept in the store and rotated on a schedule — the BBS key and a credential-only JWS key on `signing.credentialRotationIntervalDays` |

A credential issued in development on an unverified token cannot sign anybody
in, in either mode. See [What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oid4vci.walletUrl` | `OID4VCI_WALLET_URL` | `http://localhost:3000` | yes | Where the wallet lives, as a URL the browser can use; the offer pages send the End-User there. |
| `oid4vci.walletIssuancePath` | `OID4VCI_WALLET_ISSUANCE_PATH` | `/vc-issuance-1.html` | yes | The page under the wallet URL an offer is handed to. |
| `oid4vci.allowedWalletUrls` | `OID4VCI_ALLOWED_WALLET_URLS` | *(empty)* | yes | In product mode, the other wallet URLs the `wallet` parameter on `/issuer/offer` may name. |
| `oid4vci.authorizationServer` | `OID4VCI_AUTHORIZATION_SERVER` | *(empty)* | yes | A separate authorization server to advertise; empty means this service. |
| `oid4vci.offerUsername` | `OID4VCI_OFFER_USERNAME` | `diploma.student` | yes | Whose credential the issuer-initiated offer pages build (development). |
| `oid4vci.offerTtlS` | `OID4VCI_OFFER_TTL_S` | `600` | yes | How long an offer, its `issuer_state`, its pre-authorized code and a `notification_id` stay usable. |
| `oid4vci.txCodeLength` | `OID4VCI_TX_CODE_LENGTH` | `5` | yes | Digits in the Transaction Code. |
| `oid4vci.txCodeMaxAttempts` | `OID4VCI_TX_CODE_MAX_ATTEMPTS` | `5` | yes | In product mode, how many wrong Transaction Codes a pre-authorized code survives. |
| `oid4vci.batchSize` | `OID4VCI_BATCH_SIZE` | `4` | yes | How many proofs, and so credentials, one request may carry. |
| `oid4vci.deferredReadyMs` | `OID4VCI_DEFERRED_READY_MS` | `4000` | yes | How long a deferred credential stays `issuance_pending`. |
| `oid4vci.deferredIntervalS` | `OID4VCI_DEFERRED_INTERVAL_S` | `2` | yes | The `interval` a wallet is asked to wait between deferred polls. |
| `oid4vci.requestEncryptionRequired` | `OID4VCI_REQUEST_ENCRYPTION_REQUIRED` | `false` | yes | Refuse a credential request that is not a JWE. |
| `oid4vci.requestEncryptionKeyBits` | `OID4VCI_REQUEST_ENCRYPTION_KEY_BITS` | `2048` | yes | The RSA modulus of the realm's request-encryption key; reaches keys made after the change. |
| `oid4vci.requestEncryptionEncValues` | `OID4VCI_REQUEST_ENCRYPTION_ENC_VALUES` | `A128GCM,A256GCM` | yes | Content encryption algorithms offered for requests; only these two are implemented. |
| `oid4vci.responseEncryptionEncValues` | `OID4VCI_RESPONSE_ENCRYPTION_ENC_VALUES` | `A128GCM,A256GCM` | yes | Content encryption algorithms offered for responses. |
| `oid4vci.responseEncryptionRequired` | `OID4VCI_RESPONSE_ENCRYPTION_REQUIRED` | `false` | yes | Refuse a request that does not ask for an encrypted response. |
| `oid4vci.credentialLifetimeS` | `OID4VCI_CREDENTIAL_LIFETIME_S` | `2592000` | yes | How long every minted credential is valid (thirty days). |
| `oid4vci.credentialSigningAlgorithm` | `OID4VCI_CREDENTIAL_SIGNING_ALGORITHM` | `RS256` | yes | The JWS algorithm for `dc+sd-jwt` and `jwt_vc_json` credentials, the status lists, the Domain Linkage Credential and `/did/generate`. |
| `oid4vci.credentialCertificateHeader` | `OID4VCI_CREDENTIAL_CERTIFICATE_HEADER` | `x5u` | yes | Whether a credential names its signing key's chain: `x5u`, `x5c`, `both` or `none`. |
| `oid4vci.signedMetadataCertificateHeader` | `OID4VCI_SIGNED_METADATA_CERTIFICATE_HEADER` | `x5u` | yes | The same for the metadata's `signed_metadata`. |
| `oid4vci.proofIatWindowS` | `OID4VCI_PROOF_IAT_WINDOW_S` | `600` | yes | How far a proof's `iat` may be from now, either way. |
| `oid4vci.cNonceTtlS` | `OID4VCI_C_NONCE_TTL_S` | `300` | yes | How long a `c_nonce` may be quoted in a proof. |
| `oid4vci.cNonceCacheSize` | `OID4VCI_C_NONCE_CACHE_SIZE` | `10000` | yes | How many `c_nonce` values a realm holds; past it the oldest is dropped. |
| `oid4vci.keyAttestationRequired` | `OID4VCI_KEY_ATTESTATION_REQUIRED` | `false` | yes | Require a key attestation with every credential request, and advertise it. |
| `oid4vci.keyAttestationTrustedCertificates` | `OID4VCI_KEY_ATTESTATION_TRUSTED_CERTIFICATES` | *(empty)* | yes | PEM certificates of the Wallet Providers whose key attestations are believed; empty trusts none. |
| `oid4vci.statusListTtlS` | `OID4VCI_STATUS_LIST_TTL_S` | `300` | yes | The `ttl` (and HTTP `max-age`) of this realm's status lists. |
| `oid4vci.statusListLifetimeS` | `OID4VCI_STATUS_LIST_LIFETIME_S` | `86400` | yes | How long a status list token, or a Bitstring Status List credential, says it is valid. |
| `oid4vci.issuerDisplayName` | `OID4VCI_ISSUER_DISPLAY_NAME` | `IdP Tools Mock Credential Issuer` | yes | The metadata's `display.name`. |
| `oid4vci.domainLinkageLifetimeS` | `OID4VCI_DOMAIN_LINKAGE_LIFETIME_S` | `31536000` | yes | How long the Domain Linkage Credential says it is valid. |
| `oid4vci.generatedDidCredentialLifetimeS` | `OID4VCI_GENERATED_DID_CREDENTIAL_LIFETIME_S` | `3600` | yes | How long the SD-JWT VC `/did/generate` signs is valid. |
| `oid4vci.sdJwtIssuerDid` | `OID4VCI_SD_JWT_ISSUER_DID` | `false` | restart | Name the plain `dc+sd-jwt` configuration's issuer by `did:web`. |
| `oid4vci.ldpVcIssuerDid` | `OID4VCI_LDP_VC_ISSUER_DID` | `false` | restart | The same for the plain `ldp_vc` configuration. |
| `signing.credentialRotationIntervalDays` | `STS_SIGNING_CREDENTIAL_ROTATION_INTERVAL_DAYS` | `365` | yes | In product mode, how long the credential signing key works before its successor is promoted, when that key signs no tokens; `0` turns rotation off. |

See [Configuration](configuration.md) for how a value is resolved. Every
`oid4vci.*` setting is on `/admin/oid4vci` in the realm it applies to, and can
be changed with `POST /admin-api/config/set`.

## Design decisions

* **Values come from the directory entry, and in development what is missing is
  invented.** An issued credential is only as true as the entry behind it. In
  development the invented values are deterministic and obviously fictional
  (RFC 2606 mail domains, `555-01xx` numbers). Nothing in this service reads a
  credential claim back to decide anything.
* **The claim catalogue is attribute types, not claim names.** A claim's value
  is the value on the person's entry, so `/admin/vc` chooses attributes, and
  saving a selection also populates the directory. An LDAP client and a wallet
  therefore describe the same person.
* **The metadata and the credential are built from one selection.** An issuer
  that advertised five claims and minted fourteen would teach every wallet
  author that the metadata is not worth reading.
* **A requested subset is refused, not trimmed, when it is wrong.** A wallet
  whose selection was quietly dropped would get a credential with claims it did
  not ask for, or without ones it did, and nothing would say why.
* **Every single-use value is spent once across the cluster.** The
  pre-authorized code, each `c_nonce`, and every wrong Transaction Code are
  claimed in the shared store. A store that cannot be asked refuses the request
  (`STS-VC-0051`) rather than risk a second use.
* **In product the Transaction Code has a budget.** Five digits could otherwise
  be guessed at the token endpoint within the offer's lifetime, so the last
  allowed wrong code spends the pre-authorized code.
* **An offer that authorizes something is gated in product.** A cross-device
  or deferred offer carries a pre-authorized code, which is an authorization.
  Minting one for a fixed user for anybody who loads the page is a test
  control.
* **One status index per credential, and the bit is computed.** The same index
  in every list, and a status derived from the credential's own entry and its
  revocation mark, means `/admin/tokens`, `/admin/vc-status`, a global sign-out
  and the sign-in door cannot disagree.
* **The sign-in register is written at issuance, where the facts are known.**
  In development the credential endpoint accepts tokens it did not issue, so a
  credential's `sub` could name anybody. Only the realm's own record of a
  verified, undisowned, issuance-scoped token can say whom a credential
  represents.
* **The request-encryption key belongs to the realm.** Each realm publishes and
  decrypts with its own key, kept sealed in the store in product mode. It is a
  plain key and not a certificate, because section 10 publishes a bare JWK that
  a wallet trusts from the metadata it fetched.
* **A holder key no cryptosuite can prove is refused at issuance**
  (`STS-VC-0080`). An `ldp_vc` bound to such a key would verify and never be
  presentable.
* **The DID configurations sit beside the plain ones instead of replacing
  them.** A server-wide switch would test either the DID route or the
  specification's own route, never both.

## In the running service

* **Protocols → Verifiable Credentials → OpenID4VCI** (`/admin/oid4vci`): the
  issuer's settings, including which wallet the offer pages use, which
  authorization server is advertised, the batch size, deferred timings,
  encryption, and the DID choices. API: `GET /admin-api/oid4vci-settings`.
* **Protocols → Verifiable Credentials → Credential claims** (`/admin/vc`):
  which claims a credential issued from now on carries, chosen from the LDAP
  attribute catalogue, for all five configurations at once. Saving also
  populates the directory. API: `GET /admin-api/credential-claims` and
  `POST /admin-api/credential-claims/select`.
* **Protocols → Verifiable Credentials → Credential status**
  (`/admin/vc-status`): this realm's status lists, where they are served, and
  every issued credential's index and status, with **Suspend**, **Reinstate**
  and **Revoke**. API: `GET /admin-api/vc-status` and
  `POST /admin-api/vc-status/{suspend,reinstate,revoke}`.
* **Tokens** (`/admin/tokens`): issued credentials among everything else this
  realm issued, with the revocation that disowns one.
* **The live metadata** at `/.well-known/openid-credential-issuer` is the
  authoritative list of what this issuer offers. `/admin/sts-metadata` lists
  every endpoint (see [Endpoints](endpoints.md)).
* Every failure is recorded under an `STS-VC-NNNN` code; see
  [Error codes](error-codes.md).

## Related

* [OpenID4VP, wallet sign-in and DIDs](oid4vp.md)
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md), whose authorization and token
  endpoints issue the access token
* [OAuth security profiles](oauth-security.md), for DPoP
* [PKI](pki.md), for the certificate chains `x5u` and `x5c` name
* [Signing out](signing-out.md), for the global sign-out that disowns
  credentials
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
