# oid4vc/

OpenID4VCI 1.0 (the Credential Issuer), OpenID4VP 1.0 (a mock Verifier), and W3C
DID Core with DIF domain linkage.

| File | What it is |
|---|---|
| `vc_configs.js` | The credential configurations. Exists to break a require cycle. |
| `vc_offers.js` | The Credential Offer pages and the pre-authorized codes. Same reason. |
| `vc_claims.js` | Which LDAP attribute types an issued credential carries, plus the invented persona. |
| `vc_verifier_config.js` | What the mock Verifier ASKS FOR, and in which of the three formats. |
| `vc_issuer.js` | The three credential endpoints. |
| `vc_verifier.js` | The bar door at `/oid4vp/verifier`. |
| `vc_did.js` | `did:web`, `did:jwk`, and the domain linkage document. |

**`vc_configs.js` and `vc_offers.js` exist to break require cycles, not to group
code** — see rule 2 in the root `CLAUDE.md`. The credential configurations are
read by both the issuer and the authorization server; the Credential Offer's
pre-authorized codes are minted by the offer pages and redeemed at the token
endpoint. In `common/protocol_stack.js` (positions 11–14), `vc_offers` is
required before `vc_issuer`; both read `vc_configs`, which is why that module
exists.

**`vc_claims.js` is read from many points of the require order and from
eight directories** — `vc_issuer.js` and `vc_verifier_config.js` here,
`../common/claim_attributes.js`, `../oauth-oidc/oauth2.js`,
`../federation/federation_map.js`, `../admin-ui/admin.js`,
`../admin-core/admin_actions.js` and `admin_views.js`,
`../ldap/ldap_server.js` and `../scim/scim_map.js` — so it must stay a
library. It is in this directory rather than in `common/` because the
catalogue is defined by what a CREDENTIAL carries; the readers elsewhere are
consumers of that definition, not co-owners of it.

3a. **`vc_claims.js` is a library like `dpop.js` too, and it is read from several
   different points of the require order.** It holds which claims an issued
   Verifiable Credential carries — a catalogue of LDAP ATTRIBUTE TYPES, not of claim
   names, because a claim's value is the value on that person's directory entry —
   plus the invented, DETERMINISTIC persona that fills what an entry lacks.
   `vc_issuer.js` (early), `admin.js` (late) and `ldap_server.js` (later) all read it,
   so it must stay a library: it registers no route and requires only `helpers.js`,
   three leaves (`realms.js`, `mode.js`, `error_codes.js`)
   and `admin_stats.js` (for `identityKeyOf()`, so that `alice`,
   `alice@REALM` and her `urn:uuid:<entryUUID>` — or the retired
   `urn:sts:user:alice` — are one invented person and one entry). The DIRECTORY half is inverted the usual way — `setDirectory()` is filled
   by `ldap_server.js` at ITS require time, because that module cannot be required
   from a module `vc_issuer.js` reads without dragging every `/ldap` route to the
   front of the router. Two things there are load-bearing and easy to undo: the
   ISSUER METADATA is built from the same selection the credential is (an issuer
   advertising five claims and minting fourteen teaches every wallet author that the
   metadata is not worth reading), and `ldp_vc` carries only the terms the vendored
   JSON-LD context defines — `bbs2023.js` canonicalizes with `safe: true`, so an
   undefined term does not go missing, it THROWS inside a cryptosuite at issuance
   time. `buildLdpVc()` filters against the context it actually loaded rather than
   trusting the hand-kept list.

3a-ii. **`vc_verifier_config.js` is the same kind of library, and it holds the
   OTHER end of that catalogue.** `vc_claims.js` says what an issued credential
   CARRIES; this says what the mock Verifier — the bar door at `/oid4vp/verifier` —
   ASKS FOR, and which of the three credential formats it asks in. Both ends read
   it (`vc_verifier.js` early, `admin.js` and `admin-core/` late), so it
   registers no route and requires only `helpers.js`, `realms.js`, `config.js`,
   `vc_claims.js` and `vc_configs.js`, none of which registers anything
   either. Four things in it are load-bearing:
   its catalogue is `vc_claims.js`'s rows GROUPED BY CLAIM rather than listed as
   attribute types, because `buildSdJwtVc()` makes one Disclosure per top-level
   claim and `address` is therefore one unit of disclosure however many attributes
   feed it; the DCQL query is built HERE and `vpDcqlQuery()` in `vc_verifier.js` is
   now only the caller that logs it, so the console's preview and the real request
   cannot drift; the ldp_vc paths use the VENDORED CONTEXT'S TERM and not the OIDC
   claim name (`birthDate`, and four flat terms where the others have `address`),
   which was silently wrong while the Verifier could only ask for the two claims
   whose spellings coincide; and `formatById()` reads a SPACE AS A PLUS, because
   `dc+sd-jwt` is a format id containing the one character a query string spells a
   space with — `?format=dc+sd-jwt` arrives as `dc sd-jwt`, which cost nothing
   while an unrecognised format fell back to a constant and costs the bar door's
   own button the moment that fallback is configuration.
   The claims a request asks for are FROZEN onto the transaction in
   `buildVpRequest()` and every check reads them from there: the list is editable
   while a presentation is in flight, and judging what came back against a list
   changed after the question was asked refuses a wallet for answering correctly.

---

## What it deliberately does not do

* **The values in an issued credential are invented IN DEVELOPMENT, and nothing
  verifies them.** `/admin/vc` says which LDAP attributes a credential carries;
  the value is read from that person's directory entry, and what the entry lacks
  is generated from their username — deterministically, so one username is one
  invented person across restarts, and in obviously fictional ranges (RFC 2606
  mail domains, `555-01xx` numbers, streets called `Placeholder`). A verifier that
  believed a birthdate from here would be believing a web form. **In product mode
  (`mode.inventsClaimValues()` false) nothing is generated since 2026-09-12**: an
  attribute the entry does not hold is ABSENT from the credential, and
  `generatedFor()` hands the populate sweep nothing to write onto an entry —
  gating only the credential would have let an invented value reach the
  directory one step earlier and come back out as a `directory` value. Nothing reads a credential claim back either:
  no token, assertion or PAC carries one and no endpoint decides anything on one.
* **A presentation that VERIFIES is not a sign-on either.** The OID4VP Verifier
  checks properly — issuer signature, every Disclosure digest against `_sd`, the Key
  Binding JWT including `sd_hash`, the nonce, the audience, the validity window and
  whether the claims asked for arrived — and then says yes on a web page and stops.
  No session starts, no token is issued and nothing else in this service reads what
  was presented. **It IS recorded, which is a different claim and the two must
  not be merged** — the distinction a verified TLS client certificate drew
  until 2026-09-05, when it became a sign-on (`GET /tls/sign-in` since
  2026-09-16). The holder goes through `recordAuthentication()` like every other
  accepted credential, so it appears on `/admin/users` and the directory seeds
  an entry for it; what the row says is that an identity presented a credential
  here and it verified, and nothing more. What it asks for is configuration
  (`/admin/vc-verifier-config`) and
  is deliberately a SEPARATE setting from what the issuer mints (`/admin/vc`), so
  that asking for a claim no credential here carries stays reachable: that is the
  only way to exercise a wallet's "I cannot satisfy this request" path, and one page
  setting both would make it impossible to produce. Asking for NO claim is a setting
  too — DCQL reads an absent `claims` member as the whole credential.

---

## THE 2026-09-12 HARD-CODED-VALUE SWEEP

The literals became `config.js` rows whose `dflt` is the old value, read per
use: credential lifetimes, the proof `iat` window, the c_nonce and offer
lifetimes, the issuer display name, the wallet pages, the encryption `enc`
lists, the Domain Linkage and `/did/generate` lifetimes, the Verifier's request
lifetime, expected `vct` and claim cap. The credential CATALOGUE — configuration
display names and colours, the `VCI_*` identifiers — stays code on purpose: it
is what `vc_configs.js` exists to hold, and a setting per string would be a
second catalogue. What is more than a number, and what
`tests/oauth_oid4vc_hardcoded.js` pins:

* **THE TRANSACTION CODE** is `crypto.randomInt()` in every mode — it was
  `Math.random()`, whose generator is recoverable from its outputs and this
  service prints its outputs on a page — of `oid4vci.txCodeLength` digits with no
  leading zero, compared in constant time by `vc_offers.checkTxCode()`. **In
  product mode** a wrong code is counted — in cluster claims since 2026-09-14,
  see the section below — and the one that reaches `oid4vci.txCodeMaxAttempts`
  SPENDS it.
* **`GET /issuer/offer` MINTS FOR THE SIGNED-IN PERSON WHERE TEST CONTROLS ARE
  CLOSED.** A cross-device or deferred offer carries a pre-authorized code, which
  IS an authorization: minting one for `oid4vci.offerUsername` for anybody who
  loads the page is H.2's demo, and a test control. In product the page sends an
  unsigned-in browser through the sign-in screen and refuses a "continue without
  signing in" session. `authn.js` is required inside the handler, because this
  file is a store module `oauth2.js` requires. A same-device offer grants
  nothing and is not gated.
* **THE `wallet` PARAMETER IS AN OPEN REDIRECT IN PRODUCT** and is refused unless
  it is the configured wallet or listed in `oid4vci.allowedWalletUrls` /
  `oid4vp.allowedWalletUrls` (`mode.acceptsUnregisteredAddresses()`).
* **CREDENTIALS SIGN WITH `oid4vci.credentialSigningAlgorithm`** — RS256 by
  default and exactly the old path; any other synchronous algorithm this realm
  holds a key for through `helpers.signingKeyFor()`. The metadata names it, the
  DID document publishes that key beside the RSA one, the Domain Linkage
  Credential and `/did/generate` use it, and the Verifier's
  `verifyIssuerSignature()` finds the realm's key by `alg` and `kid` — plus
  anything in `oid4vp.trustedIssuerCertificates`, used as keys and nothing more.
* **THE KEY BINDING JWT ACCEPTS WHAT THE ISSUER BINDS TO** — every asymmetric
  non-post-quantum algorithm. It accepted four while the issuer bound credentials
  to keys of eleven, so a wallet with an EdDSA key was issued a credential and
  refused for presenting it. A bug in every mode.
* **`stsDid()` IS DERIVED FROM `baseUrlOf(req)`**, so a trust realm's DID is
  `did:web:host%3A8081:realm:acme` and resolves at `/realm/acme/did.json` (a new
  route that 404s for a DID with no path), a pinned `global.publicBaseUrl` is
  honoured, and the default realm's DID is byte-for-byte what the Host header
  produced.
* **THE REQUEST-ENCRYPTION KEY IS A MEMBER OF THE REALM'S KEY SET — IN EVERY
  PROCESS AND IN PRODUCT MODE ACROSS A RESTART.** This bullet said the key was
  per realm "where it can be": the default realm kept a process key generated
  when `vc_issuer.js` loaded, the request pool handed ONE key down the fork in
  `STS_VCI_REQUEST_ENC_KEY_PEM`, so in a pooled process every realm shared it and
  a realm's issuer decrypted requests encrypted to another realm's published
  key, and no kind survived a restart. It is `vciRequestEncKey` on
  `helpers.stsKeysFor`'s set now (`common/helpers.js`'s
  makeRequestEncryptionKey()), and the set already had every property the key
  lacked — per realm, written down SEALED in `sts_keys` in product mode,
  decrypted only while used (`keys.plaintextRetention`), agreed across the front
  process and every request worker by the key channel's first-generator-wins.
  `vc_issuer.js` makes no key: `requestEncryptionKeys()` asks
  `helpers.requestEncryptionKeyFor()` for the AMBIENT realm's, so
  `credential_request_encryption.jwks` at `/realm/<id>/.well-known/openid-credential-issuer`
  publishes that realm's key and only that realm's key decrypts. **What a
  wallet sees is unchanged**: one RSA-OAEP-256 key, kid `sts-req-enc-<thumbprint>`,
  `use: enc`, `key_ops: ["encrypt"]`, of `oid4vci.requestEncryptionKeyBits` read
  in the realm the set is made for. **It is a plain key, not a leaf of the PKI
  hierarchy**: section 10 publishes a bare JWK a wallet trusts because it read it
  out of the issuer's own metadata over TLS, nothing looks for a certificate on
  it, and every certificate `pki.js` issues from a use case is a SIGNING
  certificate while this key only decrypts. A set written by a build from before
  the key joined it is BACKFILLED once on first use — asking the store and the
  shared blob first, so a process adopting a sibling's backfill does not make a
  second key — written down, and offered on as an enrichment
  (`keystore.enriches()`). `tests/vci_request_encryption_key.js` pins all of it.
* **`/oid4vci/last_request` IS PER REALM TOO (2026-09-12).** It was one `let`, so
  a realm's debugging endpoint reported however another realm's last Credential
  Request had arrived, kid included. **Persisted since 2026-09-14 (#46)**
  (`vc_issuer.lastCredentialRequest`, one key): behind a balancer the wallet's
  request and its read-back land on different nodes, and the other node said
  `seen: false` to a wallet that had encrypted. And **`vc_offers.deferredAccessTokens` is a
  persisted `realms.map()`** keyed by a SHA-256 of the token: it was a `new Set()`
  beside four per-realm stores, so a deferred token minted in one realm was
  deferred in every realm, and in a dispatched service on one worker only.

---

## SPENT ONCE ACROSS THE CLUSTER (2026-09-14, #46) — capability `oid4vc.once`

Three values were a check and a delete (or a write) on a replicated
`realms.map({ persist })`, so once per NODE against one store. Each keeps its
in-memory check first and is then spent through `cluster/cluster_claims.js`;
`vc_issuer.js` provides the capability, which the row names.

* **The pre-authorized code** — `vc_offers.spendPreAuthorizedCode()`, called by
  the token endpoint in `oauth2.js` right after its delete (scope
  `oid4vci.pre-authorized-code`). Refused `invalid_grant`, `STS-VC-0049`.
  Nothing releases it: a refused token request spent the code before this too.
* **The c_nonce** — `vc_issuer.spendProofNonces()`, now asynchronous, once per
  distinct nonce of a request (scope `oid4vci.c_nonce`). Refused
  `invalid_proof`, `STS-VC-0050`. This also closed the same race INSIDE one
  process: `verifyProofJwt()` awaits the signature, so two concurrent requests
  could both find the nonce before either deleted it.
* **Transaction Code failures** — `checkTxCode()` is asynchronous and counts in
  CLAIMS, not on the record: each wrong code claims the next free slot
  `<code>#1 … #limit` (scope `oid4vci.tx-code-failure`), and the slot it won is
  its number, so concurrent failures on N nodes take different slots and share
  one budget. The record's `txCodeFailures` is only where the probe starts —
  safe because a node writes n only after winning slot n — and what the console
  shows. The last slot spends the code through `spendPreAuthorizedCode()`, so a
  node still holding the record refuses the right code too. **A claims variant
  rather than a counter table** because the limit is at most 100 (five by
  default): no schema, no driver statement, and memory mode counts exactly as
  the record did.

Every claim lives for the value's remaining lifetime plus 60 s of clock
disagreement. A store that cannot be asked refuses (`STS-VC-0051`): the
redemption, the proof, or the wrong-code attempt uncounted.
`tests/cluster_single_use_protocols.js` section 2 holds each against a node
still holding the value, with the empty-store control.

**OpenID4VP is not in this list, and not by omission.** Its `request_uri` is
served as often as it is fetched and a second `direct_post` response overwrites
the verdict — neither is single-use even in one process, so there is no "once"
for a cluster to break. Making them single-use would be a behaviour change of
its own, not a clustering fix.

