# oid4vc/

OpenID4VCI 1.0 (the Credential Issuer), OpenID4VP 1.0 (a mock Verifier), and W3C
DID Core with DIF domain linkage.

| File | What it is |
|---|---|
| `vc_configs.ts` | The credential configurations. Exists to break a require cycle. |
| `vc_offers.ts` | The Credential Offer pages and the pre-authorized codes. Same reason. |
| `vc_claims.ts` | Which LDAP attribute types an issued credential carries, plus the invented persona. |
| `vc_verifier_config.ts` | What the mock Verifier ASKS FOR, and in which of the three formats. |
| `vc_issuer.ts` | The three credential endpoints. |
| `vc_verifier.ts` | The bar door at `/oid4vp/verifier`, and the Verifier every sign-in's request goes through. |
| `vc_issued.ts` | The register of credentials this realm issued for a person on an access token it verified (rule 3ar). A library. |
| `vc_signin.ts` | Signing in with a wallet: `/authn/wallet` and `/authn/wallet/wait`. |
| `vc_did.ts` | `did:web`, `did:jwk`, and the domain linkage document. |

**`vc_configs.ts` and `vc_offers.ts` exist to break require cycles, not to group
code** — see rule 2 in the root `CLAUDE.md`. The credential configurations are
read by both the issuer and the authorization server; the Credential Offer's
pre-authorized codes are minted by the offer pages and redeemed at the token
endpoint. In `common/protocol_stack.ts` (positions 11–14), `vc_offers` is
required before `vc_issuer`; both read `vc_configs`, which is why that module
exists. **Its ROUTES are registered earlier than that line, just before
`oauth-oidc/oauth2`'s** (#50's R1): `oauth2.ts` requires `vc_offers.ts`, and
until R1 that require was what registered the offer pages, so the composition
root's `register()` for `vc_offers` sits where they always landed.

**`vc_claims.ts` is read from many points of the require order and from
eight directories** — `vc_issuer.ts` and `vc_verifier_config.ts` here,
`../common/claim_attributes.ts`, `../oauth-oidc/oauth2.ts`,
`../federation/federation_map.ts`, `../admin-ui/admin.ts`,
`../admin-core/admin_actions.ts` and `admin_views.js`,
`../ldap/ldap_server.js` and `../scim/scim_map.ts` — so it must stay a
library. It is in this directory rather than in `common/` because the
catalogue is defined by what a CREDENTIAL carries; the readers elsewhere are
consumers of that definition, not co-owners of it.

3a. **`vc_claims.ts` is a library like `dpop.js` too, and it is read from several
   different points of the require order.** It holds which claims an issued
   Verifiable Credential carries — a catalogue of LDAP ATTRIBUTE TYPES, not of claim
   names, because a claim's value is the value on that person's directory entry —
   plus the invented, DETERMINISTIC persona that fills what an entry lacks.
   `vc_issuer.ts` (early), `admin.js` (late) and `ldap_server.js` (later) all read it,
   so it must stay a library: it registers no route and requires only `helpers.js`,
   three leaves (`realms.js`, `mode.js`, `error_codes.js`)
   and `admin_stats.js` (for `identityKeyOf()`, so that `alice`,
   `alice@REALM` and her `urn:uuid:<entryUUID>` — or the retired
   `urn:sts:user:alice` — are one invented person and one entry). The DIRECTORY half is inverted the usual way — `setDirectory()` is filled
   by `ldap_server.js` at ITS require time, because that module cannot be required
   from a module `vc_issuer.ts` reads without dragging every `/ldap` route to the
   front of the router. Two things there are load-bearing and easy to undo: the
   ISSUER METADATA is built from the same selection the credential is (an issuer
   advertising five claims and minting fourteen teaches every wallet author that the
   metadata is not worth reading), and `ldp_vc` carries only the terms the vendored
   JSON-LD context defines — `bbs2023.js` canonicalizes with `safe: true`, so an
   undefined term does not go missing, it THROWS inside a cryptosuite at issuance
   time. `buildLdpVc()` filters against the context it actually loaded rather than
   trusting the hand-kept list.

3a-ii. **`vc_verifier_config.ts` is the same kind of library, and it holds the
   OTHER end of that catalogue.** `vc_claims.ts` says what an issued credential
   CARRIES; this says what the mock Verifier — the bar door at `/oid4vp/verifier` —
   ASKS FOR, and which of the three credential formats it asks in. Both ends read
   it (`vc_verifier.ts` early, `admin.js` and `admin-core/` late), so it
   registers no route and requires only `helpers.js`, `realms.js`, `config.js`,
   `vc_claims.ts` and `vc_configs.ts`, none of which registers anything
   either. Four things in it are load-bearing:
   its catalogue is `vc_claims.ts`'s rows GROUPED BY CLAIM rather than listed as
   attribute types, because `buildSdJwtVc()` makes one Disclosure per top-level
   claim and `address` is therefore one unit of disclosure however many attributes
   feed it; the DCQL query is built HERE and `vpDcqlQuery()` in `vc_verifier.ts` is
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
* ~~**A presentation that VERIFIES is not a sign-on either.**~~ — **reversed
  2026-09-17 (#38)** for one door and one kind of credential; *Signing in with
  a wallet* below is the argument. **The bar door still is not one.** The
  OID4VP Verifier checks properly — issuer signature, every Disclosure digest
  against `_sd`, the Key Binding JWT including `sd_hash`, the nonce, the
  audience, the validity window and whether the claims asked for arrived — and
  a presentation made at `/oid4vp/verifier` then says yes on a web page and
  stops: nobody there asked to be signed in, and a session started because a
  bar door was shown a credential would be one nobody requested. **It IS
  recorded, which is a different claim and the two must not be merged** — the
  holder goes through `recordAuthentication()` like every other accepted
  credential, so it appears on `/admin/users` and the directory seeds an entry
  for it; what the row says is that an identity presented a credential here
  and it verified, and nothing more. What it asks for is configuration
  (`/admin/vc-verifier-config`) and
  is deliberately a SEPARATE setting from what the issuer mints (`/admin/vc`), so
  that asking for a claim no credential here carries stays reachable: that is the
  only way to exercise a wallet's "I cannot satisfy this request" path, and one page
  setting both would make it impossible to produce. Asking for NO claim is a setting
  too — DCQL reads an absent `claims` member as the whole credential.

---

## SIGNING IN WITH A WALLET (2026-09-17, #38)

rcbj's direction for the issue was *we are eliminating the list of things this
project does not do*, and the row *Turn a verified presentation into a sign-on*
went with it. What replaced it is deliberately narrow, and each narrowing is a
decision with a reason.

### The door, and why it is here

`/authn/wallet?authn={id}` and `/authn/wallet/wait` are `vc_signin.ts`'s, and
the shape is `kerberos/spnego_authn.ts`'s followed on purpose: a door in
`/authn/*` whose two paths `authn.ts` declares (`WALLET_PATH`,
`WALLET_WAIT_PATH`) and links to from the sign-in screen, reached only with an
`?authn=` naming a pending record, and leaving through `startSession()` and
`completeAuthentication()`. So every protocol that reaches the screen through
`beginAuthentication()` — OAuth/OIDC, SAML 2.0 and 1.1, WS-Federation, the
console, the portal — can be answered by a wallet without being told one
exists. It lives in this directory because what it drives is the Verifier
(`buildVpRequest()` with `signIn`, `transactionFor()`, `saveTransaction()`,
`signInOutcome()`), required at 11–14; `authn.ts` at #8 requires nothing here,
so no slot and no cycle — rule 3e's test answered the way SPNEGO answered it.

**It needs a pending record.** SPNEGO can be used directly and says who you now
are; a wallet sign-in cannot, because the transaction has to be bound to
something the browser started and the record is that something. A door reached
with nothing pending answers `STS-VC-0053`.

### Whom it signs in: rule 3ar, `vc_issued.ts`

**Only a holder-bound SD-JWT VC this realm issued, and only as the directory
entry it was issued for.** The obvious reading — the credential's `sub` is
`urn:uuid:<entryUUID>`, so sign in whoever that names — is wrong, and the
reason is in `vc_issuer.ts`: the credential endpoint accepts access tokens it
did not issue and reads their claims unverified. A token anybody wrote,
carrying alice's subject, gets a credential signed by this realm, naming
alice, bound to the writer's key. `tests/oid4vp_sign_in.js` 6e–6g issue exactly
that credential and present it.

So the fact is recorded where it is known: at issuance. `rememberIssued()`
writes a row — keyed by the SHA-256 of the issuer-signed JWT, holding the
subject, the holder key's RFC 7638 thumbprint, the format and the expiry, never
the credential — only when `subjectFromToken()` says the token (a) verified
against this realm's key, (b) names a `urn:uuid:` subject, (c) whose entry
exists now and has that subject, and (d) was granted for credential issuance
(one of `VCI_CONFIGS`' scopes or an `openid_credential` authorization detail —
without (d), any access token a client holds for somebody would be convertible
into a way to sign them in). A deferred issuance decides this on the ORIGINAL
request and carries it on the deferred record. **The credential is unchanged**:
nothing a claim in it could say is something any party but this realm, which
holds the register, could check.

`signInOutcome()` then asks, in order: the presentation verified (so the Key
Binding JWT verified against the credential's `cnf` key, for this nonce and this
audience, fresh, over exactly these bytes — `STS-VC-0061`); this realm's key
signed it, not a certificate in `oid4vp.trustedIssuerCertificates`
(`STS-VC-0058`); the register holds it (`STS-VC-0059`); its subject and holder
key agree with the row (`STS-VC-0066`); the subject still names an entry with
that subject (`STS-VC-0060`). The issuance policy is asked by `startSession()`
as at every door (`STS-VC-0064`). **There is no disabled flag to ask beyond
that** — `scimActive: false` deactivates nobody, which is a root `CLAUDE.md`
row of its own. **There is no status list**: the issuer publishes none, and the
register's expiry and `forget()` are the closest thing.

**Only `dc+sd-jwt` is asked for**: `jwt_vc_json`'s VP JWT has no freshness check
here and discloses the whole credential, and `ldp_vc`'s derived proof has no
holder key and is unlinkable to the credential by design. The request is always
BY REFERENCE (signed, so a wallet can show where it is presenting), names this
issuer's `vct` whatever `oid4vp.expectedVct` says (frozen on the transaction as
`expectedVct`), and asks for `sub` only.

**Another realm's credential** fails twice: its signature does not verify here,
and this realm's partition of the register never held it.

### What the session says

`amr ["pop"]`, `acr "1"`. RFC 8176's `pop` is proof of possession of a key
whose storage is unspecified, which is exactly what is known — a JWK says
nothing about hardware, and the issuer accepts no key attestation — so `hwk` or
`swk` would claim knowledge nobody has, and `user` would claim a presence test
nobody made. One factor, so the button is withheld under `forceMfa` and the door
refuses such a record (`STS-VC-0054`). `authn.ts`'s `methodPhraseFor()` grew a
`pop` branch. The presentation is RECORDED by `startSession()` when the session
is started, and not by the response endpoint as well — two records for one
sign-in is the defect federation and SPNEGO each fixed; a presentation that
signs nobody in is recorded at the response endpoint exactly as before.

### The browser it belongs to

The wallet's `direct_post` is the wallet's request, so the session is minted on
the browser's next request to `/authn/wallet/wait`, and only in the browser that
started the sign-in: `sts_wallet_binding` (HttpOnly, SameSite=Lax, one per
browser, reused) is hashed onto the transaction and compared in constant time
(`STS-VC-0055`). A same-device wallet is answered with a `redirect_uri`
carrying a one-time `response_code` (OpenID4VP section 8.2; its hash is kept),
and a wait request carrying one must carry the right one (`STS-VC-0065`). The
transaction lives `oid4vp.signInTtlS` — enforced at the response endpoint too,
for a sign-in only (`STS-VC-0056`; the bar door's late answers are still
verified as before) — and is answered once and finished once (above).

**The cross-device relay is not prevented, and says so**: somebody who starts a
sign-in and shows their own QR code to a victim holds the binding cookie. The
signed request lets the wallet say where the presentation goes, the lifetime is
five minutes, and `oid4vp.signInCrossDevice` drops the code.

**A browser holding a DIFFERENT person's session** has it replaced, not joined:
`startSession()`'s `sameIdentity()` decides, as for every door
(`tests/oid4vp_sign_in.js` 5b).

### No script

The wait page reloads itself with `<meta http-equiv="refresh">` every
`oid4vp.signInPollS` seconds and the QR code is an SVG drawn here, under the
base policy's `img-src 'self' data:`. A polling page looks like the case for a
script and is not: the reload is the poll and the answer is a page this server
draws. The `meta` target is not an `href`, so `app.js` does not rewrite it for a
realm and `vc_signin.ts` passes it through `realms.href()` itself.

### Settings

`oid4vp.signIn` (on), `oid4vp.signInTtlS` (300), `oid4vp.signInPollS` (3),
`oid4vp.signInCrossDevice` (on) — group OID4VP, so `/admin/oid4vp` and
`/admin-api/config` carry them. **On by default in both modes**: the screen
offers every mechanism the service supports, and this one signs in only an
entry this realm issued a credential for on a token it verified — in product
mode, a token from a person who signed in with a verified credential of their
own, since the offer page is gated there.

### Logout and signals

Nothing new: the session is an `authn.ts` session, so `/logout`,
`/admin/sessions` and CAEP see it as they see every other
(`logout/CLAUDE.md`). `tests/oid4vp_sign_in.js` 3f checks the live-session
list.

### What has no test

The parent project's debugger wallet has not been driven against
`/authn/wallet`: `tests/oid4vp_sign_in.js` is a wallet written for the test, and
whether the debugger's `vc-presentation-1.html` answers a DCQL query naming only
`sub` is not established here.

---

## THE 2026-09-12 HARD-CODED-VALUE SWEEP

The literals became `config.js` rows whose `dflt` is the old value, read per
use: credential lifetimes, the proof `iat` window, the c_nonce and offer
lifetimes, the issuer display name, the wallet pages, the encryption `enc`
lists, the Domain Linkage and `/did/generate` lifetimes, the Verifier's request
lifetime, expected `vct` and claim cap. The credential CATALOGUE — configuration
display names and colours, the `VCI_*` identifiers — stays code on purpose: it
is what `vc_configs.ts` exists to hold, and a setting per string would be a
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
  when `vc_issuer.ts` loaded, the request pool handed ONE key down the fork in
  `STS_VCI_REQUEST_ENC_KEY_PEM`, so in a pooled process every realm shared it and
  a realm's issuer decrypted requests encrypted to another realm's published
  key, and no kind survived a restart. It is `vciRequestEncKey` on
  `helpers.stsKeysFor`'s set now (`common/helpers.js`'s
  makeRequestEncryptionKey()), and the set already had every property the key
  lacked — per realm, written down SEALED in `sts_keys` in product mode,
  decrypted only while used (`keys.plaintextRetention`), agreed across the front
  process and every request worker by the key channel's first-generator-wins.
  `vc_issuer.ts` makes no key: `requestEncryptionKeys()` asks
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
`vc_issuer.ts` provides the capability, which the row names.

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

**The bar door's OpenID4VP transactions are not in this list, and not by
omission.** Its `request_uri` is served as often as it is fetched and a second
`direct_post` response overwrites the verdict — neither is single-use even in
one process, so there is no "once" for a cluster to break.

**A SIGN-IN'S TRANSACTION IS, since 2026-09-17 (#38)** — scope
`oid4vp.sign-in`, the same capability. The response endpoint refuses a second
`direct_post` for it (`STS-VC-0057`), because there the verdict decides whom a
waiting browser is signed in as, and `/authn/wallet/wait` claims the state before it
starts a session, so two polls on two nodes cannot both sign somebody in
(`STS-VC-0062`; a store that cannot be asked, `STS-VC-0063`). The bar door's
behaviour is unchanged.

