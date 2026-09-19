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
| `vc_signin.ts` | Signing in with a wallet: `/authn/wallet`, `/authn/wallet/wait`, the Digital Credentials API answer at `/authn/wallet/dc-api` and the one script at `/authn/wallet.js`. |
| `vc_status.ts` | The status lists every issued credential names, and the check the Verifier makes against them (rule 3as). A library and four routes. |
| `vc_status_codec.ts` | Their encodings: the compressed byte array, CBOR, COSE_Sign1, the JWT and CWT tokens, and the W3C bitstring (rule 3as). A pure library. |
| `vc_data_integrity.ts` | The holder's Data Integrity proof on a presentation (`ecdsa-jcs-2019`, `eddsa-jcs-2022`, `mldsa44-jcs-2024`), `did:jwk` and `did:key` (rule 3at). A pure library. |
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
  2026-09-17 (#38)** for one door, and for every credential format it mints
  since the follow-ups; *Signing in with
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
reason is in `vc_issuer.ts`: in development mode the credential endpoint
accepts access tokens it did not issue and reads their claims unverified
(product mode refuses one it cannot verify, and a revoked one, since
2026-09-18 — `presentedIssuerToken()`). A token anybody wrote,
carrying alice's subject, gets a credential signed by this realm, naming
alice, bound to the writer's key. `tests/oid4vp_sign_in.js` 6e–6g issue exactly
that credential and present it.

**A DISOWNED TOKEN IS NOT A VERIFIED ONE (2026-09-17).** A sign-out marks the
session's access tokens revoked, and a token inside its `exp` still verifies.
Until this date `signInSubjectOf()` counted it, so whoever still held a
signed-out person's token could mint a credential and sign that person back in
at `/authn/wallet` — a sign-out undone by the token it was meant to cut off.
In development mode the credential is still ISSUED on a disowned token (the
credential endpoint consults revocation only in product mode, since
2026-09-18); it no longer gets the register row.
`tests/oid4vp_sign_in.js` 6g-ii–6g-iv, and the same test without the check
signs the person in.

So the fact is recorded where it is known: at issuance. `rememberIssued()`
writes a row — keyed by the SHA-256 of the issuer-signed JWT, holding the
subject, the holder key's RFC 7638 thumbprint, the format and the expiry, never
the credential — only when `subjectFromToken()` says the token (a) verified
against this realm's key and was NOT DISOWNED — its `jti` is not marked
revoked (`stats.isRevoked()`) — (b) names a `urn:uuid:` subject, (c) whose entry
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
as at every door (`STS-VC-0064`). **A DISABLED ACCOUNT IS REFUSED THERE TOO (2026-09-17)**:
`startSession()` asks `common/account_state.ts` before anything else, so a
wallet presentation for somebody an administrator disabled — or a SCIM
`active: false` did — signs nobody in. **There is no status list**: the issuer publishes none, and the
register's expiry and `forget()` are the closest thing.

~~**Only `dc+sd-jwt` is asked for**~~ — **reversed in the follow-ups; every
format signs in now**, and the paragraph that was here is the argument for
what each one had to grow: `jwt_vc_json`'s VP JWT had no freshness check and
`ldp_vc`'s derived proof had no holder key at all. See *Every format signs in*
below. The request is always BY REFERENCE (signed, so a wallet can show where
it is presenting) and names this issuer's own credential whatever
`oid4vp.expectedVct` says (frozen on the transaction as `expectedVct` for the
SD-JWT query).

**Another realm's credential** fails twice: its signature does not verify here,
and this realm's partition of the register never held it.

### What the session says

`amr ["pop"]`, `acr "1"` — **unless a key attestation says more, and unless a
second factor follows; see *A wallet is a factor* below.** RFC 8176's `pop` is proof of possession of a key
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

~~**The cross-device relay is not prevented, and says so**~~ — **answered in
the follow-ups**: the plain QR code is the one path it works on, it is OFF by
default in both modes now, and the Digital Credentials API path it was replaced
by cannot be relayed. *The Digital Credentials API* below is the argument.

**A browser holding a DIFFERENT person's session** has it replaced, not joined:
`startSession()`'s `sameIdentity()` decides, as for every door
(`tests/oid4vp_sign_in.js` 5b).

### The page has a script now, and it is the root `CLAUDE.md`'s exception

The wait page had none and argued that it needed none: a `<meta>` refresh was
the poll, and the answer was a page this server drew. **What changed is the
Digital Credentials API**, which is a browser API call
(`navigator.credentials.get({ digital: … })`) and cannot be made by markup, a
form or a link: nothing but a script can ask a wallet that way, and the answer
arrives in the page and nowhere else. So the page CANNOT offer the one path
that resists the relay without one, which is the test the root file sets, and
the exception takes the same shape as every other:

* `script-src 'self'` through `app.contentSecurityPolicy()`, so
  `frame-ancestors` and `base-uri` cannot be lost; never `'unsafe-inline'`;
* ONE static resource, `/authn/wallet.js`, which carries no transaction and is
  the same bytes for everybody — everything it needs is a `data-request`
  attribute on the form;
* a REAL SUBMIT BUTTON. The form posts to `/authn/wallet/dc-api` whether the
  script ran or not; with it blocked, that endpoint answers a page saying the
  API did not run (`STS-VC-0081`) and offers the same-device link, which is a
  plain `<a>`.

**THE `<meta>` REFRESH MOVED TO THE QR PAGE** (`?qr=1`, drawn only where the QR
code is on): a reload while the browser's credential dialog is open throws the
dialog away. That page has no script, polls exactly as the wait page used to,
and is the second half of the refused-script table's row — a polling page still
does not need a script, which is why it did not get one.

### The Digital Credentials API (rcbj's decision for the relay)

`vc_verifier.ts`'s `dcApiRequest()` builds a SECOND request for the same
transaction — one nonce, one DCQL query, answered once:

* **`openid4vp-v1-signed`** (Appendix A.1), as `{ request: <JWS> }`: the signed
  form, so the wallet can authenticate this Verifier and — with
  **`expected_origins`** naming this service's origin, which a signed request
  MUST carry (A.2) — refuse the request if a page on another origin hands it
  over. That is the relay, refused at the victim's phone.
* **`response_mode` `dc_api.jwt`** by default: the answer travels through the
  page's script, so it is encrypted (section 8.3) to an ephemeral P-256
  ECDH-ES key made for this transaction and published in `client_metadata`.
  The private half lives on the transaction, SEALED under the key-encryption
  key where there is one, and dies with it.
  `oid4vp.signInDcApiResponseMode` asks for `dc_api` instead, for a wallet
  that cannot encrypt.
* **No `response_uri`, `redirect_uri` or `state`**, which A.2 does not define
  for this API.
* **THE AUDIENCE IS THE ORIGIN.** A.4 fixes it at `origin:<origin>` *even for
  a signed request*, so the Key Binding JWT's `aud`, the VP JWT's `aud` and the
  Data Integrity proof's `domain` are checked against that and not against the
  Client Identifier. A presentation made for the `direct_post` path therefore
  signs nobody in here, which `tests/oid4vp_dc_api.js` holds.

`/authn/wallet/dc-api` takes what the page posts. It is admitted exactly as the
wait page is — the binding cookie, the transaction, the pending record — and
then: the `Origin` header must be this service's own (`STS-VC-0074`); the
answer must be a `DigitalCredential` in the protocol the request named
(`STS-VC-0073`); an encrypted one is opened with that transaction's key; and
the sign-in is finished IN THAT REQUEST, because it is the browser's own — no
poll, no `response_code`, nothing to collect.

**What is not implemented**: the unsigned and multi-signed request forms
(A.3.1, A.3.2.2) — this door always signs, and an unsigned request carries no
`expected_origins` at all — and `transaction_data`.

### Every format signs in

The DCQL query carries one credential query per format in
`oid4vp.signInFormats` and a `credential_sets` saying any ONE of them answers
(section 6.2), so a wallet presents whichever it holds. Each format proves the
holder in its own way, and the guarantee is the same one every time — a FRESH
proof, by the key the credential is bound to, for THIS request's nonce and THIS
audience:

| Format | The holder proof | What the register is keyed by |
|---|---|---|
| `dc+sd-jwt` | a Key Binding JWT: `nonce`, `aud`, `iat` within `oid4vp.kbMaxAgeS`, `sd_hash` over exactly the bytes presented | the SHA-256 of the issuer-signed JWT |
| `jwt_vc_json` | a VP JWT signed by the credential's `cnf` key, with `nonce`, `aud` and an `iat` held to the same bound (added here: without it a VP could be kept and replayed for the transaction's whole life) | the SHA-256 of the embedded credential JWT |
| `ldp_vc` | a W3C `VerifiablePresentation` whose Data Integrity proof (`challenge` = the nonce, `domain` = the audience, B.1.3.2.5) is made by the `did:jwk` the credential names as its subject | the HOLDER KEY and the person |

**`ldp_vc` IS THE ONE THAT NEEDED A DESIGN.** A bbs-2023 derived proof is
unlinkable to the credential by design and has no holder secret at all: anyone
holding the base credential can derive one, and it binds the nonce and nothing
about who derived it. So the sign-in asks for a presentation AROUND it, and
three of the credential's own statements with it — the subject (the holder's
`did:jwk`), the `issuer` and the validity window:

* the derived proof says THIS REALM SIGNED a credential whose subject is that
  `did:jwk` (the BBS key is the service's, one for every realm, which is why
  the `issuer` statement is what tells two realms apart);
* the Data Integrity proof says the presenter HOLDS that key;
* the register's row for that key and that person says this realm issued it on
  a verified token, and the `(validFrom, validUntil)` pair says WHICH
  credential of that person's it is — which is what a revocation needs, since
  nothing in the proof itself identifies one.

A holder key recorded for two people signs nobody in (`STS-VC-0066`): the proof
shows the key and the key names both. A key no cryptosuite covers — RSA,
secp256k1, Ed448, a composite — is refused AT ISSUANCE (`STS-VC-0080`), because
a credential bound to it could never be presented.

**The bar door still accepts a bare derived proof**, and its query now says so
(`require_cryptographic_holder_binding: false`): that door admits nobody, so a
proof that binds only the nonce is a fair thing to let it verify.

**POST-QUANTUM, ON BOTH SIDES.** The issuer signature and every holder proof
are checked asynchronously now, so `oid4vci.credentialSigningAlgorithm` may
name ML-DSA, SLH-DSA or a composite and the Verifier accepts the result as this
realm's (`verifyIssuerSignatureAsync()` finds the realm's AKP key by `alg` and
`kid` and hands the check to the worker pool); a holder may bind a credential
to an ML-DSA-44 key and prove a Key Binding JWT, a VP JWT or — through
`mldsa44-jcs-2024`, the one quantum-resistant JCS suite the W3C draft defines —
a Data Integrity proof with it. What is NOT possible: a trusted issuer
CERTIFICATE with a post-quantum key (node reads no ML-DSA certificate into a
`KeyObject` here), and an ldp_vc holder key of any other post-quantum kind,
because no cryptosuite defines one.

### A wallet is a factor

A presentation proves possession of one key, and #38 answered that by
WITHHOLDING the wallet from any request that demanded two factors. The
follow-ups answer it properly, and `authn/CLAUDE.md` carries the mechanics:

* **a wallet, then a second factor** — `authn.beginSecondFactorAfterWallet()`
  is asked once a presentation has named somebody, and draws their
  authenticator app, their security key or their PASSWORD
  (`/authn/password-factor`, new, no script); the session then says
  `amr ["pop","otp"]` (or `"pwd"`, or `"hwk"`) and `acr "mfa"`;
* **a password, then a wallet** — every second-factor screen carries a *Use
  your wallet instead* link, `/authn/wallet?mfa=<step>`, and
  `authn.finishWithWallet()` finishes the step for a credential issued to THE
  SAME PERSON and refuses anybody else's (`STS-VC-0084`);
* **two factors in one act** — where the issuer verified a KEY ATTESTATION
  (OpenID4VCI Appendix D) saying the key storage resists Moderate attack
  potential, the session adds `hwk`; where the USER AUTHENTICATION guarding
  the key is attested too, it adds `mfa` and `acr` is `"mfa"`, because the
  wallet asked the person for something they know or are before it would sign.
  Nothing a presentation says about itself is believed: only what the issuer
  recorded at issuance (`vc_issued.ts`'s row).

`oid4vci.keyAttestationRequired` requires an attestation of every proof and
advertises it (`key_attestations_required`); `oid4vci.keyAttestationTrusted‑
Certificates` is who may sign one. The `attestation` proof type (Appendix F.3)
is accepted as well as the `jwt` proof's `key_attestation` header.

### Disowned: what stops a credential signing in

Three acts, all of them read through `vc_issued.disownedReason()`:

* a GLOBAL sign-out — `/logout`, `/admin/logout`, `/admin-api/logout` — ending
  the `wallet-credential` family (`logout/CLAUDE.md`). It stamps the row, and
  every credential issued up to that instant stops signing in; one issued
  AFTER, on a fresh token, signs in again;
* an administrator's revocation of the credential on `/admin/tokens` (the
  issued register's own mark, read by handle, so a restore undoes it);
* a status-list entry that is not VALID — set by either of those, or by
  `/admin/vc-status`.

**An ordinary session sign-out disowns nothing.** `/oauth2/logout`, SAML Single
Logout, `wsignout1.0` and the console's and portal's Sign out end one session
through `authn.dropSession()`, which never reaches this register: a person who
signs out of an application signs back in with the wallet they hold.

**And the issuance-time check is the other half** (`signInSubjectOf()`): a
credential minted on a DISOWNED access token gets no register row at all, so a
sign-out cannot be undone by the token it was meant to cut off.

### The status lists

`vc_status.ts` publishes them and `vc_status_codec.ts` encodes them:

* **Token Status List** (draft-ietf-oauth-status-list-21) for the JOSE
  formats, at `/oid4vci/status-lists/1` — `application/statuslist+jwt`, or
  `application/statuslist+cwt` (a COSE_Sign1, not CWT-tagged) when `Accept`
  asks for it — two bits per credential, with `ttl` and `exp`, and an
  aggregation endpoint at `/oid4vci/status-lists`. `?time=` answers 501: no
  historical lists are kept.
* **W3C Bitstring Status List** for the W3C formats, one list per purpose at
  `/oid4vci/status-lists/bitstring/{revocation,suspension}`, each a
  `BitstringStatusListCredential` secured as `application/vc+jwt`, 131,072
  entries (the specification's minimum).

**ONE INDEX PER CREDENTIAL, THE SAME IN EVERY LIST**, taken at random (the
draft's linkability guidance) through a cluster claim, and free again when the
credential expires. **A bit is COMPUTED**, never stored twice: the entry's own
status, or INVALID because the issued register's mark says an administrator
revoked it — so `/admin/tokens`, `/admin/vc-status`, a global sign-out and the
sign-in door cannot disagree.

**The Verifier CONSULTS it** for every presentation that otherwise verified
(section 8.3's order): a credential this realm signed is read from this realm's
own entries; one a TRUSTED FOREIGN issuer signed has its list fetched through
`federation/federation_http.ts`'s `fetchPublished()` — the fourth outbound
exception, argued in the root `CLAUDE.md` — verified against the same
certificate that verified the credential, and cached for its `ttl` (bounded by
`oid4vp.statusListMaxCacheS`). A list that cannot be fetched or verified means
NO STATEMENT CAN BE MADE, and the credential is refused (`STS-VC-0072`) rather
than let through.

### Settings

`oid4vp.signIn` (on), `oid4vp.signInTtlS` (300), `oid4vp.signInPollS` (3),
`oid4vp.signInCrossDevice` (**OFF**, in both modes: the relayable path),
`oid4vp.signInFormats` (all three), `oid4vp.signInDcApiResponseMode`
(`dc_api.jwt`) and `oid4vp.statusListMaxCacheS` (3600) — group OID4VP; and
`oid4vci.statusListTtlS` (300), `oid4vci.statusListLifetimeS` (86400),
`oid4vci.keyAttestationRequired` (off) and
`oid4vci.keyAttestationTrustedCertificates` (empty) — group OID4VCI. So
`/admin/oid4vp`, `/admin/oid4vci` and `/admin-api/config` carry them, and
`/admin/vc-status` is where the lists themselves are read and changed. **On by default in both modes**: the screen
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

**The parent project's wallet has not been RUN against this door**, and cannot
be from here: its presentation code (`client/src/sd_jwt_vp.js`,
`vc_presentation_*.js`) is not among the files vendored into `tests/vendored/`,
so nothing in this repository can load it. What IS held
(`tests/oid4vp_sign_in_formats.js` section 5) is its SHAPES, built with the
vendored `tests/vendored/jws.js` that wallet signs with: its Key Binding JWT
and its VP JWT sign in, and its `ldp_vc` envelope — a bare derived proof — is
refused by name. Three things that wallet would need before it could drive
this door are recorded here rather than guessed at: it reads only the FIRST
DCQL credential query (so it answers the first format
`oid4vp.signInFormats` names), it signs with ES256 only, and it speaks only
`direct_post` — no Digital Credentials API, and no `ldp_vc` holder proof.

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

