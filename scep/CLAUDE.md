# scep/

**The Simple Certificate Enrolment Protocol (RFC 8894), per trust realm, since
2026-09-13.** A device holding a single-use challenge password sends a PKCS#10
request inside a CMS SignedData it signed and a CMS EnvelopedData encrypted to
the realm's SCEP RA, and is answered with a CertRep signed by the RA whose
certificate is encrypted back to it. Required at 23g in
`common/protocol_stack.ts`, as one require, and registered there by two
`register()` calls — `scep`, then `scep_admin` — since #50's R1, when requiring
a converted module stopped registering its routes.

| File | What it is |
|---|---|
| `scep.ts` | The eight routes (`/enroll/scep`, `/pkiclient.exe`, `/:profile`, `/:profile/pkiclient.exe`, GET and POST), the four operations, the five message types, the transaction store. Requires `scep_admin.ts` itself, AFTER its exports are assigned. |
| `scep_cms.ts` | The CMS codec: read a pkiMessage, verify its signer, open its envelope, write a certs-only SignedData, an EnvelopedData and a CertRep. A LIBRARY (rule 3) that decides nothing. |
| `scep_ra.ts` | The RA certificate: an RSA leaf of the realm's SCEP Issuing CA, `pki.certify()` slot `scep-ra`, pinned, re-issued on demand. |
| `scep_console.ts` | The view model and the six actions both `/admin/scep` and `/admin-api/scep` use (rule 7). No route, no `res`, no markup. |
| `scep_admin.ts` | `GET/POST /admin/scep` (Protocols) and `GET /admin/scep/monitor` (Monitoring). |
| `scep_api.ts` | The three `/admin-api` rows, `module.exports = { ROUTES }`, requiring the model lazily. |

What a certificate may be issued for, what goes in it and where it is kept are
**not decided here**: every issuance goes through `common/cert_enrollment.ts`,
and `common/CLAUDE.md` and that file's header argue it. The counters are
`common/enrollment_monitor.ts`'s.

## The decisions

### The authorization is the challenge, and the principal is the entry it names

The contract's decision 2: a challenge is issued for ONE entry and ONE profile,
by the person on the portal or by an administrator for anybody in the realm.
So the principal handed to `core.issue()` is `{ kind, id, admin: false }` for
**the entry the challenge names**, and `core.targetFromRequest()` +
`authorizeTarget()` then refuse a CSR whose subjectAltName names anybody else
(`STS-ENROLL-0021`). An administrator's authority was exercised when the
challenge was made; the device redeeming it is not an administrator.

**A challenge is spent by the first request that proves it**, BEFORE the core
rules on the certificate — `redeemScepChallenge(…, { peek: true })` first (so a
URL naming another profile does not use it up), then the spending redeem, then
`issue()`. The alternative, spending only on success, lets two transactions
racing one challenge both be issued. The cost is that a request refused by the
core after the redeem (an unregistered host name, say) has used its challenge,
and the operator makes another.

**Verified in both modes.** A permissive challenge verifier is a broken
verifier — the TOTP argument (`common/CLAUDE.md`).

### Not refused over plain HTTP, in either mode

ACME and EST ask `core.transportRefusal()`. SCEP does not, and that is RFC 8894
section 2.1 rather than an omission: the request is signed by the device and
encrypted to the RA, the challenge travels inside the encryption, and the reply
is signed and its certificate encrypted back. A transport refusal would refuse
every device that implements the specification and protect nothing the
envelope does not.

### Two answers, and which a refusal gets

An HTTP error (400, 405, 413, 415, 429, 501, 503) for a request that cannot be
NAMED — without a SignedData, a transactionID and a 16-byte senderNonce there is
nothing a CertRep could echo (`parsePkiMessage()`'s `stage: 'http'`). Every
refusal after that is a **CertRep FAILURE**, HTTP 200, signed by the RA, with a
failInfo. **The STS code goes on the response mark, the audit row and the
monitor, and never into the CertRep** — `failInfo` is the protocol's word, and
the job asserts the code is not in the reply bytes.

`failInfoForCore()` maps every core code: the CSR signature and a refused
signer certificate to `badMessageCheck`, an unacceptable or KEM key to
`badAlg`, everything else to `badRequest`. `scep_cms.ts`'s own refusals carry
their failInfo with them.

### Four codec decisions, each a refusal somebody will meet

`scep_cms.ts`'s header argues them; in short:

1. **SHA-256/384/512 only** — SHA-1 and MD5 `badAlg` (`sscep -S sha256`).
2. **AES-128/192/256-CBC only** — DES-EDE3-CBC `badAlg` (`sscep -E aes`). The
   reply uses the AES key size the request used.
3. **PKCS#1 v1.5 key transport is unwrapped with node-forge**, because node 22
   refuses `privateDecrypt()` with `RSA_PKCS1_PADDING` outright (CVE-2023-46809,
   Marvin). A failed unwrap is replaced with random key bytes so a padding error
   and a wrong key are one answer (`STS-SCEP-0030`) — the implicit rejection.
   OAEP (SHA-1/256/384/512) goes through node. **A plaintext that is not one
   DER value is 0030 too** (2026-09-15): a random AES key passes CBC's padding
   check about one time in 256, and until then that one time came back `ok`
   with garbage — `tests/scep_enrollment.js` failed on it in a dispatch run.
4. **Signed attributes are verified over the bytes that arrived**, tag swapped
   to SET; the ones this service signs are DER-sorted.

### Why the codec is in `scep/` and not `common/crypto.js`

Rule 3r is about primitives having one policy. This is an ENVELOPE only SCEP
reads, over node's own primitives, with every algorithm it accepts in a table
`admin-ui/crypto_metadata.ts` reads (`algorithms()`) — `gnap/gnap_httpsig.ts`'s
arrangement.

### The RA certificate

A leaf of the SCEP Issuing CA through `pki.certify()` under slot `scep-ra`,
`pinned: true` so the private key is kept in the realm's PKI row — sealed with
the hierarchy in product mode, gone with the realm, known to OCSP because
`certify()` records it. RSA of `scep.raKeyAlgorithm`, `digitalSignature` +
`keyEncipherment`. **Re-issued on demand**: missing, expiring within thirty
days, a different key size from the setting, or no longer chaining to the
realm's current SCEP Issuing CA. The certificate it replaces goes on that CA's
list as `superseded`.

**One RA for the cluster since 2026-09-14 (#46, `scep.ra-agreement`).** The race
used to be stated and not solved — two processes finding the RA stale each
issued one, the PKI row was last write wins, and across CONTAINERS each issued
its own lazily, so GetCACert on A and PKIOperation on B failed with
`STS-SCEP-0027` on every alternation. Where the store arbitrates, the issue runs
through `pki.oneBuildInTheCluster()` under its own claim (`scep-ra:<realm>`,
never the branch's — `certify()` may repair the branch under that): the row is
read from the store, and again once the claim is held, and a current RA another
node issued is served instead. A certificate slot is first writer wins in the
row's merge (`common/pki_merge.js`), so an issue that ran anyway adopts the
other; a console Reissue that lost is refused (`STS-PKI-0182`). The write
commits before the response (the cluster barrier waits for the keystore's
queued rows), so B's catch-up sees A's RA. Measured: GetCACert on two
active-active nodes at once returns one RA; with the cluster off, two. In one
process a re-issue is still serialised per realm.

### The transaction store

`realms.map({ persist: 'scep.transactions' })`, transactionID → the SUCCESS it
produced (the certificate, the CSR's SHA-256, the signer key's SHA-256). Only
successes are stored: a refused request may be corrected and retried under the
same transactionID. A day's retention and a thousand per realm, both
constants, because a result is a public certificate and the bound is about the
store's size. It answers:

* **a retried PKCSReq/RenewalReq** with the same transactionID and the same CSR
  → the stored certificate, and no second redemption. A different signer key →
  `STS-SCEP-0039`. **A different CSR is a NEW transaction** (#249, #250,
  2026-09-26; it was `STS-SCEP-0037`, now retired): certmonger and jscep derive
  the transactionID from the public key, so every request for one key repeats
  it — a `getcert resubmit`, a jscep renewal that keeps the key — and the
  refusal lasted as long as the result was held. It gives nothing away: the
  stored result goes back only for the same request, and a new one is
  authorized from scratch and replaces it. RFC 8894 section 3.2.1.1 puts the
  uniqueness on the client.
* **CertPoll** → the stored certificate, to the same signer key only; an
  unknown transactionID → `badCertId` (`STS-SCEP-0038`).

One transaction per (realm, transactionID) runs at a time in a process
(`serialized()`), so a client retrying before its first reply meets the stored
result.

### The other message types

* **RenewalReq (17)** — signed by a certificate this realm issued over ANY
  enrollment protocol, checked by `core.authenticatePresentedCertificate(pem,
  'scep', { clientAuth: false })` (added for SCEP: the TLS-connection version's
  checks on a certificate that arrived in a SignedData, without the `clientAuth`
  requirement, because an S/MIME certificate renews itself too). No challenge;
  the profile is the renewed certificate's; `replaces:` supersedes it. A
  certificate from another realm fails the realm Intermediate check
  (`STS-SCEP-0040`).
* **GetCert (21)** — a certificate the SIGNER'S entry holds, else `badCertId`.
* **GetCRL (22)** — the SCEP Issuing CA's CRL from `pki_revocation.buildCrl()`,
  in a certs-only SignedData's `crls`, for an IssuerAndSerialNumber naming that
  CA; anything else `badCertId`.

A PKCSReq must be signed by a certificate over **the CSR's own key** (RFC 8894
section 2.3; `STS-SCEP-0034`).

## Several nodes: the challenge and the transaction (2026-09-14, #46)

* **A challenge password is claimed** between the peek that proves it right and
  the write that spends it (`core.redeemScepChallengeOnce()`), so one challenge
  in two PKCSReqs with two transactionIDs at two nodes issues once. A claimed
  challenge is the refusal a spent one always was (`STS-ENROLL-0084`).
* **The transaction guard is also a claim** (`acrossNodes()` under
  `serialized()`). `inflight` is a Map in one process, so a client's retry at a
  second node met no guard, found no stored result, and was refused on the
  already-claimed challenge while the first node issued the certificate it then
  discarded. A node that finds the transaction claimed WAITS (every 250ms, up
  to 20s); the holder releases only after its writes COMMIT, and the waiter
  catches up with the store before running the handler — without both the
  waiter takes the claim, does not yet see the stored result, and refuses the
  retry it waited for. A wait that runs out is `STS-SCEP-0064`, a store that
  cannot be asked `STS-SCEP-0065`; the claim lives two minutes, so a node that
  died holding it blocks that one transactionID and nothing else.

## What the real clients found (#210, #211, 2026-09-24; #249, #250, 2026-09-26)

* **sscep has no TLS** and refuses an https URL, and SCEP was answered only on
  the main port. `pki/pki_service.ts`'s plain-HTTP listener now answers
  `/enroll/scep`, bare and under a realm prefix, beside `/pki/` — nothing else
  moved there.
* **sscep POSTs with no Content-Type; micromdm's client with
  `application/octet-stream`.** Both were 415 `STS-SCEP-0007`; `messageBytes()`
  takes both (an absent type reads `req.rawBody`, the bytes the text parser
  kept). Any other declared type is still 415.
* **sscep renews with a PKCSReq signed by the old certificate** (it has no
  RenewalReq) and was refused `STS-SCEP-0034`. RFC 8894 section 2.3 notes most
  implementations keep that form; `pkcsReq()` hands one whose signer this
  realm issued to `renewalReq()`, with exactly its checks. A foreign signer is
  still 0034.
* **The hint could not work**: the https URL, `openssl req` without
  `prompt=no` (so no challengePassword, `STS-SCEP-0035`), and `-c ca.crt-1`
  where sscep verifies the RA's CertRep with `-c`. `scep_console.ts` now names
  the plain URL (`plainUrl` in the answer), writes the subject the certificate
  will carry, and passes the RA. The job runs it literally.
* **micromdm's scepclient cannot be issued a certificate, and the service is
  right.** It builds every pkiMessage with smallstep/pkcs7 v0.1.1's package
  defaults — single DES-CBC for the envelope, SHA-1 for the signature — reads
  GetCACaps only to choose POST, and has no flag for either (v2.3.0 and `main`
  at 9902c1a). Refused `badAlg` (`STS-SCEP-0020`, the SHA-1 signature, first).
  Documented exception on #211; a legacy-algorithm setting is an open
  question there, and would be a weaker option behind a setting.
* **sscep warns when the certificate's subject is not the request's.** The
  certificate's content comes from the entry, never the CSR (RFC 8894 lets the
  CA change it), so a request must carry `CN=<entry>, O=<organisation>` (or
  `CN=<host>, UID=<entry>, O=…`) to see no warning; the hint does.
* **certmonger signs with a version 1 certificate**, and every request was
  refused `STS-SCEP-0011` ("0 match"): its self-signed "mini certificate" has
  no `[0]` version and no extensions — six TBS fields — and
  `describeCertificate()` demanded seven, so the signer was dropped from the
  SignedData's set. It reads six now.
* **certmonger and jscep repeat the transactionID** for every request with one
  key (above, *The transaction store*): a same-key renewal inside the day a
  result is held was `STS-SCEP-0037`. It is a new transaction now.
* **certmonger cannot read a FAILURE CertRep — a client defect, the service is
  right.** RFC 8894 section 3.2: FAILURE and PENDING "will lack any signed
  content", and certmonger's `cm_pkcs7_verify_signed()` calls
  `PKCS7_verify()` with no content, which fails "no content". So every
  refusal shows as `CA_UNREACHABLE` with that ca-error, and certmonger retries
  it until it is stopped. Sending an empty content instead would be a
  signed content RFC 8894 says a FAILURE lacks; the code is on the monitor.
* **certmonger's HTTPS stops at the PKIOperation — a client defect.**
  `scep-submit` passes `-R` (its CA file) to GetCACaps and GetCACert, and its
  PKIOperation request to `cm_submit_h_init()` with none (0.79.21, `scep.c`),
  so libcurl uses the system trust store and fails error 60. Over the plain
  listener it enrolls, renews and rekeys; `docs/scep.md` tells an operator.
* **jscep needed nothing else.** It negotiates AES and SHA-512 from GetCACaps,
  renews with a PKCSReq signed by the old certificate, polls, gets
  certificates and CRLs, refuses to ask GetNextCACert because it is not
  offered, and reads every FAILURE; every AES size with SHA-256 and SHA-512
  enrolls, and DES, DES-EDE3 and SHA-1 are `badAlg`.

## Documented exceptions

| Not implemented | Why |
|---|---|
| A non-RSA requester key (ECDSA, EdDSA, ML-DSA, composites, ML-KEM) | The CertRep's certificate is encrypted to the requester with RSA key transport; a non-RSA signer is `STS-SCEP-0025` and a non-RSA CSR `STS-SCEP-0033`, both `badAlg`. **Every one of the nine profiles is issued over SCEP for an RSA key**, and no /admin/pki cryptographic approach but classical RSA reaches SCEP. |
| PENDING | Nothing is approved by hand. |
| GetNextCACert | No pre-announced CA rollover; 501, not in GetCACaps. |
| SHA-1, MD5, DES, DES-EDE3 | Refused `badAlg` — which is why micromdm's scepclient, fixed on SHA-1 and single DES, cannot enroll (above). |
| A FAILURE CertRep certmonger can read | RFC 8894 section 3.2 sends it with no signed content, and certmonger requires some (above); it reports every refusal as `CA_UNREACHABLE`. A client defect, recorded on #249. |
| certmonger over HTTPS | Its PKIOperation request ignores `-R` (above). A client defect; the plain listener is the SCEP transport RFC 8894 section 2.1 names. |
| KeyAgreeRecipientInfo, RSASSA-PSS signers | An RSA RA has no agreement key; PSS signers are refused `badAlg` as an unknown signature algorithm. |
| `failInfoText` (RFC 8894's human-readable failure) | The reason is an operator's; it is recorded, not sent. |
| The five CA / OCSP / KDC profiles | Never over an enrollment protocol (`core.REFUSED_PROFILES`); a challenge for one cannot be created. |

## Tests

* `tests/scep_enrollment.js` — in process: the codec structure by structure
  (including OAEP, which the forge client cannot make, and the implicit
  rejection), the RA's life, the transaction store per realm, the console model
  and the API rows' schemas, the failInfo map. Mutants caught: signature always
  verifying, no implicit rejection, a process-wide transaction store, a zod
  schema that drifted from the OpenAPI body.
* `tests/vendored/sts_scep_sscep.js` — **certnanny's sscep at cb3e539, the real
  client** (#210), over the plain-HTTP listener: GetCACaps, GetCACert, the
  `/admin-api` hint run literally by bash, a challenge the person made on
  `/portal/certificates`, `-R`, GetCert, GetCRL, the historical renewal and the
  old serial on the CRL, and the refusals (reused, unknown, another realm's RA,
  3DES, SHA-1). No sscep warning on any success.
* `tests/vendored/sts_scep_micromdm.js` — **micromdm's scepclient v2.3.0**
  (#211): its transport over HTTPS and plain HTTP, three ways of choosing the
  recipient, and the `badAlg` its fixed SHA-1 and DES draw (below), which
  spends no challenge.
* `tests/vendored/sts_scep_certmonger.js` — **certmonger 0.79.21** (#249):
  the daemon started by the job on a private socket, add-scep-ca, a request
  with the person's portal challenge, CertPoll through its own `scep-submit`
  and stored GetCertInitial, resubmit and rekey onto the CRL, the refusals
  (reused, another realm's RA, DES-EDE3 and SHA-1 by editing its CA record)
  as `CA_UNREACHABLE` plus the monitor's code, and the HTTPS exception.
* `tests/vendored/sts_scep_jscep.js` — **jscep 3.0.1** through
  `tests/tools/jscep-driver` (#250): negotiated algorithms, GetCACert with the
  CA checked against the Intermediate and Root, GetNextCACert refused, enrol,
  poll, retry, all six AES × SHA-2 combinations, GetCert, GetCRL, renewal
  keeping and changing the key, the refusals, and HTTPS.
* `tests/scep_enrollment.js` section 3a — a version 1 signer and a repeated
  transactionID, in process (mutants: `parts.length < 7`, the 0037 refusal).
* `tests/vendored/sts_scep_enrollment.js` with `tests/vendored/scep_client.js`
  (forge + node, nothing from here) — over HTTP, ~70 checks, ~70 seconds (it
  waits out a sixty-second challenge). Mutants caught: no URL-profile check, no
  signer-key/CSR-key check.

## Traps

* **forge re-encodes what it parses.** The first job run failed "the RA is not a
  leaf of the SCEP Issuing CA": forge's ASN.1 decoder turns a BIT STRING that
  looks like DER into children, and a certificate or a signed-attribute set that
  goes through `certificateFromAsn1()`/`toDer()` comes back as different bytes.
  The client slices bytes with a TLV walker wherever a signature is involved.
* **forge's `pki` reads RSA certificates only**, so the EC-signer negative reads
  the issuer and serial with the same walker.
* **`node --check` passes and `require` loops**: `scep.ts` requires
  `scep_admin.ts` → `scep_console.ts`, which reads `scep.ts`'s tables — so the
  console requires `./scep` lazily and `scep.ts` assigns its exports first.
* **`admin-core/admin_views` may be required only from the allowed list** in
  `tests/admin_actions_layer.js`; `scep_console.ts` is on it and `scep_admin.ts`
  is not, which is why the console session's actor is read in the model.
* **A challenge secret is base64url** and so is not a PrintableString (`_` is
  outside its alphabet). forge writes challengePassword as UTF8String; OpenSSL
  may pick another string type for a value that is not printable. The core
  reads the value of whichever string type arrives — only forge's is exercised
  by the tests here.
