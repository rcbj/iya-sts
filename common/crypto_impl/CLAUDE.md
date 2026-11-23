# common/crypto_impl/

**`algorithm_registry.js` (#1368, phase 1) is the one exception to "an engine"
here**: it signs nothing. It is every signature algorithm once, with its
spelling on every surface, and `JWS_ALGS`, `COSE_SIGNATURE_ALGS`,
`XML_SIGNATURE_METHODS`, the PKI ids in `config.js` and the rest are views of
it, each keeping its name, shape, members and order. **Add an algorithm there,
in both `ROWS` and `RECORDED`**; `tests/algorithm_registry.js` fails on one
without the other, and pins each view's bytes against the tree before the
registry existed. `ROWS` is preference order, what a console draws; `RECORDED`
is what each surface does today, which is what an empty setting means. They are
different on purpose, because post-quantum signing is on by default and
preference order would otherwise move every default signature to ML-DSA. The
file's header argues the rest, including why each COSE consumer keeps its own
set. `pq_jose.js`, `x509.js` and `xmldsig.js` keep their own tables because they
run on them; the same test holds them equal.

**EVERY FILE IN THIS DIRECTORY IS THIS SERVICE'S OWN SINCE #1280
(2026-11-02).** They began as byte-identical copies of the parent project's
(`../id-proto-debugger`) and stopped being copies in three steps:
`pqc.js`, `pqc_x509.js` and `xmldsig.js` on #363 (rcbj: "this is its own
project that has different requirements"), `bbs2023.js` with its identity
context on #663, and the other five (`x509.js`, `key_material.js`,
`jose_jwe.js`, `crypto_bytes.js`, `symmetric_crypto.js`) on #1280, when rcbj
ended vendoring them altogether. They are edited here, carry this
repository's SPDX lines, follow its rules (`tests/error_codes.js` and
`tests/no_periodic_timers.js` scan them), and are NOT re-synced from the
parent in either direction. The one exception is the two W3C contexts in
`contexts/`, which are W3C's documents and stay byte for byte (`REUSE.toml`
names their licence).

**What the copies were for is still true of the code**, and is the reason to
be careful here rather than a rule against editing: most of these files are
the far end of an exchange with the debugger, and a change that the
debugger's own code does not share shows up as a signature that does not
verify rather than as a diff. The parent's byte-compare and cross-suite tests
(`tests/krb5_codec_sync.js`, `tests/bbs2023_cryptosuite.js`) are the parent's
business now; nothing here is owed to them.

**`bbs2023.js` and `contexts/iya_identity_v1.json` (#663)**: a credential
this service mints may not carry another project's name, and the parent's
copy signed against `https://idptools.com/contexts/identity/v1`. The identity
context is now `https://iyasec.io/contexts/identity/v1`, its own terms
(`IdentityCredential`, `isOver18`, `isOver21`) under
`https://iyasec.io/contexts/identity#`. A credential issued before #663
named the old context and is refused by both loaders here; there is no
back-compatibility row for it.

`pqc.js` and `pqc_x509.js` rest on `common/pq_native.js` (ML-DSA, SLH-DSA
and ML-KEM on node's OpenSSL) rather than on `@noble/post-quantum`;
`common/CLAUDE.md` argues it.

| File | What it is |
|---|---|
| `x509.js` | Certificate building and parsing. `node-forge`, which `helpers.js` and `tls/tls_server.js` use, **cannot sign with an EC key at all**, and SPIFFE issues P-256. Since 2026-09-10 it also carries PKCS#10 and the post-quantum encodings — see the re-sync below. |
| `pqc.js`, `pqc_x509.js` | The post-quantum algorithms and their ASN.1, which `key_material.js` and `x509.js` rest on, on node's OpenSSL through `common/pq_native.js`. **They are NOT what signs a JWS here** — that is `common/pq_jose.js`, deliberately independent, and the section at the foot of this file argues the difference. |
| `symmetric_crypto.js` | The AES paths `jose_jwe.js` rests on. |
| `key_material.js` | Key generation and JWK/PEM conversion. What `x509.js` rests on. |
| `jose_jwe.js` | JWE, for the same reason. |
| `pkcs11.js` | **This service's own (#1955 P8).** The PKCS#11 engine: a token's session pool, the three wrapping mechanisms and their versioned stored forms, key-pair generation, `C_SignAsync`, and RSA-OAEP / ECDH asked asynchronously through `C_DecryptAsync` / `C_DeriveKeyAsync`. A blocking `C_Sign`, `C_Decrypt` or `C_DeriveKey` (asked synchronously, or by a module with no asynchronous call) runs only while `keys.pkcs11SynchronousSign` is on; otherwise `STS-KEYS-0209` before the Init call. Since the P8 follow-up (2026-11-23, rcbj: "I do not want this activity to block the main event loop") every service door reaches the asynchronous calls (`crypto.js`'s `…OffLoop()` twins), so off is never a refusal there. The calls pkcs11js has no asynchronous form for (sessions, logins, searches, attribute reads, every `C_*Init`, the `k1` wrap's object, re-initialisation) are made by the module's control thread, `pkcs11_thread.js`; a re-initialisation is made once per module for every token on it, after its operations drain. Takes the binding (`pkcs11js` or a test's fake) from its caller and requires none; reached only through `crypto.js` section 19 (`common/CLAUDE.md`, *Keys in a hardware security module*). |
| `pkcs11_thread.js` | **This service's own (#1955 P8 follow-up).** A PKCS#11 module's control thread, started by `pkcs11.js`'s `Pkcs11Control`: it loads the binding again from the file its caller loaded it from and answers `{ id, op, args }` with `pkcs11.js`'s own `CONTROL_OPS`, so the two cannot disagree. Every failure is an answer, never an exception out of the thread. |
| `crypto_bytes.js` | The byte-level helpers those three rest on. |
| `bbs2023.js` | The BBS primitives (Sign, Verify, ProofGen, ProofVerify) behind `bbs-2023`, the BLS12-381 G2 Multikey, and, read only, the pre-1.1 private format. The W3C cryptosuite itself is `oid4vc/vc_bbs.ts` since #1878. |
| `xmldsig.js` | **XML Signature and XML Encryption, and since 2026-08-27 the signer behind every signed document this service emits.** It is not a library somebody found — it is the OTHER END of most of these exchanges: the debugger signs, verifies, encrypts and decrypts with this exact file on its WS-Trust, SAML and Digital Signature pages. Both ends of a SAML exchange now canonicalize with the same code, which matters because a disagreement about c14n is invisible until it is a signature that verifies on one side and not the other. |
| `openpgp_engine.js` | **openpgp.js, wrapped (#1955 P6, rcbj's D3)**: read ONE public key (never a secret one), describe it, verify a cleartext signature by a signing-capable key of it, encrypt to it. Every call gets its own openpgp.js config, so nothing changes the library's globals; the library is loaded at the first call. The policy — the algorithm allow list, the challenge, freshness, S/MIME — is `common/crypto.js` section 19, the only file that requires this one (`tests/crypto_centralised.js` refuses `openpgp` anywhere else). |
| `contexts/` | The three JSON-LD contexts `bbs2023.js` reads: the two W3C ones (W3C's, byte for byte) and `iya_identity_v1.json`, this issuer's own since #663. |

**`contexts/` is inside this directory because `bbs2023.js` resolves
`path.join(__dirname, 'contexts')`.** That is the whole reason it moved here in
the 2026-08-23 reorganisation rather than staying at the package root: the
alternative, then, was editing what was still a vendored file.

Nothing in here requires anything of this service outside this directory but
two leaves — `pqc.js` requires `../pq_native`, and `key_material.js`
`../error_codes` (#1280) — which is what made the copies possible, and is
still worth keeping: `x509.js` requires `./jose_jwe`, `./key_material` and
`./pqc_x509`; `jose_jwe.js` requires `./crypto_bytes` and `./symmetric_crypto`;
`key_material.js` requires `./jose_jwe`, `./pqc` and `./pqc_x509`; `pqc_x509.js`
requires `./pqc` and `./crypto_bytes`; `bbs2023.js` requires nothing local at
all, and `xmldsig.js` requires nothing local either — only `bunyan` and
`node-forge`. The reorganisation did not have to touch a single line in this
directory.

**THAT LIST IS WHAT A RE-SYNC HAD TO WALK (until #1280), and the 2026-09-10
one found two files missing from it**: the parent's current `jose_jwe.js` requires
`./symmetric_crypto` and its `key_material.js` requires `./pqc`, neither of
which was here. A copy whose own requires are not satisfied fails at LOAD with
`Cannot find module`, which names a file nobody chose — so copy the file, then
walk what it requires, and repeat until nothing is missing.

The PKI modules are read from `spiffe/spiffe_ca.js`, `common/pki.js` and
`common/pki_authoring.js`; `bbs2023.js` from
`common/helpers.js` and the three `oid4vc/` modules that sign; `xmldsig.js` from
`common/crypto.js` and from nothing else.

---

## `xmldsig.js` NEEDS TWO GLOBALS AND WILL NOT SAY SO

It is the parent project's BROWSER code, where `DOMParser` and `XMLSerializer`
are ambient. Node has neither. `common/crypto.js` installs `@xmldom/xmldom` as
both **before it requires this file**, which is what `api/server.js` does over
there for the same file — so it is the established way to run it server-side
rather than something invented here.

**The ordering is load-bearing and the failure is misleading.** Nothing is
captured at require time, so a `require` that happened first would load
perfectly and then fail on the first signature with `DOMParser is not defined`,
which names neither the file nor the real problem. Require this module only
through `common/crypto.js`.

`genId()` in there also uses `window.crypto` and would throw in node. Nothing
here calls it — `helpers.js` has its own — and it is exported, so do not start.

`kerberos/krb5_spnego.js` and the rest of the Kerberos codec are not here —
they sit beside the KDC they belong to, for the reason `kerberos/CLAUDE.md`
gives, and became this service's own on #1280 too.

---

## The JSON-LD contexts are load-bearing

`bbs2023.js` reads the three files in `contexts/` **at require time, at module
scope**. A missing one is not a degraded feature — the service does not start. They
ship with the service rather than being fetched because Data Integrity signs canonicalized
statements, so a one-byte difference in a context fails every signature later and
looks like a crypto bug.

`bbs2023.js` reads `./contexts` only, since #663. Where the parent puts a
copy of it is the parent's concern: this file is not vendored to it.

---

## THE 2026-09-10 RE-SYNC, AND `pqc.js` — WHICH THIS FILE USED TO SAY WAS NOT HERE

*History, kept because the reasoning still applies to the code: there are no
re-syncs since #1280.*

**Six files were re-copied from the parent on 2026-09-10 and two of them are
new**, for `/admin/pki`'s Certificate Workbench: it needs the
PKCS#10 request and the post-quantum certificate encodings, and the copies here
were a snapshot from before either existed.

| File | What changed |
|---|---|
| `x509.js` | re-copied. It gained `certificationRequest()` (PKCS#10), the X.509 (2019) clause 9.8 alternative-signature machinery, and the post-quantum algorithm identifiers |
| `key_material.js` | re-copied. `KEY_ALGS` is now seven classical entries plus thirty-four generated from `pqc_x509.js`'s registry |
| `jose_jwe.js`, `crypto_bytes.js` | re-copied, because the two above rest on them |
| `symmetric_crypto.js` | **new** — `jose_jwe.js` requires it |
| `pqc.js`, `pqc_x509.js` | **new** — the post-quantum algorithms and their ASN.1 |

**THE DRIFT WAS REAL AND IT IS WHAT THIS DIRECTORY EXISTED TO PREVENT.** Every
one of the four existing copies had fallen behind: 963 differing lines in
`x509.js`, 690 in `jose_jwe.js`, 211 in `key_material.js`, six in
`crypto_bytes.js`. "Byte-identical" was the rule and had stopped being the
state, in the one direction nobody notices — the parent grew and these did not,
so nothing here broke and this service quietly had an older encoder than the
project it is the far end of.

### `pqc.js` IS HERE AND `common/pq_jose.js` IS STILL THIS SERVICE'S OWN

That file's header spends a page on why the debugger's post-quantum JOSE was
NOT vendored: this service exists to be the far end of that code, and the value
of the arrangement is INDEPENDENCE — the mock signs, the debugger reads, and a
misunderstanding they share is one neither can see.

**That argument is about JOSE and it is untouched.** Nothing about signing a JWS
changed: `common/pq_jose.js` is still this service's own reading of the AKP JWK,
the composite message, the key and signature layouts, and the traditional half
of every composite still runs on node's OpenSSL rather than on the curve library
the debugger uses. **`common/worker_pool.js`'s job table still runs that file and
not this one.**

What arrived is a CERTIFICATE ENCODER, and the independence argument does not
reach it for a reason worth stating rather than assuming: **there was no second
implementation of post-quantum X.509 here to lose.** Vendoring `pqc.js` added a
capability; it did not collapse two readings into one. The two are used for
different things by different modules and must stay that way —

* **`common/pq_jose.js`** — JWS. `crypto.js` routes an `alg` to it, the worker
  pool runs it. **The debugger's own reading of the same constructions is what
  it is checked against, and that check is the point of it.**
* **`common/crypto_impl/pqc.js` and `pqc_x509.js`** — the ASN.1 inside a
  certificate, reached only through `key_material.js` and `x509.js`.

**DO NOT WIRE THEM TOGETHER.** Generating a key on the worker pool (which runs
`pq_jose.js`) and handing it to the certificate encoder (which expects
`pqc_x509.js`'s byte layout) is precisely the class of defect the independence
exists to expose, introduced to save a console button a few seconds.
`common/pki_authoring.js`'s header says the same thing from the other end, and
says what it costs instead: an SLH-DSA key generation takes seconds. **Since
#1464 those seconds are on libuv's thread pool**, not this thread:
`pqc_x509.js`'s `generateKeyPair()` and `sign()` call the SAME primitive's
`keygenAsync()` and `signAsync()` (`pq_native.js`), so the independence above is
untouched and only the waiting moved.

**WHAT *DID* CROSS ON 2026-09-13 IS A PUBLIC KEY, AND THE RULE ABOVE STANDS.**
A realm's eleven post-quantum signing keys became leaves of `common/pki.js`'s
hierarchy, which needs their public keys in a certificate. So the AKP JWK
`pq_jose.js` already publishes is written into a SubjectPublicKeyInfo through
`pqc_x509.js` — and that is not the wiring forbidden above, for a reason worth
stating rather than assuming: nothing GENERATED by one reading is handed to the
other to USE. No private key of those eleven reaches `pqc_x509.js`, it
signs with none of them, and the certificate is signed by the Issuing
CA's own key. **The one place the two byte layouts differ** — an ECDSA
composite half's `0x04` — is written out in `pki.js`'s
`pqSubjectPublicKeyPem()` rather than left for either side to assume, and
`tests/pq_key_certification.js` holds the two readings against each other: a
`pq_jose.js` signature must verify under `pqc_x509.js` against the key in the
certificate. That is the independence doing its job at the seam, where before
there was no seam for a disagreement to show at.

### What it cost to install

**`@noble/curves` and `@noble/hashes`, pinned EXACTLY at `1.4.0`.** `pqc.js`
requires `@noble/curves/p256` and five more v1 subpaths, which v2 does not
export — and the pins match the parent's and `tests/package.json`'s, which are
exact for a reason that now applies here too: a second opinion that floats to a
different version of the curve library than the opinion it is being compared
with is not a second opinion.

**1.4.0 cannot write or read a P-521 ECDSA signature in DER (#445).** Its
codec puts the SEQUENCE length in one byte, and a P-521 Ecdsa-Sig-Value is
always longer than 127 bytes, so the byte it writes is not a length. The
release that fixes the codec is 1.6.0. It is not taken: later 1.x releases
change `sign()`'s nonce, 2.x is ESM-only and drops those subpaths, and the
parent project and the protocol copies in `tests/protocol/` still pin 1.4.0.
`pqc_x509.js` keeps the scalar arithmetic on this library and writes and
reads the Ecdsa-Sig-Value itself. P-256 and P-384 encodings are unchanged.

`@noble/post-quantum` was already a dependency (`common/pq_jose.js`) and its own
nested `@noble/hashes` is unaffected.

## `xmldsig.js` READS AND SIGNS HMAC SINCE #658 (2026-11-03)

Four HMAC SignatureMethods (`xmldsig#hmac-sha1`, `xmldsig-more#hmac-sha256`,
`-sha384`, `-sha512`) are in `SIG_METHODS`, family `hmac`, keyKind `secret`,
for a WS-Security signature keyed by a Kerberos token's session key (the
Kerberos Token Profile 1.1 section 3.2). The engine verifies none itself:
`verifyXml()` hands the octets to the caller's `opts.verifier`, which
`common/crypto.js`'s `verifyWsSecurityHmac()` supplies. `signWsSecurity()`
takes the post-quantum path's `opts.signer` / `opts.keyInfoXml` for one. An
X.509 path that meets an HMAC method refuses it at
`verifyXmlSignatureValue()`'s key-type check, because no public key is
`secret`. The rows also appear on `/admin/crypto-metadata`'s XML table.
