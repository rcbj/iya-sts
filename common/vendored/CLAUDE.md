# common/vendored/

**Every file in this directory is somebody else's. DO NOT EDIT THEM HERE.**

They are byte-identical copies of files in the parent project
(`../id-proto-debugger`), and two of the parent's tests exist to keep them
that way — `tests/krb5_codec_sync.js` compares the Kerberos codec, and
`tests/bbs2023_cryptosuite.js` drives BOTH implementations of the cryptosuite
against the same vectors. A local "improvement" here is not a change to this
service, it is a divergence between two halves of one exchange, and the symptom
arrives as a signature that does not verify rather than as a diff.

| File | Why it is vendored |
|---|---|
| `x509.js` | Certificate building and parsing. `node-forge`, which `helpers.js` and `tls/tls_server.js` use, **cannot sign with an EC key at all**, and SPIFFE issues P-256. Since 2026-09-10 it also carries PKCS#10 and the post-quantum encodings — see the re-sync below. |
| `pqc.js`, `pqc_x509.js` | **New on 2026-09-10.** The post-quantum algorithms and their ASN.1, which `key_material.js` and `x509.js` rest on. **They are NOT what signs a JWS here** — that is `common/pq_jose.js`, deliberately independent, and the section at the foot of this file argues the difference. |
| `symmetric_crypto.js` | The AES paths `jose_jwe.js` rests on. |
| `key_material.js` | Key generation and JWK/PEM conversion. What `x509.js` rests on. |
| `jose_jwe.js` | JWE, for the same reason. |
| `crypto_bytes.js` | The byte-level helpers those three rest on. |
| `bbs2023.js` | The bbs-2023 Data Integrity cryptosuite, for `ldp_vc`. |
| `xmldsig.js` | **XML Signature and XML Encryption, and since 2026-08-27 the signer behind every signed document this service emits.** It is not a library somebody found — it is the OTHER END of most of these exchanges: the debugger signs, verifies, encrypts and decrypts with this exact file on its WS-Trust, SAML and Digital Signature pages. Both ends of a SAML exchange now canonicalize with the same code, which matters because a disagreement about c14n is invisible until it is a signature that verifies on one side and not the other. |
| `contexts/` | The three JSON-LD contexts `bbs2023.js` reads. |

**`contexts/` is inside this directory because `bbs2023.js` resolves
`path.join(__dirname, 'contexts')`.** That is the whole reason it moved here in
the 2026-08-23 reorganisation rather than staying at the package root: the
alternative was editing a vendored file, which is the one thing this directory
forbids. Its first candidate — `path.join(__dirname, '..', 'client', 'src',
'contexts')` — is the parent project's layout and resolves to nothing here,
which is exactly what that `existsSync` guard is for.

Nothing in here requires anything outside this directory, and that is what makes
the copies possible: `x509.js` requires `./jose_jwe`, `./key_material` and
`./pqc_x509`; `jose_jwe.js` requires `./crypto_bytes` and `./symmetric_crypto`;
`key_material.js` requires `./jose_jwe`, `./pqc` and `./pqc_x509`; `pqc_x509.js`
requires `./pqc` and `./crypto_bytes`; `bbs2023.js` requires nothing local at
all, and `xmldsig.js` requires nothing local either — only `bunyan` and
`node-forge`. The reorganisation did not have to touch a single line in this
directory.

**THAT LIST IS WHAT A RE-SYNC HAS TO WALK, and the 2026-09-10 one found two
files missing from it**: the parent's current `jose_jwe.js` requires
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

`kerberos/krb5_spnego.js` is vendored too and is NOT here — it sits beside the
Kerberos codec it belongs to, for the reason `kerberos/CLAUDE.md` gives.

---

## The JSON-LD contexts are load-bearing

`bbs2023.js` reads the three files in `contexts/` **at require time, at module
scope**. A missing one is not a degraded feature — the service does not start. They
are vendored rather than fetched because Data Integrity signs canonicalized
statements, so a one-byte difference in a context fails every signature later and
looks like a crypto bug.

`bbs2023.js` resolves two layouts: `../client/src/contexts` (its position in the
parent project) and `./contexts` (this repo). Do not simplify that away — it is what
let the file be copied here unchanged.

---

## THE 2026-09-10 RE-SYNC, AND `pqc.js` — WHICH THIS FILE USED TO SAY WAS NOT HERE

**Six files were re-copied from the parent on 2026-09-10 and two of them are
new**, for `/admin/pki`'s Certificate & Key Configuration pane: it needs the
PKCS#10 request and the post-quantum certificate encodings, and the copies here
were a snapshot from before either existed.

| File | What changed |
|---|---|
| `x509.js` | re-copied. It gained `certificationRequest()` (PKCS#10), the X.509 (2019) clause 9.8 alternative-signature machinery, and the post-quantum algorithm identifiers |
| `key_material.js` | re-copied. `KEY_ALGS` is now seven classical entries plus thirty-four generated from `pqc_x509.js`'s registry |
| `jose_jwe.js`, `crypto_bytes.js` | re-copied, because the two above rest on them |
| `symmetric_crypto.js` | **new** — `jose_jwe.js` requires it |
| `pqc.js`, `pqc_x509.js` | **new** — the post-quantum algorithms and their ASN.1 |

**THE DRIFT WAS REAL AND IT IS WHAT THIS DIRECTORY EXISTS TO PREVENT.** Every
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
* **`common/vendored/pqc.js` and `pqc_x509.js`** — the ASN.1 inside a
  certificate, reached only through `key_material.js` and `x509.js`.

**DO NOT WIRE THEM TOGETHER.** Generating a key on the worker pool (which runs
`pq_jose.js`) and handing it to the certificate encoder (which expects
`pqc_x509.js`'s byte layout) is precisely the class of defect the independence
exists to expose, introduced to save a console button a few seconds.
`common/pki_authoring.js`'s header says the same thing from the other end, and
says what it costs instead: an SLH-DSA key generation takes seconds and takes
them on this thread.

### What it cost to install

**`@noble/curves` and `@noble/hashes`, pinned EXACTLY at `1.4.0`.** `pqc.js`
requires `@noble/curves/p256` and five more v1 subpaths, which v2 does not
export — and the pins match the parent's and `tests/package.json`'s, which are
exact for a reason that now applies here too: a second opinion that floats to a
different version of the curve library than the opinion it is being compared
with is not a second opinion.

`@noble/post-quantum` was already a dependency (`common/pq_jose.js`) and its own
nested `@noble/hashes` is unaffected.
