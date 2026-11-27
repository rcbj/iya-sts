---
title: Post-quantum migration plan
---

# Post-quantum migration plan

This page is for an operator planning how a deployment moves to post-quantum
cryptography, and for an assessor checking that a plan exists. It answers
four questions for each place iya-sts uses public-key cryptography: what it
does by default, what post-quantum options exist today and which setting
turns each on, what the wider ecosystem still prevents, and what comes next.
It is the migration plan ASVS 5.0.0 requirement 11.1.4 asks for.

The algorithms themselves are described elsewhere:
[Signature algorithms](crypto.md) for the per-realm signature policy,
[Post-quantum key establishment](post-quantum-encryption.md) for ML-KEM and
HPKE, [Key management](key-management.md) for the key inventory, and
[PKI](pki.md) for certificates. This page links to them rather than repeating
them.

## The rules the plan follows

* **No supported algorithm is ever removed.** That holds for classical
  algorithms and, above all, for post-quantum ones. A setting may stop a
  realm *using* an algorithm; the code that signs, verifies, encrypts or
  decrypts with it stays. A token, certificate, credential or message made
  before a change can still be checked after it.
* **Classical algorithms stay available** for every relying party, client,
  wallet and authenticator that cannot yet handle a post-quantum one.
* **Migration is by policy, per realm and per surface.** One realm can sign
  post-quantum only while another, serving older clients, signs RS256. Within
  a realm, JOSE, COSE, XML, Data Integrity, X.509 and TLS each have their own
  lists ([Signature algorithms](crypto.md#the-settings)).
* **Both are published during a move.** A new post-quantum key is published
  beside the classical one, so a relying party can fetch it before it is
  needed. A realm narrows to post-quantum only when its relying parties can
  verify it.
* **A combination the libraries cannot handle is refused, or falls back.**
  Where a client library or the TLS stack cannot read a construction, the
  service refuses the setting with an error code, or uses the classical
  default and logs that it did. It never sends something the other side
  cannot read. The composite certificate authority below is the main case.
* **Key establishment before signatures.** Data encrypted today can be
  recorded and decrypted once a quantum computer exists ("harvest now,
  decrypt later"). A signature only has to hold while it is checked. So TLS
  key exchange and encryption move first, and signatures follow as
  verifiers catch up.

### The hybrid and composite stance

A post-quantum algorithm is new, and a classical one is well studied. Where a
standard or draft allows it, iya-sts offers a **hybrid** that combines both,
so the result is secure while either half holds:

| Where | Hybrid offered | Default |
|---|---|---|
| TLS key exchange | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | **On**: first in `tls.groups` |
| JWE key establishment | X-Wing (`HPKE-10`, ML-KEM-768 + X25519) and the other HPKE hybrids | Off (`keys.offerKemEncryption`, `keys.encryptionKemAlgs`); on for OpenID4VP responses |
| JWS signatures | Six composite ML-DSA + ECDSA or EdDSA algorithms (draft-ietf-jose-pq-composite-sigs) | Published and accepted while `keys.postQuantumSigning` is on; no client gets one unless it asks |
| X.509 certificate authorities | A second, ML-DSA key and signature in each certificate (ITU-T X.509 clause 9.8) | Off (`pki.alternativeKeyAlgorithm` `none`) |
| A realm's signing keys | Each classical key certified together with an ML-DSA key (`keys.signerModel` `hybrid-groups`) | Off (`per-algorithm`) |
| OpenPGP | RFC 9980 composites: ML-DSA-65+Ed25519, ML-DSA-87+Ed448, ML-KEM-768+X25519, ML-KEM-1024+X448 | All allowed (`openpgp.algorithms`) |

Pure post-quantum algorithms (ML-DSA, SLH-DSA, ML-KEM) are offered beside the
hybrids, not instead of them.

## How to tell where a realm stands

* **Cryptography** (`/admin/crypto-metadata`), tab **Algorithms, by surface**,
  shows for each surface what the realm signs with and accepts, and why an
  algorithm is not used. **Key establishment, surface by surface** shows the
  same for encryption. `GET /admin-api/crypto` returns it as JSON, and
  `GET /crypto/metadata` publishes it with no sign-in.
* The same page's **Post-quantum** tab counts the TLS handshakes on this
  node by the key exchange they negotiated, and how many were ML-KEM
  (`GET /admin-api/tls/key-exchange`): whether clients are ready for
  `tls.pqcOnly`.
* `/admin/keys` and `/admin/pki` mark every post-quantum key with **PQC**, a
  composite with **PQC+**, an ML-KEM key with **PQC KEM** and a classical key
  with an alternative post-quantum key with **PQC alt**
  ([Which key pairs are post-quantum](pki.md#which-key-pairs-are-post-quantum)).
* **Monitoring → Passkeys** (`/admin/passkey-report`) counts people by
  whether their passkeys are post-quantum
  ([Measuring the move](passkeys.md#measuring-the-move-to-post-quantum-passkeys)).
* **Post-login activities** report each person's progress, also as a
  [Reporting](reporting.md) source
  ([Following the migration](post-login-activities.md#following-the-migration)).

## Surface by surface

Each section gives today's default, the post-quantum options and their
settings, what the ecosystem limits, and the next steps. Settings are per
realm unless the section says otherwise. Every one is described in
[Configuration](configuration.md).

**Every *Future* step has a trigger**: the named specification reaching
RFC (or W3C Recommendation, or a published ISO amendment), or a named
library shipping the support, and what iya-sts does when it arrives. A
date cannot be given, because none of these depend on iya-sts. When a
trigger fires, the change follows the rules above: the new algorithm is
added beside the old ones, nothing is removed, and a default changes only
in a release whose notes say so.

### JOSE and JWT signing

**Today.** A realm holds one key per JWS algorithm (`keys.signerModel`
`per-algorithm`): an RSA key, six curve keys and eleven post-quantum keys.
The post-quantum keys are ML-DSA-44, -65 and -87 (RFC 9964 for JOSE, FIPS
204), SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s (FIPS 205), and the six
composites `ML-DSA-44-ES256`, `ML-DSA-65-ES256`, `ML-DSA-87-ES384`,
`ML-DSA-44-Ed25519`, `ML-DSA-65-Ed25519` and `ML-DSA-87-Ed448`
(`common/pq_jose.js`). Tokens are signed RS256 by default.
`keys.postQuantumSigning` is **on by default**: the post-quantum keys are in
`/oauth2/jwks`, their algorithms are in the discovery lists, a client may
register one, and the realm verifies them. Each is also certified by the
realm's JOSE signing Issuing CA.

**Post-quantum options now.**

| Setting | Default | What it does |
|---|---|---|
| `keys.postQuantumSigning` | `true` | Publish, sign with when asked, and verify the post-quantum and composite JWS algorithms |
| `keys.signingAlgorithms` | empty | The algorithms the realm signs with, in order. Its first usable algorithm becomes the default for anything that does not name one |
| `keys.acceptedSigningAlgorithms` | empty | The algorithms the realm accepts from anybody |
| `keys.pqcOnly` | `false` | Sign only with post-quantum algorithms on JOSE, COSE, XML and Data Integrity |
| `keys.signerModel` | `per-algorithm` | `hybrid-groups` gives five signer groups keys of their own, each classical key certified with an ML-DSA key |
| a client's `id_token_signed_response_alg` and the other `*_signed_response_alg` | per client | One client moves to ML-DSA while the others stay on RS256 |

**What the ecosystem limits.**

* Most OAuth and OpenID Connect client libraries cannot verify ML-DSA yet,
  and some reject a JWK Set holding a key type (`AKP`) they do not know. A
  realm whose clients include such a library can turn
  `keys.postQuantumSigning` off; nothing post-quantum is then published.
* OpenID Connect Discovery requires RS256 for ID Tokens. Even with
  `keys.pqcOnly` on, RS256 stays for a client that registered it or
  registered no algorithm.
* The composites and SLH-DSA in JOSE are Internet-Drafts and may change.
* In an HSM, the realm's published ML-DSA and SLH-DSA keys are made in the
  module when it offers PKCS#11 3.2's `CKM_ML_DSA` or `CKM_SLH_DSA`
  mechanisms, and in software when it does not; the six composites are
  always made in software, because no PKCS#11 mechanism signs one
  ([Keys in an HSM](hsm.md#a-realms-signing-keys-in-the-hsm)).

**Next steps.**

1. *Done*: post-quantum keys published and verified by default; clients can
   opt in one at a time.
2. *Done*: per-realm ordered sign and accept lists, and `keys.pqcOnly`
   (#1368).
3. *Operator's step*: move clients that can verify ML-DSA to it, through their
   registration. Waits on each client's library.
4. *Operator's step*: put an ML-DSA algorithm first in `keys.signingAlgorithms`
   for a realm whose clients all verify it, then `keys.pqcOnly`. Waits on the
   same.
5. *Future*: an RS256-free ID Token default. **Trigger**: an OpenID
   Foundation errata set or successor of OpenID Connect Discovery 1.0
   (section 3, `id_token_signing_alg_values_supported`) and Core 1.0
   (section 15.1) that no longer requires RS256. **Then** a realm with
   `keys.pqcOnly` on signs the ID Token of a client that registered no
   algorithm with the first ML-DSA algorithm in `keys.signingAlgorithms`;
   RS256 stays for a client that asks for it.
6. *Future*: the composite and SLH-DSA JWS identifiers made final.
   **Trigger**: draft-ietf-jose-pq-composite-sigs and
   draft-ietf-cose-sphincs-plus published as RFCs. **Then** the RFC's
   identifiers are added beside the draft ones, which are still accepted
   from a client that registered them, and a release note says which
   identifier a new key is published under.

### SAML and XML signatures

**Today.** XML signatures (SAML 2.0, SAML 1.1, WS-Federation, WS-Trust) use
the realm's `xml` RSA key, `rsa-sha256` by default (`saml.signatureAlgorithm`).
Incoming XML signatures in RSA, ECDSA, EdDSA, DSA, ML-DSA and SLH-DSA are
verified ([SAML 2.0](saml2-sso.md)).

**Post-quantum options now.** In a realm with `keys.signerModel`
`hybrid-groups`, `saml.signatureAlgorithm` may be `ml-dsa-44`, `ml-dsa-65`,
`ml-dsa-87` or `slh-dsa-sha2-128s`, under the W3C xmldsig-more draft
identifiers. Each such key has a certificate of its own for KeyInfo, and SAML
metadata lists every XML signing certificate. `saml.signatureAlgorithms` and
`saml.acceptedSignatureAlgorithms` narrow what the realm signs with and
accepts. `keys.pqcOnly` also narrows XML, and needs `hybrid-groups` for a
post-quantum XML key to exist. See
[Signer groups](pki.md#signer-groups-a-key-pair-per-use-in-a-chosen-set-of-algorithms).

**What the ecosystem limits.**

* The ML-DSA and SLH-DSA XML identifiers are drafts, and few service
  providers verify them.
* **XML Encryption has no post-quantum option.** XML Encryption 1.1 defines no
  KEM, and no later W3C or IETF document adds one. Encrypted assertions stay
  RSA, and the encryption KeyDescriptor in metadata stays RSA.

**Next steps.**

1. *Done*: post-quantum XML signing in `hybrid-groups` realms, and
   verification of post-quantum XML signatures.
2. *Operator's step*: move a partner to an ML-DSA signature once it verifies
   one.
3. *Future*: post-quantum XML Encryption. **Trigger**: a W3C
   Recommendation or an IETF RFC (a successor of RFC 9231, *Additional XML
   Security Uniform Resource Identifiers*) that defines a key-encapsulation
   key transport for XML Encryption 1.1 with ML-KEM, and an XML security
   library a service provider uses (xmlsec1, Apache Santuario) that
   implements it. **Then** a realm can publish an ML-KEM encryption
   KeyDescriptor in SAML metadata and encrypt assertions to it, per service
   provider, with RSA kept for everybody else.
4. *Future*: the ML-DSA and SLH-DSA XML signature identifiers made final.
   **Trigger**: a W3C or IETF document publishing the xmldsig-more
   identifiers this service uses today. **Then** the published identifiers
   are added and the draft ones stay accepted.

### X.509 and the certificate authority hierarchy

**Today.** One Root, an Intermediate per realm, and an Issuing CA per use
case ([PKI](pki.md)). New authorities are RSA-3072 in product mode and
RSA-2048 in development (`pki.keyAlgorithm`). The realm's post-quantum JOSE
keys are leaves of the hierarchy, each with its own certificate. Certificate
paths with ML-DSA, SLH-DSA and composite signatures are validated
(`pki.acceptedSignatureAlgorithms` narrows them).

**Post-quantum options now.**

| Setting | Default | What it does |
|---|---|---|
| `pki.keyAlgorithm` | `rsa-3072` (product), `rsa-2048` (development) | A new authority's key: also ML-DSA or SLH-DSA |
| `pki.alternativeKeyAlgorithm` | `none` | A hybrid hierarchy: each authority holds a second, post-quantum key and signs every certificate twice (clause 9.8). ML-DSA-87 is the recommended value |
| `altKeyAlg` on `POST /admin-api/pki/build`, `build-root` and `build-scope` | | The same, per build |
| `pki.sshUserCaAlgorithms`, `pki.sshUserCaPqcOnly`, `pki.sshUserCaPqcAlongsideClassical` | `ssh-mldsa-65` first | The SSH user CA ([PKI](pki.md#the-signature-algorithms)) |

A hybrid-aware validator, this service among them, requires both signatures
on a path in its own hierarchy, so "RSA and ML-DSA" cannot be downgraded to
"RSA or ML-DSA" (`STS-PKI-0201`, `STS-PKI-0202`). A validator that does not
know the extensions sees an ordinary chain.

**What the ecosystem limits.**

* **No certificate authority may have a composite ML-DSA key.** The TLS
  library the listeners use cannot read one, and the Root, the process branch
  and each realm's Intermediate are on some listener's chain. A build that
  names a composite key is refused (`STS-PKI-0272`, `STS-PKI-0274`); where
  only `pki.keyAlgorithm` names one, the build uses the classical default and
  logs `STS-PKI-0273` or `STS-PKI-0275`. Composite keys are still issued to
  applications and people, marked *not usable by TLS clients*.
* A hybrid certificate is larger: an ML-DSA-87 alternative adds about 7 KB to
  each CA certificate and 4.6 KB to each leaf. Some products refuse it (an EST
  client that limits an enroll response to 4 KB, for example). A process
  branch whose chain would exceed a TLS client's 102400-byte certificate list
  is refused (`STS-PKI-0270`).
* **CRLs and OCSP responses carry one signature.** In a hybrid hierarchy
  (`pki.alternativeKeyAlgorithm`) they are signed with the authority's
  classical key only. ITU-T X.509 (10/2019) clause 9.8 lets the
  `altSignatureAlgorithm` and `altSignatureValue` extensions appear in a
  CRL, but RFC 5280 does not profile them, no verifier checks them, and an
  OCSP response (RFC 6960) has no place for a second signature at all. An
  authority built with an ML-DSA or SLH-DSA `pki.keyAlgorithm` signs its CRLs
  and OCSP responses with that key.
* **Stock OpenSSH cannot verify an ML-DSA certificate.** `ssh-mldsa-65` is
  this service's own wire name.

**Next steps.**

1. *Done*: pure ML-DSA and SLH-DSA authorities, hybrid hierarchies, and
   path validation of all of them.
2. *Operator's step*: rebuild a realm's branch with `altKeyAlg` once its
   relying parties accept the larger certificates. A hierarchy keeps what it
   was built with, so this is a rebuild, not a setting change.
3. *Done*: the `piv-reissue` post-login activity, which re-issues PIV
   smart-card certificates once the realm's EST Issuing CA is post-quantum
   ([The PIV re-issue](post-login-activities.md#the-piv-re-issue)). The rest
   of the smart-card migration is still open (#2009).
4. *Future*: composite-keyed authorities. **Trigger**:
   draft-ietf-lamps-pq-composite-sigs published as an RFC **and** an OpenSSL
   release whose default provider loads a composite ML-DSA key from a
   certificate on a TLS chain (OpenSSL 3.5 and 3.6 do not), shipped in the
   node release the image uses. **Then** `STS-PKI-0272` and `STS-PKI-0274`
   no longer refuse a composite `pki.keyAlgorithm`, and `STS-PKI-0273` and
   `STS-PKI-0275` no longer fall back.
5. *Future*: a second, post-quantum signature on CRLs and OCSP responses in
   a hybrid hierarchy. **Trigger**: an IETF RFC (LAMPS) profiling X.509
   clause 9.8's alternative signature for CRLs, or defining one for RFC 6960
   OCSP responses, and a verifier (OpenSSL) that checks it. **Then** a
   hybrid authority signs its CRLs (and, if profiled, its OCSP responses)
   with both keys, and a classical verifier sees what it sees today.
6. *Future*: an SSH user CA a stock `sshd` verifies post-quantum.
   **Trigger**: an RFC from the IETF sshm working group defining ML-DSA
   public keys and signatures for SSH (RFC 4253) and its certificates, and
   an OpenSSH release implementing it (OpenSSH 10 has post-quantum key
   exchange, `mlkem768x25519-sha256`, and no post-quantum signature).
   **Then** the standard name is added beside `ssh-mldsa-65`, which stays
   accepted, and the ML-DSA authority's line is published for
   `TrustedUserCAKeys`.

### TLS listeners

These settings are process-wide, not per realm. A custom listener has its own
copies in `listeners.realm` and `listeners.applications`
([Listeners](listeners.md)).

**Today.** Key exchange is already hybrid by default: `tls.groups` puts
X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 in its first tuple,
then X25519 and P-256, then X448, P-384 and P-521. The service image's
OpenSSL 3.5 negotiates them with any client that offers one. The server
certificate is RSA (`tls.certificateAlgorithms` `rsa`).
`tls.signatureAlgorithms` lists ML-DSA first, so a client certificate signed
with ML-DSA is accepted.

**Post-quantum options now.**

| Setting | Default | What it does |
|---|---|---|
| `tls.groups` | the three ML-KEM hybrids first | The key-exchange groups |
| `tls.pqcOnly` | `false` | TLS 1.3 only, 256-bit suites only, and ML-KEM groups only. A client offering none is refused at the handshake. Signatures are not restricted |
| `tls.certificateAlgorithms` | `rsa` | Add `ml-dsa-44`, `ml-dsa-65` or `ml-dsa-87`. With `rsa,ml-dsa-65` OpenSSL serves the certificate that matches what the client offered, so old and new clients share a port |
| `tls.signatureAlgorithms` | ML-DSA, then ECDSA, EdDSA, RSA-PSS, RSA PKCS #1 v1.5 | What the listeners sign with and accept from a client certificate |

**What the ecosystem limits.**

* An ML-DSA server certificate is refused by everything older than OpenSSL
  3.5, so RSA stays the default and comes first.
* `tls.pqcOnly` does not restrict signatures, because a recorded handshake
  cannot be forged later and few clients accept an ML-DSA certificate.
* Composite certificates cannot be loaded (above).

**How many clients come post-quantum.** Every completed handshake on the
main port, LDAPS, the debugger and the custom listeners is counted by the
key exchange group it negotiated, read from the session OpenSSL holds.
**Cryptography** (`/admin/crypto-metadata`), tab **Post-quantum**, draws
the counts per listener and group, and `GET /admin-api/tls/key-exchange`
answers them. **Monitoring → TLS connection** (`GET
/admin-api/tls-connection`) shows the group of the connection the request
came on ([TLS](tls.md#which-key-exchange-clients-negotiated)).

**Next steps.**

1. *Done*: hybrid key exchange by default, `tls.pqcOnly`, ML-DSA
   certificates served beside RSA on every listener, LDAPS included, and a
   count of the key exchanges clients negotiated.
2. *Operator's step*: turn on `tls.pqcOnly` once every client offers an
   ML-KEM group. Waits on clients; the key exchange counts show when the
   classical ones have stopped.
3. *Operator's step*: add an ML-DSA certificate with `rsa,ml-dsa-65`, and
   later put it first. Waits on clients' TLS stacks.

### Kerberos

**Today.** `krb5.enctypes` defaults to `18,17,20,19,23`. Product mode uses
19 and 20 (RFC 8009) alone unless `krb5.allowSha1Enctypes` is on, and never
23 (rc4-hmac). PKINIT replies are signed with an EC P-256 key
(`krb5.pkinitKdcKeyAlgorithm`).

**Post-quantum options now.** None, and none is needed for tickets: the
enctypes are symmetric, and Grover's algorithm leaves AES-256 at about
128-bit strength ([Kerberos](kerberos.md)).

**What the ecosystem limits.** No post-quantum PKINIT and no post-quantum
enctype is standardised, and no PKINIT client verifies a post-quantum
signature. PKINIT's Diffie-Hellman key agreement is the quantum-exposed part.

**Next steps.**

1. *Future*: ML-KEM key agreement and ML-DSA CMS signatures in PKINIT.
   **Trigger**: an IETF RFC updating RFC 4556 with an ML-KEM key
   establishment (no kitten working-group document defines one as of
   November 2026; the ML-DSA signature itself is RFC 9882 in CMS), **and**
   a PKINIT client that sends it: MIT Kerberos, Heimdal or Windows. **Then**
   the KDC accepts the ML-KEM exchange beside Diffie-Hellman and may sign
   its reply with an ML-DSA `krb5.pkinitKdcKeyAlgorithm`; Diffie-Hellman
   stays for every other client.

### S/MIME and OpenPGP

**Today.** Mail encrypted with S/MIME is RFC 5083 AuthEnvelopedData under
AES-256-GCM (`mail.smimeContentEncryption`). A recipient certificate may be
RSA, ECDH on P-256, P-384 or P-521, or **ML-KEM** (RFC 9935), carried as a
KEMRecipientInfo (RFC 9629) (#2124). OpenPGP accepts RFC 9980's composites and
its three SLH-DSA algorithms first, and the classical algorithms after them
(`openpgp.algorithms`).
[OpenPGP](openpgp.md) has the full list.

**Post-quantum options now.**

| Setting | Default | What it does |
|---|---|---|
| `openpgp.algorithms` | every supported algorithm, post-quantum first | Which algorithms a registered key may use: RFC 9980's ML-DSA composites and SLH-DSA-SHAKE-128s, -128f and -256s (v6 keys) sign, its ML-KEM composites encrypt |
| `openpgp.pqcOnly` | `false` | A newly registered key must use a post-quantum algorithm (a composite or SLH-DSA). Keys already registered keep working |
| the portal's **An ML-KEM certificate from this service** (the OpenPGP and S/MIME tab of Tokens and keys, `/portal/tokens-and-keys#tk-openpgp`; the account API's `smime-kem-challenge` and `smime-kem-issue`) | | The realm's EST Issuing CA issues an ML-KEM S/MIME certificate on a proof of possession (below) |
| `openpgp.pqcAlongsideClassical` | `false` | A newly registered key must carry a post-quantum and a separate classical algorithm |
| the `pqc-mail-encryption` post-login activity | off | Asks people whose mail is encrypted to a classical key to register an ML-KEM OpenPGP key or upload an ML-KEM S/MIME certificate. The classical OpenPGP key is kept beside the new one for the profile's `mailKeepClassical` days (90 by default) |

**What the ecosystem limits.**

* **A KEM key cannot sign a certification request**, so an ML-KEM S/MIME
  certificate is issued on a challenge-response proof of possession
  instead (RFC 9810, CMP, section 5.2.8.3.3; `KEMKPOPChallengeResp` in
  section 5.2.8.4): the person sends their
  ML-KEM public key, the service encapsulates to it, the person recovers
  the shared secret with `openssl pkeyutl -decap` (OpenSSL 3.5) and sends
  it back, and only then does the realm's EST Issuing CA issue the
  certificate (the `email` profile, `keyEncipherment` alone as RFC 9935
  requires). A person may still upload one instead
  ([OpenPGP](openpgp.md#an-ml-kem-smime-certificate-issued-here)).
* An OpenPGP card cannot hold an RFC 9980 key, so nothing registered by the
  mail activity is hardware-bound.
* **DKIM has no post-quantum algorithm registered** ([Mail](mail.md)).
  `mail.dkimAlgorithm` is `rsa-sha256` or `ed25519-sha256`.
* The activity is offered only where the runtime can encapsulate to ML-KEM
  (`crypto.smimeKemAvailable()`); a sign-in is never held for something that
  cannot be done.

**Next steps.**

1. *Done*: ML-KEM S/MIME recipients and RFC 9980 OpenPGP keys, SLH-DSA
   among them, and the post-login mail activity (#2009 phase 2).
2. *Done*: ML-KEM S/MIME certificates issued by the realm on a proof of
   possession (#2220).
3. *Future*: post-quantum DKIM. **Trigger**: an RFC that registers a
   post-quantum signing algorithm (ML-DSA or a composite) in the IANA
   DomainKeys Identified Mail *Key Type* registry of RFC 6376, as RFC 8463
   did for Ed25519, and a receiving mail provider that verifies it.
   **Then** `mail.dkimAlgorithm` gains the value, the DNS record to publish
   is shown beside the RSA or Ed25519 one, and a message can carry both
   signatures.

### WebAuthn and passkeys

**Today.** `webauthn.algorithms` requests, in order, `ML-DSA-87`, `ML-DSA-65`,
`ML-DSA-44` (RFC 9964), then `EdDSA`, `ES256` and `RS256`. An authenticator
picks the first it supports, so a device that can make an ML-DSA passkey
does, and every other device makes a classical one.

**Post-quantum options now.**

| Setting | Default | What it does |
|---|---|---|
| `webauthn.algorithms` | ML-DSA first, then classical | What a new passkey may use, in preference order |
| `webauthn.pqcAlongsideClassical` | `false` | Lets a person hold a classical and a post-quantum passkey side by side, each in its own lane |
| `webauthn.pqcOnly` | `false` | Requests ML-DSA only; a classical passkey already enrolled keeps signing in |
| the passkey policy's `postQuantumRequired` | `off` | `sign-in` refuses a classical passkey at sign-in (`STS-AUTHN-0356`); `registration-and-sign-in` refuses one at registration too (`STS-AUTHN-0355`). Selected per group or application |
| `webauthn.postQuantumAllowCredentials` | `narrow` | While post-quantum is required, which passkeys are offered |
| the `pqc-passkey-migration` post-login activity | off | Asks people with only a classical passkey to register an ML-DSA one |

**What the ecosystem limits.** Most authenticators cannot make an ML-DSA
passkey yet ([Where ML-DSA passkeys are expected to work](passkeys.md#where-ml-dsa-passkeys-are-expected-to-work)).
A save that requires post-quantum passkeys while the realm offers no ML-DSA
is refused (`STS-AUTHN-0357`).

**Next steps.**

1. *Done*: ML-DSA requested first, side-by-side lanes, the passkey report
   (#942), the migration activity (#939, #1096) and `postQuantumRequired`.
2. *Operator's step*: start `pqc-passkey-migration` for a group, follow
   *classical only* on the passkey report, then set `postQuantumRequired` for
   that group ([Before requiring post-quantum passkeys](passkeys.md#measuring-the-move-to-post-quantum-passkeys)).
   Waits on people's authenticators.

### Verifiable credentials

**Today.** `dc+sd-jwt` and `jwt_vc_json` credentials and their status lists
are signed with `oid4vci.credentialSigningAlgorithm`, `RS256` by default,
which may be any JWS algorithm including the post-quantum ones. Data Integrity
(the VC API, Bitstring status lists, zcap) has the `mldsa44-jcs-2024` and
`slhdsa128-jcs-2024` cryptosuites beside the ECDSA, EdDSA and `bbs-2023`
ones (`vc.cryptosuites`). OpenID4VP responses are encrypted to an X-Wing key
first and P-256 second (`oid4vp.responseEncryptionKeyAlgs`
`HPKE-10-KE,ECDH-ES`).

**Post-quantum options now.** `oid4vci.credentialSigningAlgorithm`,
`vc.cryptosuites`, `vc.acceptedCryptosuites`, `cose.algorithms` and
`oid4vp.responseEncryptionKeyAlgs`. A person can also choose the signing
algorithm when they make an offer on the portal.

**What the ecosystem limits.**

* No wallet accepts a post-quantum credential signature yet. With
  `oid4vc.walletCompatibility` on (off by default), every post-quantum and
  composite algorithm is left out of OpenID4VCI and OpenID4VP metadata.
* The W3C Quantum-Resistant Cryptosuites are a First Public Working Draft.
* `bbs-2023` (`ldp_vc`) is pairing-based and has no post-quantum
  replacement; it is the only algorithm that gives selective disclosure and
  unlinkable presentations.
* An ISO mdoc's Mobile Security Object is not signed with a post-quantum COSE
  algorithm ([Verifiable credentials](verifiable-credentials.md)).

**Next steps.**

1. *Done*: post-quantum credential signing, cryptosuites and hybrid response
   encryption.
2. *Operator's step*: move `oid4vci.credentialSigningAlgorithm` to ML-DSA once
   the realm's wallets and verifiers accept it. A credential already issued
   keeps its algorithm.
3. *Future*: a post-quantum mdoc signature (#1862 covers mdoc issuance).
   **Trigger**: an amendment or revision of ISO/IEC 18013-5 (section 9.1.2,
   the Mobile Security Object's `COSE_Sign1`) that lists an ML-DSA COSE
   algorithm (RFC 9964's identifiers), and a wallet that verifies it.
   **Then** an mdoc's Mobile Security Object may be signed with ML-DSA, per
   credential configuration, with ES256 kept for every other wallet.
4. *Future*: the W3C quantum-resistant cryptosuites made final.
   **Trigger**: the W3C *Quantum-Resistant Cryptosuites* reaching
   Recommendation. **Then** the final cryptosuite names are added beside
   `mldsa44-jcs-2024` and `slhdsa128-jcs-2024`, which stay accepted.

### KEM and encryption at rest

**Today.** Values the service stores are sealed with AES-256-GCM (or
AES-256-SIV for directory data, `keys.directoryCipher`) under data keys
wrapped by a key-encryption key ([Encryption at rest](encryption-at-rest.md)).
These are symmetric, and a 256-bit key is the usual choice for quantum
resistance. Refresh tokens are encrypted with `A256KW`
(`oauth2.refreshTokenEncryptionAlg`).

JWE encryption to and from clients can use ML-KEM and HPKE
([Post-quantum key establishment](post-quantum-encryption.md)):

| Setting | Default | What it does |
|---|---|---|
| `keys.offerKemEncryption` | `false` | Offer ML-KEM and HPKE where the realm encrypts to a client's key (ID Token, UserInfo, JARM, introspection, OpenID4VCI responses) |
| `keys.encryptionKemAlgs` | empty | Hold and publish a decryption key per algorithm, for request objects, assertions and OpenID4VCI requests encrypted to the realm |
| `oauth2.refreshTokenEncryptionAlg` | `A256KW` | May be any of the ML-KEM and HPKE algorithms; refresh tokens are sealed to the realm itself, so no client sees the change |
| `fedEncryptionKeyType` (per federation relationship) | | `x-wing` or `ml-kem-768`, so a partner can encrypt ID Tokens to this service |

**What the ecosystem limits.**

* Every JWE ML-KEM and HPKE algorithm is from an Internet-Draft, and the
  hybrid HPKE draft has expired. That is why both settings are off by default.
* Some client libraries reject a JWK Set with an `AKP` key, so
  `keys.encryptionKemAlgs` is empty by default.
* A key management service that wraps data keys with RSA (Azure RSA keys) is
  not post-quantum; an AES-256 key in the KMS avoids it
  ([The key-encryption key in a KMS](encryption-at-rest.md#the-key-encryption-key-in-a-key-management-service)).
* SAML and WS-Federation relationships cannot use post-quantum keys: XML
  Encryption has none.

**Next steps.**

1. *Done*: ML-KEM and HPKE in JOSE, X-Wing first for OpenID4VP, symmetric
   sealing at rest.
2. *Operator's step*: turn on `keys.offerKemEncryption` and set
   `keys.encryptionKemAlgs` for a realm whose clients handle AKP keys.
3. *Future*: on by default. **Trigger**: draft-ietf-jose-pqc-kem and
   draft-ietf-jose-hpke-encrypt published as RFCs (the hybrid HPKE draft,
   draft-reddy-cose-jose-pqc-hybrid-hpke, has expired and is not a
   trigger). **Then** a release turns `keys.offerKemEncryption` on by
   default under the RFC identifiers, the draft ones still accepted, and
   `keys.encryptionKemAlgs` stays empty until clients handle AKP keys.

## Moving a realm today

A realm moves in this order. Each step is reversible, and none removes an
algorithm.

1. **Look.** Open `/admin/crypto-metadata` in the realm and read **Algorithms,
   by surface** and **Key establishment, surface by surface**.
2. **Key establishment.** Keep `tls.groups` at its default. Where the
   clients allow it, set `keys.encryptionKemAlgs` and `keys.offerKemEncryption`,
   and start the `pqc-mail-encryption` activity.
3. **Publish.** Keep `keys.postQuantumSigning` on, so the realm's ML-DSA keys
   are in `/oauth2/jwks` and its algorithms in discovery before any token is
   signed with them. A relying party that caches the JWK Set has them in time.
4. **Move clients one at a time.** Register `id_token_signed_response_alg`
   (and the other `*_signed_response_alg` values) as an ML-DSA algorithm for
   each client whose library verifies it.
5. **Change the realm's order.** Put an ML-DSA algorithm first in
   `keys.signingAlgorithms`, and in `saml.signatureAlgorithms` and
   `vc.cryptosuites` where those surfaces are ready. Keep the classical
   algorithms in the list and in the accept lists, so a client that still
   asks for RS256 gets it.
6. **Certificates.** Rebuild the realm's branch with an alternative ML-DSA key,
   and add an ML-DSA listener certificate with `tls.certificateAlgorithms`.
7. **People.** Start `pqc-passkey-migration`, follow the passkey report, then
   set `postQuantumRequired`.
8. **Post-quantum only.** Turn on `keys.pqcOnly` and `tls.pqcOnly` only when
   the realm's relying parties all verify post-quantum signatures and offer
   ML-KEM groups. What the realm *accepts* does not change, so classical
   client assertions still verify.

Try each step in a test realm first ([Trust realms](trust-realms.md)). A write
that would lock a realm out, such as an accept list that leaves out what the
realm signs with, is refused ([Signature algorithms](crypto.md#how-a-list-behaves)).

## Known gaps

What the plan cannot do yet, and what would close each one.

| Gap | Where | What would close it |
|---|---|---|
| No composite-keyed certificate authority | `common/config.js` (`pki.keyAlgorithm`), `STS-PKI-0272`–`0275` | draft-ietf-lamps-pq-composite-sigs as an RFC, and an OpenSSL release (with the node release that links it) that loads a composite ML-DSA key from a certificate on a TLS chain; OpenSSL 3.5 and 3.6 do not |
| A hybrid hierarchy's CRLs and OCSP responses carry the classical signature only | [PKI](pki.md) | An IETF RFC profiling ITU-T X.509 (10/2019) clause 9.8's `altSignatureAlgorithm` and `altSignatureValue` for CRLs, or defining a second signature for RFC 6960 OCSP responses, and a verifier that checks it |
| No post-quantum PKINIT | `common/config.js` (`krb5.pkinitKdcKeyAlgorithm`) | An IETF RFC updating RFC 4556 with ML-KEM key establishment (none adopted as of November 2026), and a PKINIT client (MIT Kerberos, Heimdal, Windows) that sends it |
| No post-quantum XML Encryption | [Post-quantum key establishment](post-quantum-encryption.md) | A W3C Recommendation or IETF RFC (a successor of RFC 9231) defining an ML-KEM key transport for XML Encryption 1.1, and xmlsec1 or Apache Santuario implementing it |
| No post-quantum DKIM | [Mail](mail.md), `common/config.js` (`mail.dkimAlgorithm`) | An RFC registering a post-quantum algorithm in RFC 6376's IANA DKIM Key Type registry, as RFC 8463 did for Ed25519, and receivers that verify it |
| An mdoc's Mobile Security Object is not post-quantum | [Verifiable credentials](verifiable-credentials.md) | An amendment of ISO/IEC 18013-5 listing an ML-DSA COSE algorithm (RFC 9964) for the Mobile Security Object, and wallets that verify it |
| `ssh-mldsa-65` is this service's own wire name; stock OpenSSH cannot verify it | [PKI](pki.md) | An RFC from the IETF sshm working group defining ML-DSA public keys and signatures for SSH (RFC 4253) and its certificates, and an OpenSSH release that implements it; OpenSSH 10 has post-quantum key exchange (`mlkem768x25519-sha256`) and no post-quantum signature |
| Credential-signing keys have no scheduled rotation, so a move to a new algorithm does not retire the old key on a schedule | `docs/v1.2.0/verifiable-credentials.md:958` | A rotation job for credential-signing keys |

## Related

* [Signature algorithms](crypto.md)
* [Post-quantum key establishment](post-quantum-encryption.md)
* [Key management](key-management.md)
* [PKI](pki.md)
* [TLS](tls.md)
* [Passkeys](passkeys.md)
* [Post-login activities](post-login-activities.md)
* [OpenPGP](openpgp.md)
* [Security in product mode](product-security.md)
