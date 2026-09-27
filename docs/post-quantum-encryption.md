---
title: Post-quantum key establishment
---

# Post-quantum key establishment

iya-sts can encrypt a JWE with **ML-KEM**, and with **HPKE over ML-KEM or a
PQ/T hybrid** such as X-Wing (ML-KEM-768 + X25519). A PQ/T hybrid is secure as
long as either half is. These algorithms matter for anything encrypted today:
ciphertext captured now can be stored and opened once a quantum computer
exists, while a signature only has to hold when it is checked.

> **Every algorithm on this page comes from an Internet-Draft, not an RFC.**
> The algorithm names, the key format, and the key derivation can still
> change. Use them to test post-quantum clients and wallets. Do not assume
> another implementation reads them the same way until the drafts are
> published.

## The algorithms

| `alg` | Construction | Specification |
|---|---|---|
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | ML-KEM direct key agreement: the KEM's shared secret, through KMAC256, is the content key | draft-ietf-jose-pqc-kem-05 |
| `ML-KEM-512+A128KW`, `ML-KEM-768+A192KW`, `ML-KEM-1024+A256KW` | The same, with the derived key wrapping the content key (AES Key Wrap) | draft-ietf-jose-pqc-kem-05 |
| `HPKE-0` … `HPKE-7`, and `HPKE-0-KE` … `HPKE-7-KE` (except `-4-KE` and `-6-KE`) | HPKE over the classical DHKEMs (P-256, P-384, P-521, X25519, X448) | draft-ietf-jose-hpke-encrypt-22 |
| `HPKE-8`, `HPKE-9` (+ `-KE`) | HPKE, ML-KEM-768 + P-256 hybrid, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |
| **`HPKE-10`, `HPKE-11` (+ `-KE`)** | **HPKE, X-Wing (ML-KEM-768 + X25519)**, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |
| `HPKE-12`, `HPKE-13` (+ `-KE`) | HPKE, ML-KEM-1024 + P-384 hybrid, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |
| `HPKE-14`, `HPKE-15`, `HPKE-16` (+ `-KE`) | HPKE, pure ML-KEM-512 / 768 / 1024, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |

Each HPKE suite comes in two forms:

* **`HPKE-n` (Integrated Encryption)** encrypts the payload with HPKE itself.
  The JWE has **no `enc`** header, and the IV and tag segments are empty.
* **`HPKE-n-KE` (Key Encryption)** uses HPKE to encrypt an ordinary content
  key. The `enc` header works as it does for any other algorithm.

Which draft revisions were implemented, and why:

* **draft-ietf-jose-pqc-kem**: revision **-06** (July 2026) removed every JOSE
  section and now covers COSE only. **-05** is the last revision that defines
  the JWE algorithms, so that is what is implemented. One exception: -05
  describes an AKP `priv` as a 32-byte seed, which cannot produce an ML-KEM
  key. iya-sts uses the 64-octet `d || z` seed that -06 corrected it to.
* **draft-reddy-cose-jose-pqc-hybrid-hpke-11** is an *individual* draft that
  expired in August 2026. It is still the only document that names a hybrid
  JWE algorithm.

## Keys

A post-quantum key is a JWK of type **`AKP`**, and it names exactly one
algorithm:

```json
{ "kty": "AKP", "alg": "HPKE-10-KE", "use": "enc", "kid": "…",
  "pub": "<base64url encapsulation key>" }
```

The private half adds `priv`: a 64-octet seed for an ML-KEM key, or a
32-octet seed for a hybrid. A key for `ML-KEM-768` does not work for
`ML-KEM-768+A192KW` or `HPKE-15`. That strictness is deliberate. The classical
HPKE suites use ordinary `EC` or `OKP` keys on the curve the suite names.

## Encrypting to a client

A client opts in by registering one of these algorithms and publishing a
matching key in its `jwks` or `jwks_uri`. This applies to:

* `id_token_encrypted_response_alg` (the ID Token and the Logout Token)
* `userinfo_encrypted_response_alg`
* `authorization_encrypted_response_alg` (JARM)
* `introspection_encrypted_response_alg`
* an OID4VCI `credential_response_encryption.jwk` whose `alg` names a Key
  Encryption form

The server advertises the algorithms in the matching
`*_encryption_alg_values_supported` lists. There is nothing to switch on. If
the client registered an `enc` next to an Integrated `HPKE-n` algorithm, that
`enc` is ignored, because the JWE has none.

If a client registers an algorithm and has no key of the right type, it is
told so at registration or when a token would be encrypted. The token is
**never** sent in the clear instead.

## Encrypting to a realm (off by default)

**Warning: a realm publishes no post-quantum decryption key until an
administrator enables it.** An AKP key is a key type many clients' JOSE
libraries cannot parse yet, and some of them reject the entire JWKS. Enable
this only when every client that reads the realm's JWKS is known to handle
AKP keys.

The setting is `keys.encryptionKemAlgs` (Key material, per realm): a list of
the ML-KEM or HPKE algorithms the realm should hold a key for. For each one
listed, the realm:

* publishes a key in `/oauth2/jwks` with `use: enc` and that `alg`;
* advertises the algorithm in `request_object_encryption_alg_values_supported`
  and `assertion_encryption_alg_values_supported`, and in OID4VCI's
  `credential_request_encryption.jwks`;
* decrypts request objects, RFC 7523 and 7522 assertions, and OID4VCI
  Credential Requests encrypted to that key.

The keys are persisted and sealed, and shared with every node like the realm's
other keys. Removing an algorithm from the list stops the realm publishing and
accepting it. Adding the algorithm back restores the same key.

## OpenID4VP wallet responses

A `direct_post.jwt` or `dc_api.jwt` request offers one ephemeral key per
algorithm in `oid4vp.responseEncryptionKeyAlgs`. The default is
**`HPKE-10-KE,ECDH-ES`**:

* the X-Wing key comes first, so a wallet that supports it protects the
  response against a future quantum adversary;
* the P-256 ECDH-ES key that OpenID4VC HAIP requires comes second, so every
  HAIP wallet still works.

## Refresh tokens

`oauth2.refreshTokenEncryptionAlg` can be any of these algorithms. A realm
seals refresh tokens only to itself, so the key pair is derived from the
realm's own refresh-token secret and never published. Nothing a client sees
changes.

## TLS and XML Encryption

* **TLS**: `tls.groups` puts the hybrid groups (X25519MLKEM768,
  SecP256r1MLKEM768, SecP384r1MLKEM1024) first. The OpenSSL 3.5 in the service
  image negotiates them with any client that offers one. See [TLS](tls.md).
* **XML Encryption** (SAML, WS-Federation, WS-Trust) has **no** post-quantum
  option. XML Encryption 1.1 defines no KEM and no post-quantum key transport,
  and no later W3C or IETF document adds one.

## What the service reports about itself

* `/admin/crypto-metadata` → *Key establishment, surface by surface* shows each
  surface's state (JWE out, JWE in, OID4VP, refresh tokens, TLS, XML
  Encryption), read from the settings in force in the realm.
* `/admin/keys` lists the realm's post-quantum decryption keys with the
  **PQC KEM** badge.
* `GET /admin-api/crypto-metadata` returns the same information as JSON.
