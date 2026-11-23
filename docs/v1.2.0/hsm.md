---
title: Keys in a hardware security module
nav_order: 15
---

# Keys in a hardware security module

iya-sts can keep two kinds of key inside a hardware security module (HSM)
through PKCS#11:

* **The key-encryption key** (`keys.kekProvider=pkcs11`). It wraps every data
  encryption key, so every sealed value at rest depends on it. The key is an
  AES-256 object in the HSM. It cannot be extracted, and every wrap and unwrap
  happens inside the HSM.
* **A realm's classical signing keys** (`keys.signingKeyStore=pkcs11`, off by
  default). The RSA key that signs JWTs, the XML signing key, and the
  elliptic-curve keys are generated in the HSM and cannot be extracted. Every
  signature is a PKCS#11 call, made without blocking the event loop.

Two modules have been tested: **SoftHSM2** and a fake module in the test
suite. The **YubiHSM 2** settings below come from Yubico's PKCS#11 module, but
**no run against a real YubiHSM 2 has been made yet**.

## What you need

1. **The `pkcs11js` package.** It is a native addon and is not a dependency
   of the service. Build the image with it:

   ```bash
   docker build --build-arg STS_CLOUD_SDKS=pkcs11js -t my-iya-sts .
   ```

   The build installs a compiler for this step only. If the package is
   missing, the service names the package to install and does not start
   (`STS-KEYS-0045`).

2. **The HSM's PKCS#11 module**, added in an image derived from the one
   above:

   ```dockerfile
   FROM my-iya-sts
   USER root
   # SoftHSM2:
   RUN apt-get update && apt-get -y install --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
   # or the YubiHSM 2: copy yubihsm_pkcs11.so and libyubihsm from Yubico's
   # yubihsm2-sdk for Debian 12, and its yubihsm_pkcs11.conf
   USER sts
   ```

3. **A PIN**, delivered like any other secret and never as a setting's value:
   `keys.pkcs11PinProvider` (`file`, `vault`, `aws`, `gcp` or `azure`) and
   `keys.pkcs11PinRef`. If different tokens have different PINs, store a JSON
   object of PINs keyed by token label, such as `{"sts": "1234", "old": "5678"}`.

## The key-encryption key in the HSM

| Setting | Value |
|---|---|
| `keys.kekProvider` | `pkcs11` |
| `keys.kekRef` | a PKCS#11 URI (RFC 7512) naming the token and the key: `pkcs11:token=sts;object=sts-kek`, or `id=%01%02` for a key id |
| `keys.pkcs11Module` | the module's path |
| `keys.pkcs11PinProvider`, `keys.pkcs11PinRef` | where the PIN is |
| `keys.pkcs11Mechanism` | `auto` (the default) |
| `keys.pkcs11GenerateKey` | `false` (the default): create the key with the HSM's own tool |

**How a data key is wrapped.** With `auto`, the service uses the first
mechanism in this list that the module offers:

| Mechanism | Used by | Binding to the realm and kind of data |
|---|---|---|
| `CKM_AES_GCM` with `C_Encrypt` | SoftHSM2 and most network HSMs | the data key's binding is GCM's additional data, checked by the HSM |
| `CKM_AES_KEY_WRAP_PAD` (RFC 5649) with `C_WrapKey` | modules that offer key wrap but not GCM | a SHA-256 digest of the binding is wrapped with the key, and checked by the service |
| `CKM_YUBICO_AES_CCM_WRAP` with `C_Encrypt` | the YubiHSM 2, whose module offers neither of the others | as for key wrap |

The stored form names its mechanism (`$dekkms$1$pkcs11$<key>$g1.…`, `k1.`,
`y1.`), so a change to `keys.pkcs11Mechanism` affects only new data keys. Data
keys that are already wrapped still unwrap.

**The key must be AES-256 and not extractable.** The service refuses an
extractable key, a key of another size, a missing key, and two objects with one
name (`STS-KEYS-0203`). If you turn on `keys.pkcs11GenerateKey`, the service
makes the key on the first start. Only the front process makes it, never a
request worker. In a cluster, make the key with the HSM's tool instead: two
nodes starting at the same moment would make two keys.

**The other two positions.** `keys.previousKekProvider` and
`keys.cellKekProvider` can also be `pkcs11`. Each position has its own URI in
its location setting (`keys.previousKekRef`, `keys.cellKekRef`). A URI's
`module-path` query attribute names another module for that position only.
To move from one HSM to another, name the new key in `keys.kekRef` and the old
one in `keys.previousKekRef`, then start: every data key is re-wrapped under
the new key. A PKCS#11 key has no versions, so `rotate-kek` is refused for it.
Make a new key and move to it in this way.

## A realm's signing keys in the HSM

| Setting | Value |
|---|---|
| `keys.signingKeyStore` | `pkcs11`, set for the realm (or globally) |
| `keys.signingKeyToken` | the token's URI, such as `pkcs11:token=signing`. Opened in every process at start |
| `keys.pkcs11Module`, `keys.pkcs11PinProvider`, `keys.pkcs11PinRef` | as above |

The setting applies to a key set that is made or rotated after the change. When
the realm's keys are next made, the HSM generates these keys. They are
sensitive and cannot be extracted:

* the RS256 key and the XML signing key (RSA, `pki.keyAlgorithm`'s size);
* the ES256, ES384, ES512 and ES256K keys (P-256, P-384, P-521, secp256k1),
  and the Ed25519 EdDSA key, **if the module can make them**.

A curve key the module cannot make (Ed448 on SoftHSM2 and on the YubiHSM 2)
is made in software. The log records `STS-KEYS-0207` for it.

**An ML-DSA key is made in the HSM only when the module offers it.** PKCS#11
3.2's `CKM_ML_DSA` and `CKM_ML_DSA_KEY_PAIR_GEN` are used when the module
lists them. A module that does not (SoftHSM 2, the YubiHSM 2) leaves that
signature in software. SLH-DSA has no mechanism here, and the realm's
published post-quantum set is made in software either way. The console's
**Encryption** page (`/admin/encryption`) and `GET /admin-api/encryption`'s
`signingKeys` member list, for each realm, which keys are in the HSM and
which are in software.

What does not change: the JWKS, the metadata and the certificates publish the
HSM keys' public halves, and a rotation's next key is also made in the HSM. The
sealed key set in the store holds a reference for each private key (its token
and its `CKA_ID`), never the key. Every process and node opens the token and
signs through its own sessions.

**Limits.**

* The keystore must persist, as it does in product mode. Otherwise every start
  would leave a new set of keys in the token, so the service refuses with
  `STS-KEYS-0206`.
* The realm's signer-group, pinned and credential-signer keys stay in
  software.

**The same keys decrypt.** In iya-sts a realm's RSA signing keys are also its
decryption keys, and its P-256, P-384 and P-521 keys answer ECDH-ES. A partner
that encrypts to the realm's SAML or WS-Trust certificate or to its JWKS uses
these keys. So the HSM makes the RSA keys with `CKA_DECRYPT` and the NIST-curve
keys with `CKA_DERIVE`. They still cannot be extracted. Every decryption with
them is done in the HSM:

| What arrives | The HSM operation |
|---|---|
| A SAML `EncryptedID`, `EncryptedAssertion` in an RFC 7522 grant, or a WS-Trust encrypted request (`rsa-oaep-mgf1p`, `rsa-oaep`) | `CKM_RSA_PKCS_OAEP` with the document's digest, without blocking the event loop |
| A JWE assertion with `RSA-OAEP` or `RSA-OAEP-256` | `CKM_RSA_PKCS_OAEP`, without blocking the event loop |
| A JWE with `ECDH-ES` or `ECDH-ES+A*KW` to an EC key | `CKM_ECDH1_DERIVE`, without blocking the event loop; the Concat KDF runs in the service |

* **RSA PKCS#1 v1.5 (`rsa-1_5`) is never decrypted with a key in the HSM.**
  The service is safe with it only through OpenSSL's implicit rejection, which
  a module does not have. Product mode refuses it anyway.
* **SoftHSM2 2.6 decrypts RSA-OAEP over SHA-1 only.** In product mode
  (`crypto.allowLegacyHashes` off), SoftHSM2 cannot open `rsa-oaep` over
  SHA-256 or `RSA-OAEP-256`, and the service refuses with `STS-KEYS-0207`. The
  YubiHSM 2's module offers OAEP over SHA-1, SHA-256, SHA-384 and SHA-512.
* **Keys made by an earlier build of this feature** carry only `CKA_SIGN`.
  The service does not try to add `CKA_DECRYPT` to an existing object: most
  modules do not allow it. A decryption with such a key is refused with
  `STS-KEYS-0208`, and the message says to rotate:
  `POST /admin-api/keys/rotate` or the `signing.rotate-now` job makes new keys
  that can decrypt. Until then, documents encrypted to that key do not open.

**The event loop is never held.** Every operation with a realm's key in the
HSM is an asynchronous PKCS#11 call (`C_SignAsync`, `C_DecryptAsync`,
`C_DeriveKeyAsync`), and the service waits for it without blocking the event
loop, in the front process and in every request worker. That covers every
place a realm key is used:

* **Signatures:** access, refresh and ID tokens, signed UserInfo responses,
  logout tokens, request objects, introspection and JARM responses, signed
  metadata (OAuth, OpenID, SAML, WS-Federation, the cryptographic metadata
  document), software statements, FAPI client assertions, Security Event
  Tokens, GNAP access tokens, OpenID4VP request objects, SAML 2.0 and SAML
  1.1 assertions and responses, SAML logout messages and their
  HTTP-Redirect signatures, WS-Trust tokens (SAML and JWT), WS-Federation
  sign-in responses, AuthnRequests sent to a federation partner, and the
  self-signed certificate made over each RSA key when a key set is created
  or rotated.
* **Decryptions:** SAML `EncryptedID` and `EncryptedAssertion`, a WS-Trust
  encrypted request, and a JWE to the realm's RSA or EC keys.

For an XML signature, the service canonicalizes the `SignedInfo` itself,
signs it in the HSM asynchronously, and writes the `SignatureValue` into the
document. A key in software is signed exactly as before.

`keys.pkcs11SynchronousSign` is the opt-in to **blocking** calls, and it is
off by default. Off, no blocking call is made: a module that offers no
asynchronous call for an operation is refused with `STS-KEYS-0209` rather
than waited for. On, such a module calls `C_Sign`, `C_Decrypt` or
`C_DeriveKey`, and the event loop waits for the token while it does.
SoftHSM2 and Yubico's module both offer the asynchronous calls through
`pkcs11js`.

Four short calls stay synchronous: opening and logging in a session (once
per session, and again after an outage), finding a key's handle (once per
key, and after an outage), and the `C_SignInit` / `C_DecryptInit` that
starts each operation. None of them performs the cryptographic operation.

**Latency.** These figures are from SoftHSM2 on a laptop with two cores:

| Operation | Time each |
|---|---|
| RS256 (RSA 2048) signature, synchronous (setting on) | about 0.7–0.95 ms (0.47 ms in software) |
| RS256 signature, 200 at a time without blocking the event loop | P8A_RS_ASYNC |
| ES256 signature, synchronous (setting on) | about 0.05–0.07 ms |
| ES256, 200 at a time without blocking the event loop | about 0.05 ms each |
| SAML assertion signature (RSA), synchronous (setting on) | about 1.2 ms |
| SAML assertion signature (RSA), 50 at a time without blocking | P8A_XML_ASYNC |
| XML RSA-OAEP decryption, synchronous (setting on) | about 0.2 ms |
| XML RSA-OAEP decryption, 50 at a time without blocking | P8A_DEC_ASYNC |

While those ran off the event loop, its longest gap was P8A_LAG.

A YubiHSM 2 is much slower: Yubico's published figures are tens of
milliseconds for ECDSA P-256 and hundreds for RSA-2048. Off the event loop
that is latency for the one request, not a stall for every request, but it
still holds a thread of libuv's pool (below). A realm that signs a high
volume of tokens with a YubiHSM 2 should sign them with an EC key
(`keys.signingAlgorithms`).

## Sessions, workers and outages

* Each process and request worker opens its own sessions, at most
  `keys.pkcs11Sessions` (4) for each token. One session runs one operation at a
  time. A YubiHSM 2 has 16 sessions in total across every process on every
  node, so keep sessions × processes × nodes below 16.
* **libuv's thread pool.** An asynchronous PKCS#11 call runs on libuv's
  thread pool, which a process shares between its front thread, its request
  workers, password hashing (scrypt) and post-quantum signing. A call holds
  a pool thread for as long as the token takes, so a process can have
  `keys.pkcs11Sessions` × (1 + `workers.requestCount` +
  `workers.surfaceCount`) of them running at once. When that reaches
  `UV_THREADPOOL_SIZE` (node's default is 4; the compose stack sets 32), the
  service logs `STS-KEYS-0210` at start with the size to set: a slow token
  could otherwise hold every pool thread while sign-ins wait to hash a
  password. The event loop is not blocked either way.
* If `yubihsm-connector` restarts, or the device goes away, every session is
  lost. The next operation opens a new session, logs in again and tries once
  more. No timer is involved. An operation that still fails is refused with
  `STS-KEYS-0201`, and the service keeps running. If a data key cannot be
  unwrapped at start, the start stops.
* The other codes: `STS-KEYS-0202` (the module or token cannot be used),
  `STS-KEYS-0203` (the key), `STS-KEYS-0204` (no mechanism), `STS-KEYS-0205`
  (the URI or PIN), `STS-KEYS-0206` (a key in the HSM was asked to do
  something it cannot do, or cannot be reached), `STS-KEYS-0207` (the module
  cannot make a key of that kind, or cannot decrypt with that digest),
  `STS-KEYS-0208` (a key made before the HSM keys could decrypt),
  `STS-KEYS-0209` (a blocking call, by a module with no asynchronous call,
  while `keys.pkcs11SynchronousSign` is off), `STS-KEYS-0210` (libuv's
  thread pool is smaller than the PKCS#11 calls that can run at once). See
  [Error codes](error-codes.md).

## SoftHSM2

```bash
softhsm2-util --init-token --free --label sts --so-pin 5678 --pin 1234
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
  --keygen --key-type AES:32 --label sts-kek --id 01 \
  --sensitive --extractable=false   # pkcs11-tool 0.23+; or keys.pkcs11GenerateKey
```

Set `keys.pkcs11Module=/usr/lib/softhsm/libsofthsm2.so`,
`keys.kekRef=pkcs11:token=sts;object=sts-kek`, and a PIN file holding `1234`.
SoftHSM2 keeps its tokens in the directory that `SOFTHSM2_CONF` names, which
must be a volume that outlives the container.

## YubiHSM 2

1. Run **`yubihsm-connector`** where it can reach the device, and point the
   module at it in `yubihsm_pkcs11.conf` (`connector = http://127.0.0.1:12345`).
   Set `YUBIHSM_PKCS11_CONF` to that file's path in the service's environment.
2. Create an authentication key for the service with only the capabilities it
   needs: `wrap-data` and `unwrap-data` for the key-encryption key, plus
   `sign-pkcs`, `sign-pss`, `sign-ecdsa`, `sign-eddsa`, `decrypt-oaep`,
   `derive-ecdh` and `generate-asymmetric-key` for signing keys.
3. Create the key-encryption key as a **wrap key** with `yubihsm-shell`, for
   example
   `generate wrapkey 0 0 sts-kek 1 wrap-data,unwrap-data none aes256-ccm-wrap`.
   The service wraps with `CKM_YUBICO_AES_CCM_WRAP`.
4. The **PIN** is the authentication key's id as four hex digits, followed by
   its password: `0001password` for key 1. Deliver it through
   `keys.pkcs11PinProvider`.
5. `keys.pkcs11Module=/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so`
   (the path of Yubico's Debian package), and
   `keys.kekRef=pkcs11:token=YubiHSM;object=sts-kek`. The YubiHSM's token label
   is `YubiHSM` unless your configuration changes it. Add `serial=` to the URI
   if more than one device is connected.

### The YubiHSM Auth applet on a YubiKey

A YubiKey's **YubiHSM Auth** applet stores the credentials for opening a
session to a YubiHSM 2. Operators use it with `yubihsm-shell` and
`yubihsm-auth` to administer the HSM without keeping the authentication
key's password on their computer.

**iya-sts does not use it and does not verify it.** It is a credential between
an operator's tools and the HSM. It is not something a person presents to an
identity service, and no protocol that iya-sts speaks carries it. The service
reaches the HSM with its own authentication key, whose PIN is delivered as a
secret. Use the applet for your administrators' sessions: creating the
service's authentication key and its keys, and rotating them.
