---
title: Key management
nav_order: 15
---

# Key management

This page is the key-management policy for iya-sts, and its inventory of keys.
It follows the lifecycle in NIST SP 800-57 Part 1. It describes product mode: in
development mode keys are made anew at every start and not rotated.

The **live inventory** is in the admin console:

* `/admin/crypto-metadata` lists every algorithm the running service performs,
  read from the code that performs it, and every key it holds.
* `/admin/keys` and `/admin/pki` list the keys and certificates of the realm.
* `GET /crypto/metadata` is the public document: every signing generation with
  its `kid`, certificate chain, validity and revocation addresses. Review it on
  your own schedule and whenever a certificate is changed. The pages are built
  from the running service, so they cannot go out of date.

The inventory below adds what those pages do not say: where each key must not
be used, and what kinds of data it may protect. The levels are those of
[Data classification](data-classification.md).

## Lifecycle

| Stage | What happens |
|---|---|
| **Generation** | Keys come from the operating system's random source. RSA keys are 3072 bits in product by default (`pki.keyAlgorithm`). The service does not generate a key-encryption key: you, or your key management service, do. |
| **Distribution** | Public halves are published in JWKS, metadata and certificates. A private key leaves the service only in the reply that creates or exports it: to the person it was made for, or to a caller holding Admin Write. Data keys move between nodes wrapped, through the database. |
| **Storage** | Private keys and secrets are sealed at rest. The key-encryption key is held outside the database. In memory, `keys.plaintextRetention` sets how long a decrypted private key is kept after use. |
| **Use** | Each key is used only for the purposes in the inventory below. A signing unit is one use case and one algorithm. |
| **Rotation** | A new signing key is published before it signs (`signing.rotate`). Data keys rotate on a schedule and values are re-encrypted in the background. |
| **Retirement** | A retired signing key is still published for what it signed, for `signing.retiredKeyGraceDays` or the longest lifetime of anything it could have signed. A superseded data key opens what it sealed and seals nothing new. |
| **Destruction** | A retired signing key is dropped and its certificate is listed as `superseded`. A superseded data key is destroyed after `keys.dataKeyRetireAfterDays`, once nothing is sealed under it. Destruction cannot be undone. |
| **Compromise** | `POST /admin-api/keys/emergency` replaces every signing key at once with no grace, revokes the old certificates for `keyCompromise`, and ends every session of the realm. |

See [Encryption at rest](encryption-at-rest.md) for data keys and the
key-encryption key, and [PKI](pki.md) for certificates and signing generations.

## Who may hold a key

* **A private key belongs to one entity.** All the nodes of one deployment count
  as one entity, and share keys through the sealed store.
* **A shared secret belongs to at most two entities.** A client secret is shared
  by the client and this service. A TOTP secret is shared by the person's
  authenticator and this service. A Kerberos service key is shared by the KDC and
  the service that holds its keytab.
* **Do not copy a key to a third party.** Export exists for migration and
  recovery. Exporting a key makes you responsible for every copy.

Where the service departs from the first rule, you can see it here. Each is an
accepted condition of this policy (ASVS 5.0.0 11.1.1), kept because the key has
to be retrievable after issue:

* The realm's signing keys and the listener certificate key can be exported by a
  caller holding Admin Write, from `/admin/keys` and `/admin/pki`. Every export is
  a second holder.
* An application's RFC 7523 or RFC 7522 assertion key pair stays sealed on its
  entry after issue, so that an administrator can collect it. The service and the
  application then both hold it. Prefer an application that generates its own key
  and registers only the public half.
* A person's assertion key pair and a TLS client certificate's key are given
  once and not kept, so they have one holder.

## Approved algorithms

These are the signature algorithms this policy approves (ASVS 5.0.0 11.6.1).
In product mode the service signs and accepts only these, and
`/admin/crypto-metadata` lists which the running realm uses.

| Family | Approved | Notes |
|---|---|---|
| RSA | RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256, SHA-384 or SHA-512 | 3072-bit keys are generated in product. Peers' keys are accepted from 2048 bits in JOSE, and with no floor in XML signatures, for partners that still sign with older keys |
| ECDSA | P-256, P-384 and P-521; brainpool curves of 256 bits and more for XML | secp256k1 (ES256K) only where `keys.signingAlgorithms` or `keys.acceptedSigningAlgorithms` lists it |
| EdDSA | Ed25519 and Ed448 | Off by default (`keys.eddsaSigning`) |
| Post-quantum | ML-DSA-44, -65 and -87 (FIPS 204); SLH-DSA (FIPS 205); the ML-DSA composites | |
| HMAC | HMAC-SHA-256, -384 and -512 | For `client_secret_jwt` and shared-secret JWS |
| BBS | `bbs-2023`, on BLS12-381 (W3C Data Integrity BBS Cryptosuites v1.0) | Approved for verifiable credentials only, for selective disclosure and unlinkable presentations, which no algorithm above provides. It is not a NIST algorithm. Each realm generates its own BBS key |

Algorithms outside this table are refused in product mode, or used only where a
specification requires them and the setting that allows them is named on
`/admin/mode`.

## Inventory of keys

| Key | Use | Must not be used for | May protect |
|---|---|---|---|
| **Key-encryption key** (`keys.kek*`) | Wrapping data keys | Anything else. Never a value, a token or a password | Data keys only |
| **Cell key-encryption key** (`keys.cellKek*`) | Wrapping the data keys of one cell's resident data | Other cells' data | That cell's data keys |
| **Data encryption keys** | Sealing stored values, one per realm per kind of data | Another realm, another kind of data, or anything off the store | Restricted, Bearer, Sensitive personal and Personal data at rest |
| **Stored digest key** | Keyed digests for lookups and cell locators | Encryption or signing | Lookup values, as digests only |
| **Realm `jose` signing keys** (RS256, curves, post-quantum) | Signing access tokens, refresh tokens, ID Tokens, signed UserInfo and other JWTs of the realm | Signing outside this realm. Not for DPoP where the algorithm has no thumbprint | Integrity of Bearer and Personal data |
| **Realm `xml` signing key** | Signing SAML, WS-Federation and WS-Trust documents and XML metadata | Non-XML signatures | Integrity of Bearer and Personal data |
| **Request object encryption keys** (`use: enc` at `/oauth2/jwks`) | Decrypting request objects sent to this realm | Signing | Confidentiality of request parameters |
| **KEM decryption keys** (`keys.encryptionKemAlgs`) | Decrypting data encrypted to the realm with those algorithms | Signing | Confidentiality of what is encrypted to the realm |
| **OpenID4VCI request encryption key** | Decrypting credential requests | Signing | Confidentiality of the request |
| **Refresh token encryption keys** | Encrypting refresh tokens | Anything else | Bearer data |
| **Credential signing key** (`oid4vci.credentialSigningAlgorithm`) | Signing verifiable credentials | Other tokens, when an algorithm of its own is chosen | Integrity of credentials |
| **Root CA key** | Signing Intermediate certificates | Leaf certificates or data | Certificate chains |
| **Intermediate and Issuing CA keys** | Signing certificates and CRLs for their use case | Data, or another use case's certificates | Certificate chains |
| **Listener certificate keys** | The TLS handshake on the main port, LDAPS and custom listeners | Application-level signing | Data in transit |
| **SPIFFE authority keys** | Issuing X509-SVIDs and JWT-SVIDs for the trust domain | Anything outside that trust domain | Workload identities |
| **Kerberos `krbtgt` key** (`krb5.krbtgtRotationIntervalDays`) | Encrypting ticket-granting tickets | Any other purpose | Kerberos tickets |
| **Kerberos service and person keys** | Service tickets, and pre-authentication | Anything outside Kerberos | Kerberos exchanges |
| **Client secrets, and federation client secrets** | Authenticating one client to one server, and `client_secret_jwt` HMAC | Another client or server | Client authentication only |
| **TOTP secrets** | Computing one person's one-time codes | Anything else | One authentication factor |
| **GNAP shared keys and macaroon root keys** | Signing GNAP requests, and verifying macaroons for one resource server | Another client or resource server | GNAP requests and tokens |
| **Application and person assertion key pairs** | Signing RFC 7523 or RFC 7522 assertions | Any other signature | Assertion integrity |
| **Service credentials**: database password, secret store client certificate, mail transport secrets, audit export tokens, secret-destination credentials | Authenticating this service to that one system | Any other system | The connection to that system |

> **Note.** The RSA keys of the `jose:RS256` and `xml:RS256` units also open JWEs
> and XML encryption sent to this realm with RSA key transport, as well as
> signing. Prefer the dedicated request object and KEM keys for encryption, and
> plan for these two keys being used for both purposes.

Algorithms and their permitted uses are in `/admin/crypto-metadata`. Certificates
are in `/admin/pki`, and every certificate this service issues carries the key
usages of its use case. See [PKI use cases](pki-use-cases.md).

## Your own responsibilities

* Generate the key-encryption key, keep it out of the database and rotate it on
  your own schedule. See
  [Rotating the key-encryption key](encryption-at-rest.md#rotating-the-key-encryption-key).
* Restrict who can read the store your key is in, and who holds Admin Write.
* Review the live inventory on the schedule your policy requires.

## Related

* [Encryption at rest](encryption-at-rest.md)
* [PKI](pki.md)
* [Data classification](data-classification.md)
