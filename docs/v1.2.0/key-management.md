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
| **Rotation** | A new signing key is published before it signs (`signing.rotate`). Data keys rotate on a schedule and values are re-encrypted in the background. Every key's schedule is in [Rotation schedule](#rotation-schedule). |
| **Retirement** | A retired signing key is still published for what it signed, for `signing.retiredKeyGraceDays` or the longest lifetime of anything it could have signed. A superseded data key opens what it sealed and seals nothing new. |
| **Destruction** | A retired signing key is dropped and its certificate is listed as `superseded`. A superseded data key is destroyed after `keys.dataKeyRetireAfterDays`, once nothing is sealed under it. Destruction cannot be undone. |
| **Compromise** | `POST /admin-api/keys/emergency` replaces every signing key at once with no grace, revokes the old certificates for `keyCompromise`, and ends every session of the realm. |

See [Encryption at rest](encryption-at-rest.md) for data keys and the
key-encryption key, and [PKI](pki.md) for certificates and signing generations.
To keep the key-encryption key, or a realm's classical signing keys, inside a
hardware security module, see [Keys in a hardware security
module](hsm.md).

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

## Rotation schedule

This section covers the rotation of every key and secret listed above (ASVS
5.0.0 13.1.4). For each one it gives the schedule, what a rotation does to
anything the old key already signed, sealed or authenticated, and the settings.
An automatic rotation is a scheduler job, and **Monitoring → Scheduler**
(`/admin/scheduler`) shows each job's last and next run. Signing keys,
OpenID Federation keys and the `krbtgt` key rotate on a schedule in product
mode only. In development mode those keys are made anew at every start.

**Signing and encryption keys of a realm**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **Realm signing keys** (every `jose` unit, `xml:RS256`, the post-quantum units, signer groups) | **Automatic:** the hourly `signing.rotate` job publishes a next key. It promotes that key once the current key is `signing.rotationIntervalDays` old (90; 0 turns the schedule off). **Manual:** Rotate on `/admin/keys`, or `POST /admin-api/keys/rotate` (the `signing.rotate-now` job) | The retired key stays published and still verifies until a grace period ends. The grace period is the longer of `signing.retiredKeyGraceDays` and the longest lifetime of anything the key could have signed, plus clock skew. The hourly `signing.retire` job then drops the key, and its certificate is listed as `superseded`. A Shared Signals `signing-key-rotated` event is sent | `signing.rotationIntervalDays`, `signing.retiredKeyGraceDays` |
| **Credential and BBS units** (`bbs:BBS`, credential-only units) | As for realm signing keys, every `signing.credentialRotationIntervalDays` (365) | The retired key verifies for the longest credential lifetime plus one hour | `signing.credentialRotationIntervalDays` |
| **Dedicated OpenID4VCI credential signer** (`keys.credentialSigner` `dedicated`) | **No schedule.** A new key is made only when its certificate is revoked for a reason that distrusts the key, or is put on hold. Its certificate is renewed over the same key when less than a third of its validity is left (`common/credential_signer.js`). With `realm-key`, the realm signing key's schedule applies | Credentials already issued keep verifying against the old key's certificate | `keys.credentialSigner` |
| **Refresh-token encryption keys** | Rotated with every `signing.rotate` | The retired set still opens refresh tokens for the longest refresh-token lifetime | As for realm signing keys |
| **Request object encryption keys, KEM decryption keys, the OpenID4VCI request encryption key** | **Never rotated.** A rotation of the signing keys carries them over unchanged (`common/helpers.js`) | — | — |
| **Every signing key at once, on compromise** | **Manual:** `POST /admin-api/keys/emergency` with `{"confirm":"compromised"}` | There is no grace period. The old certificates are revoked for `keyCompromise`, the refresh-token keys are replaced, and every session of the realm ends | — |
| **OpenID Federation entity keys** | **Automatic:** the hourly `oidfed.key-rotate` job, once the current key is `oidfed.keyRotationDays` old (180). **Manual:** `/admin/oidfed` or `POST /admin-api/oidfed/rotate-key`. An emergency rotation revokes the current and next keys | The old private key is dropped at once. Its public key stays published for `oidfed.keyOverlapDays` (14) and is listed in the historical keys | `oidfed.keyRotationDays`, `oidfed.keyOverlapDays` |
| **Shared Signals transmitter** | SETs are signed with the realm signing keys and rotate with them | As for realm signing keys | `ssf.signingAlgorithm` |
| **SPIFFE authorities** | **Automatic, in both modes:** the hourly `spiffe.authority-rotation` job. The X.509 authority is replaced once it is past half its lifetime, and the JWT authority once it is past half of `spiffe.caTtl` (86400 s) | `spiffe.retainedAuthorities` (4) old authorities stay in the trust bundle | `spiffe.caTtl`, `spiffe.retainedAuthorities` |

**Certificates and the CA hierarchy**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **Root CA** | **Manual only:** Replace the Root on `/admin/pki`. No job renews it. Its lifetime is `pki.rootLifetimeYears` (0 means the profile's 20 years) | Everything that trusts the old Root must be given the new one | `pki.rootLifetimeYears` |
| **Intermediate and Issuing CAs** | **Manual only:** Renew certificates, Reissue this CA, or Rebuild this branch on `/admin/pki`. No job renews them. Lifetimes are `pki.intermediateLifetimeYears` (0 means 10 years) and `pki.issuingLifetimeYears` (0 means 5 years) | **Renew** keeps the keys and issues new certificates, so nothing stops verifying. **Reissue** lists the old CA as `superseded` on its parent's CRL and re-certifies its leaves. **Rebuild** puts the old Intermediate on the Root's CRL. A revoked or expired leaf is never re-certified. See [PKI](pki.md) | `pki.intermediateLifetimeYears`, `pki.issuingLifetimeYears`, `pki.leafLifetimeDays` |
| **Listener certificate** (main port, LDAPS, the debugger) | **At start, and on the console's Renew.** The certificate is re-issued over the same key when less than a third of its validity is left, the chain has changed, it was revoked, or `tls.hostnames` or `tls.ips` has changed. **No job renews it while the process runs** (`common/pki.js`, `certifyRegistered()`). You renew a certificate you supply in `tls.certificateFile` yourself | The key does not change | `tls.hostnames`, `tls.ips`, `tls.certificateFile` |
| **Custom listener certificates** | **Automatic:** once two thirds of a certificate's life has passed, the hourly `tls.listener-renew` job re-issues it without closing the listener. This applies only to certificates the service issued | — | See [Listeners](listeners.md) |
| **LDAPS session-ticket key** (active-active clusters) | **Automatic:** the `tls.ticket-key-rotate` job, every `tls.sessionTicketRotationS` (3600) | The old key is deleted | `tls.sessionTicketRotationS` |
| **Federation relationship encryption keys** | **Manual:** the console, or `POST /admin-api/federation/rotate-key` | The old key decrypts for `federation.encryptionKeyGraceS` (86400 s). The `federation.encryption-key-retire` job then removes it | `federation.encryptionKeyGraceS` |
| **FAPI client certificates** (this service as a FAPI 1.0 Advanced client) | **Automatic:** the hourly `federation.client-certificate-renew` job renews each certificate `federation.clientCertificateRenewDays` (30) before it expires | — | `federation.clientCertificateRenewDays` |

**Keys that protect stored data**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **Key-encryption key** | **Manual.** For a key read into the process, supply the new key, point `keys.previousKek*` at the old one and restart. For a key in a key management service, use **Rotate the key-encryption key** on `/admin/encryption`, `POST /admin-api/encryption/rotate-kek` (the `keys.kek-rotate-now` job), or the key service's own schedule. A PKCS#11 key has no versions: make a new key and move to it as you would for a key read into the process. See [Rotating the key-encryption key](encryption-at-rest.md#rotating-the-key-encryption-key) | The data keys are re-wrapped under the new key. Nothing stored is re-encrypted | `keys.kekProvider`, `keys.previousKekProvider` |
| **Cell key-encryption key** | **Cannot be rotated**: there is no previous-key setting | — | `keys.cellKek*` |
| **Data encryption keys** | **Automatic:** the daily `keys.data-key-rotate` job, every `keys.dataKeyRotationDays` (365; 0 turns it off). **Manual:** `/admin/encryption`, or `POST /admin-api/encryption/rotate-data-keys` | The new key is used `keys.dataKeyActivationLeadSeconds` (300) after it is published, and the old one still opens what it sealed. The hourly `keys.data-key-reencrypt` job re-seals those values. The old key is destroyed once nothing is sealed under it and `keys.dataKeyRetireAfterDays` (7) have passed. See [Rotating the data encryption keys](encryption-at-rest.md#rotating-the-data-encryption-keys) | `keys.dataKeyRotationDays`, `keys.dataKeyActivationLeadSeconds`, `keys.dataKeyRetireAfterDays` |
| **Stored digest key** | **Never rotated** (`common/keystore.js`). A rotation of the key-encryption key re-wraps it | — | — |
| **Shared cluster secrets**: the CSRF key, the ACME nonce key, the Shared Signals receiver secret, the pairwise-subject secret, the DBSC secret, and the others in `cluster/cluster_secrets.ts` | **Never rotated.** Each one is made once for the whole store and sealed under the key-encryption key. An environment variable such as `STS_CSRF_SECRET` replaces the stored value | Changing one invalidates every outstanding form, nonce or value made with it | `STS_CSRF_SECRET`, `STS_ACME_NONCE_SECRET`, `STS_SSF_RECEIVER_SECRET` |

**Kerberos keys**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **`krbtgt`** | **Automatic:** the hourly `krb5.krbtgt-rotate` job, once the key is `krb5.krbtgtRotationIntervalDays` old (180; 0 turns it off). It does not rotate while the previous version is still kept, or when `krb5.retainedKeyVersions` is 0. **Manual:** `/admin/kerberos/principals`, or `POST /admin-api/kerberos/principals/rotate-krbtgt` | The previous key version is kept for `krb5.retainedKeyTtlS`, so tickets already issued keep working. Its default of 0 means the longest ticket or renewal lifetime plus clock skew. `rotate-krbtgt-invalidate` keeps nothing, and every ticket-granting ticket is refused. See [Kerberos](kerberos.md) | `krb5.krbtgtRotationIntervalDays`, `krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS` |
| **Service principal keys** | **Manual only:** Rotate on `/admin/kerberos/principals`, or `POST /admin-api/kerberos/principals/rotate-service`. The new keytab is given out once | Previous key versions are kept as for `krbtgt`, and the new keytab carries them | `krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS` |
| **A person's Kerberos keys** | Change with the person's password | — | — |

**Credentials that authenticate a party**

| Secret | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **OAuth client secrets** | **They expire but are not rotated automatically.** Each new secret expires `oauth2.clientSecretLifetimeDays` (365; 0 means never) after it is made, and `client_secret_expires_at` gives the date. The daily `oauth2.client-secret-expiry` job warns `oauth2.clientSecretExpiryWarningDays` (14) ahead. It also removes expired secrets when the application holds an unexpired one. **Rotation is manual:** Rotate secret on `/admin/applications`, the `rotate-secret` action of `/admin-api`, or RFC 7592 | A secret that was rotated out still authenticates for `oauth2.clientSecretOverlapS` (7 days). In product mode the token endpoint refuses an expired secret. See [Applications](applications.md#the-client-secret) | `oauth2.clientSecretLifetimeDays`, `oauth2.clientSecretOverlapS`, `oauth2.clientSecretExpiryWarningDays`, `oauth2.clientSecretsMax` |
| **Management API secret** (`adminApi.clientSecret`) | **Never rotated, and never expires.** The console and the API refuse to rotate it while the setting holds it (`STS-REG-0061`). To change it, change the setting and restart. If the setting is empty, a new secret is made at every start | The old secret stops working at the restart | `adminApi.clientSecret` (`ADMIN_API_CLIENT_SECRET`) |
| **Service account passwords** | **Automatic when the service-account policy turns it on** (`rotationEnabled`, off by default): the hourly `service-accounts.rotate` job, every `rotationIntervalDays` (30). **Manual:** Rotate now, or `POST /admin-api/users/rotate-password`. The new password is pushed to the secret destination before it is committed | The previous password still works for `rotationOverlapMinutes` (60). The `service-accounts.previous-cleanup` job then removes it. See [Service accounts](service-accounts.md#rotation) | The service-account policy |
| **Database password** | **Nothing rotates it.** It is read once, at start | Change it in the database and the secret store, then restart every node | `persistence.databasePasswordProvider` |
| **TOTP secrets** | Not rotated. A secret changes only when the person enrols again | — | — |
| **GNAP macaroon root keys and `jwt-encrypted` key** | Derived from the realm's refresh-token secret, which changes with every `signing.rotate` | See the known gaps below | — |
| **Application and person assertion key pairs** | **Manual:** replace the key pair. See [PKI](pki.md#replacing-a-key-pair) | — | — |
| **DPoP and DBSC keys** | Held by the client or the browser, not by this service. The DPoP nonce is a stored list of issued nonces, not a key. The DBSC server secret is a shared cluster secret (see above) | — | — |
| **OpenPGP and S/MIME keys** | This service holds none of its own. It encrypts to each person's registered key or certificate. When a person keeps a classical OpenPGP key beside a post-quantum one, the hourly `post-login.mail-classical-retire` job removes the classical key once its keep period ends | — | — |
| **DKIM signing key**, mail transport secrets, audit export tokens, secret-destination credentials, the secret store's client certificate | Read from your secret store. **This service does not rotate them** | Rotate them in the secret store on your own schedule | `mail.dkimKeyProvider`, `mail.dkimKeyRef`, and each feature's own settings |

### Known gaps

The keys and secrets below are never rotated, or are rotated only by hand.
Each gap is a follow-up.

1. **The database password** is never rotated, and is read only at start
   (`persistence.databasePasswordProvider`, `common/secrets.js`).
2. **The management API secret** never expires, and cannot be rotated while
   `adminApi.clientSecret` holds it (`common/applications.js`, `STS-REG-0061`).
3. **OAuth client secrets** expire but are never rotated automatically, so the
   application has to rotate its secret before it expires.
4. **The listener certificate** is renewed only at start or from the console.
   A node that runs past two thirds of the certificate's validity without a
   restart does not renew it (`common/pki.js`, `certifyRegistered()`).
5. **The Root, Intermediate and Issuing CAs** have no renewal job.
6. **The cell key-encryption key** cannot be rotated (`keys.cellKek*`).
7. **The stored digest key** is never rotated (`common/keystore.js`).
8. **The shared cluster secrets** (CSRF, ACME nonce, Shared Signals receiver,
   pairwise subjects, DBSC and the others) are never rotated
   (`cluster/cluster_secrets.ts`).
9. **Request object encryption keys, KEM decryption keys and the OpenID4VCI
   request encryption key** are carried over every rotation and never replaced
   (`common/helpers.js`).
10. **Kerberos service principal keys** have no schedule. Only the `krbtgt` key
    rotates on its own.
11. **The dedicated credential signer's key** has no schedule. It is replaced
    only when its certificate is revoked (`common/credential_signer.js`).
12. **GNAP macaroon and `jwt-encrypted` keys** are derived only from the
    realm's current refresh-token secret (`gnap/gnap_tokens.ts`,
    `realmDerived()`). That secret changes with every `signing.rotate`, and the
    copy written to a resource server's entry is written only once
    (`gnap/gnap_rs.ts`, `ensureMacaroonKey`). So a rotation appears to stop
    outstanding GNAP macaroons and `jwt-encrypted` tokens from verifying, and to
    leave the resource server's stored root key stale. This was found by reading
    the code and has not been tested.
13. **TOTP secrets, the DKIM key and the service credentials** in your secret
    store are not rotated by this service.

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
* [Dependencies, limits and timeouts](dependencies.md)
