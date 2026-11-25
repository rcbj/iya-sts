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
OpenID Federation keys, the `krbtgt` key, this service's own Kerberos
acceptor key, the credential signers and the request decryption keys rotate
on a schedule in product mode only. In development mode those keys are made
anew at every start. The CA certificates and the listener certificate are
renewed in both modes.

**Signing and encryption keys of a realm**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **Realm signing keys** (every `jose` unit, `xml:RS256`, the post-quantum units, signer groups) | **Automatic:** the hourly `signing.rotate` job publishes a next key. It promotes that key once the current key is `signing.rotationIntervalDays` old (90; 0 turns the schedule off). **Manual:** Rotate on `/admin/keys`, or `POST /admin-api/keys/rotate` (the `signing.rotate-now` job) | The retired key stays published and still verifies until a grace period ends. The grace period is the longer of `signing.retiredKeyGraceDays` and the longest lifetime of anything the key could have signed, plus clock skew. The hourly `signing.retire` job then drops the key, and its certificate is listed as `superseded`. A Shared Signals `signing-key-rotated` event is sent | `signing.rotationIntervalDays`, `signing.retiredKeyGraceDays` |
| **Credential and BBS units** (`bbs:BBS`, credential-only units) | As for realm signing keys, every `signing.credentialRotationIntervalDays` (365) | The retired key verifies for the longest credential lifetime plus one hour | `signing.credentialRotationIntervalDays` |
| **Dedicated OpenID4VCI credential signer** (`keys.credentialSigner` `dedicated`) | **Automatic:** the hourly `keys.credential-signer-rotate` job makes the next key of each key family once the current key is `keys.credentialSignerRotationIntervalDays` (365) old, counted from when the job first saw it, so an upgrade rotates nothing at once. A new key is also made when its certificate is revoked for a reason that distrusts the key, or is put on hold. Its certificate is renewed over the same key when less than a third of its validity is left. With `realm-key`, the realm signing key's schedule applies | The key it replaces signs nothing more and **stays published** in the credential issuer's JWKS and DID document, with its certificate, so every credential it signed keeps verifying | `keys.credentialSigner`, `keys.credentialSignerRotationIntervalDays` |
| **Refresh-token encryption keys** | Rotated with every `signing.rotate` | The retired set still opens refresh tokens for the longest refresh-token lifetime | As for realm signing keys |
| **Request object encryption keys, KEM decryption keys, the OpenID4VCI request encryption key** | **Automatic:** the hourly `keys.encryption-key-rotate` job replaces them once they are `keys.encryptionKeyRotationIntervalDays` (180) old, counted from when the job first saw them. A rotation of the signing keys still carries them over unchanged | The new key is published (`/oauth2/jwks`, the credential issuer metadata) at once. The key it replaces is published nowhere but still decrypts what a client encrypted to it for `keys.encryptionKeyOverlapDays` (30). The `signing.retire` job then drops it | `keys.encryptionKeyRotationIntervalDays`, `keys.encryptionKeyOverlapDays` |
| **Every signing key at once, on compromise** | **Manual:** `POST /admin-api/keys/emergency` with `{"confirm":"compromised"}` | There is no grace period. The old certificates are revoked for `keyCompromise`, the refresh-token keys are replaced, and every session of the realm ends | — |
| **OpenID Federation entity keys** | **Automatic:** the hourly `oidfed.key-rotate` job, once the current key is `oidfed.keyRotationDays` old (180). **Manual:** `/admin/oidfed` or `POST /admin-api/oidfed/rotate-key`. An emergency rotation revokes the current and next keys | The old private key is dropped at once. Its public key stays published for `oidfed.keyOverlapDays` (14) and is listed in the historical keys | `oidfed.keyRotationDays`, `oidfed.keyOverlapDays` |
| **Shared Signals transmitter** | SETs are signed with the realm signing keys and rotate with them | As for realm signing keys | `ssf.signingAlgorithm` |
| **SPIFFE authorities** | **Automatic, in both modes:** the hourly `spiffe.authority-rotation` job. The X.509 authority is replaced once it is past half its lifetime, and the JWT authority once it is past half of `spiffe.caTtl` (86400 s) | `spiffe.retainedAuthorities` (4) old authorities stay in the trust bundle | `spiffe.caTtl`, `spiffe.retainedAuthorities` |

**Certificates and the CA hierarchy**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **Root CA** | **Automatic renewal:** the daily `pki.ca-renew` job renews the Root's certificate over the **same key and subject** `pki.rootRenewalLeadDays` (1095) before it expires. **Manual re-key:** Replace the Root on `/admin/pki`, which needs a second administrator when `admin.dualControl` is on. Its lifetime is `pki.rootLifetimeYears` (0 means the profile's 20 years) | A renewal is published, never swapped in silently: the renewed Root is at `/pki/ca/service/root.cer`, and the one it replaced stays at `/pki/ca/service/root-previous.cer` until it expires. Every chain validates against either, so give relying parties the renewed one before the old one expires. A **re-key** is a new trust anchor: everything that trusts the old Root must be given the new one | `pki.caRenewal`, `pki.rootRenewalLeadDays`, `pki.rootLifetimeYears` |
| **Intermediate and Issuing CAs** | **Automatic renewal:** the daily `pki.ca-renew` job renews each one over the same key and subject `pki.caRenewalLeadDays` (365) before it expires, after the Root and top down. A CA whose parent expires first waits for the parent's renewal. An imported CA is not renewed. **Manual:** Renew certificates, Reissue this CA, or Rebuild this branch on `/admin/pki`. Lifetimes are `pki.intermediateLifetimeYears` (0 means 10 years) and `pki.issuingLifetimeYears` (0 means 5 years) | A scheduled renewal keeps the key and the name, so everything the CA signed keeps verifying, a pin on its key holds, and the serial it replaced stays known to its parent's OCSP responder until it expires. **Renew certificates** keeps the keys and issues new leaf certificates. **Reissue** lists the old CA as `superseded` on its parent's CRL and re-certifies its leaves. **Rebuild** puts the old Intermediate on the Root's CRL. A revoked or expired leaf is never re-certified. See [PKI](pki.md) | `pki.caRenewal`, `pki.caRenewalLeadDays`, `pki.intermediateLifetimeYears`, `pki.issuingLifetimeYears`, `pki.leafLifetimeDays` |
| **Listener certificate** (main port, LDAPS, the debugger) | **Automatic:** the hourly `tls.server-certificate-renew` job, in every node's front process, re-issues the certificate over the same key once less than a third of its validity is left, or inside `tls.serverCertificateRenewLeadDays`, and puts it on every socket **without a restart**. It is also re-issued at start, and on the console's Renew, when the chain has changed, it was revoked, or `tls.hostnames` or `tls.ips` has changed. You renew a certificate you supply in `tls.certificateFile` yourself | The key does not change. Each node renews its own and hands it to its request workers | `tls.serverCertificateRenewal`, `tls.serverCertificateRenewLeadDays`, `tls.hostnames`, `tls.ips`, `tls.certificateFile` |
| **Custom listener certificates** | **Automatic:** once two thirds of a certificate's life has passed, the hourly `tls.listener-renew` job re-issues it without closing the listener. This applies only to certificates the service issued | — | See [Listeners](listeners.md) |
| **LDAPS session-ticket key** (active-active clusters) | **Automatic:** the `tls.ticket-key-rotate` job, every `tls.sessionTicketRotationS` (3600) | The old key is deleted | `tls.sessionTicketRotationS` |
| **Federation relationship encryption keys** | **Manual:** the console, or `POST /admin-api/federation/rotate-key` | The old key decrypts for `federation.encryptionKeyGraceS` (86400 s). The `federation.encryption-key-retire` job then removes it | `federation.encryptionKeyGraceS` |
| **FAPI client certificates** (this service as a FAPI 1.0 Advanced client) | **Automatic:** the hourly `federation.client-certificate-renew` job renews each certificate `federation.clientCertificateRenewDays` (30) before it expires | — | `federation.clientCertificateRenewDays` |

**Keys that protect stored data**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **Key-encryption key** | **Manual.** For a key read into the process, supply the new key, point `keys.previousKek*` at the old one and restart. For a key in a key management service, use **Rotate the key-encryption key** on `/admin/encryption`, `POST /admin-api/encryption/rotate-kek` (the `keys.kek-rotate-now` job), or the key service's own schedule. A PKCS#11 key has no versions: make a new key and move to it as you would for a key read into the process. See [Rotating the key-encryption key](encryption-at-rest.md#rotating-the-key-encryption-key) | The data keys are re-wrapped under the new key. Nothing stored is re-encrypted | `keys.kekProvider`, `keys.previousKekProvider` |
| **Cell key-encryption key** | **Manual**, as for a key read into the process: supply the new key in `keys.cellKek*`, point `keys.previousCellKek*` at the old one and restart every node of the cell. See [Rotating a cell's key-encryption key](encryption-at-rest.md#rotating-a-cells-key-encryption-key) | The cell's data keys are re-wrapped under the new key. Nothing stored is re-encrypted | `keys.cellKek*`, `keys.previousCellKek*` |
| **Data encryption keys** | **Automatic:** the daily `keys.data-key-rotate` job, every `keys.dataKeyRotationDays` (365; 0 turns it off). **Manual:** `/admin/encryption`, or `POST /admin-api/encryption/rotate-data-keys` | The new key is used `keys.dataKeyActivationLeadSeconds` (300) after it is published, and the old one still opens what it sealed. The hourly `keys.data-key-reencrypt` job re-seals those values. The old key is destroyed once nothing is sealed under it and `keys.dataKeyRetireAfterDays` (7) have passed. See [Rotating the data encryption keys](encryption-at-rest.md#rotating-the-data-encryption-keys) | `keys.dataKeyRotationDays`, `keys.dataKeyActivationLeadSeconds`, `keys.dataKeyRetireAfterDays` |
| **Stored digest key** | **Not rotated, by design.** It is a blind-index key: every digest it makes is stored and later looked up by computing it again (the cell routing index, the lookup columns of sealed directory values, the session index, minted row keys, shared claims). A new key would orphan every stored digest, and a lookup cannot be "verified with an overlap". A rotation of the key-encryption key re-wraps it without changing it (`common/keystore.js`) | Nothing changes | — |
| **Shared cluster secrets that are keys**: the CSRF key, the ACME nonce key, the Shared Signals receiver secret, the OpenID Federation page key, the sign-out result key and the DBSC key (`cluster/cluster_secrets.ts`) | **Automatic, on a store shared through the database:** the `cluster.secret-rotate` job, every `cluster.secretRotationDays` (90; 0 turns it off). A new value is published first and made current ten minutes later, once every process has read it (`cluster.secret-refresh`, every 15 seconds in each process). A value stored by an earlier release is dated at the job's first run and first rotated that many days later. A value set by an environment variable (`STS_CSRF_SECRET` and the others) is not rotated: it is yours | The old value is still accepted for `cluster.secretOverlapS` (one day), so a form, nonce, page pointer or bound cookie made before the rotation still works | `cluster.secretRotationDays`, `cluster.secretOverlapS` |
| **Shared cluster secrets that are identifiers**: the pairwise-subject secret and the bootstrap name secret | **Never rotated, by design.** The pairwise secret derives every pairwise `sub` (OIDC Core section 8.1), the device identifiers and GNAP's opaque subject identifiers, so a new value would make every person a stranger to every pairwise client. The bootstrap name secret derives the generated bootstrap administrator's name; it starts as the CSRF key's value, so the name does not change now that the CSRF key rotates | Nothing changes | `STS_OIDC_PAIRWISE_SECRET`, `STS_BOOTSTRAP_NAME_SECRET` |

**Kerberos keys**

| Key | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **`krbtgt`** | **Automatic:** the hourly `krb5.krbtgt-rotate` job, once the key is `krb5.krbtgtRotationIntervalDays` old (180; 0 turns it off). It does not rotate while the previous version is still kept, or when `krb5.retainedKeyVersions` is 0. **Manual:** `/admin/kerberos/principals`, or `POST /admin-api/kerberos/principals/rotate-krbtgt` | The previous key version is kept for `krb5.retainedKeyTtlS`, so tickets already issued keep working. Its default of 0 means the longest ticket or renewal lifetime plus clock skew. `rotate-krbtgt-invalidate` keeps nothing, and every ticket-granting ticket is refused. See [Kerberos](kerberos.md) | `krb5.krbtgtRotationIntervalDays`, `krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS` |
| **Service principal keys** | **Automatic for this service's own acceptor key:** the hourly `krb5.service-key-rotate` job replaces it at the next kvno once it is `krb5.serviceKeyRotationIntervalDays` (180) old, and never while the version the last rotation kept is still in its window. **A key whose keytab was handed to another service is reported as due** on `/admin/scheduler` and not rotated, because that service needs the new keytab. Rotate it on `/admin/kerberos/principals`, or `POST /admin-api/kerberos/principals/rotate-service`. The new keytab is given out once | Previous key versions are kept as for `krbtgt`, so tickets already issued keep working, and the new keytab carries them | `krb5.serviceKeyRotationIntervalDays`, `krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS` |
| **A person's Kerberos keys** | Change with the person's password | — | — |

**Credentials that authenticate a party**

| Secret | Schedule | What happens to what was already issued | Settings |
|---|---|---|---|
| **OAuth client secrets** | Each new secret expires `oauth2.clientSecretLifetimeDays` (365; 0 means never) after it is made, and `client_secret_expires_at` gives the date. The daily `oauth2.client-secret-expiry` job warns `oauth2.clientSecretExpiryWarningDays` (14) ahead, and removes expired secrets when the application holds an unexpired one. **Automatic, opt-in per client:** an application listed in `oauth2.clientSecretAutoRotate` is rotated by that job `oauth2.clientSecretAutoRotateDays` (30) before its secret expires, and the new secret is pushed to its secret destination first, or read by the client from its RFC 7592 configuration. See [Automatic rotation](applications.md#automatic-rotation). **Manual:** Rotate secret on `/admin/applications`, the `rotate-secret` action of `/admin-api`, or RFC 7592 | A secret that was rotated out still authenticates for `oauth2.clientSecretOverlapS` (7 days). In product mode the token endpoint refuses an expired secret. See [Applications](applications.md#the-client-secret) | `oauth2.clientSecretLifetimeDays`, `oauth2.clientSecretOverlapS`, `oauth2.clientSecretExpiryWarningDays`, `oauth2.clientSecretsMax`, `oauth2.clientSecretAutoRotate`, `oauth2.clientSecretAutoRotateDays` |
| **Management API secret** (`adminApi.clientSecret`) | **Manual, with an overlap.** A newly seeded secret expires after `oauth2.clientSecretLifetimeDays` and is warned about like any other; an entry seeded by an earlier release keeps the expiry it has. Rotate secret on the console, or `rotate-secret`, adds a new secret while the setting pins the old one; then set the setting to it and restart. Or change the setting and restart: a value the entry does not hold is adopted as a new secret at start. **Regenerate** is still refused while the setting pins it (`STS-REG-0061`). See [The management API client's secret](applications.md#the-management-api-clients-secret) | The old secret still authenticates for `oauth2.clientSecretOverlapS` | `adminApi.clientSecret` (`ADMIN_API_CLIENT_SECRET`), `oauth2.clientSecretOverlapS` |
| **Service account passwords** | **Automatic when the service-account policy turns it on** (`rotationEnabled`, off by default): the hourly `service-accounts.rotate` job, every `rotationIntervalDays` (30). **Manual:** Rotate now, or `POST /admin-api/users/rotate-password`. The new password is pushed to the secret destination before it is committed | The previous password still works for `rotationOverlapMinutes` (60). The `service-accounts.previous-cleanup` job then removes it. See [Service accounts](service-accounts.md#rotation) | The service-account policy |
| **Database password** | **Rotating it is the secret store's or your job**, not this service's: OpenBao's database secrets engine (a static role) changes the password at the database and in the store together, or you change both. **This service picks it up without a restart:** each process reads it again every `persistence.databasePasswordRefreshS` (3600; the `persistence.database-password-refresh` job), and at once when the database refuses a login, and new connections use the new password | Open connections keep working. Keep the old password valid at the database for at least one refresh interval, so every node has read the new one | `persistence.databasePasswordProvider`, `persistence.databasePasswordRefreshS` |
| **TOTP secrets** | **Not this service's to rotate.** A TOTP secret is shared with the person's authenticator app, so a new one means the person enrolling again (removing the authenticator on the portal and adding it back). This service cannot change it alone without locking the person out | — | — |
| **GNAP macaroon root keys and `jwt-encrypted` key** | Derived from the realm's refresh-token secret, which changes with every `signing.rotate`; new tokens use the current secret (#2212) | Tokens issued before a rotation still verify under each replaced secret the rotation keeps, which is kept for at least the longest GNAP access-token lifetime (an emergency rotation keeps none). A resource server's stored `gnapMacaroonKey` is rewritten at the first macaroon minted for it after a rotation | `signing.retiredKeyGraceDays`, `gnap.accessTokenLifetimeS` |
| **Application and person assertion key pairs** | **Manual:** replace the key pair. See [PKI](pki.md#replacing-a-key-pair) | — | — |
| **DPoP and DBSC keys** | Held by the client or the browser, not by this service. The DPoP nonce is a stored list of issued nonces, not a key. The DBSC server secret is a shared cluster secret (see above) | — | — |
| **OpenPGP and S/MIME keys** | This service holds none of its own. It encrypts to each person's registered key or certificate. When a person keeps a classical OpenPGP key beside a post-quantum one, the hourly `post-login.mail-classical-retire` job removes the classical key once its keep period ends | — | — |
| **DKIM signing key** | **Manual, with a selector overlap:** put the new key in the DKIM key's secret under `mail.dkimNextKeyField`, set `mail.dkimNextSelector`, publish the record the log gives you, and set `mail.dkimSwitchAt`. Signing moves to the new selector at that time, and only once DNS publishes its key. See [Rotating the DKIM key](mail.md#rotating-the-dkim-key). **The DNS records are yours** to publish and withdraw | Keep the old selector's record for at least a week after the switch, so mail already sent still verifies | `mail.dkimNextSelector`, `mail.dkimNextKeyField`, `mail.dkimSwitchAt` |
| Mail transport secrets, audit export tokens, secret-destination credentials, the secret store's client certificate | Read from your secret store. **Rotating them is your job**, in the store and at the system they open. This service reads them again: the mail transport's secrets at least once an hour, and the others each time they are used | Keep the old credential valid at the other system until the new one has been read | Each feature's own settings |

### Known gaps

None. Every key and secret above has a rotation: a scheduler job, a re-read
from your secret store, or a step that is yours and is described in its row.
Two are never rotated by design, and their rows say why: the stored digest key
and the shared cluster secrets that are identifiers.

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
