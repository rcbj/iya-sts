---
title: Data classification
nav_order: 15
---

# Data classification

This page sorts the data iya-sts handles into protection levels and says what
each level requires. It describes **product mode on a PostgreSQL store**, which
is the only configuration that keeps the data this page covers.
[Encryption at rest](encryption-at-rest.md) explains the sealing mechanism, and
`/admin/encryption` in the running service lists exactly what is sealed. This
page says why it is sealed and what else applies.

The service does not know which laws apply to your deployment. The two personal
levels below are the data that privacy laws such as the GDPR usually cover.
Deciding the lawful basis, the notice you give people, and the retention your
policy requires is your responsibility. The settings named here are how you put
those decisions into effect.

## The levels

| Level | What it is | Examples |
|---|---|---|
| **Restricted** | Lets whoever holds it act as the service, as an application, or as a person, for as long as it stays valid | The key-encryption key, data encryption keys, signing and CA private keys, Kerberos long-term keys, client secrets, GNAP shared and macaroon keys, federation client secrets, TOTP secrets, the database password, audit export tokens, secret-destination credentials |
| **Restricted (verifier)** | One-way form of a credential, which still allows offline guessing | Password hashes, recovery codes, app passwords, device secrets |
| **Bearer** | Works when presented, for a short time | Session cookies, access, refresh and ID tokens, authorization codes, SAML artifacts, emailed link tokens, sign-in step ids, Kerberos tickets |
| **Sensitive personal** | Personal data whose exposure causes particular harm | Identity verification evidence with document numbers (`stsIdaVerification`), the IP addresses kept for risk scoring |
| **Personal** | Identifies or describes a person | Directory attributes (names, mail, telephone, group memberships), profile photos, sign-in history, the claims in a token or an assertion, consent records, device records |
| **Internal** | Describes the deployment and its operation | Settings, audit rows, statistics, scheduler runs |
| **Public** | Published on purpose | JWKS, metadata documents, certificates, CRLs, OCSP answers |

Data that is only encoded is protected at the level of what it contains. See
[Encoded is not encrypted](#encoded-is-not-encrypted).

## What each level requires

### Restricted

| Requirement | Rule, and the control that implements it |
|---|---|
| Encryption | Sealed with AES-256-GCM before it reaches the store, under a data key per realm and kind of data, or AES-256-SIV for directory data when `keys.directoryCipher` says so. The key-encryption key stays outside the database. |
| Integrity | Authenticated encryption. A sealed value is bound to its data key, and a data key to its realm and kind of data. Tampering fails the decryption. |
| Transit | TLS only, and never in a URL. A private key leaves the service only in the reply that hands it over: to the person it was made for, or to a caller holding Admin Write. |
| Retention | As long as it is needed. Keys follow the [key lifecycle](key-management.md). A superseded data key is destroyed once nothing is sealed under it. |
| Logging | Never recorded. The audit log carries no credential, by construction. Export destinations remove `password`, `secret`, `token`, `authorization`, `client_secret` and the other names on [Audit export](audit-export.md#what-a-destination-receives). |
| Access | Withheld from every LDAP read, administrators included (`withholdsDirectorySecrets`), and masked in every GET answer of the management API. See [Field-level access](field-access.md). |
| Database encryption | Application-level sealing, so a copy of the database does not reveal it. Add storage-level encryption for everything else. |
| Privacy | Not applicable. |

A verifier is hashed with scrypt, not sealed, and the plaintext is never stored.
An app password or recovery code is shown once.

### Bearer

| Requirement | Rule, and the control that implements it |
|---|---|
| Encryption | Minted rows (sessions, tokens, codes, artifacts) are sealed in the store. The row's name, which is often the credential itself, is sealed too and found by a keyed digest. |
| Integrity | Tokens and assertions are signed. A refresh token is encrypted. |
| Transit | TLS. Over TLS the session cookie is `__Host-` or `__Secure-` prefixed, and Secure. Emailed links carry their token in the URL fragment. |
| Retention | The artifact's own lifetime. See [Sessions](sessions.md#how-long-a-session-may-last-and-why). |
| Logging | Never recorded in the audit log. Authorization codes, step ids and similar values in a path or query are replaced with `(redacted)`. |
| Access | Only the holder. `/admin/sessions` shows who is signed in, never the cookie. |
| Database encryption | As for Restricted. |
| Privacy | A pairwise or ephemeral `sub` keeps relying parties from correlating a person. |

### Sensitive personal

| Requirement | Rule, and the control that implements it |
|---|---|
| Encryption | Sealed. `stsIdaVerification` is sealed under the home cell's key where there is one. A risk assessment's address is sealed, and also kept as its /24 or /48 network. |
| Integrity | Authenticated encryption. |
| Transit | TLS. |
| Retention | Identity verification evidence stays until the entry is deleted. Risk data follows `risk.assessmentRetentionDays` (90), `risk.historyRetentionDays` (180) and `risk.failureRetentionDays` (30). |
| Logging | Never in the audit log. |
| Access | `stsIdaVerification` is withheld from every LDAP read. |
| Database encryption | Application-level sealing. |
| Privacy | Reduced precision for addresses (a network, a keyed digest). Released in a token only where the request and consent allow it. Browser fingerprinting is off by default. |

### Personal

| Requirement | Rule, and the control that implements it |
|---|---|
| Encryption | On PostgreSQL every entry's attributes are sealed as one blob. The DN and the attribute names stay readable, and lookup values are stored as keyed digests. |
| Integrity | Authenticated encryption in the store. Signatures in a token or assertion. |
| Transit | TLS. Encrypting a token is optional per client; see below. |
| Retention | Until the entry is deleted. Sign-in history follows `audit.authenticationHistoryDays` on the portal and the audit log's own cap. |
| Logging | Named in the audit log only as far as needed: an actor, a target, a DN. A modify names the attributes changed and never their values. |
| Access | A person reads their own entry. Another person's entry is not readable over LDAP by default. See [Field-level access](field-access.md). |
| Database encryption | Sealing of the entry. Use storage-level encryption underneath. |
| Privacy | Consent before release, pairwise or ephemeral subjects, selective disclosure in verifiable credentials, the realm's scope and claim rules, and a person's DID released only on their own consent. |

### Internal

| Requirement | Rule, and the control that implements it |
|---|---|
| Encryption | Audit rows and other minted rows are sealed where they persist. Secret settings are sealed. Other settings are plain JSON. |
| Integrity | Sealing where sealed. Stored settings rely on the database's own access control. |
| Transit | TLS, including the database connection, which is verified by default on this stack. |
| Retention | `audit.maxEvents` (5000 per realm) and the destinations you export to. |
| Logging | See [the logging inventory](logging-inventory.md). |
| Access | Admin Read in the realm. |
| Database encryption | Storage-level encryption. |

### Public

No confidentiality requirement. Key documents are served with
`Cache-Control: no-store` so that a client never holds a stale key.

## Encoded is not encrypted

Base64 and Base64url hide nothing. These values look opaque and are not:

| Value | What is readable by anyone holding it | Level |
|---|---|---|
| A JWT access token or ID Token | Every claim: `sub`, names, mail, groups, `amr`, `acr` | Personal, and Bearer as a whole |
| A SAML assertion or WS-Federation token | Every attribute, unless the assertion is encrypted | Personal, and Bearer as a whole |
| A verifiable credential in JWT form | Every claim except those withheld by selective disclosure | Personal |
| `state`, `nonce` and sign-in step ids | Whatever the client put in `state` | Bearer |
| `oauthClientSecret` in a Basic header | The client secret | Restricted |

To keep the claims out of a client's reach, use an opaque access token
(`oauth2.accessTokenFormat`), encrypted ID Tokens
(`id_token_encrypted_response_alg` on the client) or encrypted assertions. A
JWT access token is the default.

## What is outside these rules

* **The service log at debug level.** `global.logLevel=debug` or `trace` writes
  request and response headers and bodies, and every token before it is signed,
  to the service log. Those are Restricted and Bearer data. Product mode does not
  refuse the setting, so **do not use debug or trace on a deployment that holds
  real data**.
* **The `ldif` store.** It holds entries as the filesystem protects them. Use
  PostgreSQL in product.
* **A report job while it runs.** Its working file is on local disk in the
  clear, readable only by the service's own user. The finished report is sealed.
  See [Reports](reporting.md#security).

## Related

* [Encryption at rest](encryption-at-rest.md)
* [Key management](key-management.md)
* [Logging inventory](logging-inventory.md)
* [Field-level access](field-access.md)
