---
title: PostgreSQL schema
---

# PostgreSQL schema

This page describes every table `persistence.mode=postgres` uses, what goes in
each column, and why the tables are shaped that way. [Persistence](persistence.md)
covers turning the store on, the compose stack and what survives a restart.
This page covers only what is in the database.

**Schema version 9**: 26 tables in a schema of their own, `sts`.

## Where the schema is written down

It is written in two places, and a test keeps them in step:

* **`postgres/schema.sql`** is the script an owner runs once, with
  `psql -v ON_ERROR_STOP=1 -f postgres/schema.sql <url>`. It builds the tables
  and the least-privilege application role. The compose stack runs the same
  file through `postgres/apply-schema.sh`.
* **`persistence/persistence_postgres.js`** holds the same `CREATE` statements
  as its exported `SCHEMA`. On every open it probes for each object
  (`to_regclass`) and creates only what is missing. Against a database the
  script already built, it therefore needs no `CREATE` privilege.

`tests/postgres_schema.js` fails if either file holds a `CREATE` the other does
not, or if the two version numbers differ. **A column change goes in both files
in one commit.**

### There are no migrations, only additions

Each schema change so far has added something: a table (`CREATE TABLE IF NOT
EXISTS`) or a column (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`). To upgrade an
older database, run `schema.sql` again as the owner. Nothing is renamed or
dropped, and nothing is rewritten. The version row in `sts_schema` records
which shape is on disk.

| Version | What it added |
|---|---|
| 1 | `sts_ldap_entries`, `sts_realms`, `sts_appconfig` |
| 2 | `sts_keys`, then `sts_minted` and `sts_changes` for minted persistence and coordination between processes |
| 4 | `sts_used_assertions` |
| 5 | `sts_cluster_nodes`, `_leases`, `_claims`, `_secrets`, `_counters`, `_windows`, `sts_change_readers` (#46) |
| 6 | the column `sts_realms.domain`, the first column added to an existing table |
| 7 | the thirteen `sts_risk_*` tables of risk scoring (#62) |
| 8 | `sts_risk_terms_acceptances` |
| 9 | the columns `sts_risk_assessments.feedback` and `.feedback_at` |

### The application role

The service connects as `sts_app` (set with `-v sts_app_role=`). That role
holds `USAGE` on the schema and `SELECT`, `INSERT`, `UPDATE` and `DELETE` on its
tables and sequences. **It does not hold `CREATE`, `TRUNCATE`, `REFERENCES` or
`TRIGGER`.** `CREATE` is revoked on `sts` and on `public`, from `PUBLIC` and
from the role. The script also stops if an existing role holds `SUPERUSER`,
`REPLICATION` or `BYPASSRLS`, because only a superuser could remove those.

The default privileges extend the same grants to tables a later version adds.
The database's `search_path` is set to `sts, public`, so the driver can use
unqualified table names.

## Conventions that hold across the tables

* **`realm` is a trust realm id.** The default realm is `default`. The empty
  string `''` means "belongs to the process, not to any realm", for example the
  rate limiter's buckets. It is never `NULL`, so primary keys need no
  `COALESCE`.
* **Two time formats, each chosen per table.** The tables from before the
  cluster work use `timestamptz` (`written_at`, `at`, `applied_at`). The
  cluster and risk tables use `bigint` milliseconds, taken from the
  **database's** clock so that two nodes' clocks never need to agree.
  `sts_ldap_entries` stores LDAP generalized time as `text`.
* **`origin` is the process that wrote the row**: a UUID made when each process
  starts. A process uses it to skip its own rows in the change log, and the
  cluster tables use it to show who holds a claim.
* **Anything that could be used as a credential is sealed.** The formats are
  `$aesgcm$1$salt$iv$tag$body`, or a SHA-256 or HMAC digest in place of the
  value. The key-encryption key is never in the database;
  [encryption at rest](encryption-at-rest.md) says where it comes from. The
  directory is the deliberate exception (see below).

## The tables, by what they hold

```
 directory & configuration      minted state            cluster coordination
 ─────────────────────────      ────────────            ────────────────────
 sts_ldap_entries  (JSONB)      sts_minted (sealed)     sts_cluster_nodes
 sts_realms                     sts_used_assertions     sts_cluster_leases
 sts_appconfig                                          sts_cluster_claims
 sts_keys          (sealed)     change log              sts_cluster_secrets (sealed)
                                ──────────              sts_cluster_counters
 bookkeeping                    sts_changes             sts_cluster_windows
 ───────────                    sts_change_readers
 sts_schema                                             risk scoring: 14 × sts_risk_*
```

There are no foreign keys. Every table is keyed by what its readers look up,
and a row is re-read by key rather than joined.

---

## Directory and configuration

### `sts_ldap_entries`: the embedded directory

The [LDAP directory](ldap.md) has one row per entry, for every realm. The
[LDAP schema](ldap-schema.md) page describes what goes in `attrs`.

| Column | Type | Meaning |
|---|---|---|
| `realm` | text | the trust realm whose tree holds the entry |
| `dn_key` | text | **the normalised DN**, from `ldap_server.js`'s `normalizeDn()`. `UID=Alice,OU=Users` and `uid=alice,ou=users` are the same key |
| `dn` | text | the DN as it was written, which is what a search returns |
| `attrs` | jsonb | `{ "attributeName": ["value", …] }`: every value is an array, as in LDAP, and operational attributes are included |
| `origin` | text | how the entry came to exist: `seed`, `console`, `ldap add`, `scim`, … (the `# sts-origin:` comment in an LDIF export) |
| `created_at`, `modified_at` | text | RFC 4517 generalized time (`20260827192200Z`), **byte-identical** to `createTimestamp` / `modifyTimestamp` in `attrs` |

Primary key `(realm, dn_key)`, with an index on `realm`.

**It is the one table you can query with SQL, and that is deliberate.** An
entry is a document without a fixed schema, and JSONB lets Postgres index into
it while still giving a primary key and transactions:

```sql
SELECT dn, attrs->'mail'->>0 AS mail
  FROM sts.sts_ldap_entries
 WHERE realm = 'default' AND attrs->'uid' ? 'alice';
```

**It is not sealed.** Secrets in an entry are protected per attribute:
`userPassword` is an scrypt hash, and the recovery codes and app passwords are
hashed. See the [LDAP schema](ldap-schema.md).

When two nodes change one entry at the same time, the update is a three-way
merge (`persistence/directory_merge.js`), not last-writer-wins.

The `created_at` and `modified_at` columns are `text` rather than `timestamptz`
so that they match the LDAP attributes byte for byte. A round trip through
`timestamptz` would re-render the value in the session's format and time zone.

### `sts_realms`: the realm registry

| Column | Type | Meaning |
|---|---|---|
| `id` | text PK | the realm id, which is the path segment in `/realm/<id>/…` |
| `name`, `description` | text | display text |
| `created_at` | bigint | milliseconds |
| `overrides` | jsonb | the realm's own setting values, `{ "oauth2.rfc9700": true, … }` |
| `domain` | text | the realm's DNS domain, **fixed at creation**, which becomes the directory base `dc=…` (v6) |

The default realm is not a row. Its settings are the process's own.

### `sts_appconfig`: runtime setting changes

One row per setting changed at runtime, from the console or `/admin-api`:
`key` is the setting name (`oauth2.consentRequired`) and `value` is JSONB. On
restart these come back as runtime overrides, not as a new configuration layer
([persistence](persistence.md#settings-come-back-as-runtime-overrides-not-as-a-new-layer)).

### `sts_keys`: private keys this service generated

| Column | Type | Meaning |
|---|---|---|
| `realm` | text PK | `<realm id>` for a realm's JWS signing keys, or `pki:<realm id>` for that scope's certificate-authority hierarchy (Root, Intermediate, Issuing CAs) |
| `material` | text | **ciphertext**, `$aesgcm$1$…`, sealed under the key-encryption key |
| `written_at` | timestamptz | the time of the last write |

This table is used in product mode only. Development regenerates its keys on
every start. The `pki:` prefix keeps CA hierarchies apart from signing keys
without adding a discriminator column. The first writer wins: a process that
finds a row already present adopts it instead of overwriting it
(`SELECT … FOR UPDATE`). This is how every node ends up with the same `kid`.
See [PKI](pki.md) and [encryption at rest](encryption-at-rest.md).

---

## Minted state

### `sts_minted`: everything the process issued

These are sessions, codes, tokens, artifacts, nonces, pending flows, counters
and the audit log, all in one table. It is written in product mode on postgres
only, and `persistence.minted` turns it off.

| Column | Type | Meaning |
|---|---|---|
| `handle` | text | **the store's name**, taken from its declaration in the code: `realms.map({ persist: 'authn.sessions' })` |
| `realm` | text | the realm id, or `''` for a store shared by the whole process (`realms.sharedMap()`) |
| `key` | text | the key within that store |
| `body` | text | **always ciphertext**, `$aesgcm$1$…` |
| `written_at` | timestamptz | used by retention: a row older than `persistence.mintedRetention` (7 days) is neither restored nor kept |

Primary key `(handle, realm, key)`, with indexes on `(handle, realm)` and
`written_at`.

**There is one table rather than one per family**, so that persisting a new
store costs one word at its declaration and no DDL. The price is that nothing
in the table can be queried with SQL, because a session id is a cookie value
and an authorization code can be redeemed. A dump of this table must not give
anyone a live session.

The handles in use, grouped by family (a `test.*` handle is used only by
tests):

| Family | Handles |
|---|---|
| Sign-in | `authn.sessions`, `authn.pending`, `authn.pendingMfa`, `authn.pendingPasswordChange`, `authn.webauthnCredentials`, `credentials.pendingBackupCodes`, `credentials.pendingKeys`, `credentials.pendingTotp`, `spnego.pending`, `oidc_rp.flows` |
| OAuth / OIDC | `oauth2.authzCodes`, `oauth2.redeemedCodes`, `oauth2.pushedRequests`, `oauth2.backchannelDeliveries`, `oauth2.cibaRequests`, `oauth2.cibaDeliveries`, `oauth2_bcp.refreshTokens`, `oauth2_bcp.refreshFamilies`, `oauth2_bcp.grantTokens`, `oauth2_bcp.transactions`, `oauth2_monitor.counters`, `consent_screen.pending`, `authorization_details.consented`, `authorization_servers.profiles`, `dpop.issuedNonces`, `dpop.seenJtis` |
| SAML, WS-* and federation | `saml2_sso.artifacts`, `saml2_sso.pendingRequests`, `saml2_sso.spContexts`, `saml2.mdqRefusals`, `saml11_sso.artifacts`, `saml11_sso.assertionsById`, `saml11_sso.pendingFlows`, `wsfed.rpContexts`, `federation_sp.contexts`, `delegation.acts` |
| Verifiable credentials | `vc_offers.credentialOffers`, `vc_offers.preAuthorizedCodes`, `vc_offers.issuerStates`, `vc_offers.deferredAccessTokens`, `vc_offers.deferredTransactions`, `vc_issuer.vciNonces`, `vc_issuer.notificationIds`, `vc_issuer.lastCredentialRequest`, `vc_issued.credentials`, `vc_status.entries`, `vc_claims.state`, `vc_verifier.vpRequests`, `vc_verifier.vpTransactions`, `vc_verifier_config.state` |
| GNAP | `gnap.grants`, `gnap.continuations`, `gnap.interactions`, `gnap.tokens`, `gnap.tokenValues`, `gnap.instances`, `gnap.approvers`, `gnap.resources`, `gnap.manageHandles`, `gnap.manageValues`, `gnap.userCodes`, `gnap.userRefs`, `gnap.replay`, `gnap_monitor.counters` |
| Kerberos | `krb5.principals`, `krb5.replayCache` |
| Certificate enrollment | `acme.accounts`, `acme.accountKeys`, `acme.orders`, `acme.authorizations`, `acme.certificates`, `acme.renewalInfo`, `acme.usedNonces`, `scep.transactions`, `enrollment_monitor.*` |
| SPIFFE | `spiffe.authorities`, `spiffe.federatedBundles`, `spiffe.joinTokens`, `spiffe.recordedConnections`, `spiffe.sigstoreTuf` |
| SCIM | `scim.digestNonces`, `scim.digestCounts`, `scim.hobaChallenges`, `scim.hobaSeen` |
| Shared Signals | `ssf_streams.streams`, `ssf_streams.queued`, `ssf_streams.received`, `ssf_streams.deadLetters`, `ssf_receivers.inbox`, `ssf_dead_letter_report.sweeps`, `caep.register`, `risc.register` |
| Mail | `mail.outbox`, `mail.preferences`, `mail.templates` |
| Console statistics and audit | `admin_stats.tokens`, `admin_stats.artifacts`, `admin_stats.revokedArtifacts`, `admin_stats.revokedJtis`, `admin_stats.claimSets`, `admin_stats.users`, `admin_stats.calls`, `admin_stats.nums`, `admin_stats.scimCounts`, `claim_attributes.selections`, `xacml_monitor.counters`, `audit.events`, `audit.nums` |
| Process-wide | `security.rateLimitBuckets`, `ldap.clusterConnections`, `ldap.clusterSignOuts`, `scheduler.runs`, `signing.history` |

To list them from a running tree:
`grep -rhoE "persist: *'[^']+'" --include=*.js --include=*.ts . | sort -u`.

### `sts_used_assertions`: accepted-once history for RFC 7523 and RFC 7522

This table holds every JWT and SAML assertion accepted as a client credential
or a grant, kept until the assertion would have expired, so that none is
accepted twice ([JWT assertions](jwt-assertions.md),
[SAML assertions](saml-assertions.md)). It is written **in both modes**,
because the key that verifies an assertion belongs to the client and outlives
a restart.

| Column | Meaning |
|---|---|
| `realm`, `key` | PK. `key` is a SHA-256 of format, issuer and identifier; **the assertion itself is never stored** |
| `format`, `used_as` | `jwt` or `saml2`; a client credential or a grant |
| `issuer`, `identifier`, `client_id`, `subject` | what the assertion said |
| `state`, `reservation`, `spent_at` | reserved when checked, **spent only when tokens are issued**, released otherwise |
| `origin`, `used_at`, `expires_at` | ms; index `(realm, expires_at)` for the purge |

It has a table of its own, rather than living in `sts_minted`, because
recording a use has to be an **atomic claim**: `INSERT … ON CONFLICT` on the
primary key. Two nodes therefore cannot both accept one assertion. A row in
`sts_minted` would reach another node only after that node pulled the change
log.

---

## The change log

### `sts_changes`

This table is how several processes against one database agree with each
other, not just share it.

| Column | Type | Meaning |
|---|---|---|
| `seq` | bigserial PK | assigned by the database and only ever increasing: **the whole synchronisation primitive** |
| `origin` | text | the writing process, which skips its own rows |
| `kind` | text | `directory`, `realms`, `appconfig`, `keys`, `minted`, `minted-own`, `risk-dataset` |
| `realm`, `key` | text | **a pointer, never data**: the reader re-reads the named row from its own table |
| `at` | timestamptz | indexed, for trimming |

Every change-log row is **written in the same transaction as the change it
describes**, so "I have applied up to N" means "I have seen everything
committed before N". `LISTEN`/`NOTIFY` on the channel `sts_ldap_change` only
wakes the poll early. Losing a notification costs latency, never correctness.
The payload is only a pointer, so neither the 8000-byte `NOTIFY` limit nor
encryption applies to it.

### `sts_change_readers`

Each process that reads the log reports the highest `seq` it has applied
(`applied`), with its `node_id` and times. `sts_changes` is trimmed below the
lowest of these marks by the scheduler job that holds the lease
`ops.change-log-purge`.

---

## Cluster coordination (#46)

These tables are used when [several containers share one store](aws-cluster.md).
Every time is the database clock in milliseconds.

| Table | Primary key | What a row is |
|---|---|---|
| `sts_cluster_nodes` | `node_id` | a member: `name`, `mode` (`active-passive` / `active-active`), `version`, a configuration `fingerprint` nodes must share, `started_at`, `heartbeat_at`, `expires_at`, `left_at`, and `info` (JSONB). Indexed on `expires_at` |
| `sts_cluster_leases` | `name` | a named lease: `holder`, a **fencing `token`** that rises every time the lease changes hands (write transactions check it), `acquired_at`, `expires_at`. The names in use are `service` (active-passive), `ops.scheduler` (the scheduler's leader), `ops.change-log-purge` and `ssf.dead-stream-probes` |
| `sts_cluster_claims` | `(scope, realm, key)` | **a value spent once across the cluster**. `key` is a SHA-256 of scope and value, so the value is never stored. The row holds a `reservation`, an `origin` and its times, and is kept or released. Examples of scopes: `oauth.code`, `oauth.refresh`, `oauth.par`, `oauth.dpop-jti`, `saml2.artifact`, `saml11.artifact`, `krb5.authenticator`, `acme.nonce`, `acme.finalize`, `acme.eab-bind`, `scep.challenge`, `oid4vci.pre-authorized-code`, `oid4vp.sign-in`, `spiffe.join-token`, `spnego.continuation`, `authn.session-end`, `pki.build`, `ops.bootstrap` |
| `sts_cluster_secrets` | `name` | a secret every node must agree on. **The first writer wins**, and `material` is sealed before it is inserted. The names are `csrf`, `acme-nonce`, `ssf-receiver` and `oidc-pairwise` (`cluster/cluster_secrets.ts`). Each can instead come from its `STS_*_SECRET` environment variable |
| `sts_cluster_counters` | `(scope, realm, key)` | **a value that only goes up**, advanced by one conditional upsert, so a lower value never overwrites a higher one. Used for a WebAuthn signature counter and the last RFC 6238 time step spent |
| `sts_cluster_windows` | `(scope, realm, key)` | **a count inside a fixed window**: the rate limiter's buckets, one budget shared by every node. Holds `count` and `window_ends_at` (indexed) |

`cluster/CLAUDE.md` explains why each of these is a separate table and why a
row in `sts_minted` would not do.

---

## Risk scoring (#62)

[Risk scoring](risk-scoring.md) explains the model. What follows is only the
storage. `realm` is `''` for datasets shared across realms.

### Datasets, stored by version

External data (geolocation, ASN, Tor exits, IP reputation, the FIDO MDS3 BLOB,
an operator's allow and deny lists) is imported as a **version**. A version is
verified before it becomes active, and the previous version is kept so an
import can be rolled back. Lookups are SQL range queries over `inet`.

| Table | Primary key | What it holds |
|---|---|---|
| `sts_risk_datasets` | `(realm, dataset)` | one row per dataset: `kind`, `active_version`, `previous_version`, `state` |
| `sts_risk_dataset_versions` | `(realm, dataset, version)` | the provenance of an import: `format`, `provider`, `licence`, `attribution`, `source`/`source_uri`, `sha256`, `byte_count`, `row_count`, `parameters`, `verification`, times through its lifecycle (`published`, `fetched`, `loaded`, `activated`, `superseded`, `rows_deleted`), `state`, and a `refusal` and `error_code` if it was refused |
| `sts_risk_dataset_blobs` | `(realm, dataset, version, part)` | the downloaded file, in `bytea` parts |
| `sts_risk_geo_locations` | `(dataset, version, location_id)` | continent, country, subdivision, city, time zone |
| `sts_risk_geo_ranges` | `(dataset, version, range_start)` | `range_start`–`range_end` (`inet`) to a location, latitude and longitude, accuracy, and the anonymous-proxy and satellite flags |
| `sts_risk_asn_ranges` | `(dataset, version, range_start)` | an address range to `asn`, `as_org`, `as_domain` |
| `sts_risk_ip_lists` | `(realm, dataset, version, range_start)` | a listed range with its `category` and `note` (Tor, reputation, allow, deny) |
| `sts_risk_fido_authenticators` | `(dataset, version, key_kind, authenticator_key)` | one MDS3 entry, by AAGUID or key identifier: certification level, latest status, `compromised`, and the status reports and metadata statement as JSONB |
| `sts_risk_terms_acceptances` | `id` (bigserial) | **who accepted which provider's terms**: `provider`, `terms_digest`, the full `terms_text`, `accepted_by`, `accepted_via`, `deployment`, `page_digest`, `accepted_at`. An import is refused unless a row exists for the provider's current terms |

### The history the model keeps

| Table | Primary key | What it holds |
|---|---|---|
| `sts_risk_assessments` | `(realm, id)` | **one row per scored sign-in**: `phase`, `door`, `subject`, `session_id`, `client_id`; the address **sealed** (`address_sealed`) plus its network prefix (`cidr`); ASN and location; `ip_lists` (text[]); the user-agent digest and family, OS and platform, and `bot`; the `ja4` TLS fingerprint; the credential's kind and digest, the WebAuthn `aaguid`, attestation certificate and backup flags, the DPoP `jkt`, the certificate fingerprint; the `datasets` versions consulted and the `signals` (JSONB); the `score` (real), `level`, `decision`, `policy_id`, `error_code`; and what the person said about the sign-in (`feedback`, `feedback_at`, from `/portal/sign-ins`). Indexed by subject, by session and by time |
| `sts_risk_feature_counts` | `(realm, subject, feature, value)` | how often a person has been seen with a given country, ASN, device and so on, with `count`, `first_at`, `last_at`. This is what makes a feature familiar or new |
| `sts_risk_failures` | `(realm, id)` | **every refused password**: `door`, and the `subject` if the name resolved, otherwise `name_hmac` (an HMAC of the name, never the name itself). Also the sealed address and its prefix, the ASN and the `error_code`. Indexed by subject, name, prefix and time, which are the four ways a spray or stuffing pattern is looked up |
| `sts_risk_session_context` | `(realm, session_id)` | the context a session was established in (prefix, ASN, country, user-agent digest, JA4, `jkt`, score, level), so that a later request can be compared with it |
| `sts_risk_subjects` | `(realm, subject)` | a person's current `score` and `level`, the `previous_level`, when it last crossed a threshold (`crossed_at`), and why; the `actions` taken (JSONB) and their `feedback` |

Only `address_prefix` is stored in the clear, and it is the network, not the
host. The full address is sealed like any minted row.

---

## `sts_schema`

This table holds one row per version applied (`version` int PK, `applied_at`).
The driver writes its `SCHEMA_VERSION` on every open, and `schema.sql` inserts
the same number.

## Related

* [Persistence](persistence.md): the modes, the compose stack, what survives.
* [Encryption at rest](encryption-at-rest.md): the key-encryption key behind
  every `$aesgcm$1$` value.
* [LDAP schema](ldap-schema.md): what is inside `sts_ldap_entries.attrs`.
* [A cluster in AWS](aws-cluster.md): the same schema on RDS.
* `postgres/CLAUDE.md` and `persistence/CLAUDE.md`, for maintainers.
