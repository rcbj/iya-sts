---
title: PostgreSQL schema
---

# PostgreSQL schema

This page describes every table `persistence.mode=postgres` uses, what goes in
each column, which columns are encrypted, every index, and why the tables are
shaped that way. [Persistence](persistence.md) covers turning the store on, the
compose stack and what survives a restart. This page covers only what is in
the database.

**Schema version 28**: 39 tables and 44 secondary indexes in a schema of their
own, `sts`.

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
EXISTS`), a column (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`) or an index.
To upgrade an older database, run `schema.sql` again as the owner. No table
or column is renamed or dropped and no row is rewritten; a few indexes have
been replaced by better ones (versions 18, 19, 27 and 28), which the script
does for you. The version row in `sts_schema` records which shape is on disk.

| Version | What it added |
|---|---|
| 1 | `sts_ldap_entries`, `sts_realms`, `sts_appconfig` |
| 2 | `sts_keys`, then `sts_minted` and `sts_changes` for minted persistence and coordination between processes |
| 3 | no schema change is recorded under this number |
| 4 | `sts_used_assertions` |
| 5 | `sts_cluster_nodes`, `_leases`, `_claims`, `_secrets`, `_counters`, `_windows`, `sts_change_readers` (#46) |
| 6 | the column `sts_realms.domain`, the first column added to an existing table |
| 7 | the thirteen `sts_risk_*` tables of risk scoring (#62) |
| 8 | `sts_risk_terms_acceptances` |
| 9 | the columns `sts_risk_assessments.feedback` and `.feedback_at` |
| 10 | the column `sts_realms.retiring_at` (#262) |
| 11 | `sts_node_snapshots`: each cluster node's latest Worker Pools and Node Health views (#332); on develop the same number is #98's `sts_cell_routing` — both tables are created by name |
| 12 | the column `sts_minted.expires_at` and its partial index `sts_minted_expires` (#333) |
| 13 | six lookup columns on `sts_ldap_entries` and seven indexes over them (#349) |
| 14 | the column `sts_minted.key_sealed`: a minted row's name, sealed, beside the keyed digest in `key` (#222). The directory's `attrs` became a sealed blob, and its value lookups became columns the service writes as keyed digests, with `value_keys` and `attr_names` added (#391) |
| 15 | `sts_cluster_budgets`: a budget spent against a limit (#432) |
| 16 | `sts_ldap_counts`, `sts_ldap_count_deltas` and the triggers that keep them: the directory's counts kept rather than counted (#618) |
| 17 | the column `sts_ldap_entries.dek_keys` and its two indexes, and `sts_ldap_dek_counts`, `sts_ldap_dek_deltas` and their triggers (#623) |
| 18 | the partial indexes `sts_ldap_entries_asked_names` and `sts_ldap_entries_group_classes`, in place of `sts_ldap_entries_attr_names` and `sts_ldap_entries_classes`; `fastupdate = off` on the directory's GIN indexes (#618) |
| 19 | the counters sharded (`shard` in the keys of `sts_ldap_counts` and `sts_ldap_dek_counts`), a BRIN in place of the btree on `sts_minted.written_at`, fillfactor 80 on `sts_minted`, autovacuum settings on `sts_changes` and `sts_ldap_entries`, and the `pg_stat_statements` extension (#630). Run `postgres/schema.sql` again as the owner to upgrade |
| 20 | `sts_ldap_entries.parent_key`'s `n_distinct` set by hand (#639) |
| 21 | `sts_sessions`: the searchable index of each live session, written in the same transaction as its sealed body (#350) |
| 22 | the partial index `sts_sessions_surface` (#754) |
| 23 | the `pg_trgm` extension and `sts_ldap_entries_uid_trgm`, a trigram index over the login names under each realm's `ou=users` (`/portal/delegate`'s search) |
| 24 | `sts_minted_index`: the index rows of an on-demand minted store (#820) |
| 25 | the column `sts_minted_index.sort_at` and the partial index `sts_minted_index_sort` (#820) |
| 26 | `sts_report_artifacts`: the bytes of a finished report (#956). Definitions and job rows stay in the realm maps |
| 27 | `sts_ldap_entries_asked_names` rebuilt with `stsbackupcodes` among the asked names, so the reports application finds recovery-code holders through the index (#1024) |
| 28 | two B-trees, `sts_ldap_entries_created` and `sts_ldap_entries_modified`, for a report's date range; `pwdaccountlockedtime` among the asked names, so "status is locked" is an index read; the asked-names index rebuilt again (#1028) |

**Versions 27 and 28 rebuild an index on a large table.** The script drops
`sts_ldap_entries_asked_names` and builds it again with the new list of
names, which reads the whole directory once and holds writers off while it
does. On a large store, run it at a quiet time.

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
  cluster, session, risk and report tables use `bigint` milliseconds; the
  cluster tables take them from the **database's** clock so that two nodes'
  clocks never need to agree. `sts_ldap_entries` stores LDAP generalized time
  as `text`.
* **`origin` is the process that wrote the row**: a UUID made when each process
  starts. A process uses it to skip its own rows in the change log, and the
  cluster tables use it to show who holds a claim. (`sts_ldap_entries.origin`
  is different: it says how the entry came to exist.)
* **Anything that could be used as a credential, and most personal data, is
  sealed or replaced by a digest.** See *Encryption at a glance*, below.

## Encryption at a glance

Three words are used for every column on this page:

* **sealed**: encrypted by the service before it reaches the database, with
  AES-256-GCM (or AES-256-SIV, where that data key is a SIV key) under a data
  encryption key. The stored text names the data key that sealed it:
  `$aesgcm$2$<data key id>$<iv>$<tag>$<ciphertext>`. The database cannot read
  it, so nothing can search or index it.
* **digest**: the value is replaced by a one-way digest and cannot be turned
  back into it. Most are **keyed** (HMAC-SHA-256 under a digest key the
  service holds), so a guessable value such as a username cannot be found by
  hashing guesses. A few are a plain SHA-256, where noted.
* **clear**: stored as is. Identifiers the service needs to route and find
  rows (realm ids, store names, distinguished names, key ids, times, counts)
  are in the clear.

The data keys are stored in `sts_keys`, each wrapped by the
**key-encryption key**, which is never in the database: it comes from a
mounted file, a secret store or a key management service, as
[encryption at rest](encryption-at-rest.md) explains. `/admin/encryption` on
a running service lists what it seals.

**This is product mode.** Sealing and keyed digests need a key-encryption key
that outlives the process. Where there is none (development mode), the
directory's attributes, its lookup columns, the secret settings and the
used-assertion columns are written in the clear, the cluster tables' digests
are a plain SHA-256, and the rows that exist only as keyed digests
(`sts_sessions`, `sts_minted_index`, `sts_cell_routing`) are not written.

| Table | Sealed | Digest | Clear |
|---|---|---|---|
| `sts_ldap_entries` | `attrs` (the whole entry) | `name_keys`, `mail_keys`, `uuid_keys`, `class_keys`, `value_keys` (keyed) | `realm`, `dn_key`, `dn`, `parent_key`, `rdn_value` (the login name), `attr_names` (attribute names only), `dek_keys`, `origin`, `created_at`, `modified_at` |
| `sts_ldap_counts`, `sts_ldap_count_deltas` | — | — | every column (DNs and counts) |
| `sts_ldap_dek_counts`, `sts_ldap_dek_deltas` | — | — | every column (data key ids and counts) |
| `sts_realms` | the secret settings inside `overrides` | — | everything else |
| `sts_appconfig` | `value` of a secret setting | — | `key`, and `value` of every other setting |
| `sts_keys` | `material` (signing keys and CA key pairs); data-key rows hold each key wrapped by the key-encryption key | — | `realm`, `written_at` |
| `sts_minted` | `body`, `key_sealed` | `key` (keyed) | `handle`, `realm`, `written_at`, `expires_at` |
| `sts_sessions` | — (the session itself is in `sts_minted`) | `key`, `subject_key`, `username_key`, `parent_key` (keyed); `credential_key` (SHA-256) | `realm`, the times, `chosen`, `authenticated`, `kind`, `rp_surface`, `backs_console`, `partner_relationship` |
| `sts_minted_index` | — | `index_key`, `key` (keyed) | `handle`, `realm`, `sort_at` |
| `sts_used_assertions` | `issuer`, `identifier`, `client_id`, `subject` | `key` (SHA-256) | `realm`, `format`, `used_as`, `state`, `reservation`, `origin`, the times |
| `sts_changes` | `key` of a minted change (the row's name) | — | `seq`, `origin`, `kind`, `realm`, `at`, and `key` of a directory change (a DN) |
| `sts_change_readers` | — | — | every column |
| `sts_cluster_nodes` | — | `fingerprint` (keyed) | everything else |
| `sts_cluster_leases` | — | — | every column |
| `sts_cluster_claims`, `sts_cluster_counters`, `sts_cluster_windows`, `sts_cluster_budgets` | — | `key` (keyed) | everything else |
| `sts_cluster_secrets` | `material` | — | `name`, `created_by`, `created_at` |
| `sts_node_snapshots` | — | — | every column |
| `sts_cell_routing` | — | `digest` (keyed) | `realm`, `kind`, `cell`, `written_at` |
| `sts_risk_assessments` | `address_sealed` | `ua_hash`, `credential_hash` (SHA-256) | everything else, including `address_prefix` (the network, not the host) |
| `sts_risk_failures` | `address_sealed` | `name_hmac` (keyed) | everything else |
| `sts_risk_session_context` | — | `ua_hash` (SHA-256) | everything else |
| the other eleven `sts_risk_*` tables | — | — | every column (public datasets, counts and scores) |
| `sts_report_artifacts` | `bytes` (since #1033) | `sha256` | `realm`, `job_id`, `media_type`, `created_at` |
| `sts_schema` | — | — | every column |

Two things on that list deserve an operator's attention:

* **A finished report is stored sealed** (since #1033), because a report
  can list people. Without a key-encryption key the service refuses to
  store one rather than write it in the clear, and the job fails. A row
  written before #1033 stays in the clear until its retention ends; see
  [Reports](reporting.md) for how long one is kept.
* **The directory's names are in the clear.** A person's DN, and so their
  login name (`uid`), is readable in `dn`, `dn_key` and `rdn_value`, because
  every cross-entry reference in the directory is a DN. Their attributes
  (mail, display name, credentials) are not.

## The tables, by what they hold

```
 directory & configuration           minted state                cluster coordination
 ─────────────────────────           ────────────                ────────────────────
 sts_ldap_entries  (attrs sealed)    sts_minted (body sealed)    sts_cluster_nodes
 sts_ldap_counts                     sts_sessions   (digests)    sts_cluster_leases
 sts_ldap_count_deltas               sts_minted_index (digests)  sts_cluster_claims
 sts_ldap_dek_counts                 sts_used_assertions         sts_cluster_secrets (sealed)
 sts_ldap_dek_deltas                                             sts_cluster_counters
 sts_realms                          change log                  sts_cluster_windows
 sts_appconfig                       ──────────                  sts_cluster_budgets
 sts_keys          (sealed)          sts_changes                 sts_node_snapshots
 sts_cell_routing  (digests)         sts_change_readers
                                                                 risk scoring: 14 × sts_risk_*
 bookkeeping                         reports
 ───────────                         ───────
 sts_schema                          sts_report_artifacts (sealed)
```

There are no foreign keys. Every table is keyed by what its readers look up,
and a row is re-read by key rather than joined.

---

## Directory and configuration

### `sts_ldap_entries`: the embedded directory

The [LDAP directory](ldap.md) has one row per entry, for every realm: people,
groups, applications, devices and the containers that hold them. The service
writes it whenever an entry changes (from the console, `/admin-api`, LDAP,
SCIM or a sign-in) and reads it to answer every directory question. The
[LDAP schema](ldap-schema.md) page describes what goes in `attrs`.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `realm` | text | clear | the trust realm whose tree holds the entry |
| `dn_key` | text | clear | **the normalised DN**, from `ldap_server.js`'s `normalizeDn()`. `UID=Alice,OU=Users` and `uid=alice,ou=users` are the same key |
| `dn` | text | clear | the DN as it was written, which is what a search returns |
| `attrs` | jsonb | **sealed (AES-256-GCM)** | every attribute of the entry, operational attributes included, sealed as one value under the realm's `directory` data key (a person's under their home cell's key, where cells are in use). The sealed value names its DN, so a blob copied onto another row does not open. Inside it, `userPassword` is an scrypt hash, recovery codes and app passwords are hashed, and a TOTP secret or a Kerberos key is sealed again under its own data key |
| `origin` | text | clear | how the entry came to exist: `seed`, `console`, `ldap add`, `scim`, … (the `# sts-origin:` comment in an LDIF export) |
| `created_at`, `modified_at` | text | clear | RFC 4517 generalized time (`20260827192200Z`), **byte-identical** to `createTimestamp` / `modifyTimestamp` inside `attrs` |
| `parent_key` | text, generated | clear | the parent's key: everything after the first comma of `dn_key` |
| `rdn_value` | text, generated | clear | the first RDN's value, lower-cased: **a person's login name (`uid`)** |
| `name_keys` | jsonb, written | digest (keyed HMAC-SHA-256) | the `uid` values, lower-cased, each as a keyed digest |
| `mail_keys` | jsonb, written | digest (keyed HMAC-SHA-256) | the `mail` values, lower-cased |
| `uuid_keys` | jsonb, written | digest (keyed HMAC-SHA-256) | the `entryUUID` and `stsEntryUuidAlias` values, lower-cased |
| `class_keys` | jsonb, written | digest (keyed HMAC-SHA-256) | the entry's **group** classes (`groupOfNames`, `groupOfUniqueNames`, `posixGroup`, `groupOfURLs`), `[]` for anything else (schema version 18) — how a group placed under `ou=users` is found. An entry written before version 18 holds all its classes until it is next written |
| `value_keys` | jsonb, written | digest (keyed HMAC-SHA-256) | `name=value` of the attributes looked up by exact value: `uid`, `didSubject`, `spiffeSubject`, `x509Subject`, `federationLink`, a device's key thumbprint, secret hash and credential id, and `owner` |
| `attr_names` | jsonb, written | clear (names only) | every attribute **name** the entry holds, lower-cased: who holds a credential of a kind, and the counts' `userpassword`. No value is in it |
| `dek_keys` | jsonb, nullable | clear (key ids) | the data keys the entry holds values under, `{ "<key id>": <values> }`: the entry's own key and the key of each sealed value inside it (schema version 17). NULL for an entry written before version 17, until the service indexes it |

Primary key `(realm, dn_key)`. Its fourteen other indexes are listed under
*Indexes*, below.

**Two columns are generated by the database and the rest are written by the
service.** `parent_key` and `rdn_value` are computed from `dn_key`, so
nothing writes them. The value lookups (`name_keys` to `value_keys`) cannot
be generated, because the database cannot read the sealed `attrs`: the
service computes each value's keyed digest beside the entry and writes them
in the same statement. A lookup of a login name, an email address or a UUID
is therefore still one index probe, but nothing in those columns says what
it matched. They exist for a request worker with
`ldap.workerDirectory=postgres-lru`, which holds the people and devices as a
bounded window and asks the store instead of keeping an index in memory.

**Two of the GIN indexes are partial since schema version 18 (#618).** A GIN
index takes an entry for every key of every row it covers, and a person
carries about fifteen attribute names and four object classes, nearly all
of them shared by every other person. So:

* `sts_ldap_entries_asked_names` indexes an expression of `attr_names` that
  keeps only the names the service asks "who holds this" about (the
  credential, consent, delegation, key, enrollment and lock attributes,
  `stsBackupCodes` since version 27 and `pwdAccountLockedTime` since 28;
  `ASKED_ATTRIBUTES` in `persistence/directory_queries.js`), and only rows
  that hold one of them;
* `sts_ldap_entries_group_classes` indexes `class_keys` only where it is not
  empty, and the service writes only group classes into it.

A person who holds none of those attributes writes no entry to either index.
On a copy of a 1.2M-entry store, version 17's two indexes cost about two WAL
records and 1.1 KB of WAL per person inserted; version 18's cost nothing
measurable, and the attribute-name index went from 23 MB to 16 kB. They
replace `sts_ldap_entries_attr_names` and `sts_ldap_entries_classes`, which
`postgres/schema.sql` drops.

**Every GIN index on this table except the data keys' has `fastupdate = off`
(schema version 18).** With PostgreSQL's default, inserts are queued in a
pending list that every search reads in full until a vacuum merges it; on a
busy directory that made each login-name or UUID lookup read hundreds of
pages. With it off, each insert updates the index at once and a lookup reads
a handful of pages.

**Upgrading a store from version 17.** Run `postgres/schema.sql` as the owner.
It builds the two new indexes, which reads the table once and holds writers
off while it does (seconds at a million entries), then drops the two old
ones, switches the existing GIN indexes to `fastupdate = off` and flushes
what each has queued. Nothing is rewritten. Entries written before the upgrade keep all their
object classes in `class_keys`, so they stay in the classes index until they
are next written; that changes no answer. The service refuses to start
against a version 17 store whose role cannot build the new indexes, and says
to run the script.

**`parent_key`'s statistics are set, not sampled (schema version 20, #639).**
A directory where one container holds nearly every entry — fifty million
people under one `ou=users` — gives `ANALYZE`'s sample of about 30,000 rows
one parent, so PostgreSQL concludes the column has one distinct value. The
script sets the column's `n_distinct` to 100,000 and analyzes that column:

```sql
ALTER TABLE sts_ldap_entries ALTER COLUMN parent_key SET (n_distinct=100000);
ANALYZE sts_ldap_entries (parent_key);
```

The setting survives every later `ANALYZE` and autovacuum. Check it with
`SELECT attoptions FROM pg_attribute WHERE attrelid =
'sts.sts_ldap_entries'::regclass AND attname = 'parent_key'` (it reads
`{n_distinct=100000}`) and `SELECT n_distinct FROM pg_stats WHERE schemaname
= 'sts' AND tablename = 'sts_ldap_entries' AND attname = 'parent_key'`
(100000).

**Upgrading a store from version 19.** Run `postgres/schema.sql` as the
owner. It sets the statistic and analyzes one column (a sample, seconds at
fifty million entries); nothing is rewritten, and neither statement blocks a reader or
a writer. The service starts against a version 19 store without it and says
so once per process (`STS-STORE-0083`): its own statements read a
container's entries in a way that does not depend on the statistic, so a
missed upgrade costs plans elsewhere, not the start.

**What you can query with SQL.** The DNs, the login names, the attribute
names and the times are in the clear, so questions about the shape of the
directory can be asked directly:

```sql
-- the people in the default realm who hold a passkey, newest first
SELECT dn, created_at
  FROM sts.sts_ldap_entries
 WHERE realm = 'default'
   AND parent_key LIKE 'ou=users,%'
   AND attr_names ? 'stswebauthncredential'
 ORDER BY created_at DESC;
```

An attribute's **value** (an email address, a display name) cannot be read
or searched in SQL in product mode, because it is inside the sealed `attrs`.
Use the console, `/admin-api` or LDAP for that. In development mode, where
nothing is sealed, `attrs` is plain JSON and `attrs->'mail'->>0` works.

When two nodes change one entry at the same time, the update is a three-way
merge (`persistence/directory_merge.js`), not last-writer-wins.

The `created_at` and `modified_at` columns are `text` rather than `timestamptz`
so that they match the LDAP attributes byte for byte. A round trip through
`timestamptz` would re-render the value in the session's format and time zone.
Generalized time sorts correctly as text, which is what the version 28 date
indexes rely on.

### `sts_ldap_counts` and `sts_ldap_count_deltas`: the directory's counts

Schema version 16 (#618). A request worker that holds the directory as a
window used to ask `count(*)` for `ldap.maxEntries`, for a container's count
on a Directory page, and for the credential tiles on `/admin/users`. A
`count(*)` is linear in the realm's rows. Each count is now one primary-key
read of `sts_ldap_counts`:

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `realm` | text | clear | the trust realm |
| `base_key` | text | clear | a normalised DN, or `''` for the whole realm. The count is of the entries **strictly under** it, so every ancestor of a row's DN has a row of its own |
| `attribute` | text | clear | `''` for every entry, or a counted attribute (`userpassword`) for the entries that hold it |
| `shard` | smallint | clear | which of sixteen rows of this counter (schema version 19, #630) |
| `n` | bigint | clear | this shard's part of the count; one shard may be negative |

Primary key `(realm, base_key, attribute, shard)`. **A count is the sum of
its shards**: each commit adds to the shard of its own server connection
(`pg_backend_pid() % 16`), so two commits of one realm rarely wait on the
same row, and every reader sums. A base with no row has nothing under it.

`sts_ldap_count_deltas` holds, for the length of one transaction, that
transaction's net change per parent: `txid` (the transaction), `realm`,
`parent_key` (a DN), `n` (entries added or removed), `holding` (of those,
how many hold a password) and `fold` (the one marker row per transaction
that triggers the fold). Every column is clear; none is personal data
beyond a container's DN.

**The database keeps the counts, not the service.** Triggers on
`sts_ldap_entries` see every write in the transaction that makes it,
whichever process or tool wrote it:

1. Each INSERT, UPDATE or DELETE statement appends its net change per parent
   to `sts_ldap_count_deltas`. This table is insert-only, so writers never
   wait on each other here.
2. When the transaction commits, a deferred constraint trigger folds that
   transaction's deltas into `sts_ldap_counts` in one statement, in key
   order.

A committed transaction leaves no delta rows behind. The counter rows are
locked only for the last moment of a commit. Updating them on every
statement would serialise every flush of a realm on the same few rows.

A TRUNCATE empties the counters. The service's role cannot TRUNCATE.

**The counts start with one count of the table.** When the triggers are
created, by `postgres/schema.sql` or by the driver against an empty store,
`sts_ldap_entries` is locked against writers and counted. This happens only
while `sts_ldap_counts` is empty, and it is the only count of the directory
there is. On a large directory the first `schema.sql` run after upgrading to
version 16 holds that lock for as long as the count takes: minutes at
hundreds of millions of rows. After that the counts cost nothing to read.

### `sts_ldap_dek_counts` and `sts_ldap_dek_deltas`: values per data key

Schema version 17 (#623). The data-key jobs (re-encryption and the daily
count, see [Encryption at rest](encryption-at-rest.md)) need to know which
directory entries hold a value under a given data key, and how many values
each key has. They used to read and decrypt every directory entry to find
out. Now:

* every write of an entry also writes its `dek_keys`;
* a re-encryption pass reads only the entries whose `dek_keys` name a
  retiring key (a GIN index on `dek_keys`);
* `sts_ldap_dek_counts` holds, per data key (`dek_id`) and shard
  (`shard`, primary key `(dek_id, shard)` since version 19), the number of
  values (`n`) the directory holds under it; the count is the sum of the
  key's shards.

`sts_ldap_dek_deltas` has `txid`, `dek_id`, `n` and `fold`, with the same
meaning as the directory count deltas. Every column of both tables is
clear: a data key's **id** and a number, never the key.

The counts are kept by triggers, exactly as `sts_ldap_counts` is: each
statement appends its net per key to `sts_ldap_dek_deltas`, and a deferred
constraint trigger folds a transaction's deltas into the counts at commit.

**Upgrading a store from version 16.** The new column is added without a
default, so the `ALTER` rewrites nothing and every existing entry reads
NULL ("keys not known"). A partial index finds those entries. The service
indexes them itself, a bounded batch per run of each data-key job (at most
10 seconds per run), so a large directory is indexed over a few hours after
the upgrade. Until that finishes, the jobs re-encrypt what they can find
but do not count or destroy any data key. Running `postgres/schema.sql`
again as the owner adds the column, the indexes, the two tables and the
triggers; it does not need to index the entries.

### `sts_realms`: the realm registry

One row per trust realm other than the default one, written when a realm is
created, changed or removed in the console or `/admin-api`, and read by
every process at start and whenever the change log says a realm changed.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `id` | text PK | clear | the realm id, which is the path segment in `/realm/<id>/…` |
| `name`, `description` | text | clear | display text |
| `created_at` | bigint | clear | milliseconds |
| `overrides` | jsonb | clear, except **secret settings, sealed** | the realm's own setting values, `{ "oauth2.rfc9700": true, … }`. A setting marked secret (today only `scim.digestPassword`) is stored as a sealed value inside the JSON |
| `domain` | text | clear | the realm's DNS domain, **fixed at creation**, which becomes the directory base `dc=…` (v6) |
| `retiring_at` | bigint | clear | milliseconds, or NULL: when the realm's removal began. While it is set, every process refuses new sign-ins and issuance in the realm; it is never cleared, because the removal deletes the row (v10, [#262](https://github.com/rcbj/iya-sts/issues/262)) |

The default realm is not a row. Its settings are the process's own.

### `sts_appconfig`: runtime setting changes

One row per setting changed at runtime, from the console or `/admin-api`.
On restart these come back as runtime overrides, not as a new configuration
layer ([persistence](persistence.md#settings-come-back-as-runtime-overrides-not-as-a-new-layer)).

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `key` | text PK | clear | the setting name (`oauth2.consentRequired`) |
| `value` | jsonb | clear, except a **secret setting, sealed** | the value. A setting marked secret (today only `scim.digestPassword`) is sealed |

### `sts_keys`: private keys and data keys this service generated

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `realm` | text PK | clear | what the row holds: `<realm id>` for a realm's JWS signing keys, `pki:<realm id>` for that scope's certificate-authority hierarchy (Root, Intermediate, Issuing CAs), or `dek:<scope>:<realm>` for the data encryption keys of that scope and realm |
| `material` | text | **sealed (AES-256-GCM)** | for signing keys and CA key pairs, ciphertext, `$aesgcm$2$…`. For a `dek:` row, JSON listing the data keys, each **wrapped by the key-encryption key** (`$dekwrap$1$…`, or `$dekkms$1$…` when a key management service wraps it); the ids and dates beside them are clear |
| `written_at` | timestamptz | clear | the time of the last write |

Signing keys and CA hierarchies are kept here in product mode only.
Development regenerates its keys on every start. The prefixes keep the three
kinds apart without a discriminator column. The first writer wins: a process
that finds a row already present adopts it instead of overwriting it
(`SELECT … FOR UPDATE`). This is how every node ends up with the same `kid`.
See [PKI](pki.md) and [encryption at rest](encryption-at-rest.md).

### `sts_cell_routing`: where each person is homed

Used only when the service runs as several [cells](cells.md) (#98). One row
per person's login name or other routing value, saying which cell holds
them, so a request arriving at the wrong cell can be sent to the right one.
Written when a directory entry is flushed; read on sign-in routing.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `realm` | text | clear | the trust realm |
| `kind` | text | clear | what the digest is of (a login name, an email address, …) |
| `digest` | text | digest (keyed HMAC-SHA-256) | the value's keyed digest; the value itself is never stored |
| `cell` | text | clear | the cell id the person is homed in |
| `written_at` | bigint | clear | milliseconds |

Primary key `(realm, kind, digest)`; no other index.

---

## Minted state

### `sts_minted`: everything the process issued

These are sessions, codes, tokens, artifacts, nonces, pending flows, counters
and the audit log, all in one table. It is written in product mode on postgres
only, and `persistence.minted` turns it off.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `handle` | text | clear | **the store's name**, taken from its declaration in the code: `realms.map({ persist: 'authn.sessions' })` |
| `realm` | text | clear | the realm id, or `''` for a store shared by the whole process (`realms.sharedMap()`) |
| `key` | text | digest (keyed HMAC-SHA-256) | the keyed digest of handle, realm and the record's name. The name is often the credential itself (a session cookie, a SAML artifact), so it is never stored as is |
| `key_sealed` | text | **sealed (AES-256-GCM)** | the record's name, sealed, for the one reader that has no name to start from: the restore at start (schema version 14) |
| `body` | text | **sealed (AES-256-GCM)**, always | the record, `$aesgcm$2$…` |
| `written_at` | timestamptz | clear | when the row was last written. A short-lived store's row with no `expires_at` that is older than `persistence.mintedRetention` (7 days) is neither restored nor kept |
| `expires_at` | bigint | clear | **the record's own expiry**, in epoch milliseconds, as the store computed it when it wrote the row, or NULL for a record that does not expire (and for a tombstone). A start reads no row whose expiry has passed, and the `persistence.minted-expiry-purge` job deletes such rows in batches (schema version 12, #333) |

Primary key `(handle, realm, key)`, with indexes on `(handle, realm)`,
`written_at`, and `expires_at` where it is not NULL. Since schema version
19 (#630) the `written_at` index is a BRIN (`sts_minted_written_brin`) and
the table's fillfactor is 80: every write of a row sets `written_at`, and a
btree on it made every update copy the row to a new page and add an entry
to every index. A BRIN does not, on PostgreSQL 16 and later. Only the
clean-up jobs read `written_at`; they may read more of the table than they
did.

A start reads only the rows of the realms that exist: `''` (the shared
stores), the default realm, and every realm in `sts_realms`. Rows of a realm
that is no longer defined are deleted by the same job once they are an hour
old.

**There is one table rather than one per family**, so that persisting a new
store costs one word at its declaration and no DDL. The price is that nothing
in the table can be queried with SQL, because a session id is a cookie value
and an authorization code can be redeemed. A dump of this table must not give
anyone a live session. The two tables that follow exist so that the few
questions the service does need to ask across these rows can be answered
without opening them.

The handles in use, grouped by family (a `test.*` handle is used only by
tests):

| Family | Handles |
|---|---|
| Sign-in | `authn.sessions`, `authn.pending`, `authn.pendingMfa`, `authn.pendingPasswordChange`, `authn.webauthnCredentials`, `credentials.pendingBackupCodes`, `credentials.pendingKeys`, `credentials.pendingTotp`, `spnego.pending`, `oidc_rp.flows` |
| OAuth / OIDC | `oauth2.authzCodes`, `oauth2.redeemedCodes`, `oauth2.pushedRequests`, `oauth2.attestationChallenges`, `oauth2.backchannelDeliveries`, `oauth2.cibaRequests`, `oauth2.cibaDeliveries`, `oauth2_bcp.refreshTokens`, `oauth2_bcp.refreshFamilies`, `oauth2_bcp.grantTokens`, `oauth2_bcp.transactions`, `oauth2.grants`, `oauth2.grantIssued`, `oauth2_monitor.counters`, `consent_screen.pending`, `authorization_details.consented`, `authorization_servers.profiles`, `dpop.issuedNonces`, `dpop.seenJtis` |
| SAML, WS-* and federation | `saml2_sso.artifacts`, `saml2_sso.pendingRequests`, `saml2.mdqRefusals`, `saml11_sso.artifacts`, `saml11_sso.assertionsById`, `saml11_sso.pendingFlows`, `federation_sp.contexts`, `federation.unmapped`, `delegation.acts` |
| Verifiable credentials | `vc_offers.credentialOffers`, `vc_offers.preAuthorizedCodes`, `vc_offers.issuerStates`, `vc_offers.deferredAccessTokens`, `vc_offers.deferredTransactions`, `vc_offers.signingAlgTokens`, `vc_issuer.vciNonces`, `vc_issuer.notificationIds`, `vc_issuer.lastCredentialRequest`, `vc_issued.credentials`, `vc_issued.bySubject`, `vc_issued.byNotification`, `vc_status.entries`, `vc_trusted_list.state`, `vc_claims.state`, `vc_verifier.vpRequests`, `vc_verifier.vpTransactions`, `vc_verifier_config.state` |
| GNAP | `gnap.grants`, `gnap.continuations`, `gnap.interactions`, `gnap.tokens`, `gnap.tokenValues`, `gnap.instances`, `gnap.approvers`, `gnap.resources`, `gnap.manageHandles`, `gnap.manageValues`, `gnap.userCodes`, `gnap.userRefs`, `gnap.replay`, `gnap.movedGrants`, `gnap_monitor.counters` |
| Kerberos | `krb5.principals`, `krb5.replayCache` |
| Certificate enrollment | `acme.accounts`, `acme.accountKeys`, `acme.orders`, `acme.authorizations`, `acme.certificates`, `acme.renewalInfo`, `acme.usedNonces`, `scep.transactions`, `enrollment_monitor.*` |
| SPIFFE | `spiffe.authorities`, `spiffe.federatedBundles`, `spiffe.joinTokens`, `spiffe.recordedConnections`, `spiffe.sigstoreTuf` |
| SCIM | `scim.digestNonces`, `scim.digestCounts`, `scim.hobaChallenges`, `scim.hobaSeen` |
| Shared Signals | `ssf_streams.streams`, `ssf_streams.queued`, `ssf_streams.deadLetters`, `ssf_receivers.inbox`, `ssf_dead_letter_report.sweeps`, `caep.register`, `risc.register` |
| Mail | `mail.outbox`, `mail.preferences`, `mail.templates` |
| Attribute sources | `attribute_sources.status` |
| Devices | `devices.events`, `devices.androidRecheck` |
| OpenID Federation | `oidfed.registerGeneration` |
| Reports | `report.definitions`, `report.jobs`, `report.control` (the finished bytes are in `sts_report_artifacts`) |
| Console statistics and audit | `admin_stats.tokens`, `admin_stats.artifacts`, `admin_stats.revokedArtifacts`, `admin_stats.revokedJtis`, `admin_stats.claimSets`, `admin_stats.users`, `admin_stats.calls`, `admin_stats.nums`, `admin_stats.scimCounts`, `claim_attributes.selections`, `xacml_monitor.counters`, `audit.events`, `audit.nums` |
| Process-wide | `security.rateLimitBuckets`, `ldap.clusterConnections`, `ldap.clusterSignOuts`, `scheduler.runs`, `signing.history`, `tls.listenerAnnounced`, `tls.listenerKeys`, `tls.presentedChains`, `tls.ticketNames` |

To list them from a running tree:
`grep -rhoE "persist: *'[^']+'" --include=*.js --include=*.ts . | sort -u`.

### `sts_sessions`: the searchable index of live sessions

Schema version 21 (#350). A sign-on session's record is sealed in
`sts_minted` under the handle `authn.sessions`. The console, the session
sweep, sign-out and the CAEP receivers need to ask questions across
sessions ("this person's sessions", "the sessions that have expired", "the
relying-party sessions derived from this one") without opening every one.
So each session also has one row here, written in the same transaction as
its sealed body, holding only what those questions compare. The session id
is not a column: `key` is the same keyed digest as the `sts_minted` row's.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `realm` | text | clear | the trust realm |
| `key` | text | digest (keyed HMAC-SHA-256) | the session's `sts_minted.key` |
| `expires_at` | bigint | clear | milliseconds, or NULL for a session with no absolute expiry |
| `last_seen_at`, `started_at` | bigint | clear | milliseconds |
| `subject_key` | text | digest (keyed HMAC-SHA-256) | the person (`sub`) the session is for |
| `username_key` | text | digest (keyed HMAC-SHA-256) | the username they signed in with |
| `chosen` | boolean | clear | false for an arrival session nobody has signed in to yet |
| `authenticated` | boolean | clear | whether the session is signed in |
| `kind` | text | clear | `sign-on`, `keyed` (an API client's session), `relying-party` (one of this service's own surfaces) or `arrival` |
| `rp_surface` | text | clear | for a relying-party session, which hosted surface it belongs to; `''` otherwise |
| `parent_key` | text | digest (keyed HMAC-SHA-256) | for a relying-party session, the sign-on session it came from; `''` otherwise |
| `backs_console` | boolean | clear | whether the session backs an admin console sign-in |
| `credential_key` | text | digest (SHA-256, truncated) | for an API client's session (SCIM, the SPIRE Server API, …), a fingerprint of the scheme and the client that authenticated, never the credential; `''` otherwise |
| `partner_relationship` | text | clear | the federation relationship id, for a session that began at a federated partner; `''` otherwise |

Primary key `(realm, key)`; seven partial indexes (see *Indexes*). A row is
written only where the service holds a digest key.

### `sts_minted_index`: the index rows of on-demand stores

Schema versions 24 and 25 (#820). Some minted stores are too large to hold
in memory and are read **on demand**: every refresh token of one family,
every token issued to one person. Because the bodies are sealed, the
database cannot answer "the rows for this person"; this table answers it.
Each row says "the `sts_minted` row with this key is filed under this index
value", and is written in the same transaction as the body.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `handle` | text | clear | the store's name, as in `sts_minted` |
| `realm` | text | clear | the realm id |
| `index_key` | text | digest (keyed HMAC-SHA-256) | the keyed digest of the index value (a family, a person), or the fixed marker `$sort$` for a store's sort row |
| `key` | text | digest (keyed HMAC-SHA-256) | the `sts_minted.key` of the row it points to |
| `sort_at` | bigint | clear | on a sort row, the store's sort value (a time in milliseconds), which `minted.newest` walks newest first; NULL on every other row |

Primary key `(handle, realm, index_key, key)`.

### `sts_used_assertions`: accepted-once history for RFC 7523 and RFC 7522

This table holds every JWT and SAML assertion accepted as a client credential
or a grant, kept until the assertion would have expired, so that none is
accepted twice ([JWT assertions](jwt-assertions.md),
[SAML assertions](saml-assertions.md)). It is written **in both modes**,
because the key that verifies an assertion belongs to the client and outlives
a restart.

| Column | Encrypted? | Meaning |
|---|---|---|
| `realm` | clear | PK, with `key` |
| `key` | digest (SHA-256) | a SHA-256 of format, issuer and identifier; **the assertion itself is never stored** |
| `format`, `used_as` | clear | `jwt` or `saml2`; a client credential or a grant |
| `issuer`, `identifier`, `client_id`, `subject` | **sealed (AES-256-GCM)** | what the assertion said: who issued it, its `jti` or `ID`, the client that presented it and who it was about. Sealed in product mode, so the console's text search over them is done in the service, over the newest rows |
| `state`, `reservation`, `spent_at` | clear | reserved when checked, **spent only when tokens are issued**, released otherwise |
| `origin`, `used_at`, `expires_at` | clear | ms; index `(realm, expires_at)` for the purge |

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

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `seq` | bigserial PK | clear | assigned by the database and only ever increasing: **the whole synchronisation primitive** |
| `origin` | text | clear | the writing process, which skips its own rows |
| `kind` | text | clear | `directory`, `realms`, `appconfig`, `keys`, `minted`, `minted-own`, `risk-dataset` |
| `realm` | text | clear | the realm the change is in |
| `key` | text | **sealed** for a minted change; clear otherwise | **a pointer, never data**: the reader re-reads the named row from its own table. For a minted change it is the row's name, sealed, because a reader told of a delete must drop that name from its own memory; for a directory change it is the entry's DN |
| `at` | timestamptz | clear | indexed, for trimming |

Every change-log row is **written in the same transaction as the change it
describes**, so "I have applied up to N" means "I have seen everything
committed before N". `LISTEN`/`NOTIFY` on the channel `sts_ldap_change` only
wakes the poll early. Losing a notification costs latency, never correctness.
The payload is only a pointer, so neither the 8000-byte `NOTIFY` limit nor
encryption applies to it. Since #630 the notification is sent **after** the
transaction commits, and at most once every 25 ms per process for all the
commits in that window. A notification sent inside the writing transaction
made every writer wait for a lock at commit.

Autovacuum runs on this table at 2% dead rows
(`autovacuum_vacuum_scale_factor=0.02`) with ten times the default cost
limit, because the trim deletes from it all the time.

### `sts_change_readers`

Each process that reads the log reports the highest `seq` it has applied
(`applied`), with its `node_id` and times (`started_at`, `reported_at`),
keyed by its `origin`. `sts_changes` is trimmed below the lowest of these
marks by the scheduler job that holds the lease `ops.change-log-purge`.
Every column is clear.

---

## Cluster coordination (#46)

These tables are used when [several containers share one store](aws-cluster.md).
Every time is the database clock in milliseconds.

| Table | Primary key | What a row is | Encrypted? |
|---|---|---|---|
| `sts_cluster_nodes` | `node_id` | a member: `name`, `mode` (`active-passive` / `active-active`), `version`, a configuration `fingerprint` nodes must share, `started_at`, `heartbeat_at`, `expires_at`, `left_at`, and `info` (JSONB). Indexed on `expires_at` | `fingerprint` is a keyed digest of the configuration; the rest is clear |
| `sts_cluster_leases` | `name` | a named lease: `holder`, a **fencing `token`** that rises every time the lease changes hands (write transactions check it), `acquired_at`, `expires_at`. The names in use are `service` (active-passive), `ops.scheduler` (the scheduler's leader), `ops.change-log-purge` and `ssf.dead-stream-probes` | all clear |
| `sts_cluster_claims` | `(scope, realm, key)` | **a value spent once across the cluster**. The row holds a `reservation`, an `origin`, `claimed_at` and `expires_at`, and is kept or released. Examples of scopes: `oauth.code`, `oauth.refresh`, `oauth.par`, `oauth.dpop-jti`, `saml2.artifact`, `saml11.artifact`, `krb5.authenticator`, `acme.nonce`, `acme.finalize`, `acme.eab-bind`, `scep.challenge`, `oid4vci.pre-authorized-code`, `oid4vp.sign-in`, `spiffe.join-token`, `spnego.continuation`, `authn.session-end`, `pki.build`, `ops.bootstrap` | `key` is a keyed digest of scope and value, so the value (often a code or a token) is never stored; the rest is clear |
| `sts_cluster_secrets` | `name` | a secret every node must agree on. **The first writer wins.** The names are `csrf`, `acme-nonce`, `ssf-receiver`, `oidc-pairwise`, `oidfed-page`, `logout-result` and `dbsc` (`cluster/cluster_secrets.ts`), with `created_by` and `created_at`. Each can instead come from its `STS_*_SECRET` environment variable | **`material` is sealed** before it is inserted; the rest is clear |
| `sts_cluster_counters` | `(scope, realm, key)` | **a value that only goes up**, advanced by one conditional upsert, so a lower value never overwrites a higher one. Used for a WebAuthn signature counter and the last RFC 6238 time step spent. Holds `value`, `origin`, `updated_at` | `key` (the credential or person) is a keyed digest; the rest is clear |
| `sts_cluster_windows` | `(scope, realm, key)` | **a count inside a fixed window**: the rate limiter's buckets, one budget shared by every node. Holds `count`, `window_ends_at` (indexed) and `origin` | `key` is a keyed digest; the rest is clear |
| `sts_cluster_budgets` | `(scope, realm, key)` | **a budget spent against a limit** (#432, schema version 15): the running totals of a [GNAP](gnap.md) right's limits, kept per grant. One conditional upsert per spend, so two nodes spending one budget at once cannot both pass it. Holds `period`, `amount` (in millionths), `count`, `origin`, `expires_at` (the end of the grant, indexed for the purge) and `updated_at` | `key` is a keyed digest; the rest is clear |
| `sts_node_snapshots` | `name` | **what each node last said about itself** (#332): the node's own Monitoring → Worker Pools and → Node Health views as `body` (JSONB), written every 15 s by its front process, with the `node_id` that wrote it and `taken_at`. One row per node NAME, overwritten, so it never grows with time; a node that left keeps its row, drawn as gone, until the hourly `cluster.node-snapshot-purge` deletes it once it is older than `cluster.nodeSnapshotRetentionHours` (24). A live member's row is never deleted | all clear (process statistics, no personal data) |

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

**Every column of these nine tables is clear.** They hold published data
about networks and authenticators, not about people, except
`sts_risk_terms_acceptances.accepted_by`, which names the administrator who
accepted a provider's terms.

| Table | Primary key | What it holds |
|---|---|---|
| `sts_risk_datasets` | `(realm, dataset)` | one row per dataset: `kind`, `active_version`, `previous_version`, `state`, `updated_at` |
| `sts_risk_dataset_versions` | `(realm, dataset, version)` | the provenance of an import: `format`, `provider`, `licence`, `attribution`, `source`/`source_uri`, `sha256`, `byte_count`, `row_count`, `parameters`, `verification`, times through its lifecycle (`published`, `next_update`, `fetched`, `loaded`, `activated`, `superseded`, `rows_deleted`), `state`, and a `refusal` and `error_code` if it was refused |
| `sts_risk_dataset_blobs` | `(realm, dataset, version, part)` | the downloaded file, in `bytea` parts (`content`) |
| `sts_risk_geo_locations` | `(dataset, version, location_id)` | continent, country, subdivision, city, time zone |
| `sts_risk_geo_ranges` | `(dataset, version, range_start)` | `range_start`–`range_end` (`inet`) to a location, registered country, latitude and longitude, accuracy, and the anonymous-proxy and satellite flags |
| `sts_risk_asn_ranges` | `(dataset, version, range_start)` | an address range to `asn`, `as_org`, `as_domain` |
| `sts_risk_ip_lists` | `(realm, dataset, version, range_start)` | a listed range with its `category` and `note` (Tor, reputation, allow, deny) |
| `sts_risk_fido_authenticators` | `(dataset, version, key_kind, authenticator_key)` | one MDS3 entry, by AAGUID or key identifier: description, protocol family, certification level, latest status, `compromised`, and the status reports and metadata statement as JSONB |
| `sts_risk_terms_acceptances` | `id` (bigserial) | **who accepted which provider's terms**: `provider`, `terms_digest`, the full `terms_text`, `accepted_by`, `accepted_via`, `deployment`, `page_digest`, `accepted_at`. An import is refused unless a row exists for the provider's current terms |

### The history the model keeps

| Table | Primary key | What it holds | Encrypted? |
|---|---|---|---|
| `sts_risk_assessments` | `(realm, id)` | **one row per scored sign-in**: `at`, `phase`, `door`, `subject`, `session_id` (the session's stable `sid`, never its cookie), `client_id`; the address (`address_sealed`) plus its network prefix (`address_prefix`); ASN and location; `ip_lists` (text[]); the user-agent digest (`ua_hash`) and family, OS and platform, and `bot`; the `ja4` TLS fingerprint; the credential's kind and digest (`credential_kind`, `credential_hash`), the WebAuthn `aaguid`, the authenticator's FIDO certification level and backup flags, the DPoP `jkt`, the certificate fingerprint; the `datasets` versions consulted and the `signals` (JSONB); the `score` (real), `level`, `decision`, `policy_id`, `error_code`; and what the person said about the sign-in (`feedback`, `feedback_at`, from `/portal/sign-ins`). Indexed by subject, by session and by time | **`address_sealed` is sealed**; `ua_hash` and `credential_hash` are SHA-256 digests; everything else is clear (`jkt` and the certificate fingerprint are thumbprints of public keys) |
| `sts_risk_feature_counts` | `(realm, subject, feature, value)` | how often a person has been seen with a given country, ASN, device and so on, with `count`, `first_at`, `last_at`. This is what makes a feature familiar or new | clear (a `value` that was a digest when recorded stays one) |
| `sts_risk_failures` | `(realm, id)` | **every refused password**: `at`, `door`, and the `subject` if the name resolved, otherwise `name_hmac`. Also the address and its prefix, the ASN and the `error_code`. Indexed by subject, name, prefix and time, which are the four ways a spray or stuffing pattern is looked up | **`address_sealed` is sealed**; `name_hmac` is a keyed digest of the typed name (people type passwords into the username field, so the name is never kept); everything else is clear |
| `sts_risk_session_context` | `(realm, session_id)` | the context a session was established in (`subject`, prefix, ASN, country, user-agent digest, JA4, `jkt`, score, level, `updated_at`), so that a later request can be compared with it | `ua_hash` is a SHA-256 digest; the rest is clear |
| `sts_risk_subjects` | `(realm, subject)` | a person's current `score` and `level`, the `previous_level`, when it last crossed a threshold (`crossed_at`), and why (`reason`, `last_assessment`); the `actions` taken (JSONB) and their `feedback` | all clear |

The full address is sealed like any minted row; only its network prefix,
which is the network and not the host, is in the clear. A refused password
is written to the database only where it can be sealed; without a durable
key-encryption key, the failure history stays in the process.

---

## `sts_report_artifacts`

The bytes of a finished report (#956), written by the reporting job when a
report completes and read when someone downloads it. Definitions and job
rows stay in the realm maps (`sts_minted`, sealed), not in this table.
[Reports](reporting.md) says how long a result stays available.

| Column | Type | Encrypted? | Meaning |
|---|---|---|---|
| `realm` | text | clear | the trust realm |
| `job_id` | text | clear | the report job |
| `bytes` | bytea | **sealed (AES-GCM)** | the finished document (CSV, PDF, …), sealed under the realm's `report-artifact` data key and stored as the envelope's bytes. Since #1033; a row from before stays in the clear until its retention ends. Without a key-encryption key no report is stored |
| `sha256` | text | digest | the SHA-256 of the report as downloaded, for integrity; not reversible |
| `media_type` | text | clear | the format's media type |
| `created_at` | bigint | clear | milliseconds |

Primary key `(realm, job_id)`; no other index.

## `sts_schema`

This table holds one row per version applied (`version` int PK, `applied_at`
timestamptz), both clear. The driver writes its `SCHEMA_VERSION` on every
open, and `schema.sql` inserts the same number.

---

## Indexes

Every table has a primary key, given with the table above; PostgreSQL builds
a unique B-tree for each. This section lists the 44 indexes **beyond** the
primary keys, by table. "Partial" means the index holds only the rows that
match its condition, which keeps it small and cheap to write.

**No index is over a sealed value**: PostgreSQL cannot read one, so it could
not index it. The GIN indexes over `name_keys`, `mail_keys`, `uuid_keys`,
`value_keys` and `class_keys` are over **keyed digests**, which find an exact
match without saying what it is; the trigram index is over `rdn_value`, the
login name, which is in the clear.

### `sts_ldap_entries` (14)

| Index | Over | Kind | What it answers |
|---|---|---|---|
| `sts_ldap_entries_realm` | `realm` | B-tree | every entry of one realm (an export, a realm's removal) |
| `sts_ldap_entries_parent` | `realm`, `parent_key`, `dn_key` | B-tree | the children of a container, in key order, a page at a time |
| `sts_ldap_entries_rdn` | `realm`, `parent_key`, `rdn_value` | B-tree | an entry by its name under a container: a login name under `ou=users` |
| `sts_ldap_entries_uid_trgm` | `rdn_value` | GIN, trigram (`pg_trgm`); partial: only entries directly under an `ou=users` container | login names that **contain** some text (`/portal/delegate`'s search) |
| `sts_ldap_entries_created` | `realm`, `parent_key`, `created_at` | B-tree; partial: only entries directly under `ou=users` | the people created in a date range (a report filter) |
| `sts_ldap_entries_modified` | `realm`, `parent_key`, `modified_at` | B-tree; partial: only entries directly under `ou=users` | the people changed in a date range (a report filter) |
| `sts_ldap_entries_names` | `name_keys` (keyed digests) | GIN (`jsonb_path_ops`), `fastupdate = off` | an entry by login name, from anywhere in the tree |
| `sts_ldap_entries_mails` | `mail_keys` (keyed digests) | GIN (`jsonb_path_ops`), `fastupdate = off` | an entry by email address |
| `sts_ldap_entries_uuids` | `uuid_keys` (keyed digests) | GIN (`jsonb_path_ops`), `fastupdate = off` | an entry by `entryUUID` or one of its aliases (how a `sub` becomes a person) |
| `sts_ldap_entries_values` | `value_keys` (keyed digests) | GIN (`jsonb_path_ops`), `fastupdate = off` | an entry by an exact attribute value: a DID, a SPIFFE ID, a certificate subject, a federation link, a device's key or credential, an owner |
| `sts_ldap_entries_asked_names` | the asked attribute names in `attr_names` | GIN over an expression; partial: only entries holding at least one asked name; `fastupdate = off` | **who holds a credential or setting of a kind**: a passkey, a TOTP secret, recovery codes, a Kerberos key, a consent, a delegation, a lock (`pwdAccountLockedTime`), … |
| `sts_ldap_entries_group_classes` | `class_keys` (keyed digests) | GIN; partial: only entries with a group class; `fastupdate = off` | the groups placed under `ou=users` or `ou=devices` |
| `sts_ldap_entries_dek_keys` | `dek_keys` | GIN | the entries holding a value under a given data key (re-encryption) |
| `sts_ldap_entries_dek_unknown` | `realm`, `dn_key` | B-tree; partial: only entries whose `dek_keys` is NULL | the entries written before version 17 that still need their data keys indexed |

### The directory's counters (2)

| Index | Table | Over | Kind | What it answers |
|---|---|---|---|---|
| `sts_ldap_count_deltas_txid` | `sts_ldap_count_deltas` | `txid` | B-tree | this transaction's count changes, folded at commit |
| `sts_ldap_dek_deltas_txid` | `sts_ldap_dek_deltas` | `txid` | B-tree | this transaction's data-key count changes, folded at commit |

### `sts_minted` (3) and `sts_minted_index` (2)

| Index | Table | Over | Kind | What it answers |
|---|---|---|---|---|
| `sts_minted_handle` | `sts_minted` | `handle`, `realm` | B-tree | every row of one store in one realm (the restore at start) |
| `sts_minted_written_brin` | `sts_minted` | `written_at` | BRIN (block ranges, `autosummarize = on`) | the rows older than the retention, for the clean-up jobs, without slowing every write |
| `sts_minted_expires` | `sts_minted` | `expires_at` | B-tree; partial: only rows with an expiry | the rows whose own expiry has passed, for the purge |
| `sts_minted_index_key` | `sts_minted_index` | `handle`, `realm`, `key` | B-tree | a row's own index rows, to replace or delete them with the row |
| `sts_minted_index_sort` | `sts_minted_index` | `handle`, `realm`, `sort_at` descending, `key` descending | B-tree; partial: only sort rows (`sort_at` set) | the newest rows of a store, a page at a time (the console's token lists) |

### `sts_sessions` (7)

All seven are B-trees and partial: each holds only the sessions for which
its question can be asked, which is a small share of all sessions.

| Index | Over | Condition | What it answers |
|---|---|---|---|
| `sts_sessions_subject` | `realm`, `subject_key`, `last_seen_at` | chosen sessions with a subject | one person's sessions, oldest first (sign out everywhere, the per-person cap) |
| `sts_sessions_username` | `realm`, `username_key` | a username is set | the sessions of a username (the console's search, a password change) |
| `sts_sessions_expires` | `realm`, `expires_at` | an expiry is set | the sessions that have expired, for the sweep |
| `sts_sessions_parent` | `realm`, `parent_key` | the session derives from another | the relying-party sessions that end with a sign-on session |
| `sts_sessions_credential` | `realm`, `credential_key` | an API client's session | the existing session of an API client presenting itself again |
| `sts_sessions_partner` | `realm`, `partner_relationship` | the session began at a federated partner | the sessions to end when a partner signs a person out |
| `sts_sessions_surface` | `realm`, `rp_surface` | a hosted surface's session | one surface's sessions, for a CAEP signal it receives |

### The change log, assertions and the cluster (6)

| Index | Table | Over | Kind | What it answers |
|---|---|---|---|---|
| `sts_changes_at` | `sts_changes` | `at` | B-tree | the old rows, for the trim |
| `sts_used_assertions_expiry` | `sts_used_assertions` | `realm`, `expires_at` | B-tree | the live count and the purge of expired entries |
| `sts_cluster_nodes_expiry` | `sts_cluster_nodes` | `expires_at` | B-tree | the members whose heartbeat has lapsed |
| `sts_cluster_claims_expiry` | `sts_cluster_claims` | `expires_at` | B-tree | the claims past their life, for the purge |
| `sts_cluster_windows_expiry` | `sts_cluster_windows` | `window_ends_at` | B-tree | the rate-limit windows that have ended, for the purge |
| `sts_cluster_budgets_expiry` | `sts_cluster_budgets` | `expires_at` | B-tree | the budgets of grants that have ended, for the purge |

### Risk scoring (10)

| Index | Table | Over | Kind | What it answers |
|---|---|---|---|---|
| `sts_risk_fido_by_key` | `sts_risk_fido_authenticators` | `key_kind`, `authenticator_key` | B-tree | an authenticator's metadata by AAGUID or key id, whatever the dataset version |
| `sts_risk_assessments_subject` | `sts_risk_assessments` | `realm`, `subject`, `at` | B-tree | one person's sign-in history, by time (`/portal/sign-ins`) |
| `sts_risk_assessments_session` | `sts_risk_assessments` | `realm`, `session_id` | B-tree | the assessments of one session |
| `sts_risk_assessments_at` | `sts_risk_assessments` | `at` | B-tree | the assessments in a time range, and the purge |
| `sts_risk_feature_counts_age` | `sts_risk_feature_counts` | `realm`, `last_at` | B-tree | the features not seen for a long time, for the purge |
| `sts_risk_failures_subject` | `sts_risk_failures` | `realm`, `subject`, `at` | B-tree | the refused passwords for one person (stuffing against an account) |
| `sts_risk_failures_name` | `sts_risk_failures` | `realm`, `name_hmac`, `at` | B-tree | the refused passwords for a name that matched nobody |
| `sts_risk_failures_prefix` | `sts_risk_failures` | `realm`, `address_prefix`, `at` | B-tree | the refused passwords from one network (a spray) |
| `sts_risk_failures_at` | `sts_risk_failures` | `at` | B-tree | the refusals in a time range, and the purge |
| `sts_risk_terms_acceptances_provider` | `sts_risk_terms_acceptances` | `provider`, `accepted_at` | B-tree | the latest acceptance of a provider's terms |

The tables not named in this section (`sts_realms`, `sts_appconfig`,
`sts_keys`, `sts_cell_routing`, `sts_ldap_counts`, `sts_ldap_dek_counts`,
`sts_change_readers`, `sts_cluster_leases`, `sts_cluster_secrets`,
`sts_cluster_counters`, `sts_node_snapshots`, the remaining risk dataset
tables, `sts_report_artifacts` and `sts_schema`) are read only by their
primary key.

## Related

* [Persistence](persistence.md): the modes, the compose stack, what survives.
* [Encryption at rest](encryption-at-rest.md): the key-encryption key and the
  data keys behind every sealed value.
* [LDAP schema](ldap-schema.md): what is inside `sts_ldap_entries.attrs`.
* [A cluster in AWS](aws-cluster.md): the same schema on RDS.
* `postgres/CLAUDE.md` and `persistence/CLAUDE.md`, for maintainers.
