// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/persistence/persistence.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of every table and index:
// `models/tools/generate.mjs` compiles it during the image build into the
// statements `persistence/persistence_postgres.js` runs and into
// `postgres/schema.sql`, whose comments and everything else are in
// `schema.template.sql` beside this file. The comments here are the ones that
// sat on these statements in the driver.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Persistence;

// The one index worth having beyond the primary key: every enumerator in
// this service walks one realm.
// -------------------------------------------------------------------------
// THE DIRECTORY'S LOOKUP INDEXES (#349, schema version 13): what a request
// worker holding the people and devices as a bounded window asks instead
// of an index in memory — `persistence/directory_queries.js` builds every
// statement that reads them. Each is over a GENERATED column (above), so no
// writer maintains it and a row that existed before the column gets it when
// the column is added. `afterColumns`: on an older table the columns come
// from SCHEMA_COLUMNS, so these can only be built after that step.
//   * the children of a container, in key order (listings, paging, the
//     `ou=users` a login name is looked for under) and the RDN value there;
//   * the lower-cased `uid`, `mail` and entryUUID values, GIN over a JSON
//     array (`@>`), and every attribute value as written, GIN over `attrs`
//     (a DID, a SPIFFE ID, a federation link).
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// A PERSON FOUND BY PART OF THEIR `uid` (schema version 23, 2026-10-20,
// `/portal/delegate`): a `pg_trgm` GIN over `rdn_value`, PARTIAL on the
// children of a realm's `ou=users` (`directory_queries.js`'s
// USERS_PARENT, which `uidContains` repeats so the planner can use it).
// `rdn_value` is generated from the key, lower-cased and in the clear —
// the one name of a person the database could already read — so this
// indexes nothing the store did not already show; every attribute stays
// sealed. Without it a contains match is a walk of the container, 50M
// rows on 8081 for a string nobody has. `extension`: the trigram operator
// class is `pg_trgm`'s, which is created first (`CREATE EXTENSION IF NOT
// EXISTS`, trusted since PostgreSQL 13, so a database owner may) — and,
// like every object here, only when the index is missing.
//
// **ON A LARGE EXISTING STORE THE OWNER BUILDS IT CONCURRENTLY FIRST.**
// `postgres/schema.sql` runs in one transaction, which CONCURRENTLY
// cannot, so it builds the index with a plain CREATE — a SHARE lock on
// the table for the build, which is every write held for minutes at 50M.
// `postgres/CLAUDE.md` gives the statement to run beforehand, after
// which the script's and this driver's `IF NOT EXISTS` find it built.
// -------------------------------------------------------------------------
// THE TWO DATES AS A RANGE (#1028, schema version 28): B-trees over the
// generalized-time text of `created_at` and `modified_at`, led by realm and
// parent, over the children of each realm's `ou=users` only — what a
// report's date range reads (`directory_queries.js`'s `createdBetween`,
// `modifiedBetween`). Fixed-width UTC text sorts as time does.
// The attribute values `byAttribute()` asks for, as keyed digests (#391
// phase 6) — where the GIN over `attrs` was, which a sealed blob makes
// nothing to index.
// -------------------------------------------------------------------------
// THE ATTRIBUTE NAMES A HOLDER QUESTION ASKS, AND THE GROUP CLASSES — AND
// NOTHING ELSE (#618 phase 2, schema version 18). Both GIN with the
// DEFAULT operator class (`?` and `?|`; `jsonb_path_ops` answers only
// containment), and both PARTIAL, so an entry that is neither a holder of
// an asked attribute nor a group — nearly every person — writes no GIN
// entry to either. Until version 18 they indexed every attribute name
// (about fifteen a person, twelve of them in 99.9% of rows) and every
// object class (four a person, each in more than 99%): about nineteen GIN
// entries a person insert that narrowed nothing.
//   * the names: an IMMUTABLE expression of `attr_names` keeping only
//     `directory_queries.js`'s ASKED_ATTRIBUTES, which every query that
//     reads it repeats character for character (`ASKED_NAMES`), because
//     the planner uses an expression index only for its own expression;
//   * the classes: `class_keys` itself, which the service writes with the
//     group classes only since this version (`directory_codec.js`'s
//     CLASS_INDEXED) — the column holds keyed digests the database cannot
//     read, so it cannot be narrowed by an expression here.
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// WHICH ENTRIES HOLD A VALUE UNDER A DATA KEY (#623, schema version 17).
// Until this, the re-encryption job and the data-key count WALKED every
// row of the directory and opened each on the front process to read the
// keys inside it — every hour while any key was superseded, about 90 s of
// the thread at 1.5M entries, hours at 200M. Now:
//   * the entries a re-seal must touch are `dek_keys ?| <superseded ids>`,
//     GIN with the default operator class (for `?|`), and only those are
//     opened;
//   * the entries written before the column, whose keys are not known,
//     are the partial index's (`dek_keys IS NULL`), found without a scan
//     and indexed a bounded batch at a time (`indexSealed()`), once;
//   * what is sealed under each key is KEPT, in `sts_ldap_dek_counts`, by
//     triggers — #618's design for `sts_ldap_counts`, for #618's reason
//     (SCHEMA_ROUTINES below) — so a count is a read of a few rows.
// -------------------------------------------------------------------------
@table(#{name: "sts_ldap_entries", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 16, text: "PRIMARY KEY (realm, dn_key)"}], driver: #{order: 0}, indexes: #[#{name: "sts_ldap_entries_realm", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm)", driver: #{order: 1}}, #{name: "sts_ldap_entries_parent", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_parent ON sts_ldap_entries (realm, parent_key, dn_key)", driver: #{order: 2, afterColumns: true}}, #{name: "sts_ldap_entries_rdn", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_rdn ON sts_ldap_entries (realm, parent_key, rdn_value)", driver: #{order: 3, afterColumns: true}}, #{name: "sts_ldap_entries_uid_trgm", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_uid_trgm ON sts_ldap_entries USING gin (rdn_value gin_trgm_ops) WITH (fastupdate = off) WHERE parent_key LIKE 'ou=users,%'", driver: #{order: 4, afterColumns: true, extension: "pg_trgm"}}, #{name: "sts_ldap_entries_created", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_created ON sts_ldap_entries (realm, parent_key, created_at) WHERE parent_key LIKE 'ou=users,%'", driver: #{order: 5, afterColumns: true}}, #{name: "sts_ldap_entries_modified", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_modified ON sts_ldap_entries (realm, parent_key, modified_at) WHERE parent_key LIKE 'ou=users,%'", driver: #{order: 6, afterColumns: true}}, #{name: "sts_ldap_entries_names", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_names ON sts_ldap_entries USING gin (name_keys jsonb_path_ops) WITH (fastupdate = off)", driver: #{order: 7, afterColumns: true}}, #{name: "sts_ldap_entries_mails", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_mails ON sts_ldap_entries USING gin (mail_keys jsonb_path_ops) WITH (fastupdate = off)", driver: #{order: 8, afterColumns: true}}, #{name: "sts_ldap_entries_uuids", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_uuids ON sts_ldap_entries USING gin (uuid_keys jsonb_path_ops) WITH (fastupdate = off)", driver: #{order: 9, afterColumns: true}}, #{name: "sts_ldap_entries_values", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_values ON sts_ldap_entries USING gin (value_keys jsonb_path_ops) WITH (fastupdate = off)", driver: #{order: 10, afterColumns: true}}, #{name: "sts_ldap_entries_asked_names", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_asked_names ON sts_ldap_entries USING gin ((jsonb_path_query_array(attr_names, '$[*] ? (@ == \"federationlink\" || @ == \"hobapublickey\" || @ == \"memberof\" || @ == \"oauthconsent\" || @ == \"pwdaccountlockedtime\" || @ == \"stsacmeeabkey\" || @ == \"stsandroidattestedcredential\" || @ == \"stsassertionissuer\" || @ == \"stsassertionkeypair\" || @ == \"stsbackupcodes\" || @ == \"stscertificatehostname\" || @ == \"stsclaimsourcetokens\" || @ == \"stsdefaultdelegationsemantics\" || @ == \"stsdelegationsemantics\" || @ == \"stsdeviceandroidkey\" || @ == \"stsdevicekey\" || @ == \"stsenrolledcertificate\" || @ == \"stsenrolledprivatekey\" || @ == \"stskrb5keyinfo\" || @ == \"stskrb5keys\" || @ == \"stsmailfactor\" || @ == \"stsmayact\" || @ == \"stsnotdelegated\" || @ == \"stssamlassertionissuer\" || @ == \"stssamlassertionkeypair\" || @ == \"stsscepchallenge\" || @ == \"stsselfissuedsubject\" || @ == \"stsserviceaccount\" || @ == \"ststotpcredential\" || @ == \"stswebauthncredential\" || @ == \"stswebauthnuserhandle\")'))) WITH (fastupdate = off) WHERE attr_names ?| ARRAY['federationlink', 'hobapublickey', 'memberof', 'oauthconsent', 'pwdaccountlockedtime', 'stsacmeeabkey', 'stsandroidattestedcredential', 'stsassertionissuer', 'stsassertionkeypair', 'stsbackupcodes', 'stscertificatehostname', 'stsclaimsourcetokens', 'stsdefaultdelegationsemantics', 'stsdelegationsemantics', 'stsdeviceandroidkey', 'stsdevicekey', 'stsenrolledcertificate', 'stsenrolledprivatekey', 'stskrb5keyinfo', 'stskrb5keys', 'stsmailfactor', 'stsmayact', 'stsnotdelegated', 'stssamlassertionissuer', 'stssamlassertionkeypair', 'stsscepchallenge', 'stsselfissuedsubject', 'stsserviceaccount', 'ststotpcredential', 'stswebauthncredential', 'stswebauthnuserhandle']", driver: #{order: 11, afterColumns: true}}, #{name: "sts_ldap_entries_group_classes", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_group_classes ON sts_ldap_entries USING gin (class_keys) WITH (fastupdate = off) WHERE class_keys <> '[]'::jsonb", driver: #{order: 12, afterColumns: true}}, #{name: "sts_ldap_entries_dek_keys", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_dek_keys ON sts_ldap_entries USING gin (dek_keys)", driver: #{order: 13, afterColumns: true}}, #{name: "sts_ldap_entries_dek_unknown", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_dek_unknown ON sts_ldap_entries (realm, dn_key) WHERE dek_keys IS NULL", driver: #{order: 14, afterColumns: true}}]})
model StsLdapEntries {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dn_key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  dn: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL", required: true})
  attrs: unknown;
  @column(#{sql: "text"})
  origin?: string;
  @column(#{sql: "text"})
  created_at?: string;
  @column(#{sql: "text"})
  modified_at?: string;
  // The directory's six generated lookup columns (#349, schema version 13).
  // Adding a STORED generated column rewrites the table once and fills every
  // existing row, which is the whole of the migration.
  @column(#{sql: "text", clauses: "GENERATED ALWAYS AS (CASE WHEN strpos(dn_key, ',') > 0 THEN substr(dn_key, strpos(dn_key, ',') + 1) ELSE '' END) STORED", generated: true, added: true})
  parent_key?: string;
  @column(#{sql: "text", clauses: "GENERATED ALWAYS AS (substr(split_part(dn_key, ',', 1), strpos(split_part(dn_key, ',', 1), '=') + 1)) STORED", generated: true, added: true})
  rdn_value?: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["uid"], added: true})
  name_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["mail"], added: true})
  mail_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["entryUUID", "stsEntryUuidAlias"], added: true})
  uuid_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["objectClass"], added: true})
  class_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, added: true})
  value_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, added: true})
  attr_names: unknown;
  // The data keys an entry holds values under (#623, schema version 17).
  // Nullable and with no default, so adding it rewrites nothing: every
  // existing row reads NULL — keys not known — until `indexSealed()` reaches
  // it or the entry is next written.
  @column(#{sql: "jsonb", added: true})
  dek_keys?: unknown;
}

// -------------------------------------------------------------------------
// THE DIRECTORY'S COUNTS, KEPT RATHER THAN COUNTED (#618, schema version
// 16). A request worker holding the directory as a window asked the store
// `count(*)` for `ldap.maxEntries`, a container's headline and the
// credential tiles — linear in the realm's rows (13–15 ms at 29,303 on
// 8081, so seconds at 200M). Now each is one primary-key read of
// `sts_ldap_counts`: per realm, per BASE (every ancestor of a row's DN, and
// '' for the whole realm, so "strictly under a base" is one row whatever
// the base), the entries under it (`attribute` '') and those holding each
// COUNTED attribute (`directory_queries.COUNTED_ATTRIBUTES`).
//
// THE DATABASE KEEPS THEM, not this driver: statement-level triggers on
// `sts_ldap_entries` (SCHEMA_ROUTINES below) see every writer — the
// flush, the merge, a removed realm, a cell conversion, a hand-run
// statement — in the transaction that wrote. A trigger does NOT update the
// counter rows itself: every write of a realm touches the same few rows
// (the realm's '', the base DN, `ou=users`), and a lock on them held from a
// flush's first statement to its commit would serialise every flush of
// the realm and close a deadlock with the entry locks the flush takes in
// key order. So each statement appends its net per parent to
// `sts_ldap_count_deltas` (insert only, no lock anybody waits on), and ONE
// deferred constraint trigger folds the transaction's deltas into
// `sts_ldap_counts` at COMMIT — one statement, in key order, after every
// entry lock is held: the counter rows are locked only for the commit's
// tail. A committed transaction leaves no delta behind.
//
// AND THE TAIL IS SHARDED (#630, schema version 19). Every add still
// updated the same four counter rows (the realm's '', `dc=…`, `ou=users`,
// and `userpassword` under them) and one data-key row at its COMMIT, so
// once the notify queue's lock was gone those rows were the ceiling: two
// commits of one realm queued on each other's row lock
// (`Lock:transactionid`, 4.4 backends at 104 adds/s in a replay; 326 with
// sixteen shards). So `shard` is part of the key and the fold adds to
// shard `pg_backend_pid() % COUNT_SHARDS` — two connections meet on a row
// only when their process ids fall in one shard — and every reader SUMS a
// key's shards (`directory_queries.count()`, `countHolding()`,
// `directoryDekCounts()`). One shard's `n` may be negative (an entry added
// through one connection and deleted through another); only the sum means
// anything, and it is what is read.
// -------------------------------------------------------------------------
@table(#{name: "sts_ldap_counts", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 5, text: "PRIMARY KEY (realm, base_key, attribute, shard)"}], driver: #{order: 18}})
model StsLdapCounts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  base_key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  attribute: string;
  // The counters' shard (#630, schema version 19). An existing row gets 0:
  // what it held is shard 0's, and the sums are unchanged. The key that
  // takes it in is SCHEMA_UPGRADES' (`*_shard_key`).
  @column(#{sql: "smallint", clauses: "NOT NULL DEFAULT 0", required: true, primaryKey: true, added: true})
  shard: int16;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  n: int64;
}

@table(#{name: "sts_ldap_count_deltas", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 19}, indexes: #[#{name: "sts_ldap_count_deltas_txid", text: "CREATE INDEX IF NOT EXISTS sts_ldap_count_deltas_txid ON sts_ldap_count_deltas (txid)", driver: #{order: 20}}]})
model StsLdapCountDeltas {
  @column(#{sql: "xid8", clauses: "NOT NULL DEFAULT pg_current_xact_id()", required: true})
  txid: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  parent_key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  n: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  holding: int64;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  fold: boolean;
}

// SHARDED SINCE #630 (schema version 19): `shard` in the key, as
// `sts_ldap_counts` below — one row per data key per shard, and a reader
// sums them.
@table(#{name: "sts_ldap_dek_counts", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 3, text: "PRIMARY KEY (dek_id, shard)"}], driver: #{order: 15}})
model StsLdapDekCounts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dek_id: string;
  @column(#{sql: "smallint", clauses: "NOT NULL DEFAULT 0", required: true, primaryKey: true, added: true})
  shard: int16;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  n: int64;
}

@table(#{name: "sts_ldap_dek_deltas", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 16}, indexes: #[#{name: "sts_ldap_dek_deltas_txid", text: "CREATE INDEX IF NOT EXISTS sts_ldap_dek_deltas_txid ON sts_ldap_dek_deltas (txid)", driver: #{order: 17}}]})
model StsLdapDekDeltas {
  @column(#{sql: "xid8", clauses: "NOT NULL DEFAULT pg_current_xact_id()", required: true})
  txid: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  dek_id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  n: int64;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  fold: boolean;
}

@table(#{name: "sts_realms", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 21}})
model StsRealms {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  id: string;
  @column(#{sql: "text"})
  name?: string;
  @column(#{sql: "text"})
  description?: string;
  @column(#{sql: "bigint"})
  created_at?: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  overrides: unknown;
  @column(#{sql: "text", added: true})
  domain?: string;
  // When the realm's removal began (#262, schema version 10), or NULL.
  @column(#{sql: "bigint", added: true})
  retiring_at?: int64;
}

@table(#{name: "sts_appconfig", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 22}})
model StsAppconfig {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL", required: true})
  value: unknown;
}

// THE SIGNING KEYS, ONE ROW PER TRUST REALM, AND THE COLUMN HOLDS
// CIPHERTEXT (2026-09-06). `keystore.js` encrypts with AES-256-GCM before
// anything reaches this driver, so nothing in this database is ever a
// private key — which is what makes it acceptable for them to live beside
// the directory in the same store. The key that opens them is read from
// outside the service entirely; see common/secrets.js.
//
// `text` and not `bytea`, because the stored form is the self-describing
// ASCII `$aesgcm$2$dek$iv$tag$body` that crypto.js writes — the same
// decision `userPassword` follows, and it means a row can be read and
// reasoned about with psql without a decode step.
@table(#{name: "sts_keys", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 23}})
model StsKeys {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  material: string;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  written_at: utcDateTime;
}

// -------------------------------------------------------------------------
// WHAT THIS PROCESS MINTED (2026-09-06). ONE TABLE FOR ALL OF IT, and the
// shape is the whole design: a HANDLE names the store, a REALM names its
// partition, a KEY names the row inside it, and the body is opaque.
//
// ONE TABLE RATHER THAN A TABLE PER FAMILY, because the handle list lives in
// the store declarations (`realms.map({ persist: … })`) and a table per
// family would be a SECOND place it is written down — which is the shape of
// drift the whole `sts_metadata.js` design exists to prevent. Adding a
// persisted store must cost one word at its declaration and nothing here.
//
// `realm` IS THE EMPTY STRING FOR THE SHARED STORES — the rate limiter's
// buckets and the directory's cluster connection lists today; the Kerberos
// principal database and replay cache were shared too until they became per
// realm (#33, 2026-09-15) — which have no realm because what they belong to
// has no path to put one in. It is
// a column value rather than a nullable, so the primary key needs no COALESCE
// and a query for one realm's rows cannot accidentally match them.
//
// `body` IS CIPHERTEXT, always, in the same self-describing
// `$aesgcm$2$dek$iv$tag$body` form `sts_keys` uses and under the SAME
// key-encryption key. A session id is a cookie value and an authorization
// code is redeemable, so a dump of this table must not be a set of usable
// credentials. What it costs is that nothing here is queryable by SQL, which
// is the trade `persistence_minted.js` argues.
//
// `written_at` IS WHAT RETENTION READS. A row older than
// `persistence.mintedRetention` is neither restored nor kept, and its index
// is what makes the purge on start a range scan rather than a table scan.
// -------------------------------------------------------------------------
// `written_at` FOR THE SWEEPS, AS A BRIN (#630, schema version 19), where
// it was a btree (`sts_minted_written`). Nothing on a request reads it —
// only `purgeTombstones()`, `purgeMinted()` and `purgeExpiredMinted()`'s
// 'orphan' and 'stale' batches — and every upsert sets `written_at =
// now()`, so a btree on it made EVERY update of this, the busiest table,
// a non-HOT update: a new index entry in all four indexes and a new heap
// page. 2.2 updates an add, 0% HOT on 8081. A BRIN is a SUMMARIZING index,
// which PostgreSQL 16 and later leave out of the HOT decision, so with
// the table's fillfactor at 80 (SCHEMA_UPGRADES) an update of a row stays
// on its page: 99% HOT in the replay, and about nine fewer WAL records an
// add. What the sweeps give up: a range's summary only WIDENS as its rows
// are rewritten, so on a churned table `written_at < x` reads most ranges
// and the sweep tends towards a scan of the table — off the request path,
// in batches, on the scheduler. `autosummarize` so a filled range is
// summarised by autovacuum without waiting for a VACUUM.
// `expires_at` (#333, schema version 12) IS THE RECORD'S OWN EXPIRY, in
// epoch milliseconds, as its store's `expiresAt` hook answered it — NULL
// for a record that does not expire, and for a tombstone. A restore reads
// no row whose instant has passed, and the `persistence.minted-expiry-purge`
// job deletes them in batches through this index. PARTIAL, because the
// rows with no expiry are the ones the purge never looks for by it, and an
// index is paid for by every INSERT into the busiest table here.
// `afterColumns`: an older table gets the column from SCHEMA_COLUMNS, so
// the index can only be built after that.
@table(#{name: "sts_minted", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 7, text: "PRIMARY KEY (handle, realm, key)"}], driver: #{order: 24}, indexes: #[#{name: "sts_minted_handle", text: "CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm)", driver: #{order: 25}}, #{name: "sts_minted_written_brin", text: "CREATE INDEX IF NOT EXISTS sts_minted_written_brin ON sts_minted USING brin (written_at) WITH (autosummarize = on)", driver: #{order: 26}}, #{name: "sts_minted_expires", text: "CREATE INDEX IF NOT EXISTS sts_minted_expires ON sts_minted (expires_at) WHERE expires_at IS NOT NULL", driver: #{order: 27, afterColumns: true}}]})
model StsMinted {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  handle: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  body: string;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  written_at: utcDateTime;
  // A minted row's own expiry (#333, schema version 12). An existing row gets
  // NULL — no expiry — and so falls under the write-age rule once, which is
  // the whole of the migration.
  @column(#{sql: "bigint", added: true})
  expires_at?: int64;
  // A minted row's name, sealed, beside its digest in `key` (#222, schema
  // version 14). An existing row gets '' — its key is its name, as before.
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, added: true})
  key_sealed: string;
}

// -------------------------------------------------------------------------
// THE SESSION INDEX (#350, schema version 21). Columns of a live
// `authn.sessions` row, written in the same transaction as the sealed
// body. Not columns of `sts_minted`: `expires_at` there stays NULL for a
// session, so the generic expiry purge cannot end one. `key` is the same
// digest `sts_minted.key` already uses. A null digest writes no row.
// -------------------------------------------------------------------------
// A hosted surface's relying-party sessions (#754, schema version 22):
// `session.surface`, which `Authn.endRelyingPartySessions()` asks for
// every signal a surface receives. Partial for the others' reason: a
// sign-on session has no surface, and those are nearly every row.
@table(#{name: "sts_sessions", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 15, text: "PRIMARY KEY (realm, key)"}], driver: #{order: 28}, indexes: #[#{name: "sts_sessions_subject", text: "CREATE INDEX IF NOT EXISTS sts_sessions_subject ON sts_sessions (realm, subject_key, last_seen_at) WHERE chosen AND subject_key <> ''", driver: #{order: 29}}, #{name: "sts_sessions_username", text: "CREATE INDEX IF NOT EXISTS sts_sessions_username ON sts_sessions (realm, username_key) WHERE username_key <> ''", driver: #{order: 30}}, #{name: "sts_sessions_expires", text: "CREATE INDEX IF NOT EXISTS sts_sessions_expires ON sts_sessions (realm, expires_at) WHERE expires_at IS NOT NULL", driver: #{order: 31}}, #{name: "sts_sessions_parent", text: "CREATE INDEX IF NOT EXISTS sts_sessions_parent ON sts_sessions (realm, parent_key) WHERE parent_key <> ''", driver: #{order: 32}}, #{name: "sts_sessions_credential", text: "CREATE INDEX IF NOT EXISTS sts_sessions_credential ON sts_sessions (realm, credential_key) WHERE credential_key <> ''", driver: #{order: 33}}, #{name: "sts_sessions_partner", text: "CREATE INDEX IF NOT EXISTS sts_sessions_partner ON sts_sessions (realm, partner_relationship) WHERE partner_relationship <> ''", driver: #{order: 34}}, #{name: "sts_sessions_surface", text: "CREATE INDEX IF NOT EXISTS sts_sessions_surface ON sts_sessions (realm, rp_surface) WHERE rp_surface <> ''", driver: #{order: 35}}]})
model StsSessions {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint"})
  expires_at?: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  last_seen_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject_key: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  username_key: string;
  @column(#{sql: "boolean", clauses: "NOT NULL", required: true})
  chosen: boolean;
  @column(#{sql: "boolean", clauses: "NOT NULL", required: true})
  authenticated: boolean;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  rp_surface: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  parent_key: string;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  backs_console: boolean;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_key: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  partner_relationship: string;
}

// -------------------------------------------------------------------------
// AN ON-DEMAND STORE'S INDEX (#820, schema version 24). A store declared
// `onDemand` with `indexBy` (`common/realms.js`) is not held whole, so
// what it was walked for — every refresh token of one family, every token
// of one person — is filed here: the keyed digest of the index value
// beside the row's own key, written in the same transaction as the body.
// The bodies are sealed, so nothing else could answer it.
// -------------------------------------------------------------------------
// A row's own index rows, for the flush's replace and a delete.
// THE NEWEST ROWS OF A STORE, BY ITS SORT VALUE (2026-10-22, #820,
// schema version 25). A store declaring `sortBy` writes one more index
// row per stored row (`index_key` `minted_queries.SORT_INDEX_KEY`,
// `sort_at` its value), and `minted.newest` walks this index newest first
// instead of sorting the store's whole partition by `written_at` — 13-14 s
// a page over 1.7M tokens on 8081. `written_at` itself may carry no btree
// (it changes on every write, and a btree on it makes every update of
// `sts_minted` non-HOT, #630); `sts_minted_index` is written by INSERT and
// DELETE only, so an index here costs no HOT update. PARTIAL, because
// every other index row's `sort_at` is NULL; the query repeats the
// predicate so a generic plan uses it. `afterColumns`: an older table
// gets the column from SCHEMA_COLUMNS first.
@table(#{name: "sts_minted_index", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 5, text: "PRIMARY KEY (handle, realm, index_key, key)"}], driver: #{order: 36}, indexes: #[#{name: "sts_minted_index_key", text: "CREATE INDEX IF NOT EXISTS sts_minted_index_key ON sts_minted_index (handle, realm, key)", driver: #{order: 37}}, #{name: "sts_minted_index_sort", text: "CREATE INDEX IF NOT EXISTS sts_minted_index_sort ON sts_minted_index (handle, realm, sort_at DESC, key DESC) WHERE sort_at IS NOT NULL", driver: #{order: 38, afterColumns: true}}]})
model StsMintedIndex {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  handle: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  index_key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  // A minted index row's sort value (#820, schema version 25). Nullable
  // with no default, so adding it rewrites nothing: every existing index
  // row reads NULL, which is what every row but a sort row holds anyway.
  @column(#{sql: "bigint", added: true})
  sort_at?: int64;
}

// -------------------------------------------------------------------------
// THE CHANGE LOG (2026-09-06), which is what makes several processes against
// one store agree rather than merely coexist.
//
// `seq` IS A bigserial AND EVERYTHING RESTS ON IT: it is assigned by the
// database, it only goes up, and a process that has applied up to N asks for
// N+1 onwards. That is the whole synchronisation primitive — no timestamps
// (two clocks), no version columns per row (a merge rule per table), no
// advisory locks (a process that dies holding one).
//
// `origin` is who wrote it, so a process can skip its own rows without
// applying its own work back over itself.
//
// `kind` and `realm` and `key` are a POINTER. The row that changed is read
// from its own table; nothing here carries data, which is why this table
// needs no encryption while `sts_minted` does.
//
// **IT IS WRITTEN INSIDE THE TRANSACTION THAT MADE THE CHANGE**, which is the
// one property that makes it trustworthy: there is no window in which the
// data is committed and the log entry is not, so "I have applied up to N"
// really does mean "I have seen everything committed before N".
// -------------------------------------------------------------------------
@table(#{name: "sts_changes", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 39}, indexes: #[#{name: "sts_changes_at", text: "CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at)", driver: #{order: 40}}]})
model StsChanges {
  @column(#{sql: "bigserial", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  seq: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  origin: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  key: string;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  at: utcDateTime;
}

// -------------------------------------------------------------------------
// THE USED-ASSERTION HISTORY (2026-09-13): every RFC 7523 JWT and RFC 7522
// SAML assertion this service accepted, until it would have expired.
// `common/used_assertions.js` argues the design; three things are this
// table's.
//
// **A TABLE OF ITS OWN AND NOT A HANDLE IN `sts_minted`**, because what it is
// for is an ATOMIC CLAIM: `(realm, key)` is the primary key, and recording a
// use is one `INSERT … ON CONFLICT`, so two processes against this store
// cannot both accept one assertion. `sts_minted` is written by a journal
// flush after the fact and converges through the change log, which is exactly
// the window this table exists to close — and it is sealed, so nothing in it
// could be compared by SQL anyway.
//
// **NOT SEALED, AND NOTHING IN IT IS A CREDENTIAL.** `key` is a SHA-256 of the
// format, issuer and identifier; the rest is an issuer's name, a `jti` or
// `ID`, a client and a subject — what an audit row already carries. The
// assertion itself is never stored, so a dump of this table replays nothing.
//
// **THE TIMES ARE MILLISECONDS IN `bigint`**, the unit every reader of the
// row works in, and `expires_at` is what every read filters on — the index is
// what makes the live count and the sweep a range scan.
// -------------------------------------------------------------------------
@table(#{name: "sts_used_assertions", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 14, text: "PRIMARY KEY (realm, key)"}], driver: #{order: 41}, indexes: #[#{name: "sts_used_assertions_expiry", text: "CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON sts_used_assertions (realm, expires_at)", driver: #{order: 42}}]})
model StsUsedAssertions {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  format: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  used_as: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  issuer: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  identifier: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  client_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  reservation: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  used_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  spent_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

// -------------------------------------------------------------------------
// THE CLUSTER (2026-09-14, #46): SEVERAL CONTAINERS AGAINST THIS ONE STORE.
// `cluster/CLAUDE.md` argues all four tables; what is the driver's is below.
//
// **EVERY TIME IN THEM IS THE DATABASE'S CLOCK**, as milliseconds in a
// `bigint`, and never a time a process sent. Two containers' clocks differ,
// and a lease that expires by the clock of whoever happens to be asking is a
// lease two nodes can both believe they hold. `DB_NOW` below is the one
// spelling of it.
//
// `sts_cluster_nodes` — ONE ROW PER PROCESS START THAT JOINED, keyed by a
// UUID made at that start. A row whose `expires_at` has passed is dead FOR
// GOOD: the heartbeat's UPDATE refuses to renew an expired row, so a node
// that paused past its lifetime cannot quietly come back and must exit.
//
// `sts_cluster_leases` — A NAMED ROLE ONLY ONE NODE MAY HOLD, with a FENCING
// TOKEN that goes up by one every time the lease changes hands. A write that
// needs the role carries the token it acquired, and the transaction checks it
// under a share lock on the lease row — so a node that lost the lease while
// paused cannot commit afterwards. A released lease is EXPIRED rather than
// deleted, so the token never goes back to 1.
//
// `sts_cluster_claims` — AN ATOMIC "ONCE": the primary key picks one winner
// among concurrent claims in every process against this store. `key` is a
// digest (`cluster/cluster_claims.js` hashes it) and never a bearer value.
//
// `sts_cluster_secrets` — A SECRET EVERY NODE MUST AGREE ON (the CSRF key,
// the ACME nonce key), SEALED under the key-encryption key before it arrives
// here and written first-writer-wins.
// -------------------------------------------------------------------------
@table(#{name: "sts_cluster_nodes", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 43}, indexes: #[#{name: "sts_cluster_nodes_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON sts_cluster_nodes (expires_at)", driver: #{order: 44}}]})
model StsClusterNodes {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  node_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  mode: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  version: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  fingerprint: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  heartbeat_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  left_at: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  info: unknown;
}

@table(#{name: "sts_cluster_leases", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 45}})
model StsClusterLeases {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  holder: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  token: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  acquired_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_claims", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 7, text: "PRIMARY KEY (scope, realm, key)"}], driver: #{order: 46}, indexes: #[#{name: "sts_cluster_claims_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON sts_cluster_claims (expires_at)", driver: #{order: 47}}]})
model StsClusterClaims {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  reservation: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  claimed_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_secrets", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 48}})
model StsClusterSecrets {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  material: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  created_by: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  created_at: int64;
}

// `sts_cluster_locks` — A NAMED LOCK AS A ROW (#677, schema version 30).
// The portable cluster statements lock a row here FOR UPDATE where the
// native ones take `pg_advisory_xact_lock`: a row lock ends with its
// transaction on every engine, and MariaDB's GET_LOCK() does not.
@table(#{name: "sts_cluster_locks", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 49}})
model StsClusterLocks {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
}

// `sts_cluster_counters` — A VALUE THAT ONLY GOES UP (2026-09-14, #46
// section 2): a WebAuthn signature counter, the last RFC 6238 time step a
// person spent. One `INSERT … ON CONFLICT DO UPDATE … WHERE value < new`
// under the primary key's row lock, so two nodes advancing one counter at
// once cannot both win and a lower value can never overwrite a higher one —
// which is exactly what the directory entry's last-writer-wins copy could
// not promise. `key` is a digest, as in the claims table.
// `cluster/cluster_counters.js` argues it.
@table(#{name: "sts_cluster_counters", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 6, text: "PRIMARY KEY (scope, realm, key)"}], driver: #{order: 50}})
model StsClusterCounters {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  value: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

// `sts_cluster_windows` — A COUNT INSIDE A FIXED WINDOW (2026-09-14, #46
// section 2): the rate limiter's buckets, counted by every node against one
// budget. One `INSERT … ON CONFLICT DO UPDATE SET count = CASE WHEN the
// window has passed THEN 1 ELSE count + 1 END` under the primary key's row
// lock, so two nodes counting one bucket at once both land and neither
// overwrites the other's count — which is what two copies of a Map row,
// last writer wins, could not promise. `key` is a digest.
// `cluster/cluster_counters.js` argues it.
@table(#{name: "sts_cluster_windows", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 6, text: "PRIMARY KEY (scope, realm, key)"}], driver: #{order: 51}, indexes: #[#{name: "sts_cluster_windows_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON sts_cluster_windows (window_ends_at)", driver: #{order: 52}}]})
model StsClusterWindows {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  window_ends_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

// `sts_cluster_budgets` — A BUDGET SPENT AGAINST A LIMIT (#432 phase 5,
// schema version 15): the running totals of a GNAP right's limits, kept per
// grant by `gnap/gnap_spend.ts`. One `INSERT … ON CONFLICT DO
// UPDATE … WHERE the new totals are within the limits` under the primary
// key's row lock, so two nodes spending one budget at once cannot both pass
// it. `amount` is millionths; `key` a digest; `expires_at` the end of the
// grant, past which the row is purged. `cluster/cluster_counters.js`
// argues it.
@table(#{name: "sts_cluster_budgets", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 9, text: "PRIMARY KEY (scope, realm, key)"}], driver: #{order: 53}, indexes: #[#{name: "sts_cluster_budgets_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_budgets_expiry ON sts_cluster_budgets (expires_at)", driver: #{order: 54}}]})
model StsClusterBudgets {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  period: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  amount: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

// `sts_node_snapshots` — WHAT EACH NODE LAST SAID ABOUT ITSELF (#332,
// schema version 11, 2026-09-28): the node's own Monitoring → Worker Pools
// and → Node Health views, written by its front process's per-process
// scheduler job `cluster.node-snapshot` every fifteen seconds and read by
// whichever node draws those pages, so every node is on the page with no
// request crossing between nodes (rcbj: no node's address is published).
// ONE ROW PER NODE NAME, OVERWRITTEN — keyed by `cluster.nodeName`, which
// survives a restart where the membership row's UUID does not — so the
// table is as long as the list of names the cluster has ever had and never
// grows with time. NOT `sts_cluster_nodes.info`: that rides the heartbeat a
// node's life depends on and is read with every retained row on each beat,
// and a snapshot is kilobytes. `taken_at` is the database's clock.
// `cluster/node_snapshots.ts` argues it.
@table(#{name: "sts_node_snapshots", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 55}})
model StsNodeSnapshots {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  node_id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  taken_at: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  body: unknown;
}

// `sts_change_readers` — WHERE EVERY PROCESS READING `sts_changes` HAS GOT
// TO (2026-09-14, #46 section 8). One row per process that coordinates —
// a front process, and each of its request workers, which are origins of
// their own — carrying its low-water mark and the database time it last
// said so. The change log is trimmed below the lowest mark of the readers
// still reporting, and never below a reader nobody has declared gone.
// `persistence/persistence_replication.js` argues the bound.
@table(#{name: "sts_change_readers", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 56}})
model StsChangeReaders {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  origin: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  node_id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  applied: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  reported_at: int64;
}

// ---------------------------------------------------------------------------
// RISK SCORING (#62, schema version 7, 2026-09-22). Thirteen tables, added
// whole so the schema moves once for the subsystem rather than once per
// phase. `risk/CLAUDE.md` argues the design; three things are this file's:
//
//   * EVERY EXTERNAL DATASET IS ROWS, by version (`sts_risk_dataset_*`, the
//     geo, ASN, IP-list and FIDO tables), so what a score used can be named
//     after the dataset has rotated. An IP range is `inet` start and end
//     rather than `cidr`, because DB-IP publishes ranges that are not
//     CIDR-aligned; a lookup is one probe of the primary key.
//   * THE HISTORY THE MODEL KEEPS IS ROWS TOO (`sts_risk_assessments`,
//     `_feature_counts`, `_failures`, `_session_context`, `_subjects`),
//     because it needs atomic upserts every node agrees on and SQL to
//     aggregate — which a sealed `sts_minted` body gives neither of.
//   * AN ADDRESS IS PERSONAL DATA AND NOT A CREDENTIAL, so it is kept SEALED
//     (`address_sealed`, under the key-encryption key `sts_minted` uses) and
//     as a /24 or /48 `cidr` prefix SQL can group on. Nothing here holds a
//     `User-Agent`, a credential id or a name a person typed in the clear.
// ---------------------------------------------------------------------------
@table(#{name: "sts_risk_datasets", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 7, text: "PRIMARY KEY (realm, dataset)"}], driver: #{order: 57}})
model StsRiskDatasets {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  active_version: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  previous_version: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_dataset_versions", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 25, text: "PRIMARY KEY (realm, dataset, version)"}], driver: #{order: 58}})
model StsRiskDatasetVersions {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  format: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  provider: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  licence: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  attribution: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  source: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  source_uri: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  sha256: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  byte_count: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  row_count: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  parameters: unknown;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  verification: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  published_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  next_update_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  fetched_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  loaded_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  activated_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  superseded_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  rows_deleted_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  refusal: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  error_code: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_risk_dataset_blobs", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 5, text: "PRIMARY KEY (realm, dataset, version, part)"}], driver: #{order: 59}})
model StsRiskDatasetBlobs {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "integer", clauses: "NOT NULL", required: true, primaryKey: true})
  part: int32;
  @column(#{sql: "bytea", clauses: "NOT NULL", required: true})
  content: bytes;
}

@table(#{name: "sts_risk_geo_locations", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 8, text: "PRIMARY KEY (dataset, version, location_id)"}], driver: #{order: 60}})
model StsRiskGeoLocations {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true, primaryKey: true})
  location_id: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  continent: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  time_zone: string;
}

@table(#{name: "sts_risk_geo_ranges", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 15, text: "PRIMARY KEY (dataset, version, range_start)"}], driver: #{order: 61}})
model StsRiskGeoRanges {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true})
  range_end: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  location_id: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  continent: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  registered_country: string;
  @column(#{sql: "double precision"})
  latitude?: float64;
  @column(#{sql: "double precision"})
  longitude?: float64;
  @column(#{sql: "integer", clauses: "NOT NULL DEFAULT 0", required: true})
  accuracy_km: int32;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  anonymous_proxy: boolean;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  satellite: boolean;
}

@table(#{name: "sts_risk_asn_ranges", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 7, text: "PRIMARY KEY (dataset, version, range_start)"}], driver: #{order: 62}})
model StsRiskAsnRanges {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true})
  range_end: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  as_org: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  as_domain: string;
}

@table(#{name: "sts_risk_ip_lists", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 7, text: "PRIMARY KEY (realm, dataset, version, range_start)"}], driver: #{order: 63}})
model StsRiskIpLists {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true})
  range_end: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  category: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  note: string;
}

@table(#{name: "sts_risk_fido_authenticators", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 12, text: "PRIMARY KEY (dataset, version, key_kind, authenticator_key)"}], driver: #{order: 64}, indexes: #[#{name: "sts_risk_fido_by_key", text: "CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON sts_risk_fido_authenticators (key_kind, authenticator_key)", driver: #{order: 65}}]})
model StsRiskFidoAuthenticators {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key_kind: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  authenticator_key: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  description: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  protocol_family: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  certification_level: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  latest_status: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  latest_status_at: int64;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  compromised: boolean;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true})
  status_reports: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  metadata_statement: unknown;
}

@table(#{name: "sts_risk_assessments", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 43, text: "PRIMARY KEY (realm, id)"}], driver: #{order: 66}, indexes: #[#{name: "sts_risk_assessments_subject", text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON sts_risk_assessments (realm, subject, at)", driver: #{order: 67}}, #{name: "sts_risk_assessments_session", text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON sts_risk_assessments (realm, session_id)", driver: #{order: 68}}, #{name: "sts_risk_assessments_at", text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON sts_risk_assessments (at)", driver: #{order: 69}}]})
model StsRiskAssessments {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  at: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  phase: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  door: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  session_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  client_id: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  address_sealed: string;
  @column(#{sql: "cidr", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  as_org: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "double precision"})
  latitude?: float64;
  @column(#{sql: "double precision"})
  longitude?: float64;
  @column(#{sql: "integer", clauses: "NOT NULL DEFAULT 0", required: true})
  accuracy_km: int32;
  @column(#{sql: "text[]", clauses: "NOT NULL DEFAULT '{}'", required: true})
  ip_lists: string[];
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_hash: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_family: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_os: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_platform: string;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  bot: boolean;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ja4: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_hash: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  aaguid: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  authenticator_cert: string;
  @column(#{sql: "boolean"})
  backup_eligible?: boolean;
  @column(#{sql: "boolean"})
  backup_state?: boolean;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  jkt: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  cert_fingerprint: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  datasets: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true})
  signals: unknown;
  @column(#{sql: "real", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  decision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  policy_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  error_code: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  // What the person said about a sign-in (#62 P6, schema version 9).
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, added: true})
  feedback: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true, added: true})
  feedback_at: int64;
}

@table(#{name: "sts_risk_feature_counts", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 7, text: "PRIMARY KEY (realm, subject, feature, value)"}], driver: #{order: 70}, indexes: #[#{name: "sts_risk_feature_counts_age", text: "CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON sts_risk_feature_counts (realm, last_at)", driver: #{order: 71}}]})
model StsRiskFeatureCounts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  feature: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  value: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  first_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  last_at: int64;
}

@table(#{name: "sts_risk_failures", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 11, text: "PRIMARY KEY (realm, id)"}], driver: #{order: 72}, indexes: #[#{name: "sts_risk_failures_subject", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON sts_risk_failures (realm, subject, at)", driver: #{order: 73}}, #{name: "sts_risk_failures_name", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON sts_risk_failures (realm, name_hmac, at)", driver: #{order: 74}}, #{name: "sts_risk_failures_prefix", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON sts_risk_failures (realm, address_prefix, at)", driver: #{order: 75}}, #{name: "sts_risk_failures_at", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON sts_risk_failures (at)", driver: #{order: 76}}]})
model StsRiskFailures {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "bigserial", clauses: "NOT NULL", required: true, primaryKey: true})
  id: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  at: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  door: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  name_hmac: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  address_sealed: string;
  @column(#{sql: "cidr", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  error_code: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_risk_session_context", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 12, text: "PRIMARY KEY (realm, session_id)"}], driver: #{order: 77}})
model StsRiskSessionContext {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  session_id: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  subject: string;
  @column(#{sql: "cidr", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_hash: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ja4: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  jkt: string;
  @column(#{sql: "real", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_subjects", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 11, text: "PRIMARY KEY (realm, subject)"}], driver: #{order: 78}})
model StsRiskSubjects {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  subject: string;
  @column(#{sql: "real", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  previous_level: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  reason: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  last_assessment: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  crossed_at: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  actions: unknown;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  feedback: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

// WHO ACCEPTED WHICH PROVIDER'S TERMS (#62, schema version 8, 2026-09-23 —
// the second licence review). One row per acceptance, never updated: the
// provider, a digest and the text of the terms as this build states them,
// who accepted them and through which door, the deployment, and the digest
// of the provider's own terms page when the install-time loader was asked
// to fetch it. An import of a provider's data is refused unless a row here
// matches that provider's CURRENT terms digest (`risk/risk_terms.ts`).
@table(#{name: "sts_risk_terms_acceptances", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 10, text: "PRIMARY KEY (id)"}], driver: #{order: 79}, indexes: #[#{name: "sts_risk_terms_acceptances_provider", text: "CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON sts_risk_terms_acceptances (provider, accepted_at)", driver: #{order: 80}}]})
model StsRiskTermsAcceptances {
  @column(#{sql: "bigserial", clauses: "NOT NULL", required: true, primaryKey: true})
  id: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  provider: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  terms_digest: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  terms_text: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  accepted_by: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  accepted_via: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  deployment: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  page_digest: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  accepted_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

// -------------------------------------------------------------------------
// WHERE EACH PERSON IS HOMED (#98, 2026-09-28, schema version 11). The
// routing index of a service deployed as cells: in the GLOBAL tier, so
// every cell can ask it, and holding NO name and NO identifier in the
// clear — `digest` is a keyed digest (`keystore.keyedDigest()`, under the
// service key every cell holds) of a login name (`kind` 'name') or of an
// entryUUID (`kind` 'uuid'). The row says which cell holds the person and
// nothing else about them. It is also what keeps a login name unique in a
// realm across cells: the PRIMARY KEY is the claim.
//
// Present in every database this driver opens, and empty in single-cell
// mode and in a cell's own database; one schema everywhere is cheaper than
// two schemas and a rule about which is where.
// -------------------------------------------------------------------------
@table(#{name: "sts_cell_routing", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 5, text: "PRIMARY KEY (realm, kind, digest)"}], driver: #{order: 81}})
model StsCellRouting {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  digest: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  cell: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  written_at: int64;
}

// A finished report's bytes (#956, schema version 26). The definition and
// the job row stay in the realm maps; this table is only the artifact.
@table(#{name: "sts_report_artifacts", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 6, text: "PRIMARY KEY (realm, job_id)"}], driver: #{order: 82}})
model StsReportArtifacts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  job_id: string;
  @column(#{sql: "bytea", clauses: "NOT NULL", required: true})
  bytes: bytes;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  sha256: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  media_type: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  created_at: int64;
}

// A finished report's pieces (#1045, schema version 29), each sealed on
// its own and numbered from 0. The `sts_report_artifacts` row of the
// same job says how many there are.
@table(#{name: "sts_report_artifact_pieces", head: "CREATE TABLE IF NOT EXISTS", constraints: #[#{at: 4, text: "PRIMARY KEY (realm, job_id, seq)"}], driver: #{order: 83}})
model StsReportArtifactPieces {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  job_id: string;
  @column(#{sql: "int", clauses: "NOT NULL", required: true, primaryKey: true})
  seq: int32;
  @column(#{sql: "bytea", clauses: "NOT NULL", required: true})
  bytes: bytes;
}

// What version of the above is on disk. One row, and nothing reads it yet —
// it is here so that a future change has something to look at other than the
// shape of the tables.
@table(#{name: "sts_schema", head: "CREATE TABLE IF NOT EXISTS", driver: #{order: 84}})
model StsSchema {
  @column(#{sql: "int", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  version: int32;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  applied_at: utcDateTime;
}

@schema(#{version: 31})
model PostgresSchema {}
