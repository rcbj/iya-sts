# CLAUDE.md — `mariadb/`

**`schema.sql` is generated since #1390**, from `models/persistence/persistence_mariadb.tsp`
and `mariadb.template.sql` beside it. Edit those and run
`tests/tools/regenerate-model-docs.sh`.

**The store's schema on MariaDB 11.8 (#677).** PostgreSQL is and stays the
primary store (`postgres/`); MariaDB is a second engine the suite runs
against. Nothing in this directory is run by the service.

| File | What it does |
|---|---|
| `schema.sql` | **builds the schema and the least-privileged account the service dials with.** Plain SQL for the `mariadb` client, idempotent, run by an owner in the database named on the command line |
| `../persistence/schema_mariadb.js` | **its second copy**: `SCHEMA_VERSION` (30), `SCHEMA_OBJECTS` (`{ name, statement }`, one per table and index, in the script's order) and `TABLES`. A leaf; requires nothing |

```bash
mariadb -u root -p sts < mariadb/schema.sql
mariadb -u root -p --init-command="SET @sts_app_user='iya_sts', \
  @sts_app_password='...', @sts_app_host='%', @sts_app_require_ssl=1" \
  sts < mariadb/schema.sql
```

## The alignment rule

**The two copies are the same statements modulo whitespace; edit both in one
change.** The `.sql` file aligns columns with runs of spaces, the `.js` file
has one space; nothing else may differ. Proved on 11.8 (2026-11-03) by loading
the script into one empty database and `SCHEMA_OBJECTS` into another, and
comparing every `SHOW CREATE TABLE`, `information_schema.COLUMNS`,
`STATISTICS`, `CHECK_CONSTRAINTS` and each table's engine and collation:
identical. `tests/mariadb_schema.js` holds the two copies together.
`common/mariadb_import.ts` emits this file's own bytes. A statement the
two copies do not share, whitespace aside, is a gap. The file is not
rebuilt from the column list.

The schema version is PostgreSQL's (30), so there is one `SCHEMA_VERSION`. A
change to `postgres/schema.sql` owes this directory the same change.

## What is in it

42 tables — PostgreSQL's 41 and `sts_ldap_entry_keys` — and 37 secondary
indexes: 36 `CREATE INDEX` and `KEY sts_risk_failures_id`, inline in its
table. PostgreSQL has 44; the difference is listed below.

## The translation, as applied

* **Every table is `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_nopad_bin`. The rule said `utf8mb4_bin`, and it did not
  fit**: `utf8mb4_bin` is binary but PAD SPACE, so `'uid=a'` and `'uid=a '`
  are one primary key (a duplicate-key error on 11.8) where PostgreSQL holds
  two. `utf8mb4_nopad_bin` compares as PostgreSQL does, case and trailing
  space both. A JSON column is `utf8mb4_bin` whatever the table says (MariaDB
  fixes it for the type). The service's session says `SET NAMES utf8mb4
  COLLATE utf8mb4_nopad_bin` too (`persistence/knex_store.js`), so a literal
  compared with a literal does not pad either.
* **Types.** `bigint` BIGINT, `integer`/`int` INT, `smallint` SMALLINT,
  `boolean` BOOLEAN (TINYINT(1)), `real` FLOAT (single precision, as
  `real`), `double precision` DOUBLE, `bytea` LONGBLOB, `jsonb` JSON (LONGTEXT
  with a `json_valid` check), `timestamptz DEFAULT now()` `DATETIME(6) NOT
  NULL DEFAULT CURRENT_TIMESTAMP(6)` — no zone is stored, so it is UTC only
  because the session's `time_zone` is `+00:00`. `bigserial`: `BIGINT NOT NULL
  AUTO_INCREMENT`; `sts_changes.seq` and `sts_risk_terms_acceptances.id` are
  the primary key, and `sts_risk_failures`, whose key starts with `realm`,
  carries `KEY sts_risk_failures_id (id)`, which InnoDB requires.
* **JSON defaults are plain literals** (`DEFAULT '[]'`); MariaDB takes them
  and needs no `DEFAULT ('[]')`. A LONGTEXT `DEFAULT ''` is kept likewise.
  JSON is stored as written: no key order or duplicate normalisation, and
  `=` compares text, where `jsonb` compares values.
* **`inet` is INET6.** An IPv4 address is stored and returned as
  `::ffff:a.b.c.d`, and sorts after `::1` and before `2000::`; PostgreSQL
  sorts every IPv4 address before every IPv6 one. A range lookup must put its
  probe in the same form. **`cidr` is `VARCHAR(50)`** holding the prefix text,
  unvalidated (PostgreSQL refuses host bits) and ordered as text. **`text[]`
  (`ip_lists`) is a JSON array**, default `'[]'` for `'{}'`.
* **`key` is a reserved word** and is back-quoted wherever it is a column.
* **The generated columns** are STORED, rewritten with `LOCATE`, `SUBSTRING`
  and `SUBSTRING_INDEX`. Checked against PostgreSQL 18's own expressions on
  thirteen keys — a normal DN, no comma, an escaped comma `uid=a\,b,…` (split
  at it, as PostgreSQL does), no `=`, a leading `=`, two `=`, an empty value,
  a leading and a trailing comma, non-ASCII, the empty string: identical.
* **The counts.** `sts_ldap_counts` and `sts_ldap_dek_counts` are tables of
  the same columns. The two delta tables keep their columns with `txid
  VARCHAR(64) NOT NULL` and no default — the driver writes a per-transaction
  id it makes, where PostgreSQL's is `pg_current_xact_id()`. **There is no
  trigger and no function**: PostgreSQL keeps the counts with statement
  triggers over transition tables and a deferred constraint trigger, and
  MariaDB has row triggers only, so **on this engine the driver maintains the
  counts** (and picks the shard, which PostgreSQL takes from
  `pg_backend_pid() % 16`).
* **`sts_ldap_entry_keys (realm, kind, k, dn_key)`**, primary key all four,
  `sts_ldap_entry_keys_entry (realm, dn_key)`, and a CHECK that `kind` is one
  of `name`, `mail`, `uuid`, `class`, `value`, `attr`, `dek`. The JSON lookup
  columns stay on the entry row; this table is what MariaDB can index, and the
  driver writes it in the entry's own transaction.

## Size limits

InnoDB's key limit is 3072 bytes, 768 utf8mb4 characters across an index's
columns; 768 exactly is accepted and 769 refused (checked). A value longer than
its column is REFUSED under `STRICT_ALL_TABLES` (error 1406), never truncated.

| Column(s) | Size | Why |
|---|---|---|
| every `realm` that is keyed or indexed | 64 | realm ids are at most 31 (`common/realms.js`) |
| `dn_key`, `parent_key`, `rdn_value`, `sts_ldap_counts.base_key` | **352** | `(realm, parent_key, dn_key)` and `(realm, parent_key, rdn_value)` are 64 + 352 + 352 = 768; the two generated columns are substrings of `dn_key`, so they need its width. **A DN key over 352 characters cannot be stored** |
| `created_at`, `modified_at` | 32 | generalized time |
| `sts_ldap_entry_keys.kind` / `.k` | 8 / **344** | 64 + 8 + 344 + 352 = 768. **`k` is a keyed digest, but where no digest key is held the lookup form is `<kind>\n<value>` in the clear** (`persistence/directory_codec.js`), and a DID or a federation link can be longer: the driver must digest such a value or refuse it |
| `key` of `sts_minted`, `sts_minted_index`, `sts_sessions`, `sts_used_assertions` and the three cluster key tables; `sts_sessions.parent_key` | **512** | `sts_minted_index`'s key is 64 + 64 + 128 + 512 = 768. **Where nothing seals, `sts_minted.key` is the row's NAME in the clear** (`persistence/persistence_minted.js`, `columnsFor()`), which can be longer |
| `handle` | 64 | the longest declared is 31 characters |
| `sts_minted_index.index_key` | 128 | always a keyed digest |
| `scope` (cluster) | 128 | |
| `subject_key`, `username_key`, `credential_key`, `partner_relationship`, `rp_surface`; `node_id`, lease, secret, lock and snapshot `name`, `sts_change_readers.origin`, `sts_appconfig.key`, `dek_id`; the risk `id`, `subject`, `session_id`, `name_hmac`, `value`, `authenticator_key`, `digest`, `job_id` | 255 | identifiers and digests |
| risk `dataset`, `version`, `provider` | 128 | |
| `feature`, `attribute`, `sts_cell_routing.kind` | 64 | |
| `key_kind` | 32 | |
| `address_prefix` | 50 | the longest IPv6 prefix is 43 |
| every other `text` | LONGTEXT | not keyed |

The txid of a delta table is 64.

## What PostgreSQL has that this does not, and what replaces it

| PostgreSQL | Here |
|---|---|
| GIN `jsonb_path_ops` indexes `sts_ldap_entries_names`, `_mails`, `_uuids`, `_values` | `sts_ldap_entry_keys`, kinds `name`, `mail`, `uuid`, `value` |
| `sts_ldap_entries_asked_names`: GIN over a `jsonb_path_query_array` expression, partial on `attr_names ?| ARRAY[…]` | kind `attr`. Writing rows for `ASKED_ATTRIBUTES` only keeps the index's property that most people write none; that is the driver's choice |
| `sts_ldap_entries_group_classes`: GIN, partial on `class_keys <> '[]'` | kind `class`; an entry with no group class writes no row |
| `sts_ldap_entries_dek_keys`: GIN | kind `dek` |
| `sts_ldap_entries_dek_unknown (realm, dn_key) WHERE dek_keys IS NULL` | **dropped**: it exists only for its predicate, and the full form would duplicate the primary key. A NULL `dek_keys` is an entry written before the column existed, which a store built at version 31 never has; finding one is a scan |
| `sts_ldap_entries_uid_trgm`: `pg_trgm` trigram GIN over `rdn_value`, partial on `ou=users` | **nothing**: a search by part of a `uid` (`/portal/delegate`, and since #1310 the role chooser's needle count and page) scans the realm's `ou=users` children, through the `(realm, parent_key)` prefix of `sts_ldap_entries_rdn`, bounded by #1308's cap only when the needle is broad. **A STATED LIMIT, not an oversight (#1310)**: FULLTEXT is word-based, and the n-gram parser is MySQL's — on `mariadb:11.8` (11.8.9) `CREATE FULLTEXT INDEX … WITH PARSER ngram` answers `Function 'ngram' is not defined`, and the official image ships no Mroonga engine. A substring index here would be a side table of trigrams the driver writes, which nobody has asked for |
| `fastupdate = off`, `gin_clean_pending_list()` | nothing: no GIN |
| partial `sts_ldap_entries_created`, `_modified` (`ou=users` only); `sts_minted_expires` (`IS NOT NULL`); the seven `sts_sessions_*` (`<> ''`, `chosen`, `IS NOT NULL`); `sts_minted_index_sort` (`IS NOT NULL`) | **whole indexes on the same columns**; `sts_minted_index_sort` keeps `DESC` |
| BRIN `sts_minted_written_brin` with `autosummarize` | a B-tree, under the name the BRIN replaced there, `sts_minted_written`. The BRIN was for PostgreSQL's HOT updates, which InnoDB has no counterpart of |
| storage parameters: `fillfactor=80` on `sts_minted`, the autovacuum settings on `sts_ldap_entries` and `sts_changes`, `n_distinct=100000` on `parent_key` and its `ANALYZE` | nothing: InnoDB has no vacuum, and its statistics are its own |
| the count and data-key triggers and their seven functions, `LOCK TABLE … SHARE ROW EXCLUSIVE`, the backfill INSERTs | nothing; the driver keeps the counts. A TRUNCATE of the directory resets nothing (the account cannot TRUNCATE: it needs DROP) |
| `xid8 DEFAULT pg_current_xact_id()` | `VARCHAR(64) NOT NULL`, written by the driver |
| the dropped retired indexes and triggers, the `ADD COLUMN IF NOT EXISTS` and shard-key `DO` upgrades | nothing: every MariaDB store is built at version 31 |
| `CREATE SCHEMA sts`, `ALTER DATABASE … SET search_path` | the database: in MariaDB a schema is a database, named on the command line |
| `CREATE EXTENSION pg_stat_statements` | nothing; profiling is the server's configuration (`performance_schema`) |
| `SET client_min_messages` | nothing: the batch client prints no notes |
| one `BEGIN … COMMIT` | none: MariaDB commits each DDL statement, so an interrupted run is finished by running it again |
| sequences and `GRANT USAGE ON SEQUENCES` | AUTO_INCREMENT, which needs no grant |

## The account

`CREATE USER IF NOT EXISTS`, then `ALTER USER … IDENTIFIED BY` every run (a
run is a rotation, as in PostgreSQL), then every GLOBAL privilege and
everything on THIS database revoked, and `SELECT, INSERT, UPDATE, DELETE ON
<db>.*` granted — which covers a table created later, as PostgreSQL's `ALTER
DEFAULT PRIVILEGES` does. Grants on other databases are left alone. Each
statement is text run with `EXECUTE IMMEDIATE` (the client has no `\gexec`),
names and the password quoted by doubling quotes under `NO_BACKSLASH_ESCAPES`,
which the script sets.

Checked on 11.8: the account inserts, updates, selects `FOR UPDATE`, deletes
and takes an AUTO_INCREMENT; CREATE TABLE, CREATE TABLE IF NOT EXISTS on a
table that exists, CREATE INDEX IF NOT EXISTS on one that exists, ALTER, DROP,
TRUNCATE, CREATE DATABASE and a read of `mysql.user` are all refused. **So, as
on PostgreSQL, a driver must PROBE (`information_schema`, which the account
can read) before issuing any CREATE.** Extra global and database grants are
removed by a second run.

**TLS.** PostgreSQL's decision is TLS required at both ends
(`persistence/CLAUDE.md`, *TLS TO THE DATABASE, REQUIRED AT BOTH ENDS*:
`hostssl` on the server, the client refusing a `sslmode` below `require`).
`@sts_app_require_ssl=1` is the server half here, `REQUIRE SSL` on the
account; it is an option, off by default, because a test container may have no
certificate, and a later run with 0 never turns it off. Checked: with it, a
plaintext login is refused and a TLS one accepted (11.8 makes a certificate
itself). The client half is the driver's.

**`--init-command` runs in the server's default `sql_mode`, before the script
sets its own**, so a backslash in a value given there is an escape.
