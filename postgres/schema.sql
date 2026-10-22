-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: postgres/schema.sql
--
-- ---------------------------------------------------------------------------
-- THE SCHEMA, BUILT ONCE, BY SOMEBODY WHO IS ALLOWED TO BUILD IT.
--
-- Until 2026-09-06 there was no such file: `persistence/persistence_postgres.js`
-- carried the whole schema as `CREATE TABLE IF NOT EXISTS` and ran it on every
-- open(), which meant THE SERVICE'S OWN DATABASE ROLE HAD TO BE ABLE TO CREATE
-- TABLES. A mock identity service that can `CREATE TABLE` can also `DROP` one,
-- and the role it dials with was the bootstrap superuser of the cluster.
--
-- This file is the other half of splitting that in two:
--
--   * an OWNER role builds the schema — that is this script, run once, by a
--     superuser or by the owner of the database;
--   * an APPLICATION role reads and writes the rows in it and can do NOTHING
--     ELSE — no CREATE, no ALTER, no DROP, no TRUNCATE. That is the role the
--     service dials with, and it is created at the bottom of this file.
--
-- **THE DRIVER STILL CREATES WHAT IS MISSING, AND THAT IS NOT A CONTRADICTION.**
-- It PROBES first (`to_regclass`) and issues a `CREATE` only for an object that
-- is not there, so against a database this script has already built it issues
-- none and needs no privilege to create one. That matters more than it looks:
-- `CREATE TABLE IF NOT EXISTS` checks CREATE on the schema BEFORE it checks
-- whether the table exists — PostgreSQL's own parse_utilcmd.c says so in a
-- comment — so a driver that ran the statement anyway would be refused on
-- every start by a role that had nothing to do.
--
-- ---------------------------------------------------------------------------
-- RUNNING IT.
--
--   psql -v ON_ERROR_STOP=1 -f postgres/schema.sql "postgres://sts:sts@localhost:5432/sts"
--
-- and to name the application role and its password rather than take the
-- defaults (`sts_app` / `sts_app`, which is what docker-compose.yml uses):
--
--   psql -v ON_ERROR_STOP=1 \
--        -v sts_app_role=iya_sts -v sts_app_password='...' \
--        -f postgres/schema.sql "postgres://.../sts"
--
-- IT IS IDEMPOTENT. Every object is `IF NOT EXISTS` and every grant is a grant
-- of something already granted, so running it twice changes nothing — except
-- the application role's password, which is set every time so that rotating it
-- is running this file again.
--
-- **IT IS ALSO WHAT THE COMPOSE STACK RUNS**, through
-- `postgres/apply-schema.sh` in `/docker-entrypoint-initdb.d`, which is why
-- this is a plain `.sql` file taking psql variables rather than a shell script
-- with the values baked in: one file, run by hand or by the image, and no
-- second copy of the DDL to drift.
--
-- ---------------------------------------------------------------------------
-- THE STATEMENTS BELOW ARE THE DRIVER'S, CHARACTER FOR CHARACTER MODULO
-- WHITESPACE, AND A TEST SAYS SO.
--
-- `tests/postgres_schema.js` reads this file, reads
-- `persistence/persistence_postgres.js`'s exported SCHEMA, and fails if either
-- holds a `CREATE` the other does not. That is the whole reason it is safe to
-- have the schema written down twice: a column added to the driver and not to
-- this file would otherwise produce a database that is subtly one column short
-- and a service that cannot add it — a failure that would arrive as a
-- permission error naming nothing.
--
-- **SO: EDIT BOTH, IN ONE CHANGE.** The comments explaining WHY each column is
-- the shape it is live in the driver, beside the code that reads them, and are
-- deliberately not repeated here.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- THE FOUR PARAMETERS, AND THEIR DEFAULTS.
--
-- `:{?name}` is psql's "was this variable set" test, so `-v` on the command
-- line wins and a run with no arguments still works. The defaults are
-- docker-compose.yml's values, so a person following the README against a
-- local database and a person running the stack get the same database.
-- ---------------------------------------------------------------------------
\if :{?sts_schema}
\else
\set sts_schema sts
\endif
\if :{?sts_app_role}
\else
\set sts_app_role sts_app
\endif
\if :{?sts_app_password}
\else
\set sts_app_password sts_app
\endif

\echo 'sts-schema: schema' :'sts_schema' 'application role' :'sts_app_role'

BEGIN;

-- NOTICES OFF, WARNINGS AND ERRORS KEPT. On a NEW database every
-- `ALTER … ADD COLUMN IF NOT EXISTS` below finds the column its `CREATE
-- TABLE` just made and says "already exists, skipping" — fourteen lines of
-- noise in the container's first start that read like a fault. Those ALTERs
-- are the upgrade path for an OLDER database and stay; only the chatter goes.
-- Session-wide rather than LOCAL, so it outlives the COMMIT and covers the
-- grants at the bottom too.
SET client_min_messages = warning;

-- ---------------------------------------------------------------------------
-- A SCHEMA OF ITS OWN, AND NOT `public`, FOR ONE REASON: A SCHEMA IS WHERE
-- CREATE IS GRANTED.
--
-- "Read and write the rows but do not change the shape" is expressed in
-- PostgreSQL as USAGE on a schema without CREATE on it. Doing that in `public`
-- means revoking a privilege the whole cluster shares — every database has a
-- `public`, and on servers before 15 PUBLIC holds CREATE on it — so the
-- narrowest thing that can be said is said about a schema this service owns.
-- `public` is locked down as well at the bottom, because a role that cannot
-- create here and can create there has not been stopped from creating.
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS :"sts_schema";

-- WHERE UNQUALIFIED NAMES RESOLVE, FOR THIS SESSION AND FOR EVERY LATER ONE.
--
-- The driver writes `sts_ldap_entries` and not `sts.sts_ldap_entries` — that
-- is what makes it a driver for PostgreSQL rather than for this stack — so
-- something has to say which schema that means. It is set on the DATABASE, so
-- it holds for every role that connects to it including this one, rather than
-- on the role, where it would have to be repeated for each new one.
--
-- **THE DEFAULT `"$user", public` WOULD HAVE BEEN A TRAP HERE AND NOT AN
-- ERROR**: the owner role in the compose stack is called `sts` and so is this
-- schema, so the owner would have found the tables through `"$user"` and the
-- application role — `sts_app`, with no schema of that name — would not, which
-- is a failure that reads as "the tables are missing" on one connection and
-- not on another.
SELECT format('ALTER DATABASE %I SET search_path = %I, public',
              current_database(), :'sts_schema')
\gexec

-- ALTER DATABASE takes effect on the NEXT session, so this one says it too.
SET search_path TO :"sts_schema", public;

-- WHAT THE DATABASE SPENDS ITS TIME ON (#630): `pg_stat_statements`, the
-- view an operator asks which statements cost what. The library is loaded
-- by the SERVER (`shared_preload_libraries`, the compose stack's postgres
-- command; postgres/CLAUDE.md); this creates the view. In `public`, beside
-- whatever else is installed there, not in this service's schema. Only a
-- role that may create it does — a superuser, RDS's master user — and any
-- other is told and goes on: a store without the view is a store an
-- operator cannot profile, not a store that is wrong. The application
-- role is granted nothing for it (it is not `pg_read_all_stats`, as it is
-- not `pg_monitor`): reading other roles' statements is the owner's.
DO $ext$ BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;
EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN
  RAISE WARNING 'sts-schema: pg_stat_statements not created (%); the store works without it', SQLERRM;
END $ext$;

-- ---------------------------------------------------------------------------
-- THE TABLES. `persistence/persistence_postgres.js`'s SCHEMA, verbatim.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sts_ldap_entries (
  realm       text        NOT NULL,
  dn_key      text        NOT NULL,
  dn          text        NOT NULL,
  attrs       jsonb       NOT NULL,
  origin      text,
  created_at  text,
  modified_at text,
  parent_key text GENERATED ALWAYS AS (CASE WHEN strpos(dn_key, ',') > 0 THEN substr(dn_key, strpos(dn_key, ',') + 1) ELSE '' END) STORED,
  rdn_value text GENERATED ALWAYS AS (substr(split_part(dn_key, ',', 1), strpos(split_part(dn_key, ',', 1), '=') + 1)) STORED,
  name_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  mail_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  uuid_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  class_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  value_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  attr_names jsonb NOT NULL DEFAULT '[]'::jsonb,
  dek_keys jsonb,
  PRIMARY KEY (realm, dn_key));

CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm);

-- AUTOVACUUM FOR AN INSERT-HEAVY DIRECTORY (#630, schema version 19): an
-- insert-only load is vacuumed every 20% of the table by default — about
-- 600,000 inserts at 2.9M entries, with the GIN pending lists and the
-- visibility map waiting that long. 1%.
ALTER TABLE sts_ldap_entries SET (autovacuum_vacuum_insert_scale_factor=0.01);

-- THE DIRECTORY'S LOOKUP COLUMNS (#349, schema version 13, 2026-09-29): what
-- a request worker holding the people and devices as a bounded window asks
-- the store instead of an index in memory. Each is GENERATED from `dn_key`
-- and `attrs` by an immutable expression, so no writer maintains it, and
-- adding one to a table that already has rows rewrites the table once and
-- fills them — the whole of the migration. What each mirrors in
-- `ldap/ldap_server.js`: `parent_key` is `parentDn()` of the key (everything
-- after the first comma — the key splits on every comma, escapes unread);
-- `rdn_value` the first RDN's value; `name_keys`, `mail_keys` and
-- `uuid_keys` the `uid`, `mail` and entryUUID (and alias) values, and
-- `class_keys` the object classes,
-- lower-cased, as a JSON array for `@>`. `persistence/directory_queries.js`
-- builds every statement that reads them. Added separately as well, for
-- `sts_realms.domain`'s reason.
--
-- SINCE #391 PHASE 6 (schema version 14) ONLY `parent_key` AND `rdn_value`
-- ARE GENERATED: `attrs` holds the entry SEALED, as one blob, which the
-- database cannot read. `name_keys`, `mail_keys`, `uuid_keys` and
-- `class_keys` are written by the service beside it as KEYED DIGESTS of the
-- same values (`persistence/directory_codec.js`), and so are `value_keys` —
-- `name=value` of the attributes looked up by value (a login name, a DID, a
-- SPIFFE ID, a certificate subject, a federation link) — and `attr_names`,
-- the attribute NAMES in the clear. A database built before version 14 has
-- them generated and is refused at start (STS-STORE-0074): recreate it.
-- Since version 18 `class_keys` holds an entry's GROUP classes only (#618).
-- An entry written before then holds all its classes until it is next
-- written, which the one question asked of the column answers the same.
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS parent_key text GENERATED ALWAYS AS (CASE WHEN strpos(dn_key, ',') > 0 THEN substr(dn_key, strpos(dn_key, ',') + 1) ELSE '' END) STORED;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS rdn_value text GENERATED ALWAYS AS (substr(split_part(dn_key, ',', 1), strpos(split_part(dn_key, ',', 1), '=') + 1)) STORED;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS name_keys jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS mail_keys jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS uuid_keys jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS class_keys jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS value_keys jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS attr_names jsonb NOT NULL DEFAULT '[]'::jsonb;

-- THE DATA KEYS AN ENTRY HOLDS VALUES UNDER (#623, schema version 17):
-- `{ "<dek id>": <values> }` — the sealed blob's own key and the key of every
-- value sealed inside it, which the database cannot see — written by the
-- service beside the blob. NULLABLE WITH NO DEFAULT: adding it rewrites
-- nothing, and NULL is an entry written before it existed, whose keys are
-- not known (never "none"); the service indexes those entries a bounded
-- batch per pass of its data-key jobs, once.
ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS dek_keys jsonb;

-- The children of a container in key order, and the RDN value there (a login
-- name); the `uid`, `mail` and entryUUID digests; and the digests of the
-- values looked up as written (a DID, a SPIFFE ID, a federation link).
CREATE INDEX IF NOT EXISTS sts_ldap_entries_parent ON sts_ldap_entries (realm, parent_key, dn_key);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_rdn ON sts_ldap_entries (realm, parent_key, rdn_value);

-- A PERSON FOUND BY PART OF THEIR `uid` (schema version 23, 2026-10-20,
-- `/portal/delegate`): a trigram GIN over `rdn_value` — generated, in the
-- clear and lower-cased, so nothing sealed is indexed — partial on the
-- children of a realm's `ou=users`. The driver argues it. `pg_trgm` is a
-- trusted extension (PostgreSQL 13+) and contrib ships in the official
-- image. THIS SCRIPT RUNS IN ONE TRANSACTION, so the index is built here
-- without CONCURRENTLY, which holds every write to the table for the build.
-- ON A LARGE EXISTING STORE, RUN THIS FIRST, as the owner, outside a
-- transaction — after which the CREATE below finds it built:
--   CREATE EXTENSION IF NOT EXISTS pg_trgm;
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS sts_ldap_entries_uid_trgm ON sts_ldap_entries USING gin (rdn_value gin_trgm_ops) WITH (fastupdate = off) WHERE parent_key LIKE 'ou=users,%';
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS sts_ldap_entries_uid_trgm ON sts_ldap_entries USING gin (rdn_value gin_trgm_ops) WITH (fastupdate = off) WHERE parent_key LIKE 'ou=users,%';

-- HOW MANY PARENTS THE DIRECTORY HAS, SAID RATHER THAN SAMPLED (#639, schema
-- version 20). ANALYZE reads about 30,000 rows, and with 50M of 50.2M entries
-- under one `ou=users` its sample held one `parent_key`: `n_distinct` was 1,
-- and a parent the planner cannot see (a LATERAL's) was estimated as the
-- whole realm, so a windowed worker's restore read the primary key with
-- `parent_key` as a filter, once per parent, and the start hung. The parents
-- are containers, which do not grow with the people, so the figure is
-- absolute; 100,000 makes an unknown parent a container's worth of rows.
-- The ANALYZE of the one column makes it take effect now. Both are the
-- table owner's to run; `persistence/CLAUDE.md` argues the value.
ALTER TABLE sts_ldap_entries ALTER COLUMN parent_key SET (n_distinct=100000);
ANALYZE sts_ldap_entries (parent_key);

CREATE INDEX IF NOT EXISTS sts_ldap_entries_names ON sts_ldap_entries USING gin (name_keys jsonb_path_ops) WITH (fastupdate = off);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_mails ON sts_ldap_entries USING gin (mail_keys jsonb_path_ops) WITH (fastupdate = off);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_uuids ON sts_ldap_entries USING gin (uuid_keys jsonb_path_ops) WITH (fastupdate = off);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_values ON sts_ldap_entries USING gin (value_keys jsonb_path_ops) WITH (fastupdate = off);

-- THE ATTRIBUTE NAMES A HOLDER QUESTION ASKS, AND THE GROUP CLASSES (#618
-- phase 2, schema version 18), each a PARTIAL GIN index with the default
-- operator class (`?`, `?|`), so an entry that holds none of the asked
-- names and is not a group — nearly every person — writes no entry to
-- either. The names are an expression of `attr_names` keeping only
-- `persistence/directory_queries.js`'s ASKED_ATTRIBUTES, which every query
-- repeats character for character; `class_keys` holds the group classes
-- only, as the service writes it from this version (an entry written before
-- still holds all its classes, which answers the same question). They
-- replace the two below, which indexed every name and every class of every
-- entry — about nineteen GIN entries a person insert that narrowed nothing.
CREATE INDEX IF NOT EXISTS sts_ldap_entries_asked_names ON sts_ldap_entries USING gin ((jsonb_path_query_array(attr_names, '$[*] ? (@ == "federationlink" || @ == "hobapublickey" || @ == "memberof" || @ == "oauthconsent" || @ == "stsacmeeabkey" || @ == "stsandroidattestedcredential" || @ == "stsassertionissuer" || @ == "stsassertionjwks" || @ == "stscertificatehostname" || @ == "stsclaimsourcetokens" || @ == "stsdefaultdelegationsemantics" || @ == "stsdelegationsemantics" || @ == "stsdeviceandroidkey" || @ == "stsdevicekey" || @ == "stsenrolledcertificate" || @ == "stsenrolledprivatekey" || @ == "stskrb5keyinfo" || @ == "stskrb5keys" || @ == "stsmailfactor" || @ == "stsmayact" || @ == "stsnotdelegated" || @ == "stssamlassertioncertificate" || @ == "stssamlassertionissuer" || @ == "stsscepchallenge" || @ == "stsselfissuedsubject" || @ == "stsserviceaccount" || @ == "ststotpcredential" || @ == "stswebauthncredential" || @ == "stswebauthnuserhandle")'))) WITH (fastupdate = off) WHERE attr_names ?| ARRAY['federationlink', 'hobapublickey', 'memberof', 'oauthconsent', 'stsacmeeabkey', 'stsandroidattestedcredential', 'stsassertionissuer', 'stsassertionjwks', 'stscertificatehostname', 'stsclaimsourcetokens', 'stsdefaultdelegationsemantics', 'stsdelegationsemantics', 'stsdeviceandroidkey', 'stsdevicekey', 'stsenrolledcertificate', 'stsenrolledprivatekey', 'stskrb5keyinfo', 'stskrb5keys', 'stsmailfactor', 'stsmayact', 'stsnotdelegated', 'stssamlassertioncertificate', 'stssamlassertionissuer', 'stsscepchallenge', 'stsselfissuedsubject', 'stsserviceaccount', 'ststotpcredential', 'stswebauthncredential', 'stswebauthnuserhandle'];
CREATE INDEX IF NOT EXISTS sts_ldap_entries_group_classes ON sts_ldap_entries USING gin (class_keys) WITH (fastupdate = off) WHERE class_keys <> '[]'::jsonb;
DROP INDEX IF EXISTS sts_ldap_entries_attr_names;
DROP INDEX IF EXISTS sts_ldap_entries_classes;

-- EVERY GIN INDEX OF THE DIRECTORY TAKES ITS INSERTS DIRECTLY (#618, schema
-- version 18): `fastupdate = off`, so no search reads a pending list. On
-- 8081 the names', uuids', mails' and values' lists held about 205,000
-- tuples each and every login-name and UUID probe read all 500 pages of
-- one (8.9-17.6 ms, against 0.02 ms for the RDN). The CREATEs above say it
-- for a new store; these switch an existing one, and flush the list it
-- already holds, once — turning the option off does not empty it. The
-- driver's SCHEMA_RELOPTIONS argues it.
ALTER INDEX sts_ldap_entries_names SET (fastupdate = off);
ALTER INDEX sts_ldap_entries_mails SET (fastupdate = off);
ALTER INDEX sts_ldap_entries_uuids SET (fastupdate = off);
ALTER INDEX sts_ldap_entries_values SET (fastupdate = off);
ALTER INDEX sts_ldap_entries_asked_names SET (fastupdate = off);
ALTER INDEX sts_ldap_entries_group_classes SET (fastupdate = off);
SELECT gin_clean_pending_list('sts_ldap_entries_names'::regclass);
SELECT gin_clean_pending_list('sts_ldap_entries_mails'::regclass);
SELECT gin_clean_pending_list('sts_ldap_entries_uuids'::regclass);
SELECT gin_clean_pending_list('sts_ldap_entries_values'::regclass);
SELECT gin_clean_pending_list('sts_ldap_entries_asked_names'::regclass);
SELECT gin_clean_pending_list('sts_ldap_entries_group_classes'::regclass);
-- The entries holding a value under any of a set of data keys (`?|`, the
-- default GIN operator class): what a re-seal reads, and all it reads
-- (#623). And the entries whose keys are not known yet, found without a
-- scan.
CREATE INDEX IF NOT EXISTS sts_ldap_entries_dek_keys ON sts_ldap_entries USING gin (dek_keys);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_dek_unknown ON sts_ldap_entries (realm, dn_key) WHERE dek_keys IS NULL;

-- THE DIRECTORY'S COUNTS, KEPT RATHER THAN COUNTED (#618, schema version 16):
-- per realm and per base (every ancestor of a row's DN, '' for the realm),
-- the entries strictly under it (`attribute` '') and those holding a counted
-- attribute. Triggers on `sts_ldap_entries` append each statement's net to
-- `sts_ldap_count_deltas`, and a deferred constraint trigger folds a
-- transaction's deltas into `sts_ldap_counts` at COMMIT. The driver's
-- SCHEMA_ROUTINES carries the argument.
CREATE TABLE IF NOT EXISTS sts_ldap_counts (
  realm     text     NOT NULL,
  base_key  text     NOT NULL,
  attribute text     NOT NULL,
  shard     smallint NOT NULL DEFAULT 0,
  n         bigint   NOT NULL DEFAULT 0,
  PRIMARY KEY (realm, base_key, attribute, shard));

-- SHARDED (#630, schema version 19): `shard` in the key, so two commits of
-- one realm fold into different rows unless their server process ids fall
-- in one of sixteen shards, and every reader sums a key's shards. An
-- existing row is shard 0, so the sums are unchanged. The key takes the
-- column in only where it does not hold it yet.
ALTER TABLE sts_ldap_counts ADD COLUMN IF NOT EXISTS shard smallint NOT NULL DEFAULT 0;
DO $upgrade$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey) WHERE i.indrelid = to_regclass('sts_ldap_counts') AND i.indisprimary AND a.attname = 'shard') THEN
  ALTER TABLE sts_ldap_counts DROP CONSTRAINT sts_ldap_counts_pkey;
  ALTER TABLE sts_ldap_counts ADD PRIMARY KEY (realm, base_key, attribute, shard);
END IF; END $upgrade$;

CREATE TABLE IF NOT EXISTS sts_ldap_count_deltas (
  txid       xid8    NOT NULL DEFAULT pg_current_xact_id(),
  realm      text    NOT NULL,
  parent_key text    NOT NULL,
  n          bigint  NOT NULL,
  holding    bigint  NOT NULL,
  fold       boolean NOT NULL DEFAULT false);

CREATE INDEX IF NOT EXISTS sts_ldap_count_deltas_txid ON sts_ldap_count_deltas (txid);

-- WHAT THE DIRECTORY HOLDS UNDER EACH DATA KEY, KEPT (#623, schema version
-- 17): the sum of every entry's `dek_keys` for the key, kept as #618 keeps
-- `sts_ldap_counts` — each statement's net appended to
-- `sts_ldap_dek_deltas`, folded in at COMMIT — so the data-key count and the
-- re-encryption job read a few rows instead of walking the directory.
CREATE TABLE IF NOT EXISTS sts_ldap_dek_counts (
  dek_id text     NOT NULL,
  shard  smallint NOT NULL DEFAULT 0,
  n      bigint   NOT NULL DEFAULT 0,
  PRIMARY KEY (dek_id, shard));

-- Sharded as `sts_ldap_counts` is (#630, schema version 19).
ALTER TABLE sts_ldap_dek_counts ADD COLUMN IF NOT EXISTS shard smallint NOT NULL DEFAULT 0;
DO $upgrade$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey) WHERE i.indrelid = to_regclass('sts_ldap_dek_counts') AND i.indisprimary AND a.attname = 'shard') THEN
  ALTER TABLE sts_ldap_dek_counts DROP CONSTRAINT sts_ldap_dek_counts_pkey;
  ALTER TABLE sts_ldap_dek_counts ADD PRIMARY KEY (dek_id, shard);
END IF; END $upgrade$;

CREATE TABLE IF NOT EXISTS sts_ldap_dek_deltas (
  txid   xid8    NOT NULL DEFAULT pg_current_xact_id(),
  dek_id text    NOT NULL,
  n      bigint  NOT NULL,
  fold   boolean NOT NULL DEFAULT false);

CREATE INDEX IF NOT EXISTS sts_ldap_dek_deltas_txid ON sts_ldap_dek_deltas (txid);

-- No writer may land between the count below and the triggers: CREATE
-- TRIGGER takes this lock too, and it is taken first so that a run against a
-- database whose triggers already exist holds it as well.
LOCK TABLE sts_ldap_entries IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION sts_ldap_count_bases(parent text) RETURNS SETOF text LANGUAGE sql IMMUTABLE AS $$
  SELECT parent
  UNION ALL SELECT substr(parent, i + 1) FROM generate_series(1, length(parent)) AS i WHERE substr(parent, i, 1) = ','
  UNION ALL SELECT '' WHERE parent <> ''
$$;

CREATE OR REPLACE FUNCTION sts_ldap_count_note() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE added bigint;
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding)
    SELECT realm, parent_key, count(*), count(*) FILTER (WHERE attr_names ? 'userpassword')
    FROM new_rows GROUP BY realm, parent_key;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding)
    SELECT realm, parent_key, -count(*), -count(*) FILTER (WHERE attr_names ? 'userpassword')
    FROM old_rows GROUP BY realm, parent_key;
  ELSE
    INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding)
    SELECT realm, parent_key, sum(n), sum(h) FROM (SELECT realm, parent_key, 1 AS n, CASE WHEN attr_names ? 'userpassword' THEN 1 ELSE 0 END AS h FROM new_rows
      UNION ALL SELECT realm, parent_key, -1, CASE WHEN attr_names ? 'userpassword' THEN -1 ELSE 0 END FROM old_rows) AS c
    GROUP BY realm, parent_key HAVING sum(n) <> 0 OR sum(h) <> 0;
  END IF;
  GET DIAGNOSTICS added = ROW_COUNT;
  IF added > 0 AND NOT EXISTS (SELECT 1 FROM sts_ldap_count_deltas WHERE txid = pg_current_xact_id() AND fold) THEN
    INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding, fold) VALUES ('', '', 0, 0, true);
  END IF;
  RETURN NULL;
END $$;

-- The fold adds to this connection's shard (#630), under a name of its own:
-- the driver probes routines by name, so the old body under the old name
-- would never be replaced on a store that has it.
CREATE OR REPLACE FUNCTION sts_ldap_count_fold_sharded() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  WITH folded AS (DELETE FROM sts_ldap_count_deltas WHERE txid = pg_current_xact_id() RETURNING realm, parent_key, n, holding),
  bases AS (SELECT f.realm, b.base_key, sum(f.n) AS n, sum(f.holding) AS holding FROM folded AS f CROSS JOIN LATERAL sts_ldap_count_bases(f.parent_key) AS b(base_key) WHERE f.n <> 0 OR f.holding <> 0 GROUP BY f.realm, b.base_key)
  INSERT INTO sts_ldap_counts AS c (realm, base_key, attribute, shard, n)
  SELECT realm, base_key, attribute, (pg_backend_pid() % 16)::smallint, n FROM (SELECT realm, base_key, '' AS attribute, n FROM bases WHERE n <> 0
    UNION ALL SELECT realm, base_key, 'userpassword', holding FROM bases WHERE holding <> 0) AS d
  ORDER BY realm, base_key, attribute
  ON CONFLICT (realm, base_key, attribute, shard) DO UPDATE SET n = c.n + EXCLUDED.n;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION sts_ldap_count_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM sts_ldap_counts;
  DELETE FROM sts_ldap_count_deltas;
  RETURN NULL;
END $$;

CREATE OR REPLACE TRIGGER sts_ldap_entries_count_insert AFTER INSERT ON sts_ldap_entries REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_note();
CREATE OR REPLACE TRIGGER sts_ldap_entries_count_update AFTER UPDATE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_note();
CREATE OR REPLACE TRIGGER sts_ldap_entries_count_delete AFTER DELETE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_note();
CREATE OR REPLACE TRIGGER sts_ldap_entries_count_truncate AFTER TRUNCATE ON sts_ldap_entries FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_truncate();
-- A constraint trigger has no OR REPLACE. The unsharded fold (#618) goes
-- first: left beside the new one, the two would race for a transaction's
-- deltas, and the old one's ON CONFLICT names a key the table no longer has.
DROP TRIGGER IF EXISTS sts_ldap_count_deltas_fold ON sts_ldap_count_deltas;
DROP FUNCTION IF EXISTS sts_ldap_count_fold();
DROP TRIGGER IF EXISTS sts_ldap_count_deltas_fold_sharded ON sts_ldap_count_deltas;
CREATE CONSTRAINT TRIGGER sts_ldap_count_deltas_fold_sharded AFTER INSERT ON sts_ldap_count_deltas DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.fold) EXECUTE FUNCTION sts_ldap_count_fold_sharded();

-- AND PER DATA KEY (#623): the same arrangement over `dek_keys`. A value
-- that is not a JSON object, and NULL, is read as no keys.
CREATE OR REPLACE FUNCTION sts_ldap_dek_note() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE added bigint;
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO sts_ldap_dek_deltas (dek_id, n)
    SELECT d.key, sum(d.value::bigint) FROM new_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d GROUP BY d.key;
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO sts_ldap_dek_deltas (dek_id, n)
    SELECT d.key, -sum(d.value::bigint) FROM old_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d GROUP BY d.key;
  ELSE
    INSERT INTO sts_ldap_dek_deltas (dek_id, n)
    SELECT k, sum(n) FROM (SELECT d.key AS k, d.value::bigint AS n FROM new_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d
      UNION ALL SELECT d.key, -d.value::bigint FROM old_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d) AS c
    GROUP BY k HAVING sum(n) <> 0;
  END IF;
  GET DIAGNOSTICS added = ROW_COUNT;
  IF added > 0 AND NOT EXISTS (SELECT 1 FROM sts_ldap_dek_deltas WHERE txid = pg_current_xact_id() AND fold) THEN
    INSERT INTO sts_ldap_dek_deltas (dek_id, n, fold) VALUES ('', 0, true);
  END IF;
  RETURN NULL;
END $$;

-- Sharded and renamed as the count fold is (#630).
CREATE OR REPLACE FUNCTION sts_ldap_dek_fold_sharded() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  WITH folded AS (DELETE FROM sts_ldap_dek_deltas WHERE txid = pg_current_xact_id() RETURNING dek_id, n)
  INSERT INTO sts_ldap_dek_counts AS c (dek_id, shard, n)
  SELECT dek_id, (pg_backend_pid() % 16)::smallint, sum(n) FROM folded
  WHERE dek_id <> '' GROUP BY dek_id
  HAVING sum(n) <> 0 ORDER BY dek_id
  ON CONFLICT (dek_id, shard) DO UPDATE SET n = c.n + EXCLUDED.n;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION sts_ldap_dek_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM sts_ldap_dek_counts;
  DELETE FROM sts_ldap_dek_deltas;
  RETURN NULL;
END $$;

CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_insert AFTER INSERT ON sts_ldap_entries REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_note();
CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_update AFTER UPDATE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_note();
CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_delete AFTER DELETE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_note();
CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_truncate AFTER TRUNCATE ON sts_ldap_entries FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_truncate();
DROP TRIGGER IF EXISTS sts_ldap_dek_deltas_fold ON sts_ldap_dek_deltas;
DROP FUNCTION IF EXISTS sts_ldap_dek_fold();
DROP TRIGGER IF EXISTS sts_ldap_dek_deltas_fold_sharded ON sts_ldap_dek_deltas;
CREATE CONSTRAINT TRIGGER sts_ldap_dek_deltas_fold_sharded AFTER INSERT ON sts_ldap_dek_deltas DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.fold) EXECUTE FUNCTION sts_ldap_dek_fold_sharded();

-- THE ONE COUNT OF THE DIRECTORY: the counters started from the rows already
-- there, under the lock above, and only when they hold nothing — running this
-- file again adds nothing. Linear in the rows, once.
INSERT INTO sts_ldap_counts (realm, base_key, attribute, n)
SELECT e.realm, b.base_key, a.attribute, count(*)
FROM sts_ldap_entries AS e
CROSS JOIN LATERAL sts_ldap_count_bases(e.parent_key) AS b(base_key)
CROSS JOIN LATERAL (SELECT '' AS attribute UNION ALL SELECT 'userpassword' WHERE e.attr_names ? 'userpassword') AS a
WHERE NOT EXISTS (SELECT 1 FROM sts_ldap_counts)
GROUP BY e.realm, b.base_key, a.attribute;

-- And the per-data-key counters (#623), on the same condition, from the
-- entries whose keys are known; on the run that adds `dek_keys` that is
-- none, and the rest join as the service indexes them.
INSERT INTO sts_ldap_dek_counts (dek_id, n)
SELECT d.key, sum(d.value::bigint) FROM sts_ldap_entries AS e
CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(e.dek_keys) = 'object' THEN e.dek_keys END) AS d
WHERE NOT EXISTS (SELECT 1 FROM sts_ldap_dek_counts)
GROUP BY d.key;

CREATE TABLE IF NOT EXISTS sts_realms (
  id          text PRIMARY KEY,
  name        text,
  description text,
  created_at  bigint,
  overrides   jsonb NOT NULL DEFAULT '{}'::jsonb,
  domain      text,
  retiring_at bigint);

-- A realm's DNS domain (2026-09-18, schema version 6). Added separately as
-- well, because `CREATE TABLE IF NOT EXISTS` leaves a table built by an older
-- version of this file without it; running this file again adds it.
ALTER TABLE sts_realms ADD COLUMN IF NOT EXISTS domain text;

-- When the realm's removal began (2026-09-26, schema version 10, #262), or
-- NULL: every process refuses new sign-ins and issuance in a realm that has
-- one. Added separately for the domain's reason.
ALTER TABLE sts_realms ADD COLUMN IF NOT EXISTS retiring_at bigint;

CREATE TABLE IF NOT EXISTS sts_appconfig (
  key   text PRIMARY KEY,
  value jsonb NOT NULL);

CREATE TABLE IF NOT EXISTS sts_keys (
  realm      text PRIMARY KEY,
  material   text NOT NULL,
  written_at timestamptz NOT NULL DEFAULT now());

-- ---------------------------------------------------------------------------
-- WHAT THE PROCESS MINTED (2026-09-06). ONE TABLE FOR ALL OF IT: sessions,
-- access, ID and refresh tokens, authorization codes, pre-authorized codes,
-- SAML artifacts, Kerberos principals and tickets, the replay caches, the
-- counters and the audit log.
--
-- `handle` NAMES THE STORE and comes from the store's own declaration in the
-- service (`realms.map({ persist: 'authn.sessions' })`). One table rather than
-- a table per family, because a table per family would be a SECOND place that
-- list is written down, and adding a persisted store has to cost one word at
-- its declaration and nothing here.
--
-- `realm` IS THE EMPTY STRING for the stores that deliberately have no realm
-- (`realms.sharedMap()`) — the rate limiter's buckets, the cluster's mirror of
-- LDAP connections — because what they count or mirror belongs to the process
-- rather than to a path with a realm segment in it. (The Kerberos principal
-- database and replay cache were on this list until they became per realm, by
-- 2026-09-15 at the latest — #33.) A column value rather than a NULL, so the
-- primary key needs no COALESCE.
--
-- `body` IS CIPHERTEXT, ALWAYS. Same AES-256-GCM, same self-describing
-- `$aesgcm$1$salt$iv$tag$body` form and the SAME key-encryption key as
-- `sts_keys` above — read from outside the database entirely, so a dump of
-- this table is not a set of live sessions and usable authorization codes. A
-- session id is a cookie value; an authorization code is redeemable. Nothing
-- here is queryable by SQL and that is the trade, taken deliberately: what
-- wants querying is `sts_ldap_entries`, which is JSONB and is not sealed.
--
-- `expires_at` IS THE RECORD'S OWN EXPIRY (2026-09-28, schema version 12,
-- #333), in epoch milliseconds, as the store's `expiresAt` hook answered it
-- when the row was written; NULL for a record that does not expire and for a
-- tombstone. A start reads no row whose instant has passed, and the
-- `persistence.minted-expiry-purge` job deletes them in batches.
--
-- `written_at` IS WHAT RETENTION READS — `persistence.mintedRetention`, seven
-- days by default — for a short-lived store's row that has NO expiry. A row
-- older than that is neither restored nor kept.
--
-- `key` IS A KEYED DIGEST OF THE RECORD'S NAME and `key_sealed` THE NAME,
-- SEALED (#222, schema version 14). The name is often the credential itself —
-- a session id, a SAML artifact — and was stored in the clear; now the row is
-- found by the digest, which the service computes from a name it already
-- holds, and the name is opened only by the restore. A row written without
-- one (a test, a store with no key) has `key_sealed` '' and its `key` is the
-- name, as before.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sts_minted (
  handle     text        NOT NULL,
  realm      text        NOT NULL,
  key        text        NOT NULL,
  body       text        NOT NULL,
  written_at timestamptz NOT NULL DEFAULT now(),
  expires_at bigint,
  key_sealed text        NOT NULL DEFAULT '',
  PRIMARY KEY (handle, realm, key));

-- Added separately as well, for `sts_realms.domain`'s reason: a table built by
-- an older version of this file has no such column. Existing rows get NULL.
ALTER TABLE sts_minted ADD COLUMN IF NOT EXISTS expires_at bigint;
ALTER TABLE sts_minted ADD COLUMN IF NOT EXISTS key_sealed text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm);
-- `written_at` for the sweeps as a BRIN (#630, schema version 19), where it
-- was the btree `sts_minted_written`: every upsert sets `written_at`, so the
-- btree made every update of this table a non-HOT one. A BRIN summarizes
-- and leaves HOT alone (PostgreSQL 16 and later); the driver argues the
-- cost to the sweeps. And room on each page for a row's next version.
CREATE INDEX IF NOT EXISTS sts_minted_written_brin ON sts_minted USING brin (written_at) WITH (autosummarize = on);
DROP INDEX IF EXISTS sts_minted_written;
ALTER TABLE sts_minted SET (fillfactor=80);
-- Partial: the purge looks rows up by it only where there is an expiry, and
-- every INSERT into this, the busiest table, pays for an index.
CREATE INDEX IF NOT EXISTS sts_minted_expires ON sts_minted (expires_at) WHERE expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- THE SESSION INDEX (schema version 21, #350). Columns of a live
-- `authn.sessions` row, written in the same transaction as the sealed body.
-- Not columns of `sts_minted`: `expires_at` there stays NULL for a session,
-- so the generic expiry purge cannot end one. `key` is the same digest
-- `sts_minted.key` already uses. A null digest writes no row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sts_sessions (
  realm                text    NOT NULL,
  key                  text    NOT NULL,
  expires_at           bigint,
  last_seen_at         bigint  NOT NULL,
  started_at           bigint  NOT NULL,
  subject_key          text    NOT NULL DEFAULT '',
  username_key         text    NOT NULL DEFAULT '',
  chosen               boolean NOT NULL,
  authenticated        boolean NOT NULL,
  kind                 text    NOT NULL,
  rp_surface           text    NOT NULL DEFAULT '',
  parent_key           text    NOT NULL DEFAULT '',
  backs_console        boolean NOT NULL DEFAULT false,
  credential_key       text    NOT NULL DEFAULT '',
  partner_relationship text    NOT NULL DEFAULT '',
  PRIMARY KEY (realm, key));

CREATE INDEX IF NOT EXISTS sts_sessions_subject ON sts_sessions (realm, subject_key, last_seen_at) WHERE chosen AND subject_key <> '';
CREATE INDEX IF NOT EXISTS sts_sessions_username ON sts_sessions (realm, username_key) WHERE username_key <> '';
CREATE INDEX IF NOT EXISTS sts_sessions_expires ON sts_sessions (realm, expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS sts_sessions_parent ON sts_sessions (realm, parent_key) WHERE parent_key <> '';
CREATE INDEX IF NOT EXISTS sts_sessions_credential ON sts_sessions (realm, credential_key) WHERE credential_key <> '';
CREATE INDEX IF NOT EXISTS sts_sessions_partner ON sts_sessions (realm, partner_relationship) WHERE partner_relationship <> '';
-- Schema version 22 (#754): a hosted surface's relying-party sessions.
CREATE INDEX IF NOT EXISTS sts_sessions_surface ON sts_sessions (realm, rp_surface) WHERE rp_surface <> '';

-- Schema version 24 (#820): an on-demand minted store's index. A store
-- declared `onDemand` with `indexBy` is not held whole by a process, so what
-- it was walked for — a refresh token family's members, a person's tokens —
-- is filed here, the keyed digest of the index value beside the row's key,
-- written in the same transaction as the body.
CREATE TABLE IF NOT EXISTS sts_minted_index (
  handle    text NOT NULL,
  realm     text NOT NULL,
  index_key text NOT NULL,
  key       text NOT NULL,
  sort_at   bigint,
  PRIMARY KEY (handle, realm, index_key, key));
CREATE INDEX IF NOT EXISTS sts_minted_index_key ON sts_minted_index (handle, realm, key);
-- Schema version 25 (#820, 2026-10-22): a store's `sortBy` value on one
-- more index row per stored row, and the partial index `minted.newest`
-- walks instead of sorting the store by `written_at`. `sts_minted_index`
-- is insert and delete only, so this index costs no HOT update; a btree on
-- `sts_minted.written_at` would (#630). Nullable with no default, so the
-- ALTER rewrites nothing. On a large table, build the index CONCURRENTLY
-- by hand first (outside a transaction); this statement then finds it.
ALTER TABLE sts_minted_index ADD COLUMN IF NOT EXISTS sort_at bigint;
CREATE INDEX IF NOT EXISTS sts_minted_index_sort ON sts_minted_index (handle, realm, sort_at DESC, key DESC) WHERE sort_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- THE CHANGE LOG (2026-09-06), which is what makes several processes against
-- one store AGREE rather than merely coexist. Until this, two processes each
-- held their own copy in memory and neither saw the other's writes.
--
-- `seq` IS A bigserial AND EVERYTHING RESTS ON IT: assigned by the database,
-- only ever rising, and a process that has applied up to N asks for N+1
-- onwards. That is the whole synchronisation primitive — no timestamps (two
-- clocks), no per-row version columns (a merge rule per table), no advisory
-- locks (a process that dies holding one).
--
-- `origin` is who wrote the row, so a process can skip its own instead of
-- applying its own work back over itself.
--
-- `kind`, `realm` and `key` are a POINTER and never data: the row that changed
-- is re-read from its own table. That is why this table needs no encryption
-- while `sts_minted` does, and why the LISTEN/NOTIFY nudge beside it is
-- allowed to be lossy — losing a notification costs latency, and the log is
-- what costs correctness.
--
-- **IT IS WRITTEN INSIDE THE TRANSACTION THAT MADE THE CHANGE.** There is no
-- window in which the data is committed and the log entry is not, which is the
-- one property that makes "I have applied up to N" mean "I have seen
-- everything committed before N".
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sts_changes (
  seq    bigserial PRIMARY KEY,
  origin text        NOT NULL,
  kind   text        NOT NULL,
  realm  text        NOT NULL DEFAULT '',
  key    text        NOT NULL DEFAULT '',
  at     timestamptz NOT NULL DEFAULT now());

CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at);

-- AUTOVACUUM FOR THE CHANGE LOG (#630, schema version 19): the trim deletes
-- its tail all the time, and the defaults let dead rows reach a fifth of the
-- table and then vacuumed at the default cost limit, mostly asleep.
ALTER TABLE sts_changes SET (autovacuum_vacuum_scale_factor=0.02, autovacuum_vacuum_cost_limit=2000);

-- ---------------------------------------------------------------------------
-- THE USED-ASSERTION HISTORY (2026-09-13): every RFC 7523 JWT and RFC 7522
-- SAML assertion this service accepted, kept until it would have expired, so
-- that none is accepted twice. It persists in both modes, unlike `sts_minted`,
-- because the key that verifies an assertion is the CLIENT's and outlives a
-- restart in every store.
--
-- A TABLE OF ITS OWN BECAUSE RECORDING A USE IS AN ATOMIC CLAIM: `(realm, key)`
-- is the primary key and the service inserts with ON CONFLICT, so two processes
-- against this database cannot both accept one assertion. A journalled row in
-- `sts_minted` would reach another process only after the change log had been
-- pulled.
--
-- NOT SEALED, AND NOTHING IN IT IS A CREDENTIAL: `key` is a SHA-256 of the
-- format, issuer and identifier, and the assertion itself is never stored.
-- Times are milliseconds. A database built by an EARLIER copy of this file has
-- no such table; running this file again as the owner adds it and changes
-- nothing else.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sts_used_assertions (
  realm       text   NOT NULL,
  key         text   NOT NULL,
  format      text   NOT NULL,
  used_as     text   NOT NULL,
  issuer      text   NOT NULL,
  identifier  text   NOT NULL,
  client_id   text   NOT NULL DEFAULT '',
  subject     text   NOT NULL DEFAULT '',
  state       text   NOT NULL,
  reservation text   NOT NULL,
  origin      text   NOT NULL DEFAULT '',
  used_at     bigint NOT NULL,
  spent_at    bigint NOT NULL DEFAULT 0,
  expires_at  bigint NOT NULL,
  PRIMARY KEY (realm, key));

CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON sts_used_assertions (realm, expires_at);

-- THE CLUSTER (2026-09-14, #46): several containers against this one store.
-- Membership with a heartbeat, named leases with a fencing token, atomic
-- claims, and the secrets every node must agree on (sealed before they arrive).
-- Every time is the DATABASE's clock in milliseconds. `cluster/CLAUDE.md`
-- argues all four; `persistence_postgres.js` holds the statements.
CREATE TABLE IF NOT EXISTS sts_cluster_nodes (
  node_id      text   PRIMARY KEY,
  name         text   NOT NULL DEFAULT '',
  mode         text   NOT NULL,
  version      text   NOT NULL DEFAULT '',
  fingerprint  text   NOT NULL DEFAULT '',
  started_at   bigint NOT NULL,
  heartbeat_at bigint NOT NULL,
  expires_at   bigint NOT NULL,
  left_at      bigint NOT NULL DEFAULT 0,
  info         jsonb  NOT NULL DEFAULT '{}'::jsonb);

CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON sts_cluster_nodes (expires_at);

CREATE TABLE IF NOT EXISTS sts_cluster_leases (
  name        text   PRIMARY KEY,
  holder      text   NOT NULL,
  token       bigint NOT NULL,
  acquired_at bigint NOT NULL,
  expires_at  bigint NOT NULL);

CREATE TABLE IF NOT EXISTS sts_cluster_claims (
  scope       text   NOT NULL,
  realm       text   NOT NULL,
  key         text   NOT NULL,
  reservation text   NOT NULL,
  origin      text   NOT NULL DEFAULT '',
  claimed_at  bigint NOT NULL,
  expires_at  bigint NOT NULL,
  PRIMARY KEY (scope, realm, key));

CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON sts_cluster_claims (expires_at);

CREATE TABLE IF NOT EXISTS sts_cluster_secrets (
  name       text   PRIMARY KEY,
  material   text   NOT NULL,
  created_by text   NOT NULL DEFAULT '',
  created_at bigint NOT NULL);

-- A VALUE THAT ONLY GOES UP (#46 section 2): a WebAuthn signature counter and
-- the last RFC 6238 step spent, advanced by one conditional upsert so a lower
-- value never overwrites a higher one. `cluster/cluster_counters.js` argues it.
CREATE TABLE IF NOT EXISTS sts_cluster_counters (
  scope      text   NOT NULL,
  realm      text   NOT NULL,
  key        text   NOT NULL,
  value      bigint NOT NULL,
  origin     text   NOT NULL DEFAULT '',
  updated_at bigint NOT NULL,
  PRIMARY KEY (scope, realm, key));

-- A COUNT INSIDE A FIXED WINDOW (#46 section 2): the rate limiter's buckets,
-- counted by every node against one budget with one conditional upsert, so
-- two nodes counting at once never overwrite each other's count.
-- `cluster/cluster_counters.js` argues it.
CREATE TABLE IF NOT EXISTS sts_cluster_windows (
  scope          text   NOT NULL,
  realm          text   NOT NULL,
  key            text   NOT NULL,
  count          bigint NOT NULL,
  window_ends_at bigint NOT NULL,
  origin         text   NOT NULL DEFAULT '',
  PRIMARY KEY (scope, realm, key));

CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON sts_cluster_windows (window_ends_at);

-- A BUDGET SPENT AGAINST A LIMIT (#432 phase 5, schema version 15): the
-- running totals of a GNAP right's limits, spent by every node with one
-- conditional upsert so two spends at once cannot both pass a limit.
-- `amount` is millionths; a row is purged once its grant has ended.
-- `cluster/cluster_counters.js` argues it.
CREATE TABLE IF NOT EXISTS sts_cluster_budgets (
  scope      text   NOT NULL,
  realm      text   NOT NULL,
  key        text   NOT NULL,
  period     bigint NOT NULL,
  amount     bigint NOT NULL,
  count      bigint NOT NULL,
  origin     text   NOT NULL DEFAULT '',
  expires_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (scope, realm, key));

CREATE INDEX IF NOT EXISTS sts_cluster_budgets_expiry ON sts_cluster_budgets (expires_at);

-- WHAT EACH NODE LAST SAID ABOUT ITSELF (#332, schema version 11): its own
-- Monitoring → Worker Pools and → Node Health views, written every fifteen
-- seconds by its front process and read by whichever node draws those pages.
-- One row per node NAME, overwritten, so it never grows with time.
-- `cluster/node_snapshots.ts` argues it.
CREATE TABLE IF NOT EXISTS sts_node_snapshots (
  name     text   PRIMARY KEY,
  node_id  text   NOT NULL DEFAULT '',
  taken_at bigint NOT NULL,
  body     jsonb  NOT NULL DEFAULT '{}'::jsonb);

-- WHERE EVERY PROCESS READING THE CHANGE LOG HAS GOT TO (#46 section 8): the
-- low-water mark each coordinating process reports, which `sts_changes` is
-- trimmed below. `persistence/persistence_replication.js` argues the bound.
CREATE TABLE IF NOT EXISTS sts_change_readers (
  origin      text   PRIMARY KEY,
  node_id     text   NOT NULL DEFAULT '',
  applied     bigint NOT NULL,
  started_at  bigint NOT NULL,
  reported_at bigint NOT NULL);

-- RISK SCORING (#62, 2026-09-22, schema version 7): the external datasets a
-- score reads, by version, and the history the model keeps. A database built
-- by an earlier copy of this file has none of them; running this file again
-- as the owner adds them and changes nothing else.
-- `persistence/persistence_postgres.js` and `risk/CLAUDE.md` argue them.
CREATE TABLE IF NOT EXISTS sts_risk_datasets (
  realm            text   NOT NULL DEFAULT '',
  dataset          text   NOT NULL,
  kind             text   NOT NULL,
  active_version   text   NOT NULL DEFAULT '',
  previous_version text   NOT NULL DEFAULT '',
  state            text   NOT NULL,
  updated_at       bigint NOT NULL,
  PRIMARY KEY (realm, dataset));

CREATE TABLE IF NOT EXISTS sts_risk_dataset_versions (
  realm           text   NOT NULL DEFAULT '',
  dataset         text   NOT NULL,
  version         text   NOT NULL,
  format          text   NOT NULL,
  provider        text   NOT NULL,
  licence         text   NOT NULL,
  attribution     text   NOT NULL DEFAULT '',
  source          text   NOT NULL,
  source_uri      text   NOT NULL DEFAULT '',
  sha256          text   NOT NULL,
  byte_count      bigint NOT NULL,
  row_count       bigint NOT NULL DEFAULT 0,
  parameters      jsonb  NOT NULL DEFAULT '{}'::jsonb,
  verification    text   NOT NULL,
  published_at    bigint NOT NULL,
  next_update_at  bigint NOT NULL DEFAULT 0,
  fetched_at      bigint NOT NULL,
  loaded_at       bigint NOT NULL DEFAULT 0,
  activated_at    bigint NOT NULL DEFAULT 0,
  superseded_at   bigint NOT NULL DEFAULT 0,
  rows_deleted_at bigint NOT NULL DEFAULT 0,
  state           text   NOT NULL,
  refusal         text   NOT NULL DEFAULT '',
  error_code      text   NOT NULL DEFAULT '',
  origin          text   NOT NULL DEFAULT '',
  PRIMARY KEY (realm, dataset, version));

CREATE TABLE IF NOT EXISTS sts_risk_dataset_blobs (
  realm   text    NOT NULL DEFAULT '',
  dataset text    NOT NULL,
  version text    NOT NULL,
  part    integer NOT NULL,
  content bytea   NOT NULL,
  PRIMARY KEY (realm, dataset, version, part));

CREATE TABLE IF NOT EXISTS sts_risk_geo_locations (
  dataset     text   NOT NULL,
  version     text   NOT NULL,
  location_id bigint NOT NULL,
  continent   text   NOT NULL DEFAULT '',
  country     text   NOT NULL DEFAULT '',
  subdivision text   NOT NULL DEFAULT '',
  city        text   NOT NULL DEFAULT '',
  time_zone   text   NOT NULL DEFAULT '',
  PRIMARY KEY (dataset, version, location_id));

CREATE TABLE IF NOT EXISTS sts_risk_geo_ranges (
  dataset            text             NOT NULL,
  version            text             NOT NULL,
  range_start        inet             NOT NULL,
  range_end          inet             NOT NULL,
  location_id        bigint           NOT NULL DEFAULT 0,
  continent          text             NOT NULL DEFAULT '',
  country            text             NOT NULL DEFAULT '',
  subdivision        text             NOT NULL DEFAULT '',
  city               text             NOT NULL DEFAULT '',
  registered_country text             NOT NULL DEFAULT '',
  latitude           double precision,
  longitude          double precision,
  accuracy_km        integer          NOT NULL DEFAULT 0,
  anonymous_proxy    boolean          NOT NULL DEFAULT false,
  satellite          boolean          NOT NULL DEFAULT false,
  PRIMARY KEY (dataset, version, range_start));

CREATE TABLE IF NOT EXISTS sts_risk_asn_ranges (
  dataset     text   NOT NULL,
  version     text   NOT NULL,
  range_start inet   NOT NULL,
  range_end   inet   NOT NULL,
  asn         bigint NOT NULL,
  as_org      text   NOT NULL DEFAULT '',
  as_domain   text   NOT NULL DEFAULT '',
  PRIMARY KEY (dataset, version, range_start));

CREATE TABLE IF NOT EXISTS sts_risk_ip_lists (
  realm       text NOT NULL DEFAULT '',
  dataset     text NOT NULL,
  version     text NOT NULL,
  range_start inet NOT NULL,
  range_end   inet NOT NULL,
  category    text NOT NULL,
  note        text NOT NULL DEFAULT '',
  PRIMARY KEY (realm, dataset, version, range_start));

CREATE TABLE IF NOT EXISTS sts_risk_fido_authenticators (
  dataset             text    NOT NULL,
  version             text    NOT NULL,
  key_kind            text    NOT NULL,
  authenticator_key   text    NOT NULL,
  description         text    NOT NULL DEFAULT '',
  protocol_family     text    NOT NULL DEFAULT '',
  certification_level text    NOT NULL DEFAULT '',
  latest_status       text    NOT NULL DEFAULT '',
  latest_status_at    bigint  NOT NULL DEFAULT 0,
  compromised         boolean NOT NULL DEFAULT false,
  status_reports      jsonb   NOT NULL DEFAULT '[]'::jsonb,
  metadata_statement  jsonb   NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (dataset, version, key_kind, authenticator_key));

CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON sts_risk_fido_authenticators (key_kind, authenticator_key);

CREATE TABLE IF NOT EXISTS sts_risk_assessments (
  realm              text    NOT NULL,
  id                 text    NOT NULL,
  at                 bigint  NOT NULL,
  phase              text    NOT NULL,
  door               text    NOT NULL,
  subject            text    NOT NULL DEFAULT '',
  session_id         text    NOT NULL DEFAULT '',
  client_id          text    NOT NULL DEFAULT '',
  address_sealed     text    NOT NULL,
  address_prefix     cidr    NOT NULL,
  asn                bigint  NOT NULL DEFAULT 0,
  as_org             text    NOT NULL DEFAULT '',
  country            text    NOT NULL DEFAULT '',
  subdivision        text    NOT NULL DEFAULT '',
  city               text    NOT NULL DEFAULT '',
  latitude           double precision,
  longitude          double precision,
  accuracy_km        integer NOT NULL DEFAULT 0,
  ip_lists           text[]  NOT NULL DEFAULT '{}',
  ua_hash            text    NOT NULL DEFAULT '',
  ua_family          text    NOT NULL DEFAULT '',
  ua_os              text    NOT NULL DEFAULT '',
  ua_platform        text    NOT NULL DEFAULT '',
  bot                boolean NOT NULL DEFAULT false,
  ja4                text    NOT NULL DEFAULT '',
  credential_kind    text    NOT NULL DEFAULT '',
  credential_hash    text    NOT NULL DEFAULT '',
  aaguid             text    NOT NULL DEFAULT '',
  authenticator_cert text    NOT NULL DEFAULT '',
  backup_eligible    boolean,
  backup_state       boolean,
  jkt                text    NOT NULL DEFAULT '',
  cert_fingerprint   text    NOT NULL DEFAULT '',
  datasets           jsonb   NOT NULL DEFAULT '{}'::jsonb,
  signals            jsonb   NOT NULL DEFAULT '[]'::jsonb,
  score              real    NOT NULL,
  level              text    NOT NULL,
  decision           text    NOT NULL,
  policy_id          text    NOT NULL DEFAULT '',
  error_code         text    NOT NULL DEFAULT '',
  origin             text    NOT NULL DEFAULT '',
  feedback           text    NOT NULL DEFAULT '',
  feedback_at        bigint  NOT NULL DEFAULT 0,
  PRIMARY KEY (realm, id));

-- What the PERSON said about a sign-in (#62 P6, schema version 9): "this was
-- me" (confirmed) or "this wasn't me" (denied), from /portal/sign-ins. Added
-- separately as well, for sts_realms.domain's reason.
ALTER TABLE sts_risk_assessments ADD COLUMN IF NOT EXISTS feedback text NOT NULL DEFAULT '';
ALTER TABLE sts_risk_assessments ADD COLUMN IF NOT EXISTS feedback_at bigint NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON sts_risk_assessments (realm, subject, at);

CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON sts_risk_assessments (realm, session_id);

CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON sts_risk_assessments (at);

CREATE TABLE IF NOT EXISTS sts_risk_feature_counts (
  realm    text   NOT NULL,
  subject  text   NOT NULL,
  feature  text   NOT NULL,
  value    text   NOT NULL,
  count    bigint NOT NULL,
  first_at bigint NOT NULL,
  last_at  bigint NOT NULL,
  PRIMARY KEY (realm, subject, feature, value));

CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON sts_risk_feature_counts (realm, last_at);

CREATE TABLE IF NOT EXISTS sts_risk_failures (
  realm          text      NOT NULL,
  id             bigserial NOT NULL,
  at             bigint    NOT NULL,
  door           text      NOT NULL,
  subject        text      NOT NULL DEFAULT '',
  name_hmac      text      NOT NULL DEFAULT '',
  address_sealed text      NOT NULL,
  address_prefix cidr      NOT NULL,
  asn            bigint    NOT NULL DEFAULT 0,
  error_code     text      NOT NULL,
  origin         text      NOT NULL DEFAULT '',
  PRIMARY KEY (realm, id));

CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON sts_risk_failures (realm, subject, at);

CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON sts_risk_failures (realm, name_hmac, at);

CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON sts_risk_failures (realm, address_prefix, at);

CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON sts_risk_failures (at);

CREATE TABLE IF NOT EXISTS sts_risk_session_context (
  realm          text   NOT NULL,
  session_id     text   NOT NULL,
  subject        text   NOT NULL,
  address_prefix cidr   NOT NULL,
  asn            bigint NOT NULL DEFAULT 0,
  country        text   NOT NULL DEFAULT '',
  ua_hash        text   NOT NULL DEFAULT '',
  ja4            text   NOT NULL DEFAULT '',
  jkt            text   NOT NULL DEFAULT '',
  score          real   NOT NULL,
  level          text   NOT NULL,
  updated_at     bigint NOT NULL,
  PRIMARY KEY (realm, session_id));

CREATE TABLE IF NOT EXISTS sts_risk_subjects (
  realm           text  NOT NULL,
  subject         text  NOT NULL,
  score           real  NOT NULL,
  level           text  NOT NULL,
  previous_level  text  NOT NULL DEFAULT '',
  reason          text  NOT NULL DEFAULT '',
  last_assessment text  NOT NULL DEFAULT '',
  crossed_at      bigint NOT NULL DEFAULT 0,
  actions         jsonb NOT NULL DEFAULT '{}'::jsonb,
  feedback        text  NOT NULL DEFAULT '',
  updated_at      bigint NOT NULL,
  PRIMARY KEY (realm, subject));

-- WHO ACCEPTED WHICH DATASET PROVIDER'S TERMS (#62, schema version 8,
-- 2026-09-23): the audit trail the second licence review asked for. An import
-- of a provider's data is refused without a row for its current terms.
CREATE TABLE IF NOT EXISTS sts_risk_terms_acceptances (
  id            bigserial NOT NULL,
  provider      text      NOT NULL,
  terms_digest  text      NOT NULL,
  terms_text    text      NOT NULL,
  accepted_by   text      NOT NULL,
  accepted_via  text      NOT NULL,
  deployment    text      NOT NULL DEFAULT '',
  page_digest   text      NOT NULL DEFAULT '',
  accepted_at   bigint    NOT NULL,
  origin        text      NOT NULL DEFAULT '',
  PRIMARY KEY (id));

CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON sts_risk_terms_acceptances (provider, accepted_at);

-- WHERE EACH PERSON IS HOMED (#98, schema version 11, 2026-09-28): the
-- routing index of a service deployed as cells, in the global tier. Keyed
-- digests of a login name or an entryUUID and the cell that holds the person;
-- no name and no identifier in the clear. The primary key is what keeps a
-- login name unique in a realm across cells.
CREATE TABLE IF NOT EXISTS sts_cell_routing (
  realm      text   NOT NULL,
  kind       text   NOT NULL,
  digest     text   NOT NULL,
  cell       text   NOT NULL,
  written_at bigint NOT NULL,
  PRIMARY KEY (realm, kind, digest));

CREATE TABLE IF NOT EXISTS sts_schema (
  version int PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now());

-- WHAT VERSION OF THE ABOVE THIS IS. The driver writes the same row on open()
-- and `tests/postgres_schema.js` checks that this number is its SCHEMA_VERSION,
-- so the two cannot disagree about which schema is on disk.
INSERT INTO sts_schema (version) VALUES (25) ON CONFLICT (version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- THE APPLICATION ROLE: READ AND WRITE THE ROWS, AND NOTHING ELSE.
--
-- CREATE if it is not there, ALTER if it is — `CREATE ROLE IF NOT EXISTS` does
-- not exist, and a `DO` block cannot be used because psql does not substitute
-- variables inside a dollar-quoted string. `\gexec` runs what the query
-- returns, and `format()`'s %I and %L are what quote the name and the
-- password, so neither can carry a quote out of the parameter and into the
-- statement.
--
-- THE PASSWORD IS SET ON EVERY RUN, deliberately: rotating it is running this
-- file again with a new `-v sts_app_password=`.
-- ---------------------------------------------------------------------------
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L',
              :'sts_app_role', :'sts_app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'sts_app_role')
\gexec

SELECT format('ALTER ROLE %I LOGIN PASSWORD %L',
              :'sts_app_role', :'sts_app_password')
\gexec

-- **NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS SAID OUT
-- LOUD.** They are the defaults for a role created above, and they are stated
-- anyway because this file is also run against a role that already exists —
-- one an operator made by hand, or one an earlier run of a different script
-- made — and inheriting whatever that role happened to have would make the
-- sentence at the top of this section false without anything failing.
--
-- **BUT ONLY A SUPERUSER MAY SAY THREE OF THEM, EVEN TO SAY NO (2026-09-15).**
-- PostgreSQL 16 and later refuse `NOSUPERUSER`, `NOREPLICATION` and
-- `NOBYPASSRLS` from a role that is not a superuser — "Only roles with the
-- SUPERUSER attribute may change the SUPERUSER attribute" — and a managed
-- database's master user is not one: this file stopped at this statement on
-- RDS (issue #51), rolling the whole schema back. So a superuser (the compose
-- stack's database) still sets all five, and anybody else sets the two it may
-- and then CHECKS the other three rather than skipping them: an existing role
-- holding any of them fails the run, because a non-superuser cannot take them
-- away and the sentence at the top of this section would otherwise be false.
SELECT format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE ' ||
              'NOREPLICATION NOBYPASSRLS', :'sts_app_role')
WHERE (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
\gexec

SELECT format('ALTER ROLE %I NOCREATEDB NOCREATEROLE', :'sts_app_role')
WHERE NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
\gexec

SELECT format('DO $check$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles ' ||
              'WHERE rolname = %L AND (rolsuper OR rolreplication OR ' ||
              'rolbypassrls)) THEN RAISE EXCEPTION ''sts-schema: the ' ||
              'application role holds SUPERUSER, REPLICATION or BYPASSRLS, ' ||
              'which only a superuser can remove''; END IF; END $check$',
              :'sts_app_role')
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I',
              current_database(), :'sts_app_role')
\gexec

-- USAGE lets it NAME things in the schema. It is not CREATE and that is the
-- whole point of this file.
GRANT USAGE ON SCHEMA :"sts_schema" TO :"sts_app_role";

-- THE FOUR VERBS THE DRIVER USES, AND NOT ONE MORE. `GRANT ALL` here would
-- also hand over TRUNCATE, REFERENCES and TRIGGER — TRUNCATE empties a table
-- with no WHERE clause to get wrong and no row-by-row audit of what went, and
-- the other two change the shape of the schema from the side.
GRANT SELECT, INSERT, UPDATE, DELETE
  ON ALL TABLES IN SCHEMA :"sts_schema" TO :"sts_app_role";

-- AND NOW THERE IS A SEQUENCE: `sts_changes.seq` is a `bigserial`, which is
-- the first one this schema has ever had. This grant used to be here for the
-- version of the schema that would need it, with a note that a `serial` column
-- added later fails at INSERT with "permission denied for sequence" — an error
-- that names an object nobody wrote down. That version is this one, and the
-- grant was already in place for it.
GRANT USAGE, SELECT
  ON ALL SEQUENCES IN SCHEMA :"sts_schema" TO :"sts_app_role";

-- AND FOR THE TABLES A LATER VERSION OF THIS FILE ADDS. Without this, the two
-- GRANTs above have to be re-run after every schema change, and the failure
-- for forgetting is a service that starts, restores five of its six tables
-- and reports a permission error on the sixth.
ALTER DEFAULT PRIVILEGES IN SCHEMA :"sts_schema"
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"sts_app_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA :"sts_schema"
  GRANT USAGE, SELECT ON SEQUENCES TO :"sts_app_role";

-- ---------------------------------------------------------------------------
-- AND NOW THE REVOCATIONS, WHICH ARE THE HALF THAT MAKES THE SENTENCE TRUE.
--
-- Granting USAGE without CREATE is not the same as taking CREATE away: a role
-- can hold it through PUBLIC, which is what `public` grants on servers before
-- PostgreSQL 15 and what a database grants to nobody by default but an
-- operator may have granted since.
--
-- **WHAT IS DELIBERATELY LEFT IS TEMPORARY.** A role that can create a
-- temporary table can create nothing that outlives its own session and can
-- change no object anybody else can see, so revoking it would narrow the claim
-- by nothing and break a future `CREATE TEMP TABLE` in a driver that has every
-- right to use one. **USAGE ON `public` IS LEFT TOO**, and only CREATE is
-- taken: `public` is on the search path, and a role that cannot even NAME what
-- is in it would fail on the day somebody installs an extension there rather
-- than on the day somebody tries to create a table.
-- ---------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA :"sts_schema" FROM PUBLIC;
REVOKE CREATE ON SCHEMA :"sts_schema" FROM :"sts_app_role";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM :"sts_app_role";

SELECT format('REVOKE CREATE ON DATABASE %I FROM PUBLIC', current_database())
\gexec
SELECT format('REVOKE CREATE ON DATABASE %I FROM %I',
              current_database(), :'sts_app_role')
\gexec

COMMIT;

\echo 'sts-schema: done. The application role may read and write the rows and cannot change the schema.'
