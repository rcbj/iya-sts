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
--        -v sts_app_role=mock_sts -v sts_app_password='...' \
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
  PRIMARY KEY (realm, dn_key));

CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm);

CREATE TABLE IF NOT EXISTS sts_realms (
  id          text PRIMARY KEY,
  name        text,
  description text,
  created_at  bigint,
  overrides   jsonb NOT NULL DEFAULT '{}'::jsonb);

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
-- `realm` IS THE EMPTY STRING for the stores that deliberately have no realm —
-- the Kerberos principal database, the replay caches, the rate limiter's
-- buckets — because the sockets they belong to have no path to put a realm
-- segment in. A column value rather than a NULL, so the primary key needs no
-- COALESCE.
--
-- `body` IS CIPHERTEXT, ALWAYS. Same AES-256-GCM, same self-describing
-- `$aesgcm$1$salt$iv$tag$body` form and the SAME key-encryption key as
-- `sts_keys` above — read from outside the database entirely, so a dump of
-- this table is not a set of live sessions and usable authorization codes. A
-- session id is a cookie value; an authorization code is redeemable. Nothing
-- here is queryable by SQL and that is the trade, taken deliberately: what
-- wants querying is `sts_ldap_entries`, which is JSONB and is not sealed.
--
-- `written_at` IS WHAT RETENTION READS — `persistence.mintedRetention`, seven
-- days by default. A row older than that is neither restored nor kept.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sts_minted (
  handle     text        NOT NULL,
  realm      text        NOT NULL,
  key        text        NOT NULL,
  body       text        NOT NULL,
  written_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (handle, realm, key));

CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm);
CREATE INDEX IF NOT EXISTS sts_minted_written ON sts_minted (written_at);

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

CREATE TABLE IF NOT EXISTS sts_schema (
  version int PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now());

-- WHAT VERSION OF THE ABOVE THIS IS. The driver writes the same row on open()
-- and `tests/postgres_schema.js` checks that this number is its SCHEMA_VERSION,
-- so the two cannot disagree about which schema is on disk.
INSERT INTO sts_schema (version) VALUES (4) ON CONFLICT (version) DO NOTHING;

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
SELECT format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE ' ||
              'NOREPLICATION NOBYPASSRLS', :'sts_app_role')
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
