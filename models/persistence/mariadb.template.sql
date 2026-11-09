-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: mariadb/schema.sql
--
-- ---------------------------------------------------------------------------
-- THE STORE'S SCHEMA ON MARIADB 11.8, BUILT ONCE BY AN OWNER (#677).
--
-- PostgreSQL is and stays this service's primary store, and
-- `postgres/schema.sql` is its schema. This is the same schema translated for
-- MariaDB, the second engine the suite runs against: the same 41 tables of
-- `postgres/schema.sql`, plus `sts_ldap_entry_keys` (MariaDB has no GIN
-- index, so the directory's JSON lookup columns get a table the engine can
-- index), at the same schema version. `mariadb/CLAUDE.md` says what was
-- translated how, every size limit, and every PostgreSQL feature left out
-- and what replaces it.
--
-- THE SAME SPLIT AS POSTGRESQL'S: an OWNER runs this script, and the
-- APPLICATION account it creates at the bottom reads and writes rows and can
-- do nothing else — no CREATE, no ALTER, no DROP.
--
-- ---------------------------------------------------------------------------
-- RUNNING IT.
--
--   mariadb -u root -p sts < mariadb/schema.sql
--
-- runs it in the database `sts` with the defaults (`sts_app` / `sts_app`,
-- from any host, TLS not required). To name them, set the client variables
-- when the session opens — `--init-command` runs before the script:
--
--   mariadb -u root -p \
--     --init-command="SET @sts_app_user='iya_sts', \
--       @sts_app_password='...', @sts_app_host='%', @sts_app_require_ssl=1" \
--     sts < mariadb/schema.sql
--
-- IT IS IDEMPOTENT. Every object is `IF NOT EXISTS`, and the account's
-- privileges are revoked and granted again, so running it twice changes
-- nothing — except the password, which is set every time so that rotating it
-- is running this file again. MariaDB commits every DDL statement on its own,
-- so unlike PostgreSQL's script this one is NOT one transaction: a run that
-- stops half way is finished by running it again.
--
-- ---------------------------------------------------------------------------
-- IT IS WRITTEN DOWN TWICE. `persistence/schema_mariadb.js` holds every
-- CREATE below as `SCHEMA_OBJECTS`, statement for statement modulo
-- whitespace, for a driver that creates what is missing. EDIT BOTH, IN ONE
-- CHANGE.
-- ---------------------------------------------------------------------------

-- THE SERVICE'S OWN SESSION (`persistence/knex_store.js`, MARIADB_SESSION),
-- so the DDL is checked as strictly as the rows will be — PLUS
-- `NO_BACKSLASH_ESCAPES`, which the service's session leaves out (`mysql2`
-- escapes bound values with a backslash on the client) and this script needs:
-- the password below is quoted by doubling quotes, which is only the whole of
-- quoting when a backslash is an ordinary character. This script is run by
-- the `mariadb` client, which binds nothing.
SET NAMES utf8mb4 COLLATE utf8mb4_nopad_bin;
SET SESSION time_zone = '+00:00';
SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION,PIPES_AS_CONCAT,NO_BACKSLASH_ESCAPES,ERROR_FOR_DIVISION_BY_ZERO';

-- THE FOUR PARAMETERS. A user variable that was never set is NULL, so a value
-- given with `--init-command` wins and a run with none takes the default.
SET @sts_app_user := COALESCE(@sts_app_user, 'sts_app');
SET @sts_app_password := COALESCE(@sts_app_password, 'sts_app');
SET @sts_app_host := COALESCE(@sts_app_host, '%');
SET @sts_app_require_ssl := COALESCE(@sts_app_require_ssl, 0);

-- ---------------------------------------------------------------------------
-- EVERY TABLE IS `utf8mb4_nopad_bin`, NOT `utf8mb4_bin`. Both compare bytes,
-- so 'A' <> 'a' as in PostgreSQL — but `utf8mb4_bin` is a PAD SPACE
-- collation, under which 'uid=a' and 'uid=a ' are one primary key (tried on
-- 11.8: a duplicate-key error), and PostgreSQL holds them as two. The NO PAD
-- collation is the one that compares as PostgreSQL does. (A JSON column is
-- `utf8mb4_bin` whatever the table says: MariaDB fixes it for the type.)
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- THE DIRECTORY.
-- ---------------------------------------------------------------------------

--@table sts_ldap_entries

--@index sts_ldap_entries_realm
--@index sts_ldap_entries_parent
--@index sts_ldap_entries_rdn
-- PostgreSQL's are partial, on the children of `ou=users` only; these are
-- whole (`mariadb/CLAUDE.md`).
--@index sts_ldap_entries_created
--@index sts_ldap_entries_modified

-- WHAT POSTGRESQL'S GIN INDEXES OVER THE JSON LOOKUP COLUMNS ANSWER: one row
-- per (entry, kind, key) — `name_keys`, `mail_keys`, `uuid_keys`,
-- `class_keys`, `value_keys`, `attr_names` and the keys of `dek_keys` — that
-- the driver writes in the entry's own transaction.
--@table sts_ldap_entry_keys

--@index sts_ldap_entry_keys_entry

-- THE COUNTS, KEPT. PostgreSQL maintains these with statement triggers over
-- transition tables; MariaDB has row triggers only, so this script creates
-- NO trigger and NO function and the driver maintains them. `txid` is the
-- per-transaction id the driver generates, where PostgreSQL's is
-- `pg_current_xact_id()`.
--@table sts_ldap_dek_counts

--@table sts_ldap_dek_deltas

--@index sts_ldap_dek_deltas_txid

--@table sts_ldap_counts

--@table sts_ldap_count_deltas

--@index sts_ldap_count_deltas_txid

-- ---------------------------------------------------------------------------
-- REALMS, SETTINGS, KEYS, WHAT WAS MINTED, SESSIONS, THE CHANGE LOG.
-- ---------------------------------------------------------------------------

--@table sts_realms

--@table sts_appconfig

--@table sts_keys

--@table sts_minted

--@index sts_minted_handle
-- PostgreSQL's is the BRIN `sts_minted_written_brin`; this is the B-tree it
-- replaced there, under that B-tree's name.
--@index sts_minted_written
--@index sts_minted_expires

--@table sts_sessions

-- PostgreSQL's seven are partial (`WHERE … <> ''`, `chosen`, `IS NOT NULL`);
-- these are whole.
--@index sts_sessions_subject
--@index sts_sessions_username
--@index sts_sessions_expires
--@index sts_sessions_parent
--@index sts_sessions_credential
--@index sts_sessions_partner
--@index sts_sessions_surface

--@table sts_minted_index

--@index sts_minted_index_key
--@index sts_minted_index_sort

--@table sts_changes

--@index sts_changes_at

--@table sts_used_assertions

--@index sts_used_assertions_expiry

-- ---------------------------------------------------------------------------
-- THE CLUSTER.
-- ---------------------------------------------------------------------------

--@table sts_cluster_nodes

--@index sts_cluster_nodes_expiry

--@table sts_cluster_leases

--@table sts_cluster_claims

--@index sts_cluster_claims_expiry

--@table sts_cluster_secrets

--@table sts_cluster_locks

--@table sts_cluster_counters

--@table sts_cluster_windows

--@index sts_cluster_windows_expiry

--@table sts_cluster_budgets

--@index sts_cluster_budgets_expiry

--@table sts_node_snapshots

--@table sts_change_readers

-- ---------------------------------------------------------------------------
-- RISK SCORING.
-- ---------------------------------------------------------------------------

--@table sts_risk_datasets

--@table sts_risk_dataset_versions

--@table sts_risk_dataset_blobs

--@table sts_risk_geo_locations

--@table sts_risk_geo_ranges

--@table sts_risk_asn_ranges

--@table sts_risk_ip_lists

--@table sts_risk_fido_authenticators

--@index sts_risk_fido_by_key

--@table sts_risk_assessments

--@index sts_risk_assessments_subject
--@index sts_risk_assessments_session
--@index sts_risk_assessments_at

--@table sts_risk_feature_counts

--@index sts_risk_feature_counts_age

-- `id` is PostgreSQL's `bigserial`; InnoDB wants an AUTO_INCREMENT column
-- first in some index, and the primary key starts with `realm`, so the table
-- carries `KEY (id)` as well.
--@table sts_risk_failures

--@index sts_risk_failures_subject
--@index sts_risk_failures_name
--@index sts_risk_failures_prefix
--@index sts_risk_failures_at

--@table sts_risk_session_context

--@table sts_risk_subjects

--@table sts_risk_terms_acceptances

--@index sts_risk_terms_acceptances_provider

-- ---------------------------------------------------------------------------
-- CELLS, REPORTS, AND THE VERSION.
-- ---------------------------------------------------------------------------

--@table sts_cell_routing

--@table sts_report_artifacts

--@table sts_report_artifact_pieces

--@table sts_schema

-- The same number as PostgreSQL's, so there is one SCHEMA_VERSION.
INSERT IGNORE INTO sts_schema (version) VALUES (31);

-- ---------------------------------------------------------------------------
-- THE APPLICATION ACCOUNT: SELECT, INSERT, UPDATE AND DELETE ON THIS
-- DATABASE'S TABLES, AND NOTHING ELSE.
--
-- MariaDB's client has no psql `\gexec`, so each statement is built as text
-- and run with EXECUTE IMMEDIATE. Names and the password are quoted by
-- doubling their quotes, which means the same under NO_BACKSLASH_ESCAPES
-- (set above) whatever the server's default mode is.
--
-- WHAT IT HELD IS REVOKED FIRST — every GLOBAL privilege (`*.*`, where
-- CREATE USER, SUPER and a CREATE on every database live) and everything on
-- THIS database — so a run leaves the account holding the four verbs here
-- and no fifth: the MariaDB form of PostgreSQL's NOSUPERUSER NOCREATEDB
-- NOCREATEROLE and its REVOKE CREATE. The grant before the revokes is there
-- because revoking a database grant the account does not hold is an error,
-- and GRANT OPTION goes before ALL for the same reason: ALL removes the row.
-- Grants on OTHER databases are left alone, as PostgreSQL's script leaves
-- another database's CONNECT alone, so one account may serve two stores.
-- `<db>.*` covers a table created later too, as PostgreSQL's ALTER DEFAULT
-- PRIVILEGES does. An AUTO_INCREMENT needs no grant of its own, where a
-- PostgreSQL sequence does.
--
-- TLS. PostgreSQL's decision is that the database connection is TLS at BOTH
-- ends and cannot be relaxed (`persistence/CLAUDE.md`, *TLS TO THE DATABASE,
-- REQUIRED AT BOTH ENDS*: `hostssl` on the server, `sslmode` refused below
-- `require` in the client). `@sts_app_require_ssl = 1` is the server half
-- here — `REQUIRE SSL` on the account — and is an option rather than the
-- default because a test container may have no certificate. It is never
-- turned OFF by a later run: a run with 0 leaves the account as it was.
-- ---------------------------------------------------------------------------
SET @sts_app_account := CONCAT('''', REPLACE(@sts_app_user, '''', ''''''), '''@''', REPLACE(@sts_app_host, '''', ''''''), '''');
SET @sts_app_database := CONCAT('`', REPLACE(DATABASE(), '`', '``'), '`');

EXECUTE IMMEDIATE CONCAT('CREATE USER IF NOT EXISTS ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('ALTER USER ', @sts_app_account, ' IDENTIFIED BY ''', REPLACE(@sts_app_password, '''', ''''''), '''');
EXECUTE IMMEDIATE CONCAT('REVOKE ALL PRIVILEGES ON *.* FROM ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('REVOKE GRANT OPTION ON *.* FROM ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.* TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('REVOKE GRANT OPTION ON ', @sts_app_database, '.* FROM ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('REVOKE ALL PRIVILEGES ON ', @sts_app_database, '.* FROM ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.* TO ', @sts_app_account);
EXECUTE IMMEDIATE IF(@sts_app_require_ssl = 1, CONCAT('ALTER USER ', @sts_app_account, ' REQUIRE SSL'), 'DO 0');

SELECT CONCAT('sts-schema: done in ', DATABASE(), '. ', @sts_app_account, ' may read and write the rows and cannot change the schema.') AS result;
