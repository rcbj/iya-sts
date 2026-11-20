-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: mariadb/upgrade-1.0.0.sql
--
-- ---------------------------------------------------------------------------
-- RELEASE 1.0.0 (SCHEMA VERSION 31) TO SCHEMA VERSION 32, ON A LIVE STORE.
--
-- The MariaDB delta since tag v1.0.0 is one index and the version row,
-- and one DATA step that is no schema change: xacml.pepAuthentication
-- (#1827's follow-up, phase 4), THE REMOTE PEPS' CREDENTIAL at the end.
-- sts_sessions_subject_band is PostgreSQL only (#876); this engine has no
-- partial indexes and the driver does not probe for that name.
-- sts_sessions_started (#882) is the index the newest-first session page
-- walks, on (realm, started_at DESC, `key`), with no WHERE.
--
-- This file adds that index and writes version 32. It does not run
-- schema.sql. That file sets the application account's password on every
-- run. MariaDB has no CREATE INDEX CONCURRENTLY. A secondary InnoDB index
-- is built with ALGORITHM=INPLACE, LOCK=NONE, which does not take a lock
-- that blocks writers.
--
-- THIS FILE IS HAND-WRITTEN. regenerate-model-docs.sh does not emit it.
-- tests/mariadb_schema.js holds the column list to mariadb/schema.sql.
--
-- ---------------------------------------------------------------------------
-- RUNNING IT, in the service's database, as the table owner:
--
--   mariadb --abort-source-on-error -u root -p sts \
--     < mariadb/upgrade-1.0.0.sql
--
-- Pass --abort-source-on-error. A client whose default is to continue
-- after an error can otherwise finish the file. The DDL below is also
-- gated on the same checks, so that client still does not build the
-- index on a store this script refuses.
--
-- The application account cannot CREATE. Do not wipe the volume. Start the
-- version-32 image after this script exits 0. A second run finds the index
-- and inserts nothing. A valid index of the wrong shape is refused: drop
-- it by hand and run this file again. A store with no sts_schema version
-- of 31 or later is refused. PostgreSQL's twin, which also builds
-- sts_sessions_subject_band, is postgres/upgrade-1.0.0.sql.
-- ---------------------------------------------------------------------------

-- EXECUTE IMMEDIATE does not accept a subquery, so each check is a user
-- variable first. SIGNAL's message has to stay short: MariaDB limits it.
-- A missing sts_schema makes the version read fail, which is a refusal.
SET @sts_upgrade_tables := (
  SELECT COUNT(*) FROM information_schema.tables
   WHERE table_schema = DATABASE()
     AND table_name IN ('sts_schema', 'sts_sessions')
);
SET @sts_upgrade_version := (
  SELECT COUNT(*) FROM sts_schema WHERE version >= 31
);
SET @sts_upgrade_have_index := (
  SELECT COUNT(*) FROM information_schema.statistics
   WHERE table_schema = DATABASE()
     AND table_name = 'sts_sessions'
     AND index_name = 'sts_sessions_started'
);

EXECUTE IMMEDIATE IF(@sts_upgrade_tables = 2,
  'DO 0',
  'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''upgrade-1.0.0: sts_schema or sts_sessions is missing''');
EXECUTE IMMEDIATE IF(@sts_upgrade_version > 0,
  'DO 0',
  'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''upgrade-1.0.0: no schema version >= 31 (release 1.0.0)''');

-- InnoDB builds a secondary index in place without blocking writers.
-- The gate is repeated so a client that ignores the SIGNAL still does not
-- add the index to a store this script has refused.
EXECUTE IMMEDIATE IF(
  @sts_upgrade_tables = 2 AND @sts_upgrade_version > 0
    AND @sts_upgrade_have_index = 0,
  'ALTER TABLE sts_sessions ADD INDEX sts_sessions_started (realm, started_at DESC, `key`), ALGORITHM=INPLACE, LOCK=NONE',
  'DO 0');

-- non_unique = 1 is a non-unique index. COLLATION is A or D. Three columns,
-- in this order, or the version row is not written.
SET @sts_upgrade_shape := (
  SELECT IF(COUNT(*) = 3 AND MIN(non_unique) = 1 AND MAX(non_unique) = 1,
            GROUP_CONCAT(CONCAT(column_name, ':', collation)
                         ORDER BY seq_in_index SEPARATOR ','),
            NULL)
    FROM information_schema.statistics
   WHERE table_schema = DATABASE()
     AND table_name = 'sts_sessions'
     AND index_name = 'sts_sessions_started'
);

EXECUTE IMMEDIATE IF(
  @sts_upgrade_tables = 2 AND @sts_upgrade_version > 0
    AND @sts_upgrade_shape = 'realm:A,started_at:D,key:A',
  'INSERT IGNORE INTO sts_schema (version) VALUES (32)',
  'DO 0');
EXECUTE IMMEDIATE IF(
  @sts_upgrade_tables = 2 AND @sts_upgrade_version > 0
    AND @sts_upgrade_shape = 'realm:A,started_at:D,key:A',
  'DO 0',
  'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''upgrade-1.0.0: sts_sessions_started has the wrong shape; drop it and rerun''');

SELECT @sts_upgrade_shape AS sts_sessions_started;

-- ---------------------------------------------------------------------------
-- THE REMOTE PEPS' CREDENTIAL (#1827's follow-up, phase 4; rcbj 2026-11-16).
--
-- postgres/upgrade-1.0.0.sql's step, argued there in full: 1.1.0 makes
-- xacml.pepAuthentication default to `token`, every PEP a 1.0.0 store
-- registered authenticated by its client certificate, so every realm with a
-- registered PEP (a row of sts_ldap_entries whose parent_key starts
-- `ou=peps,`) is given `either`, and only where no value is stored:
--
--   1. the default realm: an sts_appconfig row {"raw": "either"}, which is
--      process-wide (every realm's fallback);
--   2. every other realm with a PEP: `either` in sts_realms.overrides;
--   3. when the default realm stores `either`, every other realm with no
--      PEP and no value: `token`, so it keeps the default rather than
--      inheriting the default realm's.
--
-- A change-log row (sts_changes, origin `upgrade-1.0.0`) follows each write
-- that changed a row (ROW_COUNT()), so a 1.1.0 process already running reads
-- the value at its next change-log pull.
--
-- The key has a dot in it, so its JSON path is quoted: $."xacml...". Each
-- statement is gated on the checks above AND on the four tables it touches
-- (sts_realms, sts_appconfig, sts_ldap_entries, sts_changes) being in this
-- database; a cell or tier database may lack one, and then nothing is
-- written and the value is set by hand in each realm with PEPs. INSERT
-- IGNORE and the JSON_CONTAINS_PATH test keep a stored value and make a
-- second run write nothing. utf8mb4_nopad_bin compares parent_key
-- byte-wise, and the keys are lower-cased by the service.
-- ---------------------------------------------------------------------------
SET @sts_upgrade_pep_tables := (
  SELECT COUNT(*) FROM information_schema.tables
   WHERE table_schema = DATABASE()
     AND table_name IN ('sts_realms', 'sts_appconfig', 'sts_ldap_entries',
                        'sts_changes')
);

EXECUTE IMMEDIATE IF(
  @sts_upgrade_tables = 2 AND @sts_upgrade_version > 0
    AND @sts_upgrade_pep_tables = 4,
  'INSERT IGNORE INTO sts_appconfig (`key`, value) SELECT ''xacml.pepAuthentication'', JSON_OBJECT(''raw'', ''either'') FROM DUAL WHERE EXISTS (SELECT 1 FROM sts_ldap_entries WHERE realm = ''default'' AND parent_key LIKE ''ou=peps,%'')',
  'DO 0');
SET @sts_upgrade_pep_written := ROW_COUNT();
EXECUTE IMMEDIATE IF(@sts_upgrade_pep_tables = 4 AND @sts_upgrade_pep_written > 0,
  'INSERT INTO sts_changes (origin, kind) VALUES (''upgrade-1.0.0'', ''appconfig'')',
  'DO 0');

EXECUTE IMMEDIATE IF(
  @sts_upgrade_tables = 2 AND @sts_upgrade_version > 0
    AND @sts_upgrade_pep_tables = 4,
  'UPDATE sts_realms AS r SET r.overrides = JSON_SET(COALESCE(r.overrides, ''{}''), ''$."xacml.pepAuthentication"'', ''either'') WHERE r.id <> ''default'' AND NOT JSON_CONTAINS_PATH(COALESCE(r.overrides, ''{}''), ''one'', ''$."xacml.pepAuthentication"'') AND EXISTS (SELECT 1 FROM sts_ldap_entries AS e WHERE e.realm = r.id AND e.parent_key LIKE ''ou=peps,%'')',
  'DO 0');
SET @sts_upgrade_pep_written := ROW_COUNT();
EXECUTE IMMEDIATE IF(@sts_upgrade_pep_tables = 4 AND @sts_upgrade_pep_written > 0,
  'INSERT INTO sts_changes (origin, kind) VALUES (''upgrade-1.0.0'', ''realms'')',
  'DO 0');

EXECUTE IMMEDIATE IF(
  @sts_upgrade_tables = 2 AND @sts_upgrade_version > 0
    AND @sts_upgrade_pep_tables = 4,
  'UPDATE sts_realms AS r SET r.overrides = JSON_SET(COALESCE(r.overrides, ''{}''), ''$."xacml.pepAuthentication"'', ''token'') WHERE r.id <> ''default'' AND NOT JSON_CONTAINS_PATH(COALESCE(r.overrides, ''{}''), ''one'', ''$."xacml.pepAuthentication"'') AND EXISTS (SELECT 1 FROM sts_appconfig AS a WHERE a.`key` = ''xacml.pepAuthentication'' AND JSON_UNQUOTE(JSON_EXTRACT(a.value, ''$.raw'')) = ''either'')',
  'DO 0');
SET @sts_upgrade_pep_written := ROW_COUNT();
EXECUTE IMMEDIATE IF(@sts_upgrade_pep_tables = 4 AND @sts_upgrade_pep_written > 0,
  'INSERT INTO sts_changes (origin, kind) VALUES (''upgrade-1.0.0'', ''realms'')',
  'DO 0');

EXECUTE IMMEDIATE IF(
  @sts_upgrade_pep_tables = 4,
  'SELECT COALESCE((SELECT JSON_UNQUOTE(JSON_EXTRACT(value, ''$.raw'')) FROM sts_appconfig WHERE `key` = ''xacml.pepAuthentication''), ''(default)'') AS default_realm_pep_authentication, (SELECT COUNT(*) FROM sts_realms WHERE JSON_UNQUOTE(JSON_EXTRACT(overrides, ''$."xacml.pepAuthentication"'')) = ''either'') AS realms_either, (SELECT COUNT(*) FROM sts_realms WHERE JSON_UNQUOTE(JSON_EXTRACT(overrides, ''$."xacml.pepAuthentication"'')) = ''token'') AS realms_token',
  'SELECT ''sts_realms, sts_appconfig, sts_ldap_entries or sts_changes is not in this database; xacml.pepAuthentication was not written'' AS pep_authentication');
