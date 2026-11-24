-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: mariadb/upgrade-1.1.0.sql
--
-- ---------------------------------------------------------------------------
-- RELEASE 1.1.x TO RELEASE 1.2.0, ON A LIVE STORE.
--
-- Schema version 32 is both releases' schema: no DDL and no version row.
-- ONE DATA STEP, postgres/upgrade-1.1.0.sql's, argued there in full: 1.2.0
-- makes oauth2.undeclaredClientScopes default to `openid` (#1589, ASVS
-- 5.0.0 10.4.11), and every client a 1.1.x store holds that declares no
-- scopes was given the old, wider set. So a store holding any application
-- (a row of sts_ldap_entries whose parent_key starts `ou=applications,`)
-- is given `legacy` — the default realm's sts_appconfig row
-- {"raw": "legacy"}, every realm's fallback — only where no value is
-- stored, and a change-log row (origin `upgrade-1.1.0`) follows the write
-- when ROW_COUNT() says it changed something.
--
-- THIS FILE IS HAND-WRITTEN. tests/mariadb_schema.js holds it to that step.
--
-- ---------------------------------------------------------------------------
-- RUNNING IT, in the service's database, as the table owner:
--
--   mariadb --abort-source-on-error -u root -p sts \
--     < mariadb/upgrade-1.1.0.sql
--
-- Before or after starting the 1.2.0 image. A second run writes nothing. A
-- store with no sts_schema version of 32 or later is refused: run
-- upgrade-1.0.0.sql first. A cell or tier database without sts_appconfig,
-- sts_ldap_entries or sts_changes is skipped, saying so; set the value by
-- hand there (POST /admin-api/config/set).
-- ---------------------------------------------------------------------------

-- EXECUTE IMMEDIATE does not accept a subquery, so each check is a user
-- variable first. A missing sts_schema makes the version read fail, which
-- is a refusal.
SET @sts_upgrade_version := (
  SELECT COUNT(*) FROM sts_schema WHERE version >= 32
);

EXECUTE IMMEDIATE IF(@sts_upgrade_version > 0,
  'DO 0',
  'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''upgrade-1.1.0: sts_schema has no version >= 32; run upgrade-1.0.0.sql first''');

SET @sts_upgrade_scope_tables := (
  SELECT COUNT(*) FROM information_schema.tables
   WHERE table_schema = DATABASE()
     AND table_name IN ('sts_appconfig', 'sts_ldap_entries', 'sts_changes')
);

EXECUTE IMMEDIATE IF(
  @sts_upgrade_version > 0 AND @sts_upgrade_scope_tables = 3,
  'INSERT IGNORE INTO sts_appconfig (`key`, value) SELECT ''oauth2.undeclaredClientScopes'', JSON_OBJECT(''raw'', ''legacy'') FROM DUAL WHERE EXISTS (SELECT 1 FROM sts_ldap_entries WHERE parent_key LIKE ''ou=applications,%'')',
  'DO 0');
SET @sts_upgrade_scope_written := ROW_COUNT();
EXECUTE IMMEDIATE IF(@sts_upgrade_scope_tables = 3 AND @sts_upgrade_scope_written > 0,
  'INSERT INTO sts_changes (origin, kind) VALUES (''upgrade-1.1.0'', ''appconfig'')',
  'DO 0');

EXECUTE IMMEDIATE IF(
  @sts_upgrade_scope_tables = 3,
  'SELECT COALESCE((SELECT JSON_UNQUOTE(JSON_EXTRACT(value, ''$.raw'')) FROM sts_appconfig WHERE `key` = ''oauth2.undeclaredClientScopes''), ''(default)'') AS undeclared_client_scopes',
  'SELECT ''sts_appconfig, sts_ldap_entries or sts_changes is not in this database; oauth2.undeclaredClientScopes was not written'' AS undeclared_client_scopes');
