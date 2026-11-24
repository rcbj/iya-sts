-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: mariadb/upgrade-1.1.0.sql
--
-- ---------------------------------------------------------------------------
-- RELEASE 1.1.x TO RELEASE 1.2.0, ON A LIVE STORE.
--
-- Release 1.1.x is schema version 32; 1.2.0 is 33. Two steps, each
-- idempotent, postgres/upgrade-1.1.0.sql's, argued there in full:
--
--   * THE APPEND-ONLY AUDIT LOG (#1616): `sts_audit`, its index, the two SQL
--     SECURITY DEFINER procedures rows leave it through, and the version row
--     — and THE APPLICATION ACCOUNT'S GRANTS MADE PER TABLE, where 1.1.x gave
--     one on `<db>.*`: MariaDB cannot take one table out of a database
--     grant, and the audit log's must be SELECT and INSERT alone. The grant
--     list is mariadb/schema.sql's, and tests/mariadb_schema.js holds the
--     two to each other. The account is named as schema.sql names it:
--     @sts_app_user (default sts_app) and @sts_app_host (default %), set
--     with --init-command as there;
--   * ONE DATA STEP: 1.2.0
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
-- BEFORE starting the 1.2.0 image, as an account that may CREATE and
-- GRANT (root on the compose stack): the application account cannot create
-- the audit table. A second run changes nothing. A
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

-- ---------------------------------------------------------------------------
-- THE AUDIT LOG, APPEND-ONLY (#1616, ASVS 5.0.0 16.4.2; schema version 33).
-- The statements are mariadb/schema.sql's. Gated on the version check above:
-- a store this file refuses gets nothing.
-- ---------------------------------------------------------------------------
SET @sts_app_user := COALESCE(@sts_app_user, 'sts_app');
SET @sts_app_host := COALESCE(@sts_app_host, '%');
SET @sts_app_account := CONCAT('''', REPLACE(@sts_app_user, '''', ''''''), '''@''', REPLACE(@sts_app_host, '''', ''''''), '''');
SET @sts_app_database := CONCAT('`', REPLACE(DATABASE(), '`', '``'), '`');

CREATE TABLE IF NOT EXISTS sts_audit (
  realm  VARCHAR(64)  NOT NULL,
  origin VARCHAR(255) NOT NULL DEFAULT '',
  seq    BIGINT       NOT NULL,
  at     BIGINT       NOT NULL,
  body   LONGTEXT     NOT NULL,
  PRIMARY KEY (realm, origin, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_audit_at ON sts_audit (realm, at, origin, seq);;

CREATE OR REPLACE PROCEDURE sts_audit_retain(IN p_realm VARCHAR(64), IN p_keep BIGINT) SQL SECURITY DEFINER DELETE a FROM sts_audit a JOIN (SELECT at, origin, seq FROM (SELECT at, origin, seq, ROW_NUMBER() OVER (ORDER BY at DESC, origin DESC, seq DESC) AS rn FROM sts_audit WHERE realm = p_realm) ranked WHERE rn = GREATEST(COALESCE(p_keep, 0), 1000)) edge ON a.realm = p_realm AND (a.at, a.origin, a.seq) < (edge.at, edge.origin, edge.seq);

CREATE OR REPLACE PROCEDURE sts_audit_purge_realm(IN p_realm VARCHAR(64)) SQL SECURITY DEFINER DELETE FROM sts_audit WHERE realm = p_realm AND p_realm NOT IN ('', 'default') AND NOT EXISTS (SELECT 1 FROM sts_realms r WHERE r.id = p_realm AND r.retiring_at IS NULL);

-- THE GRANTS, PER TABLE. The database-wide grant 1.1.x gave is given (so
-- the revoke cannot fail on an account that lacks it) and taken away, the
-- audit table's likewise, and then each table's own.
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.* TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('REVOKE ALL PRIVILEGES ON ', @sts_app_database, '.* FROM ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_audit` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('REVOKE ALL PRIVILEGES ON ', @sts_app_database, '.`sts_audit` FROM ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_ldap_entries` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_ldap_entry_keys` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_ldap_dek_counts` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_ldap_dek_deltas` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_ldap_counts` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_ldap_count_deltas` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_realms` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_appconfig` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_keys` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_minted` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_sessions` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_minted_index` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_changes` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_used_assertions` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_nodes` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_leases` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_claims` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_secrets` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_locks` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_counters` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_windows` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cluster_budgets` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_node_snapshots` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_change_readers` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_datasets` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_dataset_versions` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_dataset_blobs` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_geo_locations` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_geo_ranges` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_asn_ranges` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_ip_lists` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_fido_authenticators` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_assessments` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_feature_counts` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_failures` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_session_context` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_subjects` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_risk_terms_acceptances` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_cell_routing` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_report_artifacts` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_report_artifact_pieces` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT ON ', @sts_app_database, '.`sts_audit` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON ', @sts_app_database, '.`sts_schema` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT EXECUTE ON PROCEDURE ', @sts_app_database, '.`sts_audit_retain` TO ', @sts_app_account);
EXECUTE IMMEDIATE CONCAT('GRANT EXECUTE ON PROCEDURE ', @sts_app_database, '.`sts_audit_purge_realm` TO ', @sts_app_account);

INSERT IGNORE INTO sts_schema (version) VALUES (33);

SELECT CONCAT('upgrade-1.1.0: sts_audit is in place (schema version 33); ', @sts_app_account, ' holds a grant per table, and SELECT and INSERT alone on the audit log.') AS audit_log;
