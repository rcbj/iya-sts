-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: postgres/upgrade-1.1.0.sql
--
-- ---------------------------------------------------------------------------
-- RELEASE 1.1.x TO RELEASE 1.2.0, ON A LIVE STORE.
--
-- Schema version 32 is both releases' schema: 1.2.0 changes no table, and
-- this file runs no DDL and records no version. It is ONE DATA STEP, which
-- keeps a 1.1.x deployment's OAuth clients working across a changed default
-- — see THE DEFAULT SCOPES OF A CLIENT THAT DECLARES NONE, below.
--
-- THIS FILE IS HAND-WRITTEN. regenerate-model-docs.sh does not emit it.
-- tests/postgres_schema.js holds it to the step below.
--
-- ---------------------------------------------------------------------------
-- RUNNING IT.
--
--   psql -v ON_ERROR_STOP=1 -f postgres/upgrade-1.1.0.sql \
--        "postgres://owner@host:5432/sts"
--
-- As the table owner. Run it before or after starting the 1.2.0 image: a
-- 1.2.0 process already running reads the value at its next change-log
-- pull. A 1.1.x process ignores the key (config.js's
-- applyPersistedOverrides() logs STS-CORE-0008 and leaves the value in the
-- store). A second run writes nothing. A store from 1.0.0 runs
-- upgrade-1.0.0.sql first, then this file.
--
-- -v sts_schema=sts is the default. A store with no sts_schema version of
-- 32 or later is refused: it is older than release 1.1.0, and
-- upgrade-1.0.0.sql is its first step.
--
-- MariaDB's twin is mariadb/upgrade-1.1.0.sql.
-- ---------------------------------------------------------------------------
\set ON_ERROR_STOP on
\if :{?sts_schema}
\else
\set sts_schema sts
\endif
SET search_path TO :"sts_schema", public;

SELECT (to_regclass('sts_schema') IS NOT NULL)::int AS schema_present
\gset
\if :schema_present
\else
-- \quit ignores an exit code in this psql, so a refused store would
-- otherwise look like success. RAISE makes ON_ERROR_STOP return non-zero.
\echo 'upgrade-1.1.0: no sts_schema on search_path' :'sts_schema' '(then public). This script upgrades a release 1.1.x store. It does not build one.'
DO $refuse$ BEGIN
  RAISE EXCEPTION
    'upgrade-1.1.0: no sts_schema on that search_path. This script does not build a store.';
END $refuse$;
\endif

-- 0 and 1, never t/f. psql's \if treats the letters f as true.
SELECT (EXISTS (
          SELECT 1 FROM sts_schema WHERE version >= 32
       ))::int AS at_least_32
\gset
\if :at_least_32
\else
DO $refuse$ BEGIN
  RAISE EXCEPTION
    'upgrade-1.1.0: sts_schema has no version >= 32. Release 1.1.0 is version 32. Run upgrade-1.0.0.sql first.';
END $refuse$;
\endif

-- ---------------------------------------------------------------------------
-- THE DEFAULT SCOPES OF A CLIENT THAT DECLARES NONE (#1589; rcbj
-- 2026-11-24: option 1, "openid only", with the compatibility step).
--
-- 1.2.0 makes oauth2.undeclaredClientScopes default to `openid`: in product
-- mode a client whose oauthAllowedScope lists nothing — typically one that
-- registered itself (RFC 7591) without a `scope` member — is issued
-- `openid` alone (ASVS 5.0.0 10.4.11). Every release before it gave such a
-- client OpenID Connect's six scopes, offline_access among them, and the
-- realm's OpenID4VCI scopes; on the new default every such client a 1.1.x
-- store holds would be refused invalid_scope (STS-OAUTH-0578) at its next
-- request for profile, email or a refresh token. So an upgraded store is
-- given `legacy`, the old set, and the operator moves it to `openid` once
-- each client declares what it needs — /admin/mode reports the requirement
-- as NOT MET while it is `legacy`, and each such client's page names the
-- default it is given (docs/v1.2.0/release-notes.md, "Behaviour change: a
-- client that declares no scopes is issued openid alone"). A new install
-- gets the default.
--
-- WHAT IS READ. Whether the store holds any application: a row of
-- sts_ldap_entries whose parent_key starts `ou=applications,` (dn_key is the
-- normalized DN and parent_key is generated from it; neither is sealed).
-- Whether a client declares scopes is on the entry's attributes, which may
-- be sealed, so it is not read: every store with an application keeps the
-- old set, which is what each of its clients had.
--
-- WHAT IS WRITTEN, and only where NO value is stored already, so a value an
-- operator set wins and a second run writes nothing: the default realm's
-- sts_appconfig row {"raw": "legacy"}. That row is PROCESS-WIDE — config.js
-- reads the default realm's overrides as every realm's fallback — so every
-- realm keeps the old set too, and a realm created after the upgrade
-- inherits it until the operator sets the default realm to `openid`. A
-- realm storing a value of its own keeps it.
--
-- A CHANGE-LOG ROW (sts_changes, kind `appconfig`, origin `upgrade-1.1.0`)
-- is written beside the write when it changed something, so a running 1.2.0
-- process reads the value at its next change-log pull.
--
-- A CELL OR TIER DATABASE without sts_appconfig, sts_ldap_entries or
-- sts_changes is skipped, saying so: the step needs the directory and the
-- settings in ONE database. Where they are split, set the value by hand
-- (POST /admin-api/config/set, oauth2.undeclaredClientScopes = legacy).
-- ---------------------------------------------------------------------------
SELECT (to_regclass('sts_appconfig') IS NOT NULL
        AND to_regclass('sts_ldap_entries') IS NOT NULL
        AND to_regclass('sts_changes') IS NOT NULL)::int
       AS scope_tables_present
\gset
\if :scope_tables_present
WITH written AS (
  INSERT INTO sts_appconfig (key, value)
  SELECT 'oauth2.undeclaredClientScopes', '{"raw": "legacy"}'::jsonb
   WHERE EXISTS (SELECT 1 FROM sts_ldap_entries
                  WHERE parent_key LIKE 'ou=applications,%')
  ON CONFLICT (key) DO NOTHING
  RETURNING 1)
INSERT INTO sts_changes (origin, kind)
SELECT 'upgrade-1.1.0', 'appconfig' WHERE EXISTS (SELECT 1 FROM written);

SELECT COALESCE((SELECT value->>'raw' FROM sts_appconfig
                  WHERE key = 'oauth2.undeclaredClientScopes'), '(default)')
         AS undeclared_client_scopes
\gset
\echo 'upgrade-1.1.0: oauth2.undeclaredClientScopes stored for the default realm, the fallback of every realm:' :'undeclared_client_scopes'
\else
\echo 'upgrade-1.1.0: sts_appconfig, sts_ldap_entries or sts_changes is not in this database, so oauth2.undeclaredClientScopes was not written. Set it to legacy by hand while any client declares no scopes.'
\endif

\echo 'upgrade-1.1.0: done. schema.sql was not run. The 1.2.0 image can start.'
