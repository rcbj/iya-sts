-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: postgres/upgrade-1.1.0.sql
--
-- ---------------------------------------------------------------------------
-- RELEASE 1.1.x TO RELEASE 1.2.0, ON A LIVE STORE.
--
-- Release 1.1.x is schema version 32; 1.2.0 is 33. This file does two
-- things, each idempotent:
--
--   * ONE DATA STEP, which keeps a 1.1.x deployment's OAuth clients
--     working across a changed default — THE DEFAULT SCOPES OF A CLIENT
--     THAT DECLARES NONE, below (#1589);
--   * THE APPEND-ONLY AUDIT LOG (#1616, schema version 33): the table
--     `sts_audit`, its index, the two SECURITY DEFINER functions rows leave
--     it through, the application role's INSERT and SELECT on it and
--     nothing more, and the version row — THE AUDIT LOG, at the end. The
--     rows already held move into it when the 1.2.0 service first starts:
--     they are sealed, and this file cannot open them.
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
-- As the table owner — the role `postgres/schema.sql` was run as — and
-- BEFORE starting the 1.2.0 image: its application role cannot create the
-- audit table, and the service refuses to start without it
-- (STS-STORE-0029, naming this file). The scope value is read by a 1.2.0
-- process already running at its next change-log pull. A 1.1.x process ignores the key (config.js's
-- applyPersistedOverrides() logs STS-CORE-0008 and leaves the value in the
-- store). A second run writes nothing. A store from 1.0.0 runs
-- upgrade-1.0.0.sql first, then this file.
--
-- -v sts_schema=sts and -v sts_app_role=sts_app are the defaults, the
-- names postgres/schema.sql uses. A store with no sts_schema version of
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
\if :{?sts_app_role}
\else
\set sts_app_role sts_app
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

-- ---------------------------------------------------------------------------
-- THE AUDIT LOG, APPEND-ONLY (#1616, ASVS 5.0.0 16.4.2; schema version 33).
--
-- Until 1.2.0 the audit ring was sealed segments in `sts_minted`, which the
-- application role may UPDATE and DELETE like every other row there: its
-- keyed chain showed a change, and nothing prevented one. 1.2.0 writes one
-- sealed row per event into `sts_audit`, where that role holds INSERT and
-- SELECT and nothing else, and rows leave through two functions owned by the
-- role running this file. The statements are postgres/schema.sql's, and
-- tests/postgres_schema.js holds the two to each other.
--
-- THE ROWS ALREADY HELD are copied in by the 1.2.0 service at its first
-- start (they are sealed under keys this file does not hold), with their
-- chain checksums, and the old segments removed — common/audit.js.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sts_audit (
  realm text NOT NULL,
  origin text NOT NULL DEFAULT '',
  seq bigint NOT NULL,
  at bigint NOT NULL,
  body text NOT NULL,
  PRIMARY KEY (realm, origin, seq)
);
CREATE INDEX IF NOT EXISTS sts_audit_at ON sts_audit (realm, at, origin, seq);

CREATE OR REPLACE FUNCTION sts_audit_retain(p_realm text, p_keep bigint)
  RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
  keep bigint := GREATEST(COALESCE(p_keep, 0), 1000);
  edge record;
  gone bigint;
BEGIN
  SELECT a.at, a.origin, a.seq INTO edge FROM sts_audit a
   WHERE a.realm = p_realm
   ORDER BY a.at DESC, a.origin DESC, a.seq DESC OFFSET keep - 1 LIMIT 1;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;
  DELETE FROM sts_audit a
   WHERE a.realm = p_realm AND (a.at, a.origin, a.seq) < (edge.at, edge.origin, edge.seq);
  GET DIAGNOSTICS gone = ROW_COUNT;
  RETURN gone;
END $$;

CREATE OR REPLACE FUNCTION sts_audit_purge_realm(p_realm text)
  RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
  gone bigint;
BEGIN
  IF p_realm IS NULL OR p_realm = '' OR p_realm = 'default' THEN
    RETURN 0;
  END IF;
  IF EXISTS (SELECT 1 FROM sts_realms r
              WHERE r.id = p_realm AND r.retiring_at IS NULL) THEN
    RETURN 0;
  END IF;
  DELETE FROM sts_audit a WHERE a.realm = p_realm;
  GET DIAGNOSTICS gone = ROW_COUNT;
  RETURN gone;
END $$;

REVOKE ALL ON FUNCTION sts_audit_retain(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION sts_audit_purge_realm(text) FROM PUBLIC;

-- The default privileges postgres/schema.sql set hand a new table all four
-- verbs; the two it may keep are granted outright in case they were not,
-- and the rest taken away.
GRANT SELECT, INSERT ON sts_audit TO :"sts_app_role";
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON sts_audit FROM :"sts_app_role";
GRANT EXECUTE ON FUNCTION sts_audit_retain(text, bigint)
  TO :"sts_app_role";
GRANT EXECUTE ON FUNCTION sts_audit_purge_realm(text) TO :"sts_app_role";

INSERT INTO sts_schema (version) VALUES (33) ON CONFLICT (version) DO NOTHING;

\echo 'upgrade-1.1.0: done. sts_audit is in place (schema version 33) and the application role may only add to it and read it. schema.sql was not run. The 1.2.0 image can start.'
