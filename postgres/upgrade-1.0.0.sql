-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
-- SPDX-License-Identifier: BUSL-1.1
--
-- File: postgres/upgrade-1.0.0.sql
--
-- ---------------------------------------------------------------------------
-- RELEASE 1.0.0 (SCHEMA VERSION 31) TO SCHEMA VERSION 32, ON A LIVE STORE.
--
-- Tag v1.0.0 is schema version 31. The statements added to
-- postgres/schema.sql since that tag are two indexes and the version row:
--
--   sts_sessions_subject_band   #876, no schema version of its own
--   sts_sessions_started        #882, schema version 32
--   INSERT version 32 beside 31 (the table keeps every version)
--
-- This file builds those two indexes and writes that row. It does not run
-- schema.sql. That file is idempotent for an empty volume, and it is the
-- wrong upgrade here: its version-31 block drops and recreates
-- sts_ldap_entries_asked_names inside one transaction even when the
-- expression on disk is already that one, which holds directory writes for
-- the rebuild, and it sets the application role's password again.
--
-- THIS FILE IS HAND-WRITTEN. regenerate-model-docs.sh does not emit it.
-- tests/postgres_schema.js holds the two CREATE INDEX statements to
-- schema.sql, apart from the word CONCURRENTLY.
--
-- ---------------------------------------------------------------------------
-- RUNNING IT.
--
--   psql -v ON_ERROR_STOP=1 -f postgres/upgrade-1.0.0.sql \
--        "postgres://owner@host:5432/sts"
--
-- As the table owner, never as sts_app: the application role cannot CREATE.
-- Do not pass --single-transaction. CREATE INDEX CONCURRENTLY cannot run
-- inside a transaction, and psql -f commits each statement on its own.
-- Do not wipe the volume. The 1.0.0 image can keep serving while the
-- indexes build. Start the version-32 image after this script exits 0.
-- A rollback to a version-31 image ignores both indexes; leave them.
--
-- -v sts_schema=sts is the default. -v sts_maintenance_work_mem=1GB raises
-- this session's maintenance_work_mem for the builds and does not change
-- the server.
--
-- A second run finds the indexes valid and does the work again only for
-- ANALYZE and the version insert, which conflict-does-nothing. An invalid
-- index left by a dead CONCURRENTLY session is dropped and built again.
-- A valid index whose definition is not the one below is refused: drop it
-- by hand and run this file again. A store with no sts_schema version of
-- 31 or later is refused. That store is older than release 1.0.0, and
-- schema.sql is its upgrade — read the asked-names note above first.
--
-- MariaDB's twin is mariadb/upgrade-1.0.0.sql. It adds only
-- sts_sessions_started. MariaDB has no sts_sessions_subject_band.
-- ---------------------------------------------------------------------------
\set ON_ERROR_STOP on
\if :{?sts_schema}
\else
\set sts_schema sts
\endif

SET search_path TO :"sts_schema", public;

\if :{?sts_maintenance_work_mem}
SET maintenance_work_mem TO :'sts_maintenance_work_mem';
\endif

-- Do not pass --single-transaction. This session cannot see that mode,
-- and CREATE INDEX CONCURRENTLY then fails before it leaves an index.

SELECT (to_regclass('sts_sessions') IS NOT NULL)::int AS sessions_present,
       (to_regclass('sts_schema') IS NOT NULL)::int AS schema_present
\gset
\if :schema_present
\else
-- \quit ignores an exit code in this psql, so a refused store would
-- otherwise look like success. RAISE makes ON_ERROR_STOP return non-zero.
-- The schema name is a psql variable, which is substituted in \echo and
-- not inside a DO body.
\echo 'upgrade-1.0.0: no sts_schema on search_path' :'sts_schema' '(then public). This script upgrades a release 1.0.0 store. It does not build one.'
DO $refuse$ BEGIN
  RAISE EXCEPTION
    'upgrade-1.0.0: no sts_schema on that search_path. This script does not build a store.';
END $refuse$;
\endif
\if :sessions_present
\else
DO $refuse$ BEGIN
  RAISE EXCEPTION
    'upgrade-1.0.0: sts_sessions is missing. schema.sql is the build, and this script does not run it.';
END $refuse$;
\endif

SELECT (EXISTS (
          SELECT 1 FROM sts_schema WHERE version >= 31
       ))::int AS at_least_31
\gset
\if :at_least_31
\else
DO $refuse$ BEGIN
  RAISE EXCEPTION
    'upgrade-1.0.0: sts_schema has no version >= 31. Release 1.0.0 is version 31. An older store is schema.sql, which this script does not run: that file rebuilds sts_ldap_entries_asked_names inside its transaction.';
END $refuse$;
\endif

-- 0 and 1, never t/f. psql's \if treats the letters f as true.
SELECT COALESCE((c.oid IS NOT NULL)::int, 0) AS band_present,
       COALESCE(i.indisvalid::int, 0) AS band_valid
  FROM (SELECT 1) AS one
  LEFT JOIN pg_namespace n ON n.nspname = current_schema()
  LEFT JOIN pg_class c
    ON c.relnamespace = n.oid
   AND c.relname = 'sts_sessions_subject_band'
   AND c.relkind = 'i'
  LEFT JOIN pg_index i ON i.indexrelid = c.oid
\gset
\if :band_present
\if :band_valid
\echo 'upgrade-1.0.0: sts_sessions_subject_band is already valid'
\else
\echo 'upgrade-1.0.0: sts_sessions_subject_band is invalid; dropping it'
DROP INDEX CONCURRENTLY IF EXISTS sts_sessions_subject_band;
\set band_present 0
\endif
\endif
\if :band_present
\else
\echo 'upgrade-1.0.0: building sts_sessions_subject_band'
CREATE INDEX CONCURRENTLY IF NOT EXISTS sts_sessions_subject_band
  ON sts_sessions (realm, subject_key COLLATE "C")
  WHERE chosen AND subject_key <> '';
\endif

SELECT COALESCE((c.oid IS NOT NULL)::int, 0) AS started_present,
       COALESCE(i.indisvalid::int, 0) AS started_valid
  FROM (SELECT 1) AS one
  LEFT JOIN pg_namespace n ON n.nspname = current_schema()
  LEFT JOIN pg_class c
    ON c.relnamespace = n.oid
   AND c.relname = 'sts_sessions_started'
   AND c.relkind = 'i'
  LEFT JOIN pg_index i ON i.indexrelid = c.oid
\gset
\if :started_present
\if :started_valid
\echo 'upgrade-1.0.0: sts_sessions_started is already valid'
\else
\echo 'upgrade-1.0.0: sts_sessions_started is invalid; dropping it'
DROP INDEX CONCURRENTLY IF EXISTS sts_sessions_started;
\set started_present 0
\endif
\endif
\if :started_present
\else
\echo 'upgrade-1.0.0: building sts_sessions_started'
CREATE INDEX CONCURRENTLY IF NOT EXISTS sts_sessions_started
  ON sts_sessions (realm, started_at DESC, key)
  WHERE chosen;
\endif

-- A valid index of the wrong shape is refused, not dropped. CONCURRENTLY
-- IF NOT EXISTS does not rebuild an invalid index either; the branches
-- above drop that case before the CREATE. open() reads to_regclass and
-- not indisvalid, so a wrong or invalid index would let the version-32
-- image start and then fail the session pages.
DO $upgrade$
DECLARE
  is_valid boolean;
  is_unique boolean;
  nkeys int;
  natts int;
  cols text;
  flags text;
  pred text;
  collname text;
BEGIN
  SELECT i.indisvalid, i.indisunique, i.indnkeyatts, i.indnatts
    INTO is_valid, is_unique, nkeys, natts
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_subject_band'
     AND c.relkind = 'i';
  IF NOT FOUND THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_subject_band is missing';
  END IF;
  IF NOT is_valid THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_subject_band is invalid';
  END IF;
  IF is_unique OR nkeys <> 2 OR natts <> 2 THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_subject_band has % key columns '
      '(% stored), unique %. Want 2 key columns, not unique. '
      'Drop it and run this script again.',
      nkeys, natts, is_unique;
  END IF;
  SELECT string_agg(a.attname, ',' ORDER BY cols.ord),
         string_agg(CASE WHEN (i.indoption[cols.ord - 1] & 1) <> 0
                         THEN 'D' ELSE 'A' END,
                    '' ORDER BY cols.ord)
    INTO cols, flags
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
    JOIN LATERAL unnest(i.indkey::smallint[])
         WITH ORDINALITY AS cols(attnum, ord)
      ON cols.ord <= i.indnkeyatts
    JOIN pg_attribute a
      ON a.attrelid = i.indrelid AND a.attnum = cols.attnum
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_subject_band';
  IF cols IS DISTINCT FROM 'realm,subject_key' OR flags IS DISTINCT FROM 'AA'
  THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_subject_band is % %, want realm ASC, '
      'subject_key ASC. Drop it and run this script again.',
      cols, flags;
  END IF;
  SELECT col.collname INTO collname
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
    JOIN pg_collation col ON col.oid = i.indcollation[1]
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_subject_band';
  IF collname IS DISTINCT FROM 'C' THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_subject_band collation is "%", want C. '
      'Drop it and run this script again.',
      collname;
  END IF;
  SELECT pg_get_expr(i.indpred, i.indrelid) INTO pred
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_subject_band';
  pred := btrim(regexp_replace(
           regexp_replace(regexp_replace(pred, '::text', '', 'g'),
                          '[()]', '', 'g'),
           '\s+', ' ', 'g'));
  IF pred IS DISTINCT FROM $pred$chosen AND subject_key <> ''$pred$ THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_subject_band predicate is "%", '
      'want chosen AND subject_key <> ''''. '
      'Drop it and run this script again.',
      pred;
  END IF;

  SELECT i.indisvalid, i.indisunique, i.indnkeyatts, i.indnatts
    INTO is_valid, is_unique, nkeys, natts
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_started'
     AND c.relkind = 'i';
  IF NOT FOUND THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_started is missing';
  END IF;
  IF NOT is_valid THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_started is invalid';
  END IF;
  IF is_unique OR nkeys <> 3 OR natts <> 3 THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_started has % key columns '
      '(% stored), unique %. Want 3 key columns, not unique. '
      'Drop it and run this script again.',
      nkeys, natts, is_unique;
  END IF;
  SELECT string_agg(a.attname, ',' ORDER BY cols.ord),
         string_agg(CASE WHEN (i.indoption[cols.ord - 1] & 1) <> 0
                         THEN 'D' ELSE 'A' END,
                    '' ORDER BY cols.ord)
    INTO cols, flags
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
    JOIN LATERAL unnest(i.indkey::smallint[])
         WITH ORDINALITY AS cols(attnum, ord)
      ON cols.ord <= i.indnkeyatts
    JOIN pg_attribute a
      ON a.attrelid = i.indrelid AND a.attnum = cols.attnum
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_started';
  IF cols IS DISTINCT FROM 'realm,started_at,key'
     OR flags IS DISTINCT FROM 'ADA' THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_started is % %, want realm ASC, '
      'started_at DESC, key ASC. Drop it and run this script again.',
      cols, flags;
  END IF;
  SELECT pg_get_expr(i.indpred, i.indrelid) INTO pred
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = c.oid
   WHERE ns.nspname = current_schema()
     AND c.relname = 'sts_sessions_started';
  IF pred IS DISTINCT FROM 'chosen' THEN
    RAISE EXCEPTION
      'upgrade-1.0.0: sts_sessions_started predicate is "%", want chosen. '
      'Drop it and run this script again.',
      pred;
  END IF;
END
$upgrade$;

ANALYZE sts_sessions;

INSERT INTO sts_schema (version) VALUES (32) ON CONFLICT (version) DO NOTHING;

\echo 'upgrade-1.0.0: schema version 32 is recorded. sts_sessions_subject_band and sts_sessions_started are valid. schema.sql was not run. The version-32 image can start.'
