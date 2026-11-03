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
-- so the DDL is checked as strictly as the rows will be, and so the quoting
-- below means the same thing whatever the server's default mode is.
SET NAMES utf8mb4 COLLATE utf8mb4_bin;
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

CREATE TABLE IF NOT EXISTS sts_ldap_entries (
  realm       VARCHAR(64)  NOT NULL,
  dn_key      VARCHAR(352) NOT NULL,
  dn          LONGTEXT     NOT NULL,
  attrs       JSON         NOT NULL,
  origin      LONGTEXT,
  created_at  VARCHAR(32),
  modified_at VARCHAR(32),
  parent_key  VARCHAR(352) GENERATED ALWAYS AS (CASE WHEN LOCATE(',', dn_key) > 0 THEN SUBSTRING(dn_key, LOCATE(',', dn_key) + 1) ELSE '' END) STORED,
  rdn_value   VARCHAR(352) GENERATED ALWAYS AS (SUBSTRING(SUBSTRING_INDEX(dn_key, ',', 1), LOCATE('=', SUBSTRING_INDEX(dn_key, ',', 1)) + 1)) STORED,
  name_keys   JSON         NOT NULL DEFAULT '[]',
  mail_keys   JSON         NOT NULL DEFAULT '[]',
  uuid_keys   JSON         NOT NULL DEFAULT '[]',
  class_keys  JSON         NOT NULL DEFAULT '[]',
  value_keys  JSON         NOT NULL DEFAULT '[]',
  attr_names  JSON         NOT NULL DEFAULT '[]',
  dek_keys    JSON,
  PRIMARY KEY (realm, dn_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_parent ON sts_ldap_entries (realm, parent_key, dn_key);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_rdn ON sts_ldap_entries (realm, parent_key, rdn_value);
-- PostgreSQL's are partial, on the children of `ou=users` only; these are
-- whole (`mariadb/CLAUDE.md`).
CREATE INDEX IF NOT EXISTS sts_ldap_entries_created ON sts_ldap_entries (realm, parent_key, created_at);
CREATE INDEX IF NOT EXISTS sts_ldap_entries_modified ON sts_ldap_entries (realm, parent_key, modified_at);

-- WHAT POSTGRESQL'S GIN INDEXES OVER THE JSON LOOKUP COLUMNS ANSWER: one row
-- per (entry, kind, key) — `name_keys`, `mail_keys`, `uuid_keys`,
-- `class_keys`, `value_keys`, `attr_names` and the keys of `dek_keys` — that
-- the driver writes in the entry's own transaction.
CREATE TABLE IF NOT EXISTS sts_ldap_entry_keys (
  realm  VARCHAR(64)  NOT NULL,
  kind   VARCHAR(8)   NOT NULL,
  k      VARCHAR(344) NOT NULL,
  dn_key VARCHAR(352) NOT NULL,
  PRIMARY KEY (realm, kind, k, dn_key),
  CONSTRAINT sts_ldap_entry_keys_kind CHECK (kind IN ('name', 'mail', 'uuid', 'class', 'value', 'attr', 'dek'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_ldap_entry_keys_entry ON sts_ldap_entry_keys (realm, dn_key);

-- THE COUNTS, KEPT. PostgreSQL maintains these with statement triggers over
-- transition tables; MariaDB has row triggers only, so this script creates
-- NO trigger and NO function and the driver maintains them. `txid` is the
-- per-transaction id the driver generates, where PostgreSQL's is
-- `pg_current_xact_id()`.
CREATE TABLE IF NOT EXISTS sts_ldap_dek_counts (
  dek_id VARCHAR(255) NOT NULL,
  shard  SMALLINT     NOT NULL DEFAULT 0,
  n      BIGINT       NOT NULL DEFAULT 0,
  PRIMARY KEY (dek_id, shard)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_ldap_dek_deltas (
  txid   VARCHAR(64) NOT NULL,
  dek_id LONGTEXT    NOT NULL,
  n      BIGINT      NOT NULL,
  fold   BOOLEAN     NOT NULL DEFAULT false
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_ldap_dek_deltas_txid ON sts_ldap_dek_deltas (txid);

CREATE TABLE IF NOT EXISTS sts_ldap_counts (
  realm     VARCHAR(64)  NOT NULL,
  base_key  VARCHAR(352) NOT NULL,
  attribute VARCHAR(64)  NOT NULL,
  shard     SMALLINT     NOT NULL DEFAULT 0,
  n         BIGINT       NOT NULL DEFAULT 0,
  PRIMARY KEY (realm, base_key, attribute, shard)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_ldap_count_deltas (
  txid       VARCHAR(64) NOT NULL,
  realm      LONGTEXT    NOT NULL,
  parent_key LONGTEXT    NOT NULL,
  n          BIGINT      NOT NULL,
  holding    BIGINT      NOT NULL,
  fold       BOOLEAN     NOT NULL DEFAULT false
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_ldap_count_deltas_txid ON sts_ldap_count_deltas (txid);

-- ---------------------------------------------------------------------------
-- REALMS, SETTINGS, KEYS, WHAT WAS MINTED, SESSIONS, THE CHANGE LOG.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sts_realms (
  id          VARCHAR(64) NOT NULL,
  name        LONGTEXT,
  description LONGTEXT,
  created_at  BIGINT,
  overrides   JSON        NOT NULL DEFAULT '{}',
  domain      LONGTEXT,
  retiring_at BIGINT,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_appconfig (
  `key` VARCHAR(255) NOT NULL,
  value JSON         NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_keys (
  realm      VARCHAR(64) NOT NULL,
  material   LONGTEXT    NOT NULL,
  written_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (realm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_minted (
  handle     VARCHAR(64)  NOT NULL,
  realm      VARCHAR(64)  NOT NULL,
  `key`      VARCHAR(512) NOT NULL,
  body       LONGTEXT     NOT NULL,
  written_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at BIGINT,
  key_sealed LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (handle, realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm);
-- PostgreSQL's is the BRIN `sts_minted_written_brin`; this is the B-tree it
-- replaced there, under that B-tree's name.
CREATE INDEX IF NOT EXISTS sts_minted_written ON sts_minted (written_at);
CREATE INDEX IF NOT EXISTS sts_minted_expires ON sts_minted (expires_at);

CREATE TABLE IF NOT EXISTS sts_sessions (
  realm                VARCHAR(64)  NOT NULL,
  `key`                VARCHAR(512) NOT NULL,
  expires_at           BIGINT,
  last_seen_at         BIGINT       NOT NULL,
  started_at           BIGINT       NOT NULL,
  subject_key          VARCHAR(255) NOT NULL DEFAULT '',
  username_key         VARCHAR(255) NOT NULL DEFAULT '',
  chosen               BOOLEAN      NOT NULL,
  authenticated        BOOLEAN      NOT NULL,
  kind                 LONGTEXT     NOT NULL,
  rp_surface           VARCHAR(255) NOT NULL DEFAULT '',
  parent_key           VARCHAR(512) NOT NULL DEFAULT '',
  backs_console        BOOLEAN      NOT NULL DEFAULT false,
  credential_key       VARCHAR(255) NOT NULL DEFAULT '',
  partner_relationship VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

-- PostgreSQL's seven are partial (`WHERE … <> ''`, `chosen`, `IS NOT NULL`);
-- these are whole.
CREATE INDEX IF NOT EXISTS sts_sessions_subject ON sts_sessions (realm, subject_key, last_seen_at);
CREATE INDEX IF NOT EXISTS sts_sessions_username ON sts_sessions (realm, username_key);
CREATE INDEX IF NOT EXISTS sts_sessions_expires ON sts_sessions (realm, expires_at);
CREATE INDEX IF NOT EXISTS sts_sessions_parent ON sts_sessions (realm, parent_key);
CREATE INDEX IF NOT EXISTS sts_sessions_credential ON sts_sessions (realm, credential_key);
CREATE INDEX IF NOT EXISTS sts_sessions_partner ON sts_sessions (realm, partner_relationship);
CREATE INDEX IF NOT EXISTS sts_sessions_surface ON sts_sessions (realm, rp_surface);

CREATE TABLE IF NOT EXISTS sts_minted_index (
  handle    VARCHAR(64)  NOT NULL,
  realm     VARCHAR(64)  NOT NULL,
  index_key VARCHAR(128) NOT NULL,
  `key`     VARCHAR(512) NOT NULL,
  sort_at   BIGINT,
  PRIMARY KEY (handle, realm, index_key, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_minted_index_key ON sts_minted_index (handle, realm, `key`);
CREATE INDEX IF NOT EXISTS sts_minted_index_sort ON sts_minted_index (handle, realm, sort_at DESC, `key` DESC);

CREATE TABLE IF NOT EXISTS sts_changes (
  seq    BIGINT      NOT NULL AUTO_INCREMENT,
  origin LONGTEXT    NOT NULL,
  kind   LONGTEXT    NOT NULL,
  realm  LONGTEXT    NOT NULL DEFAULT '',
  `key`  LONGTEXT    NOT NULL DEFAULT '',
  at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at);

CREATE TABLE IF NOT EXISTS sts_used_assertions (
  realm       VARCHAR(64)  NOT NULL,
  `key`       VARCHAR(512) NOT NULL,
  format      LONGTEXT     NOT NULL,
  used_as     LONGTEXT     NOT NULL,
  issuer      LONGTEXT     NOT NULL,
  identifier  LONGTEXT     NOT NULL,
  client_id   LONGTEXT     NOT NULL DEFAULT '',
  subject     LONGTEXT     NOT NULL DEFAULT '',
  state       LONGTEXT     NOT NULL,
  reservation LONGTEXT     NOT NULL,
  origin      LONGTEXT     NOT NULL DEFAULT '',
  used_at     BIGINT       NOT NULL,
  spent_at    BIGINT       NOT NULL DEFAULT 0,
  expires_at  BIGINT       NOT NULL,
  PRIMARY KEY (realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON sts_used_assertions (realm, expires_at);

-- ---------------------------------------------------------------------------
-- THE CLUSTER.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sts_cluster_nodes (
  node_id      VARCHAR(255) NOT NULL,
  name         LONGTEXT     NOT NULL DEFAULT '',
  mode         LONGTEXT     NOT NULL,
  version      LONGTEXT     NOT NULL DEFAULT '',
  fingerprint  LONGTEXT     NOT NULL DEFAULT '',
  started_at   BIGINT       NOT NULL,
  heartbeat_at BIGINT       NOT NULL,
  expires_at   BIGINT       NOT NULL,
  left_at      BIGINT       NOT NULL DEFAULT 0,
  info         JSON         NOT NULL DEFAULT '{}',
  PRIMARY KEY (node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON sts_cluster_nodes (expires_at);

CREATE TABLE IF NOT EXISTS sts_cluster_leases (
  name        VARCHAR(255) NOT NULL,
  holder      LONGTEXT     NOT NULL,
  token       BIGINT       NOT NULL,
  acquired_at BIGINT       NOT NULL,
  expires_at  BIGINT       NOT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_cluster_claims (
  scope       VARCHAR(128) NOT NULL,
  realm       VARCHAR(64)  NOT NULL,
  `key`       VARCHAR(512) NOT NULL,
  reservation LONGTEXT     NOT NULL,
  origin      LONGTEXT     NOT NULL DEFAULT '',
  claimed_at  BIGINT       NOT NULL,
  expires_at  BIGINT       NOT NULL,
  PRIMARY KEY (scope, realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON sts_cluster_claims (expires_at);

CREATE TABLE IF NOT EXISTS sts_cluster_secrets (
  name       VARCHAR(255) NOT NULL,
  material   LONGTEXT     NOT NULL,
  created_by LONGTEXT     NOT NULL DEFAULT '',
  created_at BIGINT       NOT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_cluster_locks (
  name VARCHAR(255) NOT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_cluster_counters (
  scope      VARCHAR(128) NOT NULL,
  realm      VARCHAR(64)  NOT NULL,
  `key`      VARCHAR(512) NOT NULL,
  value      BIGINT       NOT NULL,
  origin     LONGTEXT     NOT NULL DEFAULT '',
  updated_at BIGINT       NOT NULL,
  PRIMARY KEY (scope, realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_cluster_windows (
  scope          VARCHAR(128) NOT NULL,
  realm          VARCHAR(64)  NOT NULL,
  `key`          VARCHAR(512) NOT NULL,
  count          BIGINT       NOT NULL,
  window_ends_at BIGINT       NOT NULL,
  origin         LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (scope, realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON sts_cluster_windows (window_ends_at);

CREATE TABLE IF NOT EXISTS sts_cluster_budgets (
  scope      VARCHAR(128) NOT NULL,
  realm      VARCHAR(64)  NOT NULL,
  `key`      VARCHAR(512) NOT NULL,
  period     BIGINT       NOT NULL,
  amount     BIGINT       NOT NULL,
  count      BIGINT       NOT NULL,
  origin     LONGTEXT     NOT NULL DEFAULT '',
  expires_at BIGINT       NOT NULL,
  updated_at BIGINT       NOT NULL,
  PRIMARY KEY (scope, realm, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_cluster_budgets_expiry ON sts_cluster_budgets (expires_at);

CREATE TABLE IF NOT EXISTS sts_node_snapshots (
  name     VARCHAR(255) NOT NULL,
  node_id  LONGTEXT     NOT NULL DEFAULT '',
  taken_at BIGINT       NOT NULL,
  body     JSON         NOT NULL DEFAULT '{}',
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_change_readers (
  origin      VARCHAR(255) NOT NULL,
  node_id     LONGTEXT     NOT NULL DEFAULT '',
  applied     BIGINT       NOT NULL,
  started_at  BIGINT       NOT NULL,
  reported_at BIGINT       NOT NULL,
  PRIMARY KEY (origin)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

-- ---------------------------------------------------------------------------
-- RISK SCORING.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sts_risk_datasets (
  realm            VARCHAR(64)  NOT NULL DEFAULT '',
  dataset          VARCHAR(128) NOT NULL,
  kind             LONGTEXT     NOT NULL,
  active_version   LONGTEXT     NOT NULL DEFAULT '',
  previous_version LONGTEXT     NOT NULL DEFAULT '',
  state            LONGTEXT     NOT NULL,
  updated_at       BIGINT       NOT NULL,
  PRIMARY KEY (realm, dataset)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_dataset_versions (
  realm           VARCHAR(64)  NOT NULL DEFAULT '',
  dataset         VARCHAR(128) NOT NULL,
  version         VARCHAR(128) NOT NULL,
  format          LONGTEXT     NOT NULL,
  provider        LONGTEXT     NOT NULL,
  licence         LONGTEXT     NOT NULL,
  attribution     LONGTEXT     NOT NULL DEFAULT '',
  source          LONGTEXT     NOT NULL,
  source_uri      LONGTEXT     NOT NULL DEFAULT '',
  sha256          LONGTEXT     NOT NULL,
  byte_count      BIGINT       NOT NULL,
  row_count       BIGINT       NOT NULL DEFAULT 0,
  parameters      JSON         NOT NULL DEFAULT '{}',
  verification    LONGTEXT     NOT NULL,
  published_at    BIGINT       NOT NULL,
  next_update_at  BIGINT       NOT NULL DEFAULT 0,
  fetched_at      BIGINT       NOT NULL,
  loaded_at       BIGINT       NOT NULL DEFAULT 0,
  activated_at    BIGINT       NOT NULL DEFAULT 0,
  superseded_at   BIGINT       NOT NULL DEFAULT 0,
  rows_deleted_at BIGINT       NOT NULL DEFAULT 0,
  state           LONGTEXT     NOT NULL,
  refusal         LONGTEXT     NOT NULL DEFAULT '',
  error_code      LONGTEXT     NOT NULL DEFAULT '',
  origin          LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (realm, dataset, version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_dataset_blobs (
  realm   VARCHAR(64)  NOT NULL DEFAULT '',
  dataset VARCHAR(128) NOT NULL,
  version VARCHAR(128) NOT NULL,
  part    INT          NOT NULL,
  content LONGBLOB     NOT NULL,
  PRIMARY KEY (realm, dataset, version, part)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_geo_locations (
  dataset     VARCHAR(128) NOT NULL,
  version     VARCHAR(128) NOT NULL,
  location_id BIGINT       NOT NULL,
  continent   LONGTEXT     NOT NULL DEFAULT '',
  country     LONGTEXT     NOT NULL DEFAULT '',
  subdivision LONGTEXT     NOT NULL DEFAULT '',
  city        LONGTEXT     NOT NULL DEFAULT '',
  time_zone   LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (dataset, version, location_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_geo_ranges (
  dataset            VARCHAR(128) NOT NULL,
  version            VARCHAR(128) NOT NULL,
  range_start        INET6        NOT NULL,
  range_end          INET6        NOT NULL,
  location_id        BIGINT       NOT NULL DEFAULT 0,
  continent          LONGTEXT     NOT NULL DEFAULT '',
  country            LONGTEXT     NOT NULL DEFAULT '',
  subdivision        LONGTEXT     NOT NULL DEFAULT '',
  city               LONGTEXT     NOT NULL DEFAULT '',
  registered_country LONGTEXT     NOT NULL DEFAULT '',
  latitude           DOUBLE,
  longitude          DOUBLE,
  accuracy_km        INT          NOT NULL DEFAULT 0,
  anonymous_proxy    BOOLEAN      NOT NULL DEFAULT false,
  satellite          BOOLEAN      NOT NULL DEFAULT false,
  PRIMARY KEY (dataset, version, range_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_asn_ranges (
  dataset     VARCHAR(128) NOT NULL,
  version     VARCHAR(128) NOT NULL,
  range_start INET6        NOT NULL,
  range_end   INET6        NOT NULL,
  asn         BIGINT       NOT NULL,
  as_org      LONGTEXT     NOT NULL DEFAULT '',
  as_domain   LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (dataset, version, range_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_ip_lists (
  realm       VARCHAR(64)  NOT NULL DEFAULT '',
  dataset     VARCHAR(128) NOT NULL,
  version     VARCHAR(128) NOT NULL,
  range_start INET6        NOT NULL,
  range_end   INET6        NOT NULL,
  category    LONGTEXT     NOT NULL,
  note        LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (realm, dataset, version, range_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_fido_authenticators (
  dataset             VARCHAR(128) NOT NULL,
  version             VARCHAR(128) NOT NULL,
  key_kind            VARCHAR(32)  NOT NULL,
  authenticator_key   VARCHAR(255) NOT NULL,
  description         LONGTEXT     NOT NULL DEFAULT '',
  protocol_family     LONGTEXT     NOT NULL DEFAULT '',
  certification_level LONGTEXT     NOT NULL DEFAULT '',
  latest_status       LONGTEXT     NOT NULL DEFAULT '',
  latest_status_at    BIGINT       NOT NULL DEFAULT 0,
  compromised         BOOLEAN      NOT NULL DEFAULT false,
  status_reports      JSON         NOT NULL DEFAULT '[]',
  metadata_statement  JSON         NOT NULL DEFAULT '{}',
  PRIMARY KEY (dataset, version, key_kind, authenticator_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON sts_risk_fido_authenticators (key_kind, authenticator_key);

CREATE TABLE IF NOT EXISTS sts_risk_assessments (
  realm              VARCHAR(64)  NOT NULL,
  id                 VARCHAR(255) NOT NULL,
  at                 BIGINT       NOT NULL,
  phase              LONGTEXT     NOT NULL,
  door               LONGTEXT     NOT NULL,
  subject            VARCHAR(255) NOT NULL DEFAULT '',
  session_id         VARCHAR(255) NOT NULL DEFAULT '',
  client_id          LONGTEXT     NOT NULL DEFAULT '',
  address_sealed     LONGTEXT     NOT NULL,
  address_prefix     VARCHAR(50)  NOT NULL,
  asn                BIGINT       NOT NULL DEFAULT 0,
  as_org             LONGTEXT     NOT NULL DEFAULT '',
  country            LONGTEXT     NOT NULL DEFAULT '',
  subdivision        LONGTEXT     NOT NULL DEFAULT '',
  city               LONGTEXT     NOT NULL DEFAULT '',
  latitude           DOUBLE,
  longitude          DOUBLE,
  accuracy_km        INT          NOT NULL DEFAULT 0,
  ip_lists           JSON         NOT NULL DEFAULT '[]',
  ua_hash            LONGTEXT     NOT NULL DEFAULT '',
  ua_family          LONGTEXT     NOT NULL DEFAULT '',
  ua_os              LONGTEXT     NOT NULL DEFAULT '',
  ua_platform        LONGTEXT     NOT NULL DEFAULT '',
  bot                BOOLEAN      NOT NULL DEFAULT false,
  ja4                LONGTEXT     NOT NULL DEFAULT '',
  credential_kind    LONGTEXT     NOT NULL DEFAULT '',
  credential_hash    LONGTEXT     NOT NULL DEFAULT '',
  aaguid             LONGTEXT     NOT NULL DEFAULT '',
  authenticator_cert LONGTEXT     NOT NULL DEFAULT '',
  backup_eligible    BOOLEAN,
  backup_state       BOOLEAN,
  jkt                LONGTEXT     NOT NULL DEFAULT '',
  cert_fingerprint   LONGTEXT     NOT NULL DEFAULT '',
  datasets           JSON         NOT NULL DEFAULT '{}',
  signals            JSON         NOT NULL DEFAULT '[]',
  score              FLOAT        NOT NULL,
  level              LONGTEXT     NOT NULL,
  decision           LONGTEXT     NOT NULL,
  policy_id          LONGTEXT     NOT NULL DEFAULT '',
  error_code         LONGTEXT     NOT NULL DEFAULT '',
  origin             LONGTEXT     NOT NULL DEFAULT '',
  feedback           LONGTEXT     NOT NULL DEFAULT '',
  feedback_at        BIGINT       NOT NULL DEFAULT 0,
  PRIMARY KEY (realm, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON sts_risk_assessments (realm, subject, at);
CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON sts_risk_assessments (realm, session_id);
CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON sts_risk_assessments (at);

CREATE TABLE IF NOT EXISTS sts_risk_feature_counts (
  realm    VARCHAR(64)  NOT NULL,
  subject  VARCHAR(255) NOT NULL,
  feature  VARCHAR(64)  NOT NULL,
  value    VARCHAR(255) NOT NULL,
  count    BIGINT       NOT NULL,
  first_at BIGINT       NOT NULL,
  last_at  BIGINT       NOT NULL,
  PRIMARY KEY (realm, subject, feature, value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON sts_risk_feature_counts (realm, last_at);

-- `id` is PostgreSQL's `bigserial`; InnoDB wants an AUTO_INCREMENT column
-- first in some index, and the primary key starts with `realm`, so the table
-- carries `KEY (id)` as well.
CREATE TABLE IF NOT EXISTS sts_risk_failures (
  realm          VARCHAR(64)  NOT NULL,
  id             BIGINT       NOT NULL AUTO_INCREMENT,
  at             BIGINT       NOT NULL,
  door           LONGTEXT     NOT NULL,
  subject        VARCHAR(255) NOT NULL DEFAULT '',
  name_hmac      VARCHAR(255) NOT NULL DEFAULT '',
  address_sealed LONGTEXT     NOT NULL,
  address_prefix VARCHAR(50)  NOT NULL,
  asn            BIGINT       NOT NULL DEFAULT 0,
  error_code     LONGTEXT     NOT NULL,
  origin         LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (realm, id),
  KEY sts_risk_failures_id (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON sts_risk_failures (realm, subject, at);
CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON sts_risk_failures (realm, name_hmac, at);
CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON sts_risk_failures (realm, address_prefix, at);
CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON sts_risk_failures (at);

CREATE TABLE IF NOT EXISTS sts_risk_session_context (
  realm          VARCHAR(64)  NOT NULL,
  session_id     VARCHAR(255) NOT NULL,
  subject        LONGTEXT     NOT NULL,
  address_prefix VARCHAR(50)  NOT NULL,
  asn            BIGINT       NOT NULL DEFAULT 0,
  country        LONGTEXT     NOT NULL DEFAULT '',
  ua_hash        LONGTEXT     NOT NULL DEFAULT '',
  ja4            LONGTEXT     NOT NULL DEFAULT '',
  jkt            LONGTEXT     NOT NULL DEFAULT '',
  score          FLOAT        NOT NULL,
  level          LONGTEXT     NOT NULL,
  updated_at     BIGINT       NOT NULL,
  PRIMARY KEY (realm, session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_subjects (
  realm           VARCHAR(64)  NOT NULL,
  subject         VARCHAR(255) NOT NULL,
  score           FLOAT        NOT NULL,
  level           LONGTEXT     NOT NULL,
  previous_level  LONGTEXT     NOT NULL DEFAULT '',
  reason          LONGTEXT     NOT NULL DEFAULT '',
  last_assessment LONGTEXT     NOT NULL DEFAULT '',
  crossed_at      BIGINT       NOT NULL DEFAULT 0,
  actions         JSON         NOT NULL DEFAULT '{}',
  feedback        LONGTEXT     NOT NULL DEFAULT '',
  updated_at      BIGINT       NOT NULL,
  PRIMARY KEY (realm, subject)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_risk_terms_acceptances (
  id           BIGINT       NOT NULL AUTO_INCREMENT,
  provider     VARCHAR(128) NOT NULL,
  terms_digest LONGTEXT     NOT NULL,
  terms_text   LONGTEXT     NOT NULL,
  accepted_by  LONGTEXT     NOT NULL,
  accepted_via LONGTEXT     NOT NULL,
  deployment   LONGTEXT     NOT NULL DEFAULT '',
  page_digest  LONGTEXT     NOT NULL DEFAULT '',
  accepted_at  BIGINT       NOT NULL,
  origin       LONGTEXT     NOT NULL DEFAULT '',
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON sts_risk_terms_acceptances (provider, accepted_at);

-- ---------------------------------------------------------------------------
-- CELLS, REPORTS, AND THE VERSION.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sts_cell_routing (
  realm      VARCHAR(64)  NOT NULL,
  kind       VARCHAR(64)  NOT NULL,
  digest     VARCHAR(255) NOT NULL,
  cell       LONGTEXT     NOT NULL,
  written_at BIGINT       NOT NULL,
  PRIMARY KEY (realm, kind, digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_report_artifacts (
  realm      VARCHAR(64)  NOT NULL,
  job_id     VARCHAR(255) NOT NULL,
  bytes      LONGBLOB     NOT NULL,
  sha256     LONGTEXT     NOT NULL,
  media_type LONGTEXT     NOT NULL,
  created_at BIGINT       NOT NULL,
  PRIMARY KEY (realm, job_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_report_artifact_pieces (
  realm  VARCHAR(64)  NOT NULL,
  job_id VARCHAR(255) NOT NULL,
  seq    INT          NOT NULL,
  bytes  LONGBLOB     NOT NULL,
  PRIMARY KEY (realm, job_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

CREATE TABLE IF NOT EXISTS sts_schema (
  version    INT         NOT NULL,
  applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;

-- The same number as PostgreSQL's, so there is one SCHEMA_VERSION.
INSERT IGNORE INTO sts_schema (version) VALUES (30);

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
