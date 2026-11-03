// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: schema_mariadb.js
//
// ---------------------------------------------------------------------------
// THE STORE'S SCHEMA ON MARIADB, AS THE DRIVER HOLDS IT (#677).
//
// PostgreSQL is and stays the primary store; MariaDB 11.8 is the second
// engine the suite runs against. `mariadb/schema.sql` is the schema an OWNER
// builds there, with the least-privileged account the service dials with,
// and this module is its SECOND COPY: every CREATE TABLE and CREATE INDEX in
// that file, in its order, as `{ name, statement }` — the same shape as
// `persistence_postgres.js`'s SCHEMA_OBJECTS, so a driver can probe each
// object by name and create only what is missing, for the reason that file
// gives (a role that may not CREATE is otherwise refused on every start).
//
// **THE TWO COPIES ARE THE SAME STATEMENTS, MODULO WHITESPACE: EDIT BOTH IN
// ONE CHANGE.** A column in one and not the other gives a database one column
// short and a service not allowed to add it. Runs of spaces that align the
// columns in the `.sql` file are one space here; nothing else differs. The
// reasoning for each type and size — and every PostgreSQL feature with no
// MariaDB form (GIN, partial and BRIN indexes, the counting triggers, the
// storage parameters) and what replaces it — is `mariadb/CLAUDE.md`'s, and
// is deliberately not repeated beside each statement.
//
// WHAT IS NOT HERE, BECAUSE POSTGRESQL'S DRIVER NEEDS IT ONLY FOR AN OLDER
// DATABASE: no SCHEMA_COLUMNS, SCHEMA_UPGRADES, SCHEMA_RETIRED or
// SCHEMA_RELOPTIONS. Every MariaDB store is built at this version, so there
// is no older shape to bring forward — the first change to THIS schema
// after it is the one that will need them. (31, #1290, rebuilt only
// PostgreSQL's asked-names index, which MariaDB has no copy of: its key
// table holds every name. The number moves with PostgreSQL's all the same,
// so a store says one version on either engine — `tests/mariadb_schema.js`
// B1 fails when the two differ.) And no SCHEMA_ROUTINES: on this
// engine the driver keeps `sts_ldap_counts` and `sts_ldap_dek_counts` itself,
// because MariaDB has no statement-level trigger to do it.
//
// A LEAF WITH NO NAMED FUNCTION: it requires nothing and logs nothing, so
// the Entering/Leaving rule has nothing to apply to.
// ---------------------------------------------------------------------------

/**
 * The schema version these statements build — the same number as
 * PostgreSQL's (`persistence_postgres.js`), so there is one SCHEMA_VERSION.
 */
const SCHEMA_VERSION = 31;

/**
 * Every table and index of the MariaDB schema, each `{ name, statement }`, in
 * creation order; each statement is `mariadb/schema.sql`'s, without its
 * semicolon.
 */
const SCHEMA_OBJECTS = [
  { name: 'sts_ldap_entries', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_entries (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  dn_key VARCHAR(352) NOT NULL,' +
  '  dn LONGTEXT NOT NULL,' +
  '  attrs JSON NOT NULL,' +
  '  origin LONGTEXT,' +
  '  created_at VARCHAR(32),' +
  '  modified_at VARCHAR(32),' +
  '  parent_key VARCHAR(352) GENERATED ALWAYS AS (CASE WHEN LOCATE(\',\', ' +
  'dn_key) > 0 THEN SUBSTRING(dn_key, LOCATE(\',\', dn_key) + 1) ELSE \'\' ' +
  'END) STORED,' +
  '  rdn_value VARCHAR(352) GENERATED ALWAYS AS ' +
  '(SUBSTRING(SUBSTRING_INDEX(dn_key, \',\', 1), LOCATE(\'=\', ' +
  'SUBSTRING_INDEX(dn_key, \',\', 1)) + 1)) STORED,' +
  '  name_keys JSON NOT NULL DEFAULT \'[]\',' +
  '  mail_keys JSON NOT NULL DEFAULT \'[]\',' +
  '  uuid_keys JSON NOT NULL DEFAULT \'[]\',' +
  '  class_keys JSON NOT NULL DEFAULT \'[]\',' +
  '  value_keys JSON NOT NULL DEFAULT \'[]\',' +
  '  attr_names JSON NOT NULL DEFAULT \'[]\',' +
  '  dek_keys JSON,' +
  '  PRIMARY KEY (realm, dn_key)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_ldap_entries_realm', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries ' +
  '(realm)' },
  { name: 'sts_ldap_entries_parent', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_parent ON sts_ldap_entries ' +
  '(realm, parent_key, dn_key)' },
  { name: 'sts_ldap_entries_rdn', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_rdn ON sts_ldap_entries ' +
  '(realm, parent_key, rdn_value)' },
  { name: 'sts_ldap_entries_created', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_created ON sts_ldap_entries ' +
  '(realm, parent_key, created_at)' },
  { name: 'sts_ldap_entries_modified', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_modified ON sts_ldap_entries ' +
  '(realm, parent_key, modified_at)' },
  { name: 'sts_ldap_entry_keys', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_entry_keys (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  kind VARCHAR(8) NOT NULL,' +
  '  k VARCHAR(344) NOT NULL,' +
  '  dn_key VARCHAR(352) NOT NULL,' +
  '  PRIMARY KEY (realm, kind, k, dn_key),' +
  '  CONSTRAINT sts_ldap_entry_keys_kind CHECK (kind IN (\'name\', ' +
  '\'mail\', \'uuid\', \'class\', \'value\', \'attr\', \'dek\'))' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_ldap_entry_keys_entry', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entry_keys_entry ON ' +
  'sts_ldap_entry_keys (realm, dn_key)' },
  { name: 'sts_ldap_dek_counts', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_dek_counts (' +
  '  dek_id VARCHAR(255) NOT NULL,' +
  '  shard SMALLINT NOT NULL DEFAULT 0,' +
  '  n BIGINT NOT NULL DEFAULT 0,' +
  '  PRIMARY KEY (dek_id, shard)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_ldap_dek_deltas', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_dek_deltas (' +
  '  txid VARCHAR(64) NOT NULL,' +
  '  dek_id LONGTEXT NOT NULL,' +
  '  n BIGINT NOT NULL,' +
  '  fold BOOLEAN NOT NULL DEFAULT false' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_ldap_dek_deltas_txid', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_dek_deltas_txid ON ' +
  'sts_ldap_dek_deltas (txid)' },
  { name: 'sts_ldap_counts', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_counts (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  base_key VARCHAR(352) NOT NULL,' +
  '  attribute VARCHAR(64) NOT NULL,' +
  '  shard SMALLINT NOT NULL DEFAULT 0,' +
  '  n BIGINT NOT NULL DEFAULT 0,' +
  '  PRIMARY KEY (realm, base_key, attribute, shard)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_ldap_count_deltas', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_count_deltas (' +
  '  txid VARCHAR(64) NOT NULL,' +
  '  realm LONGTEXT NOT NULL,' +
  '  parent_key LONGTEXT NOT NULL,' +
  '  n BIGINT NOT NULL,' +
  '  holding BIGINT NOT NULL,' +
  '  fold BOOLEAN NOT NULL DEFAULT false' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_ldap_count_deltas_txid', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_count_deltas_txid ON ' +
  'sts_ldap_count_deltas (txid)' },
  { name: 'sts_realms', statement:
  'CREATE TABLE IF NOT EXISTS sts_realms (' +
  '  id VARCHAR(64) NOT NULL,' +
  '  name LONGTEXT,' +
  '  description LONGTEXT,' +
  '  created_at BIGINT,' +
  '  overrides JSON NOT NULL DEFAULT \'{}\',' +
  '  domain LONGTEXT,' +
  '  retiring_at BIGINT,' +
  '  PRIMARY KEY (id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_appconfig', statement:
  'CREATE TABLE IF NOT EXISTS sts_appconfig (' +
  '  `key` VARCHAR(255) NOT NULL,' +
  '  value JSON NOT NULL,' +
  '  PRIMARY KEY (`key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_keys', statement:
  'CREATE TABLE IF NOT EXISTS sts_keys (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  material LONGTEXT NOT NULL,' +
  '  written_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),' +
  '  PRIMARY KEY (realm)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_minted', statement:
  'CREATE TABLE IF NOT EXISTS sts_minted (' +
  '  handle VARCHAR(64) NOT NULL,' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  body LONGTEXT NOT NULL,' +
  '  written_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),' +
  '  expires_at BIGINT,' +
  '  key_sealed LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (handle, realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_minted_handle', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, ' +
  'realm)' },
  { name: 'sts_minted_written', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_written ON sts_minted (written_at)' },
  { name: 'sts_minted_expires', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_expires ON sts_minted (expires_at)' },
  { name: 'sts_sessions', statement:
  'CREATE TABLE IF NOT EXISTS sts_sessions (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  expires_at BIGINT,' +
  '  last_seen_at BIGINT NOT NULL,' +
  '  started_at BIGINT NOT NULL,' +
  '  subject_key VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  username_key VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  chosen BOOLEAN NOT NULL,' +
  '  authenticated BOOLEAN NOT NULL,' +
  '  kind LONGTEXT NOT NULL,' +
  '  rp_surface VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  parent_key VARCHAR(512) NOT NULL DEFAULT \'\',' +
  '  backs_console BOOLEAN NOT NULL DEFAULT false,' +
  '  credential_key VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  partner_relationship VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_sessions_subject', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_subject ON sts_sessions (realm, ' +
  'subject_key, last_seen_at)' },
  { name: 'sts_sessions_username', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_username ON sts_sessions (realm, ' +
  'username_key)' },
  { name: 'sts_sessions_expires', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_expires ON sts_sessions (realm, ' +
  'expires_at)' },
  { name: 'sts_sessions_parent', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_parent ON sts_sessions (realm, ' +
  'parent_key)' },
  { name: 'sts_sessions_credential', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_credential ON sts_sessions ' +
  '(realm, credential_key)' },
  { name: 'sts_sessions_partner', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_partner ON sts_sessions (realm, ' +
  'partner_relationship)' },
  { name: 'sts_sessions_surface', statement:
  'CREATE INDEX IF NOT EXISTS sts_sessions_surface ON sts_sessions (realm, ' +
  'rp_surface)' },
  { name: 'sts_minted_index', statement:
  'CREATE TABLE IF NOT EXISTS sts_minted_index (' +
  '  handle VARCHAR(64) NOT NULL,' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  index_key VARCHAR(128) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  sort_at BIGINT,' +
  '  PRIMARY KEY (handle, realm, index_key, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_minted_index_key', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_index_key ON sts_minted_index ' +
  '(handle, realm, `key`)' },
  { name: 'sts_minted_index_sort', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_index_sort ON sts_minted_index ' +
  '(handle, realm, sort_at DESC, `key` DESC)' },
  { name: 'sts_changes', statement:
  'CREATE TABLE IF NOT EXISTS sts_changes (' +
  '  seq BIGINT NOT NULL AUTO_INCREMENT,' +
  '  origin LONGTEXT NOT NULL,' +
  '  kind LONGTEXT NOT NULL,' +
  '  realm LONGTEXT NOT NULL DEFAULT \'\',' +
  '  `key` LONGTEXT NOT NULL DEFAULT \'\',' +
  '  at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),' +
  '  PRIMARY KEY (seq)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_changes_at', statement:
  'CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at)' },
  { name: 'sts_used_assertions', statement:
  'CREATE TABLE IF NOT EXISTS sts_used_assertions (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  format LONGTEXT NOT NULL,' +
  '  used_as LONGTEXT NOT NULL,' +
  '  issuer LONGTEXT NOT NULL,' +
  '  identifier LONGTEXT NOT NULL,' +
  '  client_id LONGTEXT NOT NULL DEFAULT \'\',' +
  '  subject LONGTEXT NOT NULL DEFAULT \'\',' +
  '  state LONGTEXT NOT NULL,' +
  '  reservation LONGTEXT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  used_at BIGINT NOT NULL,' +
  '  spent_at BIGINT NOT NULL DEFAULT 0,' +
  '  expires_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_used_assertions_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON ' +
  'sts_used_assertions (realm, expires_at)' },
  { name: 'sts_cluster_nodes', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_nodes (' +
  '  node_id VARCHAR(255) NOT NULL,' +
  '  name LONGTEXT NOT NULL DEFAULT \'\',' +
  '  mode LONGTEXT NOT NULL,' +
  '  version LONGTEXT NOT NULL DEFAULT \'\',' +
  '  fingerprint LONGTEXT NOT NULL DEFAULT \'\',' +
  '  started_at BIGINT NOT NULL,' +
  '  heartbeat_at BIGINT NOT NULL,' +
  '  expires_at BIGINT NOT NULL,' +
  '  left_at BIGINT NOT NULL DEFAULT 0,' +
  '  info JSON NOT NULL DEFAULT \'{}\',' +
  '  PRIMARY KEY (node_id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_nodes_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON sts_cluster_nodes ' +
  '(expires_at)' },
  { name: 'sts_cluster_leases', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_leases (' +
  '  name VARCHAR(255) NOT NULL,' +
  '  holder LONGTEXT NOT NULL,' +
  '  token BIGINT NOT NULL,' +
  '  acquired_at BIGINT NOT NULL,' +
  '  expires_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (name)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_claims', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_claims (' +
  '  scope VARCHAR(128) NOT NULL,' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  reservation LONGTEXT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  claimed_at BIGINT NOT NULL,' +
  '  expires_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (scope, realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_claims_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON ' +
  'sts_cluster_claims (expires_at)' },
  { name: 'sts_cluster_secrets', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_secrets (' +
  '  name VARCHAR(255) NOT NULL,' +
  '  material LONGTEXT NOT NULL,' +
  '  created_by LONGTEXT NOT NULL DEFAULT \'\',' +
  '  created_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (name)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_locks', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_locks (' +
  '  name VARCHAR(255) NOT NULL,' +
  '  PRIMARY KEY (name)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_counters', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_counters (' +
  '  scope VARCHAR(128) NOT NULL,' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  value BIGINT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  updated_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (scope, realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_windows', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_windows (' +
  '  scope VARCHAR(128) NOT NULL,' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  count BIGINT NOT NULL,' +
  '  window_ends_at BIGINT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (scope, realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_windows_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON ' +
  'sts_cluster_windows (window_ends_at)' },
  { name: 'sts_cluster_budgets', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_budgets (' +
  '  scope VARCHAR(128) NOT NULL,' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  `key` VARCHAR(512) NOT NULL,' +
  '  period BIGINT NOT NULL,' +
  '  amount BIGINT NOT NULL,' +
  '  count BIGINT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  expires_at BIGINT NOT NULL,' +
  '  updated_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (scope, realm, `key`)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_cluster_budgets_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_budgets_expiry ON ' +
  'sts_cluster_budgets (expires_at)' },
  { name: 'sts_node_snapshots', statement:
  'CREATE TABLE IF NOT EXISTS sts_node_snapshots (' +
  '  name VARCHAR(255) NOT NULL,' +
  '  node_id LONGTEXT NOT NULL DEFAULT \'\',' +
  '  taken_at BIGINT NOT NULL,' +
  '  body JSON NOT NULL DEFAULT \'{}\',' +
  '  PRIMARY KEY (name)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_change_readers', statement:
  'CREATE TABLE IF NOT EXISTS sts_change_readers (' +
  '  origin VARCHAR(255) NOT NULL,' +
  '  node_id LONGTEXT NOT NULL DEFAULT \'\',' +
  '  applied BIGINT NOT NULL,' +
  '  started_at BIGINT NOT NULL,' +
  '  reported_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (origin)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_datasets', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_datasets (' +
  '  realm VARCHAR(64) NOT NULL DEFAULT \'\',' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  kind LONGTEXT NOT NULL,' +
  '  active_version LONGTEXT NOT NULL DEFAULT \'\',' +
  '  previous_version LONGTEXT NOT NULL DEFAULT \'\',' +
  '  state LONGTEXT NOT NULL,' +
  '  updated_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, dataset)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_dataset_versions', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_dataset_versions (' +
  '  realm VARCHAR(64) NOT NULL DEFAULT \'\',' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  format LONGTEXT NOT NULL,' +
  '  provider LONGTEXT NOT NULL,' +
  '  licence LONGTEXT NOT NULL,' +
  '  attribution LONGTEXT NOT NULL DEFAULT \'\',' +
  '  source LONGTEXT NOT NULL,' +
  '  source_uri LONGTEXT NOT NULL DEFAULT \'\',' +
  '  sha256 LONGTEXT NOT NULL,' +
  '  byte_count BIGINT NOT NULL,' +
  '  row_count BIGINT NOT NULL DEFAULT 0,' +
  '  parameters JSON NOT NULL DEFAULT \'{}\',' +
  '  verification LONGTEXT NOT NULL,' +
  '  published_at BIGINT NOT NULL,' +
  '  next_update_at BIGINT NOT NULL DEFAULT 0,' +
  '  fetched_at BIGINT NOT NULL,' +
  '  loaded_at BIGINT NOT NULL DEFAULT 0,' +
  '  activated_at BIGINT NOT NULL DEFAULT 0,' +
  '  superseded_at BIGINT NOT NULL DEFAULT 0,' +
  '  rows_deleted_at BIGINT NOT NULL DEFAULT 0,' +
  '  state LONGTEXT NOT NULL,' +
  '  refusal LONGTEXT NOT NULL DEFAULT \'\',' +
  '  error_code LONGTEXT NOT NULL DEFAULT \'\',' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, dataset, version)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_dataset_blobs', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_dataset_blobs (' +
  '  realm VARCHAR(64) NOT NULL DEFAULT \'\',' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  part INT NOT NULL,' +
  '  content LONGBLOB NOT NULL,' +
  '  PRIMARY KEY (realm, dataset, version, part)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_geo_locations', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_geo_locations (' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  location_id BIGINT NOT NULL,' +
  '  continent LONGTEXT NOT NULL DEFAULT \'\',' +
  '  country LONGTEXT NOT NULL DEFAULT \'\',' +
  '  subdivision LONGTEXT NOT NULL DEFAULT \'\',' +
  '  city LONGTEXT NOT NULL DEFAULT \'\',' +
  '  time_zone LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (dataset, version, location_id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_geo_ranges', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_geo_ranges (' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  range_start INET6 NOT NULL,' +
  '  range_end INET6 NOT NULL,' +
  '  location_id BIGINT NOT NULL DEFAULT 0,' +
  '  continent LONGTEXT NOT NULL DEFAULT \'\',' +
  '  country LONGTEXT NOT NULL DEFAULT \'\',' +
  '  subdivision LONGTEXT NOT NULL DEFAULT \'\',' +
  '  city LONGTEXT NOT NULL DEFAULT \'\',' +
  '  registered_country LONGTEXT NOT NULL DEFAULT \'\',' +
  '  latitude DOUBLE,' +
  '  longitude DOUBLE,' +
  '  accuracy_km INT NOT NULL DEFAULT 0,' +
  '  anonymous_proxy BOOLEAN NOT NULL DEFAULT false,' +
  '  satellite BOOLEAN NOT NULL DEFAULT false,' +
  '  PRIMARY KEY (dataset, version, range_start)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_asn_ranges', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_asn_ranges (' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  range_start INET6 NOT NULL,' +
  '  range_end INET6 NOT NULL,' +
  '  asn BIGINT NOT NULL,' +
  '  as_org LONGTEXT NOT NULL DEFAULT \'\',' +
  '  as_domain LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (dataset, version, range_start)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_ip_lists', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_ip_lists (' +
  '  realm VARCHAR(64) NOT NULL DEFAULT \'\',' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  range_start INET6 NOT NULL,' +
  '  range_end INET6 NOT NULL,' +
  '  category LONGTEXT NOT NULL,' +
  '  note LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, dataset, version, range_start)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_fido_authenticators', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_fido_authenticators (' +
  '  dataset VARCHAR(128) NOT NULL,' +
  '  version VARCHAR(128) NOT NULL,' +
  '  key_kind VARCHAR(32) NOT NULL,' +
  '  authenticator_key VARCHAR(255) NOT NULL,' +
  '  description LONGTEXT NOT NULL DEFAULT \'\',' +
  '  protocol_family LONGTEXT NOT NULL DEFAULT \'\',' +
  '  certification_level LONGTEXT NOT NULL DEFAULT \'\',' +
  '  latest_status LONGTEXT NOT NULL DEFAULT \'\',' +
  '  latest_status_at BIGINT NOT NULL DEFAULT 0,' +
  '  compromised BOOLEAN NOT NULL DEFAULT false,' +
  '  status_reports JSON NOT NULL DEFAULT \'[]\',' +
  '  metadata_statement JSON NOT NULL DEFAULT \'{}\',' +
  '  PRIMARY KEY (dataset, version, key_kind, authenticator_key)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_fido_by_key', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON ' +
  'sts_risk_fido_authenticators (key_kind, authenticator_key)' },
  { name: 'sts_risk_assessments', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_assessments (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  id VARCHAR(255) NOT NULL,' +
  '  at BIGINT NOT NULL,' +
  '  phase LONGTEXT NOT NULL,' +
  '  door LONGTEXT NOT NULL,' +
  '  subject VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  session_id VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  client_id LONGTEXT NOT NULL DEFAULT \'\',' +
  '  address_sealed LONGTEXT NOT NULL,' +
  '  address_prefix VARCHAR(50) NOT NULL,' +
  '  asn BIGINT NOT NULL DEFAULT 0,' +
  '  as_org LONGTEXT NOT NULL DEFAULT \'\',' +
  '  country LONGTEXT NOT NULL DEFAULT \'\',' +
  '  subdivision LONGTEXT NOT NULL DEFAULT \'\',' +
  '  city LONGTEXT NOT NULL DEFAULT \'\',' +
  '  latitude DOUBLE,' +
  '  longitude DOUBLE,' +
  '  accuracy_km INT NOT NULL DEFAULT 0,' +
  '  ip_lists JSON NOT NULL DEFAULT \'[]\',' +
  '  ua_hash LONGTEXT NOT NULL DEFAULT \'\',' +
  '  ua_family LONGTEXT NOT NULL DEFAULT \'\',' +
  '  ua_os LONGTEXT NOT NULL DEFAULT \'\',' +
  '  ua_platform LONGTEXT NOT NULL DEFAULT \'\',' +
  '  bot BOOLEAN NOT NULL DEFAULT false,' +
  '  ja4 LONGTEXT NOT NULL DEFAULT \'\',' +
  '  credential_kind LONGTEXT NOT NULL DEFAULT \'\',' +
  '  credential_hash LONGTEXT NOT NULL DEFAULT \'\',' +
  '  aaguid LONGTEXT NOT NULL DEFAULT \'\',' +
  '  authenticator_cert LONGTEXT NOT NULL DEFAULT \'\',' +
  '  backup_eligible BOOLEAN,' +
  '  backup_state BOOLEAN,' +
  '  jkt LONGTEXT NOT NULL DEFAULT \'\',' +
  '  cert_fingerprint LONGTEXT NOT NULL DEFAULT \'\',' +
  '  datasets JSON NOT NULL DEFAULT \'{}\',' +
  '  signals JSON NOT NULL DEFAULT \'[]\',' +
  '  score FLOAT NOT NULL,' +
  '  level LONGTEXT NOT NULL,' +
  '  decision LONGTEXT NOT NULL,' +
  '  policy_id LONGTEXT NOT NULL DEFAULT \'\',' +
  '  error_code LONGTEXT NOT NULL DEFAULT \'\',' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  feedback LONGTEXT NOT NULL DEFAULT \'\',' +
  '  feedback_at BIGINT NOT NULL DEFAULT 0,' +
  '  PRIMARY KEY (realm, id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_assessments_subject', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON ' +
  'sts_risk_assessments (realm, subject, at)' },
  { name: 'sts_risk_assessments_session', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON ' +
  'sts_risk_assessments (realm, session_id)' },
  { name: 'sts_risk_assessments_at', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON ' +
  'sts_risk_assessments (at)' },
  { name: 'sts_risk_feature_counts', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_feature_counts (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  subject VARCHAR(255) NOT NULL,' +
  '  feature VARCHAR(64) NOT NULL,' +
  '  value VARCHAR(255) NOT NULL,' +
  '  count BIGINT NOT NULL,' +
  '  first_at BIGINT NOT NULL,' +
  '  last_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, subject, feature, value)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_feature_counts_age', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON ' +
  'sts_risk_feature_counts (realm, last_at)' },
  { name: 'sts_risk_failures', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_failures (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  id BIGINT NOT NULL AUTO_INCREMENT,' +
  '  at BIGINT NOT NULL,' +
  '  door LONGTEXT NOT NULL,' +
  '  subject VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  name_hmac VARCHAR(255) NOT NULL DEFAULT \'\',' +
  '  address_sealed LONGTEXT NOT NULL,' +
  '  address_prefix VARCHAR(50) NOT NULL,' +
  '  asn BIGINT NOT NULL DEFAULT 0,' +
  '  error_code LONGTEXT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, id),' +
  '  KEY sts_risk_failures_id (id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_failures_subject', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON ' +
  'sts_risk_failures (realm, subject, at)' },
  { name: 'sts_risk_failures_name', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON sts_risk_failures ' +
  '(realm, name_hmac, at)' },
  { name: 'sts_risk_failures_prefix', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON sts_risk_failures ' +
  '(realm, address_prefix, at)' },
  { name: 'sts_risk_failures_at', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON sts_risk_failures (at)' },
  { name: 'sts_risk_session_context', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_session_context (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  session_id VARCHAR(255) NOT NULL,' +
  '  subject LONGTEXT NOT NULL,' +
  '  address_prefix VARCHAR(50) NOT NULL,' +
  '  asn BIGINT NOT NULL DEFAULT 0,' +
  '  country LONGTEXT NOT NULL DEFAULT \'\',' +
  '  ua_hash LONGTEXT NOT NULL DEFAULT \'\',' +
  '  ja4 LONGTEXT NOT NULL DEFAULT \'\',' +
  '  jkt LONGTEXT NOT NULL DEFAULT \'\',' +
  '  score FLOAT NOT NULL,' +
  '  level LONGTEXT NOT NULL,' +
  '  updated_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, session_id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_subjects', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_subjects (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  subject VARCHAR(255) NOT NULL,' +
  '  score FLOAT NOT NULL,' +
  '  level LONGTEXT NOT NULL,' +
  '  previous_level LONGTEXT NOT NULL DEFAULT \'\',' +
  '  reason LONGTEXT NOT NULL DEFAULT \'\',' +
  '  last_assessment LONGTEXT NOT NULL DEFAULT \'\',' +
  '  crossed_at BIGINT NOT NULL DEFAULT 0,' +
  '  actions JSON NOT NULL DEFAULT \'{}\',' +
  '  feedback LONGTEXT NOT NULL DEFAULT \'\',' +
  '  updated_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, subject)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_terms_acceptances', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_terms_acceptances (' +
  '  id BIGINT NOT NULL AUTO_INCREMENT,' +
  '  provider VARCHAR(128) NOT NULL,' +
  '  terms_digest LONGTEXT NOT NULL,' +
  '  terms_text LONGTEXT NOT NULL,' +
  '  accepted_by LONGTEXT NOT NULL,' +
  '  accepted_via LONGTEXT NOT NULL,' +
  '  deployment LONGTEXT NOT NULL DEFAULT \'\',' +
  '  page_digest LONGTEXT NOT NULL DEFAULT \'\',' +
  '  accepted_at BIGINT NOT NULL,' +
  '  origin LONGTEXT NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_risk_terms_acceptances_provider', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON ' +
  'sts_risk_terms_acceptances (provider, accepted_at)' },
  { name: 'sts_cell_routing', statement:
  'CREATE TABLE IF NOT EXISTS sts_cell_routing (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  kind VARCHAR(64) NOT NULL,' +
  '  digest VARCHAR(255) NOT NULL,' +
  '  cell LONGTEXT NOT NULL,' +
  '  written_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, kind, digest)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_report_artifacts', statement:
  'CREATE TABLE IF NOT EXISTS sts_report_artifacts (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  job_id VARCHAR(255) NOT NULL,' +
  '  bytes LONGBLOB NOT NULL,' +
  '  sha256 LONGTEXT NOT NULL,' +
  '  media_type LONGTEXT NOT NULL,' +
  '  created_at BIGINT NOT NULL,' +
  '  PRIMARY KEY (realm, job_id)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_report_artifact_pieces', statement:
  'CREATE TABLE IF NOT EXISTS sts_report_artifact_pieces (' +
  '  realm VARCHAR(64) NOT NULL,' +
  '  job_id VARCHAR(255) NOT NULL,' +
  '  seq INT NOT NULL,' +
  '  bytes LONGBLOB NOT NULL,' +
  '  PRIMARY KEY (realm, job_id, seq)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' },
  { name: 'sts_schema', statement:
  'CREATE TABLE IF NOT EXISTS sts_schema (' +
  '  version INT NOT NULL,' +
  '  applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),' +
  '  PRIMARY KEY (version)' +
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin' }
];

/**
 * The tables of the schema, in creation order.
 */
const TABLES = SCHEMA_OBJECTS.filter(function (object) {
  return /^CREATE TABLE /.test(object.statement);
}).map(function (object) {
  return object.name;
});

// THE KEY LIMITS a DOOR asks before it creates an entry (#677): InnoDB's
// 3072-byte key over (realm, parent_key, dn_key) fixes them, and a DN key
// over them would be refused at the flush (STS-STORE-0140) after the entry
// was already in memory. `persistence.dnKeyRefusal()` reads these.
const LIMITS = { dnKey: 352, realm: 64 };

module.exports = {
  LIMITS: LIMITS,
  SCHEMA_VERSION: SCHEMA_VERSION,
  SCHEMA_OBJECTS: SCHEMA_OBJECTS,
  TABLES: TABLES
};
