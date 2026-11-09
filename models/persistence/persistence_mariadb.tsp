// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/persistence/persistence_mariadb.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of every MariaDB table and index:
// `models/tools/generate.mjs` compiles it during the image build into what
// `persistence/schema_mariadb.js` holds and into `mariadb/schema.sql`, whose
// comments and everything else are in `mariadb.template.sql` beside this file.
// A separate model from PostgreSQL's, because the two engines differ in types,
// keys and indexes (`mariadb/CLAUDE.md`).

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.PersistenceMariaDb;

@table(#{name: "sts_ldap_entries", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 16, text: "PRIMARY KEY (realm, dn_key)"}], driver: #{order: 0}, indexes: #[#{name: "sts_ldap_entries_realm", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm)", driver: #{order: 1}}, #{name: "sts_ldap_entries_parent", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_parent ON sts_ldap_entries (realm, parent_key, dn_key)", driver: #{order: 2}}, #{name: "sts_ldap_entries_rdn", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_rdn ON sts_ldap_entries (realm, parent_key, rdn_value)", driver: #{order: 3}}, #{name: "sts_ldap_entries_created", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_created ON sts_ldap_entries (realm, parent_key, created_at)", driver: #{order: 4}}, #{name: "sts_ldap_entries_modified", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_modified ON sts_ldap_entries (realm, parent_key, modified_at)", driver: #{order: 5}}]})
model StsLdapEntries {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(352)", clauses: "NOT NULL", required: true, primaryKey: true})
  dn_key: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  dn: string;
  @column(#{sql: "JSON", clauses: "NOT NULL", required: true})
  attrs: unknown;
  @column(#{sql: "LONGTEXT"})
  origin?: string;
  @column(#{sql: "VARCHAR(32)"})
  created_at?: string;
  @column(#{sql: "VARCHAR(32)"})
  modified_at?: string;
  @column(#{sql: "VARCHAR(352)", clauses: "GENERATED ALWAYS AS (CASE WHEN LOCATE(',', dn_key) > 0 THEN SUBSTRING(dn_key, LOCATE(',', dn_key) + 1) ELSE '' END) STORED", generated: true})
  parent_key?: string;
  @column(#{sql: "VARCHAR(352)", clauses: "GENERATED ALWAYS AS (SUBSTRING(SUBSTRING_INDEX(dn_key, ',', 1), LOCATE('=', SUBSTRING_INDEX(dn_key, ',', 1)) + 1)) STORED", generated: true})
  rdn_value?: string;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  name_keys: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  mail_keys: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  uuid_keys: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  class_keys: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  value_keys: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  attr_names: unknown;
  @column(#{sql: "JSON"})
  dek_keys?: unknown;
}

@table(#{name: "sts_ldap_entry_keys", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 4, text: "PRIMARY KEY (realm, kind, k, dn_key)"}, #{at: 4, text: "CONSTRAINT sts_ldap_entry_keys_kind CHECK (kind IN ('name', 'mail', 'uuid', 'class', 'value', 'attr', 'dek'))"}], driver: #{order: 6}, indexes: #[#{name: "sts_ldap_entry_keys_entry", text: "CREATE INDEX IF NOT EXISTS sts_ldap_entry_keys_entry ON sts_ldap_entry_keys (realm, dn_key)", driver: #{order: 7}}]})
model StsLdapEntryKeys {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(8)", clauses: "NOT NULL", required: true, primaryKey: true})
  kind: string;
  @column(#{sql: "VARCHAR(344)", clauses: "NOT NULL", required: true, primaryKey: true})
  k: string;
  @column(#{sql: "VARCHAR(352)", clauses: "NOT NULL", required: true, primaryKey: true})
  dn_key: string;
}

@table(#{name: "sts_ldap_dek_counts", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 3, text: "PRIMARY KEY (dek_id, shard)"}], driver: #{order: 8}})
model StsLdapDekCounts {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  dek_id: string;
  @column(#{sql: "SMALLINT", clauses: "NOT NULL DEFAULT 0", required: true, primaryKey: true})
  shard: int16;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  n: int64;
}

@table(#{name: "sts_ldap_dek_deltas", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", driver: #{order: 9}, indexes: #[#{name: "sts_ldap_dek_deltas_txid", text: "CREATE INDEX IF NOT EXISTS sts_ldap_dek_deltas_txid ON sts_ldap_dek_deltas (txid)", driver: #{order: 10}}]})
model StsLdapDekDeltas {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true})
  txid: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  dek_id: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  n: int64;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  fold: unknown;
}

@table(#{name: "sts_ldap_counts", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 5, text: "PRIMARY KEY (realm, base_key, attribute, shard)"}], driver: #{order: 11}})
model StsLdapCounts {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(352)", clauses: "NOT NULL", required: true, primaryKey: true})
  base_key: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  attribute: string;
  @column(#{sql: "SMALLINT", clauses: "NOT NULL DEFAULT 0", required: true, primaryKey: true})
  shard: int16;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  n: int64;
}

@table(#{name: "sts_ldap_count_deltas", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", driver: #{order: 12}, indexes: #[#{name: "sts_ldap_count_deltas_txid", text: "CREATE INDEX IF NOT EXISTS sts_ldap_count_deltas_txid ON sts_ldap_count_deltas (txid)", driver: #{order: 13}}]})
model StsLdapCountDeltas {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true})
  txid: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  realm: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  parent_key: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  n: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  holding: int64;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  fold: unknown;
}

@table(#{name: "sts_realms", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (id)"}], driver: #{order: 14}})
model StsRealms {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  id: string;
  @column(#{sql: "LONGTEXT"})
  name?: string;
  @column(#{sql: "LONGTEXT"})
  description?: string;
  @column(#{sql: "BIGINT"})
  created_at?: int64;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  overrides: unknown;
  @column(#{sql: "LONGTEXT"})
  domain?: string;
  @column(#{sql: "BIGINT"})
  retiring_at?: int64;
}

@table(#{name: "sts_appconfig", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 2, text: "PRIMARY KEY (`key`)"}], driver: #{order: 15}})
model StsAppconfig {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "JSON", clauses: "NOT NULL", required: true})
  value: unknown;
}

@table(#{name: "sts_keys", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 3, text: "PRIMARY KEY (realm)"}], driver: #{order: 16}})
model StsKeys {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  material: string;
  @column(#{sql: "DATETIME(6)", clauses: "NOT NULL DEFAULT CURRENT_TIMESTAMP(6)", required: true})
  written_at: unknown;
}

@table(#{name: "sts_minted", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (handle, realm, `key`)"}], driver: #{order: 17}, indexes: #[#{name: "sts_minted_handle", text: "CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm)", driver: #{order: 18}}, #{name: "sts_minted_written", text: "CREATE INDEX IF NOT EXISTS sts_minted_written ON sts_minted (written_at)", driver: #{order: 19}}, #{name: "sts_minted_expires", text: "CREATE INDEX IF NOT EXISTS sts_minted_expires ON sts_minted (expires_at)", driver: #{order: 20}}]})
model StsMinted {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  handle: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  body: string;
  @column(#{sql: "DATETIME(6)", clauses: "NOT NULL DEFAULT CURRENT_TIMESTAMP(6)", required: true})
  written_at: unknown;
  @column(#{sql: "BIGINT"})
  expires_at?: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  key_sealed: string;
}

@table(#{name: "sts_sessions", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 15, text: "PRIMARY KEY (realm, `key`)"}], driver: #{order: 21}, indexes: #[#{name: "sts_sessions_subject", text: "CREATE INDEX IF NOT EXISTS sts_sessions_subject ON sts_sessions (realm, subject_key, last_seen_at)", driver: #{order: 22}}, #{name: "sts_sessions_username", text: "CREATE INDEX IF NOT EXISTS sts_sessions_username ON sts_sessions (realm, username_key)", driver: #{order: 23}}, #{name: "sts_sessions_expires", text: "CREATE INDEX IF NOT EXISTS sts_sessions_expires ON sts_sessions (realm, expires_at)", driver: #{order: 24}}, #{name: "sts_sessions_parent", text: "CREATE INDEX IF NOT EXISTS sts_sessions_parent ON sts_sessions (realm, parent_key)", driver: #{order: 25}}, #{name: "sts_sessions_credential", text: "CREATE INDEX IF NOT EXISTS sts_sessions_credential ON sts_sessions (realm, credential_key)", driver: #{order: 26}}, #{name: "sts_sessions_partner", text: "CREATE INDEX IF NOT EXISTS sts_sessions_partner ON sts_sessions (realm, partner_relationship)", driver: #{order: 27}}, #{name: "sts_sessions_surface", text: "CREATE INDEX IF NOT EXISTS sts_sessions_surface ON sts_sessions (realm, rp_surface)", driver: #{order: 28}}]})
model StsSessions {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "BIGINT"})
  expires_at?: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  last_seen_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  subject_key: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  username_key: string;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL", required: true})
  chosen: unknown;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL", required: true})
  authenticated: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  rp_surface: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL DEFAULT ''", required: true})
  parent_key: string;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  backs_console: unknown;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_key: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  partner_relationship: string;
}

@table(#{name: "sts_minted_index", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 5, text: "PRIMARY KEY (handle, realm, index_key, `key`)"}], driver: #{order: 29}, indexes: #[#{name: "sts_minted_index_key", text: "CREATE INDEX IF NOT EXISTS sts_minted_index_key ON sts_minted_index (handle, realm, `key`)", driver: #{order: 30}}, #{name: "sts_minted_index_sort", text: "CREATE INDEX IF NOT EXISTS sts_minted_index_sort ON sts_minted_index (handle, realm, sort_at DESC, `key` DESC)", driver: #{order: 31}}]})
model StsMintedIndex {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  handle: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  index_key: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "BIGINT"})
  sort_at?: int64;
}

@table(#{name: "sts_changes", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 6, text: "PRIMARY KEY (seq)"}], driver: #{order: 32}, indexes: #[#{name: "sts_changes_at", text: "CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at)", driver: #{order: 33}}]})
model StsChanges {
  @column(#{sql: "BIGINT", clauses: "NOT NULL AUTO_INCREMENT", required: true, primaryKey: true})
  seq: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  origin: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  realm: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", backticks: true, required: true})
  key: string;
  @column(#{sql: "DATETIME(6)", clauses: "NOT NULL DEFAULT CURRENT_TIMESTAMP(6)", required: true})
  at: unknown;
}

@table(#{name: "sts_used_assertions", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 14, text: "PRIMARY KEY (realm, `key`)"}], driver: #{order: 34}, indexes: #[#{name: "sts_used_assertions_expiry", text: "CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON sts_used_assertions (realm, expires_at)", driver: #{order: 35}}]})
model StsUsedAssertions {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  format: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  used_as: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  issuer: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  identifier: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  client_id: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  reservation: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  used_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  spent_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_nodes", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 10, text: "PRIMARY KEY (node_id)"}], driver: #{order: 36}, indexes: #[#{name: "sts_cluster_nodes_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON sts_cluster_nodes (expires_at)", driver: #{order: 37}}]})
model StsClusterNodes {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  node_id: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  name: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  mode: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  version: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  fingerprint: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  heartbeat_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  expires_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  left_at: int64;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  info: unknown;
}

@table(#{name: "sts_cluster_leases", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 5, text: "PRIMARY KEY (name)"}], driver: #{order: 38}})
model StsClusterLeases {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  holder: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  token: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  acquired_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_claims", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (scope, realm, `key`)"}], driver: #{order: 39}, indexes: #[#{name: "sts_cluster_claims_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON sts_cluster_claims (expires_at)", driver: #{order: 40}}]})
model StsClusterClaims {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  reservation: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  claimed_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_secrets", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 4, text: "PRIMARY KEY (name)"}], driver: #{order: 41}})
model StsClusterSecrets {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  material: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  created_by: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  created_at: int64;
}

@table(#{name: "sts_cluster_locks", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 1, text: "PRIMARY KEY (name)"}], driver: #{order: 42}})
model StsClusterLocks {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  name: string;
}

@table(#{name: "sts_cluster_counters", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 6, text: "PRIMARY KEY (scope, realm, `key`)"}], driver: #{order: 43}})
model StsClusterCounters {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  value: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_cluster_windows", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 6, text: "PRIMARY KEY (scope, realm, `key`)"}], driver: #{order: 44}, indexes: #[#{name: "sts_cluster_windows_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON sts_cluster_windows (window_ends_at)", driver: #{order: 45}}]})
model StsClusterWindows {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  window_ends_at: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_cluster_budgets", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 9, text: "PRIMARY KEY (scope, realm, `key`)"}], driver: #{order: 46}, indexes: #[#{name: "sts_cluster_budgets_expiry", text: "CREATE INDEX IF NOT EXISTS sts_cluster_budgets_expiry ON sts_cluster_budgets (expires_at)", driver: #{order: 47}}]})
model StsClusterBudgets {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(512)", clauses: "NOT NULL", backticks: true, required: true, primaryKey: true})
  key: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  period: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  amount: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  expires_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_node_snapshots", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 4, text: "PRIMARY KEY (name)"}], driver: #{order: 48}})
model StsNodeSnapshots {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  node_id: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  taken_at: int64;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  body: unknown;
}

@table(#{name: "sts_change_readers", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 5, text: "PRIMARY KEY (origin)"}], driver: #{order: 49}})
model StsChangeReaders {
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  origin: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  node_id: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  applied: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  reported_at: int64;
}

@table(#{name: "sts_risk_datasets", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (realm, dataset)"}], driver: #{order: 50}})
model StsRiskDatasets {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  active_version: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  previous_version: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_dataset_versions", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 25, text: "PRIMARY KEY (realm, dataset, version)"}], driver: #{order: 51}})
model StsRiskDatasetVersions {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  format: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  provider: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  licence: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  attribution: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  source: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  source_uri: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  sha256: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  byte_count: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  row_count: int64;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  parameters: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  verification: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  published_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  next_update_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  fetched_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  loaded_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  activated_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  superseded_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  rows_deleted_at: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  refusal: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  error_code: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_risk_dataset_blobs", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 5, text: "PRIMARY KEY (realm, dataset, version, part)"}], driver: #{order: 52}})
model StsRiskDatasetBlobs {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "INT", clauses: "NOT NULL", required: true, primaryKey: true})
  part: int32;
  @column(#{sql: "LONGBLOB", clauses: "NOT NULL", required: true})
  content: bytes;
}

@table(#{name: "sts_risk_geo_locations", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 8, text: "PRIMARY KEY (dataset, version, location_id)"}], driver: #{order: 53}})
model StsRiskGeoLocations {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true, primaryKey: true})
  location_id: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  continent: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  time_zone: string;
}

@table(#{name: "sts_risk_geo_ranges", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 15, text: "PRIMARY KEY (dataset, version, range_start)"}], driver: #{order: 54}})
model StsRiskGeoRanges {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "INET6", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: unknown;
  @column(#{sql: "INET6", clauses: "NOT NULL", required: true})
  range_end: unknown;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  location_id: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  continent: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  registered_country: string;
  @column(#{sql: "DOUBLE"})
  latitude?: float64;
  @column(#{sql: "DOUBLE"})
  longitude?: float64;
  @column(#{sql: "INT", clauses: "NOT NULL DEFAULT 0", required: true})
  accuracy_km: int32;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  anonymous_proxy: unknown;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  satellite: unknown;
}

@table(#{name: "sts_risk_asn_ranges", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (dataset, version, range_start)"}], driver: #{order: 55}})
model StsRiskAsnRanges {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "INET6", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: unknown;
  @column(#{sql: "INET6", clauses: "NOT NULL", required: true})
  range_end: unknown;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  asn: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  as_org: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  as_domain: string;
}

@table(#{name: "sts_risk_ip_lists", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (realm, dataset, version, range_start)"}], driver: #{order: 56}})
model StsRiskIpLists {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "INET6", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: unknown;
  @column(#{sql: "INET6", clauses: "NOT NULL", required: true})
  range_end: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  category: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  note: string;
}

@table(#{name: "sts_risk_fido_authenticators", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 12, text: "PRIMARY KEY (dataset, version, key_kind, authenticator_key)"}], driver: #{order: 57}, indexes: #[#{name: "sts_risk_fido_by_key", text: "CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON sts_risk_fido_authenticators (key_kind, authenticator_key)", driver: #{order: 58}}]})
model StsRiskFidoAuthenticators {
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "VARCHAR(32)", clauses: "NOT NULL", required: true, primaryKey: true})
  key_kind: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  authenticator_key: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  description: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  protocol_family: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  certification_level: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  latest_status: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  latest_status_at: int64;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  compromised: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  status_reports: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  metadata_statement: unknown;
}

@table(#{name: "sts_risk_assessments", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 43, text: "PRIMARY KEY (realm, id)"}], driver: #{order: 59}, indexes: #[#{name: "sts_risk_assessments_subject", text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON sts_risk_assessments (realm, subject, at)", driver: #{order: 60}}, #{name: "sts_risk_assessments_session", text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON sts_risk_assessments (realm, session_id)", driver: #{order: 61}}, #{name: "sts_risk_assessments_at", text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON sts_risk_assessments (at)", driver: #{order: 62}}]})
model StsRiskAssessments {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  id: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  at: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  phase: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  door: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  session_id: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  client_id: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  address_sealed: string;
  @column(#{sql: "VARCHAR(50)", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  as_org: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "DOUBLE"})
  latitude?: float64;
  @column(#{sql: "DOUBLE"})
  longitude?: float64;
  @column(#{sql: "INT", clauses: "NOT NULL DEFAULT 0", required: true})
  accuracy_km: int32;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  ip_lists: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_hash: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_family: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_os: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_platform: string;
  @column(#{sql: "BOOLEAN", clauses: "NOT NULL DEFAULT false", required: true})
  bot: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ja4: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_kind: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_hash: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  aaguid: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  authenticator_cert: string;
  @column(#{sql: "BOOLEAN"})
  backup_eligible?: unknown;
  @column(#{sql: "BOOLEAN"})
  backup_state?: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  jkt: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  cert_fingerprint: string;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  datasets: unknown;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '[]'", required: true})
  signals: unknown;
  @column(#{sql: "FLOAT", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  decision: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  policy_id: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  error_code: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  feedback: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  feedback_at: int64;
}

@table(#{name: "sts_risk_feature_counts", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 7, text: "PRIMARY KEY (realm, subject, feature, value)"}], driver: #{order: 63}, indexes: #[#{name: "sts_risk_feature_counts_age", text: "CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON sts_risk_feature_counts (realm, last_at)", driver: #{order: 64}}]})
model StsRiskFeatureCounts {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  subject: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  feature: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  value: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  first_at: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  last_at: int64;
}

@table(#{name: "sts_risk_failures", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 11, text: "PRIMARY KEY (realm, id)"}, #{at: 11, text: "KEY sts_risk_failures_id (id)"}], driver: #{order: 65}, indexes: #[#{name: "sts_risk_failures_subject", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON sts_risk_failures (realm, subject, at)", driver: #{order: 66}}, #{name: "sts_risk_failures_name", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON sts_risk_failures (realm, name_hmac, at)", driver: #{order: 67}}, #{name: "sts_risk_failures_prefix", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON sts_risk_failures (realm, address_prefix, at)", driver: #{order: 68}}, #{name: "sts_risk_failures_at", text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON sts_risk_failures (at)", driver: #{order: 69}}]})
model StsRiskFailures {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL AUTO_INCREMENT", required: true, primaryKey: true})
  id: int64;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  at: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  door: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL DEFAULT ''", required: true})
  name_hmac: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  address_sealed: string;
  @column(#{sql: "VARCHAR(50)", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  error_code: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_risk_session_context", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 12, text: "PRIMARY KEY (realm, session_id)"}], driver: #{order: 70}})
model StsRiskSessionContext {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  session_id: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  subject: string;
  @column(#{sql: "VARCHAR(50)", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_hash: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  ja4: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  jkt: string;
  @column(#{sql: "FLOAT", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_subjects", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 11, text: "PRIMARY KEY (realm, subject)"}], driver: #{order: 71}})
model StsRiskSubjects {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  subject: string;
  @column(#{sql: "FLOAT", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  previous_level: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  reason: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  last_assessment: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL DEFAULT 0", required: true})
  crossed_at: int64;
  @column(#{sql: "JSON", clauses: "NOT NULL DEFAULT '{}'", required: true})
  actions: unknown;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  feedback: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_terms_acceptances", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 10, text: "PRIMARY KEY (id)"}], driver: #{order: 72}, indexes: #[#{name: "sts_risk_terms_acceptances_provider", text: "CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON sts_risk_terms_acceptances (provider, accepted_at)", driver: #{order: 73}}]})
model StsRiskTermsAcceptances {
  @column(#{sql: "BIGINT", clauses: "NOT NULL AUTO_INCREMENT", required: true, primaryKey: true})
  id: int64;
  @column(#{sql: "VARCHAR(128)", clauses: "NOT NULL", required: true})
  provider: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  terms_digest: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  terms_text: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  accepted_by: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  accepted_via: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  deployment: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  page_digest: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  accepted_at: int64;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_cell_routing", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 5, text: "PRIMARY KEY (realm, kind, digest)"}], driver: #{order: 74}})
model StsCellRouting {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  kind: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  digest: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  cell: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  written_at: int64;
}

@table(#{name: "sts_report_artifacts", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 6, text: "PRIMARY KEY (realm, job_id)"}], driver: #{order: 75}})
model StsReportArtifacts {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  job_id: string;
  @column(#{sql: "LONGBLOB", clauses: "NOT NULL", required: true})
  bytes: bytes;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  sha256: string;
  @column(#{sql: "LONGTEXT", clauses: "NOT NULL", required: true})
  media_type: string;
  @column(#{sql: "BIGINT", clauses: "NOT NULL", required: true})
  created_at: int64;
}

@table(#{name: "sts_report_artifact_pieces", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 4, text: "PRIMARY KEY (realm, job_id, seq)"}], driver: #{order: 76}})
model StsReportArtifactPieces {
  @column(#{sql: "VARCHAR(64)", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "VARCHAR(255)", clauses: "NOT NULL", required: true, primaryKey: true})
  job_id: string;
  @column(#{sql: "INT", clauses: "NOT NULL", required: true, primaryKey: true})
  seq: int32;
  @column(#{sql: "LONGBLOB", clauses: "NOT NULL", required: true})
  bytes: bytes;
}

@table(#{name: "sts_schema", engine: "mariadb", head: "CREATE TABLE IF NOT EXISTS", suffix: "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin", constraints: #[#{at: 2, text: "PRIMARY KEY (version)"}], driver: #{order: 77}})
model StsSchema {
  @column(#{sql: "INT", clauses: "NOT NULL", required: true, primaryKey: true})
  version: int32;
  @column(#{sql: "DATETIME(6)", clauses: "NOT NULL DEFAULT CURRENT_TIMESTAMP(6)", required: true})
  applied_at: unknown;
}

@schema(#{engine: "mariadb", version: 31})
model MariaDbSchema {}
