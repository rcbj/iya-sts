// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// Written by common/model_emit.ts (#1390). The TypeSpec compiler
// compiles this file in tests/model_typespec.js.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Persistence;

@table(#{name: "sts_ldap_entries", at: 5, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 16, text: "PRIMARY KEY (realm, dn_key)"}], indexes: #[#{at: 6, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm)"}, #{at: 17, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_parent ON sts_ldap_entries (realm, parent_key, dn_key)"}, #{at: 18, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_rdn ON sts_ldap_entries (realm, parent_key, rdn_value)"}, #{at: 20, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_uid_trgm ON sts_ldap_entries USING gin (rdn_value gin_trgm_ops) WITH (fastupdate = off) WHERE parent_key LIKE 'ou=users,%'"}, #{at: 21, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_created ON sts_ldap_entries (realm, parent_key, created_at) WHERE parent_key LIKE 'ou=users,%'"}, #{at: 22, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_modified ON sts_ldap_entries (realm, parent_key, modified_at) WHERE parent_key LIKE 'ou=users,%'"}, #{at: 25, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_names ON sts_ldap_entries USING gin (name_keys jsonb_path_ops) WITH (fastupdate = off)"}, #{at: 26, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_mails ON sts_ldap_entries USING gin (mail_keys jsonb_path_ops) WITH (fastupdate = off)"}, #{at: 27, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_uuids ON sts_ldap_entries USING gin (uuid_keys jsonb_path_ops) WITH (fastupdate = off)"}, #{at: 28, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_values ON sts_ldap_entries USING gin (value_keys jsonb_path_ops) WITH (fastupdate = off)"}, #{at: 30, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_asked_names ON sts_ldap_entries USING gin ((jsonb_path_query_array(attr_names, '$[*] ? (@ == \"federationlink\" || @ == \"hobapublickey\" || @ == \"memberof\" || @ == \"oauthconsent\" || @ == \"pwdaccountlockedtime\" || @ == \"stsacmeeabkey\" || @ == \"stsandroidattestedcredential\" || @ == \"stsassertionissuer\" || @ == \"stsassertionkeypair\" || @ == \"stsbackupcodes\" || @ == \"stscertificatehostname\" || @ == \"stsclaimsourcetokens\" || @ == \"stsdefaultdelegationsemantics\" || @ == \"stsdelegationsemantics\" || @ == \"stsdeviceandroidkey\" || @ == \"stsdevicekey\" || @ == \"stsenrolledcertificate\" || @ == \"stsenrolledprivatekey\" || @ == \"stskrb5keyinfo\" || @ == \"stskrb5keys\" || @ == \"stsmailfactor\" || @ == \"stsmayact\" || @ == \"stsnotdelegated\" || @ == \"stssamlassertionissuer\" || @ == \"stssamlassertionkeypair\" || @ == \"stsscepchallenge\" || @ == \"stsselfissuedsubject\" || @ == \"stsserviceaccount\" || @ == \"ststotpcredential\" || @ == \"stswebauthncredential\" || @ == \"stswebauthnuserhandle\")'))) WITH (fastupdate = off) WHERE attr_names ?| ARRAY['federationlink', 'hobapublickey', 'memberof', 'oauthconsent', 'pwdaccountlockedtime', 'stsacmeeabkey', 'stsandroidattestedcredential', 'stsassertionissuer', 'stsassertionkeypair', 'stsbackupcodes', 'stscertificatehostname', 'stsclaimsourcetokens', 'stsdefaultdelegationsemantics', 'stsdelegationsemantics', 'stsdeviceandroidkey', 'stsdevicekey', 'stsenrolledcertificate', 'stsenrolledprivatekey', 'stskrb5keyinfo', 'stskrb5keys', 'stsmailfactor', 'stsmayact', 'stsnotdelegated', 'stssamlassertionissuer', 'stssamlassertionkeypair', 'stsscepchallenge', 'stsselfissuedsubject', 'stsserviceaccount', 'ststotpcredential', 'stswebauthncredential', 'stswebauthnuserhandle']"}, #{at: 31, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_group_classes ON sts_ldap_entries USING gin (class_keys) WITH (fastupdate = off) WHERE class_keys <> '[]'::jsonb"}, #{at: 46, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_dek_keys ON sts_ldap_entries USING gin (dek_keys)"}, #{at: 47, text: "CREATE INDEX IF NOT EXISTS sts_ldap_entries_dek_unknown ON sts_ldap_entries (realm, dn_key) WHERE dek_keys IS NULL"}]})
model StsLdapEntries {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dn_key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  dn: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL", required: true})
  attrs: unknown;
  @column(#{sql: "text"})
  origin?: string;
  @column(#{sql: "text"})
  created_at?: string;
  @column(#{sql: "text"})
  modified_at?: string;
  @column(#{sql: "text", clauses: "GENERATED ALWAYS AS (CASE WHEN strpos(dn_key, ',') > 0 THEN substr(dn_key, strpos(dn_key, ',') + 1) ELSE '' END) STORED", generated: true})
  parent_key?: string;
  @column(#{sql: "text", clauses: "GENERATED ALWAYS AS (substr(split_part(dn_key, ',', 1), strpos(split_part(dn_key, ',', 1), '=') + 1)) STORED", generated: true})
  rdn_value?: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["uid"]})
  name_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["mail"]})
  mail_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["entryUUID", "stsEntryUuidAlias"]})
  uuid_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true, attributes: #["objectClass"]})
  class_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true})
  value_keys: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true})
  attr_names: unknown;
  @column(#{sql: "jsonb"})
  dek_keys?: unknown;
}

@table(#{name: "sts_ldap_counts", at: 48, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 5, text: "PRIMARY KEY (realm, base_key, attribute, shard)"}], indexes: #[]})
model StsLdapCounts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  base_key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  attribute: string;
  @column(#{sql: "smallint", clauses: "NOT NULL DEFAULT 0", required: true, primaryKey: true})
  shard: int16;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  n: int64;
}

@table(#{name: "sts_ldap_count_deltas", at: 51, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[#{at: 52, text: "CREATE INDEX IF NOT EXISTS sts_ldap_count_deltas_txid ON sts_ldap_count_deltas (txid)"}]})
model StsLdapCountDeltas {
  @column(#{sql: "xid8", clauses: "NOT NULL DEFAULT pg_current_xact_id()", required: true})
  txid: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  parent_key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  n: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  holding: int64;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  fold: boolean;
}

@table(#{name: "sts_ldap_dek_counts", at: 53, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 3, text: "PRIMARY KEY (dek_id, shard)"}], indexes: #[]})
model StsLdapDekCounts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dek_id: string;
  @column(#{sql: "smallint", clauses: "NOT NULL DEFAULT 0", required: true, primaryKey: true})
  shard: int16;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  n: int64;
}

@table(#{name: "sts_ldap_dek_deltas", at: 56, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[#{at: 57, text: "CREATE INDEX IF NOT EXISTS sts_ldap_dek_deltas_txid ON sts_ldap_dek_deltas (txid)"}]})
model StsLdapDekDeltas {
  @column(#{sql: "xid8", clauses: "NOT NULL DEFAULT pg_current_xact_id()", required: true})
  txid: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  dek_id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  n: int64;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  fold: boolean;
}

@table(#{name: "sts_realms", at: 84, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsRealms {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  id: string;
  @column(#{sql: "text"})
  name?: string;
  @column(#{sql: "text"})
  description?: string;
  @column(#{sql: "bigint"})
  created_at?: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  overrides: unknown;
  @column(#{sql: "text"})
  domain?: string;
  @column(#{sql: "bigint"})
  retiring_at?: int64;
}

@table(#{name: "sts_appconfig", at: 87, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsAppconfig {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL", required: true})
  value: unknown;
}

@table(#{name: "sts_keys", at: 88, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsKeys {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  material: string;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  written_at: utcDateTime;
}

@table(#{name: "sts_minted", at: 89, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 7, text: "PRIMARY KEY (handle, realm, key)"}], indexes: #[#{at: 92, text: "CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm)"}, #{at: 93, text: "CREATE INDEX IF NOT EXISTS sts_minted_written_brin ON sts_minted USING brin (written_at) WITH (autosummarize = on)"}, #{at: 96, text: "CREATE INDEX IF NOT EXISTS sts_minted_expires ON sts_minted (expires_at) WHERE expires_at IS NOT NULL"}]})
model StsMinted {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  handle: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  body: string;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  written_at: utcDateTime;
  @column(#{sql: "bigint"})
  expires_at?: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  key_sealed: string;
}

@table(#{name: "sts_sessions", at: 97, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 15, text: "PRIMARY KEY (realm, key)"}], indexes: #[#{at: 98, text: "CREATE INDEX IF NOT EXISTS sts_sessions_subject ON sts_sessions (realm, subject_key, last_seen_at) WHERE chosen AND subject_key <> ''"}, #{at: 99, text: "CREATE INDEX IF NOT EXISTS sts_sessions_username ON sts_sessions (realm, username_key) WHERE username_key <> ''"}, #{at: 100, text: "CREATE INDEX IF NOT EXISTS sts_sessions_expires ON sts_sessions (realm, expires_at) WHERE expires_at IS NOT NULL"}, #{at: 101, text: "CREATE INDEX IF NOT EXISTS sts_sessions_parent ON sts_sessions (realm, parent_key) WHERE parent_key <> ''"}, #{at: 102, text: "CREATE INDEX IF NOT EXISTS sts_sessions_credential ON sts_sessions (realm, credential_key) WHERE credential_key <> ''"}, #{at: 103, text: "CREATE INDEX IF NOT EXISTS sts_sessions_partner ON sts_sessions (realm, partner_relationship) WHERE partner_relationship <> ''"}, #{at: 104, text: "CREATE INDEX IF NOT EXISTS sts_sessions_surface ON sts_sessions (realm, rp_surface) WHERE rp_surface <> ''"}]})
model StsSessions {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint"})
  expires_at?: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  last_seen_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject_key: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  username_key: string;
  @column(#{sql: "boolean", clauses: "NOT NULL", required: true})
  chosen: boolean;
  @column(#{sql: "boolean", clauses: "NOT NULL", required: true})
  authenticated: boolean;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  rp_surface: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  parent_key: string;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  backs_console: boolean;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_key: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  partner_relationship: string;
}

@table(#{name: "sts_minted_index", at: 105, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 5, text: "PRIMARY KEY (handle, realm, index_key, key)"}], indexes: #[#{at: 106, text: "CREATE INDEX IF NOT EXISTS sts_minted_index_key ON sts_minted_index (handle, realm, key)"}, #{at: 108, text: "CREATE INDEX IF NOT EXISTS sts_minted_index_sort ON sts_minted_index (handle, realm, sort_at DESC, key DESC) WHERE sort_at IS NOT NULL"}]})
model StsMintedIndex {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  handle: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  index_key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint"})
  sort_at?: int64;
}

@table(#{name: "sts_changes", at: 109, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[#{at: 110, text: "CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at)"}]})
model StsChanges {
  @column(#{sql: "bigserial", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  seq: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  origin: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  key: string;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  at: utcDateTime;
}

@table(#{name: "sts_used_assertions", at: 112, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 14, text: "PRIMARY KEY (realm, key)"}], indexes: #[#{at: 113, text: "CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON sts_used_assertions (realm, expires_at)"}]})
model StsUsedAssertions {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  format: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  used_as: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  issuer: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  identifier: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  client_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  reservation: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  used_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  spent_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_nodes", at: 114, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[#{at: 115, text: "CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON sts_cluster_nodes (expires_at)"}]})
model StsClusterNodes {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  node_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  mode: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  version: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  fingerprint: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  heartbeat_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  left_at: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  info: unknown;
}

@table(#{name: "sts_cluster_leases", at: 116, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsClusterLeases {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  holder: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  token: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  acquired_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_claims", at: 117, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 7, text: "PRIMARY KEY (scope, realm, key)"}], indexes: #[#{at: 118, text: "CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON sts_cluster_claims (expires_at)"}]})
model StsClusterClaims {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  reservation: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  claimed_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
}

@table(#{name: "sts_cluster_secrets", at: 119, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsClusterSecrets {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  material: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  created_by: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  created_at: int64;
}

@table(#{name: "sts_cluster_locks", at: 120, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsClusterLocks {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
}

@table(#{name: "sts_cluster_counters", at: 121, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 6, text: "PRIMARY KEY (scope, realm, key)"}], indexes: #[]})
model StsClusterCounters {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  value: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_cluster_windows", at: 122, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 6, text: "PRIMARY KEY (scope, realm, key)"}], indexes: #[#{at: 123, text: "CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON sts_cluster_windows (window_ends_at)"}]})
model StsClusterWindows {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  window_ends_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_cluster_budgets", at: 124, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 9, text: "PRIMARY KEY (scope, realm, key)"}], indexes: #[#{at: 125, text: "CREATE INDEX IF NOT EXISTS sts_cluster_budgets_expiry ON sts_cluster_budgets (expires_at)"}]})
model StsClusterBudgets {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  scope: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  period: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  amount: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  expires_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_node_snapshots", at: 126, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsNodeSnapshots {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  name: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  node_id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  taken_at: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  body: unknown;
}

@table(#{name: "sts_change_readers", at: 127, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsChangeReaders {
  @column(#{sql: "text", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  origin: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  node_id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  applied: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  started_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  reported_at: int64;
}

@table(#{name: "sts_risk_datasets", at: 128, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 7, text: "PRIMARY KEY (realm, dataset)"}], indexes: #[]})
model StsRiskDatasets {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  active_version: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  previous_version: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_dataset_versions", at: 129, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 25, text: "PRIMARY KEY (realm, dataset, version)"}], indexes: #[]})
model StsRiskDatasetVersions {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  format: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  provider: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  licence: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  attribution: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  source: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  source_uri: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  sha256: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  byte_count: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  row_count: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  parameters: unknown;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  verification: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  published_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  next_update_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  fetched_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  loaded_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  activated_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  superseded_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  rows_deleted_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  state: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  refusal: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  error_code: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_risk_dataset_blobs", at: 130, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 5, text: "PRIMARY KEY (realm, dataset, version, part)"}], indexes: #[]})
model StsRiskDatasetBlobs {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "integer", clauses: "NOT NULL", required: true, primaryKey: true})
  part: int32;
  @column(#{sql: "bytea", clauses: "NOT NULL", required: true})
  content: bytes;
}

@table(#{name: "sts_risk_geo_locations", at: 131, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 8, text: "PRIMARY KEY (dataset, version, location_id)"}], indexes: #[]})
model StsRiskGeoLocations {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true, primaryKey: true})
  location_id: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  continent: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  time_zone: string;
}

@table(#{name: "sts_risk_geo_ranges", at: 132, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 15, text: "PRIMARY KEY (dataset, version, range_start)"}], indexes: #[]})
model StsRiskGeoRanges {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true})
  range_end: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  location_id: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  continent: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  registered_country: string;
  @column(#{sql: "double precision"})
  latitude?: float64;
  @column(#{sql: "double precision"})
  longitude?: float64;
  @column(#{sql: "integer", clauses: "NOT NULL DEFAULT 0", required: true})
  accuracy_km: int32;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  anonymous_proxy: boolean;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  satellite: boolean;
}

@table(#{name: "sts_risk_asn_ranges", at: 133, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 7, text: "PRIMARY KEY (dataset, version, range_start)"}], indexes: #[]})
model StsRiskAsnRanges {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true})
  range_end: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  as_org: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  as_domain: string;
}

@table(#{name: "sts_risk_ip_lists", at: 134, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 7, text: "PRIMARY KEY (realm, dataset, version, range_start)"}], indexes: #[]})
model StsRiskIpLists {
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true, primaryKey: true})
  range_start: string;
  @column(#{sql: "inet", clauses: "NOT NULL", required: true})
  range_end: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  category: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  note: string;
}

@table(#{name: "sts_risk_fido_authenticators", at: 135, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 12, text: "PRIMARY KEY (dataset, version, key_kind, authenticator_key)"}], indexes: #[#{at: 136, text: "CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON sts_risk_fido_authenticators (key_kind, authenticator_key)"}]})
model StsRiskFidoAuthenticators {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  dataset: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  version: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  key_kind: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  authenticator_key: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  description: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  protocol_family: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  certification_level: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  latest_status: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  latest_status_at: int64;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  compromised: boolean;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true})
  status_reports: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  metadata_statement: unknown;
}

@table(#{name: "sts_risk_assessments", at: 137, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 43, text: "PRIMARY KEY (realm, id)"}], indexes: #[#{at: 140, text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON sts_risk_assessments (realm, subject, at)"}, #{at: 141, text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON sts_risk_assessments (realm, session_id)"}, #{at: 142, text: "CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON sts_risk_assessments (at)"}]})
model StsRiskAssessments {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  id: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  at: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  phase: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  door: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  session_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  client_id: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  address_sealed: string;
  @column(#{sql: "cidr", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  as_org: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subdivision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  city: string;
  @column(#{sql: "double precision"})
  latitude?: float64;
  @column(#{sql: "double precision"})
  longitude?: float64;
  @column(#{sql: "integer", clauses: "NOT NULL DEFAULT 0", required: true})
  accuracy_km: int32;
  @column(#{sql: "text[]", clauses: "NOT NULL DEFAULT '{}'", required: true})
  ip_lists: string[];
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_hash: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_family: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_os: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_platform: string;
  @column(#{sql: "boolean", clauses: "NOT NULL DEFAULT false", required: true})
  bot: boolean;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ja4: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_kind: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  credential_hash: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  aaguid: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  authenticator_cert: string;
  @column(#{sql: "boolean"})
  backup_eligible?: boolean;
  @column(#{sql: "boolean"})
  backup_state?: boolean;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  jkt: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  cert_fingerprint: string;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  datasets: unknown;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '[]'::jsonb", required: true})
  signals: unknown;
  @column(#{sql: "real", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  decision: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  policy_id: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  error_code: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  feedback: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  feedback_at: int64;
}

@table(#{name: "sts_risk_feature_counts", at: 143, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 7, text: "PRIMARY KEY (realm, subject, feature, value)"}], indexes: #[#{at: 144, text: "CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON sts_risk_feature_counts (realm, last_at)"}]})
model StsRiskFeatureCounts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  feature: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  value: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  count: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  first_at: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  last_at: int64;
}

@table(#{name: "sts_risk_failures", at: 145, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 11, text: "PRIMARY KEY (realm, id)"}], indexes: #[#{at: 146, text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON sts_risk_failures (realm, subject, at)"}, #{at: 147, text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON sts_risk_failures (realm, name_hmac, at)"}, #{at: 148, text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON sts_risk_failures (realm, address_prefix, at)"}, #{at: 149, text: "CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON sts_risk_failures (at)"}]})
model StsRiskFailures {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "bigserial", clauses: "NOT NULL", required: true, primaryKey: true})
  id: int64;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  at: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  door: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  subject: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  name_hmac: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  address_sealed: string;
  @column(#{sql: "cidr", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  error_code: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_risk_session_context", at: 150, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 12, text: "PRIMARY KEY (realm, session_id)"}], indexes: #[]})
model StsRiskSessionContext {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  session_id: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  subject: string;
  @column(#{sql: "cidr", clauses: "NOT NULL", required: true})
  address_prefix: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  asn: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  country: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ua_hash: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  ja4: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  jkt: string;
  @column(#{sql: "real", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_subjects", at: 151, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 11, text: "PRIMARY KEY (realm, subject)"}], indexes: #[]})
model StsRiskSubjects {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  subject: string;
  @column(#{sql: "real", clauses: "NOT NULL", required: true})
  score: float32;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  level: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  previous_level: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  reason: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  last_assessment: string;
  @column(#{sql: "bigint", clauses: "NOT NULL DEFAULT 0", required: true})
  crossed_at: int64;
  @column(#{sql: "jsonb", clauses: "NOT NULL DEFAULT '{}'::jsonb", required: true})
  actions: unknown;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  feedback: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  updated_at: int64;
}

@table(#{name: "sts_risk_terms_acceptances", at: 152, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 10, text: "PRIMARY KEY (id)"}], indexes: #[#{at: 153, text: "CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON sts_risk_terms_acceptances (provider, accepted_at)"}]})
model StsRiskTermsAcceptances {
  @column(#{sql: "bigserial", clauses: "NOT NULL", required: true, primaryKey: true})
  id: int64;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  provider: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  terms_digest: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  terms_text: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  accepted_by: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  accepted_via: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  deployment: string;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  page_digest: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  accepted_at: int64;
  @column(#{sql: "text", clauses: "NOT NULL DEFAULT ''", required: true})
  origin: string;
}

@table(#{name: "sts_cell_routing", at: 154, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 5, text: "PRIMARY KEY (realm, kind, digest)"}], indexes: #[]})
model StsCellRouting {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  kind: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  digest: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  cell: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  written_at: int64;
}

@table(#{name: "sts_report_artifacts", at: 155, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 6, text: "PRIMARY KEY (realm, job_id)"}], indexes: #[]})
model StsReportArtifacts {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  job_id: string;
  @column(#{sql: "bytea", clauses: "NOT NULL", required: true})
  bytes: bytes;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  sha256: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true})
  media_type: string;
  @column(#{sql: "bigint", clauses: "NOT NULL", required: true})
  created_at: int64;
}

@table(#{name: "sts_report_artifact_pieces", at: 156, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[#{at: 4, text: "PRIMARY KEY (realm, job_id, seq)"}], indexes: #[]})
model StsReportArtifactPieces {
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  realm: string;
  @column(#{sql: "text", clauses: "NOT NULL", required: true, primaryKey: true})
  job_id: string;
  @column(#{sql: "int", clauses: "NOT NULL", required: true, primaryKey: true})
  seq: int32;
  @column(#{sql: "bytea", clauses: "NOT NULL", required: true})
  bytes: bytes;
}

@table(#{name: "sts_schema", at: 157, head: "CREATE TABLE IF NOT EXISTS", tightClose: true, constraints: #[], indexes: #[]})
model StsSchema {
  @column(#{sql: "int", clauses: "PRIMARY KEY", required: true, primaryKey: true})
  version: int32;
  @column(#{sql: "timestamptz", clauses: "NOT NULL DEFAULT now()", required: true})
  applied_at: utcDateTime;
}

@schema(#{version: 31, extensions: #["pg_stat_statements", "pg_trgm"], statements: #[#{at: 0, text: "BEGIN"}, #{at: 1, text: "SET client_min_messages = warning"}, #{at: 2, text: "CREATE SCHEMA IF NOT EXISTS :\"sts_schema\""}, #{at: 3, text: "SELECT format('ALTER DATABASE %I SET search_path = %I, public', current_database(), :'sts_schema') SET search_path TO :\"sts_schema\", public"}, #{at: 4, text: "DO $ext$ BEGIN CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public; EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN RAISE WARNING 'sts-schema: pg_stat_statements not created (%); the store works without it', SQLERRM; END $ext$"}, #{at: 7, text: "ALTER TABLE sts_ldap_entries SET (autovacuum_vacuum_insert_scale_factor=0.01)"}, #{at: 8, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS parent_key text GENERATED ALWAYS AS (CASE WHEN strpos(dn_key, ',') > 0 THEN substr(dn_key, strpos(dn_key, ',') + 1) ELSE '' END) STORED"}, #{at: 9, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS rdn_value text GENERATED ALWAYS AS (substr(split_part(dn_key, ',', 1), strpos(split_part(dn_key, ',', 1), '=') + 1)) STORED"}, #{at: 10, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS name_keys jsonb NOT NULL DEFAULT '[]'::jsonb"}, #{at: 11, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS mail_keys jsonb NOT NULL DEFAULT '[]'::jsonb"}, #{at: 12, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS uuid_keys jsonb NOT NULL DEFAULT '[]'::jsonb"}, #{at: 13, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS class_keys jsonb NOT NULL DEFAULT '[]'::jsonb"}, #{at: 14, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS value_keys jsonb NOT NULL DEFAULT '[]'::jsonb"}, #{at: 15, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS attr_names jsonb NOT NULL DEFAULT '[]'::jsonb"}, #{at: 16, text: "ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS dek_keys jsonb"}, #{at: 19, text: "CREATE EXTENSION IF NOT EXISTS pg_trgm"}, #{at: 23, text: "ALTER TABLE sts_ldap_entries ALTER COLUMN parent_key SET (n_distinct=100000)"}, #{at: 24, text: "ANALYZE sts_ldap_entries (parent_key)"}, #{at: 29, text: "DROP INDEX IF EXISTS sts_ldap_entries_asked_names"}, #{at: 32, text: "DROP INDEX IF EXISTS sts_ldap_entries_attr_names"}, #{at: 33, text: "DROP INDEX IF EXISTS sts_ldap_entries_classes"}, #{at: 34, text: "ALTER INDEX sts_ldap_entries_names SET (fastupdate = off)"}, #{at: 35, text: "ALTER INDEX sts_ldap_entries_mails SET (fastupdate = off)"}, #{at: 36, text: "ALTER INDEX sts_ldap_entries_uuids SET (fastupdate = off)"}, #{at: 37, text: "ALTER INDEX sts_ldap_entries_values SET (fastupdate = off)"}, #{at: 38, text: "ALTER INDEX sts_ldap_entries_asked_names SET (fastupdate = off)"}, #{at: 39, text: "ALTER INDEX sts_ldap_entries_group_classes SET (fastupdate = off)"}, #{at: 40, text: "SELECT gin_clean_pending_list('sts_ldap_entries_names'::regclass)"}, #{at: 41, text: "SELECT gin_clean_pending_list('sts_ldap_entries_mails'::regclass)"}, #{at: 42, text: "SELECT gin_clean_pending_list('sts_ldap_entries_uuids'::regclass)"}, #{at: 43, text: "SELECT gin_clean_pending_list('sts_ldap_entries_values'::regclass)"}, #{at: 44, text: "SELECT gin_clean_pending_list('sts_ldap_entries_asked_names'::regclass)"}, #{at: 45, text: "SELECT gin_clean_pending_list('sts_ldap_entries_group_classes'::regclass)"}, #{at: 49, text: "ALTER TABLE sts_ldap_counts ADD COLUMN IF NOT EXISTS shard smallint NOT NULL DEFAULT 0"}, #{at: 50, text: "DO $upgrade$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey) WHERE i.indrelid = to_regclass('sts_ldap_counts') AND i.indisprimary AND a.attname = 'shard') THEN ALTER TABLE sts_ldap_counts DROP CONSTRAINT sts_ldap_counts_pkey; ALTER TABLE sts_ldap_counts ADD PRIMARY KEY (realm, base_key, attribute, shard); END IF; END $upgrade$"}, #{at: 54, text: "ALTER TABLE sts_ldap_dek_counts ADD COLUMN IF NOT EXISTS shard smallint NOT NULL DEFAULT 0"}, #{at: 55, text: "DO $upgrade$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey) WHERE i.indrelid = to_regclass('sts_ldap_dek_counts') AND i.indisprimary AND a.attname = 'shard') THEN ALTER TABLE sts_ldap_dek_counts DROP CONSTRAINT sts_ldap_dek_counts_pkey; ALTER TABLE sts_ldap_dek_counts ADD PRIMARY KEY (dek_id, shard); END IF; END $upgrade$"}, #{at: 58, text: "LOCK TABLE sts_ldap_entries IN SHARE ROW EXCLUSIVE MODE"}, #{at: 59, text: "CREATE OR REPLACE FUNCTION sts_ldap_count_bases(parent text) RETURNS SETOF text LANGUAGE sql IMMUTABLE AS $$ SELECT parent UNION ALL SELECT substr(parent, i + 1) FROM generate_series(1, length(parent)) AS i WHERE substr(parent, i, 1) = ',' UNION ALL SELECT '' WHERE parent <> '' $$"}, #{at: 60, text: "CREATE OR REPLACE FUNCTION sts_ldap_count_note() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE added bigint; BEGIN IF TG_OP = 'INSERT' THEN INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding) SELECT realm, parent_key, count(*), count(*) FILTER (WHERE attr_names ? 'userpassword') FROM new_rows GROUP BY realm, parent_key; ELSIF TG_OP = 'DELETE' THEN INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding) SELECT realm, parent_key, -count(*), -count(*) FILTER (WHERE attr_names ? 'userpassword') FROM old_rows GROUP BY realm, parent_key; ELSE INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding) SELECT realm, parent_key, sum(n), sum(h) FROM (SELECT realm, parent_key, 1 AS n, CASE WHEN attr_names ? 'userpassword' THEN 1 ELSE 0 END AS h FROM new_rows UNION ALL SELECT realm, parent_key, -1, CASE WHEN attr_names ? 'userpassword' THEN -1 ELSE 0 END FROM old_rows) AS c GROUP BY realm, parent_key HAVING sum(n) <> 0 OR sum(h) <> 0; END IF; GET DIAGNOSTICS added = ROW_COUNT; IF added > 0 AND NOT EXISTS (SELECT 1 FROM sts_ldap_count_deltas WHERE txid = pg_current_xact_id() AND fold) THEN INSERT INTO sts_ldap_count_deltas (realm, parent_key, n, holding, fold) VALUES ('', '', 0, 0, true); END IF; RETURN NULL; END $$"}, #{at: 61, text: "CREATE OR REPLACE FUNCTION sts_ldap_count_fold_sharded() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN WITH folded AS (DELETE FROM sts_ldap_count_deltas WHERE txid = pg_current_xact_id() RETURNING realm, parent_key, n, holding), bases AS (SELECT f.realm, b.base_key, sum(f.n) AS n, sum(f.holding) AS holding FROM folded AS f CROSS JOIN LATERAL sts_ldap_count_bases(f.parent_key) AS b(base_key) WHERE f.n <> 0 OR f.holding <> 0 GROUP BY f.realm, b.base_key) INSERT INTO sts_ldap_counts AS c (realm, base_key, attribute, shard, n) SELECT realm, base_key, attribute, (pg_backend_pid() % 16)::smallint, n FROM (SELECT realm, base_key, '' AS attribute, n FROM bases WHERE n <> 0 UNION ALL SELECT realm, base_key, 'userpassword', holding FROM bases WHERE holding <> 0) AS d ORDER BY realm, base_key, attribute ON CONFLICT (realm, base_key, attribute, shard) DO UPDATE SET n = c.n + EXCLUDED.n; RETURN NULL; END $$"}, #{at: 62, text: "CREATE OR REPLACE FUNCTION sts_ldap_count_truncate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN DELETE FROM sts_ldap_counts; DELETE FROM sts_ldap_count_deltas; RETURN NULL; END $$"}, #{at: 63, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_count_insert AFTER INSERT ON sts_ldap_entries REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_note()"}, #{at: 64, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_count_update AFTER UPDATE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_note()"}, #{at: 65, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_count_delete AFTER DELETE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_note()"}, #{at: 66, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_count_truncate AFTER TRUNCATE ON sts_ldap_entries FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_count_truncate()"}, #{at: 67, text: "DROP TRIGGER IF EXISTS sts_ldap_count_deltas_fold ON sts_ldap_count_deltas"}, #{at: 68, text: "DROP FUNCTION IF EXISTS sts_ldap_count_fold()"}, #{at: 69, text: "DROP TRIGGER IF EXISTS sts_ldap_count_deltas_fold_sharded ON sts_ldap_count_deltas"}, #{at: 70, text: "CREATE CONSTRAINT TRIGGER sts_ldap_count_deltas_fold_sharded AFTER INSERT ON sts_ldap_count_deltas DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.fold) EXECUTE FUNCTION sts_ldap_count_fold_sharded()"}, #{at: 71, text: "CREATE OR REPLACE FUNCTION sts_ldap_dek_note() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE added bigint; BEGIN IF TG_OP = 'INSERT' THEN INSERT INTO sts_ldap_dek_deltas (dek_id, n) SELECT d.key, sum(d.value::bigint) FROM new_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d GROUP BY d.key; ELSIF TG_OP = 'DELETE' THEN INSERT INTO sts_ldap_dek_deltas (dek_id, n) SELECT d.key, -sum(d.value::bigint) FROM old_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d GROUP BY d.key; ELSE INSERT INTO sts_ldap_dek_deltas (dek_id, n) SELECT k, sum(n) FROM (SELECT d.key AS k, d.value::bigint AS n FROM new_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d UNION ALL SELECT d.key, -d.value::bigint FROM old_rows AS r CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(r.dek_keys) = 'object' THEN r.dek_keys END) AS d) AS c GROUP BY k HAVING sum(n) <> 0; END IF; GET DIAGNOSTICS added = ROW_COUNT; IF added > 0 AND NOT EXISTS (SELECT 1 FROM sts_ldap_dek_deltas WHERE txid = pg_current_xact_id() AND fold) THEN INSERT INTO sts_ldap_dek_deltas (dek_id, n, fold) VALUES ('', 0, true); END IF; RETURN NULL; END $$"}, #{at: 72, text: "CREATE OR REPLACE FUNCTION sts_ldap_dek_fold_sharded() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN WITH folded AS (DELETE FROM sts_ldap_dek_deltas WHERE txid = pg_current_xact_id() RETURNING dek_id, n) INSERT INTO sts_ldap_dek_counts AS c (dek_id, shard, n) SELECT dek_id, (pg_backend_pid() % 16)::smallint, sum(n) FROM folded WHERE dek_id <> '' GROUP BY dek_id HAVING sum(n) <> 0 ORDER BY dek_id ON CONFLICT (dek_id, shard) DO UPDATE SET n = c.n + EXCLUDED.n; RETURN NULL; END $$"}, #{at: 73, text: "CREATE OR REPLACE FUNCTION sts_ldap_dek_truncate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN DELETE FROM sts_ldap_dek_counts; DELETE FROM sts_ldap_dek_deltas; RETURN NULL; END $$"}, #{at: 74, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_insert AFTER INSERT ON sts_ldap_entries REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_note()"}, #{at: 75, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_update AFTER UPDATE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_note()"}, #{at: 76, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_delete AFTER DELETE ON sts_ldap_entries REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_note()"}, #{at: 77, text: "CREATE OR REPLACE TRIGGER sts_ldap_entries_dek_truncate AFTER TRUNCATE ON sts_ldap_entries FOR EACH STATEMENT EXECUTE FUNCTION sts_ldap_dek_truncate()"}, #{at: 78, text: "DROP TRIGGER IF EXISTS sts_ldap_dek_deltas_fold ON sts_ldap_dek_deltas"}, #{at: 79, text: "DROP FUNCTION IF EXISTS sts_ldap_dek_fold()"}, #{at: 80, text: "DROP TRIGGER IF EXISTS sts_ldap_dek_deltas_fold_sharded ON sts_ldap_dek_deltas"}, #{at: 81, text: "CREATE CONSTRAINT TRIGGER sts_ldap_dek_deltas_fold_sharded AFTER INSERT ON sts_ldap_dek_deltas DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.fold) EXECUTE FUNCTION sts_ldap_dek_fold_sharded()"}, #{at: 82, text: "INSERT INTO sts_ldap_counts (realm, base_key, attribute, n) SELECT e.realm, b.base_key, a.attribute, count(*) FROM sts_ldap_entries AS e CROSS JOIN LATERAL sts_ldap_count_bases(e.parent_key) AS b(base_key) CROSS JOIN LATERAL (SELECT '' AS attribute UNION ALL SELECT 'userpassword' WHERE e.attr_names ? 'userpassword') AS a WHERE NOT EXISTS (SELECT 1 FROM sts_ldap_counts) GROUP BY e.realm, b.base_key, a.attribute"}, #{at: 83, text: "INSERT INTO sts_ldap_dek_counts (dek_id, n) SELECT d.key, sum(d.value::bigint) FROM sts_ldap_entries AS e CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(e.dek_keys) = 'object' THEN e.dek_keys END) AS d WHERE NOT EXISTS (SELECT 1 FROM sts_ldap_dek_counts) GROUP BY d.key"}, #{at: 85, text: "ALTER TABLE sts_realms ADD COLUMN IF NOT EXISTS domain text"}, #{at: 86, text: "ALTER TABLE sts_realms ADD COLUMN IF NOT EXISTS retiring_at bigint"}, #{at: 90, text: "ALTER TABLE sts_minted ADD COLUMN IF NOT EXISTS expires_at bigint"}, #{at: 91, text: "ALTER TABLE sts_minted ADD COLUMN IF NOT EXISTS key_sealed text NOT NULL DEFAULT ''"}, #{at: 94, text: "DROP INDEX IF EXISTS sts_minted_written"}, #{at: 95, text: "ALTER TABLE sts_minted SET (fillfactor=80)"}, #{at: 107, text: "ALTER TABLE sts_minted_index ADD COLUMN IF NOT EXISTS sort_at bigint"}, #{at: 111, text: "ALTER TABLE sts_changes SET (autovacuum_vacuum_scale_factor=0.02, autovacuum_vacuum_cost_limit=2000)"}, #{at: 138, text: "ALTER TABLE sts_risk_assessments ADD COLUMN IF NOT EXISTS feedback text NOT NULL DEFAULT ''"}, #{at: 139, text: "ALTER TABLE sts_risk_assessments ADD COLUMN IF NOT EXISTS feedback_at bigint NOT NULL DEFAULT 0"}, #{at: 158, text: "INSERT INTO sts_schema (version) VALUES (31) ON CONFLICT (version) DO NOTHING"}, #{at: 159, text: "SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'sts_app_role', :'sts_app_password') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'sts_app_role') SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'sts_app_role', :'sts_app_password') SELECT format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE ' || 'NOREPLICATION NOBYPASSRLS', :'sts_app_role') WHERE (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) SELECT format('ALTER ROLE %I NOCREATEDB NOCREATEROLE', :'sts_app_role') WHERE NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) SELECT format('DO $check$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles ' || 'WHERE rolname = %L AND (rolsuper OR rolreplication OR ' || 'rolbypassrls)) THEN RAISE EXCEPTION ''sts-schema: the ' || 'application role holds SUPERUSER, REPLICATION or BYPASSRLS, ' || 'which only a superuser can remove''; END IF; END $check$', :'sts_app_role') SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'sts_app_role') GRANT USAGE ON SCHEMA :\"sts_schema\" TO :\"sts_app_role\""}, #{at: 160, text: "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA :\"sts_schema\" TO :\"sts_app_role\""}, #{at: 161, text: "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA :\"sts_schema\" TO :\"sts_app_role\""}, #{at: 162, text: "ALTER DEFAULT PRIVILEGES IN SCHEMA :\"sts_schema\" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :\"sts_app_role\""}, #{at: 163, text: "ALTER DEFAULT PRIVILEGES IN SCHEMA :\"sts_schema\" GRANT USAGE, SELECT ON SEQUENCES TO :\"sts_app_role\""}, #{at: 164, text: "REVOKE CREATE ON SCHEMA :\"sts_schema\" FROM PUBLIC"}, #{at: 165, text: "REVOKE CREATE ON SCHEMA :\"sts_schema\" FROM :\"sts_app_role\""}, #{at: 166, text: "REVOKE CREATE ON SCHEMA public FROM PUBLIC"}, #{at: 167, text: "REVOKE CREATE ON SCHEMA public FROM :\"sts_app_role\""}, #{at: 168, text: "SELECT format('REVOKE CREATE ON DATABASE %I FROM PUBLIC', current_database()) SELECT format('REVOKE CREATE ON DATABASE %I FROM %I', current_database(), :'sts_app_role') COMMIT"}]})
model PostgresSchema {}
