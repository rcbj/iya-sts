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
const ModelTables = require('../common/model_tables');

const SCHEMA_VERSION = 32;

/**
 * Every table and index of the MariaDB schema, each `{ name, statement }`, in
 * creation order; each statement is `mariadb/schema.sql`'s, without its
 * semicolon.
 */
// The tables and indexes are written in
// models/persistence/persistence_mariadb.tsp (#1390).
const SCHEMA_OBJECTS = ModelTables.file('persistence.mariadb.json').objects;

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
