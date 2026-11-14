// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: store_modes.js
//
// ---------------------------------------------------------------------------
// WHICH PERSISTENCE MODES ARE A DATABASE (#677).
//
// `persistence.mode` was `memory`, `ldif` or `postgres`, and "is this a
// database" was spelt `mode === 'postgres'` in a dozen modules. Since #677
// there is a second database engine, `mariadb`, which is the same store —
// the same tables, the same driver (`persistence_postgres.js`), the same
// change log and coordination — compiled for another engine. Every question
// that meant "a database" asks `isDatabase()` here; a question that really
// is about PostgreSQL (the directory window's bridge thread, cells, the bulk
// import, cell conversion, the risk installer) keeps asking for `postgres`
// and refuses MariaDB with its reason.
//
// A LEAF: it requires nothing of this service (bunyan only), so any module
// may require it at any point of the require order without moving a route or
// closing a cycle (rule 3e's test, both ways round: it registers nothing and
// requires nothing here).
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({
  name: 'sts-store-modes',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// The modes, in the order `persistence.mode` lists them.
const MODES = ['memory', 'ldif', 'postgres', 'mariadb'];

// The modes that are a database, each its engine's name.
const DATABASES = ['postgres', 'mariadb'];

/**
 * Whether a persistence mode is a database store.
 *
 * @param mode - a value of `persistence.mode`
 * @returns true for `postgres` and `mariadb`
 */
function isDatabase(mode) {
  log.debug("Entering isDatabase().");
  log.debug("Leaving isDatabase().");
  return DATABASES.indexOf(String(mode)) >= 0;
}

module.exports = {
  MODES: MODES,
  DATABASES: DATABASES,
  isDatabase: isDatabase
};
