// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_bykeys_nul.js
//
// ===========================================================================
// A NUL BYTE IN A dn_key NEVER REACHES THE STORE (#1356).
//
// iya-sts-60 root-caused the fuzz gate's twelve uncaught admin-api 500s to one
// bug: a fuzzed input carrying a NUL byte (0x00) became a directory lookup key
// and was handed to `byKeys`, whose `SELECT ... WHERE dn_key = ANY(...)` sent
// it to PostgreSQL — which holds no NUL in text and rejected the whole
// statement, so the driver threw and the request answered an uncaught 500.
//
// A dn_key with a NUL can match NO stored key (nothing this service writes
// into dn_key holds a NUL), so the correct answer for such a key is "no row".
// Both byKeys builders (PostgreSQL `directory_queries.js`, MariaDB
// `directory_queries_mariadb.js`) drop a NUL-bearing key before it reaches the
// connection. This holds that: a NUL key is dropped, the clean keys beside it
// are kept, and an all-NUL list queries nothing. It is not a refusal and
// carries no error code — a 500 becomes a correct empty result.
//
// IN PROCESS because both claims are about the STATEMENT a builder produces
// (its values / its bindings), which no running service exposes — the shape of
// `postgres_minted_writes.js` and `knex_store.js`.
// ===========================================================================

const pg = require('../persistence/directory_queries');
const maria = require('../persistence/directory_queries_mariadb');

const CLEAN_A = 'cn=alice,ou=users,dc=example,dc=com';
const CLEAN_B = 'cn=bob,ou=users,dc=example,dc=com';
const NUL_KEY = 'cn=\u0000evil,ou=users,dc=example,dc=com';

function run(t) {
  // -----------------------------------------------------------------------
  // PostgreSQL: byKeys(realm, keys) builds { text, values }; values[1] is the
  // key array that goes to `= ANY($2::text[])`.
  // -----------------------------------------------------------------------
  const clean = pg.byKeys('acme', [CLEAN_A, CLEAN_B]);
  t.equal(JSON.stringify(clean.values[1]), JSON.stringify([CLEAN_A, CLEAN_B]),
          'postgres byKeys keeps keys with no NUL byte');

  const mixed = pg.byKeys('acme', [CLEAN_A, NUL_KEY, CLEAN_B]);
  t.equal(JSON.stringify(mixed.values[1]), JSON.stringify([CLEAN_A, CLEAN_B]),
          'postgres byKeys drops the NUL-bearing key and keeps the rest');

  const allNul = pg.byKeys('acme', ['\u0000', 'x\u0000y']);
  t.equal(JSON.stringify(allNul.values[1]), JSON.stringify([]),
          'postgres byKeys with only NUL keys queries an empty key array');
  t.equal(allNul.values[0], 'acme',
          'postgres byKeys still carries the realm');

  // A NUL anywhere in the key is dropped, not only at the front.
  const tail = pg.byKeys('acme', [CLEAN_A, CLEAN_B + '\u0000']);
  t.equal(JSON.stringify(tail.values[1]), JSON.stringify([CLEAN_A]),
          'postgres byKeys drops a key whose NUL is not at the start');

  // -----------------------------------------------------------------------
  // MariaDB: byKeys(ask, realm, keys) calls ask(name, sql, bindings); the
  // bindings are [realm, ...keys]. An empty list after filtering resolves []
  // without calling ask.
  // -----------------------------------------------------------------------
  let captured = null;
  const ask = function (name, sql, bindings) {
    captured = { name: name, sql: sql, bindings: bindings };
    return Promise.resolve([]);
  };

  captured = null;
  maria.QUERIES.byKeys(ask, 'acme', [CLEAN_A, CLEAN_B]);
  t.equal(JSON.stringify(captured && captured.bindings),
          JSON.stringify(['acme', CLEAN_A, CLEAN_B]),
          'mariadb byKeys binds the realm and the clean keys');

  captured = null;
  maria.QUERIES.byKeys(ask, 'acme', [CLEAN_A, NUL_KEY, CLEAN_B]);
  t.equal(JSON.stringify(captured && captured.bindings),
          JSON.stringify(['acme', CLEAN_A, CLEAN_B]),
          'mariadb byKeys drops the NUL-bearing key from the bindings');

  captured = null;
  const empty = maria.QUERIES.byKeys(ask, 'acme', ['\u0000', 'x\u0000y']);
  t.ok(captured === null,
       'mariadb byKeys with only NUL keys never reaches the driver');
  t.ok(empty && typeof empty.then === 'function',
       'mariadb byKeys with only NUL keys resolves (an empty answer)');
}

module.exports = {
  name: 'directory_bykeys_nul',
  describe: 'a NUL byte in a dn_key is dropped before byKeys reaches the ' +
            'store (#1356)',
  run: run
};
