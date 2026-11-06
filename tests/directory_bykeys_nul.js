// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_bykeys_nul.js
//
// ===========================================================================
// A NUL BYTE IN A DIRECTORY LOOKUP NEVER REACHES THE STORE (#1356).
//
// iya-sts-60 root-caused the fuzz gate's uncaught admin-api 500s to one bug: a
// fuzzed input carrying a NUL byte (0x00) became a directory lookup key and was
// handed to `byKeys`, whose `SELECT ... WHERE dn_key = ANY(...)` sent it to
// PostgreSQL — which holds no NUL in text and rejected the whole statement, so
// the driver threw and the request answered an uncaught 500.
//
// `byName` reads the same NUL a second way: the name it looks up is bound to
// `rdn_value = $4` (and digested into a `name_keys @> $3` term), so a NUL in a
// looked-up name throws exactly as a NUL dn_key does — and the RDN carries it
// even in product, where the key is a digest.
//
// A value with a NUL can match NO stored entry (nothing this service writes
// into a dn_key, an rdn_value or a name digest holds a NUL), so the correct
// answer for such a lookup is "no row". The builders (PostgreSQL
// `directory_queries.js`, MariaDB `directory_queries_mariadb.js`) drop a
// NUL-bearing key or name before it reaches the connection. This holds that: a
// NUL key/name is dropped, the clean values beside it are kept, and an all-NUL
// lookup queries nothing. It is not a refusal and carries no error code — a 500
// becomes a correct empty result.
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
const PARENT = 'ou=users,dc=example,dc=com';
const NUL_NAME = 'al\u0000ice';

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

  // -----------------------------------------------------------------------
  // PostgreSQL: byName(realm, parentKey, name) builds { text, values }. A
  // clean name is the ordinary four-value lookup; a NUL in the name (as a raw
  // string, or in the `rdn`/`key` of the keyed `{ key, rdn }` form) short-
  // circuits to a statement that matches nothing, with no values.
  // -----------------------------------------------------------------------
  const cleanName = pg.byName('acme', PARENT, 'alice');
  t.equal(cleanName.values.length, 4,
          'postgres byName builds the four-value lookup for a clean name');
  t.equal(cleanName.values[3], 'alice',
          'postgres byName binds the clean RDN');
  t.ok(cleanName.text.indexOf('WHERE false') < 0,
       'postgres byName with a clean name is the ordinary lookup');

  const nulName = pg.byName('acme', PARENT, NUL_NAME);
  t.ok(nulName.text.indexOf('WHERE false') >= 0,
       'postgres byName with a NUL in the name matches nothing');
  t.equal(nulName.values.length, 0,
          'postgres byName with a NUL name binds no value');

  const nulRdn = pg.byName('acme', PARENT, { key: 'name\nclean', rdn: NUL_NAME });
  t.ok(nulRdn.text.indexOf('WHERE false') >= 0,
       'postgres byName with a NUL in the keyed form\'s RDN matches nothing');

  const nulKeyed = pg.byName('acme', PARENT,
                             { key: 'name\nal\u0000ice', rdn: 'alice' });
  t.ok(nulKeyed.text.indexOf('WHERE false') >= 0,
       'postgres byName with a NUL in the keyed form\'s key matches nothing');

  // -----------------------------------------------------------------------
  // MariaDB: byName(ask, realm, parentKey, name) and withNames() both go
  // through namedRows, which drops a NUL-bearing name and resolves [] without
  // calling ask when nothing clean is left.
  // -----------------------------------------------------------------------
  captured = null;
  maria.QUERIES.byName(ask, 'acme', PARENT, 'alice');
  t.ok(captured !== null &&
       captured.bindings.indexOf('alice') >= 0,
       'mariadb byName binds a clean name');

  captured = null;
  const nameEmpty = maria.QUERIES.byName(ask, 'acme', PARENT, NUL_NAME);
  t.ok(captured === null,
       'mariadb byName with a NUL in the name never reaches the driver');
  t.ok(nameEmpty && typeof nameEmpty.then === 'function',
       'mariadb byName with a NUL name resolves (an empty answer)');

  captured = null;
  maria.QUERIES.withNames(ask, 'acme', PARENT, ['alice', NUL_NAME, 'bob']);
  t.ok(captured !== null &&
       captured.bindings.indexOf('alice') >= 0 &&
       captured.bindings.indexOf('bob') >= 0,
       'mariadb withNames keeps the clean names');
  t.ok(captured !== null &&
       captured.bindings.indexOf(NUL_NAME) < 0,
       'mariadb withNames drops the NUL-bearing name from the bindings');
}

module.exports = {
  name: 'directory_bykeys_nul',
  describe: 'a NUL byte in a dn_key or a looked-up name is dropped before ' +
            'byKeys or byName reaches the store (#1356)',
  run: run
};
