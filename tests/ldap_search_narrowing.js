// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_search_narrowing.js
//
// ===========================================================================
// AN LDAP SEARCH IN A WINDOWED PROCESS IS NARROWED BY THE STORE'S INDEX
// (#320, 2026-10-13).
//
// A windowed process — every process on a postgres store since #320 — answers
// an equality on `uid` or `mail` from the store's index rather than by paging
// every person under the base. The answer must not change, so what is held
// here is the part that decides it:
//
//   A. which filters narrow, and to which lookups: an indexed equality; an
//      AND's narrowable term; every term of an OR, or nothing; never a NOT,
//      a presence, a substring, a non-indexed attribute, a value with
//      surrounding space, or more lookups than the bound;
//   B. the `equalUnder` statement: the base and everything under it, the
//      column of the kind, the asserted value lower-cased, the cap; an
//      unknown kind refused;
//   C. the bridge's keying of it: the value replaced by its index key, the
//      kind left for the column.
//
// WHAT NEEDS A REAL POSTGRES (measured on #320, not here): that the narrowed
// answers equal a whole directory's — eighteen filter shapes, entries written
// and not yet flushed included — and the timings.
// ===========================================================================

const filters = require('@ldapjs/filter');
const ldap = require('../ldap/ldap_server');
const queries = require('../persistence/directory_queries');
const codec = require('../persistence/directory_codec');

const log = require('bunyan').createLogger({ name: 'ldap_search_narrowing',
  level: process.env.LOG_LEVEL || 'info' });

function lookups(text) {
  log.debug("Entering lookups(). " + text);
  log.debug("Leaving lookups().");
  return ldap.indexedLookupsOf(filters.parseString(text), 0);
}

function sectionFilters(t) {
  log.debug("Entering sectionFilters().");
  t.log.info('=== A. which filters narrow ===');
  t.equal(JSON.stringify(lookups('(uid=alice)')),
          JSON.stringify([{ kind: 'name', value: 'alice' }]),
          'A1. a uid equality is one name lookup');
  t.equal(JSON.stringify(lookups('(MAIL=a@example.com)')),
          JSON.stringify([{ kind: 'mail', value: 'a@example.com' }]),
          'A2. a mail equality, the attribute in any case, is one mail lookup');
  t.equal(JSON.stringify(lookups('(&(objectClass=person)(uid=bob))')),
          JSON.stringify([{ kind: 'name', value: 'bob' }]),
          'A3. an AND narrows on its indexed term');
  t.equal(JSON.stringify(lookups('(|(uid=a)(mail=b@x))')),
          JSON.stringify([{ kind: 'name', value: 'a' },
                          { kind: 'mail', value: 'b@x' }]),
          'A4. an OR of indexed equalities is the union of their lookups');
  t.equal(JSON.stringify(lookups('(&(sn=x)(|(uid=a)(uid=b)))')),
          JSON.stringify([{ kind: 'name', value: 'a' },
                          { kind: 'name', value: 'b' }]),
          'A5. an OR nested in an AND narrows the AND');
  t.equal(lookups('(|(uid=a)(sn=b))'), null,
          'A6. an OR with a term that names nothing walks');
  t.equal(lookups('(!(uid=a))'), null, 'A7. a NOT walks');
  t.equal(lookups('(uid=*)'), null, 'A8. a presence walks');
  t.equal(lookups('(uid=al*)'), null, 'A9. a substring walks');
  t.equal(lookups('(cn=alice)'), null,
          'A10. an equality on an attribute the store does not index walks');
  t.equal(lookups('(uid= alice)'), null,
          'A11. a value with surrounding space walks (the query trims)');
  const wide = '(|' + Array.from({ length: 17 }, function (x, i) {
    return '(uid=u' + i + ')';
  }).join('') + ')';
  t.equal(lookups(wide), null,
          'A12. more lookups than the bound walks rather than asking 17 ' +
          'questions');
  log.debug("Leaving sectionFilters().");
}

function sectionStatement(t) {
  log.debug("Entering sectionStatement().");
  t.log.info('=== B. the equalUnder statement ===');
  const base = 'ou=users,dc=example,dc=com';
  const q = queries.build('equalUnder', ['r1', base, 'name', 'Alice', 1000]);
  t.check(/name_keys @> \$3::jsonb/.test(q.text) &&
          /\(dn_key = \$2 OR right\(dn_key, \$5\) = ',' \|\| \$2\)/
            .test(q.text) &&
          /LIMIT \$4/.test(q.text),
          'B1. the name column, the base and everything under it, a limit',
          q.text);
  t.equal(JSON.stringify(q.values),
          JSON.stringify(['r1', base, JSON.stringify(['name\nalice']), 1000,
                          base.length + 1]),
          'B2. the value lower-cased under its kind, the cap, the suffix ' +
          'length');
  t.check(/mail_keys @>/.test(queries.build('equalUnder',
    ['r1', base, 'mail', 'x', 10]).text), 'B3. the mail kind reads mail_keys');
  let refused = false;
  try {
    queries.build('equalUnder', ['r1', base, 'uuid', 'x', 10]);
  } catch (e) {
    log.debug("Caught in sectionStatement(): " + ((e && e.message) || e));
    refused = /no kind uuid/.test(String(e && e.message));
  }
  t.check(refused, 'B4. a kind with no superset column is refused');
  log.debug("Leaving sectionStatement().");
}

function sectionKeying(t) {
  log.debug("Entering sectionKeying().");
  t.log.info('=== C. the bridge keys the value ===');
  const keyed = codec.keyArgs('equalUnder',
    ['r1', 'ou=users,dc=example,dc=com', 'mail', ' A@Example.COM ', 50]);
  t.equal(keyed[2], 'mail', 'C1. the kind is left for the column');
  t.check(keyed[3] && typeof keyed[3] === 'object' &&
          keyed[3].key === 'mail\na@example.com',
          'C2. the value becomes its index key, trimmed and lower-cased, ' +
          'the form the codec writes', JSON.stringify(keyed[3]));
  const q = queries.build('equalUnder', keyed);
  t.equal(q.values[2], JSON.stringify(['mail\na@example.com']),
          'C3. and the statement uses that key as it is');
  log.debug("Leaving sectionKeying().");
}

async function run(t) {
  log.debug("Entering run().");
  sectionFilters(t);
  sectionStatement(t);
  sectionKeying(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ldap_search_narrowing',
  describe: 'An LDAP equality search in a windowed process is narrowed by ' +
            'the store\'s uid and mail index, to the same answer (#320).',
  run: run
};
