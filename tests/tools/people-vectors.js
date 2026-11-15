// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: people-vectors.js
//
// ---------------------------------------------------------------------------
// THE INVENTED PERSON AND THE TYPED-ATTRIBUTE CHECK (#444, phase 5, the
// `apis5` slice; `sts-registers`' `persona` module).
//
// What `users/create` reads in Node that Rust reads as tables
// (`rust/crates/sts-registers/tables/people.json`,
// `tests/tools/export-person-tables.js`):
//
//   * `personas`: `vcClaims.personaFor(name)` for names of every shape a
//     create or a sign-in hands it — a plain name, a dotted one, upper case,
//     digits, a long one, one with spaces round it, the empty name;
//   * `checks`: `personEditor.checkCreateValues(name, values)` and
//     `vcClaims.personField(name)` for the attribute names and values a
//     create may carry — every format the editor holds a value to, a value
//     too long, a control character, several values where one is allowed,
//     a name nobody knows.
//
// Written by `tests/tools/crypto-vectors.js` as `people-node.json`
// (`STS_ONLY=people`); read by `rust/crates/sts-registers/tests/
// people_vectors.rs`, which writes `people-rust.json` back under
// `STS_WRITE_VECTORS=1` — Rust's personas for names of its own choosing,
// and its checks — and `tests/rust_crypto_vectors.js` holds THAT to Node
// through `checkRust()` below.
// ---------------------------------------------------------------------------

const path = require('path');

const NAMES = ['alice', 'bob', 'carol', 'admin', 'Alice', 'e2e.ann',
               'two.realms.1', 'x', 'user-0001', 'user-4999', ' padded ',
               'MiXeD.Case', 'ünïcode', 'a'.repeat(120), '', 'bootstrap',
               'sts-admin', 'pseudo.owner', 'bulk.00042', 'realm.admin'];

const CHECKS = [
  ['c', ['SE']], ['c', ['se']], ['c', ['XX']], ['c', ['SE', 'NO']],
  ['schacDateOfBirth', ['1990-02-28']], ['schacDateOfBirth', ['19900230']],
  ['schacDateOfBirth', ['1990-1-01']], ['preferredLanguage', ['sv, en;q=0.5']],
  ['preferredLanguage', ['not a language!']], ['labeledURI',
    ['https://example.com/~ann Ann']], ['labeledURI', ['ftp://x']],
  ['employeeNumber', ['E123456']], ['mail', ['ann@example.com']],
  ['mail', ['not-an-address']], ['manager',
    ['uid=bob,ou=users,dc=example,dc=com']], ['manager', ['bob']],
  ['givenName', ['Ann']], ['givenName', ['Ann', 'Anne']],
  ['description', ['line\nbreak']], ['description', ['x'.repeat(1025)]],
  ['telephoneNumber', ['+1 555 0100', '+1 555 0101']],
  ['nosuchattribute', ['x']], ['userPassword', ['secret']],
  ['displayName', ['  spaced  ']], ['cn', ['Ann Example']],
  ['sn', ['Example']], ['title', ['Engineer']], ['o', ['Example']],
  ['schacGender', ['2']], ['zoneinfo', ['Europe/Stockholm']],
  ['picture', ['https://example.com/p.jpg']], ['middleName', ['Q']]
];

/**
 * The vectors.
 *
 * @param {string} ROOT - the repository
 * @returns {any} the set
 */
function build(ROOT) {
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const vcClaims = require(path.join(ROOT, 'oid4vc', 'vc_claims'));
  const personEditor = require(path.join(ROOT, 'ldap', 'person_editor'));
  return {
    personas: NAMES.map(function (name) {
      return { name: name, persona: vcClaims.personaFor(name) };
    }),
    checks: CHECKS.map(function (one) {
      const field = vcClaims.personField(one[0]);
      return { name: one[0], values: one[1],
               personField: field ? field.ldap : null,
               checked: personEditor.checkCreateValues(one[0], one[1]) };
    })
  };
}

/**
 * Holds Rust's answers to Node's.
 *
 * @param {string} ROOT - the repository
 * @param {any} rust - people-rust.json
 * @param {Function} check - `check(ok, what, detail)`
 */
function checkRust(ROOT, rust, check) {
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const vcClaims = require(path.join(ROOT, 'oid4vc', 'vc_claims'));
  const personEditor = require(path.join(ROOT, 'ldap', 'person_editor'));
  (rust.personas || []).forEach(function (one) {
    const node = vcClaims.personaFor(one.name);
    check(JSON.stringify(node) === JSON.stringify(one.persona),
          'Rust invents the person Node invents for "' + one.name + '"',
          'Node ' + JSON.stringify(node) + ', Rust ' +
          JSON.stringify(one.persona));
  });
  (rust.checks || []).forEach(function (one) {
    const node = personEditor.checkCreateValues(one.name, one.values);
    check(JSON.stringify(node) === JSON.stringify(one.checked),
          'Rust holds ' + one.name + ' ' + JSON.stringify(one.values) +
          ' to the editor\'s rule as Node does',
          'Node ' + JSON.stringify(node) + ', Rust ' +
          JSON.stringify(one.checked));
  });
}

module.exports = { build: build, checkRust: checkRust, NAMES: NAMES,
                   CHECKS: CHECKS };
