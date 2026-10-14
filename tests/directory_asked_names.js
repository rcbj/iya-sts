// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_asked_names.js
//
// ===========================================================================
// THE DIRECTORY'S TWO NARROWED INDEXES (#618 phase 2, schema version 18,
// 2026-10-14).
//
// Until version 18 `sts_ldap_entries` had a GIN index over every attribute
// NAME of every entry (`attr_names`, about fifteen a person, twelve of them
// in 99.9% of 8081's 1.2M rows) and another over every object CLASS
// (`class_keys`, four a person, each in more than 99%): about nineteen GIN
// entries a person insert that no question could narrow by. Version 18
// indexes the names a holder question asks and the group classes, and
// nothing else. What can go wrong with that is SILENT — a holder question
// that misses the index is a scan, and one whose name the index leaves out
// would answer "nobody" if it used the index — so asserted here:
//
//   A. THE LIST IS THE CALLERS': every attribute name a holder question is
//      asked about, read out of the call sites' source (the
//      `eachHolderOfAny([...])` literals and the named constants the
//      dynamic callers pass), is in ASKED_ATTRIBUTES or counted — and every
//      name in the list is asked somewhere, so it cannot rot into an index
//      of names nobody asks.
//   B. THE QUERIES REPEAT THE INDEX: `withAttribute()` and
//      `anyWithAttribute()` ask an asked name through ASKED_NAMES and the
//      partial predicate, character for character what the driver's index
//      is built on; a counted name is asked of its counter; any other name
//      is still answered, by the bare column, and said once in the log.
//      `classesUnder()` repeats the group-class predicate.
//   C. THE CODEC WRITES THE GROUP CLASSES ONLY: a person's `class_keys` is
//      `[]`, which the partial index leaves out; a group's holds its group
//      class and nothing else; and `classesUnder` asked for a class the
//      column no longer holds is refused rather than answered "nobody".
//   D. THE SCHEMA: the two indexes are PARTIAL, GIN with the default
//      operator class, on exactly the builders' expressions; the two they
//      replace are retired, not in SCHEMA_OBJECTS; the version is 18.
//
// WHAT NEEDS A REAL POSTGRES — that the planner USES each index for each
// query, and what the per-insert cost is — was measured on a copy of
// 8081's 1.2M-entry store and is on #618; `npm test` has no PostgreSQL.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const queries = require('../persistence/directory_queries');
const codec = require('../persistence/directory_codec');
const postgres = require('../persistence/persistence_postgres');

const log = require('bunyan').createLogger({ name: 'directory_asked_names',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const USERS = 'ou=users,dc=example,dc=com';

function source(relative) {
  log.debug("Entering source(). " + relative);
  log.debug("Leaving source().");
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

// The one quoted value a pattern captures in a file, or '' — a constant
// renamed or moved is a failure here, not a name silently left out.
function captured(relative, pattern) {
  log.debug("Entering captured(). " + relative);
  const match = pattern.exec(source(relative));
  log.debug("Leaving captured().");
  return match ? match[1].toLowerCase() : '';
}

// ---------------------------------------------------------------------------
// A. Every name a holder question is asked about, from its call site.
// ---------------------------------------------------------------------------
function namesAsked(t) {
  log.debug("Entering namesAsked().");
  const asked = new Map();
  const note = function (name, where) {
    if (name) {
      asked.set(name, (asked.get(name) || []).concat([where]));
    }
  };
  // `ldap_server.js`'s own walks: `eachHolderOfAny([...])` with literals.
  const ldap = source('ldap/ldap_server.js');
  const literal = /eachHolderOfAny\(\s*\[([^\]]*)\]/g;
  let sites = 0;
  let match;
  while ((match = literal.exec(ldap)) !== null) {
    const names = match[1].match(/'([^']+)'/g) || [];
    if (names.length) {
      sites += 1;
    }
    names.forEach(function (quoted) {
      note(quoted.slice(1, -1).toLowerCase(), 'ldap_server.js');
    });
  }
  t.check(sites >= 9,
          'A1. the eachHolderOfAny() literal sites in ldap_server.js are ' +
          'read (' + sites + ')');
  // `anybodyHoldsACredential()`: whether anybody holds a password.
  const anyHolder = /anyHolder\([^,]+,\s*'([^']+)'\)/.exec(ldap);
  note(anyHolder ? anyHolder[1] : '', 'ldap_server.js anyHolder');
  // The dynamic callers, by the constants they pass.
  const constants = [
    ['common/credentials.ts', /WEBAUTHN_ATTRIBUTE = '([^']+)'/],
    ['common/credentials.ts', /TOTP_ATTRIBUTE = '([^']+)'/],
    ['common/credentials.ts', /ANDROID_MARKER_ATTRIBUTE = '([^']+)'/],
    ['common/mail_factor.ts', /OPT_IN_ATTRIBUTE = '([^']+)'/],
    ['common/devices.ts', /const ANDROID_MARKER_ATTRIBUTE = '([^']+)'/],
    ['common/devices.ts', /'holdersAsync', 'device',\s*'([^']+)'/],
    ['common/person_assertions.js', /const ISSUER_ATTRIBUTE = '([^']+)'/],
    ['common/person_assertions.js',
     /const SAML_ISSUER_ATTRIBUTE = '([^']+)'/],
    ['common/person_assertions.js', /present: '(stsAssertion[^']+)'/],
    ['common/person_assertions.js', /present: '(stsSaml[^']+)'/],
    ['scim/scim_auth.ts', /HOBA_ATTRIBUTE = '([^']+)'/]
  ];
  constants.forEach(function (one) {
    const name = captured(one[0], one[1]);
    t.check(!!name, 'A2. ' + one[0] + ' still names ' + one[1].source);
    note(name, one[0]);
  });
  // `cert_enrollment.ts`'s holders: every person attribute it may name.
  const enrollment = /\n {2}person: \{([^}]*)\}/.exec(
    source('common/cert_enrollment.ts'));
  t.check(!!enrollment, 'A3. cert_enrollment.ts\'s person attributes are ' +
          'read');
  ((enrollment && enrollment[1].match(/'([^']+)'/g)) || []).forEach(
    function (quoted) {
      note(quoted.slice(1, -1).toLowerCase(), 'cert_enrollment.ts');
    });
  const covered = function (name) {
    return queries.ASKED_ATTRIBUTES.indexOf(name) >= 0 ||
      queries.COUNTED_ATTRIBUTES.indexOf(name) >= 0;
  };
  const missing = Array.from(asked.keys()).filter(function (name) {
    return !covered(name);
  });
  t.check(asked.size >= 25 && missing.length === 0,
          'A4. every name a holder question is asked about (' + asked.size +
          ') is in ASKED_ATTRIBUTES or counted',
          JSON.stringify(missing.map(function (name) {
            return name + ' (' + asked.get(name).join(', ') + ')';
          })));
  const unasked = queries.ASKED_ATTRIBUTES.filter(function (name) {
    return !asked.has(name);
  });
  t.check(unasked.length === 0,
          'A5. and every name in ASKED_ATTRIBUTES is asked somewhere — an ' +
          'index of names nobody asks is the cost version 18 removed',
          JSON.stringify(unasked));
  t.check(queries.ASKED_ATTRIBUTES.indexOf('userpassword') < 0 &&
          asked.has('userpassword'),
          'A6. userpassword, held by nearly every person, is asked of the ' +
          'counters rather than indexed');
  log.debug("Leaving namesAsked().");
}

// ---------------------------------------------------------------------------
// B. The builders repeat the index's expression and predicate.
// ---------------------------------------------------------------------------
function builders(t) {
  log.debug("Entering builders().");
  const asked = queries.withAttribute('default', USERS, 'stsTotpCredential',
                                      'uid=a', 50);
  t.check(asked.text.indexOf(queries.ASKED_NAMES + ' ? $3') >= 0 &&
          asked.text.indexOf(queries.ASKED_NAMES_HELD) >= 0 &&
          !/[^(]attr_names \?/.test(asked.text.replace(
            queries.ASKED_NAMES_HELD, '')) &&
          asked.values[2] === 'ststotpcredential',
          'B1. withAttribute() asks an asked name through ASKED_NAMES and ' +
          'the partial predicate', asked.text);
  const other = queries.withAttribute('default', USERS, 'description', '',
                                      50);
  t.check(/ AND attr_names \? \$3 AND /.test(other.text) &&
          other.text.indexOf(queries.ASKED_NAMES) < 0,
          'B2. a name not in the list is still answered, by the bare column',
          other.text);
  const counted = queries.anyWithAttribute('acme', 'userPassword');
  t.check(/FROM sts_ldap_counts/.test(counted.text) &&
          /base_key = ''/.test(counted.text) && /n > 0/.test(counted.text) &&
          !/sts_ldap_entries/.test(counted.text) &&
          JSON.stringify(counted.values) ===
            JSON.stringify(['acme', 'userpassword']),
          'B3. whether anybody holds a password is the realm\'s counter',
          counted.text);
  const any = queries.anyWithAttribute('acme', 'oauthConsent');
  t.check(any.text.indexOf(queries.ASKED_NAMES + ' ? $2') >= 0 &&
          any.text.indexOf(queries.ASKED_NAMES_HELD) >= 0 &&
          /LIMIT 1$/.test(any.text),
          'B4. whether anybody holds an asked name is the index', any.text);
  const groups = queries.classesUnder('default', USERS, ['groupOfNames']);
  t.check(groups.text.indexOf('class_keys ?| $3::text[] AND ' +
                              queries.GROUP_CLASSES_HELD) >= 0,
          'B5. classesUnder() repeats the group-class predicate',
          groups.text);
  t.check(/^jsonb_path_query_array\(attr_names, '\$\[\*\] \? \(@ == "/
    .test(queries.ASKED_NAMES) &&
          queries.ASKED_ATTRIBUTES.every(function (name) {
            return queries.ASKED_NAMES.indexOf('@ == "' + name + '"') > 0 &&
              queries.ASKED_NAMES_HELD.indexOf('\'' + name + '\'') > 0;
          }),
          'B6. the expression and the predicate name every asked attribute');
  log.debug("Leaving builders().");
}

// ---------------------------------------------------------------------------
// C. The codec writes the group classes only.
// ---------------------------------------------------------------------------
function classes(t) {
  log.debug("Entering classes().");
  const person = codec.indexOf({
    objectclass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
    uid: ['alice'], userpassword: ['x'] });
  t.equal(JSON.stringify(person.classKeys), '[]',
          'C1. a person writes no class key, so the partial index leaves ' +
          'it out');
  t.check(person.attrNames.indexOf('userpassword') >= 0 &&
          person.attrNames.indexOf('objectclass') >= 0,
          'C2. and attr_names still holds every name (the counters read it)');
  const group = codec.indexOf({ objectClass: ['top', 'GroupOfNames'],
                                cn: ['staff'] });
  t.equal(JSON.stringify(group.classKeys),
          JSON.stringify([codec.lookupOf('class', 'groupofnames')]),
          'C3. a group writes its group class, lower-cased, and not `top`');
  const posix = codec.indexOf({ objectclass: ['posixGroup', 'groupOfURLs',
                                              'top'] });
  t.equal(posix.classKeys.length, 2,
          'C4. every group class an entry carries is written');
  t.equal(JSON.stringify(codec.CLASS_INDEXED),
          JSON.stringify(['groupofnames', 'groupofuniquenames', 'posixgroup',
                          'groupofurls']),
          'C5. the indexed classes are the four group classes');
  const groupClasses = /const GROUP_CLASSES = \[([^\]]*)\]/.exec(
    source('ldap/ldap_server.js'));
  t.equal(JSON.stringify(((groupClasses && groupClasses[1]
    .match(/'([^']+)'/g)) || []).map(function (q) {
    return q.slice(1, -1);
  })), JSON.stringify(codec.CLASS_INDEXED),
          'C6. and they are ldap_server.js\'s GROUP_CLASSES, the only ' +
          'classes classesUnder() is asked for');
  let refused = '';
  try {
    codec.keyArgs('classesUnder', ['default', USERS, ['inetOrgPerson']]);
  } catch (e) {
    log.debug("Caught in classes(): " + ((e && e.message) || e));
    refused = String((e && e.message) || e);
  }
  t.check(/group classes/.test(refused),
          'C7. classesUnder asked for a class the column does not hold is ' +
          'refused, not answered "nobody"', refused);
  const keyed = codec.keyArgs('classesUnder',
                              ['default', USERS, ['groupOfNames']]);
  t.equal(JSON.stringify(keyed[2]),
          JSON.stringify([{ key: codec.lookupOf('class', 'groupofnames') }]),
          'C8. a group class is keyed as the codec writes it');
  log.debug("Leaving classes().");
}

// ---------------------------------------------------------------------------
// D. The schema.
// ---------------------------------------------------------------------------
function schema(t) {
  log.debug("Entering schema().");
  const byName = function (name) {
    return postgres.SCHEMA_OBJECTS.filter(function (o) {
      return o.name === name;
    })[0];
  };
  const names = byName('sts_ldap_entries_asked_names');
  t.equal(names && names.statement,
          'CREATE INDEX IF NOT EXISTS sts_ldap_entries_asked_names ON ' +
          'sts_ldap_entries USING gin ((' + queries.ASKED_NAMES + ')) WHERE ' +
          queries.ASKED_NAMES_HELD,
          'D1. the names\' index is a partial GIN, default operator class, ' +
          'on exactly the builders\' expression and predicate');
  const groups = byName('sts_ldap_entries_group_classes');
  t.equal(groups && groups.statement,
          'CREATE INDEX IF NOT EXISTS sts_ldap_entries_group_classes ON ' +
          'sts_ldap_entries USING gin (class_keys) WHERE ' +
          queries.GROUP_CLASSES_HELD,
          'D2. the classes\' index is a partial GIN on the builders\' ' +
          'predicate');
  t.check(names && names.afterColumns === true && groups &&
          groups.afterColumns === true,
          'D3. both wait for the column step');
  const retired = (postgres.SCHEMA_RETIRED || []).map(function (o) {
    return o.name;
  });
  t.check(retired.length === 2 && retired.every(function (name) {
    return !byName(name);
  }), 'D4. the two indexes they replace are retired and no longer created',
          JSON.stringify(retired));
  t.equal(postgres.SCHEMA_VERSION, 18, 'D5. the schema version is 18');
  log.debug("Leaving schema().");
}

module.exports = {
  name: 'directory_asked_names',
  describe: 'schema version 18 indexes only the attribute names a holder ' +
            'question asks and the group classes (#618): the list is the ' +
            'callers\', the queries repeat the index, the codec writes the ' +
            'group classes only',
  run: function run(t) {
    log.debug("Entering run().");
    namesAsked(t);
    builders(t);
    classes(t);
    schema(t);
    log.debug("Leaving run().");
  }
};
