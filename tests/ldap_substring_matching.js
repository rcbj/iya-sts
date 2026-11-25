// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_substring_matching.js
//
// ===========================================================================
// AN LDAP SUBSTRING ASSERTION IS MATCHED BY ONE LINEAR SCAN, AND A WIDE ONE
// IS REFUSED (#2137, ASVS 5.0.0 1.3.12).
//
// `ldap/ldap_matching.ts` built `^initial.*any1.*any2.*...final$` for a
// case-ignoring attribute and handed every other attribute to
// `@ldapjs/filter`, which builds the same thing: `(cn=*a*a*...*b)` against a
// long value backtracked polynomially on the event loop. It now matches
// every substring by a left-to-right `indexOf` scan, and the search handler
// refuses an assertion of more than 32 components. This holds it:
//
//   A. EQUIVALENCE: a table of cases — initial only, any, final, the three
//      together, overlaps (`ab*ba` against `aba`), empty values, empty
//      components, unicode, values with regular-expression characters — each
//      answered by `substringMatches()` exactly as a reference regular
//      expression answers it, and, through `LdapMatching.matches()`, as the
//      library's own `matches()` answers it for an exact-rule attribute and
//      for the value lower-cased on a case-ignoring one.
//   B. THE PATHOLOGICAL FILTER: `*a*a*...*b` at the cap, against a 10 kB
//      value of `a`s, on a case-ignoring and an exact-rule attribute,
//      answered false in well under 200 ms.
//   C. THE CAP: `widestSubstring()` through AND, OR and NOT; a search of 33
//      components refused adminLimitExceeded by `performOperation('search')`
//      (the handler the socket and a request worker run), and one of 32
//      answered.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({
  name: 'ldap_substring_matching',
  level: process.env.LOG_LEVEL || 'info' });

// [value, initial, any, final, expected]
const CASES = [
  ['alice', 'al', [], '', true],
  ['alice', 'li', [], '', false],
  ['alice', '', ['lic'], '', true],
  ['alice', '', ['x'], '', false],
  ['alice', '', [], 'ce', true],
  ['alice', '', [], 'al', false],
  ['alice', 'a', ['l', 'i'], 'e', true],
  ['alice', 'a', ['i', 'l'], 'e', false],
  ['aba', 'ab', [], 'ba', false],
  ['abba', 'ab', [], 'ba', true],
  ['abab', 'ab', [], 'ab', true],
  ['aaa', 'a', ['a'], 'a', true],
  ['aa', 'a', ['a'], 'a', false],
  ['abcabc', '', ['abc', 'abc'], '', true],
  ['abcab', '', ['abc', 'abc'], '', false],
  ['xaybx', '', ['a', 'b'], 'x', true],
  ['xabx', '', ['ab'], 'bx', false],
  ['', 'a', [], '', false],
  ['', '', ['a'], '', false],
  ['', '', [], 'a', false],
  ['', '', [''], '', true],
  ['abc', '', [''], 'c', true],
  ['abc', 'abc', [], '', true],
  ['abc', '', [], 'abc', true],
  ['abc', 'abc', [], 'abc', false],
  ['a.b*c', 'a.', ['*'], 'c', true],
  ['axbyc', 'a.', ['*'], 'c', false],
  ['(x)[y]$', '(', ['[y]'], '$', true],
  ['é-ünïcødé', 'é', ['ünï'], 'dé', true],
  ['é-ünïcødé', 'e', [], '', false],
  ['日本語のテキスト', '日本', ['の'], 'スト', true],
  ['😀x😀', '😀', ['x'], '😀', true],
  ['😀', '😀', [], '😀', false]
];

// The regular expression `@ldapjs/filter` builds, with `s` so that `.`
// crosses a line break as RFC 4517 section 4.2.29 does: the reference the
// scan must equal.
function reference(value, initial, any, final) {
  log.debug('Entering reference().');
  const escape = function (text) {
    return text.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&');
  };
  let re = '';
  if (initial) {
    re += '^' + escape(initial) + '.*';
  }
  any.forEach(function (one) {
    re += escape(one) + '.*';
  });
  if (final) {
    re += escape(final) + '$';
  }
  const answer = new RegExp(re, 's').test(value);
  log.debug('Leaving reference().');
  return answer;
}

// A substring filter built from its parts, so that its components hold the
// characters as given (the string parser keeps a non-ASCII character
// escaped, which is the library's and not what is tested here).
function filterOf(attribute, initial, any, final) {
  log.debug('Entering filterOf().');
  const filters = require('@ldapjs/filter');
  const built = new filters.SubstringFilter({
    attribute: attribute, initial: initial || undefined, any: any,
    final: final || undefined });
  log.debug('Leaving filterOf().');
  return built;
}

function equivalence(t) {
  log.debug('Entering equivalence().');
  t.log.info('=== A. equivalence ===');
  const LdapMatching = require('../ldap/ldap_matching');
  const scanWrong = [];
  const referenceWrong = [];
  const libraryWrong = [];
  const foldedWrong = [];
  CASES.forEach(function (one) {
    const [value, initial, any, final, expected] = one;
    const scan = LdapMatching.substringMatches(value, initial, any, final);
    if (scan !== expected) {
      scanWrong.push(JSON.stringify(one));
    }
    if (reference(value, initial, any, final) !== expected) {
      referenceWrong.push(JSON.stringify(one));
    }
    // An exact-rule attribute: the library's own leaf against ours.
    const exact = filterOf('memberUid', initial, any, final);
    const ours = LdapMatching.matches(exact, { memberuid: [value] });
    const theirs = exact.matches({ memberuid: [value] }, false);
    if (ours !== theirs || ours !== expected) {
      libraryWrong.push(JSON.stringify(one) + ' ours=' + ours +
                        ' library=' + theirs);
    }
    // A case-ignoring attribute: the value in upper case still matches the
    // components in lower case, exactly when the folded case does.
    const folded = filterOf('cn', initial.toLowerCase(),
                            any.map(function (a) {
                              return a.toLowerCase();
                            }), final.toLowerCase());
    const foldedExpected = LdapMatching.substringMatches(
      value.toLowerCase(), initial.toLowerCase(),
      any.map(function (a) {
        return a.toLowerCase();
      }), final.toLowerCase());
    if (LdapMatching.matches(folded, { cn: [value.toUpperCase()] }) !==
        foldedExpected) {
      foldedWrong.push(JSON.stringify(one));
    }
  });
  t.check(scanWrong.length === 0, 'A1. substringMatches() answers each of ' +
          CASES.length + ' cases as RFC 4517 section 4.2.29 does (initial a ' +
          'prefix, each any after the last without overlap, final a suffix ' +
          'overlapping nothing)', scanWrong.join('; '));
  t.check(referenceWrong.length === 0, 'A2. and the reference regular ' +
          'expression agrees on every case', referenceWrong.join('; '));
  t.check(libraryWrong.length === 0, 'A3. an exact-rule attribute ' +
          '(memberUid) answers as @ldapjs/filter\'s own matches() does',
          libraryWrong.join('; '));
  t.check(foldedWrong.length === 0, 'A4. a case-ignoring attribute (cn) ' +
          'matches an upper-cased value as the folded scan does',
          foldedWrong.join('; '));
  t.check(LdapMatching.matches(filterOf('description', 'a', [], 'b'),
                               { description: ['a\nb'] }),
          'A5. a value with a line break matches across it (a regular ' +
          'expression\'s `.` did not; the RFC makes no exception)');
  t.check(!LdapMatching.matches(filterOf('memberUid', 'abc', [], ''),
                                { memberuid: ['ABCD'] }) &&
          LdapMatching.matches(filterOf('memberUid', 'ABC', [], ''),
                               { MemberUid: ['ABCD'] }),
          'A6. an exact-rule attribute keeps case in the value and ignores ' +
          'it in the attribute description');
  const filters = require('@ldapjs/filter');
  t.check(LdapMatching.matches(filters.parseString('(uid=a*C*q)'),
                               { uid: ['Alice-Q'] }) &&
          !LdapMatching.matches(filters.parseString('(uid=*bob*)'),
                                { uid: ['Alice-Q'] }) &&
          !LdapMatching.matches(filters.parseString('(title=a*)'),
                                { uid: ['Alice-Q'] }),
          'A7. a parsed filter is matched the same way; an attribute the ' +
          'entry lacks matches nothing');
  log.debug('Leaving equivalence().');
}

function pathological(t) {
  log.debug('Entering pathological().');
  t.log.info('=== B. the pathological filter ===');
  const LdapMatching = require('../ldap/ldap_matching');
  const value = 'a'.repeat(10 * 1024);
  const any = [];
  for (let i = 0; i < LdapMatching.MAX_SUBSTRING_COMPONENTS - 1; i++) {
    any.push('a');
  }
  ['cn', 'memberUid'].forEach(function (attribute) {
    const filter = filterOf(attribute, '', any, 'b');
    const entry = {};
    entry[attribute.toLowerCase()] = [value];
    const started = process.hrtime.bigint();
    const answer = LdapMatching.matches(filter, entry);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    t.check(answer === false && ms < 200, 'B. `*a*a*...*b` of ' +
            (any.length + 1) + ' components against 10 kB of `a` on ' +
            attribute + ' is answered false in under 200 ms',
            'answer=' + answer + ' took ' + ms.toFixed(1) + ' ms');
  });
  log.debug('Leaving pathological().');
}

// A filter string of `count` components: `*a*a*...*b`.
function wideFilter(count) {
  log.debug('Entering wideFilter().');
  let text = '(cn=';
  for (let i = 0; i < count - 1; i++) {
    text += '*a';
  }
  log.debug('Leaving wideFilter().');
  return text + '*b)';
}

async function cap(t) {
  log.debug('Entering cap().');
  t.log.info('=== C. the cap ===');
  const LdapMatching = require('../ldap/ldap_matching');
  const filters = require('@ldapjs/filter');
  const max = LdapMatching.MAX_SUBSTRING_COMPONENTS;
  t.check(max === 32, 'C1. the cap is 32 components', String(max));
  t.check(LdapMatching.widestSubstring(filters.parseString(
    '(&(objectClass=*)(|(uid=x)(!' + wideFilter(40) + ')))')) === 40 &&
          LdapMatching.widestSubstring(filters.parseString('(uid=a*b*c)')) ===
          3 &&
          LdapMatching.widestSubstring(filters.parseString('(uid=x)')) === 0,
          'C2. widestSubstring() counts initial, any and final, through ' +
          'AND, OR and NOT');
  const ldap = require('../ldap/ldap_server');
  const search = async function (filter) {
    return Promise.resolve(ldap.performOperation('search', {
      dn: ldap.baseDn(), boundDn: '', channel: 'ldap', remoteAddress: '',
      scope: 2, filter: filter, attributes: ['uid'], sizeLimit: 0,
      timeLimit: 0 }, function () {
      // The entries are not what is asked.
    }));
  };
  const over = await search('(&(objectClass=*)' + wideFilter(max + 1) + ')');
  t.check(over && over.ok === false &&
          over.errorName === 'AdminLimitExceededError',
          'C3. a search with a substring of ' + (max + 1) + ' components is ' +
          'refused adminLimitExceeded (STS-LDAP-0226)', JSON.stringify(over));
  const at = await search(wideFilter(max));
  t.check(at && at.ok === true, 'C4. one of ' + max + ' components is ' +
          'answered', JSON.stringify(at));
  log.debug('Leaving cap().');
}

async function run(t) {
  log.debug('Entering run().');
  equivalence(t);
  pathological(t);
  await cap(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'ldap_substring_matching',
  describe: 'an LDAP substring assertion matched by one linear scan, equal ' +
            'to RFC 4517 and the library on ordinary values, fast on a ' +
            'pathological filter, and refused over 32 components (#2137)',
  run: run
};
