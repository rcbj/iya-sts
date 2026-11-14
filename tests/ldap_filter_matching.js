// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_filter_matching.js
//
// ===========================================================================
// AN LDAP SEARCH FILTER IS MATCHED BY EACH ATTRIBUTE'S OWN EQUALITY RULE
// (#632, 2026-10-14).
//
// `(uid=LOAD-x)` found nobody stored as `uid=load-x`: @ldapjs/filter
// compares every value exactly, and RFC 4519 section 2.39 gives `uid`
// caseIgnoreMatch (and caseIgnoreSubstringsMatch); RFC 4524 section 2.16
// gives `mail` caseIgnoreIA5Match. `ldap/ldap_matching.ts` matches the
// filter by those rules, and this holds it:
//
//   A. THE MATCHER: an equality and a substring (initial, any, final) on
//      `uid`, `mail` and `cn` ignore case; NOT, AND and OR compose; an
//      attribute whose rule is exact (`memberUid`, an `sts*` attribute)
//      stays exact; presence and `objectClass` are the library's.
//   B. THE WHOLE DIRECTORY: a person added over LDAP with a mixed-case uid
//      and mail is found by `performOperation('search')` — the handler the
//      socket and a request worker run — with the uid and mail in another
//      case, by equality and by substring, and an exact attribute is not.
//   C. A WINDOW ONTO THE STORE (#320, #616), in a child: the same searches,
//      the equalities NARROWED through the store's `equalUnder` index (its
//      lower-cased keys) and the substrings paged asynchronously — the same
//      answers.
//
// WHAT NEEDS A REAL POSTGRES: that `name_keys` and `mail_keys` hold a value
// lower-cased and trimmed, which `tests/ldap_search_narrowing.js` section B
// holds for the statement and `persistence/directory_codec.js` for the keys.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ldap_filter_matching',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_LDAP_FILTER_MATCHING_CHILD';

// The person each section searches for, as stored: every case-ignoring value
// in MIXED case, and an exact attribute beside them.
const PERSON = {
  uid: 'Load-MixedCase',
  mail: 'Load.Mixed@Example.COM',
  cn: 'Load MixedCase',
  sn: 'MixedCase',
  memberUid: 'ExactValue'
};

// The searches B and C both run, each with the answer it must give: whether
// the person is found.
const SEARCHES = [
  ['(uid=load-mixedcase)', true, 'a uid equality in lower case'],
  ['(uid=LOAD-MIXEDCASE)', true, 'a uid equality in upper case'],
  ['(uid=Load-MixedCase)', true, 'a uid equality as stored'],
  ['(uid=LOAD-MIXED*)', true, 'a uid substring: initial, another case'],
  ['(uid=*mixed*)', true, 'a uid substring: any, another case'],
  ['(uid=*MIXEDCASE)', true, 'a uid substring: final, another case'],
  ['(mail=load.mixed@example.com)', true, 'a mail equality in lower case'],
  ['(mail=LOAD.MIXED@EXAMPLE.COM)', true, 'a mail equality in upper case'],
  ['(mail=*@EXAMPLE.com)', true, 'a mail substring, another case'],
  ['(&(objectClass=inetOrgPerson)(uid=LOAD-MIXEDCASE))', true,
   'an AND narrowed on its uid term'],
  ['(|(uid=nobody-here)(mail=LOAD.MIXED@example.com))', true,
   'an OR of indexed equalities'],
  ['(!(uid=LOAD-MIXEDCASE))', false, 'a NOT of the uid in another case'],
  ['(uid=load-mixedcas)', false, 'a uid that is not hers, in any case'],
  ['(memberUid=exactvalue)', false,
   'memberUid (caseExactIA5Match, RFC 2307) is still exact'],
  ['(memberUid=ExactValue)', true, 'and matches as stored']
];

// --- A. the matcher ----------------------------------------------------------

function matcher(t) {
  log.debug('Entering matcher().');
  t.log.info('=== A. the matcher ===');
  const filters = require('@ldapjs/filter');
  const LdapMatching = require('../ldap/ldap_matching');
  const entry = { uid: ['Alice-Q'], mail: ['Alice@Example.COM'],
                  cn: ['Alice Quinn'], objectclass: ['inetOrgPerson'],
                  memberuid: ['CaseExact'],
                  stsappliedtag: ['MixedTag'] };
  const ask = function (text) {
    return LdapMatching.matches(filters.parseString(text), entry);
  };
  t.check(ask('(uid=alice-q)') && ask('(UID=ALICE-Q)') && ask('(uid=Alice-Q)'),
          'A1. a uid equality ignores case, in the value and the attribute ' +
          'description (RFC 4519 caseIgnoreMatch, RFC 4512 section 2.5)');
  t.check(ask('(uid=ALI*)') && ask('(uid=*E-q)') && ask('(uid=a*C*q)') &&
          !ask('(uid=*bob*)'),
          'A2. a uid substring ignores case in its initial, any and final ' +
          '(caseIgnoreSubstringsMatch)');
  t.check(ask('(mail=alice@example.com)') && ask('(mail=*@EXAMPLE.COM)'),
          'A3. mail ignores case too (RFC 4524 caseIgnoreIA5Match)');
  t.check(ask('(cn=ALICE QUINN)'), 'A4. and cn (RFC 4519 caseIgnoreMatch)');
  t.check(!ask('(memberUid=caseexact)') && ask('(memberUid=CaseExact)') &&
          !ask('(stsAppliedTag=mixedtag)') && ask('(stsAppliedTag=MixedTag)'),
          'A5. an attribute whose rule is exact — memberUid (RFC 2307 ' +
          'caseExactIA5Match), this service\'s own sts* — stays exact');
  t.check(ask('(&(objectClass=INETORGPERSON)(uid=ALICE-Q))') &&
          ask('(|(uid=nobody)(mail=ALICE@EXAMPLE.COM))') &&
          !ask('(!(uid=ALICE-Q))') && ask('(!(uid=bob))'),
          'A6. AND, OR and NOT compose over the folded leaves');
  t.check(ask('(uid=*)') && !ask('(title=*)'),
          'A7. a presence is the library\'s, unchanged');
  t.check(LdapMatching.ignoresCase('UID') &&
          LdapMatching.ignoresCase('mail;x-option') &&
          !LdapMatching.ignoresCase('memberUid') &&
          !LdapMatching.ignoresCase('userPassword'),
          'A8. ignoresCase() reads the attribute type, any case, any option');
  log.debug('Leaving matcher().');
}

// --- B and C: searches through the directory -------------------------------

// The DN of the person under `users`.
function personDn(users) {
  log.debug('Entering personDn().');
  log.debug('Leaving personDn().');
  return 'uid=' + PERSON.uid + ',' + users;
}

// Runs every search of SEARCHES and reports, per search, whether the person
// was found and whether the search succeeded.
async function searchAll(ldap, users) {
  log.debug('Entering searchAll().');
  const wanted = ldap.normalizeDn(personDn(users));
  const out = [];
  for (const one of SEARCHES) {
    const emitted = [];
    const result = await Promise.resolve(ldap.performOperation('search', {
      dn: ldap.baseDn(), boundDn: '', channel: 'ldap', remoteAddress: '',
      scope: 2, filter: one[0], attributes: ['uid'], sizeLimit: 0,
      timeLimit: 0 }, function (batch) {
      batch.forEach(function (entry) {
        emitted.push(entry);
      });
    }));
    const found = emitted.concat((result && result.entries) || [])
      .some(function (entry) {
        return ldap.normalizeDn(entry.objectName || entry.dn || '') === wanted;
      });
    out.push({ filter: one[0], ok: !!(result && result.ok), found: found,
               error: (result && result.errorName) || '' });
  }
  log.debug('Leaving searchAll().');
  return out;
}

// Checks one set of answers against SEARCHES.
function checkAnswers(t, label, answers) {
  log.debug('Entering checkAnswers(). ' + label);
  SEARCHES.forEach(function (one, i) {
    const answer = answers[i] || {};
    t.check(answer.ok && answer.found === one[1],
            label + (i + 1) + '. ' + one[2] + ' — ' + one[0] + ' ' +
            (one[1] ? 'finds' : 'does not find') + ' the person',
            JSON.stringify(answer));
  });
  log.debug('Leaving checkAnswers().');
}

// B. the whole directory, in this process. The person is added over LDAP and
// deleted again in a `finally`.
async function wholeDirectory(t) {
  log.debug('Entering wholeDirectory().');
  t.log.info('=== B. the whole directory ===');
  const ldap = require('../ldap/ldap_server');
  if (ldap.directoryWindow) {
    t.bad('B0. this process should hold the whole directory');
    log.debug('Leaving wholeDirectory(). A window.');
    return;
  }
  const users = ldap.usersDn();
  const dn = personDn(users);
  const added = await Promise.resolve(ldap.performOperation('add', {
    dn: dn, boundDn: '', channel: 'ldap',
    attributes: Object.keys(PERSON).map(function (type) {
      return { type: type, values: [PERSON[type]] };
    }).concat([{ type: 'objectClass',
                 values: ['top', 'inetOrgPerson'] }])
  }));
  try {
    if (!t.check(added && added.ok, 'B0. the person is added over LDAP, ' +
                 'uid and mail in mixed case', JSON.stringify(added))) {
      log.debug('Leaving wholeDirectory(). Not added.');
      return;
    }
    checkAnswers(t, 'B', await searchAll(ldap, users));
  } finally {
    await Promise.resolve(ldap.performOperation('del', {
      dn: dn, boundDn: '', channel: 'ldap' }));
  }
  log.debug('Leaving wholeDirectory().');
}

// The stand-in bridge for C: `tests/directory_window.js`'s, plus the
// `equalUnder` question #320 narrows by — answered as the store's index
// does, both sides trimmed and lower-cased — and an asynchronous door.
function narrowingBridge(rows) {
  log.debug('Entering narrowingBridge().');
  const shared = require('./directory_window');
  const queries = require('../persistence/directory_queries');
  const base = shared.fakeBridge(rows);
  const asked = {};
  const under = function (key, b) {
    return key === b || (key.length > b.length + 1 && key.endsWith(',' + b));
  };
  const answer = function (name, args) {
    asked[name] = (asked[name] || 0) + 1;
    if (name === 'equalUnder') {
      const column = args[2] === 'mail' ? 'mail' : 'uid';
      const wanted = String(args[3]).trim().toLowerCase();
      return Array.from(rows.values()).filter(function (r) {
        return r.realm === args[0] && under(r.dn_key, args[1]) &&
          (r.attrs[column] || []).some(function (v) {
            return String(v).trim().toLowerCase() === wanted;
          });
      }).map(function (r) {
        return queries.rowOf(JSON.parse(JSON.stringify(r)));
      });
    }
    return base.query(name, args);
  };
  log.debug('Leaving narrowingBridge().');
  return {
    asked: asked,
    query: answer,
    queryAsync: function (name, args) {
      return Promise.resolve(answer(name, args));
    }
  };
}

// C, in the child: the directory loaded as a windowed process, the person a
// row of the store it has never held.
async function windowed() {
  log.debug('Entering windowed().');
  const shared = require('./directory_window');
  const ldap = require('../ldap/ldap_server');
  const w = ldap.directoryWindow;
  if (!w) {
    log.debug('Leaving windowed(). No window.');
    return { windowed: false };
  }
  const users = ldap.usersDn();
  const rows = new Map();
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes, origin: 'seed',
      created_at: '1', modified_at: '1' });
  });
  const attrs = { objectclass: ['top', 'inetOrgPerson'] };
  Object.keys(PERSON).forEach(function (type) {
    attrs[type.toLowerCase()] = [PERSON[type]];
  });
  const dn = personDn(users);
  rows.set('default\n' + ldap.normalizeDn(dn),
           shared.row('default', dn, attrs));
  rows.get('default\n' + ldap.normalizeDn(dn)).dn_key = ldap.normalizeDn(dn);
  const bridge = narrowingBridge(rows);
  w.attach(bridge);
  const answers = await searchAll(ldap, users);
  log.debug('Leaving windowed().');
  return { windowed: true, answers: answers,
           narrowed: bridge.asked.equalUnder || 0,
           paged: bridge.asked.page || 0 };
}

async function childMain() {
  log.debug('Entering childMain().');
  let answer = null;
  let threw = '';
  try {
    answer = await windowed();
  } catch (e) {
    log.debug('Caught in childMain(): ' + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ answer: answer, threw: threw }));
  log.debug('Leaving childMain().');
  process.exit(0);
}

// C. a window onto the store, in a child: the directory is chosen when it is
// loaded, and this process has loaded the whole one.
function windowedDirectory(t) {
  log.debug('Entering windowedDirectory().');
  t.log.info('=== C. a window onto the store ===');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-lfm-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  env.STS_REQUEST_WORKER = '1';
  env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
  env.STS_PERSISTENCE_MODE = 'postgres';
  env.LDAP_WORKER_CACHE_ENTRIES = '100';
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug('Caught in windowedDirectory(): ' + ((e && e.message) || e));
    t.bad('the windowed child reported nothing', 'status ' + child.status +
          ': ' + String(child.stderr || '').slice(-2000));
    log.debug('Leaving windowedDirectory().');
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  if (result.threw) {
    t.bad('the windowed child threw', result.threw);
  }
  const answer = result.answer || {};
  if (!t.check(answer.windowed, 'C0. the child holds the directory as a ' +
               'window onto the store')) {
    log.debug('Leaving windowedDirectory(). No window.');
    return;
  }
  checkAnswers(t, 'C', answer.answers);
  t.check(answer.narrowed > 0 && answer.paged > 0,
          'C' + (SEARCHES.length + 1) + '. the equalities were asked of ' +
          'the store\'s index (equalUnder) and the substrings paged — both ' +
          'paths were taken', JSON.stringify(answer));
  log.debug('Leaving windowedDirectory().');
}

async function run(t) {
  log.debug('Entering run().');
  matcher(t);
  await wholeDirectory(t);
  windowedDirectory(t);
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'ldap_filter_matching',
  describe: 'an LDAP search filter matched by each attribute\'s own ' +
            'equality rule (#632): uid and mail ignore case, by equality ' +
            'and substring, in the whole directory and through a window',
  run: run
};
