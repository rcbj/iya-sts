// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_delegate_search.js
//
// ---------------------------------------------------------------------------
// `/portal/delegate`'s SEARCH, AND THE STAMP THAT DECIDES WHO IT MAY FIND
// (2026-10-20, rcbj).
//
// A person on /portal/delegate finds the people they may name as their
// delegate by part of a username (`GET /account-api/delegate/candidates`),
// and only NATIVE people of their realm: never one a federation partner's
// or a consumer provider's sign-in created, which `stsProvisionedBy`, written
// once at that creation, says. In a child process, the whole stack on a
// port of its own and a person signed in as the static portal signs in
// (`tests/vendored/portal_signin.js`):
//
//   A. THE STAMP: a federated create and a consumer provider's create write
//      `federation:<relationship>`; a federated sign-in that reaches a
//      person already here writes nothing; an overwrite keeps it and never
//      takes a caller's; every door refuses it (an LDAP add and modify, the
//      console's create and the person editor, the portal's editor, SCIM's
//      table); a re-homing carries it; an unstamped entry is native.
//   B. THE SEARCH: a `uid` substring finds a native person of this realm,
//      and not a federated one, a consumer provider's, another realm's, the
//      person themselves, a disabled account, a service account, a group
//      or an application; fewer than three characters is refused
//      STS-PORTAL-0620; `*`, `(`, `)`, `%` and `_` match themselves; ten at
//      most, with `more`; each result is the uid, the cn and the DN only;
//      the store's statement escapes LIKE's wildcards and repeats the
//      partial index's predicate; an over-fetched page of excluded rows
//      says `more` rather than "nobody".
//   C. CHOOSING ONE names them through the existing POST: `stsMayAct` is the
//      chosen DN.
//   D. THE PAGE: the answer drawn escaped; the debounce asks nothing under
//      three characters or before three idle seconds, Enter asks at once,
//      and a stale answer is never drawn.
//
// A child process for `account_api.js`'s reason: the stack is built once,
// with a composition root.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const ROOT = path.join(__dirname, '..');
const log = bunyan.createLogger({ name: 'portal_delegate_search',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.DS_ROOT;
  const OUT = process.env.DS_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function brief(r) {
    return r ? r.status + ' ' + String(r.text || '').slice(0, 300) : 'none';
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const http = require('http');
    const app = require(ROOT_DIR + '/common/app');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const realms = require(ROOT_DIR + '/common/realms');
    const audit = require(ROOT_DIR + '/common/audit');
    const accountState = require(ROOT_DIR + '/common/account_state');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');
    const applications = require(ROOT_DIR + '/common/applications');
    const personEditor = require(ROOT_DIR + '/ldap/person_editor');
    const scimMap = require(ROOT_DIR + '/scim/scim_map');
    const queries = require(ROOT_DIR + '/persistence/directory_queries');
    const signin = require(ROOT_DIR + '/tests/vendored/portal_signin');

    // Every name carries the run's token, so the search's text finds only
    // what this file made.
    const TOKEN = 'dsq' + String(process.pid);
    const PASSWORD = 'Deleg4te-Search-' + TOKEN + '-Passw0rd!';
    const ALICE = TOKEN + '-alice';
    const stampOf = function (entry) {
      return entry ? (entry.attributes.stsprovisionedby || []) : [];
    };
    const entryOf = function (name) {
      return ldap.existingUserEntry(name) || null;
    };
    const make = function (name, cn) {
      const made = ldap.createUser(name, { invent: false,
        attributes: { cn: cn || name, sn: 'Test', givenName: 'Test' } });
      return made;
    };
    // A federated sign-in, as `federation_sp.ts` hands it to the directory
    // through the authentication funnel: the relationship, its decision to
    // create, and what the partner sent. `tests/federation_*` drive the
    // real sign-ins; this drives the directory's half of one.
    const federatedSignIn = function (key, relationship, create) {
      return ldap.autoCreateUser({ key: key, protocol: 'SAML 2.0',
        federation: { id: relationship, create: create,
                      peer: 'https://' + relationship + '.example',
                      link: relationship + ' https://' + relationship +
                            '.example ' + key,
                      attributes: { cn: [key], givenName: ['Fed'],
                                    sn: ['Erated'],
                                    mail: [key + '@example.com'] } } });
    };

    ldap.createUser(ALICE, { invent: false,
      attributes: { cn: 'Alice ' + TOKEN, sn: 'A', givenName: 'Alice' } });
    credentials.setPassword(ALICE, PASSWORD);
    const aliceDn = entryOf(ALICE).dn;

    // ===== A. THE STAMP ====================================================
    const FED = 'fedrel~' + TOKEN + '-fed';
    const fed = federatedSignIn(FED, 'fedrel', true);
    note(fed && stampOf(fed).join('|') === 'federation:fedrel',
         'A1. a federated sign-in that creates the entry stamps it ' +
         'federation:<relationship>', JSON.stringify(stampOf(fed)));
    const SOCIAL = 'cp-google~' + TOKEN + '-social';
    const social = federatedSignIn(SOCIAL, 'cp-google', true);
    note(social && stampOf(social).join('|') === 'federation:cp-google',
         'A2. a consumer provider\'s create is the same funnel and the same ' +
         'stamp', JSON.stringify(stampOf(social)));
    const LINKED = TOKEN + '-linked';
    make(LINKED, 'Linked Native');
    const linked = federatedSignIn(LINKED, 'fedrel', false);
    note(linked && (linked.attributes.federationrelationship || [])
           .indexOf('fedrel') >= 0 && !stampOf(linked).length,
         'A3. a federated sign-in reaching a person already here records ' +
         'the partner and stamps nothing: they stay native',
         JSON.stringify(linked && linked.attributes));
    federatedSignIn(FED, 'otherrel', true);
    note(stampOf(entryOf(FED)).join('|') === 'federation:fedrel',
         'A4. a later sign-in through another partner does not move it',
         JSON.stringify(stampOf(entryOf(FED))));

    // An overwrite keeps the entry's and never takes the caller's.
    const fedEntry = entryOf(FED);
    const rebuilt = {};
    Object.keys(fedEntry.attributes).forEach(function (name) {
      if (name !== 'stsprovisionedby') {
        rebuilt[name] = fedEntry.attributes[name].slice(0);
      }
    });
    ldap.writePerson(fedEntry.dn, rebuilt);
    note(stampOf(entryOf(FED)).join('|') === 'federation:fedrel',
         'A5. an overwrite that rebuilds the attributes without it keeps it',
         JSON.stringify(stampOf(entryOf(FED))));
    const BOB = TOKEN + '-bob';
    make(BOB, 'Bob Native');
    const bobEntry = entryOf(BOB);
    const forged = {};
    Object.keys(bobEntry.attributes).forEach(function (name) {
      forged[name] = bobEntry.attributes[name].slice(0);
    });
    forged.stsProvisionedBy = ['federation:forged'];
    ldap.writePerson(bobEntry.dn, forged);
    note(!stampOf(entryOf(BOB)).length,
         'A6. an overwrite handing one in does not write it',
         JSON.stringify(stampOf(entryOf(BOB))));

    // The doors.
    const lastCode = function (target) {
      const row = audit.list().filter(function (event) {
        return event.target === target && event.errorCode;
      })[0];
      return row ? String(row.errorCode) : '';
    };
    const forgedDn = 'uid=' + TOKEN + '-forged,' + ldap.usersDn();
    let r = ldap.performOperation('add', {
      dn: forgedDn, boundDn: '', channel: 'ldaps',
      attributes: [{ type: 'objectClass', values: ['inetOrgPerson'] },
                   { type: 'uid', values: [TOKEN + '-forged'] },
                   { type: 'cn', values: ['Forged'] },
                   { type: 'sn', values: ['Forged'] },
                   { type: 'stsProvisionedBy', values: ['federation:x'] }] });
    note(r.ok === false && lastCode(forgedDn) === 'STS-LDAP-0076' &&
         !entryOf(TOKEN + '-forged'),
         'A7. an LDAP add naming stsProvisionedBy is refused STS-LDAP-0076',
         JSON.stringify({ ok: r.ok, error: r.errorName,
                          code: lastCode(forgedDn) }));
    r = ldap.performOperation('modify', {
      dn: fedEntry.dn, boundDn: '', channel: 'ldaps',
      changes: [{ operation: 'delete', modification: {
        type: 'stsProvisionedBy', values: [] } }] });
    const r2 = ldap.performOperation('modify', {
      dn: bobEntry.dn, boundDn: '', channel: 'ldaps',
      changes: [{ operation: 'add', modification: {
        type: 'stsProvisionedBy', values: ['federation:x'] } }] });
    note(r.ok === false && r2.ok === false &&
         stampOf(entryOf(FED)).length === 1 && !stampOf(entryOf(BOB)).length,
         'A8. an LDAP modify removing or adding it is refused, in either ' +
         'direction', JSON.stringify({ remove: r.ok, add: r2.ok }));
    const consoleCreate = ldap.createUser(TOKEN + '-console', {
      invent: false, attributes: { cn: 'Console', sn: 'C',
                                   stsProvisionedBy: 'federation:x' } });
    note(consoleCreate.ok === false && !entryOf(TOKEN + '-console'),
         'A9. the console\'s and /admin-api\'s create refuses it',
         JSON.stringify(consoleCreate.errors));
    const edited = personEditor.update(BOB, { attribute: 'stsProvisionedBy',
                                              mode: 'set',
                                              value: 'federation:x' },
                                       { actor: 'test', via: 'console' });
    const unedited = personEditor.update(FED, {
      attribute: 'stsProvisionedBy', mode: 'set', value: '' },
      { actor: FED, via: 'portal' });
    note(edited.ok === false && unedited.ok === false &&
         !stampOf(entryOf(BOB)).length &&
         stampOf(entryOf(FED)).length === 1,
         'A10. the person editor — the console\'s, /admin-api\'s and the ' +
         'portal\'s — refuses to set or clear it',
         JSON.stringify([edited.errors, unedited.errors]));
    note(!scimMap.USER_ATTRIBUTES.some(function (row) {
      return String(row.ldap || '').toLowerCase() === 'stsprovisionedby';
    }), 'A11. SCIM\'s table maps nothing onto it');

    // A re-homing (#98) carries the attributes whole.
    const MOVED = TOKEN + '-moved';
    const movedDn = 'uid=' + MOVED + ',' + ldap.usersDn();
    ldap.adoptEntry(movedDn, { objectclass: ['top', 'inetOrgPerson'],
      uid: [MOVED], cn: ['Moved Federated'], sn: ['M'],
      stsprovisionedby: ['federation:fedrel'] }, 'rehomed');
    const MOVEDNATIVE = TOKEN + '-movednative';
    ldap.adoptEntry('uid=' + MOVEDNATIVE + ',' + ldap.usersDn(),
      { objectclass: ['top', 'inetOrgPerson'], uid: [MOVEDNATIVE],
        cn: ['Moved Native'], sn: ['M'] }, 'rehomed');
    note(stampOf(entryOf(MOVED)).join('|') === 'federation:fedrel',
         'A12. a re-homed entry keeps its stamp',
         JSON.stringify(entryOf(MOVED) && entryOf(MOVED).attributes));

    // ===== B. THE SEARCH, THROUGH THE ACCOUNT API ===========================
    const DISABLED = TOKEN + '-disabled';
    make(DISABLED, 'Disabled Native');
    accountState.setDisabled(DISABLED, true, { actor: 'test' });
    const SVC = TOKEN + '-svc';
    make(SVC, 'Service Native');
    const svc = serviceAccounts.set(SVC, { serviceAccount: true,
                                           owners: [ALICE] });
    note(svc && svc.ok !== false && !!entryOf(SVC),
         'precondition: a service account exists', JSON.stringify(svc));
    ldap.createGroup(TOKEN + '-group', { members: [] });
    applications.createApplication({ identifier: TOKEN + '-app',
                                     kind: 'oauth2-client' });
    const OTHER_REALM = 'dsr' + String(process.pid);
    realms.create({ id: OTHER_REALM, name: 'Delegate search elsewhere' });
    realms.run(realms.get(OTHER_REALM), function () {
      make(TOKEN + '-elsewhere', 'Somebody Elsewhere');
    });
    const STAR = TOKEN + 'q*x';
    const PAREN = TOKEN + 'q(x)';
    const PCT = TOKEN + 'q%x';
    const UNDER = TOKEN + 'q_x';
    [STAR, PAREN, PCT, UNDER].forEach(function (name) {
      make(name, 'Odd ' + name);
    });
    make(TOKEN + 'qyx', 'Plain qyx');

    const server = http.createServer(app);
    await new Promise(function (res) { server.listen(0, '127.0.0.1', res); });
    const base = 'http://127.0.0.1:' + server.address().port;
    const alice = await signin.signInToThePortal(base, ALICE, null,
                                                 { password: PASSWORD });
    note(!!alice.token, 'precondition: alice signs in as the portal does');
    const search = function (q) {
      return alice.api('GET', '/account-api/delegate/candidates?q=' +
                       encodeURIComponent(q));
    };
    const uidsOf = function (answer) {
      return ((answer && answer.json && answer.json.people) || [])
        .map(function (one) { return one.uid; });
    };

    let found = await search(TOKEN);
    const uids = uidsOf(found);
    note(found.status === 200 && uids.indexOf(BOB) >= 0 &&
         uids.indexOf(LINKED) >= 0 && uids.indexOf(MOVEDNATIVE) >= 0,
         'B1. a uid substring finds the native people of the realm — one ' +
         'who linked a partner and one re-homed here included', brief(found));
    const excluded = { federated: FED, social: SOCIAL, themselves: ALICE,
                       disabled: DISABLED, 'a service account': SVC,
                       'a group': TOKEN + '-group',
                       'an application': TOKEN + '-app',
                       'another realm\'s person': TOKEN + '-elsewhere',
                       're-homed and stamped': MOVED };
    Object.keys(excluded).forEach(function (what) {
      note(found.status === 200 &&
           uids.indexOf(excluded[what]) < 0 &&
           !(found.json.people || []).some(function (one) {
             return String(one.dn).toLowerCase()
               .indexOf('=' + excluded[what].toLowerCase() + ',') >= 0;
           }),
           'B2. it does not find ' + what + ' (' + excluded[what] + ')',
           uids.join(', '));
    });
    note(found.status === 200 && (found.json.people || []).every(
      function (one) {
        return Object.keys(one).sort().join(',') === 'cn,dn,uid';
      }) && (found.json.people || []).some(function (one) {
        return one.uid === BOB && one.cn === 'Bob Native' &&
               one.dn === bobEntry.dn;
      }),
         'B3. each result is the uid, the cn and the DN, and nothing else',
         JSON.stringify(found.json && found.json.people).slice(0, 400));

    const auditAt = audit.list().length;
    const short = await search('ab');
    const shortRow = audit.list().slice(0, audit.list().length - auditAt)
      .filter(function (event) {
        return event.action === 'portal.delegation.search';
      })[0];
    note(short.status === 400 && shortRow &&
         shortRow.errorCode === 'STS-PORTAL-0620' && shortRow.actor === ALICE,
         'B4. fewer than three characters is refused STS-PORTAL-0620, and ' +
         'audited', brief(short) + ' ' + JSON.stringify(shortRow || {}));
    const okRow = audit.list().filter(function (event) {
      return event.action === 'portal.delegation.search' &&
             event.outcome === 'success' && event.actor === ALICE;
    })[0];
    note(!!okRow && okRow.detail && okRow.detail.query === TOKEN,
         'B5. a search is audited as the person\'s account-api call',
         JSON.stringify(okRow || {}));

    const literal = async function (q, wanted) {
      const answer = await search(q);
      const got = uidsOf(answer);
      note(answer.status === 200 && got.length === 1 && got[0] === wanted,
           'B6. ' + JSON.stringify(q.slice(TOKEN.length)) + ' matches ' +
           'itself and nothing else', brief(answer));
    };
    await literal(TOKEN + 'q*', STAR);
    await literal(TOKEN + 'q(', PAREN);
    await literal(TOKEN + 'q%', PCT);
    await literal(TOKEN + 'q_', UNDER);
    const statement = queries.uidContains('default', 'ou=users,dc=x',
                                          'a%b_c\\d', 51);
    note(statement.values[2] === '%a\\%b\\_c\\\\d%' &&
         /rdn_value LIKE \$3 ESCAPE '\\'/.test(statement.text) &&
         statement.text.indexOf(queries.USERS_PARENT) > 0 &&
         statement.values[3] === 51 && !/a%b/.test(statement.text),
         'B7. the store\'s statement takes the text as a parameter, its ' +
         'LIKE wildcards and escape escaped, under the index\'s predicate',
         JSON.stringify(statement));

    // The cap, and `more`.
    for (let i = 0; i < 12; i++) {
      make(TOKEN + 'cap' + String(i).padStart(2, '0'), 'Cap ' + i);
    }
    found = await search(TOKEN + 'cap');
    note(found.status === 200 && uidsOf(found).length === 10 &&
         found.json.more === true,
         'B8. twelve matches answer ten, and say more matched',
         uidsOf(found).length + ' more=' + (found.json && found.json.more));
    found = await search(TOKEN + 'cap0');
    note(found.status === 200 && uidsOf(found).length === 10 &&
         found.json.more === false,
         'B9. exactly ten answer ten, and say nothing more did',
         uidsOf(found).length + ' more=' + (found.json && found.json.more));

    // THE STORE'S PAGE IS OVER-FETCHED AND READ HONESTLY: fifty excluded
    // rows and one native in a page the store filled answers the native and
    // `more`, never "that is everybody"; a page the store did not fill
    // answers exactly what it kept.
    const stamped = function (i) {
      return { entry: { dn: 'uid=s' + i + ',' + ldap.usersDn(), attributes: {
        uid: ['s' + i], cn: ['S'], stsprovisionedby: ['federation:x'] } } };
    };
    const page = [];
    for (let i = 0; i < 50; i++) {
      page.push(stamped(i));
    }
    page.push({ entry: { dn: 'uid=native,' + ldap.usersDn(),
                         attributes: { uid: ['native'], cn: ['N'] } } });
    const asked = ldap.DELEGATE_CANDIDATE_CAP *
      ldap.DELEGATE_CANDIDATE_OVERFETCH + 1;
    const full = ldap.delegateCandidatesOfPage(page, page.length, asked, 10,
                                               '');
    const partial = ldap.delegateCandidatesOfPage(page.slice(0, 51),
                                                  40, asked, 10, '');
    note(asked === 51 && full.people.length === 1 && full.more === true &&
         partial.more === false,
         'B10. a filled page of excluded rows says more may match; a short ' +
         'one says what it found', JSON.stringify({ full: full,
                                                    partial: partial.more }));

    // ===== C. CHOOSING ONE =================================================
    found = await search(BOB);
    const chosen = (found.json.people || [])[0] || {};
    const set = await alice.api('POST', '/account-api/delegate',
                                { action: 'set', delegate: chosen.dn });
    const facts = credentials.delegationFactsFor(ALICE) || {};
    note(set.status === 200 && chosen.dn === bobEntry.dn &&
         String(facts.mayAct || '').toLowerCase() ===
           bobEntry.dn.toLowerCase(),
         'C1. choosing a result names them through the existing POST: ' +
         'stsMayAct is their DN', brief(set) + ' ' + facts.mayAct);

    // ===== D. THE PAGE =====================================================
    const bundle = signin.portalBundle();
    const me = await alice.api('GET', '/account-api/me');
    const t = bundle.messages.WebTranslator.fromData(me.json.locale);
    const delegatePage = bundle.find('/portal/delegate');
    const drawn = delegatePage.render({ mayAct: '', delegate: null,
                                        notDelegated: false },
                                      { t: t, query: {} });
    note(/id="delegate-search"/.test(drawn) &&
         /id="delegate-search-q"/.test(drawn) &&
         /name="delegate"/.test(drawn) &&
         !/portalDelegate\./.test(drawn),
         'D1. the page draws the search beside the DN form, translated',
         drawn.slice(0, 300));
    const hostile = bundle.delegate.results('<x>', { status: 200, json: {
      people: [{ uid: '<script>u</script>', cn: '"><img src=x>',
                 dn: 'uid=a"b,ou=users' }], more: true } }, t);
    note(hostile.indexOf('<script>') < 0 && hostile.indexOf('<img') < 0 &&
         hostile.indexOf('&lt;script&gt;') >= 0 &&
         hostile.indexOf('value="uid=a&quot;b,ou=users"') >= 0 &&
         /action="\/portal\/delegate"/.test(hostile),
         'D2. the results are drawn escaped, each with a form naming its DN',
         hostile.slice(0, 400));
    const none = bundle.delegate.results('<b>zz', { status: 200,
      json: { people: [], more: false } }, t);
    note(none.indexOf('<b>zz') < 0 && none.indexOf('&lt;b&gt;zz') >= 0,
         'D3. "nobody" quotes the text escaped', none);

    // The debounce, on a clock of its own.
    const clock = { now: 0, timers: [] };
    const timers = {
      set: function (fn, ms) {
        const handle = { at: clock.now + ms, fn: fn, live: true };
        clock.timers.push(handle);
        return handle;
      },
      clear: function (handle) {
        handle.live = false;
      }
    };
    const advance = function (ms) {
      clock.now += ms;
      clock.timers.filter(function (h) {
        return h.live && h.at <= clock.now;
      }).forEach(function (h) {
        h.live = false;
        h.fn();
      });
    };
    const asks = [];
    const drawnFor = [];
    const pending = {};
    const ask = function (q) {
      asks.push(q);
      return new Promise(function (resolve) {
        pending[q] = resolve;
      });
    };
    const box = new bundle.delegate.Search(ask, function (q, answer) {
      drawnFor.push(answer ? q : null);
    }, timers, 3000);
    box.typed('a');
    box.typed('ab');
    advance(5000);
    note(asks.length === 0,
         'D4. under three characters, nothing is asked, however long the ' +
         'wait', JSON.stringify(asks));
    box.typed('abc');
    advance(2999);
    note(asks.length === 0, 'D5. nothing before three idle seconds',
         JSON.stringify(asks));
    box.typed('abcd');
    advance(2999);
    note(asks.length === 0, 'D6. a keystroke starts the three seconds again',
         JSON.stringify(asks));
    advance(1);
    note(asks.join('|') === 'abcd',
         'D7. three idle seconds ask once, for the text as it stands',
         JSON.stringify(asks));
    box.typed('abcde');
    advance(3000);
    pending.abcde({ status: 200, json: { people: [] } });
    await new Promise(function (res) { setImmediate(res); });
    pending.abcd({ status: 200, json: { people: [] } });
    await new Promise(function (res) { setImmediate(res); });
    note(drawnFor.filter(Boolean).join('|') === 'abcde',
         'D8. an answer made stale by a newer keystroke is never drawn',
         JSON.stringify(drawnFor));
    const submitted = box.submitted('ab');
    note(asks[asks.length - 1] === 'ab',
         'D9. Enter asks at once, whatever the length — the operation ' +
         'refuses a short text', JSON.stringify(asks));
    pending.ab({ status: 400, json: { errors: ['too short'] } });
    await submitted;

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ds-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  DS_ROOT: ROOT, DS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_delegate_search',
  describe: '/portal/delegate\'s search: native people of the realm by ' +
            'part of a uid, the stsProvisionedBy stamp that decides who ' +
            'is native, the doors that refuse it, and the debounced page',
  run: run
};
