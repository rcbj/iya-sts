// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: users_page_subjects_async.js
//
// ===========================================================================
// THE SHOWN ROWS' OWN SUBJECTS, ASKED TOGETHER (#881).
//
// `/admin/users` decorates a page with `stats.userRowsOfAsync()`. While the
// token register is on demand that used to warm `uid=<name>` and then call
// `subjectForName()` per row, and a certificate DN, a DID, a SPIFFE ID or a
// name that is not the uid was still one synchronous directory read, charged
// to the request's store budget (STS-LDAP-0175). The rows' identity keys are
// now one `subjectsForNamesAsync()`.
//
//   S1. the register is on demand and the directory is a window;
//   S2. during the page, `bridge.query` stays 0: one `byKeys` of the four
//       `uid=` directs, none for a certificate DN, `byName` for the three
//       uid misses, `byAttribute` for the certificate subject, the DID and
//       the SPIFFE ID, and no `withNames`;
//   S3. each row, including an `s:`-only token, equals `userRow()`;
//   S4. an empty list resolves [] and asks none of those questions;
//   S5. the batch tries the whole string before the fold, and agrees with
//       `subjectForName()`, the synchronous bridge idle while it asks;
//   S6. the page folds first, so `partner~erin@example.com` is asked as
//       `partner~erin` (`s:` of that person, not of the email's entry) and
//       still equals `userRow()` of the same key;
//   S7. not on demand, the batch is not asked and the row still matches;
//   S8. a rejecting `queryAsync` still fulfills the page: the `u:` token
//       counted, the `s:` one absent, and no synchronous fallback;
//   S9. with no window, `userRowsOfAsync()` matches `userRow()` and
//       `subjectsForNamesAsync()` matches `subjectForName()`.
//
// `helpers.warmPeopleAsync()` still warms the refresh grant. It is not on
// this path, and this file does not delete it.
//
// Three children, so the runner's own register is untouched. The windowed
// ones hold the directory as a request worker over a stand-in bridge that
// counts synchronous and asynchronous questions, and a reader active only
// for `admin_stats.tokens`. The third child installs neither.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'users_page_subjects_async',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_USERS_PAGE_SUBJECTS_CHILD';
const DANA = 'CN=dana,O=Example,C=US';
const ERIN = 'did:example:erin';
const FRANK = 'spiffe://example/ns/frank';
const EMAIL = 'partner~erin@example.com';
const FOLDED = 'partner~erin';

function person(dn, attrs) {
  log.debug('Entering person().');
  log.debug('Leaving person().');
  return { dn: dn, attrs: attrs };
}

// The stand-in world: a window, a counting bridge, and tokens that live only
// in the reader. Seeded uid=alice and uid=carol are forgotten and left out
// of the bridge, or `entriesAtAsync()` would answer them from the window
// and the cold `byKeys` / `byName` this file counts would never run.
async function prepare(t) {
  log.debug('Entering prepare().');
  const shared = require('./directory_window');
  const queries = require('../persistence/directory_queries');
  const ldap = require('../ldap/ldap_server');
  const stats = require('../common/admin_stats');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const w = ldap.directoryWindow;
  t.check(!!w, 'S1. the directory is a window onto the store');
  if (!w) {
    log.debug('Leaving prepare(). No window.');
    return null;
  }
  const users = ldap.usersDn();
  const rows = new Map();
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes, origin: null,
      created_at: '1', modified_at: '1' });
  });
  const skip = ['alice', 'carol'].map(function (uid) {
    return ldap.normalizeDn('uid=' + uid + ',' + users);
  });
  skip.forEach(function (key) {
    rows.delete('default\n' + key);
  });
  const made = {};
  const plant = function (name, spec) {
    const uuid = crypto.randomUUID();
    const attrs = Object.assign({
      objectclass: ['inetOrgPerson'], entryuuid: [uuid]
    }, spec.attrs);
    const one = shared.row('default', spec.dn, attrs);
    one.dn_key = ldap.normalizeDn(spec.dn);
    rows.set('default\n' + one.dn_key, one);
    made[name] = { uuid: uuid, subject: 'urn:uuid:' + uuid, dn: spec.dn };
  };
  plant('alice', person('uid=alice,' + users, { uid: ['alice'] }));
  plant('carol', person('cn=carol,' + users, { cn: ['Carol'] }));
  plant('dana', person('cn=dana,' + users,
                       { cn: ['Dana'], x509subject: [DANA] }));
  plant('erin', person('cn=erin,' + users,
                       { cn: ['Erin'], didsubject: [ERIN] }));
  plant('frank', person('cn=frank,' + users,
                        { cn: ['Frank'], spiffesubject: [FRANK] }));
  plant('gina', person('uid=gina,' + users, { uid: ['gina'] }));
  plant('email', person('uid=' + EMAIL + ',' + users, { uid: [EMAIL] }));
  plant('folded', person('uid=' + FOLDED + ',' + users, { uid: [FOLDED] }));
  const base = shared.fakeBridge(rows);
  const counts = { query: 0, queryAsync: 0 };
  const asyncNames = {};
  const syncNames = {};
  const asyncByKeys = [];
  const asyncByName = [];
  const asyncByAttr = [];
  const withUuids = function (args) {
    const wanted = new Set(args[1]);
    return Array.from(rows.values()).filter(function (r) {
      return r.realm === args[0] && (r.attrs.entryuuid || []).some(
        function (u) {
          return wanted.has(String(u).toLowerCase());
        });
    }).map(function (r) {
      return queries.rowOf(JSON.parse(JSON.stringify(r)));
    });
  };
  // A question the stand-in does not know must reject rather than answer
  // empty: an empty answer would hide a synchronous fallback.
  const failBox = { next: null };
  const bridgeObj = {
    query: function (name, args) {
      counts.query++;
      syncNames[name] = (syncNames[name] || 0) + 1;
      if (name === 'withUuids') {
        return withUuids(args);
      }
      return base.query(name, args);
    },
    queryAsync: function (name, args) {
      counts.queryAsync++;
      asyncNames[name] = (asyncNames[name] || 0) + 1;
      if (name === 'byKeys') {
        asyncByKeys.push((args[1] || []).slice());
      } else if (name === 'byName') {
        asyncByName.push(args[2]);
      } else if (name === 'byAttribute') {
        asyncByAttr.push(String(args[1]) + '=' + String(args[2]));
      }
      if (name === 'withUuids') {
        return Promise.resolve(withUuids(args));
      }
      if (failBox.next && failBox.next.name === name) {
        const err = failBox.next.err;
        failBox.next = null;
        return Promise.reject(err);
      }
      try {
        return Promise.resolve(base.query(name, args));
      } catch (e) {
        log.debug('Caught in queryAsync(): ' + ((e && e.message) || e));
        return Promise.reject(e);
      }
    }
  };
  w.attach(bridgeObj);
  const forgotten = skip.map(function (key) {
    return w.forget('default', key);
  });
  t.check(forgotten[0] === true && forgotten[1] === true,
          'S1. the seeded alice and carol slots were forgotten, so the ' +
          'page reads them from the store', JSON.stringify(forgotten));
  const tokens = new Map();
  const indexAsked = [];
  let tokensLive = true;
  realms.setOnDemandReader({
    active: function (handle) {
      return tokensLive && handle === 'admin_stats.tokens';
    },
    read: function (handle, realmId, key) {
      if (tokens.has(key)) {
        return { present: true, value: tokens.get(key) };
      }
      return { present: false };
    },
    readMany: function (handle, realmId, keys) {
      const out = new Map();
      keys.forEach(function (key) {
        if (tokens.has(key)) {
          out.set(key, tokens.get(key));
        }
      });
      return Promise.resolve(out);
    },
    byIndex: function (handle, realmId, indexKey) {
      indexAsked.push(indexKey);
      return rowsUnder(indexKey);
    },
    byIndexAsync: function (handle, realmId, indexKey) {
      indexAsked.push(indexKey);
      return Promise.resolve(rowsUnder(indexKey));
    },
    page: function () {
      return { rows: [], next: '' };
    },
    journalled: function () {
      return false;
    }
  });
  function rowsUnder(indexKey) {
    log.debug('Entering rowsUnder().');
    const out = [];
    tokens.forEach(function (value, key) {
      const indexes = [];
      if (value.username) {
        indexes.push('u:' + String(value.username));
      }
      if (value.sub) {
        indexes.push('s:' + String(value.sub));
      }
      if (indexes.indexOf(indexKey) >= 0) {
        out.push({ key: key, value: value });
      }
    });
    log.debug('Leaving rowsUnder().');
    return out;
  }
  const future = Math.floor(Date.now() / 1000) + 3600;
  const give = function (name, record) {
    const row = Object.assign({
      exp: future, revoked: false, issuedAt: Date.now(), jti: name
    }, record);
    tokens.set(name, row);
  };
  give('alice-u', { username: 'alice', sub: '' });
  give('alice-s', { username: '', sub: made.alice.subject });
  give('carol-s', { username: '', sub: made.carol.subject });
  give('dana-s', { username: '', sub: made.dana.subject });
  give('erin-s', { username: '', sub: made.erin.subject });
  give('frank-s', { username: '', sub: made.frank.subject });
  give('nobody-u', { username: 'nobody', sub: '' });
  give('svc-u', { username: 'svc-app', sub: '', grant: 'client_credentials' });
  give('folded-s', { username: '', sub: made.folded.subject });
  const inRealm = function (fn) {
    return realms.run(realms.get(realms.DEFAULT_ID), fn);
  };
  const snap = function () {
    return {
      query: counts.query,
      byKeys: asyncByKeys.length,
      byName: asyncByName.length,
      byAttr: asyncByAttr.length,
      syncWith: syncNames.withUuids || 0,
      syncByKeys: syncNames.byKeys || 0,
      syncByName: syncNames.byName || 0,
      syncByUuid: syncNames.byUuid || 0,
      asyncWith: asyncNames.withUuids || 0,
      withNames: asyncNames.withNames || 0,
      keys: asyncByKeys.slice(),
      names: asyncByName.slice(),
      attrs: asyncByAttr.slice(),
      index: indexAsked.slice()
    };
  };
  log.debug('Leaving prepare().');
  return {
    ldap: ldap, stats: stats, helpers: helpers, errorCodes: errorCodes,
    made: made, inRealm: inRealm, snap: snap, failBox: failBox,
    live: function (on) {
      tokensLive = on;
    },
    indexAsked: indexAsked
  };
}

function issuedOf(row) {
  log.debug('Entering issuedOf().');
  const n = row && row.tokens ? row.tokens.issued : -1;
  log.debug('Leaving issuedOf().');
  return n;
}

function shapeOf(row) {
  log.debug('Entering shapeOf().');
  const shape = row ? {
    key: row.key, isClient: !!row.isClient, artifacts: row.artifacts,
    tokens: row.tokens
  } : null;
  log.debug('Leaving shapeOf().');
  return shape;
}

async function inTheWorker(t) {
  log.debug('Entering inTheWorker().');
  const world = await prepare(t);
  if (!world) {
    log.debug('Leaving inTheWorker(). No window.');
    return;
  }
  const stats = world.stats;
  const ldap = world.ldap;
  const users = ldap.usersDn();
  const live = realmsLive(stats);
  t.check(live, 'S1. the token register is on demand', String(live));
  const pageKeys = ['alice', 'carol', DANA, ERIN, FRANK, 'nobody', 'svc-app'];

  const emptyBefore = world.snap();
  const empty = await world.inRealm(function () {
    return stats.userRowsOfAsync([]);
  });
  const emptyAfter = world.snap();
  t.check(Array.isArray(empty) && empty.length === 0 &&
          emptyAfter.byKeys === emptyBefore.byKeys &&
          emptyAfter.byName === emptyBefore.byName &&
          emptyAfter.byAttr === emptyBefore.byAttr,
          'S4. an empty list resolves [] and asks no byKeys, byName or ' +
          'byAttribute', JSON.stringify({ empty: empty,
                                          before: emptyBefore,
                                          after: emptyAfter }));

  const before = world.snap();
  const rows = await world.inRealm(function () {
    return stats.userRowsOfAsync(pageKeys);
  });
  const after = world.snap();
  const askedKeys = [];
  after.keys.slice(before.byKeys).forEach(function (list) {
    list.forEach(function (key) {
      askedKeys.push(key);
    });
  });
  const uidOf = function (name) {
    return ldap.normalizeDn('uid=' + name + ',' + users);
  };
  const wantedUids = ['alice', 'carol', 'nobody', 'svc-app'].map(uidOf)
    .sort().join('|');
  const danaKey = ldap.normalizeDn(DANA);
  t.check(after.query === before.query && after.byKeys === before.byKeys + 1 &&
          askedKeys.slice().sort().join('|') === wantedUids &&
          askedKeys.indexOf(danaKey) < 0 && askedKeys.indexOf(DANA) < 0,
          'S2. one byKeys of the four uid directs, none for the ' +
          'certificate DN, and bridge.query stays 0',
          JSON.stringify({ query: after.query - before.query,
                           keys: askedKeys }));
  const names = after.names.slice(before.byName).slice().sort().join('|');
  t.check(after.byName === before.byName + 3 && names ===
          'carol|nobody|svc-app' && after.withNames === before.withNames,
          'S2. byName once each for the three uid misses, and no withNames',
          JSON.stringify({ names: after.names.slice(before.byName),
                           withNames: after.withNames }));
  const attrs = after.attrs.slice(before.byAttr).slice().sort().join('|');
  const wantedAttrs = ['x509subject=' + DANA, 'didsubject=' + ERIN,
                       'spiffesubject=' + FRANK].sort().join('|');
  t.check(attrs === wantedAttrs,
          'S2. byAttribute for the certificate subject, the DID and the ' +
          'SPIFFE ID, the certificate text un-normalised',
          JSON.stringify(after.attrs.slice(before.byAttr)));
  const expectIssued = [2, 1, 1, 1, 1, 1, 1];
  const issued = (rows || []).map(issuedOf);
  t.check(JSON.stringify(issued) === JSON.stringify(expectIssued) &&
          rows[5] && rows[5].isClient === false &&
          rows[6] && rows[6].isClient === true,
          'S2. s:-only tokens counted for the five people, nobody\'s u: ' +
          'token counted, and svc-app is a client',
          JSON.stringify(issued));

  const helperKeys = [EMAIL, FOLDED, 'alice@REALM', 'urn:sts:user:alice',
                     'urn:uuid:' + world.made.alice.uuid, ''];
  const helperBefore = world.snap();
  const subjects = await world.inRealm(function () {
    return world.helpers.subjectsForNamesAsync(helperKeys);
  });
  const helperAfter = world.snap();
  const wantSubjects = [world.made.email.subject, world.made.folded.subject,
                       world.made.alice.subject, world.made.alice.subject,
                       world.made.alice.subject, ''];
  let oracle = [];
  world.inRealm(function () {
    oracle = helperKeys.map(function (key) {
      return world.helpers.subjectForName(key);
    });
  });
  t.check(helperAfter.query === helperBefore.query &&
          helperAfter.syncByUuid === helperBefore.syncByUuid &&
          JSON.stringify(subjects) === JSON.stringify(wantSubjects) &&
          JSON.stringify(subjects) === JSON.stringify(oracle),
          'S5. the whole string before the fold, agreeing with ' +
          'subjectForName(), and no synchronous byUuid',
          JSON.stringify({ subjects: subjects, oracle: oracle,
                           query: helperAfter.query - helperBefore.query }));

  world.indexAsked.length = 0;
  const emailBefore = world.snap();
  const emailRows = await world.inRealm(function () {
    return stats.userRowsOfAsync([EMAIL]);
  });
  const emailIndex = world.indexAsked.slice();
  const emailAfter = world.snap();
  const emailSync = world.inRealm(function () {
    return stats.userRow(EMAIL);
  });
  world.indexAsked.length = 0;
  const foldedRows = await world.inRealm(function () {
    return stats.userRowsOfAsync([FOLDED]);
  });
  const foldedSync = world.inRealm(function () {
    return stats.userRow(FOLDED);
  });
  t.check(emailAfter.query === emailBefore.query &&
          JSON.stringify(shapeOf(emailRows && emailRows[0])) ===
          JSON.stringify(shapeOf(emailSync)) &&
          emailIndex.indexOf('s:' + world.made.folded.subject) >= 0 &&
          emailIndex.indexOf('s:' + world.made.email.subject) < 0 &&
          issuedOf(foldedRows && foldedRows[0]) === 1 &&
          JSON.stringify(shapeOf(foldedRows && foldedRows[0])) ===
          JSON.stringify(shapeOf(foldedSync)),
          'S6. the page folds the email first, asks s: of that person, ' +
          'and matches userRow() of both keys',
          JSON.stringify({ email: shapeOf(emailRows && emailRows[0]),
                           emailSync: shapeOf(emailSync),
                           folded: shapeOf(foldedRows && foldedRows[0]),
                           index: emailIndex }));

  const compared = pageKeys.map(function (key, i) {
    const sync = world.inRealm(function () {
      return stats.userRow(key);
    });
    return JSON.stringify(shapeOf(rows[i])) === JSON.stringify(shapeOf(sync));
  });
  t.check(compared.every(Boolean),
          'S3. each async row equals userRow(), s:-only tokens included',
          JSON.stringify(compared));

  world.live(false);
  t.check(realmsLive(stats) === false,
          'S7. the token register is no longer on demand');
  world.inRealm(function () {
    stats.recordJwt({ jti: 'g-u', sub: '', username: 'gina', exp: futureExp(),
                      typ: 'Bearer' }, 'x.y.z', { kind: 'access_token' });
    stats.recordJwt({ jti: 'g-s', sub: world.made.gina.subject,
                      exp: futureExp(), typ: 'Bearer' }, 'x.y.z',
                    { kind: 'access_token' });
  });
  const offBefore = world.snap();
  const ginaAsync = await world.inRealm(function () {
    return stats.userRowsOfAsync(['gina']);
  });
  const offAfter = world.snap();
  const ginaSync = world.inRealm(function () {
    return stats.userRow('gina');
  });
  t.check(offAfter.byKeys === offBefore.byKeys &&
          offAfter.byName === offBefore.byName &&
          offAfter.syncByKeys === offBefore.syncByKeys &&
          offAfter.syncByName === offBefore.syncByName &&
          offAfter.syncWith === offBefore.syncWith &&
          issuedOf(ginaAsync && ginaAsync[0]) === 2 &&
          JSON.stringify(shapeOf(ginaAsync && ginaAsync[0])) ===
          JSON.stringify(shapeOf(ginaSync)),
          'S7. not on demand, no subject batch, and the row matches, ' +
          'the s:-only token included',
          JSON.stringify({ async: shapeOf(ginaAsync && ginaAsync[0]),
                           sync: shapeOf(ginaSync),
                           byKeys: offAfter.byKeys - offBefore.byKeys,
                           byName: offAfter.byName - offBefore.byName }));
  log.debug('Leaving inTheWorker().');
}

function realmsLive(stats) {
  log.debug('Entering realmsLive().');
  // `onDemandLive()` is the store's own method. `handleFor()` returns the
  // declared handle row, which has no such function.
  const live = stats.tokensOnDemand();
  log.debug('Leaving realmsLive().');
  return live;
}

function futureExp() {
  log.debug('Entering futureExp().');
  const exp = Math.floor(Date.now() / 1000) + 3600;
  log.debug('Leaving futureExp().');
  return exp;
}

async function failureCase(t) {
  log.debug('Entering failureCase().');
  const world = await prepare(t);
  if (!world) {
    log.debug('Leaving failureCase(). No window.');
    return;
  }
  const before = world.snap();
  world.failBox.next = { name: 'byKeys', err: new Error('store refused') };
  let rows = null;
  let rejected = '';
  try {
    rows = await world.inRealm(function () {
      return world.stats.userRowsOfAsync(['alice']);
    });
  } catch (e) {
    log.debug('Caught in failureCase(): ' + ((e && e.message) || e));
    rejected = (e && e.message) || String(e);
  }
  const after = world.snap();
  t.check(!rejected && issuedOf(rows && rows[0]) === 1 &&
          after.query === before.query &&
          after.syncByKeys === before.syncByKeys &&
          after.syncByName === before.syncByName,
          'S8. a rejecting queryAsync still draws the page: the u: token ' +
          'counted, the s: one absent, and no synchronous fallback',
          JSON.stringify({ rejected: rejected, issued: issuedOf(rows &&
                                                                rows[0]),
                           query: after.query - before.query }));
  world.failBox.next = {
    name: 'byKeys',
    err: world.errorCodes.mark(new Error('budget spent'), 'STS-LDAP-0175')
  };
  let answered = null;
  let threw = '';
  try {
    answered = await world.inRealm(function () {
      return world.helpers.subjectsForNamesAsync(['alice']);
    });
  } catch (e) {
    log.debug('Caught in failureCase(): ' + ((e && e.message) || e));
    threw = (e && e.message) || String(e);
  }
  const spent = world.snap();
  t.check(!threw && JSON.stringify(answered) === JSON.stringify(['']) &&
          spent.query === after.query,
          'S8. a spent directory budget is an empty subject and does not ' +
          'throw', JSON.stringify({ threw: threw, answered: answered,
                                    query: spent.query - after.query }));
  log.debug('Leaving failureCase().');
}

async function plainCase(t) {
  log.debug('Entering plainCase().');
  const ldap = require('../ldap/ldap_server');
  const stats = require('../common/admin_stats');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  t.check(!ldap.directoryWindow && realmsLive(stats) === false,
          'S9. no window and the token register is held whole',
          JSON.stringify({ window: !!ldap.directoryWindow,
                           live: realmsLive(stats) }));
  const name = 'upsa-' + crypto.randomUUID().slice(0, 8);
  const created = realms.run(realms.get(realms.DEFAULT_ID), function () {
    return ldap.createUser(name);
  });
  const subject = helpers.subjectForName(name);
  t.check(created && created.ok && /^urn:uuid:/i.test(subject),
          'S9. a person exists to be the subject of',
          JSON.stringify({ ok: created && created.ok, subject: subject }));
  const exp = futureExp();
  realms.run(realms.get(realms.DEFAULT_ID), function () {
    stats.recordJwt({ jti: 'p-u', sub: '', username: name, exp: exp,
                      typ: 'Bearer' }, 'x.y.z', { kind: 'access_token' });
    stats.recordJwt({ jti: 'p-s', sub: subject, exp: exp, typ: 'Bearer' },
                    'x.y.z', { kind: 'access_token' });
  });
  const asyncRow = await realms.run(realms.get(realms.DEFAULT_ID),
    function () {
      return stats.userRowsOfAsync([name]);
    });
  const syncRow = realms.run(realms.get(realms.DEFAULT_ID), function () {
    return stats.userRow(name);
  });
  const many = await helpers.subjectsForNamesAsync([name, 'no-such-upsa', '']);
  const oneByOne = [name, 'no-such-upsa', ''].map(function (key) {
    return helpers.subjectForName(key);
  });
  t.check(issuedOf(asyncRow && asyncRow[0]) === 2 &&
          JSON.stringify(shapeOf(asyncRow && asyncRow[0])) ===
          JSON.stringify(shapeOf(syncRow)) &&
          JSON.stringify(many) === JSON.stringify(oneByOne) &&
          many[0] === subject && many[1] === '' && many[2] === '',
          'S9. with no window the async row matches userRow(), the s:-only ' +
          'token included, and subjectsForNamesAsync matches subjectForName()',
          JSON.stringify({ async: shapeOf(asyncRow && asyncRow[0]),
                           sync: shapeOf(syncRow), many: many,
                           oneByOne: oneByOne }));
  log.debug('Leaving plainCase().');
}

async function childMain() {
  log.debug('Entering childMain().');
  const seen = [];
  const t = {
    log: log,
    check: function (ok, what, detail) {
      seen.push({ ok: !!ok, what: what, detail: detail || '' });
      return !!ok;
    }
  };
  let threw = '';
  try {
    const which = process.env.STS_TEST_USERS_PAGE_SUBJECTS_WHICH || 'window';
    if (which === 'fail') {
      await failureCase(t);
    } else if (which === 'plain') {
      await plainCase(t);
    } else {
      await inTheWorker(t);
    }
  } catch (e) {
    log.debug('Caught in childMain(): ' + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug('Leaving childMain().');
  process.exit(0);
}

function spawnChild(which) {
  log.debug('Entering spawnChild().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-upsa-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, {
    PROBE_OUT: outFile, LOG_LEVEL: 'fatal'
  });
  env[CHILD_FLAG] = '1';
  env.STS_TEST_USERS_PAGE_SUBJECTS_WHICH = which;
  delete env.CONFIG_FILE;
  if (which === 'plain') {
    delete env.STS_REQUEST_WORKER;
    delete env.LDAP_WORKER_DIRECTORY;
    delete env.STS_PERSISTENCE_MODE;
    delete env.LDAP_WORKER_CACHE_ENTRIES;
  } else {
    env.STS_REQUEST_WORKER = '1';
    env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
    env.STS_PERSISTENCE_MODE = 'postgres';
    env.LDAP_WORKER_CACHE_ENTRIES = '100';
  }
  const child = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
    timeout: 180000
  });
  log.debug('Leaving spawnChild().');
  return { child: child, outFile: outFile, dir: dir };
}

function reportChild(t, which, spawned) {
  log.debug('Entering reportChild().');
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(spawned.outFile, 'utf8'));
  } catch (e) {
    log.debug('Caught in reportChild(): ' + ((e && e.message) || e));
    t.bad('the ' + which + ' child reported nothing', 'status ' +
          spawned.child.status + ': ' +
          String(spawned.child.stderr || '').slice(-2000));
    log.debug('Leaving reportChild().');
    return;
  } finally {
    fs.rmSync(spawned.dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the ' + which + ' child threw', result.threw);
  }
  t.check(result.seen.length >= 1, 'the ' + which + ' child ran',
          String(result.seen.length));
  log.debug('Leaving reportChild().');
}

function run(t) {
  log.debug('Entering run().');
  ['window', 'fail', 'plain'].forEach(function (which) {
    reportChild(t, which, spawnChild(which));
  });
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'users_page_subjects_async',
  describe: 'the Users page resolves shown-row subjects in one async batch ' +
            '(#881)',
  run: run
};
