// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: users_page_before_decoration.js
//
// ===========================================================================
// /admin/users PAGES BEFORE IT DECORATES (#352, 2026-09-29).
//
// On testidp (29,267 people) `GET /admin-api/users` took ten seconds whatever
// the page or `?q=`, because `usersListJson()` asked
// `credentials.mechanismsFor()` — nine directory reads and an unseal of the
// TOTP secret — of EVERY person, to show fifty and count seven tiles. It now
// lists the population from names, filters and pages on them, decorates only
// the rows shown, and answers the tiles and `?factor=` from one census pass
// whose TOTP verdicts are remembered per sealed secret.
//
// Asserted, against a realm of a few thousand people seeded here with
// passwords, security keys in both roles, sealed, clear and unreadable
// authenticator enrolments, recovery codes and an opted-in emailed factor:
//
//   1. page one, a far page and a `?q=` filter each call `mechanismsFor()` no
//      more often than the page holds rows, and `keystore.open()` no more
//      often than there are sealed enrolments — on the first request — and
//      NEVER on a repeat;
//   2. the seven tiles, `known`, `authenticatedHere`, `protocols`, the
//      scan-cap reporting and the rows shown are what the old algorithm
//      gives, computed here independently: every person asked on their own,
//      with the TOTP verdict from `totpOf()`, which really opens the secret;
//   3. each `?factor=` filter matches the same people as before, and still
//      decorates only one page;
//   4. `GET /admin-api/mfa` answers the same counts out of the same view;
//   5. `?user=` answers the row `userRows()` would have held, and
//      `knownUserKeys()` the keys, without building the rows;
//   6. `stats.issuedArtifactsOfKind()` answers the Kerberos tickets
//      `issuedList()` would have, in the same order.
//
// The timings printed are information only; nothing here asserts a clock.
//
// WHY IN PROCESS: the claim is about how often two functions are CALLED per
// request, which only a spy inside the process can count, and the population
// that makes it matter is thousands of entries no HTTP job should create.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const helpers = require('../common/helpers');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');
const credentials = require('../common/credentials');
const keystore = require('../common/keystore');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({
  name: 'users_page_before_decoration',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const REALM = 'upbd' + STAMP.slice(-6);
const PEOPLE = 3000;
// Below PEOPLE, so the scan cap is reached and reported, and the register's
// rows past it still reach the list.
const SCAN_LIMIT = 2500;
const PER = 50;

// ---------------------------------------------------------------------------
// The two spies. `keystore.open()` is replaced for the test's own sealed
// texts only (anything else goes to the real one), so the enrolments need no
// key-encryption key and the count is exact.
// ---------------------------------------------------------------------------
const counts = { mechanisms: 0, opens: 0 };
const SEALED = 'test-sealed:' + STAMP + ':';
const BROKEN = 'test-broken:' + STAMP + ':';

function installSpies() {
  log.debug("Entering installSpies().");
  const proto = credentials.Credentials.prototype;
  const realMechanisms = proto.mechanismsFor;
  const realOpen = keystore.open;
  proto.mechanismsFor = function () {
    counts.mechanisms += 1;
    return realMechanisms.apply(this, arguments);
  };
  keystore.open = function (ciphertext, label) {
    const text = String(ciphertext);
    if (text.indexOf(SEALED) === 0) {
      counts.opens += 1;
      return 'JBSWY3DPEHPK3PXP';
    }
    if (text.indexOf(BROKEN) === 0) {
      counts.opens += 1;
      return null;
    }
    return realOpen.call(keystore, ciphertext, label);
  };
  log.debug("Leaving installSpies().");
  return function restore() {
    log.debug("Entering restore().");
    proto.mechanismsFor = realMechanisms;
    keystore.open = realOpen;
    log.debug("Leaving restore().");
  };
}

function reset() {
  log.debug("Entering reset().");
  counts.mechanisms = 0;
  counts.opens = 0;
  log.debug("Leaving reset().");
}

// ---------------------------------------------------------------------------
// SEEDING. Each person is created through `createUser()` — the console's door,
// which also notes them in the register — and their credential attributes are
// then set on the stored entry as the directory holds them. The values are the
// shapes `credentials.ts` writes; no password is hashed, because only its
// presence is read.
// ---------------------------------------------------------------------------
function nameOf(i) {
  log.debug("Entering nameOf().");
  log.debug("Leaving nameOf().");
  return 'upbd-' + STAMP + '-' + String(i).padStart(4, '0');
}

function storedOf(name) {
  log.debug("Entering storedOf().");
  const found = ldap.existingUserEntry(name);
  log.debug("Leaving storedOf().");
  return found;
}

function totpValue(secret, sealed) {
  log.debug("Entering totpValue().");
  log.debug("Leaving totpValue().");
  return JSON.stringify({ secret: secret, sealed: sealed, algorithm: 'SHA1',
                          digits: 6, period: 30, enrolledAt: 1000,
                          lastUsedAt: 0 });
}

function keyValue(id, role) {
  log.debug("Entering keyValue().");
  log.debug("Leaving keyValue().");
  return JSON.stringify({ credentialId: id, role: role, signCount: 0,
                          publicKeyJwk: { kty: 'EC', crv: 'P-256',
                                          x: 'AA', y: 'AA' } });
}

function seed(t) {
  log.debug("Entering seed().");
  const tally = { sealed: 0 };
  const started = Date.now();
  for (let i = 0; i < PEOPLE; i++) {
    const name = nameOf(i);
    const made = ldap.createUser(name, { invent: false, origin: 'test' });
    if (!made || !made.ok) {
      t.bad('seeding ' + name, JSON.stringify(made && made.errors));
      log.debug("Leaving seed(). A create failed.");
      return tally;
    }
    const a = storedOf(name).attributes;
    if (i % 3 === 0) {
      a.userpassword = ['$scrypt$seeded-presence-only'];
    }
    const keys = [];
    if (i % 7 === 0) {
      keys.push(keyValue('mfa-' + i, 'mfa'));
    }
    if (i % 11 === 0) {
      keys.push(keyValue('primary-' + i, 'primary'));
    }
    if (i % 500 === 250) {
      keys.push('not json a client wrote');
    }
    if (keys.length) {
      a.stswebauthncredential = keys;
    }
    if (i % 13 === 0) {
      a.ststotpcredential = [totpValue(SEALED + i, true)];
      tally.sealed += 1;
    } else if (i % 29 === 0) {
      a.ststotpcredential = [totpValue(BROKEN + i, true)];
      tally.sealed += 1;
    } else if (i % 17 === 0) {
      a.ststotpcredential = [totpValue('JBSWY3DPEHPK3PXP', false)];
    } else if (i === 31) {
      a.ststotpcredential = ['not json either'];
    }
    if (i % 23 === 0) {
      a.stsbackupcodes = [JSON.stringify({ version: 2, total: 0,
        remaining: 0, generatedAt: 1000, lastUsedAt: 0, sealed: false,
        hashed: true, vault: '[]' })];
    }
    if (i % 41 === 0) {
      a.mail = [name + '@example.org'];
      a.stsmailverified = [name + '@example.org'];
      a.stsmailfactor = ['code'];
    }
  }
  // A person the register knows under another spelling of their name, one
  // it knows and the directory does not, a client, and a registered
  // application seen only as an artifact's subject.
  stats.recordAuthentication({ presented: nameOf(5) + '@EXAMPLE.ORG',
                               protocol: 'Kerberos v5', method: 'password' });
  stats.recordAuthentication({ presented: 'upbd-ghost-' + STAMP,
                               protocol: 'OAuth 2.0', method: 'password' });
  helpers.signJwt({ jti: 'upbd-cc-' + STAMP, typ: 'Bearer',
                    sub: 'urn:sts:client:upbd-client-' + STAMP,
                    client_id: 'upbd-client-' + STAMP,
                    exp: Math.floor(Date.now() / 1000) + 600 },
                  { grant: 'client_credentials' });
  const app = 'upbd-app-' + STAMP;
  applications.createApplication({ identifier: app, protocols: ['saml2'],
                                   fields: {} });
  stats.recordAssertion('2.0', { id: 'upbd-a-' + STAMP, subject: app });
  // Two Kerberos tickets for section 6.
  stats.recordTicket('TGT', { client: nameOf(1) + '@UPBD', realm: 'UPBD',
                              expiresAt: Date.now() + 600000 });
  stats.recordTicket('TGT', { client: nameOf(2) + '@UPBD', realm: 'UPBD',
                              expiresAt: Date.now() - 1000 });
  t.log.info('seeded ' + PEOPLE + ' people in ' + (Date.now() - started) +
             ' ms (' + tally.sealed + ' sealed authenticator enrolments)');
  log.debug("Leaving seed().");
  return tally;
}

// ---------------------------------------------------------------------------
// THE OLD ALGORITHM, WRITTEN OUT AGAIN HERE. Every name the population holds
// is asked on its own — `mechanismsFor()` for what it holds and `totpOf()`,
// which really opens the secret, for whether an enrolment can be read — and
// folded, filtered and counted the way `peopleRows()` and `usersListJson()`
// did before #352. Only `mergeFactors()` is borrowed, because #352 did not
// change it and the rows shown are compared whole.
// ---------------------------------------------------------------------------
function oldHolders(known) {
  log.debug("Entering oldHolders().");
  const seen = new Map();
  const add = function (name, source) {
    const value = String(name == null ? '' : name).trim();
    if (!value) {
      return;
    }
    const key = value.toLowerCase();
    if (!seen.has(key)) {
      seen.set(key, { username: value, inDirectory: false, known: false });
    }
    seen.get(key)[source] = true;
  };
  let people = ldap.allPersons().map(function (entry) {
    return ldap.usernameOfEntry(entry);
  }).filter(function (name) { return !!name; });
  const scanned = people.length;
  const capped = people.length > SCAN_LIMIT;
  people = people.slice(0, SCAN_LIMIT);
  people.forEach(function (name) { add(name, 'inDirectory'); });
  known.forEach(function (name) { add(name, 'known'); });
  const rows = [];
  seen.forEach(function (row) {
    const m = credentials.mechanismsFor(row.username);
    const opened = credentials.totpOf(row.username);
    rows.push({ username: row.username, inDirectory: row.inDirectory,
                known: row.known, password: m.password,
                primaryKeys: m.primaryKeys, mfaKeys: m.mfaKeys,
                totp: !!opened, totpUsable: !!opened && !opened.unusable,
                totpDetail: m.totpDetail, backupCodes: m.backupCodes,
                recoveryAdvised: m.recoveryAdvised,
                mfaRequired: m.mfaRequired, secondFactor: m.secondFactor,
                usable: m.usable });
  });
  rows.sort(function (a, b) {
    return a.username.toLowerCase() < b.username.toLowerCase() ? -1 : 1;
  });
  log.debug("Leaving oldHolders().");
  return { rows: rows, scanned: scanned, capped: capped };
}

function oldView(query) {
  log.debug("Entering oldView().");
  const seen = stats.userRows();
  const byKey = new Map();
  seen.forEach(function (row) {
    row.factors = null;
    row.inDirectory = false;
    byKey.set(row.key, row);
  });
  const holders = oldHolders(seen.map(function (row) { return row.key; }));
  holders.rows.forEach(function (holder) {
    const key = stats.identityKeyOf(holder.username);
    if (!key) {
      return;
    }
    let row = byKey.get(key);
    if (!row) {
      row = { key: key, name: holder.username, forms: [], realms: [],
              protocols: [], authentications: 0, firstAt: 0, lastAt: 0,
              isClient: false, authenticated: false, knownBy: 'directory',
              events: [], eventsForgotten: 0,
              tokens: { issued: 0, valid: 0, expired: 0, revoked: 0,
                        other: 0 },
              artifactKinds: [], artifacts: 0, lastActivityAt: 0,
              factors: null, inDirectory: false };
      byKey.set(key, row);
    }
    row.inDirectory = row.inDirectory || !!holder.inDirectory;
    row.factors = adminViews.mergeFactors(row.factors, holder);
  });
  const all = Array.from(byKey.values()).filter(function (row) {
    const clientForm = (row.forms || []).some(function (one) {
      return /^urn:sts:client:/.test(String((one && one.form) || one));
    });
    return !(row.isClient || clientForm ||
             (!row.inDirectory && applications.get(row.key)));
  });
  all.sort(function (a, b) {
    return String(a.name).toLowerCase() < String(b.name).toLowerCase() ? -1 :
           1;
  });
  const q = String(query.q || '').trim().toLowerCase();
  const factor = String(query.factor || '');
  const filtered = all.filter(function (row) {
    const f = row.factors;
    if (q && row.key.toLowerCase().indexOf(q) < 0) return false;
    if (factor === 'totp' && !(f && f.totp)) return false;
    if (factor === 'key' && !(f && f.mfaKeys > 0)) return false;
    if (factor === 'any' && !(f && f.mfaRequired)) return false;
    if (factor === 'none' && !(f && !f.mfaRequired)) return false;
    if (factor === 'unreadable' && !(f && f.totp && !f.totpUsable)) {
      return false;
    }
    return true;
  });
  const n = function (test) {
    return all.filter(function (r) {
      return r.factors && test(r.factors, r);
    }).length;
  };
  const page = Math.min(Math.max(parseInt(query.page || '1', 10) || 1, 1),
                        Math.max(1, Math.ceil(filtered.length / PER)));
  log.debug("Leaving oldView().");
  return {
    known: all.length, matched: filtered.length,
    authenticatedHere: all.filter(function (r) {
      return r.authenticated;
    }).length,
    scanned: holders.scanned, capped: holders.capped,
    factors: {
      withSecond: n(function (f) { return f.mfaRequired; }),
      withTotp: n(function (f) { return f.totp; }),
      withKeys: n(function (f) { return f.mfaKeys > 0; }),
      primaryKeys: n(function (f) { return f.primaryKeys > 0; }),
      passwordOnly: n(function (f) { return f.password && !f.mfaRequired; }),
      unreadable: n(function (f) { return f.totp && !f.totpUsable; }),
      noCredential: n(function (f, r) { return !f.usable && !r.isClient; })
    },
    users: filtered.slice((page - 1) * PER, page * PER)
  };
}

// The members compared between the two answers. Whole rows, with their
// factors, for the rows shown — less `liveSessions`, which the answer has
// carried since #446 for the page's sessions column and which counts sign-on
// sessions rather than anything the old algorithm decided, less
// `serviceAccount`, which #221 added for the page's service-account mark,
// and less `dn`, which #461 added for the delegation fields' search — neither
// is anything the old algorithm decided.
function comparable(json) {
  log.debug("Entering comparable().");
  const users = (json.users || []).map(function (row) {
    const copy = Object.assign({}, row);
    delete copy.liveSessions;
    delete copy.serviceAccount;
    delete copy.dn;
    return copy;
  });
  log.debug("Leaving comparable().");
  return JSON.stringify({ known: json.known, matched: json.matched,
                          authenticatedHere: json.authenticatedHere,
                          scanned: json.scanned, capped: json.capped,
                          factors: json.factors, users: users });
}

// Two answers compared, with a SHORT detail on a mismatch — the whole reply
// is hundreds of kilobytes, and printing it on every pass would bury the
// report (and once lost its tail to an exiting process).
function same(t, got, wanted, what) {
  log.debug("Entering same().");
  const a = comparable(got);
  const b = comparable(wanted);
  let at = 0;
  while (at < a.length && a[at] === b[at]) {
    at++;
  }
  t.check(a === b, what, a === b ? a.length + ' bytes alike'
    : 'first difference at ' + at + ': got …' + a.slice(at, at + 160) +
      '… wanted …' + b.slice(at, at + 160) + '…');
  log.debug("Leaving same().");
}

function timed(fn) {
  log.debug("Entering timed().");
  const started = process.hrtime.bigint();
  const value = fn();
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  log.debug("Leaving timed().");
  return { value: value, ms: Math.round(ms) };
}

function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  const restore = installSpies();
  try {
    realms.run(made.realm, function () {
      config.setOverride('ldap.maxEntries', '100000');
      config.setOverride('credentials.factorScanLimit', String(SCAN_LIMIT));
      try {
        body(t, seed(t));
      } finally {
        config.clearOverride('ldap.maxEntries');
        config.clearOverride('credentials.factorScanLimit');
      }
    });
  } finally {
    restore();
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

function body(t, tally) {
  log.debug("Entering body().");
  const view = function (query) {
    return adminViews.usersJson({ query: Object.assign({ per: String(PER) },
                                                       query) });
  };

  // --- 1. page one: bounded, then free ----------------------------------
  // FIRST, before anything else here has asked about anybody, so the TOTP
  // verdicts are not yet remembered and the count is a first request's.
  reset();
  const first = timed(function () { return view({}); });
  const firstCounts = Object.assign({}, counts);
  t.log.info('AFTER, first request: ' + first.ms + ' ms, ' +
             firstCounts.mechanisms + ' mechanismsFor(), ' +
             firstCounts.opens + ' keystore.open()');
  t.check(firstCounts.mechanisms <= PER,
          '1a. page one asks mechanismsFor() at most once per row shown',
          firstCounts.mechanisms + ' call(s)');
  t.check(firstCounts.opens > 0 && firstCounts.opens <= tally.sealed,
          '1b. and opens each sealed authenticator secret at most once',
          firstCounts.opens + ' of ' + tally.sealed);

  // --- 2. the old answer ------------------------------------------------
  const before = timed(function () { return oldView({}); });
  t.log.info('BEFORE (every person asked on their own): ' + before.ms +
             ' ms for ' + before.value.known + ' people');
  t.check(before.value.known > PER * 20 && before.value.capped === true,
          '(precondition) the population is many pages long and past the ' +
          'scan cap', 'known=' + before.value.known);
  same(t, first.value, before.value,
       '2. page one answers exactly what the old algorithm did — tiles, ' +
       'counts, scan cap and the rows shown with their factors');
  t.check(first.value.users.length === PER &&
          first.value.users.every(function (row) { return !!row.factors; }),
          '2a. every row shown carries its factors');

  reset();
  const again = timed(function () { return view({}); });
  t.log.info('AFTER, repeat: ' + again.ms + ' ms, ' + counts.opens +
             ' keystore.open()');
  t.equal(counts.opens, 0, '1c. a repeat request opens nothing');
  same(t, again.value, before.value, '1d. and answers the same');

  // --- 1. a far page and a text filter ----------------------------------
  const farPage = String(Math.floor(before.value.known / PER) - 1);
  reset();
  const far = view({ page: farPage });
  t.check(counts.mechanisms <= PER && counts.opens === 0,
          '1e. page ' + farPage + ' asks mechanismsFor() at most once per ' +
          'row and opens nothing', counts.mechanisms + ' / ' + counts.opens);
  same(t, far, oldView({ page: farPage }),
       '1f. and shows the rows the old algorithm put on that page');
  const q = '-' + STAMP + '-00';
  reset();
  const filtered = view({ q: q });
  t.check(counts.mechanisms <= PER,
          '1g. ?q= asks mechanismsFor() at most once per row shown',
          String(counts.mechanisms));
  same(t, filtered, oldView({ q: q }), '1h. and matches the same people');

  // --- 3. every ?factor= ------------------------------------------------
  ['totp', 'key', 'any', 'none', 'unreadable'].forEach(function (factor) {
    reset();
    const got = view({ factor: factor });
    t.check(counts.mechanisms <= PER,
            '3. ?factor=' + factor + ' decorates only the page (' +
            got.matched + ' matched)', String(counts.mechanisms));
    same(t, got, oldView({ factor: factor }),
         '3. ?factor=' + factor + ' matches the same people as before');
  });

  // --- 4. the roster ----------------------------------------------------
  const roster = adminViews.mfaRosterJson({ query: { per: String(PER) } });
  t.equal(JSON.stringify(roster.counts),
          JSON.stringify(Object.assign({ people: before.value.known },
                                       before.value.factors)),
          '4. /admin-api/mfa counts what the users view counts');

  // --- 5. one person, and the keys --------------------------------------
  const who = nameOf(5);
  const wholeRow = stats.userRows().filter(function (r) {
    return r.key === who;
  })[0];
  const detail = adminViews.usersJson({ query: { user: who } });
  t.check(detail.known === true &&
          JSON.stringify(detail.user) === JSON.stringify(wholeRow),
          '5a. ?user= answers the row userRows() would have held');
  t.check(JSON.stringify(stats.userRow(who)) === JSON.stringify(wholeRow),
          '5b. stats.userRow() is that row');
  const keys = Object.keys(adminViews.knownUserKeys()).sort();
  const rowKeys = stats.userRows().map(function (r) { return r.key; }).sort();
  t.check(JSON.stringify(keys) === JSON.stringify(rowKeys),
          '5c. knownUserKeys() is the keys of userRows(), read without them',
          keys.length + ' key(s)');

  // --- 6. the Kerberos tickets ------------------------------------------
  const pick = function (rows) {
    return JSON.stringify(rows.map(function (r) {
      return [r.subject, r.state, r.issuedAt, r.expiresAtMs, r.family];
    }));
  };
  const tickets = stats.issuedArtifactsOfKind('Kerberos TGT');
  t.check(tickets.length >= 2 &&
          pick(tickets) === pick(stats.issuedList().filter(function (r) {
            return r.kind === 'Kerberos TGT';
          })),
          '6. issuedArtifactsOfKind() answers the tickets issuedList() ' +
          'would, in its order', String(tickets.length));
  log.debug("Leaving body().");
}

module.exports = {
  name: 'users_page_before_decoration',
  describe: '/admin/users, /admin-api/users and /admin-api/mfa page before ' +
            'they decorate (#352): mechanismsFor() per row shown, each ' +
            'sealed TOTP secret opened once per process, and the same ' +
            'answers as before',
  run: run
};
