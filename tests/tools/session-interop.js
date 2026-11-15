// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/session-interop.js
//
// ---------------------------------------------------------------------------
// NODE'S HALF OF THE SESSIONS' TWO-WAY PROOF OVER A REAL STORE (#444, phase
// 5, the `session` slice). rcbj decided on 2026-11-14 that the Rust runtime
// upgrades a 1.x install IN PLACE, so a person signed in before the upgrade
// is still signed in after it, and the reverse. `store-interop.js` holds the
// store's rows to each other field for field; this holds the SESSIONS to the
// doors that read them, through the real minted persistence of each side:
//
//   node tests/tools/session-interop.js write <dir>
//     Clears the minted tables, starts Node's keystore over the durable
//     key-encryption key in <dir>/interop-kek.txt (made when absent), signs
//     people in through `authn.ts`'s own `startSession()` — a password
//     sign-in, a step-up on it (two events), a passkey sign-in, a sign-in
//     partnered with a federation's SessionNotOnOrAfter, and one ended by its
//     sign-out (a tombstone) — and FLUSHES them with
//     `persistence_minted.js`, as a running 1.x service does. What each
//     cookie names and the row behind it go to <dir>/session-interop-node.json.
//
//   node tests/tools/session-interop.js read <dir>
//     Restores, with `persistence_minted.js`'s own restore, a store the Rust
//     runtime's minted flush wrote (<dir>/session-interop-rust.json says
//     what), and checks that each cookie Rust wrote names its session in
//     Node with its current handle, that the session is live, and that the
//     row is the row Rust wrote; and that the session Rust ended stays
//     ended. Exits 1 on a difference.
//
// The Rust half is `rust/crates/sts-authn/tests/store_interop.rs`. The
// database is STS_TEST_DATABASE_URL (PostgreSQL with `postgres/schema.sql`;
// its certificate is not verified, a throwaway container's). <dir> is never
// committed: it holds a key-encryption key.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const MODE = process.argv[2];
const DIR = process.argv[3];
const URL = process.env.STS_TEST_DATABASE_URL || '';
const KEK_FILE = DIR ? path.join(DIR, 'interop-kek.txt') : '';

if (KEK_FILE && !fs.existsSync(KEK_FILE) && MODE === 'write') {
  fs.writeFileSync(KEK_FILE, nodeCrypto.randomBytes(32).toString('base64') +
                   '\n', { mode: 0o600 });
}
process.env.STS_KEYS_SOURCE = 'persisted';
process.env.STS_KEYS_KEK_PROVIDER = 'file';
process.env.STS_KEYS_KEK_FILE = KEK_FILE;
process.env.STS_DATABASE_TLS_REJECT_UNAUTHORIZED = 'false';
process.env.STS_LOG_LEVEL = process.env.STS_LOG_LEVEL || 'fatal';

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'session-interop',
                                  level: process.env.STS_LOG_LEVEL });

// Whether `authn.multipleAccounts` is on (#561): for the browser holding
// two accounts, and for reading Rust's.
const ACCOUNTS = { on: false };

// The people the sessions are for, and their subjects.
const PEOPLE = {
  dora: '0b6f6c1e-8c55-4b8a-9b2e-3d1f0d5c2a11',
  fay: '3c9e7b55-2d8a-4e1f-9b3c-6a5d4e2f1b33',
  gil: '5e4d3c2b-1a09-4f8e-9d7c-6b5a4e3d2c55',
  emil: '7d0f2a44-1b9c-4f3e-8a6d-5c2b1e9f4d22'
};

/**
 * A browser's cookies, kept as each answer's Set-Cookie lines say.
 *
 * @returns {any} the jar
 */
function cookieJar() {
  log.debug('Entering cookieJar().');
  const held = {};
  log.debug('Leaving cookieJar().');
  return {
    take: function (res) {
      res.cookies.forEach(function (line) {
        const first = String(line).split(';')[0];
        const at = first.indexOf('=');
        if (/Max-Age=0/.test(line) || at === first.length - 1) {
          delete held[first.slice(0, at)];
        } else {
          held[first.slice(0, at)] = first.slice(at + 1);
        }
      });
    },
    header: function () {
      return Object.keys(held).map(function (k) {
        return k + '=' + held[k];
      }).join('; ');
    }
  };
}

/**
 * ONE BROWSER, TWO ACCOUNTS (#561): dora and then emil sign in in one
 * browser with `authn.multipleAccounts` on, so the second joins the set the
 * first made rather than replacing her session.
 *
 * @param {any} s - `started()`'s answer
 * @returns {any} `{ cookie, setId, sids }`
 */
function twoAccounts(s) {
  log.debug('Entering twoAccounts().');
  ACCOUNTS.on = true;
  const jar = cookieJar();
  const sids = [];
  try {
    ['dora', 'emil'].forEach(function (username) {
      const req = { headers: { 'user-agent': 'Interop/1.0',
                               cookie: jar.header() }, body: {}, url: '/' };
      const res = response(req);
      const d = { request: req, application: 'app-one',
                  credential: { kind: 'password' } };
      const session = s.authn.startSession(res, username, ['pwd'], '1',
                                           'OAuth 2.0 / OIDC', d);
      if (!session) {
        throw new Error('session-interop: ' + username + ' was refused (' +
                        d.refusedWith + ')');
      }
      sids.push(session.id);
      jar.take(res);
    });
  } finally {
    ACCOUNTS.on = false;
  }
  const setId = String(s.authn.sessions.get(sids[0]).accountSetId || '');
  log.debug('Leaving twoAccounts().');
  return { cookie: jar.header(), setId: setId, sids: sids };
}

/**
 * What a browser's set says to Node's doors: the set its cookie opens, the
 * accounts listed, and who the request acts as with no hint and with each
 * account's name as one.
 *
 * @param {any} s - `started()`'s answer
 * @param {any} browser - `{ cookie, set, sids }`
 * @param {string[]} failures - where a difference is written
 */
function holdBrowser(s, browser, failures) {
  log.debug('Entering holdBrowser().');
  const AccountSets = require(path.join(ROOT, 'authn', 'account_sets.js'));
  ACCOUNTS.on = true;
  try {
    const req = function () {
      return { headers: { cookie: browser.cookie }, url: '/' };
    };
    const opened = AccountSets.setOf(s.authn.cookiesOf(req()));
    if (!opened || opened.id !== browser.set.id) {
      failures.push('the browser\'s sts_accounts cookie opens no set');
      return;
    }
    if (JSON.stringify(opened) !== JSON.stringify(browser.set)) {
      failures.push('the account set: Node read ' + JSON.stringify(opened) +
                    ', the other side wrote ' + JSON.stringify(browser.set));
    }
    const listed = s.authn.browserAccounts(req());
    const live = (listed.accounts || []).filter(function (a) {
      return a.state === 'signed-in';
    }).length;
    if (live !== browser.sids.length) {
      failures.push('browserAccounts() lists ' + live + ' signed-in, not ' +
                    browser.sids.length);
    }
    if (s.authn.sessionOf(req())) {
      failures.push('sessionOf() chose an account where nothing chose one');
    }
    browser.sids.forEach(function (sid) {
      const r = req();
      const name = s.authn.sessions.get(sid).user.username;
      s.authn.hintAccount(r, { loginHint: name });
      const chosen = s.authn.sessionOf(r);
      if (!chosen || chosen.id !== sid) {
        failures.push('a hint naming ' + name + ' does not choose ' + sid);
      }
    });
  } finally {
    ACCOUNTS.on = false;
  }
  log.debug('Leaving holdBrowser().');
}

/**
 * A query against the store, outside the driver.
 *
 * @param {string} sql - the statement
 * @returns {Promise<any>} the result
 */
async function raw(sql) {
  log.debug('Entering raw().');
  const pg = require('pg');
  const client = new pg.Client({ connectionString: URL,
                                 ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const out = await client.query(sql);
    log.debug('Leaving raw().');
    return out;
  } finally {
    await client.end();
  }
}

/**
 * Node's minted persistence over the store, as `persistence.js` installs it:
 * the driver open, the keystore started over the durable key, the subject
 * resolver the directory would fill, and `persistence.minted` on.
 *
 * @returns {Promise<any>} `{ driver, keystore, minted, authn }`
 */
async function started() {
  log.debug('Entering started().');
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const realValue = config.value.bind(config);
  config.value = function (key) {
    if (key === 'persistence.minted') {
      return true;
    }
    // PRODUCT MODE: what a 1.x install that keeps its sessions runs, and
    // the arm of `persistence_minted.enabled()` that needs no cluster.
    if (key === 'global.mode') {
      return 'product';
    }
    // The key-encryption key is a file in <dir>: a throwaway one.
    if (key === 'secrets.allowLocalSecrets') {
      return true;
    }
    // Off for the sessions above, as the session slice proved them; on
    // for the one browser that holds two accounts (#561).
    if (key === 'authn.multipleAccounts') {
      return ACCOUNTS.on;
    }
    // THE FULL MAP, as the Rust runtime holds it: the window (#350) reads
    // through a store this process has not opened as `persistence.js`
    // would, and what is proved here is the rows, not the window.
    if (key === 'authn.sessionWindow') {
      return 'off';
    }
    return realValue.apply(null, arguments);
  };
  const realProcess = config.processValue.bind(config);
  config.processValue = function (key) {
    if (key === 'authn.sessionWindow') {
      return 'off';
    }
    return realProcess.apply(null, arguments);
  };
  const helpers = require(path.join(ROOT, 'common', 'helpers.js'));
  helpers.setSubjectResolver({
    subjectFor: function (name) {
      return PEOPLE[String(name)] ? 'urn:uuid:' + PEOPLE[String(name)] : '';
    },
    nameFor: function (sub) {
      const id = String(sub || '').replace(/^urn:uuid:/i, '');
      return Object.keys(PEOPLE).filter(function (n) {
        return PEOPLE[n] === id;
      })[0] || '';
    }
  });
  const driver = require(path.join(ROOT, 'persistence',
                                   'persistence_postgres.js'))
    .create({ url: URL, log: log, engine: 'postgres' });
  await driver.open();
  const keystore = require(path.join(ROOT, 'common', 'keystore.js'));
  keystore.setStore(driver);
  await keystore.start();
  const authn = require(path.join(ROOT, 'authn', 'authn.js'));
  const minted = require(path.join(ROOT, 'persistence',
                                   'persistence_minted.js'));
  minted.setDriver(driver, 'postgres');
  log.debug('Leaving started().');
  return { driver: driver, keystore: keystore, minted: minted, authn: authn };
}

/**
 * A response the sign-in doors write their cookie on.
 *
 * @param {any} req - the request it answers
 * @returns {any} the response
 */
function response(req) {
  return { req: req, cookies: [], locals: {},
           set: function (k, v) {
             this.cookies = [v];
           },
           append: function (k, v) {
             this.cookies.push(v);
           } };
}

/**
 * The `<sid>.<handle>` a response's sign-on cookie carries.
 *
 * @param {any} res - the response
 * @returns {string} the value, or ''
 */
function cookieOf(res) {
  const line = res.cookies.filter(function (l) {
    return /^sts_session=[^;]/.test(l);
  }).pop();
  return line ? line.split(';')[0].slice('sts_session='.length) : '';
}

/**
 * Signs people in through `startSession()` and flushes their sessions.
 *
 * @returns {Promise<void>}
 */
async function write() {
  log.debug('Entering write().');
  for (const table of ['sts_minted', 'sts_minted_index', 'sts_sessions',
                       'sts_changes', 'sts_keys']) {
    await raw('DELETE FROM ' + table);
  }
  const s = await started();
  const now = Date.now();
  const request = function (cookie) {
    return { headers: Object.assign({ 'user-agent': 'Interop/1.0' },
                                    cookie ? { cookie: 'sts_session=' +
                                                       cookie } : {}),
             body: {} };
  };
  const start = function (username, amr, acr, via, detail, cookie) {
    const req = request(cookie);
    const res = response(req);
    const d = Object.assign({ request: req }, detail);
    const session = s.authn.startSession(res, username, amr, acr, via, d);
    if (!session) {
      throw new Error('session-interop: the sign-in of ' + username +
                      ' was refused (' + d.refusedWith + '): ' +
                      (d.refusedWhy || ''));
    }
    return { session: session, cookie: cookieOf(res) || cookie };
  };
  const out = [];
  const dora = start('dora', ['pwd'], '1', 'OAuth 2.0 / OIDC',
                     { application: 'app-one',
                       credential: { kind: 'password' } });
  const up = start('dora', ['pwd', 'otp'], 'mfa', 'OAuth 2.0 / OIDC',
                   { application: 'app-two', credential: { kind: 'totp' } },
                   dora.cookie);
  out.push({ name: 'a password sign-in stepped up', cookie: up.cookie,
             sid: up.session.id });
  const fay = start('fay', ['hwk', 'user'], 'mfa', 'OAuth 2.0 / OIDC',
                    { application: 'app-one',
                      credential: { kind: 'webauthn', id: 'cred-fay',
                                    ceremony: 'assertion',
                                    backupEligible: false,
                                    attestationTrusted: true,
                                    algorithm: 'ES256', coseAlg: -7,
                                    lane: 'classical' } });
  out.push({ name: 'a passkey sign-in', cookie: fay.cookie,
             sid: fay.session.id });
  const gil = start('gil', ['pwd'], '1', 'SAML 2.0',
                    { application: 'sp-one',
                      credential: { kind: 'federation', relationship: 'p1' },
                      federation: { id: 'p1', peer: 'https://idp.example',
                                    subject: 'g-1' },
                      fedPartnerSession: { relationship: 'p1',
                                           sessionIndex: 'idx-1' },
                      sessionNotOnOrAfter: now + 20 * 60 * 1000 });
  out.push({ name: 'a federated sign-in, bounded by its partner',
             cookie: gil.cookie, sid: gil.session.id });
  const gone = start('gil', ['pwd'], '1', 'OAuth 2.0 / OIDC',
                     { application: 'app-one',
                       credential: { kind: 'password' } });
  s.authn.endSessionById(gone.session.id, 'the interop proof', 'admin');
  const two = twoAccounts(s);
  await s.minted.flush();
  await s.keystore.settleAll();
  const sessions = out.map(function (one) {
    return Object.assign({}, one, {
      row: JSON.parse(JSON.stringify(s.authn.sessions.get(one.sid))) });
  });
  const counted = await raw('SELECT count(*) AS n FROM sts_sessions');
  fs.writeFileSync(path.join(DIR, 'session-interop-node.json'),
    JSON.stringify({ now: now, sessions: sessions,
                     ended: gone.session.id,
                     browser: { cookie: two.cookie, sids: two.sids,
                                set: require(path.join(ROOT, 'authn',
                                  'account_sets.js')).byId(two.setId),
                                rows: two.sids.map(function (sid) {
                                  return JSON.parse(JSON.stringify(
                                    s.authn.sessions.get(sid)));
                                }) },
                     sessionIndexRows: Number(counted.rows[0].n) }, null, 1) +
    '\n');
  await s.driver.close();
  console.log('session-interop: Node signed in ' + sessions.length +
              ' session(s), ended one, and flushed them (' +
              counted.rows[0].n + ' sts_sessions rows).');
  log.debug('Leaving write().');
}

/**
 * Restores what the Rust runtime flushed and holds Node's doors to it.
 *
 * @returns {Promise<void>}
 */
async function read() {
  log.debug('Entering read().');
  const v = JSON.parse(fs.readFileSync(path.join(DIR,
    'session-interop-rust.json'), 'utf8'));
  const s = await started();
  await s.minted.restore();
  const failures = [];
  const realNow = Date.now;
  Date.now = function () {
    return Number(v.now);
  };
  try {
    v.sessions.forEach(function (one) {
      const found = s.authn.cookieSession(
        { headers: { cookie: 'sts_session=' + one.cookie } }, 'sts_session');
      if (!found || found.id !== one.sid) {
        failures.push(one.name + ': the cookie Rust wrote names no session ' +
                      'in Node');
        return;
      }
      if (JSON.stringify(found.session) !== JSON.stringify(one.row)) {
        failures.push(one.name + ': Node restored ' +
                      JSON.stringify(found.session) + ', Rust wrote ' +
                      JSON.stringify(one.row));
      }
      if (s.authn.sessionEnded(found.session) !== '') {
        failures.push(one.name + ': Node reads the session as ended (' +
                      s.authn.sessionEnded(found.session) + ')');
      }
      const live = s.authn.sessionOf({ headers: { cookie: 'sts_session=' +
                                                          one.cookie } });
      if (!live || live.id !== one.sid) {
        failures.push(one.name + ': sessionOf() does not honour it');
      }
    });
    if (v.ended && s.authn.sessions.get(v.ended)) {
      failures.push('the session Rust ended came back in Node');
    }
    if (v.browser) {
      holdBrowser(s, v.browser, failures);
    } else {
      failures.push('Rust wrote no browser with two accounts');
    }
  } finally {
    Date.now = realNow;
  }
  await s.driver.close();
  if (failures.length) {
    console.error('session-interop: ' + failures.length + ' difference(s):\n' +
                  failures.join('\n'));
    process.exitCode = 1;
  } else {
    console.log('session-interop: Node honours all ' + v.sessions.length +
                ' session(s) the Rust runtime flushed, and the one it ended ' +
                'stays ended.');
  }
  log.debug('Leaving read().');
}

if (require.main === module) {
  if (!URL || !DIR || (MODE !== 'write' && MODE !== 'read')) {
    console.error('usage: STS_TEST_DATABASE_URL=… node ' +
                  'tests/tools/session-interop.js write|read <dir>');
    process.exit(2);
  }
  (MODE === 'write' ? write() : read()).catch(function (e) {
    console.error(e);
    process.exitCode = 1;
  });
}
