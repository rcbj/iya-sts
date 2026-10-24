// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: session_window.js
//
// authn.sessionWindow defaults to auto (#350). Without minted persistence
// the full map stays. A miss loads a sealed session. Eviction forgets the
// memory copy after the commit and does not end the session. A read error
// is not absence. A failed index read is unread, not an empty list and
// not the rows still in the cache. A child whose own children read
// fails leaves that child and the sign-on in place.

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const cells = require('../common/cells');
const stsCrypto = require('../common/crypto');
const minted = require('../persistence/persistence_minted');
const tiers = require('../persistence/tiers');
const authn = require('../authn/authn');
const sessionWindow = require('../authn/session_window');
const scheduler = require('../cluster/scheduler');

const log = require('bunyan').createLogger({ name: 'session_window',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'session-window';
const TOMBSTONE = '$tombstone$1';

const answer = { read: null, load: [], filter: null };
const captured = { upserts: [], deletes: [] };
let queryFn = function () {
  log.debug("Entering queryFn().");
  log.debug("Leaving queryFn().");
  return null;
};

function emptyAnswer(name) {
  log.debug("Entering emptyAnswer().");
  let out = [];
  if (name === 'session.exists') {
    out = { hit: false };
  } else if (name === 'session.count') {
    out = { n: 0 };
  } else if (name === 'session.read') {
    out = null;
  }
  log.debug("Leaving emptyAnswer().");
  return out;
}

function installQuery() {
  log.debug("Entering installQuery().");
  sessionWindow.setQuery(function (name, args) {
    return queryFn(name, args);
  });
  log.debug("Leaving installQuery().");
}

function freshWindow() {
  log.debug("Entering freshWindow().");
  sessionWindow.resetForTests();
  installQuery();
  queryFn = function (name) {
    return emptyAnswer(name);
  };
  answer.read = null;
  answer.load = [];
  log.debug("Leaving freshWindow().");
}

function sidDigest(sid) {
  log.debug("Entering sidDigest().");
  const digest = keystore.keyedDigest('minted-key',
    'authn.sessions\n' + REALM + '\n' + sid);
  log.debug("Leaving sidDigest().");
  return digest;
}

function hashOf(handle) {
  log.debug("Entering hashOf().");
  const hash = stsCrypto.digest('sha256', String(handle), 'base64url');
  log.debug("Leaving hashOf().");
  return hash;
}

function sessionBody(id, over) {
  log.debug("Entering sessionBody().");
  const row = {
    id: id,
    user: { username: id, sub: '' },
    subjectId: id,
    chosen: true,
    authenticated: true,
    authTime: 1,
    lastSeenAt: 1000,
    startedAt: 500,
    expires: Date.now() + 3600000,
    amr: [],
    acr: '1',
    via: 'Test'
  };
  log.debug("Leaving sessionBody().");
  return Object.assign(row, over || {});
}

function sealSession(value) {
  log.debug("Entering sealSession().");
  const sealed = keystore.seal(JSON.stringify(value), 'minted-rows',
                                tiers.mintedTierOf('authn.sessions'),
                                { realm: REALM });
  log.debug("Leaving sealSession().");
  return sealed;
}

function changeKey(sid) {
  log.debug("Entering changeKey().");
  const key = Buffer.from('authn.sessions').toString('base64url') + '.' +
    Buffer.from(sid).toString('base64url');
  log.debug("Leaving changeKey().");
  return key;
}

function audits(action, target, code) {
  log.debug("Entering audits().");
  const rows = audit.list().filter(function (row) {
    if (action && row.action !== action) {
      return false;
    }
    if (target && row.target !== target) {
      return false;
    }
    if (code && row.errorCode !== code) {
      return false;
    }
    return true;
  });
  log.debug("Leaving audits().");
  return rows;
}

function deletesOf(journalKey) {
  log.debug("Entering deletesOf().");
  const rows = captured.deletes.filter(function (row) {
    return row.journalKey === journalKey;
  });
  log.debug("Leaving deletesOf().");
  return rows;
}

function upsertsOf(journalKey) {
  log.debug("Entering upsertsOf().");
  const rows = captured.upserts.filter(function (row) {
    return row.journalKey === journalKey;
  });
  log.debug("Leaving upsertsOf().");
  return rows;
}

function signIn(username, extra) {
  log.debug("Entering signIn().");
  const session = authn.startSession({ set: function () {} },
                                     username, ['pwd'], '1', 'Test', extra);
  log.debug("Leaving signIn().");
  return session;
}

function clearSessions() {
  log.debug("Entering clearSessions().");
  const ids = [];
  // The facade pages the index while the window is on. This wants the
  // rows this process actually holds, including ones the index stub
  // never named.
  authn.sessions.realmMap().forEach(function (session, id) {
    ids.push(id);
  });
  ids.forEach(function (id) {
    authn.sessions.delete(id);
  });
  log.debug("Leaving clearSessions().");
}

// Production code outside authn/authn.ts that still forEachs the session
// store. While the window is on that map is a cache. A new hit is a walk
// that can treat the cache as the whole store.
function productionSessionWalks() {
  log.debug("Entering productionSessionWalks().");
  const root = path.join(__dirname, '..');
  const skip = new RegExp('(^|/)(node_modules|tests|coverage|' +
    'debugger/embedded|common/crypto_impl|node-ldapjs|deploy|xacml-pep|' +
    'docs|\\.claude|types|companion)(/|$)');
  const hits = [];
  function strip(text) {
    log.debug("Entering strip().");
    const out = String(text).replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:\\])\/\/.*$/gm, '$1');
    log.debug("Leaving strip().");
    return out;
  }
  function walk(dir) {
    log.debug("Entering walk().");
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      log.debug("Caught in walk(): " + ((e && e.message) || e));
      log.debug("Leaving walk().");
      return;
    }
    entries.forEach(function (entry) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (skip.test(rel) || rel === 'authn/authn.ts') {
        return;
      }
      if (entry.isDirectory()) {
        walk(full);
        return;
      }
      if (!/\.(js|ts)$/.test(entry.name) || /\.d\.ts$/.test(entry.name)) {
        return;
      }
      if (/\.js$/.test(entry.name) &&
          fs.existsSync(full.replace(/\.js$/, '.ts'))) {
        return;
      }
      let text = '';
      try {
        text = fs.readFileSync(full, 'utf8');
      } catch (e) {
        log.debug("Caught in walk(): " + ((e && e.message) || e));
        return;
      }
      const source = strip(text);
      if (/authn\.sessions\s*\.\s*forEach\s*\(/.test(source)) {
        hits.push(rel);
      }
      // The console list used to walk the injected map under this name.
      if (rel === 'admin-core/admin_views.ts' &&
          /\bsessions\.forEach\s*\(/.test(source)) {
        hits.push(rel + ':sessions');
      }
    });
    log.debug("Leaving walk().");
  }
  walk(root);
  log.debug("Leaving productionSessionWalks().");
  return hits;
}

function cacheEntries(n) {
  log.debug("Entering cacheEntries().");
  config.setOverride('authn.sessionCacheEntries', String(n));
  log.debug("Leaving cacheEntries().");
}

// The window is restart-only, so a test sets the process environment
// rather than a runtime override. Cache size and the read timeout stay
// overridable; they are still the process value.
function runSweep() {
  log.debug("Entering runSweep().");
  const job = scheduler.job('authn.session-expiry');
  const result = job.run({
    realm: REALM, runId: 'window-shed', trigger: 'manual',
    params: null,
    stillOwner: function () {
      return true;
    },
    nowMs: function () {
      return Date.now();
    },
    log: log
  });
  log.debug("Leaving runSweep().");
  return result;
}

function windowSetting(raw) {
  log.debug("Entering windowSetting().");
  if (raw === undefined || raw === null) {
    delete process.env.STS_AUTHN_SESSION_WINDOW;
  } else {
    process.env.STS_AUTHN_SESSION_WINDOW = String(raw);
  }
  log.debug("Leaving windowSetting().");
}

function stubDriver() {
  log.debug("Entering stubDriver().");
  log.debug("Leaving stubDriver().");
  return {
    loadMinted: function (filter) {
      log.debug("Entering loadMinted().");
      answer.filter = filter;
      log.debug("Leaving loadMinted().");
      return Promise.resolve(answer.load || []);
    },
    readMinted: function () {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(answer.read);
    },
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'session-window-origin';
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      (upserts || []).forEach(function (row) {
        captured.upserts.push({
          journalKey: row.journalKey,
          realm: row.realm,
          key: row.key,
          body: row.body,
          tombstone: row.tombstone
        });
      });
      (deletes || []).forEach(function (row) {
        captured.deletes.push({
          journalKey: row.journalKey,
          realm: row.realm,
          key: row.key,
          body: row.body,
          tombstone: row.tombstone
        });
      });
      log.debug("Leaving saveMinted().");
      return Promise.resolve({ refused: [], merged: [] });
    }
  };
}

function installDriver() {
  log.debug("Entering installDriver().");
  minted.reset();
  minted.endPrefetch();
  const ok = minted.setDriver(stubDriver(), 'postgres');
  log.debug("Leaving installDriver().");
  return ok;
}

function thrownMessage(fn) {
  log.debug("Entering thrownMessage().");
  let message = '';
  try {
    fn();
  } catch (e) {
    log.debug("Caught in thrownMessage(): " + ((e && e.message) || e));
    message = String((e && e.message) || e);
  }
  log.debug("Leaving thrownMessage().");
  return message;
}

function loggedLines(code, fn) {
  log.debug("Entering loggedLines().");
  const lines = [];
  const stdout = process.stdout.write;
  const stderr = process.stderr.write;
  function wrap(orig) {
    log.debug("Entering wrap().");
    log.debug("Leaving wrap().");
    return function (chunk, enc, cb) {
      const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8')
                                           : String(chunk);
      if (text.indexOf(code) >= 0) {
        lines.push(text);
      }
      return orig.call(this, chunk, enc, cb);
    };
  }
  process.stdout.write = wrap(stdout);
  process.stderr.write = wrap(stderr);
  try {
    fn();
  } finally {
    process.stdout.write = stdout;
    process.stderr.write = stderr;
  }
  log.debug("Leaving loggedLines().");
  return lines;
}

function offCase(t) {
  log.debug("Entering offCase().");
  t.log.info('off: a second subject at the cap is refused, and the first ' +
             'stays');
  config.setOverride('authn.maxSessions', '1');
  try {
    const alice = signIn('win-alice');
    const detail = {};
    const bob = signIn('win-bob', detail);
    t.check(!!alice && !!alice.id, 'Alice receives a session while the ' +
            'window is off');
    t.equal(bob, null, 'Bob is refused at a cap of one');
    t.equal(detail.refusedWith, 'STS-AUTHN-0337',
            'the refusal is the realm cap');
    t.check(!!alice && !!authn.sessions.get(alice.id),
            'Alice stays — a flood still cannot end another subject');
    t.equal(alice ? audits('session.end', alice.id).length : 1, 0,
            'Alice has no session.end row');
    t.equal(sessionWindow.active(), false,
            'auto without minted persistence does not turn the window on');
  } finally {
    config.clearOverride('authn.maxSessions');
    clearSessions();
  }
  log.debug("Leaving offCase().");
}

async function evictionCase(t) {
  log.debug("Entering evictionCase().");
  t.log.info('on: eviction after a committed upsert forgets memory only');
  freshWindow();
  cacheEntries(1);
  const first = sessionBody('win-a', { lastSeenAt: 10, startedAt: 10 });
  authn.sessions.set(first.id, first);
  await minted.flush();
  t.check(upsertsOf('win-a').length >= 1,
          'the committed upsert wrote the session');
  t.check(upsertsOf('win-a').every(function (row) {
    return row.body !== TOMBSTONE;
  }), 'that upsert is not a tombstone');
  t.equal(deletesOf('win-a').length, 0,
          'the commit did not delete the row');
  t.check(!!authn.sessions.get('win-a'),
          'a commit inside the bound leaves the body in the map');
  t.equal(sessionWindow.slotState(REALM, 'win-a').cached, true,
          'and the slot stays cached');
  const second = sessionBody('win-b', { lastSeenAt: 20, startedAt: 20 });
  authn.sessions.set(second.id, second);
  t.equal(authn.sessions.get('win-a'), undefined,
          'eviction drops the memory copy');
  t.equal(sessionWindow.slotState(REALM, 'win-a').cached, false,
          'the evicted id is not cached');
  t.equal(audits('session.end', 'win-a').length, 0,
          'eviction writes no session.end');
  t.equal(audits(null, 'win-a', 'STS-AUTHN-0292').length, 0,
          'eviction writes no STS-AUTHN-0292');
  await minted.flush();
  t.equal(deletesOf('win-a').length, 0,
          'the later commit does not tombstone the evicted session');
  t.equal(authn.sessions.get('win-a'), undefined,
          'the map still does not hold the evicted body');
  cacheEntries(10000);
  log.debug("Leaving evictionCase().");
}

async function floodCase(t) {
  log.debug("Entering floodCase().");
  t.log.info('on: unknown ids do not evict a cached live session');
  freshWindow();
  cacheEntries(1);
  const live = sessionBody('flood-live', { lastSeenAt: 30, startedAt: 30 });
  authn.sessions.set(live.id, live);
  await minted.flush();
  t.equal(sessionWindow.slotState(REALM, 'flood-live').cached, true,
          'the live session is cached after its commit');
  let absent = 0;
  for (let i = 0; i < 2000; i++) {
    const got = sessionWindow.get(REALM, 'flood-' + i);
    if (got && got.ok === false && got.absent === true) {
      absent += 1;
    }
  }
  t.equal(absent, 2000, 'each unknown id is absence');
  t.equal(sessionWindow.slotState(REALM, 'flood-live').cached, true,
          'the live session is still cached');
  const again = sessionWindow.get(REALM, 'flood-live');
  t.equal(again.ok, true, 'and it still loads');
  t.equal(again.session && again.session.id, 'flood-live',
          'it is the same session');
  cacheEntries(10000);
  log.debug("Leaving floodCase().");
}

function timeoutCase(t) {
  log.debug("Entering timeoutCase().");
  t.log.info('on: a read timeout cools the next miss');
  freshWindow();
  let reads = 0;
  queryFn = function (name) {
    if (name === 'session.read') {
      reads += 1;
      throw new Error('timeout');
    }
    return emptyAnswer(name);
  };
  const first = sessionWindow.get(REALM, 'cool-1');
  const second = sessionWindow.get(REALM, 'cool-2');
  t.equal(first.ok, false, 'the timed-out read is not a session');
  t.equal(first.error, true, 'it is the typed error');
  t.equal(second.error, true, 'the next miss is still an error');
  t.equal(reads, 1, 'the cooled miss does not call the bridge');
  const held = sessionBody('cool-held');
  authn.sessions.set(held.id, held);
  const during = sessionWindow.get(REALM, 'cool-held');
  t.equal(during.ok, true, 'a session already in the map still loads');
  t.equal(reads, 1, 'that hit does not call the bridge either');
  log.debug("Leaving timeoutCase().");
}

// warmAsync() (2026-10-21, #820): a session a refresh is about to read is
// admitted off the event loop, unless something touched it meanwhile.
async function warmCase(t) {
  log.debug("Entering warmCase().");
  t.log.info('on: a session warmed ahead of a read is admitted');
  freshWindow();
  let reads = 0;
  queryFn = function (name, args) {
    if (name === 'session.read') {
      reads += 1;
      if (args && args[1] === sidDigest('warm-touched')) {
        sessionWindow.considerApply(REALM, 'warm-touched',
                                    sessionBody('warm-touched'), false);
        return { body: sealSession(sessionBody('warm-touched')) };
      }
      if (args && args[1] === sidDigest('warm-s1')) {
        return { body: sealSession(sessionBody('warm-s1')) };
      }
    }
    return emptyAnswer(name);
  };
  const admitted = await sessionWindow.warmAsync(REALM, 'warm-s1');
  const before = reads;
  const read = sessionWindow.get(REALM, 'warm-s1');
  t.check(admitted && read.ok && read.session.id === 'warm-s1' &&
          before === 1 && reads === 1,
          'a warmed session is admitted, and its get() reads nothing more',
          JSON.stringify({ admitted: admitted, reads: reads }));
  const touched = await sessionWindow.warmAsync(REALM, 'warm-touched');
  t.check(!touched,
          'one changed while its read was out is not admitted from it');
  log.debug("Leaving warmCase().");
}

function middlewareCase(t) {
  log.debug("Entering middlewareCase().");
  t.log.info('on: an unread cookie is 503 and the cookie stays');
  freshWindow();
  queryFn = function (name) {
    if (name === 'session.read') {
      throw new Error('unread cookie');
    }
    return emptyAnswer(name);
  };
  const uses = [];
  const app = new Proxy({}, {
    get: function (_target, prop) {
      if (prop === 'use') {
        return function () {
          for (let i = 0; i < arguments.length; i++) {
            if (typeof arguments[i] === 'function') {
              uses.push(arguments[i]);
            }
          }
        };
      }
      return function () {};
    }
  });
  authn.registerRoutes(app);
  t.check(uses.length >= 1, 'the cookie middleware is registered');
  let nextCalled = false;
  let statusCode = 0;
  let body = null;
  const headers = {};
  const res = {
    headersSent: false,
    setHeader: function (name, value) {
      headers[name] = value;
    },
    status: function (code) {
      statusCode = code;
      return {
        json: function (payload) {
          body = payload;
        }
      };
    }
  };
  const req = {
    headers: { cookie: 'sts_session=unknownsid.handle' },
    url: '/oauth2/authorize'
  };
  // EVERY MIDDLEWARE authn registers, in order, each one's next() the
  // following one's: since #561 the account-selection ticket's middleware
  // runs before the cookie's, so the cookie's is no longer uses[0].
  const runFrom = function (i) {
    log.debug("Entering runFrom().");
    if (i >= uses.length) {
      nextCalled = true;
      log.debug("Leaving runFrom(). Past the last.");
      return;
    }
    uses[i](req, res, function () {
      runFrom(i + 1);
    });
    log.debug("Leaving runFrom().");
  };
  runFrom(0);
  t.equal(statusCode, 503, 'the middleware answers 503');
  t.equal(headers['Retry-After'], '5', 'Retry-After is set');
  t.equal(headers['Cache-Control'], 'no-store', 'the answer is not stored');
  t.equal(body && body.error, 'unavailable', 'the body names unavailable');
  t.equal(JSON.stringify(body || {}).indexOf('STS-AUTHN'), -1,
          'the code is not in the body');
  t.equal(errorCodes.codeOf(res), 'STS-AUTHN-0338',
          'the code is marked on the response');
  t.equal(nextCalled, false, 'no later handler runs');
  t.equal(headers['Set-Cookie'], undefined, 'the cookie is not cleared');
  log.debug("Leaving middlewareCase().");
}

function parentCase(t) {
  log.debug("Entering parentCase().");
  t.log.info('on: a parent read error does not end the child');
  freshWindow();
  const handle = 'child-handle-window-test-1';
  const child = sessionBody('child-window', {
    handleHash: hashOf(handle),
    derivedFrom: 'parent-window',
    user: { username: 'alice' },
    subjectId: 'alice'
  });
  authn.sessions.set(child.id, child);
  const parentDigest = sidDigest('parent-window');
  let parentReads = 0;
  queryFn = function (name, args) {
    if (name === 'session.read' && args && args[1] === parentDigest) {
      parentReads += 1;
      throw new Error('parent unread');
    }
    return emptyAnswer(name);
  };
  const req = {
    headers: { cookie: 'sts_portal=' + child.id + '.' + handle },
    url: '/portal'
  };
  const found = authn.relyingPartySessionOf(req, 'sts_portal', REALM);
  t.equal(found, null, 'the child is not honoured while the parent is ' +
          'unread');
  t.check(parentReads >= 1, 'the parent was read, and the read failed');
  t.check(!!authn.sessions.get(child.id), 'the child is still stored');
  t.equal(audits('session.end', child.id).length, 0,
          'the child has no session.end row');
  log.debug("Leaving parentCase().");
}

async function dropErrorCase(t) {
  log.debug("Entering dropErrorCase().");
  t.log.info('on: dropSession of a read error does not delete');
  freshWindow();
  queryFn = function (name) {
    if (name === 'session.read') {
      throw new Error('drop unread');
    }
    return emptyAnswer(name);
  };
  const ended = authn.endSessionById('unread-window', 'a test sign-out');
  t.equal(ended, null, 'an unread session is not ended');
  await minted.flush();
  t.equal(deletesOf('unread-window').length, 0,
          'the unread id is not deleted');
  t.equal(audits('session.end', 'unread-window', 'STS-AUTHN-0011').length, 0,
          'STS-AUTHN-0011 is not audited');
  t.equal(audits('session.end', 'unread-window').length, 0,
          'there is no session.end row either');
  log.debug("Leaving dropErrorCase().");
}

function cascadeCase(t) {
  log.debug("Entering cascadeCase().");
  t.log.info('on: a session that exists only in the stub is ended, with ' +
             'its child');
  freshWindow();
  const parent = sessionBody('stub-parent', {
    user: { username: 'alice' },
    subjectId: 'alice'
  });
  const child = sessionBody('stub-child', {
    user: { username: 'alice' },
    subjectId: 'alice',
    derivedFrom: 'stub-parent',
    derivedFromRealm: REALM
  });
  const parentDigest = sidDigest('stub-parent');
  const childDigest = sidDigest('stub-child');
  const parentKey = keystore.keyedDigest('session-parent', 'stub-parent');
  queryFn = function (name, args) {
    if (name === 'session.read') {
      if (args && args[1] === parentDigest) {
        return { session: parent };
      }
      if (args && args[1] === childDigest) {
        return { session: child };
      }
      return null;
    }
    if (name === 'session.children' && args && args[1] === parentKey) {
      return [childDigest];
    }
    return emptyAnswer(name);
  };
  t.equal(authn.sessions.get('stub-parent'), undefined,
          'the parent starts outside this process\'s map');
  t.equal(authn.sessions.get('stub-child'), undefined,
          'and so does the child');
  const ended = authn.endSessionById('stub-parent', 'a test sign-out');
  t.equal(ended && ended.id, 'stub-parent', 'the parent is ended');
  const parentRows = audits('session.end', 'stub-parent');
  t.check(parentRows.some(function (row) {
    return row.outcome === 'success' && row.errorCode !== 'STS-AUTHN-0011';
  }), 'the parent audit is a successful end, not STS-AUTHN-0011');
  const childRows = audits('session.end', 'stub-child');
  t.check(childRows.some(function (row) {
    return row.outcome === 'success';
  }), 'the child is ended with the parent');
  log.debug("Leaving cascadeCase().");
}

async function tombstoneCase(t) {
  log.debug("Entering tombstoneCase().");
  t.log.info('on: a tombstone apply drops the slot and records absence');
  freshWindow();
  const row = sessionBody('tomb-window', { lastSeenAt: 50, startedAt: 40 });
  authn.sessions.set(row.id, row);
  t.equal(sessionWindow.slotState(REALM, row.id).pinned, true,
          'the local write is pinned');
  answer.read = null;
  const applied = await minted.applyChange({
    key: changeKey(row.id), realm: REALM
  });
  t.equal(applied, true, 'the tombstone change is applied');
  const state = sessionWindow.slotState(REALM, row.id);
  t.equal(state.cached, false, 'the positive slot is gone');
  t.equal(state.pinned, false, 'the pin is gone');
  t.equal(state.negative, true, 'the absence is recorded');
  t.equal(sessionWindow.has(REALM, row.id), 'absent',
          'membership is absence');
  t.equal(authn.sessions.get(row.id), undefined,
          'the map does not hold the tombstone');
  log.debug("Leaving tombstoneCase().");
}

async function dirtyCase(t) {
  log.debug("Entering dirtyCase().");
  t.log.info('on: a dirty pin keeps this process\'s object');
  freshWindow();
  const local = sessionBody('dirty-window', { lastSeenAt: 111 });
  authn.sessions.set(local.id, local);
  const remote = sessionBody('dirty-window', { lastSeenAt: 999 });
  const sealed = sealSession(remote);
  const opened = keystore.open(sealed, 'minted-rows');
  t.equal(opened && JSON.parse(opened).lastSeenAt, 999,
          'the remote body opens to the other lastSeenAt');
  answer.read = { body: sealed };
  const applied = await minted.applyChange({
    key: changeKey(local.id), realm: REALM
  });
  t.equal(applied, true, 'the live change is applied');
  t.equal((authn.sessions.get('dirty-window') || {}).lastSeenAt, 111,
          'the map keeps this process\'s lastSeenAt');
  const held = sessionWindow.get(REALM, 'dirty-window');
  t.equal(held.ok && held.session.lastSeenAt, 111,
          'the window keeps this process\'s object');
  log.debug("Leaving dirtyCase().");
}

async function restoreCase(t) {
  log.debug("Entering restoreCase().");
  t.log.info('on: restore does not load session bodies');
  freshWindow();
  const skipped = sessionBody('should-skip', { lastSeenAt: 7, startedAt: 7 });
  const pending = { id: 'pend-window', expires: Date.now() + 60000 };
  answer.load = [
    {
      handle: 'authn.sessions',
      realm: REALM,
      key: 'should-skip',
      body: sealSession(skipped)
    },
    {
      handle: 'authn.pending',
      realm: REALM,
      key: 'pend-window',
      body: keystore.seal(JSON.stringify(pending), 'minted-rows',
                          tiers.mintedTierOf('authn.pending'),
                          { realm: REALM })
    }
  ];
  await minted.restore();
  const skippedHandles = (answer.filter && answer.filter.skipHandles) || [];
  t.check(skippedHandles.indexOf('authn.sessions') >= 0,
          'restore is asked to skip authn.sessions');
  const restored = realms.handleFor('authn.pending').read(REALM,
                                                           'pend-window');
  t.check(!!(restored && restored.present),
          'a non-session row is restored');
  t.equal(authn.sessions.get('should-skip'), undefined,
          'the session body is not loaded');
  t.equal(sessionWindow.slotState(REALM, 'should-skip').cached, false,
          'and it is not admitted to the window');
  log.debug("Leaving restoreCase().");
}

function upgradeCase(t) {
  log.debug("Entering upgradeCase().");
  t.log.info('on: an arrival that is not in the map still upgrades at ' +
             'the cap');
  freshWindow();
  config.setOverride('authn.maxSessions', '2');
  try {
    const alice = sessionBody('cap-alice', {
      user: { username: 'cap-alice' },
      subjectId: 'cap-alice',
      lastSeenAt: 100,
      startedAt: 100
    });
    const bob = sessionBody('cap-bob', {
      user: { username: 'cap-bob' },
      subjectId: 'cap-bob',
      lastSeenAt: 200,
      startedAt: 200
    });
    authn.sessions.set(alice.id, alice);
    authn.sessions.set(bob.id, bob);
    const arrivalId = 'arrival-upgrade';
    const handle = 'arrival-handle-window-test';
    const arrival = sessionBody(arrivalId, {
      chosen: false,
      authenticated: false,
      handleHash: hashOf(handle),
      user: { username: 'anonymous' },
      subjectId: '',
      expires: Date.now() + 3600000
    });
    const arrivalDigest = sidDigest(arrivalId);
    t.equal(authn.sessions.get(arrivalId), undefined,
            'the arrival is not in this process\'s map');
    queryFn = function (name, args) {
      if (name === 'session.read') {
        if (args && args[1] === arrivalDigest) {
          return { session: arrival };
        }
        return null;
      }
      if (name === 'session.exists') {
        return { hit: !!(args && args[1] === arrivalDigest) };
      }
      if (name === 'session.count') {
        return { n: 2 };
      }
      if (name === 'session.oldest') {
        return [];
      }
      return emptyAnswer(name);
    };
    const detail = {
      request: {
        headers: { cookie: 'sts_session=' + arrivalId + '.' + handle },
        url: '/oauth2/authorize'
      }
    };
    // AN EARLIER FILE IN THE SAME RUN MAY HAVE LOADED THE DIRECTORY (the
    // risk tests do), and in product mode a person with no entry is then
    // refused with STS-AUTHN-0180 before the cap is reached. That is not
    // what this asks, so the person is given an entry where a directory is
    // there to hold one; standalone there is none and nothing is created.
    if (require('../common/helpers').hasSubjectResolver()) {
      // Every attribute the default attribute policy (#702) requires.
      require('../ldap/ldap_server').createUser('up-alice', {
        invent: false,
        attributes: { cn: 'Up Alice', sn: 'Alice', givenName: 'Up',
                      mail: 'up-alice@session-window.example' }
      });
    }
    const session = signIn('up-alice', detail);
    t.equal(detail.refusedWith, undefined,
            'the upgrade is not refused');
    t.equal(session && session.id, arrivalId,
            'the arrival id is the session id');
    t.check(!!authn.sessions.get('cap-alice') &&
            !!authn.sessions.get('cap-bob'),
            'the two other subjects stay');
  } finally {
    config.clearOverride('authn.maxSessions');
  }
  log.debug("Leaving upgradeCase().");
}

function processSettingCase(t) {
  log.debug("Entering processSettingCase().");
  t.log.info('on: the window is the process value and is not runtime');
  t.equal(config.isPerProcess('authn.sessionWindow'), true,
          'the window is per process');
  t.equal(config.isPerProcess('authn.sessionCacheEntries'), true,
          'the cache size is per process');
  t.equal(config.isPerProcess('authn.sessionReadTimeoutMs'), true,
          'the read timeout is per process');
  const refused = config.setOverride('authn.sessionWindow', 'off');
  t.equal(refused.ok, false, 'the window cannot be changed while running');
  t.check(/cannot be changed while this service is running/.test(
    (refused.errors || [])[0] || ''),
          'the refusal says to restart', (refused.errors || [])[0]);
  t.equal(config.processValue('authn.sessionWindow'), 'on',
          'the process value stays on');
  t.equal(config.value('authn.sessionWindow'), 'on',
          'the ambient realm reads that same value');
  t.equal(sessionWindow.active(), true,
          'a realm does not turn the window off');
  cacheEntries(9);
  t.equal(config.processValue('authn.sessionCacheEntries'), 9,
          'the cache size is the process value');
  t.equal(config.value('authn.sessionCacheEntries'), 9,
          'the ambient realm does not size the cache');
  config.setOverride('authn.sessionReadTimeoutMs', '0');
  t.equal(config.processValue('authn.sessionReadTimeoutMs'), 0,
          'a wait of 0 is the process value');
  config.clearOverride('authn.sessionReadTimeoutMs');
  cacheEntries(10000);
  log.debug("Leaving processSettingCase().");
}

function zeroWaitCase(t) {
  log.debug("Entering zeroWaitCase().");
  t.log.info('on: a wait of 0 does not cool the next miss');
  freshWindow();
  config.setOverride('authn.sessionReadTimeoutMs', '0');
  let reads = 0;
  queryFn = function (name) {
    if (name === 'session.read') {
      reads += 1;
      throw new Error('timeout');
    }
    return emptyAnswer(name);
  };
  const first = sessionWindow.get(REALM, 'zero-1');
  const second = sessionWindow.get(REALM, 'zero-2');
  t.equal(first.error, true, 'the first miss is an error');
  t.equal(second.error, true, 'the next miss is an error too');
  t.equal(reads, 2, 'a wait of 0 does not cool the next miss');
  config.clearOverride('authn.sessionReadTimeoutMs');
  log.debug("Leaving zeroWaitCase().");
}

async function bridgeWaitCase(t) {
  log.debug("Entering bridgeWaitCase().");
  t.log.info('on: a session wait of 0 is not replaced with 2000');
  const SyncQuery = require('../common/sync_query');
  let wait = 0;
  const bridge = new SyncQuery({
    backend: path.join(__dirname, 'sync_query_kit.js'),
    timeoutMs: function () {
      return wait;
    },
    timeoutCode: 'STS-AUTHN-0338',
    refusedCode: 'STS-AUTHN-0338',
    threadErrorCode: 'STS-AUTHN-0338'
  });
  try {
    const started = Date.now();
    let message = '';
    let code = '';
    try {
      bridge.query('slow', [1500, 'late']);
    } catch (e) {
      log.debug("Caught in bridgeWaitCase(): " + ((e && e.message) || e));
      message = String((e && e.message) || e);
      code = errorCodes.codeOf(e);
    }
    const ms = Date.now() - started;
    t.equal(code, 'STS-AUTHN-0338', 'a wait of 0 is a read failure');
    t.check(/within 0 ms/.test(message),
            'the bound that was waited is 0', message);
    t.check(ms < 500, 'a wait of 0 does not block for 2000 ms', String(ms));
    wait = 80;
    const again = Date.now();
    let message2 = '';
    let code2 = '';
    try {
      bridge.query('slow', [1500, 'late']);
    } catch (e) {
      log.debug("Caught in bridgeWaitCase(): " + ((e && e.message) || e));
      message2 = String((e && e.message) || e);
      code2 = errorCodes.codeOf(e);
    }
    const ms2 = Date.now() - again;
    t.equal(code2, 'STS-AUTHN-0338', 'the later wait is a read failure');
    t.check(/within 80 ms/.test(message2),
            'the replaced thread waits the new bound', message2);
    t.check(ms2 >= 60 && ms2 < 500,
            'the later wait is about 80 ms, not 0 and not 2000',
            String(ms2));
  } finally {
    await bridge.stop();
  }
  log.debug("Leaving bridgeWaitCase().");
}

function cooledIndexCase(t) {
  log.debug("Entering cooledIndexCase().");
  t.log.info('on: an index failure cools the request path, not the sweep');
  freshWindow();
  let calls = 0;
  queryFn = function (name) {
    calls += 1;
    if (name === 'session.exists' || name === 'session.count' ||
        name === 'session.oldest') {
      throw new Error('index down');
    }
    return emptyAnswer(name);
  };
  const first = sessionWindow.has(REALM, 'cool-has');
  const after = calls;
  const second = sessionWindow.has(REALM, 'cool-has-2');
  const counted = sessionWindow.count(REALM);
  const rows = sessionWindow.oldest(REALM, 'subject');
  t.equal(first, 'error', 'the first membership read fails');
  t.equal(second, 'error', 'the next membership read fails closed');
  t.equal(counted, null, 'a cooled count does not pretend to be zero');
  t.equal(rows, null, 'a cooled oldest read fails closed');
  t.equal(calls, after, 'those reads do not call the bridge');
  let sweepCalls = 0;
  queryFn = function (name) {
    if (name === 'session.expired' || name === 'session.overCapRows') {
      sweepCalls += 1;
      return [];
    }
    throw new Error('request path');
  };
  runSweep();
  t.check(sweepCalls >= 1,
          'the sweep still queries while the request path is cooled',
          String(sweepCalls));
  log.debug("Leaving cooledIndexCase().");
}

function shedErrorCase(t) {
  log.debug("Entering shedErrorCase().");
  t.log.info('on: a failed shed load ends nobody for that subject');
  freshWindow();
  config.setOverride('authn.maxSessionsPerSubject', '1');
  const older = 'digest-older';
  const newer = 'digest-newer';
  const reads = [];
  // 2026-10-21: the shed asks the store for the over-cap subjects alone,
  // with the cap and the sweep's budget, and pages nobody else.
  let overCapArgs = null;
  let pagedEverySession = false;
  queryFn = function (name, args) {
    if (name === 'session.expired') {
      return [];
    }
    if (name === 'session.subjectRows') {
      pagedEverySession = true;
      return [];
    }
    if (name === 'session.overCapRows') {
      overCapArgs = args;
      if (!args || args[0] !== REALM) {
        return [];
      }
      return [
        { subjectKey: 'subj', key: older, lastSeenAt: 1, startedAt: 1 },
        { subjectKey: 'subj', key: newer, lastSeenAt: 2, startedAt: 2 }
      ];
    }
    if (name === 'session.read') {
      reads.push(args && args[1]);
      if (args && args[1] === older) {
        return { session: {} };
      }
      return {
        session: sessionBody('shed-newer', {
          subjectId: 'shed-alice', lastSeenAt: 2, startedAt: 2
        })
      };
    }
    return emptyAnswer(name);
  };
  try {
    const ended = runSweep();
    t.equal(ended && ended.ended, 0, 'a failed load ends nobody');
    t.equal(reads.indexOf(newer), -1, 'the later live row is not read');
    t.equal(audits('session.end', 'shed-newer').length, 0,
            'the later row has no session.end');
    t.check(!!overCapArgs && overCapArgs[1] === 1 && overCapArgs[2] >= 1 &&
            !pagedEverySession,
            'the shed asks for the over-cap subjects alone, with the cap ' +
            'and its budget, and pages no other session (2026-10-21)',
            JSON.stringify({ args: overCapArgs, paged: pagedEverySession }));
  } finally {
    config.clearOverride('authn.maxSessionsPerSubject');
  }
  log.debug("Leaving shedErrorCase().");
}

// AN ACCOUNT SET (#561) LISTS SESSIONS THE WINDOW MAY NOT HOLD. A member
// evicted from the window is still live, and a member whose read fails is
// not absent: the expiry job must move neither to remembered. Before the
// merge with #350 the set read the realm map, which while the window is on
// is a cache, and every non-resident account was signed out of its set.
function accountSetCase(t) {
  log.debug("Entering accountSetCase().");
  t.log.info('on: an account set keeps a member the window does not hold');
  freshWindow();
  clearSessions();
  const AccountSets = require('../authn/account_sets');
  const body = sessionBody('acct-window', {
    user: { username: 'acct-window', sub: 'urn:uuid:acct-window' }
  });
  const digest = sidDigest(body.id);
  queryFn = function (name, args) {
    if (name === 'session.read' && args && args[1] === digest) {
      return { session: body };
    }
    return emptyAnswer(name);
  };
  const row = AccountSets.fresh();
  AccountSets.addSession(row, body.id, { sub: body.user.sub,
    username: body.user.username, displayName: body.user.username });
  AccountSets.save(row);
  t.equal(authn.sessions.realmMap().has(body.id), false,
          'the member is not resident in this process');
  authn.sweepAccountSets();
  let kept = AccountSets.byId(row.id);
  t.check(!!(kept && kept.sessions && kept.sessions[body.id]),
          'the expiry job keeps a live member the window had to read');
  // A SECOND member, never read before, whose read fails.
  const other = sessionBody('acct-window-unread', {
    user: { username: 'acct-unread', sub: 'urn:uuid:acct-window-unread' }
  });
  const otherDigest = sidDigest(other.id);
  queryFn = function (name, args) {
    if (name === 'session.read' && args && args[1] === otherDigest) {
      throw new Error('account member unread');
    }
    if (name === 'session.read' && args && args[1] === digest) {
      return { session: body };
    }
    return emptyAnswer(name);
  };
  const second = AccountSets.byId(row.id);
  AccountSets.addSession(second, other.id, { sub: other.user.sub,
    username: other.user.username, displayName: other.user.username });
  AccountSets.save(second);
  authn.sweepAccountSets();
  kept = AccountSets.byId(row.id);
  t.check(!!(kept && kept.sessions && kept.sessions[other.id]),
          'and keeps one whose read FAILED: a failed read is not absence');
  // THE PICKER OF A SET WITH AN UNREAD MEMBER IS A 503 (rcbj's decision 3
  // on #561), with Retry-After, as an unread cookie is above — never a
  // picker drawn from the members that could be read.
  config.setOverride('authn.multipleAccounts', 'true');
  try {
    const handle = AccountSets.rotate(kept);
    AccountSets.save(kept);
    const headers = {};
    let status = 0;
    let sent = '';
    const res = { headersSent: false, locals: {},
      set: function (name, value) {
        headers[String(name).toLowerCase()] = String(value);
        return res;
      },
      status: function (code) {
        status = code;
        return res;
      },
      type: function () {
        return res;
      },
      send: function (payload) {
        sent = String(payload);
        return res;
      } };
    const req = { headers: { cookie: AccountSets.cookieName() + '=' +
                             handle }, query: {}, url: '/', res: res };
    t.equal(authn.refuseAccountsUnread(req, res), true,
            'the picker of a set with an unread member refuses to draw');
    t.check(status === 503 && headers['retry-after'] === '5' &&
            /unavailable/.test(sent) && !/STS-/.test(sent) &&
            errorCodes.codeOf(res) === 'STS-AUTHN-0338',
            'with 503 and Retry-After, STS-AUTHN-0338 recorded and not sent',
            status + ' ' + JSON.stringify(headers) + ' ' + sent);
    const begun = authn.beginAuthentication({
      returnTo: '/oauth2/authorize?client_id=c', details: [],
      protocol: 'OAuth 2.0 / OIDC', application: '',
      request: { headers: req.headers, query: {}, url: '/oauth2/authorize' }
    });
    t.check(/^\/authn\/accounts\?authn=/.test(begun),
            'and a sign-in that needs the set goes to that picker, not to ' +
            'the sign-in screen', begun);
  } finally {
    config.clearOverride('authn.multipleAccounts');
  }
  AccountSets.remove(row.id);
  freshWindow();
  log.debug("Leaving accountSetCase().");
}

async function onHalf(t) {
  log.debug("Entering onHalf().");
  t.equal(sessionWindow.active(), true, 'explicit on with the three ' +
          'predicates holds the window');
  processSettingCase(t);
  await evictionCase(t);
  await floodCase(t);
  timeoutCase(t);
  zeroWaitCase(t);
  await bridgeWaitCase(t);
  cooledIndexCase(t);
  shedErrorCase(t);
  await warmCase(t);
  middlewareCase(t);
  parentCase(t);
  await dropErrorCase(t);
  cascadeCase(t);
  await tombstoneCase(t);
  await dirtyCase(t);
  await restoreCase(t);
  upgradeCase(t);
  partialWalkCase(t);
  accountSetCase(t);
  log.debug("Leaving onHalf().");
}

// Rows that exist only in the index stub. The realm map stays empty, so a
// walk that reads the cache and stops cannot see them.
function partialWalkCase(t) {
  log.debug("Entering partialWalkCase().");
  t.log.info('on: a partial cache still answers from the index');
  freshWindow();
  clearSessions();
  const logout = require('../logout/logout');
  const stats = require('../common/admin_stats');
  const admin = require('../admin-ui/admin');
  const adminViews = require('../admin-core/admin_views');
  const HIT_SUB = 'urn:uuid:11111111-1111-1111-1111-111111111111';
  const LIVE_SUB = 'urn:uuid:22222222-2222-2222-2222-222222222222';
  const bodies = {};
  function plant(id, over) {
    log.debug("Entering plant().");
    bodies[id] = sessionBody(id, over);
    log.debug("Leaving plant().");
  }
  plant('walk-hit', {
    subjectId: HIT_SUB,
    user: { username: 'walk-hit', sub: HIT_SUB }
  });
  plant('walk-miss', { user: { username: 'walk-miss', sub: '' } });
  plant('walk-child', {
    derivedFrom: 'walk-parent',
    user: { username: 'walk-child', sub: '' }
  });
  plant('walk-console-child', {
    derivedFrom: 'walk-parent',
    derivedFromRealm: REALM,
    user: { username: 'walk-console-child', sub: '' }
  });
  plant('walk-keyed', {
    credentialKey: 'fp-walk',
    user: { username: 'walk-keyed', sub: '' }
  });
  plant('walk-fed', {
    fedPartnerSession: { relationship: 'rel-walk' },
    user: { username: 'walk-fed', sub: '' }
  });
  plant('walk-live', {
    subjectId: LIVE_SUB,
    user: { username: 'walk-live', sub: LIVE_SUB }
  });
  plant('walk-arrival', {
    chosen: false,
    subjectId: '',
    user: { username: 'anonymous', sub: '' }
  });
  plant('walk-risk', {
    risk: { level: 'low' },
    user: { username: 'walk-risk', sub: '' }
  });
  const hitName = keystore.keyedDigest('session-username', 'walk-hit');
  const localName = keystore.keyedDigest('session-username', 'walk-local');
  const missName = keystore.keyedDigest('session-username', 'walk-miss');
  // A sign-out's inventory reads one person's sessions by these two (#854,
  // 2026-10-22): the walk of every session was two minutes on 8081.
  const liveName = keystore.keyedDigest('session-username', 'walk-live');
  const liveSubject = keystore.keyedDigest('session-subject', LIVE_SUB);
  const parentKey = keystore.keyedDigest('session-parent', 'walk-parent');
  const keepParent = keystore.keyedDigest('session-parent', 'walk-keep');
  const consoleParent = keystore.keyedDigest('session-parent',
                                             'walk-console-keep');
  const seen = [];
  let countNull = false;
  let localNull = false;
  let partnerNull = false;
  let bodyBad = false;
  let childrenNull = false;
  let childChildrenNull = false;
  let pageNull = false;
  queryFn = function (name, args) {
    seen.push(name);
    const realm = args && args[0];
    const second = args && args[1];
    if (name === 'session.count') {
      if (countNull) {
        return null;
      }
      return { n: 11 };
    }
    if (name === 'session.read') {
      if (bodyBad && (second === 'walk-bad' || second === 'walk-bad-fed' ||
                      second === 'walk-bad-page')) {
        return { body: 'not-a-seal' };
      }
      const body = bodies[second];
      if (!body) {
        return null;
      }
      return { session: body };
    }
    if (name === 'session.username') {
      if (second === hitName) {
        return ['walk-hit'];
      }
      if (second === liveName) {
        return pageNull ? null : ['walk-live'];
      }
      if (localNull && second === localName) {
        return null;
      }
      return [];
    }
    if (name === 'session.subject' && second === liveSubject) {
      return pageNull ? null : ['walk-live'];
    }
    if (name === 'session.children') {
      if (childrenNull && second === keepParent) {
        return null;
      }
      if (childChildrenNull && second === consoleParent) {
        return null;
      }
      if (bodyBad && second === parentKey) {
        return ['walk-bad', 'walk-child'];
      }
      if (second !== parentKey) {
        return [];
      }
      if (realm === REALM) {
        return ['walk-child'];
      }
      if (realm === realms.DEFAULT_ID) {
        return ['walk-console-child'];
      }
      return [];
    }
    if (name === 'session.credential' && realm === REALM &&
        second === 'fp-walk') {
      return ['walk-keyed'];
    }
    if (name === 'session.partner' && realm === REALM &&
        partnerNull && second === 'rel-unread') {
      return null;
    }
    if (name === 'session.partner' && realm === REALM &&
        bodyBad && second === 'rel-bad') {
      return ['walk-bad-fed'];
    }
    if (name === 'session.partner' && realm === REALM &&
        second === 'rel-walk') {
      return ['walk-fed'];
    }
    if (name === 'session.page') {
      if (pageNull) {
        return null;
      }
      if (bodyBad) {
        return ['walk-bad-page'];
      }
      if (realm !== REALM || second) {
        return [];
      }
      return ['walk-miss', 'walk-live', 'walk-arrival', 'walk-risk'];
    }
    return emptyAnswer(name);
  };
  try {
    t.check(!!hitName && hitName !== 'walk-hit' && hitName !== HIT_SUB,
            'the username key is a digest, not the urn');
    t.check(!!missName && missName !== 'walk-miss',
            'a miss still has a username digest');
    seen.length = 0;
    const hit = authn.sessionsOf('walk-hit');
    t.equal(hit.length, 1, 'sessionsOf finds the urn subject by username');
    t.equal(hit[0] && hit[0].subjectId, HIT_SUB,
            'the row found is the urn subject');
    t.equal(authn.sessions.get('walk-hit'), undefined,
            'the username hit is not in the cache');
    t.check(seen.indexOf('session.username') >= 0,
            'sessionsOf asks username_key');
    t.equal(seen.indexOf('session.page'), -1,
            'a username hit does not page');
    t.equal(seen.indexOf('session.subjectRows'), -1,
            'sessionsOf does not filter subject_key');
    seen.length = 0;
    const miss = authn.sessionsOf('walk-miss');
    t.equal(miss.length, 1, 'a username miss falls through to a page');
    t.check(seen.indexOf('session.page') >= 0,
            'the miss did page');
    const kids = authn.derivedFrom('walk-parent').map(function (row) {
      return row.id;
    });
    t.check(kids.indexOf('walk-child') >= 0,
            'derivedFrom returns the uncached child');
    t.check(kids.indexOf('walk-console-child') >= 0,
            'derivedFrom returns the console child in the default realm');
    t.equal(authn.sessions.get('walk-child'), undefined,
            'the child is not in the cache');
    const fed = authn.sessionsForRelationship('rel-walk');
    t.equal(fed.length, 1, 'a federated session is still found');
    t.equal(fed[0] && fed[0].id, 'walk-fed',
            'the federated row is the relationship\'s');
    t.equal(authn.sessions.realmMap().size, 0,
            'the risk walk starts from an empty cache');
    const riskIds = authn.sessionsForRisk().map(function (row) {
      return row.id;
    });
    t.check(riskIds.indexOf('walk-risk') >= 0,
            'sessionsForRisk sees an uncached person session');
    const liveIds = logout.liveSessions().map(function (row) {
      return row.id;
    });
    t.check(liveIds.indexOf('session:walk-live') >= 0,
            'a chosen session that is not cached is still live');
    t.equal(liveIds.indexOf('session:walk-arrival'), -1,
            'an arrival is still skipped');
    const held = stats.holderKeyOf('walk-live', LIVE_SUB);
    const inventory = logout.inventoryFor(held);
    t.check(inventory.sessions >= 1,
            'the inventory finds an uncached session through the index ' +
            '(#854: by username and subject, not a walk)');
    const listed = adminViews.signOnSessionRows().map(function (row) {
      return row.id;
    });
    t.check(listed.indexOf('walk-live') >= 0,
            'the console lists the uncached session');
    const counted = admin.consoleJson();
    t.equal(counted.signOnSessions, 11,
            'signOnSessions is the index count');
    countNull = true;
    const unread = admin.consoleJson();
    t.equal(unread.signOnSessions, null,
            'a failed count stays null');
    countNull = false;
    seen.length = 0;
    const local = sessionBody('walk-local', {
      user: { username: 'walk-local', sub: '' }
    });
    authn.sessions.set(local.id, local);
    seen.length = 0;
    const paged = authn.sessionsOf('walk-local');
    t.equal(paged && paged.length, 1,
            'an empty username key list still pages and keeps the ' +
            'unflushed row');
    t.check(seen.indexOf('session.page') >= 0,
            'an empty username key list does page');
    seen.length = 0;
    localNull = true;
    const unflushed = authn.sessionsOf('walk-local');
    t.equal(unflushed, null,
            'a failed username read is not the unflushed row');
    t.equal(seen.indexOf('session.page'), -1,
            'a failed username read is not the miss that pages');
    const fedLocal = sessionBody('walk-fed-local', {
      fedPartnerSession: { relationship: 'rel-unread' },
      user: { username: 'walk-fed-local', sub: '' }
    });
    authn.sessions.set(fedLocal.id, fedLocal);
    partnerNull = true;
    t.equal(authn.sessionsForRelationship('rel-unread'), null,
            'a failed partner read is not the unflushed map');
    t.equal(authn.sessions.get('walk-fed-local').id, 'walk-fed-local',
            'the unflushed federated row is still held');
    partnerNull = false;
    bodyBad = true;
    t.equal(authn.sessionsForRelationship('rel-bad'), null,
            'a partner body that will not open is unread');
    t.equal(authn.derivedFrom('walk-parent'), null,
            'a child body that will not open is unread');
    const pageBlow = thrownMessage(function () {
      logout.liveSessions();
    });
    t.check(/could not be read/.test(pageBlow),
            'a page body that will not open fails the live list', pageBlow);
    bodyBad = false;
    const keep = sessionBody('walk-keep', {
      user: { username: 'walk-keep', sub: '' }
    });
    authn.sessions.set(keep.id, keep);
    childrenNull = true;
    t.equal(authn.derivedFrom('walk-keep'), null,
            'a failed children read is not an empty generation');
    t.equal(authn.endSessionById('walk-keep', 'a test sign-out'), null,
            'the parent is not ended while its children are unread');
    t.equal(authn.sessions.get('walk-keep') &&
            authn.sessions.get('walk-keep').id, 'walk-keep',
            'the parent stays in the map');
    t.equal(audits('session.end', 'walk-keep').length, 0,
            'an unread children walk audits no session.end');
    childrenNull = false;
    const signon = sessionBody('walk-signon', {
      user: { username: 'walk-signon', sub: '' }
    });
    const earlier = sessionBody('walk-earlier', {
      derivedFrom: 'walk-signon',
      user: { username: 'walk-earlier', sub: '' }
    });
    const consoleChild = sessionBody('walk-console-keep', {
      derivedFrom: 'walk-signon',
      derivedFromRealm: REALM,
      rpSurface: 'admin',
      user: { username: 'walk-console-keep', sub: '' }
    });
    authn.sessions.set(signon.id, signon);
    authn.sessions.set(earlier.id, earlier);
    // A console session lives in the default realm. The cascade reaches
    // it through realms.run, and that call's return is the child's.
    authn.sessions.realmMap(realms.DEFAULT_ID).set(consoleChild.id,
                                                    consoleChild);
    childChildrenNull = true;
    t.equal(authn.endSessionById('walk-signon', 'a test sign-out'), null,
            'a failed child drop does not end the sign-on');
    t.equal(authn.sessions.get('walk-signon') &&
            authn.sessions.get('walk-signon').id, 'walk-signon',
            'the sign-on stays in the map');
    t.equal(authn.sessions.get('walk-earlier'), undefined,
            'a child already ended stays ended');
    t.check(audits('session.end', 'walk-earlier').some(function (row) {
      return row.outcome === 'success';
    }), 'the earlier child has its session.end');
    const keptConsole = authn.sessions.realmMap(realms.DEFAULT_ID)
      .get('walk-console-keep');
    t.equal(keptConsole && keptConsole.id, 'walk-console-keep',
            'the console child stays in the default realm');
    t.equal(audits('session.end', 'walk-signon').length, 0,
            'a failed child drop audits no session.end for the sign-on');
    t.equal(audits('session.end', 'walk-signon',
                   'STS-AUTHN-0011').length, 0,
            'STS-AUTHN-0011 is not recorded for the sign-on');
    t.equal(audits('session.end', 'walk-console-keep').length, 0,
            'the console child is not ended');
    childChildrenNull = false;
    pageNull = true;
    const liveBlow = thrownMessage(function () {
      logout.liveSessions();
    });
    t.check(/could not be read/.test(liveBlow),
            'an unread page fails the live list', liveBlow);
    const inventoryBlow = thrownMessage(function () {
      logout.inventoryFor(held);
    });
    t.check(/could not be read/.test(inventoryBlow),
            'an unread index fails the inventory', inventoryBlow);
    const rowsBlow = thrownMessage(function () {
      adminViews.signOnSessionRows();
    });
    t.check(/could not be read/.test(rowsBlow),
            'an unread page fails the console list', rowsBlow);
    pageNull = false;
    localNull = false;
    bodyBad = false;
    partnerNull = false;
    authn.sessions.delete('walk-local');
    t.equal(authn.sessions.get('walk-keyed'), undefined,
            'the keyed row is not cached before the sign-in');
    const detail = { key: 'fp-walk' };
    const keyed = signIn('walk-keyed', detail);
    t.equal(detail.refusedWith, undefined,
            'the keyed sign-in is not refused', detail.refusedWith);
    t.equal(keyed && keyed.id, 'walk-keyed',
            'a keyed session is still found');
  } finally {
    countNull = false;
    childChildrenNull = false;
    try {
      // clearSessions walks only the ambient map. This row is in the
      // default realm, and a failed delete must not skip that clear.
      authn.sessions.realmMap(realms.DEFAULT_ID).delete(
        'walk-console-keep');
    } catch (e) {
      log.debug("Caught in partialWalkCase(): " +
                ((e && e.message) || e));
    }
    clearSessions();
  }
  log.debug("Leaving partialWalkCase().");
}

async function refusalCases(t, dir) {
  log.debug("Entering refusalCases().");
  t.log.info('explicit on is refused; auto keeps the full map');
  const savedIsMulti = cells.isMulti;
  try {
    windowSetting('on');
    minted.reset();
    const missing = thrownMessage(function () {
      sessionWindow.assertConfigured();
    });
    t.check(/minted persistence is not enabled/.test(missing),
            'on without a minted driver is STS-AUTHN-0339', missing);

    t.equal(installDriver(), true, 'the stub driver is installed again');
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    cells.isMulti = function () {
      return true;
    };
    const several = thrownMessage(function () {
      sessionWindow.assertConfigured();
    });
    t.check(/several cells/.test(several),
            'on in several cells is STS-AUTHN-0339', several);
    t.check(!/not enabled/.test(several),
            'a cell id is not the same failure as a missing driver');

    cells.isMulti = savedIsMulti;
    keystore.reset();
    t.equal(minted.enabled(), true,
            'product mode with a driver stays enabled while unsealed');
    const undigested = thrownMessage(function () {
      sessionWindow.assertConfigured();
    });
    t.check(/not a digest/.test(undigested),
            'on without a digest key is STS-AUTHN-0339', undigested);

    sessionWindow.resetForTests();
    windowSetting('auto');
    minted.reset();
    t.equal(minted.enabled(), false,
            'auto without a driver is not minted persistence');
    const noDriver = loggedLines('STS-AUTHN-0339', function () {
      sessionWindow.assertConfigured();
    });
    t.equal(noDriver.length, 1,
            'auto without a driver logs STS-AUTHN-0339 once');
    t.check(/not enabled/.test(noDriver[0] || ''),
            'that log is the missing driver', noDriver[0]);
    t.equal(sessionWindow.active(), false,
            'auto without minted persistence keeps the full map');
    keptWhole(t, 'auto-no-driver');
    const noDriverAgain = loggedLines('STS-AUTHN-0339', function () {
      sessionWindow.assertConfigured();
    });
    t.equal(noDriverAgain.length, 0,
            'auto without a driver does not log again');

    sessionWindow.resetForTests();
    windowSetting('auto');
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    t.equal(installDriver(), true, 'the driver is back for several cells');
    t.equal(minted.enabled(), true,
            'minted persistence is enabled for the cell check');
    cells.isMulti = function () {
      return true;
    };
    const multi = loggedLines('STS-AUTHN-0339', function () {
      sessionWindow.assertConfigured();
    });
    t.equal(multi.length, 1, 'auto in several cells logs STS-AUTHN-0339 once');
    t.check(/several cells/.test(multi[0] || ''),
            'that log is the cell id', multi[0]);
    t.equal(sessionWindow.active(), false,
            'auto in several cells keeps the full map');
    keptWhole(t, 'auto-several');
    const multiAgain = loggedLines('STS-AUTHN-0339', function () {
      sessionWindow.assertConfigured();
    });
    t.equal(multiAgain.length, 0, 'auto in several cells does not log again');
    cells.isMulti = savedIsMulti;

    sessionWindow.resetForTests();
    windowSetting('auto');
    keystore.reset();
    t.equal(minted.enabled(), true,
            'product mode with a driver stays enabled while unsealed');
    const first = loggedLines('STS-AUTHN-0339', function () {
      sessionWindow.assertConfigured();
    });
    const second = loggedLines('STS-AUTHN-0339', function () {
      sessionWindow.assertConfigured();
    });
    t.equal(first.length, 1, 'auto in that state logs STS-AUTHN-0339 once');
    t.check(/not a digest/.test(first[0] || ''),
            'the log is the digest failure, not a missing driver',
            first[0]);
    t.equal(second.length, 0, 'a second check does not log it again');
    t.equal(sessionWindow.active(), false,
            'auto without a digest keeps the full map');
    keptWhole(t, 'auto-undigested');

    await armKeystore(dir);
    cells.isMulti = savedIsMulti;
    windowSetting('auto');
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    t.equal(installDriver(), true, 'the driver is back for the auto check');
    t.equal(minted.enabled(), true, 'minted persistence is enabled');
    t.equal(cells.isMulti(), false, 'the process is one cell');
    const column = minted.keyColumnOf('authn.sessions', REALM, 'probe-sid');
    t.check(!!column && column !== 'probe-sid',
            'the minted key is a digest');
    sessionWindow.resetForTests();
    installQuery();
    t.equal(sessionWindow.active(), true,
            'auto turns the window on when the three predicates hold');
    const autoRow = sessionBody('auto-row');
    authn.sessions.set(autoRow.id, autoRow);
    t.check(!!authn.sessions.get('auto-row'),
            'auto keeps the session in the map');
    t.equal(sessionWindow.slotState(REALM, 'auto-row').cached, true,
            'auto admits it to the window');
    authn.sessions.delete('auto-row');
  } finally {
    cells.isMulti = savedIsMulti;
  }
  log.debug("Leaving refusalCases().");
}

async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  keystore.reset();
  keystore.setStore({
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
    saveKeys: function () {
      log.debug("Entering saveKeys().");
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function () {
      log.debug("Entering deleteKeys().");
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    }
  });
  await keystore.start();
  log.debug("Leaving armKeystore().");
}

function disarmKeystore() {
  log.debug("Entering disarmKeystore().");
  delete process.env.STS_KEYS_SOURCE;
  delete process.env.STS_KEYS_KEK_PROVIDER;
  delete process.env.STS_KEYS_KEK_FILE;
  keystore.reset();
  log.debug("Leaving disarmKeystore().");
}

function clearOverrides() {
  log.debug("Entering clearOverrides().");
  config.clearOverride('global.mode');
  config.clearOverride('persistence.minted');
  windowSetting(null);
  config.clearOverride('authn.sessionWindow');
  config.clearOverride('authn.sessionCacheEntries');
  config.clearOverride('authn.sessionReadTimeoutMs');
  config.clearOverride('authn.maxSessions');
  log.debug("Leaving clearOverrides().");
}

async function withTempDir(fn) {
  log.debug("Entering withTempDir().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-session-window-'));
  try {
    const out = await fn(dir);
    log.debug("Leaving withTempDir().");
    return out;
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in withTempDir(): " + ((e && e.message) || e));
    }
  }
}

function keptWhole(t, label) {
  log.debug("Entering keptWhole().");
  const row = sessionBody(label);
  authn.sessions.set(row.id, row);
  t.check(!!authn.sessions.get(label), label + ' stays in the map');
  t.equal(sessionWindow.slotState(REALM, label).cached, false,
          label + ' is not admitted');
  authn.sessions.delete(label);
  log.debug("Leaving keptWhole().");
}

async function body(t, dir) {
  log.debug("Entering body().");
  t.equal(productionSessionWalks().join(', '), '',
          'no production forEach of authn.sessions outside authn.ts');
  authn.setSessionObserver(function () {
    return null;
  });
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "session-window"',
          (made.errors || []).join(' '));
    log.debug("Leaving body().");
    return;
  }
  let armed = false;
  try {
    await realms.run(made.realm, function () {
      offCase(t);
    });
    armed = true;
    await armKeystore(dir);
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    windowSetting('on');
    cacheEntries(10000);
    t.equal(installDriver(), true, 'the stub driver holds minted rows');
    t.equal(config.processValue('authn.sessionWindow'), 'on',
            'the test forces the process window on');
    await realms.run(made.realm, function () {
      return onHalf(t);
    });
    await realms.run(made.realm, function () {
      return refusalCases(t, dir);
    });
  } finally {
    try {
      clearOverrides();
      clearSessions();
    } catch (e) {
      log.debug("Caught in body(): " + ((e && e.message) || e));
    }
    realms.remove(REALM);
    if (armed) {
      disarmKeystore();
    }
    minted.reset();
    minted.endPrefetch();
    sessionWindow.resetForTests();
  }
  log.debug("Leaving body().");
}

async function run(t) {
  log.debug("Entering run().");
  log.debug("Leaving run().");
  return withTempDir(function (dir) {
    return body(t, dir);
  });
}

module.exports = {
  name: 'session_window',
  describe: 'authn.sessionWindow defaults to auto (#350): without minted ' +
            'persistence the full map stays, a miss loads a sealed ' +
            'session, and eviction forgets memory after the commit ' +
            'without ending the session',
  run: run
};
