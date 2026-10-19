// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: session_window.js
//
// authn.sessionWindow stays off unless this file forces on (#350). A miss
// loads a sealed session. Eviction forgets the memory copy after the commit
// and does not end the session. A read error is not absence.

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
  authn.sessions.forEach(function (session, id) {
    ids.push(id);
  });
  ids.forEach(function (id) {
    authn.sessions.delete(id);
  });
  log.debug("Leaving clearSessions().");
}

function cacheEntries(n) {
  log.debug("Entering cacheEntries().");
  config.setOverride('authn.sessionCacheEntries', String(n));
  log.debug("Leaving cacheEntries().");
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
            'the default off does not turn the window on');
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
  uses[0](req, res, function () {
    nextCalled = true;
  });
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

async function onHalf(t) {
  log.debug("Entering onHalf().");
  t.equal(sessionWindow.active(), true, 'explicit on with the three ' +
          'predicates holds the window');
  await evictionCase(t);
  await floodCase(t);
  timeoutCase(t);
  middlewareCase(t);
  parentCase(t);
  await dropErrorCase(t);
  cascadeCase(t);
  await tombstoneCase(t);
  await dirtyCase(t);
  await restoreCase(t);
  upgradeCase(t);
  log.debug("Leaving onHalf().");
}

async function refusalCases(t, dir) {
  log.debug("Entering refusalCases().");
  t.log.info('explicit on is refused; auto keeps the full map');
  const savedIsMulti = cells.isMulti;
  try {
    config.setOverride('authn.sessionWindow', 'on');
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
    config.setOverride('authn.sessionWindow', 'auto');
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

    await armKeystore(dir);
    cells.isMulti = savedIsMulti;
    config.setOverride('authn.sessionWindow', 'auto');
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    t.equal(installDriver(), true, 'the driver is back for the auto check');
    t.equal(minted.enabled(), true, 'minted persistence is enabled');
    t.equal(cells.isMulti(), false, 'the process is one cell');
    const column = minted.keyColumnOf('authn.sessions', REALM, 'probe-sid');
    t.check(!!column && column !== 'probe-sid',
            'the minted key is a digest');
    t.equal(sessionWindow.active(), false,
            'auto stays inactive when the three predicates hold');
    const autoRow = sessionBody('auto-row');
    authn.sessions.set(autoRow.id, autoRow);
    t.check(!!authn.sessions.get('auto-row'),
            'auto keeps the session in the map');
    t.equal(sessionWindow.slotState(REALM, 'auto-row').cached, false,
            'auto does not admit it to the window');
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

async function body(t, dir) {
  log.debug("Entering body().");
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
    config.setOverride('authn.sessionWindow', 'on');
    cacheEntries(10000);
    t.equal(installDriver(), true, 'the stub driver holds minted rows');
    t.equal(config.value('authn.sessionWindow'), 'on',
            'the test forces the window on');
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
  describe: 'authn.sessionWindow is off unless forced on (#350): a miss ' +
            'loads a sealed session, and eviction forgets memory after ' +
            'the commit without ending the session',
  run: run
};
