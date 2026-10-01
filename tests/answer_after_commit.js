// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: answer_after_commit.js
//
// ===========================================================================
// A WRITE IS ANSWERED AFTER ITS COMMIT, AND THE LEASE THAT KEEPS A PROCESS
// WRITING DOES NOT QUEUE BEHIND THE WRITES (2026-09-29, #351).
//
// On testidp a SCIM Bulk load starved a request worker's four pooled
// connections; its writes failed (STS-STORE-0002) while their requests were
// answered 204, the origin renewal could not get a connection, the worker
// exited (STS-STORE-0061), and ~600 deleted people came back from the
// database. Each section is one of the fixes:
//
//   A. A FAILED FLUSH KEEPS ITS JOURNAL AND RETRIES ON ITS OWN. The DNs a
//      failed directory flush had taken went back only as a dirty bit, so
//      the next journalled flush wrote the NEW DNs and advanced the commit
//      position past the failed ones; and nothing retried until the next
//      change. Driven through the real `persistence.js` on an ldif store
//      whose driver fails when this file says.
//   B. RULE 2 OUTSIDE A CLUSTER, THROUGH THE REAL `common/app.js`: a writing
//      request is answered only once its commit lands (the order is checked:
//      no answer while the commit is held), a failed commit is 503 with
//      Retry-After and none of the handler's Location, Set-Cookie or body, a
//      read is answered at once, and a writing method is held while a refused
//      write still waits for its retry.
//   C. THE SAME FOR AN LDAP OPERATION, through `ldap/ldap_server.js`'s own
//      registered handlers: an add run the way a request worker runs it
//      (`performOperation()`) and the way the socket runs it, answered
//      unavailable (52) when its commit fails and its result when it lands.
//   D. THE LIVENESS CONNECTION: the postgres driver's origin renewal and
//      heartbeat succeed while every pooled connection is taken, through a
//      client of their own, and fall back to the pool when that client
//      cannot connect; a lapsed origin claim is not purged with the others.
//   E. THE EVENT-LOOP DELAY: the per-process job is registered and the status
//      carries its report.
//   F. A KEY ROW WHOSE WRITE FAILED fails the commit a response waits for,
//      and is written again by the retry with what it held.
//
// IN A CHILD PROCESS, for `cluster_barrier_throughput.js`'s reason: the store
// modules are one per process, and this file installs stubs on them.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'answer_after_commit',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_ANSWER_AFTER_COMMIT_CHILD';

function settle() {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function recordingHarness() {
  log.debug("Entering recordingHarness().");
  const seen = [];
  function check(condition, what, detail) {
    log.debug("Entering check().");
    seen.push({ ok: !!condition, what: what,
                detail: detail === undefined ? '' : String(detail) });
    log.debug("Leaving check().");
    return !!condition;
  }
  log.debug("Leaving recordingHarness().");
  return { log: log, seen: seen, check: check };
}

// ---------------------------------------------------------------------------
// A. The journal goes back, and the retry runs by itself.
// ---------------------------------------------------------------------------
async function journalAndRetry(t, dir) {
  log.debug("Entering journalAndRetry().");
  t.log.info('=== A. a failed flush keeps its journal and retries ===');
  process.env.STS_PERSISTENCE_MODE = 'ldif';
  process.env.STS_PERSISTENCE_DATA_DIR = dir;
  process.env.STS_PERSISTENCE_WRITE_DELAY = '0';
  const persistence = require('../persistence/persistence');
  const ldif = require('../persistence/persistence_ldif');
  const control = { fail: false, saves: [] };
  const create = ldif.create;
  ldif.create = function (options) {
    log.debug("Entering the wrapped ldif create().");
    const driver = create(options);
    const save = driver.saveDirectory;
    driver.saveDirectory = function (change) {
      log.debug("Entering the wrapped saveDirectory().");
      const keys = (change.upserts || []).map(function (row) {
        return row.key;
      });
      control.saves.push({ keys: keys, failed: control.fail });
      if (control.fail) {
        log.debug("Leaving the wrapped saveDirectory(). Failing.");
        return Promise.reject(new Error('the store refused on purpose'));
      }
      log.debug("Leaving the wrapped saveDirectory().");
      return save.apply(driver, arguments);
    };
    log.debug("Leaving the wrapped ldif create().");
    return driver;
  };
  // The directory: one realm's rows, keyed by the normalised DN.
  const rows = new Map();
  persistence.setDirectory({
    realmEntries: function (realmId) {
      log.debug("Entering realmEntries().");
      log.debug("Leaving realmEntries().");
      if (realmId !== 'default') {
        return [];
      }
      return Array.from(rows.entries()).map(function (pair) {
        return { key: pair[0], entry: pair[1] };
      });
    },
    replaceRealm: function () {
      log.debug("Entering replaceRealm().");
      log.debug("Leaving replaceRealm().");
      return undefined;
    }
  });
  await persistence.start();
  await persistence.flush();
  function put(name) {
    log.debug("Entering put().");
    const dn = 'uid=' + name + ',ou=users,dc=example,dc=com';
    rows.set(dn, { dn: dn, attributes: { uid: [name], cn: [name] } });
    persistence.directoryChanged(dn);
    log.debug("Leaving put().");
    return dn;
  }

  // The first write fails.
  control.fail = true;
  const a = put('journal-a');
  const failed = await persistence.flush();
  t.check(!!(failed && failed.error),
          'A: a flush whose driver refuses answers with its error',
          JSON.stringify(failed));
  t.check(persistence.commitBacklog() === true,
          'A: and the store is behind memory by a refused write',
          String(persistence.commitBacklog()));
  t.check(persistence.status().retryArmed === true,
          'A: and a retry of it is armed without waiting for a change',
          JSON.stringify(persistence.status().retryArmed));

  // THE NEXT CHANGE names another DN; the failed one must ride with it.
  control.fail = false;
  const b = put('journal-b');
  const after = await persistence.flush();
  const last = control.saves[control.saves.length - 1] || { keys: [] };
  t.check(!after.error && last.keys.indexOf(a) >= 0 &&
          last.keys.indexOf(b) >= 0,
          'A: THE JOURNAL WENT BACK — the next flush writes the DN the ' +
          'failed one had taken beside its own (it wrote only the new DN, ' +
          'and the ' +
          'failed change reached the store only if a full walk ever ran)',
          JSON.stringify(last));
  t.check(persistence.commitBacklog() === false,
          'A: and once it lands the store is no longer behind',
          String(persistence.commitBacklog()));

  // THE RETRY, WITH NO CHANGE AFTER THE FAILURE.
  control.fail = true;
  const c = put('journal-c');
  await persistence.flush();
  control.fail = false;
  const savesBefore = control.saves.length;
  await sleep(1600);
  const retried = control.saves.slice(savesBefore).filter(function (one) {
    return !one.failed && one.keys.indexOf(c) >= 0;
  });
  t.check(retried.length === 1,
          'A: A FAILED WRITE IS RETRIED ON ITS OWN within its first ' +
          'backoff — nothing else changed, so "the next change" would ' +
          'never have come',
          JSON.stringify(control.saves.slice(savesBefore)));
  t.check(persistence.commitBacklog() === false &&
          persistence.status().retryArmed === false,
          'A: and nothing is left behind or armed afterwards',
          JSON.stringify({ backlog: persistence.commitBacklog(),
                           armed: persistence.status().retryArmed }));
  t.check(persistence.answersAfterCommit() === false,
          'A: an ldif store is not one a response waits for',
          String(persistence.answersAfterCommit()));

  // E, while a store is started: the event loop is being measured.
  const scheduler = require('../cluster/scheduler');
  const job = scheduler.job('persistence.event-loop-lag');
  t.check(!!job && job.kind === 'per-process',
          'E: the event-loop delay report is a per-process scheduler job',
          JSON.stringify(job ? { kind: job.kind } : null));
  const loop = persistence.status().eventLoop;
  t.check(!!loop && typeof loop.warnAboveMs === 'number' &&
          !!loop.sinceReport && typeof loop.sinceReport.maxMs === 'number',
          'E: and the status carries the loop\'s delay',
          JSON.stringify(loop));
  await persistence.stop();
  ldif.create = create;
  log.debug("Leaving journalAndRetry().");
}

// ---------------------------------------------------------------------------
// F. A key row whose write fails is a failure of the commit, and is retried.
// ---------------------------------------------------------------------------
async function keyRows(t, dir) {
  log.debug("Entering keyRows().");
  t.log.info('=== F. a failed key row fails the commit and is retried ===');
  const nodeCrypto = require('crypto');
  const keystore = require('../common/keystore');
  const helpers = require('../common/helpers');
  const persistence = require('../persistence/persistence');
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   'utf8');
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  const store = { rows: new Map(), fail: true,
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
    saveKeys: function (realm, material) {
      log.debug("Entering saveKeys().");
      if (store.fail) {
        log.debug("Leaving saveKeys(). Failing.");
        return Promise.reject(new Error('the key table refused on purpose'));
      }
      store.rows.set(realm, material);
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function () {
      log.debug("Entering deleteKeys().");
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    } };
  try {
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    const kid = helpers.STS.kid;
    const answers = await persistence.commitThrough();
    const failed = (answers || []).filter(function (one) {
      return one && one.error;
    });
    t.check(!!kid && failed.length === 1 && store.rows.size === 0,
            'F: A KEY ROW THAT FAILED FAILS THE COMMIT a response waits for ' +
            '— its outcome was dropped, and a realm was answered as created ' +
            'with keys the store never held', JSON.stringify(answers));
    t.check(keystore.failing() === true,
            'F: and the key store says a failed row is waiting',
            String(keystore.failing()));
    store.fail = false;
    keystore.retryFailed();
    await keystore.settleAll();
    t.check(store.rows.size === 1 && keystore.failing() === false,
            'F: the retry writes the row it failed with, and nothing is left ' +
            'waiting', JSON.stringify({ rows: store.rows.size,
                                        failing: keystore.failing() }));
  } finally {
    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    helpers.resetStsKeys();
  }
  log.debug("Leaving keyRows().");
}

// ---------------------------------------------------------------------------
// B and C share one stubbed store: answers after commit, a position that
// moves when a test route writes, and commits this file settles.
// ---------------------------------------------------------------------------
function stubTheStore() {
  log.debug("Entering stubTheStore().");
  const persistence = require('../persistence/persistence');
  const cluster = require('../cluster/cluster');
  const state = { directory: 0, minted: 0, backlog: false, commits: [],
                  autoAnswer: null };
  cluster.isActiveActive = function () {
    log.debug("Entering the stubbed isActiveActive().");
    log.debug("Leaving the stubbed isActiveActive().");
    return false;
  };
  persistence.answersAfterCommit = function () {
    log.debug("Entering the stubbed answersAfterCommit().");
    log.debug("Leaving the stubbed answersAfterCommit().");
    return true;
  };
  persistence.writeGeneration = function () {
    log.debug("Entering the stubbed writeGeneration().");
    log.debug("Leaving the stubbed writeGeneration().");
    return { directory: state.directory, minted: state.minted, observed: 0 };
  };
  persistence.keysPending = function () {
    log.debug("Entering the stubbed keysPending().");
    log.debug("Leaving the stubbed keysPending().");
    return false;
  };
  persistence.commitBacklog = function () {
    log.debug("Entering the stubbed commitBacklog().");
    log.debug("Leaving the stubbed commitBacklog().");
    return state.backlog;
  };
  persistence.commitThrough = function (target) {
    log.debug("Entering the stubbed commitThrough().");
    log.debug("Leaving the stubbed commitThrough().");
    if (state.autoAnswer) {
      state.commits.push({ target: target, resolve: null });
      return Promise.resolve(state.autoAnswer);
    }
    return new Promise(function (resolve) {
      state.commits.push({ target: target, resolve: resolve });
    });
  };
  log.debug("Leaving stubTheStore().");
  return state;
}

function request(port, method, urlPath) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                               method: method,
                               headers: { 'content-length': 0 } },
                             function (res) {
      let text = '';
      res.on('data', function (chunk) { text += chunk; });
      res.on('end', function () {
        resolve({ status: res.statusCode, headers: res.headers, text: text,
                  at: Date.now() });
      });
    });
    req.on('error', function (e) {
      resolve({ status: 0, text: String(e && e.message), headers: {} });
    });
    req.end();
  });
}

async function theApp(t, state) {
  log.debug("Entering theApp().");
  t.log.info('=== B. rule 2 outside a cluster, through common/app.js ===');
  const app = require('../common/app');
  app.post('/test/aac/write', function (req, res) {
    log.debug("Entering the test write route.");
    state.directory += 1;
    res.cookie('aac', 'a-session-the-store-does-not-hold');
    log.debug("Leaving the test write route.");
    res.redirect(302, '/somewhere/that/assumes/the/write');
  });
  app.get('/test/aac/read', function (req, res) {
    log.debug("Entering the test read route.");
    log.debug("Leaving the test read route.");
    res.json({ ok: true });
  });
  app.post('/test/aac/noop', function (req, res) {
    log.debug("Entering the test noop route.");
    log.debug("Leaving the test noop route.");
    // A 200 and not the 404 a retried DELETE would get: a refusal is held
    // for its own audit row anyway, which would make the backlog check below
    // pass for the wrong reason.
    res.json({ done: true });
  });
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  try {
    // 1. A WRITE WHOSE COMMIT LANDS: nothing is answered before it does.
    let answered = null;
    const pending = request(port, 'POST', '/test/aac/write')
      .then(function (r) {
        answered = r;
        return r;
      });
    for (let i = 0; i < 50 && !state.commits.length; i += 1) {
      await sleep(10);
    }
    await sleep(100);
    t.check(state.commits.length === 1 && answered === null,
            'B: A WRITE IS NOT ANSWERED BEFORE ITS COMMIT — the commit is ' +
            'asked for and the client has nothing yet',
            JSON.stringify({ commits: state.commits.length,
                             answered: answered && answered.status }));
    const releasedAt = Date.now();
    state.commits[0].resolve([{ written: true }, { written: false }]);
    const landed = await pending;
    t.check(landed.status === 302 &&
            /assumes\/the\/write/.test(String(landed.headers.location)) &&
            landed.at >= releasedAt,
            'B: and once it lands the handler\'s own answer goes out',
            JSON.stringify({ status: landed.status,
                             location: landed.headers.location }));

    // 2. A WRITE WHOSE COMMIT FAILS: 503, never the redirect.
    state.commits.length = 0;
    const refusedP = request(port, 'POST', '/test/aac/write');
    for (let i = 0; i < 50 && !state.commits.length; i += 1) {
      await sleep(10);
    }
    state.commits[0].resolve([{ written: false,
                                error: 'timeout exceeded when trying to ' +
                                       'connect' }, null]);
    const refused = await refusedP;
    let body = null;
    try {
      body = JSON.parse(refused.text);
    } catch (e) {
      log.debug("Caught in theApp(): " + ((e && e.message) || e));
    }
    t.check(refused.status === 503,
            'B: A WRITE WHOSE COMMIT FAILED IS ANSWERED 503, not the 302 its ' +
            'handler wrote (testidp: 204s whose deletes were lost)',
            String(refused.status));
    t.check(refused.headers['retry-after'] === '5',
            'B: with Retry-After', JSON.stringify(refused.headers));
    t.check(!refused.headers.location && !refused.headers['set-cookie'],
            'B: and none of the handler\'s Location or Set-Cookie — a ' +
            'redirect or a session cookie for a write that did not land is ' +
            'a success by another name', JSON.stringify(refused.headers));
    t.check(!!body && body.error === 'temporarily_unavailable' &&
            !/STS-/.test(refused.text),
            'B: the body says temporarily_unavailable and names no error ' +
            'code', refused.text);
    t.check(/frame-ancestors/.test(String(
      refused.headers['content-security-policy'])),
            'B: and the security headers every response carries stay',
            String(refused.headers['content-security-policy']));

    // 3. A READ: answered at once, no commit asked for.
    state.commits.length = 0;
    const read = await request(port, 'GET', '/test/aac/read');
    t.check(read.status === 200 && state.commits.length === 0,
            'B: a request that wrote nothing is answered at once',
            JSON.stringify({ status: read.status,
                             commits: state.commits.length }));

    // 4. A WRITING METHOD WHILE A REFUSED WRITE WAITS FOR ITS RETRY — and
    // first the control: with nothing waiting, the same request is answered
    // at once.
    const control = await request(port, 'POST', '/test/aac/noop');
    t.check(control.status === 200 && state.commits.length === 0,
            'B: THE CONTROL — a writing method that changed nothing, with no ' +
            'refused write waiting, is answered at once',
            JSON.stringify({ status: control.status,
                             commits: state.commits.length }));
    state.backlog = true;
    state.autoAnswer = [{ written: false, error: 'still refusing' }];
    const noop = await request(port, 'POST', '/test/aac/noop');
    t.check(state.commits.length === 1 && noop.status === 503,
            'B: while a refused write waits for its retry, a writing request ' +
            'that changed nothing itself is held for it too — the retry of a ' +
            'DELETE answered 503 must not be told 404 "done" before the ' +
            'store holds the delete', JSON.stringify({
              commits: state.commits.length, status: noop.status }));
    const readDuring = await request(port, 'GET', '/test/aac/read');
    t.check(readDuring.status === 200 && state.commits.length === 1,
            'B: and a read is still answered from memory at once',
            JSON.stringify({ status: readDuring.status,
                             commits: state.commits.length }));
    state.backlog = false;
    state.autoAnswer = null;
  } finally {
    server.close();
  }
  log.debug("Leaving theApp().");
}

// ---------------------------------------------------------------------------
// C. An LDAP add, through the handlers ldap_server.js registered.
// ---------------------------------------------------------------------------
async function theDirectory(t, state) {
  log.debug("Entering theDirectory().");
  t.log.info('=== C. an LDAP write is answered after its commit ===');
  const ldap = require('ldapjs');
  const ldapServer = require('../ldap/ldap_server');
  const USERS = 'ou=users,dc=example,dc=com';
  function socketRequest(dn, attributes) {
    log.debug("Entering socketRequest().");
    log.debug("Leaving socketRequest().");
    return {
      connection: { encrypted: false,
                    ldap: { bindDN: 'cn=anonymous', id: 'aac-connection' },
                    remoteAddress: '127.0.0.1', remotePort: 40000 },
      dn: ldap.parseDN(dn),
      attributes: attributes
    };
  }
  function person(uid) {
    log.debug("Entering person().");
    log.debug("Leaving person().");
    return [{ type: 'objectClass', values: ['top', 'inetOrgPerson'] },
            { type: 'uid', values: [uid] },
            { type: 'cn', values: [uid] },
            { type: 'sn', values: [uid] }];
  }
  // The moving position: the add changes the directory, and in memory mode
  // the real store does not count it, so the stub is moved by the
  // directory's own change door.
  const persistence = require('../persistence/persistence');
  const directoryChanged = persistence.directoryChanged;
  persistence.directoryChanged = function () {
    log.debug("Entering the counting directoryChanged().");
    state.directory += 1;
    log.debug("Leaving the counting directoryChanged().");
    return directoryChanged.apply(persistence, arguments);
  };
  try {
    // THE WORKER'S HALF: performOperation(), whose outcome the front
    // process writes to the socket.
    state.autoAnswer = [{ written: false, error: 'the pool is exhausted' }];
    const refusedShape = ldapServer.operationRequest('add',
      socketRequest('uid=aac-refused,' + USERS, person('aac-refused')));
    const refused = await Promise.resolve(ldapServer.performOperation('add',
      JSON.parse(JSON.stringify(refusedShape))));
    t.check(!!refused && refused.ok === false &&
            refused.errorName === 'UnavailableError',
            'C: AN LDAP ADD WHOSE COMMIT FAILED, RUN AS A WORKER RUNS IT, IS ' +
            'REFUSED UNAVAILABLE and never a success', JSON.stringify(refused));
    t.check(new ldap.UnavailableError('x').code === 52,
            'C: which is result code 52', '');

    state.autoAnswer = [{ written: true }, { written: false }];
    const madeShape = ldapServer.operationRequest('add',
      socketRequest('uid=aac-made,' + USERS, person('aac-made')));
    const made = await Promise.resolve(ldapServer.performOperation('add',
      JSON.parse(JSON.stringify(madeShape))));
    t.check(!!made && made.ok === true,
            'C: and one whose commit lands is its ordinary success',
            JSON.stringify(made));

    // THE SOCKET'S HALF: the registered handler with an ldapjs-shaped
    // response, whose end() must not be called with the success first.
    state.autoAnswer = null;
    state.commits.length = 0;
    const handler = ldapServer.localHandler('add');
    const out = { ended: 0, failure: null, nexts: 0 };
    const res = {
      messageId: 9,
      end: function () {
        log.debug("Entering the test end().");
        out.ended += 1;
        log.debug("Leaving the test end().");
      },
      send: function () {
        log.debug("Entering the test send().");
        log.debug("Leaving the test send().");
      }
    };
    handler(socketRequest('uid=aac-socket,' + USERS, person('aac-socket')),
            res, function (err) {
      out.nexts += 1;
      if (err) {
        out.failure = err;
      }
    });
    for (let i = 0; i < 50 && !state.commits.length; i += 1) {
      await settle();
    }
    t.check(state.commits.length === 1 && out.ended === 0 &&
            out.nexts === 0,
            'C: on the socket, the result is not sent while its commit is ' +
            'out', JSON.stringify(out));
    state.commits[0].resolve([{ written: false, error: 'the fence refused' }]);
    for (let i = 0; i < 20; i += 1) {
      await settle();
    }
    t.check(out.ended === 0 && !!out.failure && out.failure.code === 52,
            'C: and a failed commit is sent as unavailable (52) through ' +
            'next(), never the success', JSON.stringify({
              ended: out.ended, code: out.failure && out.failure.code }));
  } finally {
    persistence.directoryChanged = directoryChanged;
    state.autoAnswer = null;
  }
  log.debug("Leaving theDirectory().");
}

// ---------------------------------------------------------------------------
// D. The liveness connection, against a `pg` whose pool is exhausted.
// ---------------------------------------------------------------------------
function exhaustiblePg(db) {
  log.debug("Entering exhaustiblePg().");
  function answer(sql, params, via) {
    const text = String(sql);
    db.statements.push({ via: via, sql: text, params: params || [] });
    if (/^INSERT INTO sts_cluster_claims/.test(text)) {
      return Promise.resolve({ rowCount: 1, rows: [
        { claimed_at: 1, expires_at: 30001 }] });
    }
    if (/^UPDATE sts_cluster_claims SET expires_at/.test(text)) {
      return Promise.resolve({ rowCount: 1, rows: [] });
    }
    if (/^WITH n AS \(UPDATE sts_cluster_nodes/.test(text)) {
      return Promise.resolve({ rowCount: 1, rows: [{ alive: 1, leases: [] }] });
    }
    return Promise.resolve({ rowCount: 0, rows: [] });
  }
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    return answer(sql, params, 'client');
  };
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () {
    if (db.clientRefuses) {
      return Promise.reject(new Error('too many clients already'));
    }
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  // AN EXHAUSTED POOL never hands out a connection: every caller waits.
  FakePool.prototype.connect = function () {
    if (db.exhausted) {
      return new Promise(function () {});
    }
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = function (sql, params) {
    if (db.exhausted) {
      db.statements.push({ via: 'pool-waiting', sql: String(sql),
                           params: params || [] });
      return new Promise(function () {});
    }
    return answer(sql, params, 'pool');
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  log.debug("Leaving exhaustiblePg().");
  return { Pool: FakePool, Client: FakeClient };
}

function bounded(promise, ms) {
  log.debug("Entering bounded().");
  let timer = null;
  const late = new Promise(function (resolve) {
    timer = setTimeout(function () {
      resolve('timed out');
    }, ms);
  });
  log.debug("Leaving bounded().");
  return Promise.race([promise, late]).then(function (value) {
    clearTimeout(timer);
    return value;
  });
}

async function theLivenessConnection(t) {
  log.debug("Entering theLivenessConnection().");
  t.log.info('=== D. the renewal does not queue behind the writes ===');
  const postgres = require('../persistence/persistence_postgres');
  const db = { statements: [], exhausted: false, clientRefuses: false };
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: exhaustiblePg(db) };
  let driver = null;
  try {
    driver = postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} } });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
  const adopted = await driver.adoptOrigin({ name: 'node-b:protocol-0',
                                             ttlMs: 30000 });
  t.check(adopted.adopted, 'D: the process takes its origin',
          JSON.stringify(adopted));

  db.exhausted = true;
  db.statements.length = 0;
  const renewed = await bounded(driver.renewOrigin(30000), 2000);
  t.check(renewed === true,
          'D: THE ORIGIN RENEWAL SUCCEEDS WHILE EVERY POOLED CONNECTION IS ' +
          'TAKEN (on testidp it waited on the pool, the claim lapsed, and ' +
          'the worker exited)', String(renewed));
  t.check(db.statements.length === 1 && db.statements[0].via === 'client',
          'D: on the liveness connection, not the pool',
          JSON.stringify(db.statements.map(function (one) {
            return one.via;
          })));
  db.statements.length = 0;
  const beat = await bounded(driver.heartbeat('node-b', 30000, null), 2000);
  t.check(beat && beat.alive === true && db.statements.length === 1 &&
          db.statements[0].via === 'client',
          'D: and so does the cluster heartbeat',
          JSON.stringify({ beat: beat, via: db.statements.map(function (o) {
            return o.via;
          }) }));
  const leased = await bounded(driver.releaseLease('scheduler', 'node-b', 3),
                               2000);
  t.check(leased !== 'timed out',
          'D: and a lease statement', String(leased));

  // A liveness connection that cannot be opened falls back to the pool.
  db.exhausted = false;
  db.clientRefuses = true;
  const second = (function () {
    require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                              exports: exhaustiblePg(db) };
    try {
      return postgres.create({
        url: 'postgres://sts_app@localhost:5432/sts',
        log: { debug: function () {}, info: function () {},
               warn: function () {}, error: function () {} } });
    } finally {
      if (previous) {
        require.cache[pgPath] = previous;
      } else {
        delete require.cache[pgPath];
      }
    }
  })();
  db.statements.length = 0;
  const viaPool = await bounded(second.heartbeat('node-c', 30000, null), 2000);
  t.check(viaPool && viaPool.alive === true &&
          db.statements.some(function (one) {
            return one.via === 'pool';
          }) && second.livenessStatus().viaPool === 1,
          'D: a liveness connection that cannot be opened sends the ' +
          'statement through the pool rather than failing it',
          JSON.stringify({ via: db.statements.map(function (o) {
            return o.via;
          }), status: second.livenessStatus() }));

  // THE PURGE KEEPS A LAPSED ORIGIN CLAIM.
  db.clientRefuses = false;
  db.statements.length = 0;
  await bounded(second.purgeClaims(), 2000);
  const purge = db.statements.filter(function (one) {
    return /^DELETE FROM sts_cluster_claims/.test(one.sql);
  })[0];
  t.check(!!purge && /scope <> \$1/.test(purge.sql) &&
          purge.params[0] === 'persistence.origin' &&
          Number(purge.params[1]) >= 60 * 60 * 1000,
          'D: A LAPSED ORIGIN CLAIM IS NOT PURGED WITH THE OTHERS — a purged ' +
          'row reads to its owner as "taken", and the owner exits on a claim ' +
          'nobody holds', JSON.stringify(purge));
  log.debug("Leaving theLivenessConnection().");
}

async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  const out = process.env.PROBE_OUT;
  const t = recordingHarness();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-aac-'));
  let threw = '';
  try {
    await journalAndRetry(t, dir);
    await keyRows(t, dir);
    const state = stubTheStore();
    await theApp(t, state);
    await theDirectory(t, state);
    await theLivenessConnection(t);
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in childMain(): " + ((e && e.message) || e));
    }
  }
  fs.writeFileSync(out, JSON.stringify({ seen: t.seen, threw: threw }));
  log.debug("Leaving childMain().");
  // Timers from the app and the store may still be armed; the answer is out.
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-aac-out-'));
  const outFile = path.join(dir, 'out.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { PROBE_OUT: outFile, LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('the child process reported nothing',
          'status ' + child.status + ', signal ' + child.signal + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the child process threw', result.threw);
  }
  t.check(result.seen.length >= 30,
          'every section ran — a section that stopped being reached would ' +
          'take its assertions with it and still say "passed"',
          String(result.seen.length) + ' assertion(s) recorded');
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'answer_after_commit',
  describe: 'issue #351: a write answered only after its commit (503 / LDAP ' +
            'unavailable when it fails), a failed flush keeping its journal ' +
            'and retrying on its own, the liveness connection for the origin ' +
            'renewal and heartbeat, the lapsed origin claim kept from the ' +
            'purge, and the event-loop delay report',
  run: run
};
