// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/directory_create_worker_release.js
//
// ===========================================================================
// A CREATE A WORKER MADE GIVES ITS CLAIM BACK TO THE FRONT PROCESS (#665,
// 2026-10-17).
//
// On one node the front process decides every directory create's claim in
// memory (`ldap/directory_create_arbiter.ts`, #628), and a request worker
// asks it, and gives the claim back, over the worker channel. The front's
// side of that channel is `common/request_pool.js`'s message handler in
// fork(), and it tested `message.committed` BEFORE `message.createClaim`. A
// worker's release of a claim whose create SUCCEEDED is
// `{ createClaim, op: 'release', committed: true }`: it went to
// receiveCommitted() as a commit announcement and never reached the arbiter.
// So every create a worker made kept its DN and username claimed for the
// claim's whole lifetime, and the next create of that name — the duplicate
// `sts_admin_api_operations` sends to be told "exists", the console account
// `sts_console_after_root` and `sts_portal_sessions` create again — waited
// `CLAIM_WAIT_MS` and was refused 409 STS-LDAP-0092. Only the single-node
// mode met it: memory mode claims nothing, and active-active asks the store.
//
// `tests/directory_create_cluster_claims.js` D had every piece of this but the
// one that was wrong: its front process wired its worker threads to the
// arbiter with a handler of its own, and only READ request_pool.js's (D7).
// This file drives the REAL handler: a child process is the front, with the
// real arbiter, and forks a worker through the real `fork()`
// (`useWorkerModule()`, as `tests/request_worker_replacement.js` does) that
// runs THIS file. The worker claims through the real
// `DirectoryCreateClaims` — the arbiter path, over the real channel — and
// settles as a door does:
//
//   1. a create that SUCCEEDED (`settle(true)`, what `/admin-api/users/
//      create`, SCIM and the console's forms do on success): the front holds
//      nothing afterwards, the same worker creates the name again at once,
//      and the front can claim it with no wait — the defect, which answered
//      STS-LDAP-0092 to both;
//   2. a create that was REFUSED (`settle(false)`): the same, which passed
//      before the fix and is kept as the control;
//   3. a claim still HELD is still refused, to the front and to the worker:
//      routing the message first did not make every claim free.
//
// In process (tests/CLAUDE.md's third question): which message reaches which
// owner in the front process is invisible over HTTP except as a five-second
// wait. The child, because the arbiter and the pool are process-wide.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');
const workerThreads = require('worker_threads');

const log = require('bunyan').createLogger({
  name: 'directory_create_worker_release',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const ROLE_VAR = 'STS_DCWR_ROLE';
const USERS = 'ou=users,dc=example,dc=com';
// Long enough for a claim given back to be taken again, short enough that a
// claim nobody gave back is refused well inside the test's bound.
const WAIT_MS = 1500;

function dnOf(name) {
  log.debug("Entering dnOf().");
  log.debug("Leaving dnOf().");
  return 'uid=' + name + ',' + USERS;
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A claimer as one node's door has it: the front decides (cluster off, not
// active-active), a store that "coordinates" so claims are taken at all, and
// a flush that commits at once. Everything else is the real module.
function claimer() {
  log.debug("Entering claimer().");
  const DCC = require('../ldap/directory_create_claims').DirectoryCreateClaims;
  const persistence = {
    clusterStore: function () {
      return {};
    },
    flush: function () {
      return Promise.resolve({ written: true });
    },
    syncNow: function () {
      return Promise.resolve();
    }
  };
  log.debug("Leaving claimer().");
  return new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () {
      return false;
    },
    clusterMode: function () {
      return 'off';
    },
    loadPersistence: function () {
      return persistence;
    }
  }));
}

// ===========================================================================
// THE WORKER: a thread the real pool forked on this file. It speaks the
// pool's start handshake (`begin` in, `ready` out) and answers the front's
// `{ dcwr }` commands; its claims go over the real channel.
// ===========================================================================
function workerMain() {
  log.debug("Entering workerMain().");
  const port = workerThreads.parentPort;
  let claims = null;
  const held = new Map();
  port.on('message', function (message) {
    if (message && message.stop) {
      process.exit(0);
    }
    if (message && message.begin) {
      claims = claimer();
      port.postMessage({ ready: true });
      return;
    }
    if (!message || !message.dcwr) {
      return;
    }
    const reply = function (value) {
      port.postMessage({ dcwrDone: true, id: message.id, value: value });
    };
    const name = message.name;
    claims.claim({ realm: 'default', dns: [dnOf(name)], usernames: [name],
                   waitMs: message.waitMs }).then(function (claim) {
      if (!claim.ok) {
        reply(claim.code || 'refused');
        return null;
      }
      if (message.cmd === 'hold') {
        held.set(name, claim);
        reply('held');
        return null;
      }
      // A door's two outcomes: the create succeeded, or it was refused.
      return claim.settle(message.cmd === 'create').then(function (back) {
        reply(message.cmd === 'create' ? 'created' : 'refused-and-released');
        return back;
      });
    }).catch(function (e) {
      log.debug("Caught in workerMain(): " + ((e && e.message) || e));
      reply('threw: ' + ((e && e.message) || e));
    });
  });
  log.debug("Leaving workerMain().");
}

// ===========================================================================
// THE FRONT: a child process, with the real arbiter and the real pool.
// ===========================================================================
async function frontChild() {
  log.debug("Entering frontChild().");
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  process.env.STS_WORKERS_REQUEST_COUNT = '1';
  process.env.STS_WORKERS_DISPATCH = '*';
  const pool = require('../common/request_pool');
  const arbiter = require('../ldap/directory_create_arbiter').arbiter;
  pool.reset();
  pool.useWorkerModule(__filename);
  const entry = pool.fork(pool.PROTOCOL_POOL, 0);
  const up = await Promise.race([entry.settled, pause(20000)]);
  if (!up || !entry.ready) {
    await pool.stop(3000);
    log.debug("Leaving frontChild(). The worker did not start.");
    return [{ ok: false, what: 'the worker started', detail: '' }];
  }
  const answers = new Map();
  let nextId = 1;
  // A listener of the test's own beside the pool's, for the replies only.
  entry.child.on('message', function (message) {
    if (message && message.dcwrDone && answers.has(message.id)) {
      const resolve = answers.get(message.id);
      answers.delete(message.id);
      resolve(message.value);
    }
  });
  const command = function (cmd, name, waitMs) {
    return new Promise(function (resolve) {
      const id = nextId;
      nextId += 1;
      answers.set(id, resolve);
      entry.child.send({ dcwr: true, id: id, cmd: cmd, name: name,
                         waitMs: waitMs });
    });
  };
  // What the front's own door (an LDAP add, which claims here) is answered.
  const front = claimer();
  const frontTries = async function (name) {
    const claim = await front.claim({ realm: 'default', dns: [dnOf(name)],
                                      usernames: [name], waitMs: 0 });
    if (claim.ok) {
      await claim.settle(false);
    }
    return claim.ok ? 'ok' : claim.code;
  };
  // The release is a message posted after the reply; it has arrived when the
  // arbiter holds nothing, or not at all.
  const settledLive = async function () {
    for (let i = 0; i < 20 && arbiter.stats().live > 0; i += 1) {
      await pause(25);
    }
    return arbiter.stats().live;
  };

  // 1. A create the worker made, and the same name again.
  const first = await command('create', 'alice', WAIT_MS);
  const liveAfter = await settledLive();
  const frontAfter = await frontTries('alice');
  const startedAt = Date.now();
  const again = await command('create', 'alice', WAIT_MS);
  const waited = Date.now() - startedAt;
  const liveAgain = await settledLive();
  note(first === 'created' && liveAfter === 0 && frontAfter === 'ok' &&
       again === 'created' && waited < WAIT_MS && liveAgain === 0,
       '1. A CREATE A WORKER MADE GIVES ITS CLAIM BACK TO THE FRONT: ' +
       'nothing is held after it, the front can take the name at once, and ' +
       'the same name created again is not refused STS-LDAP-0092 after the ' +
       'wait (#665: the release was taken for a commit announcement)',
       JSON.stringify({ first: first, liveAfter: liveAfter,
                        frontAfter: frontAfter, again: again,
                        waitedMs: waited, liveAgain: liveAgain }));

  // 2. A create the worker refused (the control: this passed before #665).
  const refusedThen = await command('refuse', 'bob', WAIT_MS);
  const liveRefused = await settledLive();
  const frontRefused = await frontTries('bob');
  note(refusedThen === 'refused-and-released' && liveRefused === 0 &&
       frontRefused === 'ok',
       '2. and a create the worker refused gives its claim back too',
       JSON.stringify({ refusedThen: refusedThen, live: liveRefused,
                        front: frontRefused }));

  // 3. A claim still held is still refused, to the front and the worker.
  const holding = await command('hold', 'carol', WAIT_MS);
  const frontHeld = await frontTries('carol');
  const workerHeld = await command('create', 'carol', 100);
  note(holding === 'held' && frontHeld === 'STS-LDAP-0092' &&
       workerHeld === 'STS-LDAP-0092' && arbiter.stats().live === 2,
       '3. a claim the worker still HOLDS is still refused, to the front and ' +
       'to the worker\'s own second create: routing the message first freed ' +
       'nothing it should not have',
       JSON.stringify({ holding: holding, front: frontHeld,
                        worker: workerHeld, live: arbiter.stats().live }));

  await pool.stop(3000);
  pool.reset();
  log.debug("Leaving frontChild().");
  return findings;
}

// ===========================================================================
// THE PARENT.
// ===========================================================================
function runChild() {
  log.debug("Entering runChild().");
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
                                               STS_LOG_LEVEL: 'fatal' });
  env[ROLE_VAR] = 'front';
  delete env.CONFIG_FILE;
  const done = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 90000,
      maxBuffer: 1 << 26 });
  const line = String(done.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('RESULT ') === 0;
  })[0];
  if (!line) {
    log.debug("Leaving runChild(). No result.");
    return { error: 'the front child printed no result (status ' +
             done.status + '): ' + String(done.stderr || '').slice(-3000) };
  }
  log.debug("Leaving runChild().");
  return JSON.parse(line.slice('RESULT '.length));
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== one node: a worker\'s create claims, given back through ' +
             'the real pool handler ===');
  const got = runChild();
  if (got.error) {
    t.bad('the front child could not run', got.error);
    log.debug("Leaving run(). The child failed.");
    return;
  }
  got.findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_create_worker_release',
  describe: 'a create a request worker made gives its claim back to the ' +
            'front process\'s arbiter through request_pool.js\'s real ' +
            'message handler (#665)',
  run: run
};

// ---------------------------------------------------------------------------
// THE CHILD AND THE WORKER.
// ---------------------------------------------------------------------------
function childEntry() {
  log.debug("Entering childEntry().");
  frontChild().then(function (findings) {
    process.stdout.write('RESULT ' + JSON.stringify({ findings: findings }) +
                         '\n');
    process.exit(0);
  }, function (e) {
    log.debug("Caught in childEntry(): " + ((e && e.message) || e));
    process.stdout.write('RESULT ' + JSON.stringify({
      error: (e && e.stack) || String(e) }) + '\n');
    process.exit(0);
  });
  log.debug("Leaving childEntry().");
}

if (!workerThreads.isMainThread && process.env.STS_REQUEST_WORKER === '1' &&
    process.env[ROLE_VAR] === 'front') {
  workerMain();
} else if (require.main === module && process.env[ROLE_VAR] === 'front') {
  childEntry();
}
