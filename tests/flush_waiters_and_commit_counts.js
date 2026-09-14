'use strict';
//
// File: flush_waiters_and_commit_counts.js
//
// ===========================================================================
// TWO SIGNALS THE PERSISTENCE LAYER GIVES THE REST OF THE SERVICE, AND BOTH
// WERE WRONG IN A WAY NO ENDPOINT SHOWS (2026-09-13).
//
// ---------------------------------------------------------------------------
// A. A FLUSH ASKED FOR WHILE ONE IS RUNNING IS ONE QUEUED FLUSH, NOT ONE PER
//    CALLER.
//
// `persistence.flush()` answered a caller that arrived during a flush with
// `flushing.then(flush)` — a waiter of its own. In postgres mode every write
// arms a zero-delay timer that calls it, so every write made while a
// transaction was open added a waiter, and when that transaction settled every
// waiter ran, one started the next flush, and all the others chained
// themselves AGAIN. They never drained while the writes went on.
//
// Measured on a single-process postgres service during the fifty-thousand
// entry LDAP load: over 3 GB of the 6.6 GB allocated in fifteen seconds was in
// that one line and the promises under it, RSS climbed from 1 GB to 4.2 GB with
// GC stalls of 2.6s and 5.3s, and one run ended in `FATAL ERROR: Ineffective
// mark-compacts near heap limit … JavaScript heap out of memory`. On the suite's
// `postgres` mode that was `sts_directory_bulk_load_ldap_50k` failing with
// `fetch failed` on its read-back. With one queued flush the same load took
// 19.2s instead of 50.3s and peaked at 815 MB.
//
// What is asserted is the property that makes the waiters bounded: two calls
// made during one flush are handed the SAME promise, and it settles after a
// flush that began after both of them — so a write made before either call is
// on disk when it resolves. It runs in a CHILD PROCESS because it opens a
// store, which is process-wide state every later file in `run.js`'s one
// process would otherwise inherit.
//
// ---------------------------------------------------------------------------
// B. THE POSTGRES DRIVER COUNTS A CHANGE ROW WHEN IT IS COMMITTED.
//
// `changeRowsWritten()` is read by a request worker either side of its flush
// to say whether it `wrote`, and by the front process to decide whether its
// own writes make every worker stale. Both readers mean COMMITTED. The counter
// moved when the INSERT was built, so an open transaction — and one about to
// roll back — had already moved it. Asserted against a `pg` whose COMMIT this
// file releases by hand, which is the only way to look inside the window.
// ===========================================================================

const path = require('path');
const fs = require('fs');
const os = require('os');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'flush_waiters_and_commit_counts',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_FLUSH_WAITERS_CHILD';

// ---------------------------------------------------------------------------
// THE CHILD: an ldif store in a temporary directory, one dirty setting, and
// three calls to flush() made before the first has had a chance to settle.
// ---------------------------------------------------------------------------
async function child() {
  log.debug("Entering child().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-flush-waiters-'));
  const out = { dir: dir };
  try {
    delete process.env.CONFIG_FILE;
    process.env.STS_PERSISTENCE_MODE = 'ldif';
    process.env.STS_PERSISTENCE_DATA_DIR = dir;
    process.env.STS_PERSISTENCE_APPCONFIG = 'true';
    process.env.STS_PERSISTENCE_REALMS = 'true';
    process.env.STS_PERSISTENCE_WRITE_DELAY = '0';
    const config = require('../common/config');
    const persistence = require('../persistence/persistence');
    persistence.setDirectory({
      realmEntries: function () {
        log.debug("Entering realmEntries().");
        log.debug("Leaving realmEntries().");
        return [];
      },
      replaceRealm: function () {
        log.debug("Entering replaceRealm().");
        log.debug("Leaving replaceRealm().");
        return undefined;
      }
    });
    await persistence.start();
    out.enabled = persistence.enabled();

    config.setOverride('audit.maxEvents', '1234');
    const first = persistence.flush();
    const second = persistence.flush();
    const third = persistence.flush();
    out.secondIsThird = second === third;
    out.secondIsFirst = second === first;
    // A write made AFTER the second and third calls, while the first flush is
    // still running: it must be on disk once the queued flush settles too,
    // because that flush takes the journal when it STARTS.
    config.setOverride('audit.maxEvents', '4321');
    const fourth = persistence.flush();
    out.fourthIsSecond = fourth === second;

    const answers = [];
    for (let i = 0; i < 20000; i += 1) {
      answers.push(persistence.flush());
    }
    out.distinctDuringOneFlush = new Set(answers).size;

    await Promise.all([first, second, third, fourth].concat(answers));
    const file = path.join(dir, 'appconfig.json');
    out.onDisk = fs.existsSync(file)
      ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
    await persistence.stop();
  } catch (e) {
    log.debug("Caught in child(): " + ((e && e.message) || e));
    out.error = (e && e.stack) || String(e);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in child(): " + ((e && e.message) || e));
    }
  }
  process.stdout.write('RESULT ' + JSON.stringify(out) + '\n');
  log.debug("Leaving child().");
}

function runChild() {
  log.debug("Entering runChild().");
  const env = Object.assign({}, process.env);
  env[CHILD_FLAG] = '1';
  env.LOG_LEVEL = 'fatal';
  const done = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000, maxBuffer: 1 << 26 });
  const line = String(done.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('RESULT ') === 0;
  })[0];
  log.debug("Leaving runChild().");
  if (!line) {
    return { error: 'the child printed no result (status ' + done.status +
             '): ' + String(done.stderr || '').slice(-2000) };
  }
  return JSON.parse(line.slice('RESULT '.length));
}

async function checkOneQueuedFlush(t) {
  log.debug("Entering checkOneQueuedFlush().");
  t.log.info('=== a flush asked for during a flush is ONE queued flush ===');
  const got = runChild();
  if (got.error) {
    t.bad('the child could not run', got.error);
    log.debug("Leaving checkOneQueuedFlush().");
    return;
  }
  t.check(got.enabled, 'the ldif store opened in the child', '');
  t.check(got.secondIsThird,
          'two callers arriving while a flush runs are handed ONE promise',
          'THE WAITER STORM: a promise per caller is a waiter per write, and ' +
          'each one re-chained itself on every commit until the writes ' +
          'stopped');
  t.check(!got.secondIsFirst,
          'and it is not the running flush — it is one that starts after it',
          'a caller whose write landed during a flush needs a flush that ' +
          'begins afterwards');
  t.check(got.fourthIsSecond,
          'a caller after another write joins that same queued flush', '');
  t.equal(got.distinctDuringOneFlush, 1,
          'twenty thousand calls during one flush get one promise between ' +
          'them');
  const saved = (got.onDisk && got.onDisk.overrides) || {};
  t.check(String(saved['audit.maxEvents']) === '4321',
          'and when it settles the LAST write is on disk, including one made ' +
          'after those callers arrived',
          JSON.stringify(got.onDisk));
  log.debug("Leaving checkOneQueuedFlush().");
}

// ---------------------------------------------------------------------------
// B, in process: a `pg` stand-in whose COMMIT waits to be released.
// ---------------------------------------------------------------------------
function gatedPg(state) {
  log.debug("Entering gatedPg().");
  function FakeClient() {}
  FakeClient.prototype.query = function (sql) {
    const text = String(sql);
    if (text === 'COMMIT') {
      return new Promise(function (resolve, reject) {
        state.releaseCommit = function (fail) {
          if (fail) {
            reject(new Error('the commit failed on purpose'));
          } else {
            resolve({ rows: [], rowCount: 0 });
          }
        };
      });
    }
    if (state.failInsert && /INSERT INTO sts_realms/.test(text)) {
      return Promise.reject(new Error('the insert failed on purpose'));
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  log.debug("Leaving gatedPg().");
  return { Pool: FakePool, Client: FakeClient };
}

function driverOver(state) {
  log.debug("Entering driverOver().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: gatedPg(state) };
  try {
    log.debug("Leaving driverOver().");
    return require('../persistence/persistence_postgres').create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
}

function tick() {
  log.debug("Entering tick().");
  log.debug("Leaving tick().");
  return new Promise(function (resolve) { setImmediate(resolve); });
}

async function checkRowsCountAtCommit(t) {
  log.debug("Entering checkRowsCountAtCommit().");
  t.log.info('=== a change row is counted when it is COMMITTED ===');
  const state = {};
  const driver = driverOver(state);
  const rows = [{ id: 'acme', name: 'Acme', description: '',
                  createdAt: new Date().toISOString(), overrides: {} }];

  const saving = driver.saveRealms(rows);
  for (let i = 0; i < 20 && !state.releaseCommit; i += 1) {
    await tick();
  }
  t.check(typeof state.releaseCommit === 'function',
          'the transaction reached its COMMIT', '');
  t.equal(driver.changeRowsWritten(), 0,
          'with the change row recorded and the COMMIT not yet returned, ' +
          'nothing is counted',
          'a worker sampling here would announce a write no other process ' +
          'can fetch');
  state.releaseCommit(false);
  await saving;
  t.equal(driver.changeRowsWritten(), 1,
          'once COMMIT returns, the row is counted');

  state.releaseCommit = null;
  const failing = driver.saveRealms(rows).catch(function (e) {
    log.debug("Caught in checkRowsCountAtCommit(): " +
              ((e && e.message) || e));
    return 'refused';
  });
  for (let i = 0; i < 20 && !state.releaseCommit; i += 1) {
    await tick();
  }
  state.releaseCommit(true);
  t.equal(await failing, 'refused', 'a COMMIT that fails fails the save');
  t.equal(driver.changeRowsWritten(), 1,
          'and counts nothing — the rows it recorded were never committed');

  state.releaseCommit = null;
  state.failInsert = true;
  const rolled = await driver.saveRealms(rows).catch(function (e) {
    log.debug("Caught in checkRowsCountAtCommit(): " +
              ((e && e.message) || e));
    return 'rolled back';
  });
  t.equal(rolled, 'rolled back', 'a statement that fails rolls back');
  t.equal(driver.changeRowsWritten(), 1, 'and counts nothing either');
  log.debug("Leaving checkRowsCountAtCommit().");
}

// ---------------------------------------------------------------------------
// AND THE WORKER READS IT AS "SINCE THE LAST ANNOUNCEMENT". A SOURCE CHECK:
// the announcement runs inside a worker's start() closure, which requires a
// forked service to reach, and what went wrong was which two numbers were
// compared.
// ---------------------------------------------------------------------------
function checkTheWorkerComparesWithItsLastAnnouncement(t) {
  log.debug("Entering checkTheWorkerComparesWithItsLastAnnouncement().");
  t.log.info('=== a worker announces rows committed since it last did ===');
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'common', 'request_worker.js'), 'utf8');
  t.check(/const wrote = committedNow > announcedWritten;/.test(source),
          '`wrote` compares the committed count with the last announced one',
          'sampled either side of one flush, a commit made by the scheduled ' +
          'flush this one waited behind was announced by nobody');
  t.check(!/wroteBefore/.test(source),
          'and no longer with a sample taken as this flush began', '');
  log.debug("Leaving checkTheWorkerComparesWithItsLastAnnouncement().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkOneQueuedFlush(t);
  await checkRowsCountAtCommit(t);
  checkTheWorkerComparesWithItsLastAnnouncement(t);
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1') {
  child().then(function () {
    process.exit(0);
  }, function (e) {
    log.debug("Caught in the child: " + ((e && e.message) || e));
    process.stdout.write('RESULT ' + JSON.stringify({
      error: (e && e.stack) || String(e) }) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'flush_waiters_and_commit_counts',
  describe: 'a flush asked for during a flush is one queued flush, and the ' +
            'postgres driver counts a change row only once it is committed',
  run: run
};
