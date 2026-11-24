// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pkcs11_reconnect.js
//
// ===========================================================================
// AN HSM RECONNECT IS SINGLE-FLIGHT PER PROCESS (#1955 P8, rcbj 2026-11-23:
// "fix it"). Every request worker is a `worker_threads` Worker that loads
// the PKCS#11 binding and `common/crypto_impl/pkcs11.js` itself, while
// C_Finalize and C_Initialize are the process's. Two threads that met an
// outage at the same moment both finalized the module, the second after the
// first had initialised it again, and the first's retry failed
// (STS-KEYS-0201): a spurious failed signature during an outage. The fix is
// a lock and a generation in a SharedArrayBuffer every Worker inherits
// (`worker_threads.setEnvironmentData()`), and this file holds it.
//
// In a CHILD PROCESS per module, whose main thread loads the engine first
// (as the front does, at `crypto.js`'s require) and then starts two worker
// threads on the same module path:
//
//   * a FAKE binding (`tests/tools/fake-pkcs11.js`), always. Each thread's
//     fake is its own, so its C_Finalize is counted in a shared counter and
//     made slow (300 ms), which is what holds the two threads inside the
//     window that used to race. Both threads sign, lose the device, meet
//     the barrier and sign again.
//       R1. the module was finalized ONCE for the two outages;
//       R2. both second signatures were made and verify — each caller got
//           the reconnected result, neither was refused;
//       R3. the process's generation moved by exactly one, seen alike by
//           both threads and by the main thread (the table is shared);
//       R4. the thread that did not reconnect took the other's result in:
//           its epoch moved once, its sessions from before were forgotten.
//   * SOFTHSM2 where the image has it: both threads meet an outage at once
//     on sessions of the same generation (`recover()`), and
//       S1. the generation moved by exactly one — one re-initialisation of
//           the real module — and both threads sign after it, verified.
//     Where it is missing that half is SKIPPED, not passed.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const workerThreads = require('worker_threads');

const log = require('bunyan').createLogger({ name: 'pkcs11_reconnect',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SLOW_FINALIZE_MS = 300;

// ONE WORKER THREAD of the child: a token on the module, a key, a
// signature, the outage, the barrier, and the signature after it.
async function workerMain() {
  log.debug('Entering workerMain().');
  const wd = workerThreads.workerData;
  const nodeCrypto = require('crypto');
  const pk = require(ROOT + '/common/crypto_impl/pkcs11');
  const shared = new Int32Array(wd.shared);
  // [0] C_Finalize calls, [1] the barrier, [2] a word nobody moves (the
  // slow finalize waits on it).
  let binding;
  let fake = null;
  if (wd.which === 'fake') {
    fake = require(ROOT + '/tests/tools/fake-pkcs11.js').fakeBinding({
      modulePath: wd.modulePath, tokens: [{ label: 'sts', pin: '1234' }] });
    binding = fake;
    const finalize = binding.PKCS11.prototype.C_Finalize;
    binding.PKCS11.prototype.C_Finalize = function () {
      Atomics.add(shared, 0, 1);
      Atomics.wait(shared, 2, 0, wd.slowMs);
      return finalize.apply(this, arguments);
    };
  } else {
    binding = require(wd.bindingPath);
  }
  const t = pk.openToken(binding, {
    modulePath: wd.modulePath, tokenLabel: wd.which === 'fake' ? 'sts' :
      'reconnect', pin: wd.which === 'fake' ? '1234' : '4321',
    maxSessions: 2 });
  const k = await t.generateKeyPairAsync({ kty: 'EC', crv: 'P-256' },
    'r-' + wd.name, nodeCrypto.randomBytes(8));
  await t.sign(k.key, 'ES256', Buffer.from('before'));
  const epoch0 = t.entry.epoch;
  const gen0 = pk.sharedGeneration(t.entry);
  const reconnects0 = t.reconnects;
  // The barrier: both threads past it at once.
  Atomics.add(shared, 1, 1);
  Atomics.notify(shared, 1);
  for (;;) {
    const at = Atomics.load(shared, 1);
    if (at >= 2) {
      break;
    }
    Atomics.wait(shared, 1, at, 5000);
  }
  let sig = null;
  let error = null;
  try {
    if (fake) {
      fake.loseDevice();
      sig = await t.sign(k.key, 'ES256', Buffer.from('after'));
    } else {
      await t.recover({ code: 0x30, message: 'test outage' }, epoch0, gen0);
      sig = await t.sign(k.key, 'ES256', Buffer.from('after'));
    }
  } catch (e) {
    log.debug('Caught in workerMain(): ' + ((e && e.message) || e));
    error = String((e && e.stack) || e).slice(0, 600);
  }
  const verifies = !!sig && nodeCrypto.verify('sha256', Buffer.from('after'),
    { key: k.publicKey, dsaEncoding: 'ieee-p1363' }, sig);
  workerThreads.parentPort.postMessage({
    name: wd.name, error: error, verifies: verifies,
    epochMoved: t.entry.epoch - epoch0, gen0: gen0,
    gen: pk.sharedGeneration(t.entry), reconnects: t.reconnects - reconnects0
  });
  t.close();
  log.debug('Leaving workerMain().');
}

// THE CHILD PROCESS: the engine loaded here first, then two threads.
async function childMain(which) {
  log.debug('Entering childMain(). ' + which);
  const pk = require(ROOT + '/common/crypto_impl/pkcs11');
  const out = { which: which };
  let modulePath = '/fake/libreconnect-' + process.pid + '.so';
  let bindingPath = null;
  if (which === 'softhsm') {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-pkcs11r-'));
    const conf = dir + '/softhsm2.conf';
    fs.mkdirSync(dir + '/tokens');
    fs.writeFileSync(conf, 'directories.tokendir = ' + dir + '/tokens\n' +
                     'objectstore.backend = file\n');
    process.env.SOFTHSM2_CONF = conf;
    childProcess.execFileSync('softhsm2-util', ['--init-token', '--free',
      '--label', 'reconnect', '--so-pin', '5678', '--pin', '4321'],
      { stdio: 'ignore', env: process.env });
    modulePath = process.env.PR_SOFTHSM_MODULE;
    bindingPath = process.env.PR_PKCS11JS;
  }
  const shared = new SharedArrayBuffer(4 * 4);
  const genBefore = pk.sharedGeneration({ modulePath: modulePath });
  const started = ['a', 'b'].map(function (name) {
    const w = new workerThreads.Worker(__filename, {
      workerData: { pkcs11Reconnect: true, which: which, name: name,
                    modulePath: modulePath, bindingPath: bindingPath,
                    shared: shared, slowMs: SLOW_FINALIZE_MS } });
    return new Promise(function (resolve) {
      w.once('message', resolve);
      w.once('error', function (e) {
        resolve({ name: name, error: String((e && e.stack) || e) });
      });
      w.once('exit', function (code) {
        resolve({ name: name, error: 'the thread exited (' + code + ')' });
      });
    });
  });
  out.threads = await Promise.all(started);
  out.finalizes = Atomics.load(new Int32Array(shared), 0);
  out.genBefore = genBefore;
  out.genAfter = pk.sharedGeneration({ modulePath: modulePath });
  process.stdout.write('PKCS11-RECONNECT ' + JSON.stringify(out) + '\n');
  log.debug('Leaving childMain().');
}

function runChild(which) {
  log.debug('Entering runChild(). ' + which);
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_(?!TEST_)|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    [__filename, '--child', which], {
      env: Object.assign(clean, {
        LOG_LEVEL: 'fatal',
        PR_PKCS11JS: process.env.STS_TEST_PKCS11JS ||
                     '/opt/pkcs11js/node_modules/pkcs11js',
        PR_SOFTHSM_MODULE: process.env.STS_TEST_SOFTHSM_MODULE ||
                           '/usr/lib/softhsm/libsofthsm2.so' }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT });
  const line = String(result.stdout || '').split('\n').find(function (l) {
    return l.indexOf('PKCS11-RECONNECT ') === 0;
  });
  let got = null;
  try {
    got = line ? JSON.parse(line.slice('PKCS11-RECONNECT '.length)) : null;
  } catch (e) {
    log.debug('Caught in runChild(): ' + ((e && e.message) || e));
    got = null;
  }
  log.debug('Leaving runChild().');
  return { got: got, result: result };
}

// Whether this image has SoftHSM2 and the binding.
function softHsmHere() {
  log.debug('Entering softHsmHere().');
  const module = process.env.STS_TEST_SOFTHSM_MODULE ||
                 '/usr/lib/softhsm/libsofthsm2.so';
  const binding = process.env.STS_TEST_PKCS11JS ||
                  '/opt/pkcs11js/node_modules/pkcs11js';
  let util = false;
  try {
    childProcess.execFileSync('softhsm2-util', ['--version'],
                              { stdio: 'ignore' });
    util = true;
  } catch (e) {
    log.debug('Caught in softHsmHere(): ' + ((e && e.message) || e));
    util = false;
  }
  log.debug('Leaving softHsmHere().');
  return util && fs.existsSync(module) && fs.existsSync(binding);
}

function run(t) {
  log.debug('Entering run().');
  const fake = runChild('fake');
  const f = fake.got;
  if (t.check(!!f, 'fake: the child process reported its findings',
              'exit ' + fake.result.status + ' ' +
              String(fake.result.stderr || '').slice(-1500))) {
    const detail = JSON.stringify(f);
    const a = f.threads[0] || {};
    const b = f.threads[1] || {};
    t.check(f.finalizes === 1, 'R1. two threads meeting an outage at the ' +
            'same moment finalize the module ONCE, not once each', detail);
    t.check(!a.error && !b.error && a.verifies && b.verifies,
            'R2. both callers get the reconnected result: each signature ' +
            'after the outage is made and verifies, neither is refused',
            detail);
    t.check(f.genAfter === f.genBefore + 1 && a.gen === f.genAfter &&
            b.gen === f.genAfter, 'R3. the process\'s generation of the ' +
            'module moved by exactly one, and both threads and the main ' +
            'thread read it from the same shared table', detail);
    t.check(a.epochMoved === 1 && b.epochMoved === 1,
            'R4. the thread that waited took the other\'s re-initialisation ' +
            'in: each thread\'s epoch moved once', detail);
  }
  if (softHsmHere()) {
    const soft = runChild('softhsm');
    const s = soft.got;
    if (t.check(!!s, 'softhsm: the child process reported its findings',
                'exit ' + soft.result.status + ' ' +
                String(soft.result.stderr || '').slice(-1500))) {
      const a = s.threads[0] || {};
      const b = s.threads[1] || {};
      t.check(s.genAfter === s.genBefore + 1 && !a.error && !b.error &&
              a.verifies && b.verifies, 'S1. (SoftHSM2) two threads ' +
              'recovering from one outage at once initialise the module ' +
              'again ONCE, and both sign after it', JSON.stringify(s));
    }
  } else {
    t.check(true, 'SKIPPED, NOT PASSED: no SoftHSM2 here, so the reconnect ' +
                  'was held only to the fake module');
  }
  log.debug('Leaving run().');
}

if (!workerThreads.isMainThread && workerThreads.workerData &&
    workerThreads.workerData.pkcs11Reconnect) {
  workerMain().catch(function (e) {
    log.debug('Caught in the worker: ' + ((e && e.message) || e));
    workerThreads.parentPort.postMessage({ error: String((e && e.stack) ||
                                                          e) });
  });
} else if (require.main === module && process.argv[2] === '--child') {
  childMain(process.argv[3]).then(function () {
    process.exit(0);
  }, function (e) {
    log.debug('Caught in the child: ' + ((e && e.message) || e));
    process.stdout.write('PKCS11-RECONNECT-FAILED ' +
                         String((e && e.stack) || e) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'pkcs11_reconnect',
  describe: 'an HSM reconnect is single-flight per process: two worker ' +
            'threads meeting one outage at once re-initialise the PKCS#11 ' +
            'module once, and both get the reconnected result — against a ' +
            'fake module and SoftHSM2',
  run: run
};
