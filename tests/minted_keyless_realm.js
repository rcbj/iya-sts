'use strict';
//
// File: minted_keyless_realm.js
//
// ===========================================================================
// A PRODUCT-MODE REALM IN A KEYLESS DEVELOPMENT PROCESS IS SAID ONCE, AND A
// KEYLESS PRODUCT PROCESS IS STILL AN ERROR ON EVERY FLUSH (2026-09-14).
//
// `persistence_minted.js`'s `enabled()` reads `global.mode` through the
// AMBIENT realm, and a flush scheduled from a request inherits that request's
// realm. So a development process on a postgres store, with no key-encryption
// key, serving a realm that carries `global.mode: product`, reached flush()'s
// no-key branch on every flush that realm's traffic scheduled and logged
// STS-STORE-0018 at ERROR each time — eleven lines in one postgres-mode suite
// run, about a configuration stated once. That branch was written for a
// PRODUCT PROCESS whose keystore is not open, which is a real failure and
// stays one.
//
// Three claims, read off the process's own log lines:
//   1. the realm case writes nothing and says STS-STORE-0018 exactly ONCE, at
//      warn, however many flushes it takes;
//   2. the process case writes nothing and says it at ERROR on every flush;
//   3. `enabled()` is unchanged in both — it is what `restore()` reads, and a
//      keyless product process must still fail that fatally.
//
// In a CHILD PROCESS: it creates a realm, switches the process's own mode,
// and has to read the module's log output, which goes to stdout.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'minted_keyless_realm',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.KEYLESS_CHILD_OUT;
  const ROOT = process.env.KEYLESS_CHILD_ROOT;
  const lines = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = function (chunk) {
    String(chunk).split('\n').forEach(function (one) {
      if (one.indexOf('STS-STORE-0018') >= 0) {
        try {
          lines.push(JSON.parse(one));
        } catch (e) {
          lines.push({ level: -1, msg: one });
        }
      }
    });
    return write.apply(null, arguments);
  };
  const main = async function () {
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const keystore = require(ROOT + '/common/keystore');
    const minted = require(ROOT + '/persistence/persistence_minted');
    const store = realms.map({ persist: 'test.mintedKeyless.map' });
    const rows = [];
    const driver = {
      origin: function () { return 'keyless-test'; },
      loadMinted: function () { return Promise.resolve([]); },
      saveMinted: function (upserts) {
        upserts.forEach(function (row) { rows.push(row); });
        return Promise.resolve();
      },
      readMinted: function () { return Promise.resolve(null); },
      purgeMinted: function () { return Promise.resolve(0); }
    };
    note(!keystore.sealed(), 'precondition: this process holds no ' +
         'key-encryption key');
    minted.reset();
    note(minted.setDriver(driver, 'postgres') !== false,
         'precondition: the stub driver is accepted');

    // 1. A PRODUCT REALM IN A DEVELOPMENT PROCESS.
    const created = realms.create({ id: 'keyless-product', name: 'keyless',
      overrides: { 'global.mode': 'product' } });
    note(created && created.ok !== false, 'precondition: the product realm ' +
         'was created', JSON.stringify(created));
    const realm = realms.get('keyless-product');
    for (let i = 0; i < 4; i++) {
      await realms.run(realm, async function () {
        store.set('row-' + i, { n: i });
        note(minted.enabled() === true, 'enabled() is still true in the ' +
             'product realm (flush ' + (i + 1) + ') — restore() reads it');
        await minted.flush();
      });
    }
    const realmLines = lines.splice(0);
    note(rows.length === 0, 'NOTHING IS WRITTEN for the realm without a key',
         String(rows.length));
    note(realmLines.length === 1,
         'A PRODUCT REALM IN A KEYLESS DEVELOPMENT PROCESS SAYS STS-STORE-0018 ' +
         'EXACTLY ONCE over four flushes — it logged an error on every one',
         JSON.stringify(realmLines.map(function (l) { return l.level; })));
    note(realmLines.length > 0 && realmLines[0].level === 40,
         'and says it at WARN, because the process is not failing — the ' +
         'realm\'s minted state is simply held in memory',
         realmLines.length ? String(realmLines[0].level) : 'none');

    // 2. A PRODUCT PROCESS WITH NO KEY.
    config.setOverride('global.mode', 'product');
    for (let i = 0; i < 3; i++) {
      store.set('process-row-' + i, { n: i });
      await minted.flush();
    }
    const processLines = lines.splice(0);
    note(rows.length === 0, 'nothing is written for the keyless product ' +
         'process either');
    note(processLines.length === 3 &&
         processLines.every(function (l) { return l.level === 50; }),
         'A KEYLESS PRODUCT PROCESS IS STILL AN ERROR ON EVERY FLUSH — the ' +
         'case the line was written for, and the warn-once must not swallow it',
         JSON.stringify(processLines.map(function (l) { return l.level; })));
    note(minted.enabled() === true, 'and enabled() is true there too');

    config.clearOverride('global.mode');
    realms.remove('keyless-product');
  };
  main().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-minted-keyless-' + process.pid +
                                     '-' + Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    KEYLESS_CHILD_OUT: out, KEYLESS_CHILD_ROOT: root });
  delete env.CONFIG_FILE;
  [
    'STS_MODE', 'STS_KEYS_SOURCE', 'STS_PERSISTENCE_MODE',
    'STS_PERSISTENCE_MINTED', 'STS_WORKERS_REQUEST_COUNT',
    'STS_WORKERS_DISPATCH'
  ].forEach(function (name) {
    delete env[name];
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'minted_keyless_realm',
  describe: 'a product-mode realm in a keyless development process warns ' +
            'once; a keyless product process is still an error per flush',
  run: run
};
