'use strict';
//
// File: listener_certificate_restart.js
//
// ===========================================================================
// A LISTENER CERTIFICATE RE-ISSUED AT RESTART IS ANNOUNCED (#264).
//
// `tls-certificate-changed` (#245) was sent only when a certificate the
// RUNNING process had issued was replaced. The listener key is made again at
// every start, so a restart presented a certificate nobody was told about and
// a receiver that pinned it learned nothing. `tls/tls_server.js` now keeps
// what the SERVICE last announced in a persisted shared store
// (`tls.listenerAnnounced`) and compares at `listen()`.
//
// **THE FAILURE IS ONLY VISIBLE ACROSS A RESTART**, which is
// `tests/CLAUDE.md`'s clause for an in-process file: no HTTP job can restart the service it is
// talking to. So three child processes, one after another, share a store the
// way two lives of one service do:
//
//   1. FIRST START, over an empty store: the listener's certificate is
//      recorded and nothing is announced — nothing was announced before it.
//   2. SECOND START, over the store the first one left: its certificate is a
//      new one (a new key), and it is announced once, from `listen()`, to
//      every realm, reason `restarted`, naming the first start's fingerprint
//      as `from` and its own as `to`. The record moves to it.
//   3. A START WITH NO STORE (memory mode): the record is gone with the
//      process, so nothing is announced — which is what the documentation
//      says memory mode cannot do.
//
// The store is `tests/minted_persistence.js`'s stub driver backed by a file,
// in PRODUCT mode with a key-encryption key read from a file shared by the
// children, and the signing keys and certificate authority kept in a second
// file — so the second start has the same Root and only a new listener key.
// (An EPHEMERAL key, a dispatched development pool's, is no use here:
// `persistence_minted.js` clears every row such a run finds, by design.)
// Postgres itself is the parent suite's job; everything asserted here is
// above the SQL.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'listener_certificate_restart',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in each child. Everything it learns goes to LCR_OUT as JSON.
function childMain() {
  const ROOT = process.env.LCR_ROOT;
  const OUT = process.env.LCR_OUT;
  const ROWS = process.env.LCR_ROWS;
  const report = { notices: [], fingerprint: '', held: {}, restored: -1 };
  const pause = function (ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms || 30);
    });
  };
  // The stub driver of tests/minted_persistence.js, keeping its rows in a
  // file so the next child reads what this one wrote.
  function fileDriver(file) {
    const rows = new Map();
    try {
      JSON.parse(fs.readFileSync(file, 'utf8')).forEach(function (row) {
        rows.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key, row);
      });
    } catch (e) {
      // No file yet: the first start, over an empty store.
      report.firstRead = String((e && e.message) || e);
    }
    const save = function () {
      fs.writeFileSync(file, JSON.stringify(Array.from(rows.values())));
    };
    return {
      origin: function () {
        return 'lcr-' + process.pid;
      },
      loadMinted: function () {
        return Promise.resolve(Array.from(rows.values()));
      },
      saveMinted: function (upserts, deletes) {
        upserts.forEach(function (row) {
          rows.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key,
                   { handle: row.handle, realm: row.realm, key: row.key,
                     body: row.body, writtenAt: Date.now() });
        });
        deletes.forEach(function (row) {
          rows.delete(row.handle + '\u0000' + row.realm + '\u0000' + row.key);
        });
        save();
        return Promise.resolve();
      },
      readMinted: function (handle, realm, key) {
        return Promise.resolve(
          rows.get(handle + '\u0000' + realm + '\u0000' + key) || null);
      },
      purgeMinted: function () {
        return Promise.resolve(0);
      }
    };
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const keystore = require(ROOT + '/common/keystore');
    const minted = require(ROOT + '/persistence/persistence_minted');
    const pki = require(ROOT + '/common/pki');
    const tls = require(ROOT + '/tls/tls_server');
    const serviceSignals = require(ROOT + '/ssf/service_signals');
    serviceSignals.keyChanged = function (kind, realmId, notice) {
      report.notices.push({ kind: kind, realm: realmId,
        reason: notice && notice.reason,
        rotated: ((notice && notice.rotated) || []).map(function (r) {
          return r.unit + ' ' + r.from + ' -> ' + r.to;
        }) });
      return Promise.resolve(0);
    };
    if (ROWS) {
      // The signing keys and the certificate authority persist too, in a
      // file of their own — so the second start has the SAME Root and only a
      // new listener key, which is the product-mode restart this is about.
      const keyRows = new Map();
      try {
        JSON.parse(fs.readFileSync(ROWS + '.keys', 'utf8'))
          .forEach(function (row) {
            keyRows.set(row.realm, row);
          });
      } catch (e) {
        report.firstKeys = String((e && e.message) || e);
      }
      const saveKeyRows = function () {
        fs.writeFileSync(ROWS + '.keys',
                         JSON.stringify(Array.from(keyRows.values())));
        return Promise.resolve();
      };
      keystore.setStore({
        loadKeys: function () {
          return Promise.resolve(Array.from(keyRows.values()));
        },
        saveKeys: function (id, cipher) {
          keyRows.set(id, { realm: id, material: cipher });
          return saveKeyRows();
        },
        deleteKeys: function (id) {
          keyRows.delete(id);
          return saveKeyRows();
        }
      });
    }
    report.keys = await keystore.start();
    if (ROWS) {
      minted.setDriver(fileDriver(ROWS), 'postgres');
      report.restored = await minted.restore();
    }
    report.heldAtStart = tls.lastAnnouncedListenerCertificates();
    await pki.start();
    await pause(100);
    report.beforeListen = report.notices.length;
    tls.listen();
    await pause(100);
    if (ROWS) {
      await minted.flush();
    }
    report.fingerprint = String(new (require('crypto').X509Certificate)(
      tls.serverCertificate().certPem).fingerprint256).toUpperCase();
    report.held = tls.lastAnnouncedListenerCertificates();
    report.root = String((pki.serviceRoot() || {}).serialHex || '');
    fs.writeFileSync(OUT, JSON.stringify(report));
    process.exit(0);
  })().catch(function (e) {
    report.error = String((e && e.stack) || e);
    fs.writeFileSync(OUT, JSON.stringify(report));
    process.exit(0);
  });
}

function startOnce(t, dir, label, rowsFile, kek) {
  log.debug("Entering startOnce(). " + label);
  const out = path.join(dir, label + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, rowsFile ? {
        // PRODUCT MODE with a key-encryption key read from a file: the
        // configuration whose minted state (and so this record) persists.
        STS_MODE: 'product', STS_KEYS_SOURCE: 'persisted',
        STS_KEYS_KEK_PROVIDER: 'file', STS_KEYS_KEK_FILE: kek
      } : {}, { LOG_LEVEL: 'fatal', LCR_ROOT: ROOT,
                LCR_OUT: out, LCR_ROWS: rowsFile || '',
                SPIFFE_GRPC_PORT: '0' }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // The child died before writing: reported below with its exit and stderr.
    log.debug("Caught in startOnce(): " + ((e && e.message) || e));
    report = null;
  }
  t.check(!!report && !report.error, 'the ' + label + ' child ran to the end',
          report ? String(report.error || '')
                 : 'exit ' + result.status + ' ' +
                   String(result.stderr || '').slice(-1200));
  log.debug("Leaving startOnce(). " + label);
  return report || { notices: [], held: {} };
}

function tlsNotices(report) {
  log.debug("Entering tlsNotices().");
  log.debug("Leaving tlsNotices().");
  return (report.notices || []).filter(function (n) {
    return n.kind === 'tls';
  });
}

function heldRsa(report) {
  log.debug("Entering heldRsa().");
  log.debug("Leaving heldRsa().");
  return String(((report.held || {}).rsa || {}).fingerprint256 || '')
    .toUpperCase();
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lcr-'));
  const rows = path.join(dir, 'rows.json');
  const kek = path.join(dir, 'kek');
  fs.writeFileSync(kek, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  try {
    const first = startOnce(t, dir, 'first', rows, kek);
    const j = JSON.stringify;
    t.check(first.keys && first.keys.persisting === true &&
            tlsNotices(first).length === 0 &&
            first.fingerprint && heldRsa(first) === first.fingerprint,
            '1. A FIRST START over an empty store records its listener ' +
            'certificate and announces nothing',
            j([first.keys, tlsNotices(first), first.fingerprint,
               first.held]));
    t.check(fs.existsSync(rows) &&
            fs.readFileSync(rows, 'utf8').indexOf('tls.listenerAnnounced') >=
              0 &&
            fs.readFileSync(rows, 'utf8').indexOf(first.fingerprint) < 0,
            '1b. the record is written to the store as a sealed row of ' +
            'tls.listenerAnnounced');

    const second = startOnce(t, dir, 'second', rows, kek);
    const sent = tlsNotices(second);
    t.check(heldRsa({ held: second.heldAtStart }) === first.fingerprint,
            '2a. the second start RESTORED the fingerprint the first one ' +
            'announced', j(second.heldAtStart));
    t.check(second.fingerprint && second.fingerprint !== first.fingerprint &&
            first.root && second.root === first.root,
            '2b. and presents a different certificate (a key made at start) ' +
            'under the SAME Root, kept in the store — a product restart',
            j([first.fingerprint, second.fingerprint, first.root,
               second.root]));
    t.check(second.beforeListen === 0 && sent.length === 1 &&
            sent[0].realm === '*' && sent[0].reason === 'restarted' &&
            sent[0].rotated.some(function (r) {
              return String(r).toUpperCase() === 'RSA ' + first.fingerprint +
                ' -> ' + second.fingerprint;
            }),
            '2c. SO IT IS ANNOUNCED, once, from listen() and not before, to ' +
            'every realm, reason "restarted", from the first start\'s ' +
            'fingerprint to its own', j([second.beforeListen, sent]));
    t.check(heldRsa(second) === second.fingerprint,
            '2d. and the record moves to the certificate it announced',
            j(second.held));

    const memory = startOnce(t, dir, 'memory', '', kek);
    t.check(tlsNotices(memory).length === 0 &&
            Object.keys(memory.heldAtStart || {}).length === 0,
            '3. A START WITH NO STORE (memory mode) has no record to ' +
            'compare with, and announces nothing',
            j([memory.heldAtStart, tlsNotices(memory)]));
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is not a test failure.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'listener_certificate_restart',
  describe: 'A listener certificate re-issued at restart is announced ' +
            '(#264): what the service last announced survives in a ' +
            'persisted shared store, a second start presenting another ' +
            'certificate sends tls-certificate-changed (restarted) from ' +
            'listen(), and a start with no store announces nothing.',
  run: run
};
