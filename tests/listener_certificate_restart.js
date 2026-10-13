// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: listener_certificate_restart.js
//
// ===========================================================================
// THE LISTENER KEY IS KEPT PER NODE, AND A CHANGED CERTIFICATE IS ANNOUNCED
// (2026-10-08; #264).
//
// Two things about one listener, both visible only ACROSS A RESTART, which is
// `tests/CLAUDE.md`'s clause for an in-process file: no HTTP job can restart
// the service it is talking to.
//
// **THE KEY IS KEPT.** Where minted state persists, each node makes its
// listener key once and keeps it sealed in its own row of `tls.listenerKeys`
// (`unit@node`), with the certificate it last took; a plain restart presents
// the same key AND the same certificate (`tls/CLAUDE.md`, *THE LISTENER KEY
// IS KEPT PER NODE*). Until that date every product restart made a new key.
//
// **A CHANGED CERTIFICATE IS ANNOUNCED (#264).** `tls/tls_server.js` keeps
// what the SERVICE last announced in a persisted shared store
// (`tls.listenerAnnounced`) and compares at `listen()`; a start that presents
// something else sends `tls-certificate-changed`, `restarted`.
//
// Child processes, one after another, share a store the way the lives of one
// service — and its nodes — do:
//
//   1. FIRST START as node-a, over an empty store: its key is stored (sealed),
//      its certificate recorded, nothing announced.
//   2. SECOND START as node-a: the SAME key and the SAME certificate, under the
//      same Root, and nothing announced — the restart rcbj named.
//   3. A START AS node-b: a key of its own (a different one), a new
//      certificate under the same Root, announced once from `listen()` as
//      `restarted` from node-a's fingerprint; and it holds node-b's row ALONE,
//      never node-a's.
//   4. node-a AGAIN WITH tls.selfSignedKeyBits=3072: the 2048-bit key it kept
//      no longer fits, so a new 3072-bit key replaces it (STS-TLS-0048) and the
//      new certificate is announced; it holds node-a's row alone.
//   5. TWO STARTS WITH NO STORE (memory mode): nothing kept, a key per start,
//      nothing announced — which is what the documentation says memory mode
//      cannot do.
//
// The store is `tests/minted_persistence.js`'s stub driver backed by a file,
// in PRODUCT mode with a key-encryption key read from a file shared by the
// children, and the signing keys and certificate authority kept in a second
// file — so every start has the same Root. (An EPHEMERAL key, a dispatched
// development pool's, is no use here: `persistence_minted.js` clears every row
// such a run finds, by design.) Postgres itself is the parent suite's job;
// everything asserted here is above the SQL.
//
// **What would make it fail**: a `settleListenerKey()` that ignores the stored
// row fails 2a and 4c's opposite (the key moves at every start); a
// `heldCertificate` that offers nothing, or a `certifyRegistered()` that does
// not ask it, fails 2b and 2c (a new leaf, announced); a reconciler that
// admits every row fails 3c and 4b; a fit check that ignores the size fails
// 4a.
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
                     keySealed: row.keySealed || '',
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
    const presented = new (require('crypto').X509Certificate)(
      tls.serverCertificate().certPem);
    report.fingerprint = String(presented.fingerprint256).toUpperCase();
    // The KEY, as the certificate carries it and as the socket's own private
    // key derives it — the two must be one key.
    report.keyFingerprint = require('crypto').createHash('sha256')
      .update(presented.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    report.keyMatches = require('crypto').createPublicKey(
      tls.serverCertificate().privateKeyPem)
      .export({ type: 'spki', format: 'der' })
      .equals(presented.publicKey.export({ type: 'spki', format: 'der' }));
    report.keyBits = Number((presented.publicKey.asymmetricKeyDetails || {})
      .modulusLength || 0);
    report.heldKeys = tls.heldListenerKeys();
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

function startOnce(t, dir, label, rowsFile, kek, extra) {
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
                SPIFFE_GRPC_PORT: '0' }, extra || {}),
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
    const j = JSON.stringify;
    const nodeA = { STS_CLUSTER_NODE_NAME: 'node-a' };
    const nodeB = { STS_CLUSTER_NODE_NAME: 'node-b' };

    const first = startOnce(t, dir, 'first', rows, kek, nodeA);
    t.check(first.keys && first.keys.persisting === true &&
            tlsNotices(first).length === 0 &&
            first.fingerprint && heldRsa(first) === first.fingerprint &&
            first.keyMatches === true,
            '1. A FIRST START over an empty store records its listener ' +
            'certificate, presents it with its own key, and announces nothing',
            j([first.keys, tlsNotices(first), first.fingerprint,
               first.held, first.keyMatches]));
    const stored = fs.existsSync(rows) ? fs.readFileSync(rows, 'utf8') : '';
    t.check(stored.indexOf('tls.listenerAnnounced') >= 0 &&
            stored.indexOf('tls.listenerKeys') >= 0 &&
            stored.indexOf(first.fingerprint) < 0 &&
            stored.indexOf('PRIVATE KEY') < 0 &&
            j(Object.keys(first.heldKeys || {})) === j(['rsa@node-a']) &&
            first.heldKeys['rsa@node-a'].certified === true,
            '1b. the record and node-a\'s key are written to the store as ' +
            'SEALED rows — no fingerprint, no PEM private key in the clear — ' +
            'and the key row carries the certificate it was issued',
            j(first.heldKeys));

    const second = startOnce(t, dir, 'second', rows, kek, nodeA);
    t.check(second.keyFingerprint && second.root === first.root &&
            second.keyFingerprint === first.keyFingerprint &&
            second.keyMatches === true,
            '2a. A SECOND START OF THE SAME NODE presents the SAME KEY under ' +
            'the same Root — generated once, not at every restart',
            j([first.keyFingerprint, second.keyFingerprint, first.root,
               second.root]));
    t.check(second.fingerprint === first.fingerprint,
            '2b. and the SAME CERTIFICATE: the one it kept is still current, ' +
            'so it is presented again rather than re-issued',
            j([first.fingerprint, second.fingerprint]));
    t.check(heldRsa({ held: second.heldAtStart }) === first.fingerprint &&
            tlsNotices(second).length === 0 &&
            heldRsa(second) === first.fingerprint,
            '2c. so nothing is announced: the certificate is the one the ' +
            'service last announced', j([second.heldAtStart,
                                         tlsNotices(second)]));

    const other = startOnce(t, dir, 'node-b', rows, kek, nodeB);
    const sent = tlsNotices(other);
    t.check(other.keyFingerprint &&
            other.keyFingerprint !== first.keyFingerprint &&
            other.fingerprint !== first.fingerprint &&
            other.root === first.root && other.keyMatches === true,
            '3a. ANOTHER NODE NAME makes a key of its own — no listener key ' +
            'is shared between nodes — under the same Root',
            j([first.keyFingerprint, other.keyFingerprint, other.root]));
    t.check(other.beforeListen === 0 && sent.length === 1 &&
            sent[0].realm === '*' && sent[0].reason === 'restarted' &&
            sent[0].rotated.some(function (r) {
              return String(r).toUpperCase() === 'RSA ' + first.fingerprint +
                ' -> ' + other.fingerprint;
            }) && heldRsa(other) === other.fingerprint,
            '3b. and its certificate, which is not the one the service last ' +
            'announced, is announced once, from listen() and not before, to ' +
            'every realm, reason "restarted", from node-a\'s fingerprint; ' +
            'the record moves to it', j([other.beforeListen, sent]));
    t.check(j(Object.keys(other.heldKeys || {})) === j(['rsa@node-b']),
            '3c. node-b HOLDS ITS OWN ROW ALONE: node-a\'s key is in the ' +
            'store and was restored into no memory but node-a\'s',
            j(other.heldKeys));

    const resized = startOnce(t, dir, 'node-a-3072', rows, kek,
      Object.assign({ STS_TLS_SELF_SIGNED_KEY_BITS: '3072' }, nodeA));
    t.check(resized.keyBits === 3072 &&
            resized.keyFingerprint !== first.keyFingerprint &&
            resized.keyMatches === true &&
            ((resized.heldKeys || {})['rsa@node-a'] || {}).bits === 3072,
            '4a. A STORED KEY THAT NO LONGER FITS (2048 bits, and ' +
            'tls.selfSignedKeyBits is 3072) is replaced by a new key, and ' +
            'the new one is what is stored',
            j([resized.keyBits, resized.heldKeys]));
    t.check(j(Object.keys(resized.heldKeys || {})) === j(['rsa@node-a']),
            '4b. node-a, too, holds its own row alone after node-b wrote ' +
            'one', j(resized.heldKeys));
    t.check(tlsNotices(resized).length === 1 &&
            tlsNotices(resized)[0].reason === 'restarted',
            '4c. and its new certificate is announced as a restart',
            j(tlsNotices(resized)));

    const memory = startOnce(t, dir, 'memory', '', kek, nodeA);
    const memoryAgain = startOnce(t, dir, 'memory-again', '', kek, nodeA);
    t.check(tlsNotices(memory).length === 0 &&
            tlsNotices(memoryAgain).length === 0 &&
            Object.keys(memory.heldAtStart || {}).length === 0 &&
            Object.keys(memoryAgain.heldAtStart || {}).length === 0,
            '5a. A START WITH NO STORE (memory mode) has no record to ' +
            'compare with, and announces nothing',
            j([memory.heldAtStart, tlsNotices(memory)]));
    t.check(memory.keyFingerprint && memoryAgain.keyFingerprint &&
            memory.keyFingerprint !== memoryAgain.keyFingerprint &&
            memory.keyFingerprint !== first.keyFingerprint,
            '5b. and keeps no key: two starts with no store make two keys, ' +
            'as development always has',
            j([memory.keyFingerprint, memoryAgain.keyFingerprint]));
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
  describe: 'The listener key is kept per node where minted state persists ' +
            '(2026-10-08): a restart of the same node presents the same key ' +
            'and certificate and announces nothing; another node name makes ' +
            'its own key, holds only its own row, and its certificate is ' +
            'announced (tls-certificate-changed, restarted, #264) from ' +
            'listen(); a key that no longer fits the size is replaced; and ' +
            'a start with no store makes a key per start and announces ' +
            'nothing.',
  run: run
};
