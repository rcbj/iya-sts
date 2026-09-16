'use strict';
//
// File: truststore_persistence.js
//
// ---------------------------------------------------------------------------
// A RUNTIME TRUST ANCHOR SURVIVES A RESTART, AND A REMOVAL DOES TOO
// (2026-09-12).
//
// Until this date an anchor added through /admin/tls/trust, POST
// /admin-api/tls/trust/add or (in development) POST /tls/trust lived exactly as
// long as the process. It is written to ou=trustAnchors in the DEFAULT realm's
// directory now, which persists wherever the directory does and replicates to
// every other process against the same store. `tls/tls_server.js` and
// `ldap/ldap_server.js` argue the design.
//
// ---------------------------------------------------------------------------
// WHY EVERY SECTION IS A CHILD PROCESS.
//
// Two reasons and either would be enough. A RESTART is only demonstrated by a
// SECOND process reading what the first wrote — an in-process "restore" would
// prove that a function agrees with a Map it just filled. And the truststore is
// one array for the process: `run.js` runs every file in one, and
// `truststore_admin.js` asserts that array is unchanged by it, so a section
// here that installed a fake store or left an anchor behind would fail that
// file about a service that is correct.
//
// The store is `ldif`, in a directory made per run with `mkdtemp` and removed
// in a `finally` — `appconfig_persistence.js`'s arrangement, for its reason: it
// is the one persistence mode that needs no database, and the code under test
// is the directory's, which both store modes share.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'truststore_persistence',
  level: process.env.LOG_LEVEL || 'info' });

delete process.env.CONFIG_FILE;

// ---------------------------------------------------------------------------
// THE CHILD. Selected by argv so this one file is both halves.
// ---------------------------------------------------------------------------
async function child(phase, pemA, pemB) {
  log.debug("Entering child().");
  const report = {};
  const say = function () {
    log.debug("Entering say().");
    process.stdout.write('REPORT' + JSON.stringify(report) + '\n');
    log.debug("Leaving say().");
  };
  require('../common/app');
  const persistence = require('../persistence/persistence');
  require('../ldap/ldap_server');
  const tls = require('../tls/tls_server');

  if (phase === 'semantics') {
    // Replaces the directory's store with one this child controls, which is
    // the only way to stand in for ANOTHER process changing ou=trustAnchors.
    const rows = new Map();
    let throwOnList = false;
    report.partialRefused = tls.setTrustAnchorStore({ list: function () {
      log.debug("Entering list().");
      log.debug("Leaving list().");
      return [];
    } }) === false;
    tls.setTrustAnchorStore({
      list: function () {
        log.debug("Entering list().");
        if (throwOnList) throw new Error('store unreachable');
        log.debug("Leaving list().");
        return Array.from(rows.values());
      },
      write: function (fp, pem, meta) {
        log.debug("Entering write().");
        rows.set(fp,
                 { fingerprint: fp, pem: pem, addedBy: meta.addedBy,
                   addedAt: '' });
        log.debug("Leaving write().");
        return true;
      },
      remove: function (fp) {
        log.debug("Entering remove().");
        log.debug("Leaving remove().");
        return rows.delete(fp);
      }
    });
    const fpOf = function (pem) {
      log.debug("Entering fpOf().");
      log.debug("Leaving fpOf().");
      return new (require('crypto').X509Certificate)(
          pem).fingerprint256.replace(/:/g, '');
    };
    tls.truststore.add(pemA, { actor: 'tester' });
    report.writtenOnAdd = rows.has(fpOf(pemA));
    report.addedByRecorded = (rows.get(fpOf(pemA)) || {}).addedBy === 'tester';
    report.listSaysStored = tls.truststore.list().stored === true;
    report.rowPersisted = tls.truststore.list().anchors.some(function (a) {
      return a.fingerprint256.replace(/:/g, '') === fpOf(pemA) &&
             a.persisted === true;
    });

    // Another process removes A.
    rows.delete(fpOf(pemA));
    const removed = tls.reloadStoredAnchors();
    report.reloadRemovesForgotten = removed.removed === 1 &&
      !tls.truststore.list().anchors.some(function (a) {
        return a.fingerprint256.replace(/:/g, '') === fpOf(pemA);
      });

    // Another process adds B.
    rows.set(fpOf(pemB),
             { fingerprint: fpOf(pemB), pem: pemB, addedBy: 'x', addedAt: '' });
    const added = tls.reloadStoredAnchors();
    report.reloadAddsNew = added.added === 1 &&
      tls.truststore.list().anchors.some(function (a) {
        return a.fingerprint256.replace(/:/g, '') === fpOf(pemB) &&
               a.source === 'runtime';
      });

    // A store that cannot be read is not evidence that anything went away.
    throwOnList = true;
    const unreadable = tls.reloadStoredAnchors();
    report.unreadableLeavesArray = unreadable.removed === 0 &&
      tls.truststore.list().anchors.length === 1;
    throwOnList = false;

    // An anchor the store REFUSED is kept through a reload.
    tls.setTrustAnchorStore({
      list: function () {
        log.debug("Entering list().");
        log.debug("Leaving list().");
        return Array.from(rows.values());
      },
      write: function () {
        log.debug("Entering write().");
        log.debug("Leaving write().");
        return false;
      },
      remove: function (fp) {
        log.debug("Entering remove().");
        log.debug("Leaving remove().");
        return rows.delete(fp);
      }
    });
    tls.truststore.add(pemA, { actor: 'tester' });
    tls.reloadStoredAnchors();
    report.unstoredSurvivesReload = tls.truststore.list().anchors.some(
        function (a) {
      return a.fingerprint256.replace(/:/g, '') === fpOf(pemA) &&
             a.persisted === false;
    });

    // Removing through the door removes from the store.
    tls.setTrustAnchorStore({
      list: function () {
        log.debug("Entering list().");
        log.debug("Leaving list().");
        return Array.from(rows.values());
      },
      write: function (fp, pem) {
        log.debug("Entering write().");
        rows.set(fp, { fingerprint: fp, pem: pem });
        log.debug("Leaving write().");
        return true;
      },
      remove: function (fp) {
        log.debug("Entering remove().");
        log.debug("Leaving remove().");
        return rows.delete(fp);
      }
    });
    tls.truststore.remove(fpOf(pemB));
    report.removeDeletesStored = !rows.has(fpOf(pemB));
    say();
    log.debug("Leaving child().");
    return;
  }

  await persistence.start();
  tls.reloadStoredAnchors();
  const held = function (pem) {
    log.debug("Entering held().");
    const fp = new (require('crypto').X509Certificate)(pem).fingerprint256;
    log.debug("Leaving held().");
    return tls.truststore.list().anchors.filter(function (a) {
      return a.fingerprint256 === fp;
    })[0] || null;
  };
  if (phase === 'add') {
    const result = tls.truststore.add(pemA, { actor: 'tester' });
    report.added = result.added;
    report.persisted = (held(pemA) || {}).persisted === true;
  } else if (phase === 'restart') {
    const back = held(pemA);
    report.restored = !!back;
    report.source = back ? back.source : '';
    report.persisted = back ? back.persisted : false;
    const fp = back ? back.fingerprint256 : '';
    report.removed = fp ? tls.truststore.remove(fp).removed : 0;
  } else if (phase === 'after-remove') {
    report.stillAbsent = !held(pemA);
  }
  await persistence.flush();
  persistence.stop();
  say();
  log.debug("Leaving child().");
}

if (process.argv[2] === '--child') {
  child(process.argv[3], process.env.TRUST_PEM_A, process.env.TRUST_PEM_B)
    .then(function () { process.exit(0); })
    .catch(function (e) {
      process.stdout.write('REPORT' + JSON.stringify({ threw: e.stack }) +
                           '\n');
      process.exit(1);
    });
  return;
}

// ---------------------------------------------------------------------------
// THE PARENT.
// ---------------------------------------------------------------------------
function runChild(t, phase, dir, pems) {
  log.debug("Entering runChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const env = Object.assign(clean, {
    LOG_LEVEL: 'fatal',
    TRUST_PEM_A: pems.a, TRUST_PEM_B: pems.b
    // `STS_TLS_PORT` and `STS_MTLS_PORT` were pinned to 0 here so that
    // requiring the stack could not bind a listener onto a live service. Both
    // settings went with the 8443 and 9443 listeners on 2026-09-16, and
    // nothing this child requires binds anything.
  });
  if (dir) {
    Object.assign(env, {
      STS_PERSISTENCE_MODE: 'ldif', STS_PERSISTENCE_DATA_DIR: dir,
      STS_PERSISTENCE_WRITE_DELAY: '0'
    });
  }
  const result = childProcess.spawnSync(process.execPath,
    [__filename, '--child', phase],
    { env: env, encoding: 'utf8', timeout: 120000 });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('REPORT') === 0;
  })[0];
  try {
    log.debug("Leaving runChild().");
    return line ? JSON.parse(line.slice('REPORT'.length)) :
           { threw: String(result.stderr).slice(-800) };
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    log.debug("Leaving runChild().");
    // Unparseable output — returned as a failure the assertions below print.
    return { threw: String(result.stdout).slice(-800) };
  }
}

async function run(t) {
  log.debug("Entering run().");
  const credentials = require('./tools/pep-credential.js');
  const stamp = process.pid + '-' + Date.now();
  const one = await credentials.mint({ rootSubject: 'CN=truststore-persist A ' +
      stamp + ',O=sts ' +
      'tests',
                                       subject:
                                         'CN=truststore-persist-leaf-a,O=sts ' +
                                                'tests' });
  const two = await credentials.mint({ rootSubject: 'CN=truststore-persist B ' +
      stamp + ',O=sts ' +
      'tests',
                                       subject:
                                         'CN=truststore-persist-leaf-b,O=sts ' +
                                                'tests' });
  const pems = { a: one.anchorPem, b: two.anchorPem };

  t.log.info('=== 1. the reload rules, against a store this file controls ===');
  const s = runChild(t, 'semantics', '', pems);
  t.check(!s.threw, 'the semantics child ran', s.threw);
  t.check(s.partialRefused, 'a store missing write or remove is refused whole');
  t.check(s.writtenOnAdd, 'an anchor added through the door is written to ' +
                          'the store');
  t.check(s.addedByRecorded, 'with the actor who added it');
  t.check(s.listSaysStored && s.rowPersisted,
          'and the list says the truststore is stored and that row is ' +
          'persisted');
  t.check(s.reloadRemovesForgotten,
          'an anchor ANOTHER process removed from the store leaves this ' +
          'listener on reload');
  t.check(s.reloadAddsNew,
          'an anchor another process added reaches this listener on reload, ' +
          'as runtime');
  t.check(s.unreadableLeavesArray,
          'a store that cannot be read changes nothing — it is not evidence ' +
          'of a removal');
  t.check(s.unstoredSurvivesReload,
          'an anchor the store REFUSED stays in force through a reload and ' +
          'reports persisted:false');
  t.check(s.removeDeletesStored, 'removing through the door removes the ' +
                                 'stored entry');

  t.log.info('=== 1b. the two call sites no behavioural section reaches ===');
  // Read as SOURCE, for `version.js`'s reason: binding the listeners to prove
  // the restore runs first would bind ports in a shared run, and driving the
  // replication applier means standing up two processes against one database.
  // What can go wrong at both is a call being deleted, which a behavioural
  // test that calls reloadStoredAnchors() itself would never notice.
  // -------------------------------------------------------------------------
  // WHERE THE STARTUP RESTORE LIVES CHANGED ON 2026-09-16, AND THIS CHECK HAD
  // TO CHANGE SHAPE RATHER THAN MOVE.
  //
  // It was `tls_server.js`'s `listen()`, which restored the stored anchors and
  // then bound 8443 and 9443 — so the check was "the reload statement comes
  // before `start(permissiveServer`". Both listeners were deleted and
  // `listen()` is a no-op, so there is no longer a `start(` in it to be before
  // and the old check could only fail.
  //
  // **WHAT MUST STILL BE TRUE IS THE THING THE OLD CHECK WAS ABOUT**: a
  // process that starts against a store holding anchors must have them in
  // force before it answers anything, because a client certificate now arrives
  // at the MAIN port and is verified against exactly this array. So the
  // requirement is a `reloadStoredAnchors();` statement reached at startup —
  // in `tls_server.js`'s `listen()` as before, or in `server.js` before it
  // binds the main port, which is where the sockets those anchors protect now
  // are. Either satisfies this. The first draft of the listener deletion had
  // neither, and this check is what caught it as the REGRESSION it was rather
  // than a stale test; `listen()` carries the statement again.
  //
  // A STATEMENT on a line of its own, not the text: the first version of this
  // check matched `// reloadStoredAnchors();` and passed a listen() whose
  // restore had been commented out.
  const tlsSource = fs.readFileSync(path.join(__dirname, '..', 'tls',
                                              'tls_server.js'), 'utf8');
  const listenBody = tlsSource.slice(tlsSource.indexOf('function listen() {'));
  const inListen = /^[ \t]*reloadStoredAnchors\(\);/m.test(listenBody);
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'),
                                       'utf8');
  const serverReload =
      /^[ \t]*tlsServer\.reloadStoredAnchors\(\);/m.exec(serverSource);
  const mainBindAt = serverSource.indexOf('mainServer.listen(PORT');
  const inServer = !!serverReload && mainBindAt > 0 &&
                   serverReload.index < mainBindAt;
  t.check(inListen || inServer,
          'the stored anchors are restored at STARTUP, before anything a ' +
          'client certificate reaches answers — in tls_server.js\'s listen() ' +
          'or in server.js before it binds the main port',
          'neither call site has a `reloadStoredAnchors();` statement. This ' +
          'was tls_server.js\'s listen(), which restored them and then bound ' +
          '8443 and 9443; those listeners were deleted on 2026-09-16 and ' +
          'listen() became a no-op, and the restore went with it — so a ' +
          'product service starts with an EMPTY client truststore however ' +
          'many anchors its store holds, and every certificate that used to ' +
          'verify against one is unverified at the main port. Section 2 ' +
          'below cannot see this: it calls reloadStoredAnchors() itself.');
  const ldapSource = fs.readFileSync(path.join(__dirname, '..', 'ldap',
                                               'ldap_server.js'), 'utf8');
  const applyBody = ldapSource.slice(ldapSource.indexOf('applyEntry: ' +
                                                        'function (realmId, ' +
                                                        'key, row) {'),
                                     ldapSource.indexOf('realmEntries: ' +
                                                        'function (realmId) ' +
                                                        '{'));
  t.check((applyBody.match(/isTrustAnchorKey\(realmId, key\)[\s\S]{0,80}reloadTrustAnchorsQuietly\(\)/g) || []).length === 2,
          'both replication appliers (an entry applied, an entry removed) ' +
          're-apply the truststore when the key is under ou=trustAnchors');
  t.check(/tlsServer\.setTrustAnchorStore\(\{/.test(ldapSource),
          'the directory installs itself as the truststore\'s store');

  t.log.info('=== 2. a real restart, against an ldif store ===');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-truststore-test-'));
  try {
    const added = runChild(t, 'add', dir, pems);
    t.check(!added.threw && added.added === 1 && added.persisted,
            'the first process adds an anchor and reports it persisted',
            JSON.stringify(added).slice(0, 600));
    const restarted = runChild(t, 'restart', dir, pems);
    t.check(!restarted.threw && restarted.restored,
            'a SECOND process against the same store has the anchor in its ' +
            'truststore',
            JSON.stringify(restarted).slice(0, 600));
    t.check(restarted.source === 'runtime' && restarted.persisted === true,
            'as a runtime anchor that is persisted',
            JSON.stringify(restarted).slice(0, 300));
    t.check(restarted.removed === 1, 'and removes it');
    const after = runChild(t, 'after-remove', dir, pems);
    t.check(!after.threw && after.stillAbsent,
            'a THIRD process does not bring the removed anchor back',
            JSON.stringify(after).slice(0, 600));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'truststore persistence',
  describe: 'a runtime trust anchor is written to ou=trustAnchors, survives ' +
            'a restart, and a removal does too; the reload rules for another ' +
            'process\'s changes',
  run: run
};
