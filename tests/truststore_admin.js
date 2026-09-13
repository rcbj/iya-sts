'use strict';
//
// File: truststore_admin.js
//
// ===========================================================================
// THE CLIENT-CERTIFICATE TRUSTSTORE'S GATED DOORS (2026-09-12).
//
// `/admin/tls/trust` and `/admin-api/tls/trust/{add,remove}` are the runtime
// door product mode did not have: `POST /tls/trust` needs no credential, so
// product mode refuses it, and until these existed an anchor could only come
// from `tls.trustAnchorsFile` at startup. `common/mode.js`'s `truststore-door`
// row recorded exactly that gap.
//
// ---------------------------------------------------------------------------
// WHAT IS HERE, AND WHY IN PROCESS.
//
// Five claims, and each is one a request over HTTP cannot make cleanly:
//
//   1. **THE PRIMITIVES.** A strict add refuses a bundle containing a block
//      OpenSSL cannot read — WHOLE, so the good block beside it is not left in
//      force under a refusal — a duplicate is counted rather than added twice,
//      a remove finds its anchor under either spelling of the fingerprint, a
//      fingerprint it does not hold removes nothing, and every change reaches
//      the `ca` the listeners are built from. Asserted against the real
//      `tls/tls_server.js` in THIS process, with every anchor added removed in
//      a `finally`: the truststore is process-wide, and `run.js` runs every
//      file in one process.
//   2. **THE SLOT IS VALIDATED WHOLE.** `admin.setTruststore()` given two of
//      its three functions refuses, and the layers go on reporting "not
//      installed" rather than listing a truststore they cannot change.
//   3. **THE ACTIONS AND THE VIEW, THROUGH THAT SLOT.** Add, the house refusal
//      sentence both vendored jobs read, remove, paging, and the audit row.
//   4. **THE ROUTING PIN.** Both doors are answered by the process holding the
//      listeners; `/admin/tls` beside them and `/admin-api/tlsx` are not
//      caught by the pin.
//   5. **PRODUCT MODE'S REFUSAL NAMES THE NEW DOORS**, as a real request.
//
// Claims 2, 3 and 5 run in a CHILD PROCESS. Requiring `admin-ui/admin.js`
// registers the whole console on the shared app and pulls the authorization
// server and both SAML profiles in with it, and a file in `run.js`'s one process
// that did that would change what every file after it resolved — the failure
// would land on somebody else's test.
//
// ---------------------------------------------------------------------------
// MUTATION RECORD. Each was applied to a copy of the tree, run, seen red, and
// the copy restored. Ten mutants; all caught, TWO OF THEM ONLY ON THE SECOND
// ROUND, and those two are the part worth keeping.
//
//   * `addAnchors()` ignoring `strict`                       — 6 red (1, 3)
//   * `normalisedFingerprint()` keeping the colons           — 7 red (1)
//   * `setTruststore()` accepting a partial object           — 6 red (2, 3)
//   * the refusal sentence naming a `clear` the switch lacks — 1 red (3)
//   * a remove writing no audit row                          — 1 red (3)
//   * `NEVER_DISPATCHED` losing `/admin-api/tls/trust`       — 4 red (4)
//   * `NEVER_DISPATCHED` naming `/admin/tls` instead         — 3 red (4)
//   * `removeAnchor()` not calling `applyAnchors()`          — 1 red (3).
//     **SURVIVED THE FIRST VERSION**, which compared
//     `clientTruststoreOptions().ca` with the anchor count: that function
//     rebuilds from the array on every call, so it agrees with a remove that
//     never reached a listener. The handshake in section 3 replaced it.
//   * the product refusal's SENTENCE losing the console path — 1 red (5).
//     **SURVIVED THE FIRST VERSION**, which searched the whole JSON body —
//     and the body also carries `console` and `api` members, so the paths
//     were found there while the sentence a person reads had lost one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_TRUSTSTORE_ADMIN_CHILD';

// A bundle OpenSSL will not read, shaped exactly like one it would: the regex
// that finds PEM blocks accepts it, which is the case the strict check exists
// for.
const UNREADABLE = '-----BEGIN CERTIFICATE-----\n' +
  'bm90IGEgY2VydGlmaWNhdGUgYXQgYWxs\n-----END CERTIFICATE-----\n';

// Two fresh certificate authorities, minted on the engine the launchers mint a
// remote PEP's with. Fresh per run, so an anchor this file adds can never
// collide with one anybody else put in the truststore.
async function mintAnchors() {
  const credentials = require('./tools/pep-credential.js');
  const stamp = process.pid + '-' + Date.now();
  const one = await credentials.mint({
    rootSubject: 'CN=truststore-admin A ' + stamp + ',O=mock-sts tests',
    subject: 'CN=truststore-admin-leaf-a,O=mock-sts tests' });
  const two = await credentials.mint({
    rootSubject: 'CN=truststore-admin B ' + stamp + ',O=mock-sts tests',
    subject: 'CN=truststore-admin-leaf-b,O=mock-sts tests' });
  return { a: one.anchorPem, b: two.anchorPem, spare: two.issuing.pem,
           clientA: { cert: one.certPem, key: one.keyPem } };
}

// WHAT A HANDSHAKE ACTUALLY SEES, which is the only honest reading of "the
// change reached the listener". `clientTruststoreOptions().ca` is recomputed
// from the array on every call, so it agrees with a remove that never called
// `setSecureContext()` — the first version of this file asserted that and a
// mutant deleting the apply survived it. So: a listener registered the way
// `server.js` registers the main port, asked-for-never-required like that port,
// reporting `socket.authorized` back to a client presenting a real chain.
function listenerVerifies(server, client) {
  return new Promise(function (resolve) {
    const https = require('https');
    const req = https.request({
      host: '127.0.0.1', port: server.address().port, path: '/', method: 'GET',
      cert: client.cert, key: client.key, rejectUnauthorized: false,
      agent: false
    }, function (res) {
      let text = '';
      res.on('data', function (c) { text += c; });
      res.on('end', function () { resolve(text); });
    });
    req.on('error', function (e) { resolve('error: ' + e.message); });
    req.end();
  });
}

function fingerprintOfPem(pem) {
  const crypto = require('crypto');
  return new crypto.X509Certificate(pem).fingerprint256;
}

// ---------------------------------------------------------------------------
// 1. THE PRIMITIVES, IN THIS PROCESS.
// ---------------------------------------------------------------------------
async function thePrimitives(t) {
  t.log.info('=== 1. strict add, duplicate, remove, and the listeners\' ca ===');
  const tls = require('../tls/tls_server');
  const anchors = await mintAnchors();
  const before = tls.truststore.list().anchors.map(function (one) {
    return one.fingerprint256;
  });
  const mine = [fingerprintOfPem(anchors.a), fingerprintOfPem(anchors.b)];
  try {
    const refused = tls.truststore.add(anchors.a + UNREADABLE);
    t.check(refused.added === 0 && /could not be read by OpenSSL/.test(refused.error || ''),
            'a bundle with one unreadable block is refused, naming why',
            JSON.stringify(refused));
    t.check(tls.truststore.list().anchors.length === before.length,
            'and the READABLE block beside it was not left in force — all or nothing',
            String(tls.truststore.list().anchors.length) + ' vs ' + before.length);

    const added = tls.truststore.add(anchors.a + anchors.b);
    t.equal(added.added, 2, 'two readable CAs are added');
    const listed = tls.truststore.list().anchors.filter(function (one) {
      return mine.indexOf(one.fingerprint256) >= 0;
    });
    t.check(listed.length === 2 && listed.every(function (one) {
      return one.source === 'runtime' && one.readable && one.ca &&
        one.issuer && one.serial && one.notAfter && /BEGIN CERTIFICATE/.test(one.pem);
    }), 'and each is listed as a readable runtime CA with issuer, serial and validity',
            JSON.stringify(listed.map(function (one) {
              return { s: one.source, r: one.readable, ca: one.ca };
            })));
    t.equal(tls.clientTruststoreOptions().ca.length, tls.anchorCount(),
            'the listeners\' ca is the truststore after an add');

    const dup = tls.truststore.add(anchors.a);
    t.check(dup.added === 0 && dup.duplicates === 1,
            'the same CA again is counted as a duplicate and not added twice',
            JSON.stringify(dup));

    const notHeld = tls.truststore.remove(fingerprintOfPem(anchors.spare));
    t.check(notHeld.removed === 0 && /holds no anchor/.test(notHeld.error || ''),
            'a fingerprint the truststore does not hold removes nothing, and says so',
            JSON.stringify(notHeld));
    const malformed = tls.truststore.remove('not-a-fingerprint');
    t.check(malformed.removed === 0 && /64 hex/.test(malformed.error || ''),
            'a value that is not a SHA-256 fingerprint is refused before any lookup',
            JSON.stringify(malformed));

    // The OTHER spelling: lower case, no colons — what most tools print.
    const plain = mine[0].replace(/:/g, '').toLowerCase();
    const removed = tls.truststore.remove(plain);
    t.check(removed.removed === 1 && removed.anchor &&
            removed.anchor.fingerprint256 === mine[0],
            'a remove finds its anchor under the plain-hex spelling of the fingerprint',
            JSON.stringify(removed).slice(0, 300));
    t.equal(tls.clientTruststoreOptions().ca.length, tls.anchorCount(),
            'and the listeners\' ca follows the remove too');
    t.check(tls.truststore.list().anchors.every(function (one) {
      return one.fingerprint256 !== mine[0];
    }), 'and the removed anchor is gone from the list');
  } finally {
    // EVERY ANCHOR THIS SECTION ADDED, AND ONLY THOSE. Another file in this
    // process may have put one there, and removing that would be this file
    // failing somebody else's test.
    mine.forEach(function (fingerprint) {
      if (before.indexOf(fingerprint) < 0) {
        tls.truststore.remove(fingerprint);
      }
    });
  }
  const after = tls.truststore.list().anchors.map(function (one) {
    return one.fingerprint256;
  });
  t.check(JSON.stringify(after) === JSON.stringify(before),
          'the truststore is exactly what it was before this section',
          after.length + ' vs ' + before.length);
}

// ---------------------------------------------------------------------------
// 2 AND 3. THE SLOT, THE ACTIONS AND THE VIEW — IN A CHILD.
// ---------------------------------------------------------------------------
async function childBody() {
  const admin = require('../admin-ui/admin');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');
  const tls = require('../tls/tls_server');
  const audit = require('../common/audit');
  const anchors = await mintAnchors();
  const report = {};
  const view = function (query) {
    return adminViews.truststoreJson({ query: query || {} });
  };
  report.installedBefore = view().installed;
  report.actionBefore = adminActions.truststoreAction(
    { action: 'add', certificates: anchors.a }, { actor: 'tester', via: 'test' });
  report.partial = admin.setTruststore({ list: tls.truststore.list,
                                         add: tls.truststore.add });
  report.installedAfterPartial = view().installed;
  report.actionAfterPartial = adminActions.truststoreAction(
    { action: 'add', certificates: anchors.a }, { actor: 'tester', via: 'test' });
  report.full = admin.setTruststore(tls.truststore);
  report.installedAfterFull = view().installed;
  report.countBefore = view().total;

  // A LISTENER OF THIS PROCESS'S OWN, registered like the main port.
  const https = require('https');
  const listener = https.createServer(
    Object.assign({ requestCert: true, rejectUnauthorized: false },
                  tls.clientTruststoreOptions()),
    function (req, res) {
      res.end(req.socket.authorized ? 'verified' : 'unverified');
    });
  await new Promise(function (ok) { listener.listen(0, '127.0.0.1', ok); });
  tls.trustClientCertificatesOn(listener, 'the truststore_admin test listener');
  report.handshakeBefore = await listenerVerifies(listener, anchors.clientA);

  report.unknown = adminActions.truststoreAction({ action: 'clear' }, {});
  report.add = adminActions.truststoreAction(
    { action: 'add', certificates: [anchors.a, anchors.b] },
    { actor: 'tester', via: 'test' });
  report.addBad = adminActions.truststoreAction(
    { action: 'add', certificates: anchors.spare + UNREADABLE },
    { actor: 'tester', via: 'test' });
  report.addEmpty = adminActions.truststoreAction({ action: 'add' }, {});
  report.removeEmpty = adminActions.truststoreAction({ action: 'remove' }, {});
  report.countAfterAdd = view().total;
  report.handshakeAfterAdd = await listenerVerifies(listener, anchors.clientA);
  report.pageTwo = view({ per: '1', page: '2' });
  report.remove = adminActions.truststoreAction(
    { action: 'remove', fingerprint: fingerprintOfPem(anchors.a) },
    { actor: 'tester', via: 'test' });
  report.handshakeAfterRemove = await listenerVerifies(listener, anchors.clientA);
  listener.close();
  report.afterRemove = view().anchors.map(function (one) {
    return one.fingerprint256;
  });
  report.removedFingerprint = fingerprintOfPem(anchors.a);
  report.auditRows = audit.list().filter(function (row) {
    return row.action === 'admin.truststore.change';
  }).map(function (row) {
    return { actor: row.actor, target: row.target, detail: row.detail };
  });
  report.viewHasKey = JSON.stringify(view()).indexOf('PRIVATE KEY') >= 0;
  return report;
}

function runChild() {
  const out = path.join(os.tmpdir(), 'truststore-admin-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  // The launchers export the stack's mode into the runner; a child that
  // inherited `STS_WORKERS_DISPATCH` or `STS_PERSISTENCE_MODE` would be asking
  // a question about a configuration this file does not describe.
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = out;
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename],
    { env: clean, encoding: 'utf8', timeout: 180000 });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // Not written: the child died before it could say anything. The status and
    // its output are what the caller reports instead.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written; the read above already said so.
  }
  return { status: result.status, report: report,
           output: String(result.stdout || '').slice(-800) +
                   String(result.stderr || '').slice(-800) };
}

function theSlotAndTheLayer(t) {
  t.log.info('=== 2 and 3. the slot, the actions and the view (in a child) ===');
  const ran = runChild();
  const r = ran.report;
  if (!t.check(!!r && !r.threw, 'the child ran',
               r && r.threw ? r.threw : 'exit ' + ran.status + ' ' + ran.output)) {
    return;
  }
  t.check(r.installedBefore === false && r.actionBefore.ok === false,
          'before the slot is filled the view says not installed and an action refuses',
          JSON.stringify(r.actionBefore));
  t.check(r.partial === false && r.installedAfterPartial === false,
          'setTruststore() given list and add without remove is REFUSED whole',
          'partial=' + r.partial + ' installed=' + r.installedAfterPartial);
  t.check(r.actionAfterPartial.ok === false,
          'and the action layer was not handed the half object either',
          JSON.stringify(r.actionAfterPartial));
  t.check(r.full === true && r.installedAfterFull === true,
          'the whole object is installed and both layers see it');

  const sentence = (r.unknown.errors || []).join(' ')
    .match(/Unknown action "[^"]*"\.\s*([^:]*):\s*([^.]+)\./);
  t.check(!!sentence && /There are two/.test(sentence[1]) &&
          sentence[2].split(/,\s*/).sort().join(',') === 'add,remove',
          'an unknown action — `clear` among them — is refused in the house sentence, ' +
          'naming exactly add and remove',
          JSON.stringify(r.unknown.errors));

  t.check(r.add.ok === true && r.add.added === 2 && r.add.persisted === false &&
          /NOT PERSISTED/.test(r.add.message),
          'add through the action layer adds both, and says it is not persisted',
          JSON.stringify(r.add).slice(0, 300));
  t.check(r.addBad.ok === false && r.countAfterAdd === r.countBefore + 2,
          'a bundle with an unreadable block is refused through the layer, and the ' +
          'readable one beside it is not added',
          'count ' + r.countAfterAdd + ' from ' + r.countBefore);
  t.check(r.addEmpty.ok === false && r.removeEmpty.ok === false,
          'an add with nothing and a remove with nothing are both refused — a bodyless ' +
          'POST, which the metadata walk sends, removes nothing',
          JSON.stringify([r.addEmpty.errors, r.removeEmpty.errors]));
  t.check(r.pageTwo.anchors.length === 1 && r.pageTwo.page === 2 &&
          r.pageTwo.pages === r.pageTwo.total && r.pageTwo.persisted === false,
          'the view pages one anchor at a time and reports the page it answered',
          JSON.stringify({ page: r.pageTwo.page, pages: r.pageTwo.pages,
                           total: r.pageTwo.total, shown: r.pageTwo.anchors.length }));
  t.check(r.remove.ok === true && r.afterRemove.indexOf(r.removedFingerprint) < 0 &&
          /nothing brings it back/.test(r.remove.message),
          'remove through the layer takes that anchor away and says a runtime anchor ' +
          'does not come back', JSON.stringify(r.remove).slice(0, 300));
  t.check(r.handshakeBefore === 'unverified' && r.handshakeAfterAdd === 'verified' &&
          r.handshakeAfterRemove === 'unverified',
          'A REAL HANDSHAKE on a registered listener follows both changes: a client ' +
          'certificate chaining to the CA is unverified, verified after the add, and ' +
          'unverified again after the remove',
          JSON.stringify([r.handshakeBefore, r.handshakeAfterAdd, r.handshakeAfterRemove]));
  t.check(r.auditRows.length === 2 && r.auditRows.every(function (row) {
    return row.actor === 'tester';
  }), 'each successful change wrote ONE admin.truststore.change row naming the actor, ' +
          'and the refusals wrote none', JSON.stringify(r.auditRows).slice(0, 400));
  t.check(r.viewHasKey === false, 'no private key appears anywhere in the view');
}

// ---------------------------------------------------------------------------
// 4. THE ROUTING PIN.
// ---------------------------------------------------------------------------
function withDispatchEverything(fn) {
  const had = process.env.STS_WORKERS_DISPATCH;
  process.env.STS_WORKERS_DISPATCH = '*';
  try {
    return fn();
  } finally {
    if (had === undefined) {
      delete process.env.STS_WORKERS_DISPATCH;
    } else {
      process.env.STS_WORKERS_DISPATCH = had;
    }
  }
}

function theRoutingPin(t) {
  t.log.info('=== 4. both doors are answered by the process holding the listeners ===');
  const pool = require('../common/request_pool');
  withDispatchEverything(function () {
    ['/admin-api/tls/trust', '/admin-api/tls/trust/add',
     '/admin-api/tls/trust/remove?x=1', '/realm/x/admin-api/tls/trust/add',
     '/admin/tls/trust', '/admin/tls/trust?page=2&per=10',
     '/realm/acme/admin/tls/trust'].forEach(function (url) {
      t.check(pool.dispatched(url) === false, 'PINNED to the front process: ' + url,
              String(pool.dispatched(url)));
    });
    ['/admin-api/tlsx', '/admin/tls', '/admin-api/tls', '/admin/tls/trustx',
     '/realm/acme/admin/tls'].forEach(function (url) {
      t.check(pool.dispatched(url) === true,
              'still dispatched — a segment boundary, not a bare prefix: ' + url,
              String(pool.dispatched(url)));
    });
  });
}

// ---------------------------------------------------------------------------
// 5. PRODUCT MODE'S REFUSAL NAMES THE NEW DOORS, AS A REQUEST.
// ---------------------------------------------------------------------------
function theProductRefusal(t) {
  t.log.info('=== 5. product mode refuses /tls/trust and names the gated doors ===');
  const script =
    'delete process.env.CONFIG_FILE;' +
    'const app = require(' + JSON.stringify(path.join(ROOT, 'common', 'app')) + ');' +
    'require(' + JSON.stringify(path.join(ROOT, 'tls', 'tls_server.js')) + ');' +
    'const http = require("http");' +
    'const server = http.createServer(app);' +
    'server.listen(0, "127.0.0.1", function () {' +
    '  const req = http.request({ host: "127.0.0.1", port: server.address().port,' +
    '    path: "/tls/trust", method: "POST", headers: { "content-type": "text/plain",' +
    '    accept: "application/json" } }, function (res) {' +
    '    let text = ""; res.on("data", function (c) { text += c; });' +
    '    res.on("end", function () { process.stdout.write("\\nREPORT" +' +
    '      JSON.stringify({ status: res.statusCode, body: text }) + "\\n");' +
    '      process.exit(0); });' +
    '  });' +
    '  req.end("");' +
    '});';
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_MODE: 'product' }),
    encoding: 'utf8', timeout: 120000 });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('REPORT') === 0;
  })[0];
  let report = null;
  try {
    report = line ? JSON.parse(line.slice('REPORT'.length)) : null;
  } catch (e) {
    // Unparseable — reported as the check failing below, with the output.
    report = null;
  }
  // THE SENTENCE, not the whole body: the JSON reply also carries `console` and
  // `api` members naming the two paths, and a check over the body passed with
  // the paths taken out of the sentence a person actually reads.
  let body = '';
  try {
    body = report ? (JSON.parse(report.body).errors || []).join(' ') : '';
  } catch (e) {
    // Not JSON — the check below fails on the empty sentence and prints the reply.
    body = '';
  }
  t.check(!!report && report.status === 403 &&
          body.indexOf('/admin/tls/trust') >= 0 &&
          body.indexOf('POST /admin-api/tls/trust/add') >= 0 &&
          /tls\.trustAnchorsFile/.test(body),
          'a product service refuses POST /tls/trust with a 403 naming the console page, ' +
          'the management-API operation AND tls.trustAnchorsFile',
          report ? JSON.stringify(report).slice(0, 500)
                 : String(result.stderr || result.stdout || '').slice(-500));
}

async function run(t) {
  await thePrimitives(t);
  theSlotAndTheLayer(t);
  theRoutingPin(t);
  theProductRefusal(t);
}

module.exports = {
  name: 'truststore_admin',
  describe: 'the client-certificate truststore\'s gated doors: strict add, remove by ' +
            'fingerprint, the thirteenth slot, the actions and view, the front-process ' +
            'pin, and the product refusal that names them',
  run: run
};

// THE CHILD. `run.js` requires this file rather than running it, so this
// branch is reached only when section 2/3 spawns it with the flag set.
if (require.main === module && process.env[CHILD_FLAG]) {
  const out = process.env[CHILD_FLAG];
  childBody().then(function (report) {
    fs.writeFileSync(out, JSON.stringify(report));
    process.exit(0);
  }, function (e) {
    fs.writeFileSync(out, JSON.stringify({ threw: String(e && e.stack || e) }));
    process.exit(0);
  });
}
