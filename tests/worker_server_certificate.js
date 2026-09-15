'use strict';
//
// File: worker_server_certificate.js
//
// ===========================================================================
// THE LISTENER CERTIFICATE BELONGS TO THE PROCESS HOLDING THE LISTENER
// (2026-09-12).
//
// The root CLAUDE.md states the rule the LDAP connection list established: a
// store is shared by coordination, and anything that is NOT a row in a store —
// a socket, a timer, a listener — is held by one process and reachable from no
// other. It says a second such thing would need the argument made again rather
// than the mechanism copied. **This file is the second such thing**, and what
// it pins is both halves of the argument.
//
// ---------------------------------------------------------------------------
// WHAT WENT WRONG, WHICH IS WHY THE TWO SECTIONS ARE THE SHAPE THEY ARE.
//
// `POST /admin-api/pki/build-root` is dispatched like every other request, so
// it lands on ONE request worker. That worker rebuilt the Root and every
// branch under it — correctly — and two processes then disagreed about a
// certificate neither of them could see the other holding:
//
//   * THE WORKER re-certified its own copy of the listener record, because it
//     had registered a certifiable at require time like any other process. So
//     it pinned a leaf under the NEW Root while the socket it dials on the
//     loopback was still presenting the OLD one. Every OpenID Connect back
//     channel it ran failed with `unable to get local issuer certificate`,
//     which reaches a reader as `/admin/callback` and `/portal/callback`
//     answering 400.
//
//   * THE FRONT PROCESS adopted the new hierarchy — that part already worked,
//     it is a row — and went on serving a leaf whose Root nothing in the
//     service held any more. `trustAnchorPems()` then refuses to publish an
//     anchor, which is right and leaves `GET /tls/server-certificate` answering
//     a bundle that terminates nowhere.
//
// On 2026-09-12 that was six jobs of the suite's dispatch mode, and not one of
// their failures mentions a certificate.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Section A needs the environment set BEFORE `tls/tls_server.js` is loaded —
// that is how a worker is handed its certificate, and a module loaded once per
// process cannot be asked the question twice. So it is a child process, which
// is the same reason `tests/xacml_pep.js` forks.
//
// Section B is about the BEFORE and the AFTER of replacing the Root, and only a
// caller inside the process can replace one without its branches. Driving the
// API cannot reach it — `/admin/pki`'s control rebuilds every branch in the
// same act, which is what `tests/pki_anchor_drift.js` says at length.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const pki = require('../common/pki');
const tls = require('../tls/tls_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'worker_server_certificate',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// THE CHILD. It sets nothing itself, reports what the module answered, and
// makes no assertion — every assertion is made in run() below, where a failure
// is reported with the rest of the run.
//
// **IT ANSWERS ON A MARKED LINE, BECAUSE ITS STDOUT IS NOT THIS ANSWER'S.** It
// loads the protocol stack's logger, and `pki.start()` is loud by design — half
// a dozen lines about the hierarchy it has just built — so a parent that parsed
// the whole stream would be parsing bunyan.
//
// **WRITTEN TO A FILE RATHER THAN PASSED WITH `-e`**, which is not a
// preference: a script on the command line is a string this file has to quote
// its way out of twice, and the first version of it ended a template literal
// on a backtick inside a comment. A file is read by node the way every other
// module here is.
// ---------------------------------------------------------------------------
const MARKER = '#ANSWER#';

function childSource() {
  log.debug("Entering childSource().");
  log.debug("Leaving childSource().");
  return [
    "'use strict';",
    'const tls = require(' +
      JSON.stringify(path.join(__dirname, '..', 'tls', 'tls_server.js')) + ');',
    'const pki = require(' +
      JSON.stringify(path.join(__dirname, '..', 'common', 'pki.js')) + ');',
    'const MARKER = ' + JSON.stringify(MARKER) + ';',
    'function answer(what) {',
    "  process.stdout.write('\\n' + MARKER + JSON.stringify(what) + '\\n');",
    '}',
    '(async function () {',
    '  const before = tls.serverCertificate();',
    '  await pki.start();',
    '  const after = tls.serverCertificate();',
    '  const reconciled = await tls.reconcileWithHierarchy();',
    '  // AND THE SECOND HAND-OFF, which is the only process that can be asked:',
    '  // the front process re-issued the leaf its socket presents and sent the',
    '  // new one over the IPC channel. What is checked here is that the record',
    '  // MOVES — a worker that ignored it would go on pinning the previous',
    '  // certificate and fail its own back channel, which is the defect the',
    '  // whole pair of functions exists to close.',
    '  const second = JSON.parse(process.env.STS_TEST_SECOND_BUNDLE || "null");',
    '  let adopted = null;',
    '  if (second) {',
    '    tls.adoptServerCertificate(second);',
    '    const now = tls.serverCertificate();',
    '    adopted = { certPem: now.certPem, anchorPem: now.trustAnchorPem,',
    '                chain: now.chainPem.length };',
    '  }',
    '  answer({',
    '    adopted: adopted,',
    '    beforeCert: before.certPem,',
    '    afterCert: after.certPem,',
    '    afterAnchor: after.trustAnchorPem,',
    '    afterChain: after.chainPem.length,',
    '    reconciled: reconciled,',
    "    root: (pki.serviceRoot() || {}).certificatePem || ''",
    '  });',
    '})().catch(function (e) {',
    '  answer({ error: e.message });',
    '});'
  ].join('\n');
}

function runTheChild(env) {
  log.debug("Entering runTheChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-worker-cert-'));
  const file = path.join(dir, 'child.js');
  fs.writeFileSync(file, childSource());
  try {
    const run = childProcess.spawnSync(process.execPath, [file], {
      env: env,
      encoding: 'utf8',
      // The child builds a Root, an Intermediate and several Issuing CAs, which
      // is several RSA key pairs. Generous rather than tight: a timeout here
      // would read as the rule under test being broken.
      timeout: 180000,
      maxBuffer: 32 * 1024 * 1024
    });
    // **REPORTED RATHER THAN THROWN ON A BAD EXIT.** `execFileSync` throws, and
    // what it throws carries the command line and not the child's stderr — so
    // the first version of this file reported a hundred-line `-e` script and
    // nothing about what went wrong inside it.
    const line = String(run.stdout || '').split('\n')
      .filter(function (one) { return one.indexOf(MARKER) === 0; })
      .pop();
    if (!line) {
      log.debug("Leaving runTheChild().");
      return { error: 'the child exited ' + run.status +
                      ' without answering. stderr: ' +
                      String(run.stderr || '').slice(-600) };
    }
    log.debug("Leaving runTheChild().");
    return JSON.parse(line.slice(MARKER.length));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. a process handed a certificate certifies nothing ===');

  await pki.start();
  const front = tls.serverCertificate();
  t.check(front.certPem && front.chainPem.length > 0,
          'this process OWNS its certificate and has certified it, which is ' +
          'the state a worker is forked out of',
          front.chainPem.length + ' chain link(s)');

  const env = Object.assign({}, process.env, {
    STS_TLS_SERVER_CERT_PEM: front.certPem,
    STS_TLS_SERVER_KEY_PEM: front.privateKeyPem,
    STS_TLS_SERVER_CHAIN_PEM: front.chainPem.join(''),
    STS_TLS_SERVER_ANCHOR_PEM: front.trustAnchorPem
  });
  delete env.CONFIG_FILE;
  // A SECOND, DIFFERENT BUNDLE for the child to adopt. It is this process's
  // OWN certificate re-issued under a replaced Root — built here rather than
  // invented, so the three fields really are a set that agrees with itself.
  const wasRoot = pki.serviceRoot().certificatePem;
  await pki.buildRoot({ organisation: 'sts' });
  await pki.certifyRegistered();
  const second = tls.serverCertificateBundle();
  t.check(second.certPem !== front.certPem && wasRoot !== second.anchorPem,
          'a second bundle exists to hand over, from a hierarchy the first ' +
          'one does not chain to');
  env.STS_TEST_SECOND_BUNDLE = JSON.stringify(second);
  const child = runTheChild(env);
  t.check(!child.error, 'the handed-in process starts', child.error || '');

  t.equal(child.beforeCert, front.certPem,
          'it presents the certificate it was handed, before anything else ' +
          'happens');
  t.equal(child.afterCert, front.certPem,
          '**AND `pki.start()` DOES NOT REPLACE IT.** This is the whole of ' +
          'section A: that process built a Root of its own — it has to, ' +
          'every process does — and certifying this record under it would ' +
          'put a certificate no socket in this service presents where the ' +
          'one it does present used to be');
  t.check(child.root && child.root !== child.afterAnchor,
          'and it HAS a Root of its own, which is what makes the line above ' +
          'an assertion rather than a description of a process with no PKI');
  t.equal(child.afterAnchor, front.trustAnchorPem,
          'and it pins the anchor it was handed — the one that signs what ' +
          'the socket presents, rather than the one its own hierarchy would ' +
          'answer');
  t.check(child.reconciled === false,
          'and reconcileWithHierarchy() refuses there, because repairing a ' +
          'certificate it does not serve is the same mistake in the other ' +
          'direction');

  t.log.info('=== A2. and it TAKES a second hand-off, which is the repair ===');
  // The bundle it is given here is a real one from a different hierarchy — the
  // Root this file is about to replace produces exactly this shape — so
  // adopting it has to move all three fields and not only the leaf.
  t.check(!!child.adopted, 'the handed-in process adopts a re-issued bundle');
  t.equal(child.adopted && child.adopted.certPem, second.certPem,
          'and presents what the socket now presents rather than what it was ' +
          'forked with — a worker that ignored this pins the previous ' +
          'certificate and fails its own back channel, silently');
  t.equal(child.adopted && child.adopted.anchorPem, second.anchorPem,
          'and pins the anchor that came with it, NOT the one its own ' +
          'hierarchy answers — which is the whole of what a worker gets this ' +
          'for');
  t.equal(child.adopted && child.adopted.chain, second.chainPem.length,
          'and the chain, so what it reports is a bundle a client can build ' +
          'a path through');

  t.log.info('=== B. and the process that DOES own it repairs itself ===');

  t.check(await tls.reconcileWithHierarchy() === false,
          'reconciling does nothing while the certificate still chains to ' +
          'this service\'s Root — it is called on every hierarchy any ' +
          'process publishes, so the ordinary case has to be free');

  const rootBefore = pki.serviceRoot().certificatePem;
  // The leaf as it stands NOW, which is section A's second bundle rather than
  // the one this file opened with — a comparison against `front` here would be
  // asserting that section A did nothing.
  const serving = tls.serverCertificate().certPem;
  const replaced = await pki.buildRoot({ organisation: 'sts' });
  t.check(replaced.ok, 'the Root is replaced underneath the listener, which ' +
          'is what a build-root on another process leaves behind here',
          (replaced.errors || []).join(' '));
  const stale = tls.serverCertificate();
  t.equal(stale.certPem, serving,
          'and the listener is untouched by it — that is the state, and it ' +
          'is the one nothing could see');
  t.equal(stale.trustAnchorPem, '',
          'so no anchor is published at all, which is what a client fetching ' +
          '/tls/server-certificate meets: a bundle that terminates nowhere');

  t.check(await tls.reconcileWithHierarchy() === true,
          '**AND RECONCILING RE-ISSUES IT.** The certificate is replaced ' +
          'under the hierarchy this service now holds, in the process that ' +
          'owns the socket, so what it presents and what it publishes agree ' +
          'again');
  const fixed = tls.serverCertificate();
  t.check(fixed.certPem !== stale.certPem, 'the leaf is new');
  t.check(!!fixed.trustAnchorPem, 'an anchor is published again');
  t.equal(fixed.trustAnchorPem, pki.serviceRoot().certificatePem,
          'and it is the CURRENT Root rather than the one that was replaced');
  t.check(new nodeCrypto.X509Certificate(
            fixed.chainPem[fixed.chainPem.length - 1])
            .verify(new nodeCrypto.X509Certificate(fixed.trustAnchorPem)
                      .publicKey),
          'and the published anchor SIGNS the published chain — checked by ' +
          'signature, because the two Roots this tells apart have identical ' +
          'subjects and every name comparison passes on the broken case');

  t.log.info('=== and what the front process hands out afterwards ===');
  const bundle = tls.serverCertificateBundle();
  t.equal(bundle.certPem, fixed.certPem,
          'the bundle the pool sends to its workers is what the socket now ' +
          'presents');
  t.equal(bundle.anchorPem, fixed.trustAnchorPem,
          'and the anchor with it, so a worker pins the Root rather than the ' +
          'leaf — the distinction tls_trust_anchor.js exists for');
  t.check(bundle.chainPem.length === fixed.chainPem.length,
          'and the chain, without which a client holding only the anchor can ' +
          'build no path',
          String(bundle.chainPem.length));
  t.check(!Object.prototype.hasOwnProperty.call(bundle, 'privateKeyPem'),
          '**AND NO PRIVATE KEY.** A worker pins and reports this ' +
          'certificate and never presents it — the socket is the front ' +
          'process\'s — so sending the key would be moving a private key ' +
          'between processes for nothing');

  // ---------------------------------------------------------------------
  // PUT THE HIERARCHY BACK, for the reason pki_anchor_drift.js gives at
  // length: `tests/run.js` runs every file in ONE process, and this one
  // replaced the service Root. A file that leaves the service in a state no
  // production path produces is a file that fails its neighbours and passes
  // alone.
  // ---------------------------------------------------------------------
  const restored = [];
  for (const scope of [pki.PROCESS_SCOPE, '']) {
    const built = await pki.buildScope(scope, {});
    restored.push(scope + '=' + (built.ok ? 'ok' : 'failed'));
  }
  await pki.certifyRegistered();
  t.check(restored.every(function (one) { return /=ok$/.test(one); }),
          'and the hierarchy is rebuilt before this file ends, so the files ' +
          'after it inherit a service whose branches chain to its Root',
          restored.join(' '));
  t.check(rootBefore !== pki.serviceRoot().certificatePem,
          'the Root is still the one this file installed, which is the ' +
          'honest report: what is restored is the BRANCHES under it and not ' +
          'the Root, and nothing downstream depends on which Root it is');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'worker server certificate',
  describe: 'the listener certificate belongs to the process holding the ' +
            'listener, and is repaired there when the hierarchy moves',
  run: run
};
