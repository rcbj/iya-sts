'use strict';
//
// File: listener_branch_adoption.js
//
// ===========================================================================
// THE LISTENER IS RE-ISSUED UNDER THE PROCESS BRANCH THIS PROCESS HOLDS, AND
// THE FRONT PROCESS NEVER BUILDS THAT BRANCH BESIDE A WORKER (2026-09-13).
//
// `tests/vendored/sts_pki_distribution_points.js` failed in `dispatch` mode
// only, on the last two full runs:
//
//   http://localhost:18082/pki/crl/process/intermediate.crl is named by
//   certificates of two different authorities — CN=sts Intermediate CA
//   (Process), O=sts and CN=sts Intermediate CA (Process), O=sts — and one
//   list can have only one issuer
//
// Observed on the kept stack: the TLS handshake and `GET
// /tls/server-certificate` chained to a process Intermediate the FRONT process
// built at 14:53:56, while `/pki/ca/process/intermediate.cer` — and every
// worker's `/admin-api/pki` — held one worker 33 built at 14:53:57. Both are
// signed by the same Root, so `tls_server.js`'s reconcile, which asked only
// whether the Root signs the chain, answered "already chains" about the stale
// one. And the front process had built its own because the Root of a
// `build-root` on worker 33 arrived ahead of the branches that worker was
// rebuilding in the same act, and `certify()` repaired the "stale" branch
// locally — two processes building one branch over a last-write-wins channel.
//
// Five claims, each a comparison of CERTIFICATES, because every candidate here
// has the same subject and every call answers without an error:
//
//   1. A process branch rebuilt elsewhere under the SAME Root is adopted and
//      the listener re-issued from it — the reconcile used to answer false.
//   2. A Root that arrives AHEAD of its branch is waited for: nothing is built
//      here, the listener is untouched, and `listenerAwaitsBranch()` says so.
//      `certifyRegistered({ repairBranch: false })` refuses in the same way,
//      which is the guarantee under the reconcile's own check.
//   3. When the branch arrives the listener is re-issued from it.
//   4. Asked without `buildBranch: false`, the reconcile is still the repair
//      it always was — the fallback the pool arms for a branch that never
//      comes.
//   5. Through `request_pool.js`: a pass left waiting arms that fallback, a
//      current pass disarms it, and only ONE pass runs at a time however many
//      publishes arrive — a queued call becomes one more pass, a repair if any
//      caller asked for one.
//
// IN A CHILD PROCESS: it replaces the service Root twice and rebuilds the
// process branch four times, and `run.js` runs every file in one process —
// the reason `tests/pki_scope_builds.js` forks. A fresh process also has no
// Root until `pki.start()`, which is the state claim 1 starts from.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'listener_branch_adoption',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const MARKER = '#ANSWER#';

// ---------------------------------------------------------------------------
// THE CHILD reports what it saw and asserts nothing; run() below does, so a
// failure is reported with the rest of the run. Written to a file rather than
// passed with `-e`, for `tests/worker_server_certificate.js`'s reason.
// ---------------------------------------------------------------------------
function childSource() {
  log.debug("Entering childSource().");
  log.debug("Leaving childSource().");
  return [
    "'use strict';",
    'delete process.env.CONFIG_FILE;',
    'const nodeCrypto = require("crypto");',
    'const tls = require(' +
      JSON.stringify(path.join(ROOT, 'tls', 'tls_server.js')) + ');',
    'const pki = require(' +
      JSON.stringify(path.join(ROOT, 'common', 'pki.js')) + ');',
    'const pool = require(' +
      JSON.stringify(path.join(ROOT, 'common', 'request_pool.js')) + ');',
    'const MARKER = ' + JSON.stringify(MARKER) + ';',
    'function answer(what) {',
    "  process.stdout.write('\\n' + MARKER + JSON.stringify(what) + '\\n');",
    '}',
    'function body(pem) {',
    "  return String(pem || '').replace(/-----[^-]+-----|\\s+/g, '');",
    '}',
    'function listenerChain() {',
    '  return tls.serverCertificate().chainPem.map(body);',
    '}',
    'function heldChain() {',
    '  const row = pki.rawRowFor(pki.PROCESS_SCOPE);',
    '  return [body(row.issuing.tls.certificatePem),',
    '          body(row.intermediate.certificatePem)];',
    '}',
    'function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }',
    'function current() { return same(listenerChain(), heldChain()); }',
    '// The published anchor signs the Intermediate the listener travels with,',
    '// by SIGNATURE: the Roots this file makes all have one subject.',
    'function anchorSignsListener() {',
    '  const cert = tls.serverCertificate();',
    '  if (!cert.trustAnchorPem) { return false; }',
    '  return new nodeCrypto.X509Certificate(',
    '      cert.chainPem[cert.chainPem.length - 1])',
    '    .verify(new nodeCrypto.X509Certificate(cert.trustAnchorPem)',
    '      .publicKey);',
    '}',
    '(async function () {',
    '  const out = {};',
    '  await pki.start();',
    '  out.startedCurrent = current();',
    '',
    '  // 1. the branch rebuilt elsewhere, under the same Root',
    '  await pki.buildScope(pki.PROCESS_SCOPE, {});',
    '  out.oneStale = !current();',
    '  const held1 = heldChain();',
    '  out.oneReconciled =',
    '    await tls.reconcileWithHierarchy({ buildBranch: false });',
    '  out.oneHeldUntouched = same(held1, heldChain());',
    '  out.oneCurrent = current();',
    '  out.oneAnchorSigns = anchorSignsListener();',
    '  out.oneAgain =',
    '    await tls.reconcileWithHierarchy({ buildBranch: false });',
    '',
    '  // 2. a Root arriving ahead of its branch',
    "  await pki.buildRoot({ organisation: 'sts' });",
    '  const held2 = heldChain();',
    '  const listener2 = listenerChain();',
    '  out.twoReconciled =',
    '    await tls.reconcileWithHierarchy({ buildBranch: false });',
    '  out.twoHeldUntouched = same(held2, heldChain());',
    '  out.twoListenerUntouched = same(listener2, listenerChain());',
    '  out.twoAwaits = tls.listenerAwaitsBranch();',
    '  await pki.certifyRegistered({ repairBranch: false });',
    '  out.twoDirectHeldUntouched = same(held2, heldChain());',
    '  out.twoDirectListenerUntouched = same(listener2, listenerChain());',
    '',
    '  // 3. the branch arrives',
    '  await pki.buildScope(pki.PROCESS_SCOPE, {});',
    '  out.threeReconciled =',
    '    await tls.reconcileWithHierarchy({ buildBranch: false });',
    '  out.threeCurrent = current();',
    '  out.threeAwaits = tls.listenerAwaitsBranch();',
    '  out.threeAnchorSigns = anchorSignsListener();',
    '',
    '  // 4. it never arrives, and the repair is asked for',
    "  await pki.buildRoot({ organisation: 'sts' });",
    '  const held4 = heldChain();',
    '  out.fourWaited =',
    '    await tls.reconcileWithHierarchy({ buildBranch: false });',
    '  out.fourRepaired = await tls.reconcileWithHierarchy();',
    '  out.fourBuilt = !same(held4, heldChain());',
    '  out.fourCurrent = current();',
    '  out.fourAnchorSigns = anchorSignsListener();',
    '',
    '  // 5. through the pool',
    '  await pki.buildScope(pki.PROCESS_SCOPE, {});',
    '  await pool.reconcileTheListener();',
    '  out.fiveACurrent = current();',
    '  out.fiveAArmed = pool.listenerRepairArmed();',
    "  await pki.buildRoot({ organisation: 'sts' });",
    '  const held5 = heldChain();',
    '  await pool.reconcileTheListener();',
    '  out.fiveBHeldUntouched = same(held5, heldChain());',
    '  out.fiveBArmed = pool.listenerRepairArmed();',
    '  await pki.buildScope(pki.PROCESS_SCOPE, {});',
    '  await pool.reconcileTheListener();',
    '  out.fiveCCurrent = current();',
    '  out.fiveCArmed = pool.listenerRepairArmed();',
    '',
    '  // 5d. one pass at a time: the reconcile is replaced by one that counts',
    '  // how many are running and takes long enough to overlap.',
    '  const real = tls.reconcileWithHierarchy;',
    '  let inFlight = 0;',
    '  let most = 0;',
    '  const asked = [];',
    '  tls.reconcileWithHierarchy = async function (options) {',
    '    inFlight += 1;',
    '    most = Math.max(most, inFlight);',
    '    asked.push(options);',
    '    await new Promise(function (r) { setTimeout(r, 40); });',
    '    inFlight -= 1;',
    '    return false;',
    '  };',
    '  const first = pool.reconcileTheListener();',
    '  pool.reconcileTheListener();',
    '  pool.reconcileTheListener({ repair: true });',
    '  pool.reconcileTheListener();',
    '  await first;',
    '  tls.reconcileWithHierarchy = real;',
    '  out.fiveDMost = most;',
    '  out.fiveDPasses = asked.length;',
    '  out.fiveDAsked = asked.map(function (o) {',
    '    return o && o.buildBranch;',
    '  });',
    '  answer(out);',
    '  process.exit(0);',
    '})().catch(function (e) {',
    '  answer({ error: e.stack || e.message });',
    '  process.exit(1);',
    '});'
  ].join('\n');
}

function runTheChild() {
  log.debug("Entering runTheChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-listener-branch-'));
  const file = path.join(dir, 'child.js');
  fs.writeFileSync(file, childSource());
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  try {
    const run = childProcess.spawnSync(process.execPath, [file], {
      cwd: ROOT,
      env: env,
      encoding: 'utf8',
      // Five Roots-and-branches of RSA key pairs. Generous rather than tight: a
      // timeout would read as the rule under test being broken.
      timeout: 240000,
      maxBuffer: 32 * 1024 * 1024
    });
    const line = String(run.stdout || '').split('\n')
      .filter(function (one) { return one.indexOf(MARKER) === 0; })
      .pop();
    if (!line) {
      log.debug("Leaving runTheChild().");
      return { error: 'the child exited ' + run.status +
                      ' without answering. stderr: ' +
                      String(run.stderr || '').slice(-1500) };
    }
    log.debug("Leaving runTheChild().");
    return JSON.parse(line.slice(MARKER.length));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function run(t) {
  log.debug("Entering run().");
  const out = runTheChild();
  if (out.error) {
    t.bad('the child process answered', out.error);
    log.debug("Leaving run().");
    return;
  }
  t.check(out.startedCurrent, 'after pki.start() the listener travels with ' +
          'the process branch this process holds');

  t.log.info('=== 1. a branch rebuilt elsewhere, under the same Root ===');
  t.check(out.oneStale, 'a rebuilt process branch leaves the listener under ' +
          'an Intermediate CA (Process) this process no longer holds — the ' +
          'state a worker\'s build-scope leaves in the front process');
  t.equal(out.oneReconciled, true,
          '**AND THE RECONCILE RE-ISSUES IT.** It used to answer "already ' +
          'chains", because the Root signs both Intermediates');
  t.check(out.oneCurrent, 'the listener now travels with the Issuing CA and ' +
          'Intermediate this process holds and publishes');
  t.check(out.oneHeldUntouched, 'and the branch it adopted is the one still ' +
          'held — adopting built nothing');
  t.check(out.oneAnchorSigns, 'and the published anchor signs the chain');
  t.equal(out.oneAgain, false, 'a second reconcile does nothing: the ' +
          'ordinary publish has to be free');

  t.log.info('=== 2. a Root that arrives ahead of its branch ===');
  t.equal(out.twoReconciled, false,
          'a publish-triggered reconcile does not re-issue from a branch the ' +
          'Root does not sign');
  t.check(out.twoHeldUntouched,
          '**AND IT BUILDS NO BRANCH HERE.** The process that replaced the ' +
          'Root is rebuilding it; a second build is the second Intermediate ' +
          'CA (Process) the distribution-points job found');
  t.check(out.twoListenerUntouched, 'the listener is left as it is until ' +
          'the branch arrives');
  t.check(out.twoAwaits, 'and listenerAwaitsBranch() says so, which is what ' +
          'the pool arms its fallback on');
  t.check(out.twoDirectHeldUntouched && out.twoDirectListenerUntouched,
          'certifyRegistered({ repairBranch: false }) refuses to rebuild the ' +
          'branch as well — the guarantee under the reconcile\'s own check, ' +
          'for a Root adopted while a pass is issuing');

  t.log.info('=== 3. the branch arrives ===');
  t.equal(out.threeReconciled, true, 'the listener is re-issued when it does');
  t.check(out.threeCurrent, 'from exactly that branch');
  t.check(!out.threeAwaits, 'and nothing is waited for any more');
  t.check(out.threeAnchorSigns, 'and the new Root signs what the socket ' +
          'presents');

  t.log.info('=== 4. and when it never arrives, the repair ===');
  t.equal(out.fourWaited, false, 'a replaced Root with no branch behind it ' +
          'is waited for');
  t.equal(out.fourRepaired, true, 'asked without buildBranch: false the ' +
          'reconcile repairs — the fallback the pool arms');
  t.check(out.fourBuilt && out.fourCurrent && out.fourAnchorSigns,
          'by building the branch here and issuing from it, so the listener ' +
          'chains to the Root this service publishes');

  t.log.info('=== 5. through request_pool.js ===');
  t.check(out.fiveACurrent && !out.fiveAArmed, 'a publish of a rebuilt ' +
          'branch re-issues the listener and arms nothing');
  t.check(out.fiveBHeldUntouched, 'a publish of a new Root builds no branch ' +
          'in the front process');
  t.check(out.fiveBArmed, 'and arms the fallback repair, for a branch that ' +
          'never comes');
  t.check(out.fiveCCurrent && !out.fiveCArmed, 'the branch arriving ' +
          're-issues the listener and disarms it');
  t.equal(out.fiveDMost, 1,
          '**ONE PASS AT A TIME.** Four publishes at once ran their passes ' +
          'one after another — overlapping passes could finish out of order ' +
          'and put an older leaf back on the socket');
  t.equal(out.fiveDPasses, 2, 'the three that arrived while one ran became ' +
          'ONE more pass, which re-reads what is held',
          JSON.stringify(out.fiveDAsked));
  t.check(out.fiveDAsked[0] === false && out.fiveDAsked[1] === true,
          'publish-triggered passes wait for a branch, and the coalesced ' +
          'pass is a repair because one of the callers asked for one',
          JSON.stringify(out.fiveDAsked));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'listener branch adoption',
  describe: 'the listener is re-issued under the process branch this process ' +
            'holds, and a dispatched front process waits for that branch ' +
            'rather than building it beside a worker',
  run: run
};
