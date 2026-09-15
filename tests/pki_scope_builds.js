'use strict';
//
// File: pki_scope_builds.js
//
// ===========================================================================
// A REALM'S CERTIFICATE BRANCH IS BUILT ONCE, HOWEVER MANY CALLERS ASK FOR IT
// AT ONCE (2026-09-12).
//
// `common/pki.js`'s `ensureScope()` looked for a complete branch and, finding
// none, awaited a build. Two callers inside that window both built, and the one
// that finished second REPLACED the first's branch — so a leaf issued from the
// first was "not signed by" an Issuing CA of the same name. The two callers
// were ordinary: `realms.create()` fires the module's realm watcher, which
// builds without being awaited, and the code that created the realm asks for
// the branch next. `tests/revocation_status.js` met it under `npm test` and had
// to move into a child process to get away from it.
//
// Three claims, and each is a comparison of CERTIFICATES rather than of
// answers, because every racing caller answers `ok: true`:
//
//   1. Concurrent `ensureRoot()` calls on a service with no Root produce ONE
//      Root, and it is the one every caller was told about.
//   2. Concurrent `ensureScope()` calls produce ONE branch: every caller
//      reports the same Intermediate, exactly one of them built it, and it is
//      still the branch the store holds afterwards. A deliberate `buildScope()`
//      queued behind them replaces it, which is what it is for.
//   3. The realm watcher builds a branch for a realm created HERE and not for
//      one that arrived `restored` — which is how `persistence.js` hands over a
//      realm another process created, and is the same race across processes.
//
// IN A CHILD PROCESS: a fresh process has no Root and no watcher, and both are
// what is under test; `run.js`'s one process has had both since the first file
// that called `pki.start()`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pki_scope_builds',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childScript() {
  log.debug("Entering childScript().");
  log.debug("Leaving childScript().");
  return [
    "delete process.env.CONFIG_FILE;",
    "const realms = require(" +
    JSON.stringify(path.join(ROOT, 'common/realms')) + ");",
    "const pki = require(" + JSON.stringify(path.join(ROOT, 'common/pki')) +
    ");",
    "function wait(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }",
    "(async function () {",
    "  const out = {};",
    // 1. the Root
    "  const roots = await Promise.all([pki.ensureRoot({}), pki.ensureRoot({}), pki.ensureRoot({})]);",
    "  out.rootsOk = roots.every(function (r) { return r.ok; });",
    "  out.rootSerials = roots.map(function (r) { return r.root && r.root.serialHex; });",
    "  out.rootBuiltCount = roots.filter(function (r) { return !r.existing; }).length;",
    // 2. one realm's branch, asked for four times at once
    "  const id = 'scope-builds-' + Date.now().toString(36);",
    "  const made = realms.create({ id: id, name: id });",
    "  out.realmOk = made.ok;",
    "  const branches = await Promise.all([pki.ensureScope(id), pki.ensureScope(id),",
    "                                      pki.ensureScope(id), pki.ensureScope(id)]);",
    "  out.branchesOk = branches.every(function (b) { return b.ok; });",
    "  out.branchBuiltCount = branches.filter(function (b) { return !b.existing; }).length;",
    "  out.branchSerials = branches.map(function (b) { return b.scope && b.scope.intermediate && b.scope.intermediate.serialHex; });",
    "  out.branchNow = pki.describeScope(id).intermediate.serialHex;",
    "  out.issuingNow = pki.describeScope(id).issuing.map(function (u) { return u.ca && u.ca.serialHex; });",
    "  out.issuingReported = branches.map(function (b) { return b.scope.issuing.map(function (u) { return u.ca && u.ca.serialHex; }); });",
    "  const queued = await Promise.all([pki.ensureScope(id), pki.buildScope(id, {})]);",
    "  out.queuedEnsureSaw = queued[0].scope.intermediate.serialHex;",
    "  out.rebuiltTo = pki.describeScope(id).intermediate.serialHex;",
    // 3. the watcher
    "  await pki.start({});",
    "  const restoredId = 'scope-restored-' + Date.now().toString(36);",
    "  const createdId = 'scope-created-' + Date.now().toString(36);",
    "  realms.create({ id: restoredId, name: restoredId, restored: true });",
    "  realms.create({ id: createdId, name: createdId });",
    "  let waited = 0;",
    "  while (!pki.describeScope(createdId).built && waited < 60000) { await wait(100); waited += 100; }",
    "  await wait(300);",
    "  out.createdBuilt = pki.describeScope(createdId).built;",
    "  out.restoredBuilt = pki.describeScope(restoredId).built;",
    "  fs.writeFileSync(process.env.PROBE_OUT, JSON.stringify(out));",
    "  process.exit(0);",
    "})().catch(function (e) {",
    "  fs.writeFileSync(process.env.PROBE_OUT, JSON.stringify({ threw: e.stack }));",
    "  process.exit(1);",
    "});"
  ].join('\n').replace("delete process.env.CONFIG_FILE;",
                       "delete process.env.CONFIG_FILE; const fs = " +
                       "require('fs');");
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pki-scope-builds-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env,
                            { LOG_LEVEL: 'fatal', PROBE_OUT: outFile });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, ['-e', childScript()],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 240000 });
  let out = null;
  try {
    out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No file is the child dying before it wrote one; its stderr says why.
    t.bad('the child process reported nothing',
          (child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  if (out.threw) {
    t.bad('the child process threw', out.threw);
    log.debug("Leaving run().");
    return;
  }

  t.log.info('=== 1. three callers, no Root ===');
  t.check(out.rootsOk, 'every ensureRoot() call answered ok');
  t.equal(out.rootBuiltCount, 1, 'exactly one of them built a Root',
          JSON.stringify(out.rootSerials));
  t.check(out.rootSerials.every(function (s) {
    return s && s === out.rootSerials[0];
  }),
          'and all three were told about the SAME Root', JSON.stringify(
              out.rootSerials));

  t.log.info('=== 2. four callers, one realm ===');
  t.check(out.realmOk && out.branchesOk, 'the realm exists and every ' +
                                         'ensureScope() answered ok');
  t.equal(out.branchBuiltCount, 1, 'exactly one caller built the branch; the ' +
                                   'other three found it',
          JSON.stringify(out.branchSerials));
  t.check(out.branchSerials.every(function (s) {
    return s && s === out.branchNow;
  }),
          'every caller reported the Intermediate the store STILL holds — ' +
          'none was replaced under the caller that made ' +
          'it', JSON.stringify({ reported: out.branchSerials,
                                 now: out.branchNow }));
  t.check(out.issuingReported.every(function (list) {
            return JSON.stringify(list) === JSON.stringify(out.issuingNow);
          }),
          'and the same for every Issuing CA under it, which is what a leaf ' +
          'is signed by');
  t.equal(out.queuedEnsureSaw, out.branchNow,
          'an ensureScope() queued beside a deliberate rebuild answers the ' +
          'branch that was there');
  t.check(out.rebuiltTo && out.rebuiltTo !== out.branchNow,
          'and the deliberate buildScope() behind it still REPLACES the ' +
          'branch, which is what it is for',
          JSON.stringify({ before: out.branchNow, after: out.rebuiltTo }));

  t.log.info('=== 3. the realm watcher ===');
  t.equal(out.createdBuilt, true, 'a realm created in this process gets its ' +
                                  'branch from the watcher');
  t.equal(out.restoredBuilt, false,
          'a realm that arrived RESTORED — from the store or another process ' +
          '— does not: that branch is the creating process\'s to build, and ' +
          'building it here too was the same race across processes');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_scope_builds',
  describe: 'a realm\'s certificate branch and the service Root are built ' +
            'once however many callers ask at once',
  run: run
};
