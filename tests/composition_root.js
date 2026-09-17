'use strict';
//
// File: composition_root.js
//
// ===========================================================================
// THE COMPOSITION ROOT BUILDS THE INSTANCES (#50, R2, 2026-09-16).
//
// rcbj's decision for R2: `common/protocol_stack.ts` builds every converted
// class once and hands it to its module through `installInstance()`; the old
// exports are facades that forward to that instance (see
// `common/instance_slot.ts`). Three claims are held here, because each is how
// the arrangement would quietly stop being true:
//
//   1. After the whole stack loads, EVERY module the root builds reports
//      `root` — none built a default for itself because something used it
//      before the root reached it. `load()` refuses such a stack too; this
//      makes the list itself visible and checked.
//   2. A module loaded on its own, with no root, builds its default
//      instance when it loads — exactly what loading it did before R2 — and
//      works through its facades, which is what every in-process test that
//      loads one module relies on.
//   3. A second `installInstance()` is refused: two instances of one module
//      would split its state.
//   4. A REQUEST WORKER's load order holds claim 1 too. `request_worker.js`
//      requires `service_state` — and through it converted modules — before
//      it loads the stack, so it has to defer to the root first; on
//      2026-09-17 it did not, and every worker failed to start in dispatch
//      mode while this file, which only loaded the stack, stayed green.
//
// IN A CHILD PROCESS for `spiffe_join_token.js`'s reason: loading the whole
// stack builds a certificate authority and registers every route on the shared
// app, and `run.js` runs every file in one process.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'composition_root',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childScript(mode) {
  log.debug("Entering childScript(). " + mode);
  const lines = mode === 'stack'
    ? [
      "const stack = require(" +
      JSON.stringify(path.join(ROOT, 'common/protocol_stack')) + ");",
      "out.origins = stack.instanceOrigins();",
      "const chooser = require(" +
      JSON.stringify(path.join(ROOT, 'common/realm_chooser')) + ");",
      "try {",
      "  chooser.installInstance(new chooser.RealmChooser(",
      "    chooser.RealmChooser.defaultDeps()));",
      "  out.secondInstall = 'accepted';",
      "} catch (e) {",
      "  out.secondInstall = String(e && e.message);",
      "}"
    ]
    : mode === 'worker'
    ? [
      "require(" +
      JSON.stringify(path.join(ROOT, 'common/request_worker')) + ");",
      "const stack = require(" +
      JSON.stringify(path.join(ROOT, 'common/protocol_stack')) + ");",
      "out.origins = stack.instanceOrigins();"
    ]
    : [
      "const context = require(" +
      JSON.stringify(path.join(ROOT, 'saml/authn_context')) + ");",
      "out.atLoad = context.instanceOrigin();",
      "out.reading = context.forSession({ amr: ['pwd'] }).kind;"
    ];
  log.debug("Leaving childScript().");
  return ["delete process.env.CONFIG_FILE;", "const out = {};"]
    .concat(lines)
    .concat(["require('fs').writeFileSync(process.env.PROBE_OUT, " +
             "JSON.stringify(out));", "process.exit(0);"])
    .join('\n');
}

function runChild(t, mode) {
  log.debug("Entering runChild(). " + mode);
  const os = require('os');
  const fs = require('fs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'composition-root-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, {
    LOG_LEVEL: 'fatal', PROBE_OUT: outFile, SPIFFE_GRPC_PORT: '0'
  });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath,
    ['-e', childScript(mode)],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000 });
  let out = null;
  try {
    out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    t.bad('the ' + mode + ' child reported nothing',
          String(child.stderr || '').slice(-2000));
  }
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving runChild().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the whole stack: every instance is the root\'s ===');
  const stack = runChild(t, 'stack');
  if (stack) {
    const origins = stack.origins || [];
    t.check(origins.length > 0,
            'the root reports the instances it built',
            JSON.stringify(origins));
    const wrong = origins.filter(function (row) {
      return row.origin !== 'root';
    });
    t.equal(wrong.map(function (row) {
      return row.what + ':' + row.origin;
    }).join(', '), '',
            'and every one of them says root (' + origins.length + ')');
    t.check(/already installed/.test(String(stack.secondInstall)),
            'a second installInstance() is refused', stack.secondInstall);
  }

  t.log.info('=== a request worker: required first, then the stack ===');
  const worker = runChild(t, 'worker');
  if (worker) {
    const early = (worker.origins || []).filter(function (row) {
      return row.origin !== 'root';
    });
    t.check((worker.origins || []).length > 0 && early.length === 0,
            'in a worker\'s load order every instance is the root\'s too',
            JSON.stringify(early));
  }

  t.log.info('=== one module alone: it builds its own default ===');
  const alone = runChild(t, 'alone');
  if (alone) {
    t.equal(alone.atLoad, 'default',
            'with no root in the process, loading the module built the ' +
            'default, as loading it always did');
    t.equal(alone.reading, 'password', 'and its facades work');
  }
  log.debug("Leaving run().");
}

module.exports = { run: run };
