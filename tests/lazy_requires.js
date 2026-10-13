// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: lazy_requires.js
//
// ===========================================================================
// THE PACKAGES A WORKER NEVER USES ARE NOT LOADED IN ONE (#348, 2026-09-29).
//
// Every request and surface worker is a fork that loads the whole protocol
// stack, so a package a module requires at its top is paid for once per
// process. #348 moved the ones worth deferring to first use
// (`common/lazy_module.ts`): the gRPC runtime and its proto loader, which
// only the front process needs when it binds the SPIFFE sockets, and
// `jsonld` (with the vendored `bbs2023.js` that requires it), which only a
// credential issuance, a presentation or a VC-API call needs. Held here:
//
//   1. After a request worker's load order — `request_worker`, then the
//      stack — none of those packages is in the require cache. One plain
//      `require` of any of them at a module's top, anywhere in the stack,
//      brings it back into every worker with nothing else failing, which is
//      why this is checked rather than trusted.
//   2. `spiffe_grpc`'s `status` table is grpc-js's own `grpc.status` — the
//      same object — so a worker's refusals carry the numbers the runtime
//      would have; a grpc-js that moved `build/src/constants.js` fails here.
//      And reading `grpc` is what loads the runtime.
//   3. A stand-in loads nothing until a property is read, loads once, and a
//      load that fails is thrown to the reader (logged as STS-CORE-0140).
//
// IN A CHILD PROCESS for `composition_root.js`'s reason: loading the whole
// stack builds a certificate authority and registers every route on the
// shared app, and `run.js` runs every file in one process — which has also
// loaded these packages already, through other files.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'lazy_requires',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The packages #348 defers, as a path fragment of each one's files in the
// require cache. grpc-js is named by its INDEX, because its
// `build/src/constants.js` (the status table, which requires nothing) is
// loaded in every process on purpose — see `spiffe_grpc.ts`.
const DEFERRED = ['/node_modules/@grpc/grpc-js/build/src/index.js',
                  '/node_modules/@grpc/proto-loader/',
                  '/node_modules/protobufjs/',
                  '/node_modules/jsonld/',
                  '/common/vendored/bbs2023.js'];

function childScript() {
  log.debug("Entering childScript().");
  const lines = [
    "delete process.env.CONFIG_FILE;",
    "const out = {};",
    "const deferred = " + JSON.stringify(DEFERRED) + ";",
    "function loaded() {",
    "  const keys = Object.keys(require.cache);",
    "  return deferred.filter(function (d) {",
    "    return keys.some(function (k) { return k.indexOf(d) >= 0; });",
    "  });",
    "}",
    "require(" + JSON.stringify(path.join(ROOT, 'common/request_worker')) +
      ");",
    "require(" + JSON.stringify(path.join(ROOT, 'common/protocol_stack')) +
      ");",
    "out.afterStack = loaded();",
    "const rpc = require(" +
      JSON.stringify(path.join(ROOT, 'spiffe/spiffe_grpc')) + ");",
    "out.statusNotFound = rpc.status.NOT_FOUND;",
    "out.stillDeferred = loaded();",
    "out.sameTable = rpc.status === rpc.grpc.status;",
    "out.afterGrpc = loaded();",
    "require('fs').writeFileSync(process.env.PROBE_OUT, " +
      "JSON.stringify(out));",
    "process.exit(0);"
  ];
  log.debug("Leaving childScript().");
  return lines.join('\n');
}

function runChild(t) {
  log.debug("Entering runChild().");
  const os = require('os');
  const fs = require('fs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lazy-requires-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, {
    LOG_LEVEL: 'fatal', PROBE_OUT: outFile, SPIFFE_GRPC_PORT: '0'
  });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath,
    ['-e', childScript()],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000 });
  let out = null;
  try {
    out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    t.bad('the child reported nothing',
          String(child.stderr || '').slice(-2000));
  }
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving runChild().");
  return out;
}

function checkTheStandIn(t) {
  log.debug("Entering checkTheStandIn().");
  t.log.info('=== a stand-in loads at the first read, once ===');
  const LazyModule = require('../common/lazy_module');
  const quiet = { debug: function () {}, error: function () {} };
  let loads = 0;
  const lazy = LazyModule.of('probe', function () {
    loads += 1;
    return { answer: 42, nested: { value: 'x' } };
  }, quiet);
  const held = { lazy: lazy };
  t.equal(loads, 0, 'building and holding a stand-in loads nothing');
  t.equal(held.lazy.answer, 42, 'the first read answers from the module');
  t.equal(lazy.nested.value, 'x', 'and so does every read after it');
  t.equal(loads, 1, 'and it was loaded exactly once');
  t.check('answer' in lazy && Object.keys(lazy).length === 2,
          'the in operator and Object.keys see the module',
          JSON.stringify(Object.keys(lazy)));

  const errors = [];
  const broken = LazyModule.of('broken-probe', function () {
    throw new Error('Cannot find module broken-probe');
  }, { debug: function () {}, error: function (m) { errors.push(m); } });
  let thrown = null;
  try {
    // The read is the point; its value is never used.
    thrown = String(broken.anything);
  } catch (e) {
    log.debug("Caught in checkTheStandIn(): " + ((e && e.message) || e));
    thrown = e;
  }
  t.check(thrown instanceof Error &&
          /broken-probe/.test(String(thrown.message)),
          'a load that fails is thrown to the reader',
          String(thrown));
  t.check(errors.length === 1 && errors[0].indexOf('STS-CORE-0140') >= 0,
          'and logged under STS-CORE-0140 first', JSON.stringify(errors));
  log.debug("Leaving checkTheStandIn().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheStandIn(t);

  t.log.info('=== a request worker\'s load order: nothing deferred loads ===');
  const out = runChild(t);
  if (out) {
    t.equal((out.afterStack || []).join(', '), '',
            'after request_worker and the stack, none of the deferred ' +
            'packages is loaded (' + DEFERRED.length + ' checked)');
    t.equal(out.statusNotFound, 5,
            'spiffe_grpc\'s status table answers without the runtime');
    t.equal((out.stillDeferred || []).join(', '), '',
            'and reading it loaded nothing');
    t.check(out.sameTable === true,
            'it is the same object as grpc-js\'s grpc.status',
            'rpc.status is not grpc.status — a worker would refuse with ' +
            'numbers the runtime does not use');
    t.check((out.afterGrpc || []).indexOf(DEFERRED[0]) >= 0,
            'and reading grpc is what loads the runtime',
            JSON.stringify(out.afterGrpc));
  }
  log.debug("Leaving run().");
}

module.exports = { run: run };
