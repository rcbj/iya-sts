'use strict';
//
// File: front_process_realm_arrival.js
//
// ===========================================================================
// A REQUEST THE FRONT PROCESS KEEPS IS PLACED IN A REALM THAT ARRIVED WHILE IT
// WAITED (2026-09-15).
//
// In a dispatched service the front process answers a few paths itself
// (`request_pool.js`'s NEVER_DISPATCHED — the truststore doors, the debugger's
// status), and since 2026-09-14 it waits for other processes' answered writes
// before routing one. `common/app.js`'s realm middleware runs BEFORE that wait,
// so a realm a worker created a moment ago was unknown when the request was
// looked at: the `/realm/<id>` prefix stayed on the path and the router
// answered `Cannot POST /realm/adminapi-…/admin-api/tls/trust/…`
// — `sts_admin_api_operations` in `dispatch` mode, 270ms after creating its
// realm, while the front process learnt of the realm during the wait.
//
// Three claims:
//   1. a request whose realm did not exist when it arrived, and does once the
//      catch-up is over, is routed inside that realm — the prefix stripped,
//      `req.realm` set, and the realm ambient for what is called next;
//   2. a request already placed in a realm is not asked again;
//   3. `app.js` hands the pool its realm middleware (a source check — without
//      it the pool's second ask is dead code and claim 1 cannot happen).
//
// In a CHILD PROCESS: it creates a realm, and it sets the two restart-only
// worker settings through the environment.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'front_process_realm_arrival',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.FPRA_OUT;
  const ROOT = process.env.FPRA_ROOT;
  const main = async function () {
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const requestPool = require(ROOT + '/common/request_pool');
    const LATE = 'fpra-late';
    const PATH = '/admin-api/tls/trust/__no_such_action__';
    let asked = 0;
    const counting = function (req, res, next) {
      asked++;
      return app.enterRealm(req, res, next);
    };
    const mw = requestPool.middleware({ enterRealm: counting });
    const fakeRes = function () {
      return { location: function () {}, send: function () {},
               get: function () { return ''; } };
    };

    // 1. The realm arrives between app.js's look and the pool's wait.
    const req = { url: '/realm/' + LATE + PATH, method: 'POST', headers: {} };
    req.originalUrl = req.url;
    const res = fakeRes();
    app.enterRealm(req, res, function () {});
    note(!req.realm && req.url === '/realm/' + LATE + PATH,
         'precondition: before the realm exists the request is placed in ' +
         'none and keeps its prefix', req.url);
    realms.create({ id: LATE, name: 'late' });
    const ambient = await new Promise(function (resolve) {
      mw(req, res, function () {
        resolve(realms.currentId());
      });
    });
    note(req.url === PATH,
         '1a. A REALM THAT ARRIVED DURING THE CATCH-UP IS ENTERED: the ' +
         'prefix ' +
         'is stripped, so the router sees the route and not Cannot POST',
         req.url);
    note(req.realm && req.realm.id === LATE,
         '1b. req.realm names it', req.realm && req.realm.id);
    note(ambient === LATE,
         '1c. and it is the ambient realm for what runs next', ambient);

    // 2. Already in a realm: not asked again.
    asked = 0;
    const req2 = { url: '/realm/' + LATE + PATH, method: 'POST', headers: {} };
    req2.originalUrl = req2.url;
    const res2 = fakeRes();
    await new Promise(function (resolve) {
      app.enterRealm(req2, res2, function () {
        mw(req2, res2, resolve);
      });
    });
    note(asked === 0 && req2.url === PATH,
         '2. a request already placed in a realm is not asked again ' +
         '(res.location and res.send are wrapped once)', 'asked ' + asked);
    realms.remove(LATE);

    // 3. app.js wires it.
    const source = fs.readFileSync(ROOT + '/common/app.js', 'utf8');
    note(/requestPool\.middleware\(\{\s*enterRealm:\s*enterRealm\s*\}\)/
           .test(source),
         '3. app.js hands the request pool its realm middleware');
  };
  main().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-fpra-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    FPRA_OUT: out, FPRA_ROOT: root,
    STS_WORKERS_DISPATCH: '/scim', STS_WORKERS_READ_YOUR_WRITE: 'true' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs"); (' + child.toString() + ')()'], {
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
  name: 'front_process_realm_arrival',
  describe: 'a request the front process keeps is placed in a realm that ' +
            'arrived while it waited for other processes\' writes',
  run: run
};
