// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: front_process_realm_cookie_names.js
//
// ===========================================================================
// A FRONT PROCESS WITH REQUEST WORKERS TRANSLATES A NEW REALM'S COOKIE NAMES
// IN THAT REALM, NOT IN THE DEFAULT ONE (2026-11-15).
//
// GitHub Actions run 43672106260, mariadb mode: `sts_est_attestation_freshness`
// made a development realm under a product process, fetched an EST nonce,
// enrolled over it (fresh), and replayed the statement three seconds later;
// the replay was recorded "The request carried no EST nonce cookie"
// (STS-DEVICE-0016). A worker made the realm, and the front process learns
// of it from the change log. Until it did, `app.js`'s enterRealm() matched no
// realm, so `common/cookie_wire.ts` ran in the DEFAULT realm — product — and
// wrote the nonce cookie as `__Host-sts_est_nonce` and read it back as
// `sts_est_nonce`. Once the front caught up the realm was development, the
// name was not translated, and the worker was handed `__Host-sts_est_nonce`,
// which EST does not read.
//
// enterRealm() now catches up first in a front process with request workers,
// as it already did on an active-active node. Three claims:
//   1. a request naming a realm this process learns of only by catching up is
//      translated in THAT realm: an unprefixed `sts_*` cookie a development
//      realm wrote reaches the handler, and a cookie the handler sets leaves
//      unprefixed;
//   2. a path naming a realm that does not exist after the catch-up still
//      falls through to Express's `Cannot GET`;
//   3. as source, enterRealm() asks `requestPool.frontWithWorkers()`.
//
// In a CHILD PROCESS: it sets the process mode and the worker count through
// the environment, replaces `persistence.syncNow()` and creates a realm.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'front_process_realm_cookie_names',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const http = require('http');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.FPRC_OUT;
  const ROOT = process.env.FPRC_ROOT;
  const main = async function () {
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const requestPool = require(ROOT + '/common/request_pool');
    const persistence = require(ROOT + '/persistence/persistence');
    const LATE = 'fprc-late';
    const HANDLE = 'est.' + 'A'.repeat(43);
    // THE CATCH-UP BRINGS THE REALM, as the change log brings a realm a
    // worker created: it is not here until somebody pulls.
    let pulls = 0;
    persistence.syncNow = async function () {
      pulls += 1;
      if (!realms.get(LATE)) {
        realms.create({ id: LATE, name: 'late', domain: LATE + '.example',
                        overrides: { 'global.mode': 'development' } });
      }
      return { caughtUp: true };
    };
    app.get('/fprc-probe', function (req, res) {
      res.append('Set-Cookie', 'sts_fprc=1; Path=/; HttpOnly');
      res.json({ cookie: String(req.headers.cookie || ''),
                 realm: realms.currentId() });
    });
    const server = http.createServer(function (req, res) {
      // What a TLS socket is to cookie_wire.ts; the listener here is plain.
      req.socket.encrypted = true;
      app(req, res);
    });
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const ask = async function (url) {
      const r = await fetch('http://127.0.0.1:' + port + url, {
        headers: { cookie: 'sts_est_nonce=' + HANDLE + '; other=1' } });
      const text = await r.text();
      let body = null;
      try {
        body = JSON.parse(text);
      } catch (e) {
        body = null;
      }
      return { status: r.status, text: text, body: body,
               setCookie: r.headers.getSetCookie() };
    };
    note(requestPool.frontWithWorkers(),
         'precondition: this process is a front process with a request ' +
         'worker configured');
    note(!realms.get(LATE),
         'precondition: the realm is not here before the catch-up');

    // 1. The realm arrives with the catch-up.
    const one = await ask('/realm/' + LATE + '/fprc-probe');
    note(one.status === 200 && one.body && one.body.realm === LATE,
         '1a. the request is routed in the realm the catch-up brought',
         one.status + ' ' + one.text.slice(0, 200));
    note(one.body && one.body.cookie.indexOf('sts_est_nonce=' + HANDLE) >= 0,
         '1b. a development realm\'s unprefixed sts_ cookie reaches the ' +
         'handler, not dropped as the product default realm\'s would be',
         one.body && one.body.cookie);
    note(one.setCookie.length === 1 &&
         one.setCookie[0].indexOf('sts_fprc=1') === 0,
         '1c. and the cookie it sets leaves unprefixed, as that realm ' +
         'writes it', JSON.stringify(one.setCookie));
    note(pulls >= 1, '1d. the front process caught up to find it',
         'pulls ' + pulls);

    // 2. A realm that never arrives.
    const none = await ask('/realm/fprc-nobody/fprc-probe');
    note(none.status === 404 && /Cannot GET/.test(none.text),
         '2. a realm that does not exist after the catch-up still falls ' +
         'through to Express\'s Cannot GET', none.status + ' ' +
         none.text.slice(0, 120));
    server.close();
    realms.remove(LATE);

    // 3. app.js asks.
    const source = fs.readFileSync(ROOT + '/common/app.js', 'utf8');
    const at = source.indexOf('function enterRealm(');
    const body = source.slice(at, source.indexOf('\n}\n', at));
    note(/requestPool\.frontWithWorkers\(\)/.test(body) &&
         /clusterBarrier\.syncShared\(\)/.test(body),
         '3. enterRealm() catches up in a front process with request workers');
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
  const out = path.join(os.tmpdir(), 'sts-fprc-' + process.pid + '-' +
                                     Date.now() + '.json');
  // Product, so the default realm prefixes; one request worker configured
  // and none started, with nothing dispatched, so the front keeps the probe.
  const env = Object.assign({}, process.env, {
    FPRC_OUT: out, FPRC_ROOT: root, STS_MODE: 'product',
    STS_WORKERS_REQUEST_COUNT: '1', STS_WORKERS_DISPATCH: '/scim',
    STS_WORKERS_READ_YOUR_WRITE: 'off' });
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
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'front_process_realm_cookie_names',
  describe: 'a front process with request workers translates a new ' +
            'realm\'s cookie names in that realm, not the default one',
  run: run
};
