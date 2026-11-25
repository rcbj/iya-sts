// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_write_budget.js
//
// ===========================================================================
// THE MANAGEMENT API COUNTS ONE CALLER'S WRITES (#2247, ASVS 5.0.0 2.4.2;
// #2167's follow-up).
//
// `mgmt-api/admin_api.ts`'s `overWriteBudget()` counts every POST that
// writes, by the token's realm and subject, through
// `websecurity.subjectActShared()`: a person's against
// `adminApi.writesPerSubject`, a program's (a client_credentials token, a
// service account) against `adminApi.programWritesPerSubject`, both in
// `adminApi.writeWindowS`. In a CHILD PROCESS with the whole stack on an
// ephemeral port (`admin_api_recent_sign_in.js`'s arrangement), two people
// holding Admin Write and the console's DPoP-bound tokens minted for them:
//
//   1. THE DEFAULTS: the person budget is 0 in development and 1200 in
//      product; the program budget is 0 in both; the window is 600 s; and
//      STS-API-0148 is in the table.
//   2. A PERSON, with the budget at 3: three group creations pass, the
//      fourth is answered 429 with Retry-After within the window, in this
//      API's refusal shape and with no error code in it, and the group was
//      not made; a read still answers; another person is not affected; and
//      the budget at 0 counts nothing.
//   3. A PROGRAM (driven through the method itself, with a client's caller):
//      not counted while its own budget is 0, whatever the person's; counted
//      against its own budget when one is set; and a person is not counted
//      by the program's.
//   4. NOT COUNTED: an act that writes nothing (a form helper) and a held
//      act's replay.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_write_budget',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AWB_ROOT;
  const OUT = process.env.AWB_OUT;
  const http = require('http');
  let dpopKit = null;
  const DPOP = {
    get jkt() {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.jkt;
    },
    headers: function (method, url, token) {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.headers(method, url, token);
    }
  };
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // One API call, with the console token's proof.
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        Object.assign(headers, DPOP.headers(method, 'http://127.0.0.1:' +
                                            port + urlPath.split('?')[0],
                                            token));
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const adminApi = require(ROOT_DIR + '/mgmt-api/admin_api');
    const AdminApi = adminApi.AdminApi;

    config.setOverride('oauth2.consentRequired', false);

    // --- 1. the defaults -------------------------------------------------
    const rowOf = function (key) {
      return config.SETTINGS.filter(function (one) {
        return one.key === key;
      })[0];
    };
    const person = rowOf('adminApi.writesPerSubject');
    const programRow = rowOf('adminApi.programWritesPerSubject');
    const windowRow = rowOf('adminApi.writeWindowS');
    const development = Number(config.value('adminApi.writesPerSubject'));
    config.setOverride('global.mode', 'product');
    const product = Number(config.value('adminApi.writesPerSubject'));
    const programProduct =
      Number(config.value('adminApi.programWritesPerSubject'));
    config.clearOverride('global.mode');
    note(!!person && !!programRow && !!windowRow && development === 0 &&
         product === 1200 && programProduct === 0 &&
         Number(config.value('adminApi.programWritesPerSubject')) === 0 &&
         Number(config.value('adminApi.writeWindowS')) === 600 &&
         !!person.perProcess && !!programRow.perProcess,
         '1a. the person budget is 0 in development and 1200 in product, ' +
         'the program budget 0 in both, the window 600 s, all process-wide',
         development + ' ' + product + ' ' + programProduct);
    note(errorCodes.CODES.some(function (one) {
      return one.code === 'STS-API-0148';
    }), '1b. STS-API-0148 is in the table');

    // --- the stack ---------------------------------------------------------
    const stamp = String(process.pid);
    const WRITER = 'awb-writer-' + stamp;
    const OTHER = 'awb-other-' + stamp;
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    const subjectOf = function (name) {
      const found = ldap.locateEntry(name);
      const stored = found && found.stored;
      return stored ? 'urn:uuid:' +
        String([].concat(stored.attributes.entryuuid)[0]).toLowerCase() : '';
    };
    [WRITER, OTHER].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    inDefault(function () {
      rbac.seedBootstrapAdministrator();
      rbac.grant(WRITER, 'write', { via: 'test' });
      rbac.grant(OTHER, 'write', { via: 'test' });
    });
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const mint = function (who) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, {
          jkt: DPOP.jkt, audience: base + '/admin-api',
          scope: 'admin:read admin:write', client_id: 'sts-admin-console',
          username: who, sub: subjectOf(who),
          auth_time: Math.floor(Date.now() / 1000) - 30 });
      });
    };
    const token = await mint(WRITER);
    const otherToken = await mint(OTHER);
    note(!!token && !!otherToken, 'precondition: both tokens were minted');

    // --- 2. a person -----------------------------------------------------
    config.setOverride('adminApi.writesPerSubject', 3);
    config.setOverride('adminApi.writeWindowS', 600);
    const group = function (n) {
      return 'awb-g' + n + '-' + stamp;
    };
    const passed = [];
    for (let n = 1; n <= 3; n++) {
      const r = await call(port, 'POST', '/admin-api/groups/create', token,
                           { group: group(n) });
      passed.push(r.status);
    }
    note(passed.join(',') === '200,200,200',
         '2a. three writes within adminApi.writesPerSubject (3) pass',
         passed.join(','));
    const over = await call(port, 'POST', '/admin-api/groups/create', token,
                            { group: group(4) });
    const retry = Number(over.headers['retry-after']);
    note(over.status === 429 && retry >= 1 && retry <= 600 &&
         !!over.json && over.json.ok === false &&
         Array.isArray(over.json.errors) &&
         /Too many changes/.test(String(over.json.errors[0])) &&
         !/STS-/.test(over.text),
         '2b. the fourth is answered 429 with Retry-After within ' +
         'adminApi.writeWindowS, in the refusal shape, with no error code',
         over.status + ' ' + over.headers['retry-after'] + ' ' +
         over.text.slice(0, 300));
    const listed = await call(port, 'GET', '/admin-api/groups?q=' +
                              encodeURIComponent(group(4)), token);
    // `matched`, not the text: the answer echoes the `q` it was asked.
    note(listed.status === 200 && !!listed.json &&
         Number(listed.json.matched) === 0,
         '2c. a read still answers, and the refused group was not made',
         listed.status + ' ' + listed.text.slice(0, 200));
    const other = await call(port, 'POST', '/admin-api/groups/create',
                             otherToken, { group: group(5) });
    note(other.status === 200,
         '2d. another person is counted in a bucket of their own',
         other.status + ' ' + other.text.slice(0, 200));
    config.setOverride('adminApi.writesPerSubject', 0);
    const unlimited = await call(port, 'POST', '/admin-api/groups/create',
                                 token, { group: group(6) });
    note(unlimited.status === 200,
         '2e. adminApi.writesPerSubject 0 counts nothing',
         unlimited.status + ' ' + unlimited.text.slice(0, 200));

    // --- 3. a program ----------------------------------------------------
    // Through the method itself, on a stand-in of the instance's members it
    // reads: what is decided is who counts in which budget.
    const sent = [];
    const fakeSelf = {
      deps: { log: { debug: function () {} }, config: config,
              errorCodes: errorCodes },
      sendJson: function (res, status, body) {
        sent.push(status);
        res.statusCode = status;
        res.body = body;
      }
    };
    const fakeRes = function (caller) {
      const headers = {};
      return { locals: { apiCaller: caller }, headers: headers,
               set: function (name, value) {
                 headers[name.toLowerCase()] = value;
               } };
    };
    const fakeReq = function () {
      return { headers: {}, socket: { remoteAddress: '127.0.0.1' },
               ip: '127.0.0.1' };
    };
    const ENTRY = { route: '/admin-api/groups/:action',
                    actions: [{ action: 'create' },
                              { action: 'helper', writesNothing: true }] };
    const budget = function (caller, action, req) {
      const res = fakeRes(caller);
      const out = AdminApi.prototype.overWriteBudget.call(fakeSelf, ENTRY,
        action || 'create', req || fakeReq(), res);
      return out === null ? Promise.resolve({ counted: false, res: res })
        : out.then(function (refused) {
          return { counted: true, refused: refused, res: res };
        });
    };
    const CLIENT = { kind: 'application', clientId: 'awb-client-' + stamp,
                     name: 'awb-client-' + stamp, realm: '' };
    const PERSON = { kind: 'person', name: OTHER, sub: 'awb-p-' + stamp,
                     realm: '' };
    config.setOverride('adminApi.writesPerSubject', 1);
    config.setOverride('adminApi.programWritesPerSubject', 0);
    const notCounted = [await budget(CLIENT), await budget(CLIENT)];
    note(AdminApi.callerIsProgram(CLIENT) === true &&
         AdminApi.callerIsProgram(PERSON) === false &&
         notCounted.every(function (one) {
           return one.counted === false;
         }),
         '3a. a client_credentials caller is a program, and is not counted ' +
         'while adminApi.programWritesPerSubject is 0, whatever the person ' +
         'budget');
    config.setOverride('adminApi.programWritesPerSubject', 2);
    const program = [await budget(CLIENT), await budget(CLIENT),
                     await budget(CLIENT)];
    note(program[0].refused === false && program[1].refused === false &&
         program[2].refused === true &&
         program[2].res.statusCode === 429 &&
         Number(program[2].res.headers['retry-after']) >= 1 &&
         errorCodes.codeOf(program[2].res) === 'STS-API-0148',
         '3b. with adminApi.programWritesPerSubject at 2 the third program ' +
         'write is refused 429 with Retry-After and STS-API-0148',
         JSON.stringify(program.map(function (one) {
           return [one.counted, one.refused, one.res.statusCode];
         })));
    config.setOverride('adminApi.writesPerSubject', 0);
    const personNot = await budget(PERSON);
    note(personNot.counted === false,
         '3c. a person is not counted by the program budget');

    // --- 4. not counted --------------------------------------------------
    config.setOverride('adminApi.writesPerSubject', 1);
    const helper = await budget(PERSON, 'helper');
    const replayReq = fakeReq();
    replayReq.__dualControlReplay = true;
    const replay = await budget(PERSON, 'create', replayReq);
    note(helper.counted === false && replay.counted === false,
         '4. an act that writes nothing and a held act\'s replay are not ' +
         'counted');

    config.clearOverride('adminApi.writesPerSubject');
    config.clearOverride('adminApi.programWritesPerSubject');
    config.clearOverride('adminApi.writeWindowS');
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'awb-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AWB_ROOT: ROOT, AWB_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_write_budget',
  describe: 'a person\'s writes on /admin-api are counted by the token\'s ' +
            'subject against adminApi.writesPerSubject and refused 429 past ' +
            'it; a program\'s only against adminApi.programWritesPerSubject, ' +
            'off by default (#2247, ASVS 5.0.0 2.4.2)',
  run: run
};
