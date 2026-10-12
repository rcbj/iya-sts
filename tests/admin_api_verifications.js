// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_verifications.js
// ===========================================================================
// THE ADMINISTRATOR'S TWIN OF `/oid4vp/start` AND `/oid4vp/result/:state`
// (#587, 2026-10-12), AND THE KERBEROS ACCOUNT POLICY ON
// `GET /admin-api/kerberos/principals`.
//
// The demonstration Verifier's pages become development-only (#585), and a
// product-mode job — or an operator — still has to start a verification and
// read what was decided. `POST /admin-api/verifications/start` and
// `GET /admin-api/verifications` do it through the Verifier's own
// `startVerification()` and `verificationOutcome()`, the functions the pages
// call. What this holds, in a CHILD PROCESS with the whole stack on an
// ephemeral port and tokens minted as the token endpoint mints them:
//
//   1. a start by value builds the request the page builds: the same wallet,
//      and every parameter but the two fresh ones (`nonce`, `state`) equal
//      to what `/oid4vp/start`'s redirect carries;
//   2. a start by reference answers the `request_uri` its wallet URL
//      carries, and the Request Object is served there;
//   3. the outcome by `state` is the object `/oid4vp/result/:state`
//      answers, with `found: true` — before a wallet answers, and after a
//      verdict is written onto the transaction;
//   4. without `state`, the open verifications, the started one among them
//      with its verdict's claim NAMES; an unknown state is 404;
//   5. the refusals: a value outside a closed set, and Admin Read starting
//      one (403);
//   6. the console: the Verifier request tab draws the Start form and the
//      open list, and its form resolves to the operation through `mirrors`;
//   7. `GET /admin-api/kerberos/principals` answers `accountPolicy` as
//      `/krb5/principals` does, without either shared password.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_verifications',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AV_ROOT;
  const OUT = process.env.AV_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) {
          raw += d;
        });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON (a redirect, a page); the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json,
                    location: res.headers.location || '' });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }
  function paramsOf(url) {
    const out = {};
    new URL(url).searchParams.forEach(function (value, name) {
      out[name] = value;
    });
    return out;
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const vcVerifier = require(ROOT_DIR + '/oid4vc/vc_verifier');

    const stamp = String(process.pid);
    const WRITER = 'av-writer-' + stamp;
    const READER = 'av-reader-' + stamp;
    const CLIENT = 'sts-management-api';
    [WRITER, READER].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
      rbac.grant(WRITER, 'write', { via: 'test' });
      rbac.grant(WRITER, 'read', { via: 'test' });
      rbac.grant(READER, 'read', { via: 'test' });
    });

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const mint = function (who) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, {
          audience: base + '/admin-api', scope: 'admin:read admin:write',
          client_id: CLIENT, username: who, sub: who });
      });
    };
    const writer = await mint(WRITER);
    const reader = await mint(READER);
    note(!!writer && !!reader, 'precondition: two access tokens were minted',
         [!!writer, !!reader].join(','));

    // --- 1. by value: the request the page builds ---------------------------
    const page = await call(port, 'GET',
                            '/oid4vp/start?format=dc%2Bsd-jwt', '');
    let r = await call(port, 'POST', '/admin-api/verifications/start',
                       writer, { format: 'dc+sd-jwt' });
    let j = r.json || {};
    note(page.status === 302 && !!page.location,
         'precondition: /oid4vp/start redirects to the wallet',
         page.status + ' ' + page.location.slice(0, 120));
    note(r.status === 200 && j.ok === true && typeof j.state === 'string' &&
         j.state.length > 10 && typeof j.walletUrl === 'string' &&
         j.walletUrl === j.wallet + '?' + j.query &&
         /^openid4vp:\/\/\?/.test(j.requestUri) &&
         j.requestUri.slice('openid4vp://?'.length) === j.query &&
         j.byReference === false && !j.request_uri,
         '1a. a start answers its state, the wallet URL (the wallet and the ' +
         'query), and the openid4vp:// URI a QR code carries',
         r.status + ' ' + r.text.slice(0, 400));
    if (page.location && j.walletUrl) {
      const fromPage = paramsOf(page.location);
      const fromApi = paramsOf(j.walletUrl);
      note(page.location.split('?')[0] === j.walletUrl.split('?')[0],
           '1b. the operation sends the holder to the wallet the page does',
           page.location.split('?')[0] + ' vs ' + j.walletUrl.split('?')[0]);
      const names = Object.keys(fromPage).sort();
      const differ = names.filter(function (name) {
        return name !== 'nonce' && name !== 'state' &&
               fromPage[name] !== fromApi[name];
      });
      note(JSON.stringify(names) ===
           JSON.stringify(Object.keys(fromApi).sort()) &&
           differ.length === 0 && fromApi.state === j.state &&
           fromApi.nonce === j.nonce && fromPage.state !== fromApi.state,
           '1c. and with the same parameters, every one equal but the ' +
           'fresh nonce and state',
           JSON.stringify(names) + ' differ=' + JSON.stringify(differ));
    }
    const byValueState = j.state;

    // --- 2. by reference --------------------------------------------------
    r = await call(port, 'POST', '/admin-api/verifications/start', writer,
                   { format: 'dc+sd-jwt', by: 'reference',
                     mode: 'cross-device' });
    j = r.json || {};
    const asked = j.walletUrl ? paramsOf(j.walletUrl) : {};
    note(r.status === 200 && j.byReference === true && j.request_uri &&
         asked.request_uri === j.request_uri && asked.client_id &&
         asked.client_id === j.clientId && j.mode === 'cross-device',
         '2a. by reference: the wallet URL carries client_id and the ' +
         'request_uri the answer names',
         r.status + ' ' + r.text.slice(0, 400));
    if (j.request_uri) {
      const object = await call(port, 'GET',
                                new URL(j.request_uri).pathname, '');
      note(object.status === 200 && object.text.split('.').length === 3,
           '2b. and the signed Request Object is served there',
           object.status + ' ' + object.text.slice(0, 80));
    }
    const byReferenceState = j.state;

    // --- 3. the outcome, as the result page answers it ----------------------
    r = await call(port, 'GET', '/admin-api/verifications?state=' +
                   encodeURIComponent(byValueState), reader);
    const result = await call(port, 'GET', '/oid4vp/result/' +
                              encodeURIComponent(byValueState), '');
    j = r.json || {};
    const sameAsPage = function (api, pageJson) {
      const copy = Object.assign({}, api);
      delete copy.found;
      delete copy.protocolEndpoints;
      return JSON.stringify(copy) === JSON.stringify(pageJson);
    };
    note(r.status === 200 && j.found === true && j.received === false &&
         j.verdict === null && result.status === 200 &&
         sameAsPage(j, result.json),
         '3a. Admin Read reads the outcome: the result page\'s object, ' +
         'found and not yet received', r.status + ' ' + r.text.slice(0, 300) +
         ' | page ' + result.text.slice(0, 200));
    await inDefault(async function () {
      const record = vcVerifier.transactionFor(byValueState);
      record.verdict = { ok: true, at: new Date().toISOString(),
                         checks: [{ name: 'signature', ok: true }],
                         claims: { given_name: 'Ada' },
                         requested: record.requested || [] };
      await vcVerifier.saveTransaction(record);
    });
    r = await call(port, 'GET', '/admin-api/verifications?state=' +
                   encodeURIComponent(byValueState), reader);
    const decided = await call(port, 'GET', '/oid4vp/result/' +
                               encodeURIComponent(byValueState), '');
    j = r.json || {};
    note(r.status === 200 && j.received === true && j.verdict &&
         j.verdict.ok === true && j.verdict.claims.given_name === 'Ada' &&
         sameAsPage(j, decided.json),
         '3b. once a verdict is on the transaction, both doors answer it',
         r.status + ' ' + r.text.slice(0, 300));

    // --- 4. the open list, and an unknown state -----------------------------
    r = await call(port, 'GET', '/admin-api/verifications', reader);
    j = r.json || {};
    const rows = j.verifications || [];
    const decidedRow = rows.filter(function (row) {
      return row.state === byValueState;
    })[0];
    const waitingRow = rows.filter(function (row) {
      return row.state === byReferenceState;
    })[0];
    note(r.status === 200 && typeof j.total === 'number' && j.total >= 2 &&
         decidedRow && decidedRow.received === true &&
         decidedRow.ok === true &&
         JSON.stringify(decidedRow.claims) === '["given_name"]' &&
         JSON.stringify(decidedRow).indexOf('Ada') < 0 &&
         waitingRow && waitingRow.received === false &&
         waitingRow.byReference === true,
         '4a. without state: the open verifications, a decided one with ' +
         'its claim NAMES and never a value', r.status + ' ' +
         r.text.slice(0, 500));
    r = await call(port, 'GET', '/admin-api/verifications?state=nope-' +
                   stamp, reader);
    note(r.status === 404 && r.json && r.json.found === false &&
         Array.isArray(r.json.errors) && r.json.errors.length === 1,
         '4b. a state with no record is 404, as on the result page',
         r.status + ' ' + r.text.slice(0, 200));

    // --- 5. the refusals --------------------------------------------------
    r = await call(port, 'POST', '/admin-api/verifications/start', writer,
                   { response_type: 'code' });
    note(r.status === 400 && r.json && Array.isArray(r.json.errors),
         '5a. a response_type outside the closed set is refused',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call(port, 'POST', '/admin-api/verifications/start', reader,
                   { format: 'dc+sd-jwt' });
    note(r.status === 403,
         '5b. Admin Read may not start a verification',
         r.status + ' ' + r.text.slice(0, 200));

    // --- 6. the console ---------------------------------------------------
    r = await call(port, 'GET', '/admin-api/verifier-request', reader);
    j = r.json || {};
    const VcVerifierConfigPage = require(ROOT_DIR +
                                         '/oid4vc/web_vc_verifier_config');
    const WebKit = require(ROOT_DIR + '/admin-ui/web_kit');
    const WebPages = require(ROOT_DIR + '/admin-ui/web_pages');
    const WebForms = require(ROOT_DIR + '/admin-ui/web_forms');
    let html = '';
    try {
      html = WebPages.vcTabLinks(
        VcVerifierConfigPage.body(WebKit.context({}, true), j));
    } catch (e) {
      html = 'threw: ' + ((e && e.stack) || e);
    }
    note(j.recentVerifications && j.startChoices &&
         html.indexOf('name="action" value="start"') >= 0 &&
         html.indexOf('action="/admin/vc#vc-tab-verifier-request"') >= 0 &&
         html.indexOf('name="response_mode"') >= 0 &&
         html.indexOf(byValueState) >= 0,
         '6a. the Verifier request tab draws the Start form and the open ' +
         'list', html.slice(0, 300));
    r = await call(port, 'GET', '/admin-api', reader);
    const table = WebForms.table((r.json && r.json.operations) || []);
    const resolved = WebForms.resolve(table,
                                      '/admin/vc#vc-tab-verifier-request',
                                      'start');
    note(resolved === '/admin-api/verifications/start',
         '6b. and its form resolves to POST /admin-api/verifications/start',
         String(resolved));

    // --- 7. the Kerberos account policy -----------------------------------
    r = await call(port, 'GET', '/admin-api/kerberos/principals', reader);
    const kdc = await call(port, 'GET', '/krb5/principals', '');
    j = r.json || {};
    const policy = j.accountPolicy || {};
    const published = (kdc.json && kdc.json.accountPolicy) || {};
    note(r.status === 200 &&
         policy.anyUsernameAuthenticates ===
           published.anyUsernameAuthenticates &&
         JSON.stringify(policy.neverCreated) ===
           JSON.stringify(published.neverCreated) &&
         JSON.stringify(policy.serviceHosts) ===
           JSON.stringify(published.serviceHosts) &&
         !('userPassword' in policy) &&
         !('autoServicePassword' in policy),
         '7. GET /admin-api/kerberos/principals answers /krb5/principals\' ' +
         'account policy, without either password', JSON.stringify(policy) +
         ' | ' + JSON.stringify(published).slice(0, 300));

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
  const out = path.join(os.tmpdir(), 'av-' + process.pid + '-' + Date.now() +
                        '.json');
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
                                  AV_ROOT: ROOT, AV_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'admin_api_verifications',
  describe: 'POST /admin-api/verifications/start and GET ' +
            '/admin-api/verifications build and read what /oid4vp/start and ' +
            '/oid4vp/result build and read, and the Kerberos account ' +
            'policy is on GET /admin-api/kerberos/principals (#587)',
  run: run
};
