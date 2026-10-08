// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/console_public_client.js
// ===========================================================================
// THE ADMIN CONSOLE AS A PUBLIC CLIENT IS DPoP-BOUND, ALWAYS (#446,
// 2026-10-05).
//
// The console is becoming a static application in the browser: a public
// client that holds its own tokens. rcbj's decision is that every token
// issued to it is then bound to a key it proves possession of — a rule about
// that one client (`oauth-oidc/sender_constraints.js`'s
// `DPOP_BOUND_PUBLIC_CLIENTS`) and not one of the realm's DPoP settings,
// which stay off throughout this file.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port:
//
//   1. AS SEEDED, the console is a confidential client and nothing changed:
//      an unbound access token issued to it is accepted at /admin-api (the
//      API explorer's token is one);
//   2. DECLARED PUBLIC, a token request from it with no DPoP proof is
//      refused whole, `invalid_dpop_proof`, recorded under STS-OAUTH-0943;
//   3. the same request with a proof is issued a DPoP token set whose access
//      token carries the key's thumbprint;
//   4. its refresh token is bound too: redeemed without the proof it is
//      refused, and with it redeemed;
//   5. at /admin-api an UNBOUND token issued to it is refused 401, recorded
//      under STS-OAUTH-0944; a bound one sent as Bearer is refused; and a
//      bound one with its proof is accepted;
//   6. another public client is not touched by the rule: it is issued a
//      bearer token with no proof.
//
// The password grant is added to the console's entry here, in this child
// alone, so that the token endpoint can be asked without a browser: what is
// under test is the rule every grant mints through, not the grant.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'console_public_client',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  // A request with a form body (the token endpoint) or none.
  function request(port, method, urlPath, form, headers) {
    return new Promise(function (resolve, reject) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const all = Object.assign({ accept: 'application/json' }, headers || {});
      if (form) {
        all['content-type'] = 'application/x-www-form-urlencoded';
        all['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: all }, function (res) {
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
          resolve({ status: res.statusCode, text: raw, json: json,
                    headers: res.headers });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  }
  function settle() {
    // The HTTP row is written when the response has finished.
    return new Promise(function (res) { setTimeout(res, 40); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const oidcRp = require(ROOT_DIR + '/common/oidc_rp');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const audit = require(ROOT_DIR + '/common/audit');
    const applications = require(ROOT_DIR + '/common/applications');

    const stamp = String(process.pid);
    const WRITER = 'cp-writer-' + stamp;
    const CONSOLE = 'sts-admin-console';
    const OTHER = 'cp-other-public-' + stamp;
    ldap.createUser(WRITER, { invent: false });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
      rbac.grant(WRITER, 'write', { via: 'test' });
    });
    applications.createApplication({ identifier: OTHER,
      protocols: ['oauth2'],
      fields: { oauthClientId: OTHER,
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['password', 'refresh_token'] } });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const TOKEN_URL = base + '/oauth2/token';
    const ME = '/admin-api/me';
    const key = oidcRp.dpopKey();
    const proofFor = function (method, url, accessToken) {
      return oidcRp.dpopProof(key, method, url,
                              accessToken ? { accessToken: accessToken } : {});
    };
    const claimsOf = function (jwt) {
      try {
        return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
          .toString('utf8'));
      } catch (e) {
        // Not a JWT; the finding that reads it reports that.
        return {};
      }
    };
    const mintFor = function (extra) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, Object.assign({
          audience: base + '/admin-api', scope: 'admin:read admin:write',
          client_id: CONSOLE, username: WRITER, sub: WRITER }, extra || {}));
      });
    };
    const ask = function (clientId, headers, form) {
      return request(port, 'POST', '/oauth2/token', Object.assign({
        grant_type: 'password', username: WRITER, password: 'anything',
        scope: 'openid offline_access', client_id: clientId }, form || {}),
        headers || {});
    };
    const coded = function (code) {
      return audit.list().filter(function (event) {
        return event.errorCode === code;
      }).length;
    };

    // --- 1. as seeded: confidential, and nothing changed --------------------
    const seeded = applications.clientConfigOf(CONSOLE) || {};
    const unbound = await mintFor();
    let r = await request(port, 'GET', ME, null,
                          { authorization: 'Bearer ' + unbound });
    // SEEDED PUBLIC SINCE THE CUTOVER (#446): the static console holds no
    // credential, so an unbound token issued to it is refused from the
    // start, not only once something declares it public.
    note(String(seeded.token_endpoint_auth_method || '') === 'none' &&
         r.status === 401,
         '1. as seeded the console is a public client, and an unbound ' +
         'token issued to it is refused at /admin-api',
         seeded.token_endpoint_auth_method + ' ' + r.status + ' ' +
         r.text.slice(0, 160));

    // --- declared public, in this child alone --------------------------------
    // Through its registration document, which writes a seeded surface's
    // method and the grant types it is held to
    // (`applications.declaredFlowsOf()`, #289).
    const document = Object.assign({}, applications.registrationOf(CONSOLE), {
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token', 'password'] });
    delete document.client_secret;
    delete document.client_secret_expires_at;
    const made = applications.updateRegistration(CONSOLE, document);
    // The method is a list on the entry, and `none` is never held beside
    // another: the seeded one comes off.
    const dropped = applications.updateApplication(CONSOLE, {
      attribute: 'oauthTokenEndpointAuthMethod', mode: 'remove',
      value: 'private_key_jwt' });
    const declared = applications.clientConfigOf(CONSOLE) || {};
    note(!!made && declared.token_endpoint_auth_method === 'none',
         'precondition: the console\'s entry now declares a public client',
         !!made + ' ' + JSON.stringify((dropped || {}).errors || 'removed') +
         ' ' + JSON.stringify(declared.token_endpoint_auth_methods) + ' ' +
         JSON.stringify(applications.declaredFlowsOf(CONSOLE)));

    // --- 2. no proof ---------------------------------------------------------
    let before = coded('STS-OAUTH-0943');
    r = await ask(CONSOLE, {});
    await settle();
    note(r.status === 400 && r.json && r.json.error === 'invalid_dpop_proof' &&
         !r.json.access_token && coded('STS-OAUTH-0943') === before + 1,
         '2a. PUBLIC: a token request with no DPoP proof is refused whole, ' +
         'invalid_dpop_proof, recorded under STS-OAUTH-0943',
         r.status + ' ' + r.text.slice(0, 200));
    note(r.text.indexOf('STS-OAUTH-') < 0,
         '2b. and the refusal carries no error code on the wire',
         r.text.slice(0, 200));

    // --- 3. with a proof -----------------------------------------------------
    r = await ask(CONSOLE, { dpop: proofFor('POST', TOKEN_URL) });
    const bound = r.json || {};
    const jkt = (claimsOf(bound.access_token).cnf || {}).jkt || '';
    note(r.status === 200 && !!bound.access_token &&
         String(bound.token_type || '').toLowerCase() === 'dpop' && !!jkt,
         '3. PUBLIC: the same request with a proof is issued a DPoP token ' +
         'set whose access token carries the key\'s thumbprint',
         r.status + ' ' + bound.token_type + ' ' + jkt + ' ' +
         r.text.slice(0, 160));

    // --- 4. the refresh token ------------------------------------------------
    r = await request(port, 'POST', '/oauth2/token', {
      grant_type: 'refresh_token', refresh_token: bound.refresh_token || '',
      client_id: CONSOLE }, {});
    note(!!bound.refresh_token && r.status === 400 && !(r.json || {})
           .access_token,
         '4a. PUBLIC: its refresh token redeemed with no proof is refused',
         !!bound.refresh_token + ' ' + r.status + ' ' + r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/token', {
      grant_type: 'refresh_token', refresh_token: bound.refresh_token || '',
      client_id: CONSOLE }, { dpop: proofFor('POST', TOKEN_URL) });
    note(r.status === 200 && !!(r.json || {}).access_token &&
         ((claimsOf((r.json || {}).access_token).cnf || {}).jkt || '') === jkt,
         '4b. and with its proof it is redeemed, for a token bound to the ' +
         'same key', r.status + ' ' + r.text.slice(0, 160));

    // --- 5. at /admin-api ----------------------------------------------------
    before = coded('STS-OAUTH-0944');
    r = await request(port, 'GET', ME, null,
                      { authorization: 'Bearer ' + unbound });
    await settle();
    note(r.status === 401 && coded('STS-OAUTH-0944') === before + 1,
         '5a. PUBLIC: an unbound token issued to the console is refused at ' +
         '/admin-api, recorded under STS-OAUTH-0944',
         r.status + ' ' + r.text.slice(0, 200));
    const boundAdmin = await mintFor({ jkt: jkt });
    r = await request(port, 'GET', ME, null,
                      { authorization: 'Bearer ' + boundAdmin });
    note(r.status === 401,
         '5b. a bound one sent as a Bearer token is refused',
         r.status + ' ' + r.text.slice(0, 160));
    r = await request(port, 'GET', ME, null, {
      authorization: 'DPoP ' + boundAdmin,
      dpop: proofFor('GET', base + ME, boundAdmin) });
    note(r.status === 200 && r.json && r.json.caller &&
         r.json.caller.name === WRITER && r.json.write === true,
         '5c. and a bound one with its proof is accepted, as the person it ' +
         'names', r.status + ' ' + r.text.slice(0, 200));

    // --- 6. another public client --------------------------------------------
    r = await ask(OTHER, {});
    note(r.status === 200 && !!(r.json || {}).access_token &&
         String((r.json || {}).token_type || '').toLowerCase() === 'bearer',
         '6. another public client is not touched: it is issued a bearer ' +
         'token with no proof', r.status + ' ' + r.text.slice(0, 200));

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
  const out = path.join(os.tmpdir(), 'cp-' + process.pid + '-' + Date.now() +
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
                                  AG_ROOT: ROOT, AG_OUT: out }),
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
  name: 'console_public_client',
  describe: 'the admin console as a public client is DPoP-bound at the ' +
            'token endpoint and at /admin-api; confidential, it is as it ' +
            'was (#446)',
  run: run
};
