// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/oauth2_response_modes.js
//
// ===========================================================================
// A CLIENT'S OWN RESPONSE MODES, AND THE PKCE COMPARISON (#2247, ASVS 5.0.0
// 10.4.12 and 11.2.4).
//
// The whole stack in a child process:
//
//   A. `oauthResponseMode` is a closed set: every mode the authorization
//      endpoint performs (`response_modes_supported` with JARM on), and an
//      add outside it is refused.
//   B. A client with a list is held to it at /oauth2/authorize: a mode it
//      does not list is answered unauthorized_client at its redirect, and so
//      is a request naming none whose response type's default (query for
//      code) is not listed; a listed mode gets past the check.
//   C. A client with no list is answered as before.
//   D. The PKCE verifier is compared through `crypto.js`'s constant-time
//      comparison, and a wrong verifier is still refused.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'oauth2_response_modes',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's whole program, serialised with toString() and run by `node -e`
// — exempt from the Entering/Leaving rule (root CLAUDE.md, Code style), and it
// carries its errors on the result it writes.
function childMain() {
  const ROOT = process.env.RM_ROOT;
  const OUT = process.env.RM_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function ask(port, p) {
    return new Promise(function (resolve) {
      const req = http.request({ host: '127.0.0.1', port: port, path: p,
                                 method: 'GET', agent: false },
                               function (res) {
        let text = '';
        res.on('data', function (chunk) { text += chunk; });
        res.on('end', function () {
          resolve({ status: res.statusCode, text: text,
                    location: String(res.headers.location || '') });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, text: e.message, location: '' });
      });
      req.end();
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const errorCodes = require(ROOT + '/common/error_codes');
    const jarm = require(ROOT + '/oauth-oidc/jarm');
    const stsCrypto = require(ROOT + '/common/crypto');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    // --- A. The closed set ------------------------------------------------
    const expected = ['query', 'fragment', 'form_post'].concat(jarm.MODES);
    note(JSON.stringify(applications.FLOW_RESPONSE_MODES.slice(0).sort()) ===
           JSON.stringify(expected.slice(0).sort()),
         'A1. oauthResponseMode\'s closed set is every mode the ' +
         'authorization endpoint performs, JARM\'s four included',
         JSON.stringify([applications.FLOW_RESPONSE_MODES, expected]));
    const client = function (id, fields) {
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2', 'oidc'],
        fields: Object.assign({ oauthClientId: id,
                                oauthTokenEndpointAuthMethod: 'none',
                                oauthAllowedScope: ['openid'],
                                oauthRedirectUri: 'https://' + id +
                                  '.example/cb' }, fields || {}) });
    };
    const made = client('rm-post', { oauthResponseMode: ['form_post'] });
    const plain = client('rm-plain');
    note(made.ok && plain.ok &&
         JSON.stringify(applications.allowedResponseModesOf('rm-post')) ===
           '["form_post"]' &&
         applications.allowedResponseModesOf('rm-plain') === null,
         'A2. a list is held on the entry; no list reads as none',
         JSON.stringify([made.errors, plain.errors]));
    const bad = applications.updateApplication('rm-post',
      { attribute: 'oauthResponseMode', mode: 'add', value: 'web_message' });
    note(!bad.ok && errorCodes.codeOf(bad) === 'STS-REG-0203',
         'A3. a mode outside the set is refused, STS-REG-0203',
         JSON.stringify(bad));

    // --- B. Held to the list ----------------------------------------------
    // RFC 7636 section 4.2: a real S256 challenge, 43 characters.
    const challenge = stsCrypto.digest('sha256',
      Buffer.from('rm-verifier-' + 'v'.repeat(40), 'ascii'))
      .toString('base64url');
    const authorize = function (id, mode, type) {
      return ask(port, '/oauth2/authorize?client_id=' + id +
        '&redirect_uri=' + encodeURIComponent('https://' + id + '.example/cb') +
        '&scope=openid&state=s&nonce=n&code_challenge_method=S256' +
        '&code_challenge=' + challenge +
        '&response_type=' + encodeURIComponent(type || 'code') +
        (mode ? '&response_mode=' + encodeURIComponent(mode) : ''));
    };
    const refusedHere = function (r) {
      return /unauthorized_client/.test(r.location + r.text) &&
        /oauthResponseMode/.test(decodeURIComponent(
          (r.location + r.text).replace(/\+/g, ' ')));
    };
    let r = await authorize('rm-post', 'query');
    note(refusedHere(r) && r.location.indexOf('https://rm-post.example/cb') ===
           0,
         'B1. a mode the client does not list is answered ' +
         'unauthorized_client at its redirect (STS-OAUTH-1016)',
         r.status + ' ' + (r.location || r.text).slice(0, 300));
    r = await authorize('rm-post', '');
    note(refusedHere(r),
         'B2. naming none is judged as the default, query for code, which ' +
         'this client does not list',
         r.status + ' ' + (r.location || r.text).slice(0, 300));
    r = await authorize('rm-post', 'form_post');
    note(!refusedHere(r) && r.status !== 0,
         'B3. the listed mode gets past the check',
         r.status + ' ' + (r.location || r.text).slice(0, 300));
    const added = applications.updateApplication('rm-post',
      { attribute: 'oauthResponseMode', mode: 'add', value: 'query' });
    r = await authorize('rm-post', '');
    note(added.ok && !refusedHere(r),
         'B4. once query is listed, a request naming none gets past it',
         r.status + ' ' + (r.location || r.text).slice(0, 300));

    // --- C. No list -------------------------------------------------------
    for (const mode of ['', 'query', 'form_post', 'fragment']) {
      r = await authorize('rm-plain', mode);
      note(!refusedHere(r), 'C1. no list restricts nothing: response_mode="' +
           mode + '"', r.status + ' ' + (r.location || r.text).slice(0, 200));
    }

    // --- D. PKCE ----------------------------------------------------------
    const source = fs.readFileSync(ROOT + '/oauth-oidc/oauth2.ts', 'utf8')
      .replace(/\s+/g, ' ');
    note(/stsCrypto\.constantTimeEquals\( ?computed, ?String\(record\.code_challenge\)\)/
           .test(source) &&
         source.indexOf('computed !== record.code_challenge') < 0,
         'D1. the code_verifier is compared through crypto.js\'s ' +
         'constant-time comparison, and the plain !== is gone');
    note(stsCrypto.constantTimeEquals('abc', 'abc') &&
         !stsCrypto.constantTimeEquals('abc', 'abd') &&
         !stsCrypto.constantTimeEquals('abc', 'abcd') &&
         !stsCrypto.constantTimeEquals('', 'a'),
         'D2. that comparison is equality, a length difference included');

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rm-' + process.pid + '-' + Date.now() +
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
                                  RM_ROOT: ROOT, RM_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
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
  name: 'oauth2_response_modes',
  describe: 'a client\'s own allowed response modes at the authorization ' +
            'endpoint (oauthResponseMode, #2247), and the PKCE verifier ' +
            'compared in constant time',
  run: run
};
