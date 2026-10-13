// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/assertion_grant_unknown_subject.js
// ===========================================================================
// A VALID ASSERTION ABOUT NOBODY IS REFUSED IN PRODUCT, AND NOBODY IS MADE
// (#410, 2026-10-02).
//
// The RFC 7523 JWT bearer grant and the RFC 7522 SAML bearer grant verify the
// assertion — signature, declared issuer, audience, expiry, an id that cannot
// be replayed — record the authentication, and then ask the directory for the
// person it names (`oauth2.ts`'s `provisionedPerson()`). A person's `sub` is
// their entry's `entryUUID`, so where the directory holds nobody there is no
// subject to issue a token about, and the grant is refused `invalid_grant`
// under STS-OAUTH-0510. In development recording the authentication CREATES the
// entry (`ldap.autocreateUsers`); product mode never auto-creates, so there the
// refusal is the rule. Nothing asserted it (#113 item 3): the HTTP jobs that
// drive these grants create their person first, precisely to avoid it.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, an
// application declared as both an RFC 7523 issuer (its own RSA key in
// `oauthJwks`) and an RFC 7522 issuer (a self-signed certificate it signs
// with), the process switched to product mode, for each grant:
//
//   1. an assertion naming a person the directory holds is issued a token —
//      the control, so the refusal below is about the subject alone;
//   2. the same assertion naming nobody is refused `invalid_grant`;
//   3. the refusal is on the audit log under STS-OAUTH-0510;
//   4. and the directory still holds nobody by that name.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'assertion_grant_unknown_subject',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.UG_ROOT;
  const OUT = process.env.UG_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function post(port, form) {
    return new Promise(function (resolve, reject) {
      const body = new URLSearchParams(form).toString();
      const req = http.request({ host: '127.0.0.1', port: port,
        path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Length': Buffer.byteLength(body) } },
      function (res) {
        let text = '';
        res.on('data', function (d) { text += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: text, json: json });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  }
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const audit = require(ROOT_DIR + '/common/audit');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const signer = require(ROOT_DIR + '/tests/vendored/saml_xmldsig.js');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const TOKEN = 'http://127.0.0.1:' + port + '/oauth2/token';
    const stamp = Date.now().toString(36);
    const JWT_ISS = 'urn:test:ug-jwt-' + stamp;
    const SAML_ISS = 'urn:test:ug-saml-' + stamp;
    const KNOWN = 'ug-known-' + stamp;

    // The RFC 7523 key: the application's own, in its JWKS.
    const pair = nodeCrypto.generateKeyPairSync('rsa',
                                                { modulusLength: 2048 });
    const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                              { kid: 'ug-' + stamp, alg: 'RS256',
                                use: 'sig' });
    // The RFC 7522 certificate: self-signed, pinned on the application.
    const samlCert = stsCrypto.selfSignedRsaCertificate({
      commonName: 'ug saml issuer ' + stamp });

    applications.createApplication({ identifier: 'ug-client-' + stamp,
      protocols: ['oauth2'],
      fields: {
        oauthClientId: 'ug-client-' + stamp,
        oauthTokenEndpointAuthMethod: 'none',
        oauthGrantType: ['urn:ietf:params:oauth:grant-type:jwt-bearer',
                         'urn:ietf:params:oauth:grant-type:saml2-bearer'],
        oauthJwks: JSON.stringify({ keys: [jwk] }),
        oauthAssertionIssuer: JWT_ISS,
        oauthSamlAssertionIssuer: SAML_ISS,
        oauthSamlAssertionSigningCertificate: samlCert.certPem
      } });
    ldap.createUser(KNOWN, { invent: false });

    const jwtFor = function (sub) {
      const head = b64u({ alg: 'RS256', typ: 'JWT', kid: jwk.kid });
      const now = Math.floor(Date.now() / 1000);
      const body = b64u({ iss: JWT_ISS, sub: sub, aud: TOKEN, iat: now,
                          exp: now + 120,
                          jti: nodeCrypto.randomBytes(12).toString('hex') });
      const sig = nodeCrypto.sign('sha256', Buffer.from(head + '.' + body),
                                  pair.privateKey).toString('base64url');
      return head + '.' + body + '.' + sig;
    };
    const samlFor = function (sub) {
      const a = signer.buildAssertion({ issuer: SAML_ISS, subject: sub,
                                        audience: TOKEN, recipient: TOKEN });
      return signer.b64u(signer.sign(a, samlCert.privateKeyPem,
                                     samlCert.certPem, {}));
    };
    const GRANTS = [
      { name: 'RFC 7523 (JWT)', type:
          'urn:ietf:params:oauth:grant-type:jwt-bearer', build: jwtFor },
      { name: 'RFC 7522 (SAML)', type:
          'urn:ietf:params:oauth:grant-type:saml2-bearer', build: samlFor }
    ];

    config.setOverride('global.mode', 'product');
    try {
      for (const g of GRANTS) {
        const ok = await post(port, { grant_type: g.type,
                                      assertion: g.build(KNOWN) });
        note(ok.status === 200 && ok.json && ok.json.access_token,
             '1. PRODUCT, ' + g.name + ': an assertion naming a person the ' +
             'directory holds is issued a token (the control)',
             ok.status + ' ' + ok.text.slice(0, 200));

        const nobody = 'ug-nobody-' + g.name.slice(4, 8) + '-' + stamp;
        // Counted before and after, so each grant's refusal is its own row
        // and the second grant cannot pass on the first one's.
        const coded = function () {
          return audit.list().filter(function (event) {
            return event.target === '/oauth2/token' &&
                   event.errorCode === 'STS-OAUTH-0510';
          }).length;
        };
        const rowsBefore = coded();
        const refused = await post(port, { grant_type: g.type,
                                           assertion: g.build(nobody) });
        note(refused.status === 400 && refused.json &&
             refused.json.error === 'invalid_grant' &&
             /no directory entry/i.test(String(
               refused.json.error_description)),
             '2. PRODUCT, ' + g.name + ': the same assertion naming nobody ' +
             'is refused invalid_grant', refused.status + ' ' +
             refused.text.slice(0, 200));
        await new Promise(function (r) { setTimeout(r, 50); });
        const row = coded() === rowsBefore + 1;
        note(!!row, '3. PRODUCT, ' + g.name + ': the refusal is on the ' +
             'audit log under STS-OAUTH-0510',
             row ? 'one new row' : 'no new STS-OAUTH-0510 row');
        const user = helpers.userFor(nobody);
        note(!user || !user.sub, '4. PRODUCT, ' + g.name + ': and the ' +
             'directory still holds nobody by that name',
             JSON.stringify(user && user.sub));
      }
    } finally {
      config.clearOverride('global.mode');
    }
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
  const out = path.join(os.tmpdir(), 'ug-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  UG_ROOT: ROOT, UG_OUT: out }),
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
  name: 'assertion_grant_unknown_subject',
  describe: 'an RFC 7523 or RFC 7522 assertion naming nobody is refused in ' +
            'product under STS-OAUTH-0510, and nobody is created (#410)',
  run: run
};
