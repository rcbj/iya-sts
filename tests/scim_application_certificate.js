// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scim_application_certificate.js
//
// ===========================================================================
// SCIM: A CLIENT CERTIFICATE HELD TO THE APPLICATION'S DECLARED SCOPES
// (#1048, from #520), OVER REAL HANDSHAKES.
//
// `scim/scim_auth.ts` (`attemptClientCertificate()`, `settleDecision()`)
// argues the design and `scim/CLAUDE.md` (6a-ii) records it: a TLS client
// certificate this realm issued to an APPLICATION is that application at
// `/scim/v2`, and may do only what its `oauthAllowedScope` declares of
// `scim:read` and `scim:write`, asked on every request. What is held here,
// each with the request that must work and the requests that must not:
//
//   1. an application declaring both reads (200) and writes (201);
//   2. one declaring only `scim:read` reads, and a write is 403,
//      STS-SCIM-0083;
//   3. one declaring neither is 403 on a read, STS-SCIM-0083;
//   4. withdrawing `scim:write` from the first cuts its certificate off at
//      once, with no new certificate;
//   5. a PERSON's certificate keeps the rule it had: both, with no
//      declaration anywhere;
//   6. the realm boundary: an application certificate another realm issued
//      is not a credential here (401), even for an identifier that declares
//      both here;
//   7. revocation: a revoked application certificate is not a credential
//      (401);
//   8. with no certificate at all, 401;
//   9. the description: GET /admin-api/scim marks the scheme
//      `applicationScoped` and carries the policy sentence, and the
//      ServiceProviderConfig's scheme says the same.
//
// Every refusal by STS-SCIM-0083 is asserted by its status AND by its code,
// read back off `/admin-api/audit`, because a code is recorded and never
// sent.
//
// **A CHILD**, for `tests/gnap_mtls_trust.js`'s reason: it loads the whole
// stack, on an HTTPS listener that asks for a client certificate exactly as
// the main port does.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'scim_application_certificate',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// THE CHILD. Shipped as source, so it carries everything it uses.
// ---------------------------------------------------------------------------
function childMain() {
  const ROOT_DIR = process.env.M_ROOT;
  const OUT = process.env.M_OUT;
  const fsC = require('fs');
  const https = require('https');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const applications = require(ROOT_DIR + '/common/applications');
    const pki = require(ROOT_DIR + '/common/pki');
    const realms = require(ROOT_DIR + '/common/realms');
    const tlsServer = require(ROOT_DIR + '/tls/tls_server');
    const tlsClient = require(ROOT_DIR + '/common/tls_client_certificates');

    await pki.ensureScope('');
    const serverCert = tlsServer.serverCertificate();
    const server = https.createServer(Object.assign({
      cert: serverCert.certPem, key: serverCert.privateKeyPem,
      ca: tlsServer.clientTruststoreOptions().ca,
      requestCert: true, rejectUnauthorized: false
    }, tlsServer.protocolOptions()), app);
    tlsServer.trustClientCertificatesOn(server,
                                        'the SCIM certificate test listener');
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const request = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.json !== undefined ? JSON.stringify(o.json) : '';
        const headers = {};
        if (method !== 'GET') {
          headers['content-type'] = o.type || 'application/json';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = https.request({ host: '127.0.0.1', port: port,
          path: urlPath, method: method, headers: headers,
          cert: o.tls ? o.tls.cert : undefined,
          key: o.tls ? o.tls.key : undefined,
          rejectUnauthorized: false, agent: false }, function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let parsed = null;
            try {
              parsed = JSON.parse(text);
            } catch (e) {
              parsed = { raw: text.slice(0, 300) };
            }
            resolve({ status: res.statusCode, json: parsed, text: text });
          });
        });
        req.on('error', function (e) {
          resolve({ status: 0, json: { error: e.message }, text: '' });
        });
        req.end(body);
      });
    };
    const api = function (op) {
      return request('GET', '/admin-api' + op);
    };
    const settle = function () {
      return new Promise(function (r) { setTimeout(r, 30); });
    };
    const codeCount = async function (code) {
      await settle();
      const r = await api('/audit?per=500&code=' + encodeURIComponent(code));
      const rows = (r.json && (r.json.rows || r.json.events)) || [];
      return rows.filter(function (row) {
        return JSON.stringify(row).indexOf('/scim') >= 0;
      }).length;
    };
    const raises = async function (code, fn) {
      const before = await codeCount(code);
      const answer = await fn();
      const after = await codeCount(code);
      answer.coded = after > before;
      return answer;
    };
    const short = function (r) {
      return r.status + ' ' + String(r.text || '').slice(0, 300);
    };

    // THE APPLICATIONS, each an OAuth client whose declaration is the only
    // thing that differs. No hyphen in an identifier: a certificate holder is
    // named by a printable identifier without one.
    const create = function (id, scopes) {
      const fields = { oauthClientId: id };
      if (scopes.length) {
        fields.oauthAllowedScope = scopes;
      }
      const made = applications.createApplication({ identifier: id,
        protocols: ['oauth2'], fields: fields });
      note(!!made.ok, 'setup: created the application ' + id,
           JSON.stringify(made.errors || []));
      return made;
    };
    create('scimcertrw', ['scim:read', 'scim:write']);
    create('scimcertro', ['scim:read']);
    create('scimcertnone', []);
    create('scimcertrev', ['scim:read', 'scim:write']);

    const tlsOf = function (made) {
      if (!made || !made.ok) {
        return null;
      }
      return { cert: [made.issued.certificatePem]
                 .concat(made.issued.chainPem || []).join('\n'),
               key: made.issued.privateKeyPem,
               serialHex: made.issued.serialHex };
    };
    const issueApp = async function (id) {
      const made = await tlsClient.issue('', { kind: 'application',
                                               application: id,
                                               keyAlg: 'ec-p256',
                                               label: 'scim' });
      note(!!made.ok, 'setup: issued a TLS client certificate to ' + id,
           JSON.stringify(made.errors || []));
      return tlsOf(made);
    };
    const rw = await issueApp('scimcertrw');
    const ro = await issueApp('scimcertro');
    const none = await issueApp('scimcertnone');
    const rev = await issueApp('scimcertrev');
    const personMade = await tlsClient.issue('', { username: 'scimcertperson',
                                                   keyAlg: 'ec-p256',
                                                   label: 'scim' });
    note(!!personMade.ok, 'setup: issued a TLS client certificate to a ' +
         'person', JSON.stringify(personMade.errors || []));
    const person = tlsOf(personMade);

    const read = function (tlsOpts) {
      return request('GET', '/scim/v2/Users?count=1&attributes=id',
                     { tls: tlsOpts });
    };
    let serial = 0;
    const write = function (tlsOpts) {
      serial += 1;
      return request('POST', '/scim/v2/Users', { tls: tlsOpts,
        type: 'application/scim+json',
        json: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                userName: 'scimcertuser' + process.pid + 'n' + serial } });
    };

    // --- 1. both declared ---------------------------------------------------
    let r = await read(rw);
    note(r.status === 200, '1a. an application declaring scim:read reads ' +
         'with its certificate', short(r));
    r = await write(rw);
    note(r.status === 201, '1b. and declaring scim:write, writes',
         short(r));

    // --- 2. read only -------------------------------------------------------
    r = await read(ro);
    note(r.status === 200, '2a. an application declaring only scim:read ' +
         'reads', short(r));
    r = await raises('STS-SCIM-0083', function () {
      return write(ro);
    });
    note(r.status === 403 && r.coded, '2b. and a write is 403, ' +
         'STS-SCIM-0083', short(r));
    note(r.json && Array.isArray(r.json.schemas) &&
         r.json.schemas.indexOf(
           'urn:ietf:params:scim:api:messages:2.0:Error') >= 0 &&
         /scim:write/.test(String(r.json.detail || '')),
         '2c. the refusal is an RFC 7644 section 3.12 Error naming the ' +
         'scope', short(r));

    // --- 3. neither -------------------------------------------------------
    r = await raises('STS-SCIM-0083', function () {
      return read(none);
    });
    note(r.status === 403 && r.coded, '3. an application declaring neither ' +
         'is refused a read, STS-SCIM-0083', short(r));

    // --- 4. withdrawn -------------------------------------------------------
    const removed = applications.updateApplication('scimcertrw',
      { attribute: 'oauthAllowedScope', mode: 'remove', value: 'scim:write' });
    note(!!removed.ok, 'setup: scim:write withdrawn from scimcertrw',
         JSON.stringify(removed.errors || []));
    r = await raises('STS-SCIM-0083', function () {
      return write(rw);
    });
    note(r.status === 403 && r.coded, '4a. withdrawing the declaration cuts ' +
         'the same certificate off at once, STS-SCIM-0083', short(r));
    r = await read(rw);
    note(r.status === 200, '4b. while what it still declares still works',
         short(r));

    // --- 5. a person --------------------------------------------------------
    r = await read(person);
    note(r.status === 200, '5a. a person\'s certificate reads, as it did',
         short(r));
    r = await write(person);
    note(r.status === 201, '5b. and writes, with no declaration anywhere',
         short(r));

    // --- 6. another realm ---------------------------------------------------
    const OTHER = 'scimcertother';
    if (!realms.get(OTHER)) {
      realms.create({ id: OTHER, name: OTHER });
    }
    await pki.ensureScope(OTHER);
    const foreignMade = await realms.run(realms.get(OTHER), function () {
      return tlsClient.issue(OTHER, { kind: 'application',
                                      application: 'scimcertro',
                                      keyAlg: 'ec-p256', label: 'scim' });
    });
    note(!!foreignMade.ok, 'setup: another realm issued a certificate to ' +
         'an identifier this realm knows',
         JSON.stringify(foreignMade.errors || []));
    r = await read(tlsOf(foreignMade));
    note(r.status === 401, '6. an application certificate another realm ' +
         'issued is not a credential here, whatever its identifier declares ' +
         'here', short(r));

    // --- 7. revoked ---------------------------------------------------------
    r = await read(rev);
    note(r.status === 200, 'setup: the certificate to be revoked reads ' +
         'first', short(r));
    const revoked = tlsClient.revoke('', 'scimcertrev', rev.serialHex,
                                     'keyCompromise', 'application');
    note(!!(revoked && revoked.ok), 'setup: revoked',
         JSON.stringify(revoked));
    r = await read(rev);
    note(r.status === 401, '7. a revoked application certificate is not a ' +
         'credential', short(r));

    // --- 8. nothing ---------------------------------------------------------
    r = await read(null);
    note(r.status === 401, '8. with no certificate, 401', short(r));

    // --- 9. the description -------------------------------------------------
    const described = await api('/scim');
    const body = described.json || {};
    const auth = body.authentication || body.auth || {};
    const row = (auth.schemes || []).filter(function (one) {
      return one.id === 'clientcert';
    })[0] || {};
    note(row.applicationScoped === true && row.scoped === false &&
         /STS-SCIM-0083/.test(String(row.description || '')),
         '9a. GET /admin-api/scim marks the certificate scheme ' +
         'applicationScoped and says so in its description',
         JSON.stringify(row).slice(0, 400));
    note((auth.policy || []).some(function (one) {
      return /APPLICATION'S CERTIFICATE IS HELD TO ITS DECLARED SCOPES/
        .test(String(one));
    }), '9b. and the access control policy carries the sentence',
         JSON.stringify(auth.policy || []).slice(0, 400));
    const spc = await request('GET', '/scim/v2/ServiceProviderConfig',
                              { tls: rw });
    const published = ((spc.json && spc.json.authenticationSchemes) || [])
      .filter(function (one) {
        return one.type === 'tlsclientauth';
      })[0] || {};
    note(/STS-SCIM-0083/.test(String(published.description || '')),
         '9c. the ServiceProviderConfig publishes the same description',
         JSON.stringify(published).slice(0, 400));

    server.close();
    fsC.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fsC.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== /scim/v2 over HTTPS with application and person ' +
             'certificates ===');
  const out = path.join(os.tmpdir(), 'scim-app-cert-' + process.pid + '-' +
                        nodeCrypto.randomBytes(8).toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|LDAPS_|KRB5_|GNAP_|SCIM_|CONFIG_FILE$)/
      .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', M_ROOT: ROOT, M_OUT: out,
                                  STS_HTTPS: 'true',
                                  ADMIN_API_AUTH_REQUIRED: 'false',
                                  ADMIN_API_CLIENT_SECRET:
                                    nodeCrypto.randomBytes(24)
                                      .toString('base64url') }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'SCIM application certificate scopes',
  describe: '#1048: a TLS client certificate this realm issued to an ' +
            'application is held at /scim/v2 to the scim:read and ' +
            'scim:write its oauthAllowedScope declares, asked on every ' +
            'request (STS-SCIM-0083); a person\'s certificate may do both; ' +
            'another realm\'s and a revoked certificate are not ' +
            'credentials; and the description says so in every place',
  run: run
};
