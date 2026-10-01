// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_did.js
//
// ---------------------------------------------------------------------------
// A DID DESCRIBING AN APPLICATION (2026-10-01).
//
// An application declared for the `did` family has a did:web under the
// realm's address — did:web:<host>[:realm:<id>]:applications:<identifier> —
// whose document this service advertises at
// <base>/applications/<identifier>/did.json: its didPublicKeyJwk keys as
// JsonWebKey2020 methods, its didService entries and its didAlsoKnownAs.
// `generate-did-key` makes a key pair, publishes the public half and hands the
// private half back once. Asserted, in a CHILD PROCESS serving the stack on a
// loopback port:
//
//   A. no document for an unknown application, one not declared for `did`,
//      or one with no key — each 404 with STS-VC-0114 — and generate-did-key
//      refused (STS-ADMIN-0837) for an undeclared one and another algorithm;
//   B. a generated key pair: the document names it as did#kid under
//      authentication and assertionMethod, publishes no private member,
//      no-store and application/did+json, and the private key handed back
//      signs what the published key verifies; the action's DID is the
//      document's id;
//   C. replace leaves one key; a second generate without it leaves two;
//   D. services and alsoKnownAs in the document, and the value refusals
//      (STS-REG-0204): a private member, a bad service, a relative URI;
//   E. an identifier with ':' and '/' is one percent-encoded component, and
//      its document resolves at the encoded path.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'application_did',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.AD_ROOT;
  const OUT = process.env.AD_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function get(port, urlPath) {
    return new Promise(function (resolve) {
      http.get({ host: '127.0.0.1', port: port, path: urlPath },
               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    json: json, text: text });
        });
      });
    });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const errorCodes = require(ROOT + '/common/error_codes');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const docPath = function (id) {
      return '/applications/' + encodeURIComponent(id) + '/did.json';
    };
    const act = function (body) {
      return actions.applicationsAction(body, [],
        { base: 'http://127.0.0.1:' + port });
    };

    // --- A. Nothing advertised until declared and keyed -------------------
    let r = await get(port, docPath('ad-nobody'));
    note(r.status === 404 && r.headers['cache-control'] === 'no-store',
         'A1. no document for an application this realm does not hold',
         r.status);
    applications.createApplication({ identifier: 'ad-plain',
      protocols: ['oauth2'], fields: {} });
    r = await get(port, docPath('ad-plain'));
    note(r.status === 404, 'A2. no document for an application not ' +
         'declared for did', r.status);
    let g = act({ action: 'generate-did-key', application: 'ad-plain' });
    note(g.ok === false && errorCodes.codeOf(g) === 'STS-ADMIN-0837',
         'A3. generate-did-key is refused for an undeclared application',
         JSON.stringify(g.errors));
    applications.createApplication({ identifier: 'ad-app',
      protocols: ['did'], fields: {} });
    r = await get(port, docPath('ad-app'));
    note(r.status === 404, 'A4. no document for a declared application ' +
         'with no key', r.status);
    g = act({ action: 'generate-did-key', application: 'ad-app',
              algorithm: 'RS256' });
    note(g.ok === false && errorCodes.codeOf(g) === 'STS-ADMIN-0837',
         'A5. an algorithm other than ES256, ES384 or EdDSA is refused');

    // --- B. A generated key pair --------------------------------------------
    g = act({ action: 'generate-did-key', application: 'ad-app' });
    r = await get(port, docPath('ad-app'));
    const doc = r.json || {};
    const vm = (doc.verificationMethod || [])[0] || {};
    note(g.ok && r.status === 200 &&
         /^application\/did\+json/.test(r.headers['content-type'] || '') &&
         r.headers['cache-control'] === 'no-store',
         'B1. a declared application with a key is advertised, ' +
         'application/did+json and no-store', r.status);
    note(doc.id === g.did &&
         doc.id === 'did:web:127.0.0.1%3A' + port + ':applications:ad-app' &&
         vm.id === doc.id + '#' + g.kid && vm.type === 'JsonWebKey2020' &&
         (doc.authentication || [])[0] === vm.id &&
         (doc.assertionMethod || [])[0] === vm.id,
         'B2. the DID is did:web:<host>:applications:<id>, and the key is a ' +
         'method under authentication and assertionMethod', doc.id);
    note(vm.publicKeyJwk && vm.publicKeyJwk.d === undefined &&
         g.privateJwk && g.privateJwk.d && /PRIVATE KEY/.test(g.privateKeyPem),
         'B3. the document publishes no private member; the reply carries ' +
         'the private key');
    const signature = nodeCrypto.sign('sha256', Buffer.from('ad'),
      { key: g.privateKeyPem, dsaEncoding: 'ieee-p1363' });
    note(nodeCrypto.verify('sha256', Buffer.from('ad'),
      { key: nodeCrypto.createPublicKey({ key: vm.publicKeyJwk,
                                          format: 'jwk' }),
        dsaEncoding: 'ieee-p1363' }, signature),
         'B4. the private key handed back signs what the published key ' +
         'verifies');

    // --- C. Replace, and add ------------------------------------------------
    const second = act({ action: 'generate-did-key', application: 'ad-app',
                         algorithm: 'EdDSA' });
    r = await get(port, docPath('ad-app'));
    note(second.ok && (r.json.verificationMethod || []).length === 2,
         'C1. a second key pair without replace leaves two keys',
         (r.json.verificationMethod || []).length);
    const third = act({ action: 'generate-did-key', application: 'ad-app',
                        algorithm: 'ES384', replace: 'yes' });
    r = await get(port, docPath('ad-app'));
    note(third.ok && (r.json.verificationMethod || []).length === 1 &&
         r.json.verificationMethod[0].id === third.verificationMethod,
         'C2. replace leaves the new key alone',
         (r.json.verificationMethod || []).length);

    // --- D. Services, alsoKnownAs, refusals -------------------------------
    const add = function (attribute, value) {
      return applications.updateApplication('ad-app',
        { mode: 'add', attribute: attribute, value: value });
    };
    add('didService', 'LinkedDomains|https://app.example.com');
    add('didAlsoKnownAs', 'https://app.example.com');
    r = await get(port, docPath('ad-app'));
    note((r.json.service || [])[0] &&
         r.json.service[0].type === 'LinkedDomains' &&
         r.json.service[0].serviceEndpoint === 'https://app.example.com' &&
         r.json.service[0].id === r.json.id + '#service-1' &&
         (r.json.alsoKnownAs || [])[0] === 'https://app.example.com',
         'D1. services and alsoKnownAs are in the document',
         JSON.stringify(r.json.service));
    const priv = add('didPublicKeyJwk', JSON.stringify(third.privateJwk));
    const badService = add('didService', 'no bar here');
    const badAka = add('didAlsoKnownAs', 'relative/path');
    note([priv, badService, badAka].every(function (one) {
      return one.ok === false && errorCodes.codeOf(one) === 'STS-REG-0204';
    }), 'D2. a private member, a bad service and a relative URI are each ' +
         'refused with STS-REG-0204',
         JSON.stringify([priv.errors, badService.errors, badAka.errors]));

    // --- E. An identifier with reserved characters --------------------------
    const odd = 'urn:example:app/1';
    applications.createApplication({ identifier: odd, protocols: ['did'],
                                     fields: {} });
    const oddKey = act({ action: 'generate-did-key', application: odd });
    r = await get(port, docPath(odd));
    note(oddKey.ok && r.status === 200 && /:applications:urn%3Aexample%3Aapp%2F1$/
           .test(r.json && r.json.id || ''),
         'E1. an identifier with ":" and "/" is one percent-encoded ' +
         'component, resolved at the encoded path', r.json && r.json.id);
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'application-did-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', AD_ROOT: ROOT, AD_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_did',
  describe: 'a DID describing an application: the did:web this service ' +
            'advertises for an application declared for the did family, ' +
            'its document, generate-did-key and the value refusals',
  run: run
};
