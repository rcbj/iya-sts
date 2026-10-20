// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/vc_trusted_list.js
//
// ===========================================================================
// THE ISSUER'S LIST OF TRUSTED ENTITIES (ETSI TS 119 602) AT
// /oid4vci/trusted-list (rcbj, 2026-10-17).
//
// In a CHILD PROCESS with the whole stack and its PKI (keys certified, as
// `jose_certificate_header.js` waits for them):
//   1. the list is a compact JWS, application/jwt, signed ES256 with the
//      signer's chain in x5c — the leaf holding the signing key, x5t#S256 its
//      digest, the chain ending under the service Root and the Root not in
//      it — which is what a wallet checks it by;
//   2. it says what the standard asks in its JSON binding: sequence 1,
//      ListIssueDateTime and NextUpdate oid4vci.trustedListLifetimeH apart,
//      DistributionPoints and a pointer to itself, and one trusted entity
//      whose /Issuance and /Revocation services each name the Root — the
//      anchor a credential's x5c and a Status List Token's both end under;
//   3. it is KEPT: asked again it is the same bytes, and If-None-Match
//      answers 304;
//   4. what it says changing signs it again with the next sequence number;
//   5. with its certificate header set to `none` there is no chain to sign
//      it with, and it is not served (503).
//
// In a child for `jose_certificate_header.js`'s reason: the stack builds a
// certificate authority and registers every route on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'vc_trusted_list',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.VTL_ROOT;
  const OUT = process.env.VTL_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function get(port, urlPath, headers) {
    return new Promise(function (resolve, reject) {
      http.get({ host: '127.0.0.1', port: port, path: urlPath,
                 headers: headers || {} }, function (res) {
        const chunks = [];
        res.on('data', function (c) { chunks.push(c); });
        res.on('error', reject);
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: Buffer.concat(chunks).toString('utf8') });
        });
      }).on('error', reject);
    });
  }
  function part(compact, i) {
    return JSON.parse(Buffer.from(String(compact).split('.')[i], 'base64url')
                            .toString('utf8'));
  }
  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const config = require(ROOT_DIR + '/common/config');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const pki = require(ROOT_DIR + '/common/pki');

    const certified = function () {
      return !!pki.certificateFor('default', 'jose', 'ES256:P-256') &&
             !!pki.certificateFor('default', 'jose', 'RS256');
    };
    for (let i = 0; i < 30 && !certified(); i++) {
      await sleep(100);
    }
    if (!certified()) {
      await pki.certifyKeySet('default', helpers.stsKeysFor.of('default'));
    }
    for (let i = 0; i < 50 && !certified(); i++) {
      await sleep(100);
    }
    note(certified(), 'precondition: the default realm\'s ES256 and RS256 ' +
         'keys are certified');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const origin = 'http://127.0.0.1:' + port;
    const listUrl = origin + '/oid4vci/trusted-list';
    const rootPem = pki.serviceRoot().certificatePem;
    const rootB64 = String(rootPem).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '');
    const root = new nodeCrypto.X509Certificate(rootPem);

    // --- 1. the signature and its chain --------------------------------------
    const got = await get(port, '/oid4vci/trusted-list');
    const header = got.status === 200 ? part(got.text, 0) : {};
    const chain = (header.x5c || []).map(function (b64) {
      return new nodeCrypto.X509Certificate(Buffer.from(b64, 'base64'));
    });
    const parts = String(got.text).split('.');
    const verified = chain.length > 0 && nodeCrypto.verify('sha256',
      Buffer.from(parts[0] + '.' + parts[1]),
      { key: chain[0].publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(parts[2] || '', 'base64url'));
    const top = chain[chain.length - 1];
    note(got.status === 200 &&
         /^application\/jwt/.test(String(got.headers['content-type'])) &&
         header.alg === 'ES256' && verified &&
         header['x5t#S256'] === nodeCrypto.createHash('sha256')
           .update(Buffer.from(header.x5c[0], 'base64')).digest('base64url') &&
         !!top && top.issuer === root.subject && top.verify(root.publicKey) &&
         (header.x5c || []).indexOf(rootB64) < 0,
         '1. a compact JWS, application/jwt, ES256, verified with the key in ' +
         'its x5c leaf; x5t#S256 that leaf\'s digest; the chain ends under ' +
         'the Root, which is not in it',
         got.status + ' ' + JSON.stringify({ alg: header.alg,
           x5c: chain.length, verified: verified,
           top: top ? top.subject : null }));

    // --- 2. what it says -----------------------------------------------------
    const lote = got.status === 200 ? (part(got.text, 1).LoTE || {}) : {};
    const scheme = lote.ListAndSchemeInformation || {};
    const entity = (lote.TrustedEntitiesList || [])[0] || {};
    const services = (entity.TrustedEntityServices || []).map(function (s) {
      return s.ServiceInformation || {};
    });
    const kinds = services.map(function (s) {
      return String(s.ServiceTypeIdentifier || '').split('/').pop();
    });
    const anchorsRoot = services.every(function (s) {
      const certs = (s.ServiceDigitalIdentity || {}).X509Certificates || [];
      return certs.length === 1 && certs[0].val === rootB64;
    });
    const span = Date.parse(scheme.NextUpdate) -
                 Date.parse(scheme.ListIssueDateTime);
    const pointer = (scheme.PointersToOtherLoTE || [])[0] || {};
    note(scheme.LoTEVersionIdentifier === 1 &&
         scheme.LoTESequenceNumber === 1 &&
         span === 24 * 3600 * 1000 &&
         JSON.stringify(scheme.DistributionPoints) ===
           JSON.stringify([listUrl]) &&
         pointer.LoTELocation === listUrl &&
         String(scheme.LoTEType).indexOf(listUrl + '/') === 0 &&
         JSON.stringify(kinds) === JSON.stringify(['Issuance', 'Revocation']) &&
         anchorsRoot && (lote.TrustedEntitiesList || []).length === 1,
         '2. sequence 1, NextUpdate a day on, its own distribution point and ' +
         'pointer, its scheme\'s URIs under its own URL, and one entity ' +
         'whose Issuance and Revocation services each name the Root',
         JSON.stringify({ seq: scheme.LoTESequenceNumber, span: span,
                          kinds: kinds, anchorsRoot: anchorsRoot,
                          type: scheme.LoTEType }));

    // --- 3. kept ---------------------------------------------------------------
    const again = await get(port, '/oid4vci/trusted-list');
    const notModified = await get(port, '/oid4vci/trusted-list',
      { 'if-none-match': String(got.headers.etag || '') });
    note(again.text === got.text && notModified.status === 304 &&
         String(got.headers['cache-control']) === 'no-cache',
         '3. asked again it is the same signed list, and If-None-Match ' +
         'answers 304', again.status + ' ' + notModified.status);

    // --- 4. signed again when it changes ------------------------------------
    config.setOverride('oid4vci.issuerDisplayName', 'Another Issuer Name');
    const changed = await get(port, '/oid4vci/trusted-list');
    const changedScheme = changed.status === 200
      ? (part(changed.text, 1).LoTE || {}).ListAndSchemeInformation || {} : {};
    note(changed.status === 200 && changed.text !== got.text &&
         changedScheme.LoTESequenceNumber === 2 &&
         ((changedScheme.SchemeOperatorName || [])[0] || {}).value ===
           'Another Issuer Name',
         '4. what it says changing signs it again with the next sequence ' +
         'number', JSON.stringify({ seq: changedScheme.LoTESequenceNumber }));
    config.clearOverride('oid4vci.issuerDisplayName');

    // --- 5. no chain, no list -------------------------------------------------
    config.setOverride('oid4vci.trustedListCertificateHeader', 'none');
    const none = await get(port, '/oid4vci/trusted-list');
    config.clearOverride('oid4vci.trustedListCertificateHeader');
    note(none.status === 503,
         '5. with its certificate header off there is no chain to sign ' +
         'with, and it is not served', none.status + ' ' + none.text);

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'vtl-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', VTL_ROOT: ROOT, VTL_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the child process reported its ' +
              'findings', 'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_trusted_list',
  describe: 'The issuer\'s ETSI TS 119 602 List of Trusted Entities: signed ' +
            'with its chain in x5c, the Root as the anchor of credentials ' +
            'and status lists, kept, and signed again with the next ' +
            'sequence number when it changes',
  run: run
};
