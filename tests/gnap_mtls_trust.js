'use strict';
//
// File: gnap_mtls_trust.js
//
// ===========================================================================
// GNAP MUTUAL TLS: THE TWO TRUST MODELS, REVOCATION IN BOTH, AND THE BINDING
// TO AN APPLICATION ENTRY (#107, 2026-09-23), OVER REAL HANDSHAKES.
//
// `gnap/gnap_proof.ts` (MUTUAL TLS, TWO TRUST MODELS) argues the design and
// `common/applications.js`'s `gnapMtlsTrustFor()` is the one combination of
// the realm's `gnap.mtlsTrust` with an entry's `gnapMtlsTrust`. What is held
// here, each with the request that must work and the requests that must not:
//
//   1. THE REGISTRY, in process: the combination (stricter wins, `auto` by
//      mode) and the write door's two refusals, STS-REG-0195 and 0196.
//   2. THE GRANT ENDPOINT, in a child process on an HTTPS listener that asks
//      for a client certificate exactly as the main port does:
//        a. `pinned`: a registered self-signed certificate proves its key by
//           value and as a JWK; no certificate is STS-GNAP-0277; another
//           certificate is STS-GNAP-0278, for a certificate key and for a
//           JWK; a pinned certificate this realm issued and then REVOKED is
//           refused on revocation (STS-PKI-0118).
//        b. `pki`: the same self-signed certificate is STS-GNAP-0287; a
//           certificate this realm issued to the entry binds by value with
//           nothing pinned and records its thumbprint; a second one from the
//           authority (rotation) binds too and is recorded; an instance
//           identifier with a newer certificate than the one pinned binds;
//           another entry's certificate is STS-GNAP-0291; one the entry no
//           longer holds is 0292; a revoked one is STS-PKI-0118; a foreign
//           authority's certificate binds by the entry's RFC 8705 subject
//           and is refused for a different subject (0290), for none (0288)
//           and for two (0289).
//        c. a per-client override: `pki` on an entry in a pinned realm
//           refuses its self-signed key (stricter), and a stored `pinned` is
//           ignored once the realm is pki (never weaker).
//        d. the product default: with the setting at `auto`, product refuses
//           the self-signed key (0287) and development accepts it.
//
// Every refusal is asserted by its GNAP error AND by its STS code, read back
// off `/admin-api/audit`, because a code is recorded and never sent.
//
// **THE FOREIGN CERTIFICATES ARE OPENSSL'S**, made at run time in a temporary
// directory and removed after: nothing here is committed key material.
//
// **A CHILD**, for `tests/acme_protocol.js`'s reason: it loads the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'gnap_mtls_trust',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE REGISTRY.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 1. applications.js ===');
  const applications = require('../common/applications');
  const config = require('../common/config');
  const at = function (realm, entry) {
    config.setOverride('gnap.mtlsTrust', realm);
    const answer = applications.gnapMtlsTrustFor(
      entry ? { gnapMtlsTrust: entry } : null).trust;
    config.clearOverride('gnap.mtlsTrust');
    return answer;
  };
  t.check(at('pinned') === 'pinned' && at('pki') === 'pki',
          '1a. the realm\'s setting is the model with no entry');
  t.check(at('pinned', 'pki') === 'pki' && at('pki', 'pinned') === 'pki',
          '1b. an entry may make it stricter and never weaker');
  config.setOverride('global.mode', 'product');
  const product = applications.gnapMtlsTrustFor(null).trust;
  config.setOverride('global.mode', 'development');
  const development = applications.gnapMtlsTrustFor(null).trust;
  config.clearOverride('global.mode');
  t.check(product === 'pki' && development === 'pinned',
          '1c. auto is pki in product and pinned in development',
          product + ' / ' + development);
  config.setOverride('gnap.mtlsTrust', 'pki');
  let p = applications.gnapMtlsTrustProblem('gnapMtlsTrust', 'pinned');
  t.check(p && p.code === 'STS-REG-0196', '1d. writing pinned where the ' +
          'realm is pki is refused', JSON.stringify(p));
  t.check(applications.gnapMtlsTrustProblem('gnapMtlsTrust', 'pki') === null &&
          applications.gnapMtlsTrustProblem('gnapMtlsTrust', '') === null,
          '1e. pki and a clear are not');
  config.setOverride('gnap.mtlsTrust', 'pinned');
  t.check(applications.gnapMtlsTrustProblem('gnapMtlsTrust', 'pinned') ===
            null &&
          applications.gnapMtlsTrustProblem('gnapMtlsTrust', 'pki') === null,
          '1f. both are written where the realm pins');
  p = applications.gnapMtlsTrustProblem('gnapMtlsTrust', 'chain');
  t.check(p && p.code === 'STS-REG-0195', '1g. a value that is not a model ' +
          'is refused', JSON.stringify(p));
  config.clearOverride('gnap.mtlsTrust');
  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 2. THE GRANT ENDPOINT. Shipped as source into a child.
// ---------------------------------------------------------------------------
function childMain() {
  const ROOT_DIR = process.env.M_ROOT;
  const OUT = process.env.M_OUT;
  const M = JSON.parse(process.env.M_MATERIAL);
  const fsC = require('fs');
  const https = require('https');
  const crypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const read = function (file) {
    return fsC.readFileSync(file, 'utf8');
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const applications = require(ROOT_DIR + '/common/applications');
    const config = require(ROOT_DIR + '/common/config');
    const pki = require(ROOT_DIR + '/common/pki');
    const tlsServer = require(ROOT_DIR + '/tls/tls_server');
    const tlsClient = require(ROOT_DIR + '/common/tls_client_certificates');

    await pki.ensureScope('');
    const serverCert = tlsServer.serverCertificate();
    const server = https.createServer(Object.assign({
      cert: serverCert.certPem, key: serverCert.privateKeyPem,
      ca: tlsServer.clientTruststoreOptions().ca,
      requestCert: true, rejectUnauthorized: false
    }, tlsServer.protocolOptions()), app);
    tlsServer.trustClientCertificatesOn(server, 'the GNAP mTLS test listener');
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const added = tlsServer.addAnchors(read(M.caCert));
    note(added.added === 1, 'setup: the foreign CA is a client trust anchor',
         JSON.stringify(added));

    const DEMO = 'urn:mock-sts:gnap:demo';
    const request = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.json !== undefined ? JSON.stringify(o.json) : '';
        const headers = {};
        if (method !== 'GET') {
          headers['content-type'] = 'application/json';
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
    const api = function (op, body) {
      return request(body === undefined ? 'GET' : 'POST', '/admin-api' + op,
                     body === undefined ? {} : { json: body });
    };
    const settle = function () {
      return new Promise(function (r) { setTimeout(r, 30); });
    };
    const codeCount = async function (code) {
      await settle();
      const r = await api('/audit?per=500&code=' + encodeURIComponent(code));
      const rows = (r.json && (r.json.rows || r.json.events)) || [];
      return rows.filter(function (row) {
        return JSON.stringify(row).indexOf('/gnap') >= 0;
      }).length;
    };
    const raises = async function (code, fn) {
      const before = await codeCount(code);
      const answer = await fn();
      const after = await codeCount(code);
      answer.coded = after > before;
      return answer;
    };
    const setting = function (key, value) {
      if (value === null) {
        config.clearOverride(key);
      } else {
        config.setOverride(key, value);
      }
    };
    const der64 = function (pem) {
      return new crypto.X509Certificate(pem).raw.toString('base64');
    };
    const x5t = function (pem) {
      return 'x5t:' + crypto.createHash('sha256')
        .update(new crypto.X509Certificate(pem).raw).digest('base64url');
    };
    const certKey = function (pem) {
      return { proof: 'mtls', cert: der64(pem) };
    };
    const grant = function (client, tlsOpts) {
      return request('POST', '/gnap', { tls: tlsOpts, json: {
        access_token: { access: [{ type: DEMO, actions: ['read'] }] },
        client: client } });
    };
    const issued = function (r) {
      return r.status === 200 && r.json && !!r.json.access_token;
    };
    const invalidClient = function (r) {
      return r.status === 401 && r.json && r.json.error &&
             r.json.error.code === 'invalid_client';
    };
    const create = function (id, fields) {
      const made = applications.createApplication({ identifier: id,
        kind: 'gnap-client', protocols: ['gnap'],
        fields: Object.assign({ gnapSkipInteraction: 'TRUE' },
                              fields || {}) });
      if (!made.ok) {
        note(false, 'setup: created ' + id, JSON.stringify(made.errors));
      }
      return made;
    };
    const identityOf = function (id) {
      const entry = applications.get(id);
      const value = entry && entry.fields && entry.fields.gnapKeyIdentity;
      return Array.isArray(value) ? value[0] : (value || '');
    };
    const PASSWORD = 'correct horse battery';
    const issueTo = async function (id, label) {
      const r = await api('/applications/issue-tls-client-certificate',
        { application: id, password: PASSWORD, keyAlg: 'ec-p256',
          label: label || 'gnap' });
      if (r.status !== 200 || !r.json.files) {
        note(false, 'setup: issued a TLS client certificate to ' + id,
             JSON.stringify(r.json).slice(0, 300));
        return null;
      }
      const key = crypto.createPrivateKey({ key: r.json.files.key.text,
                                            format: 'pem',
                                            passphrase: PASSWORD })
        .export({ type: 'pkcs8', format: 'pem' });
      return { tls: { cert: r.json.files.chain.text, key: key },
               leaf: r.json.certificate.certificatePem,
               serialHex: r.json.certificate.serialHex };
    };
    const selfTls = { cert: read(M.selfCert), key: read(M.selfKey) };
    const self2Tls = { cert: read(M.self2Cert), key: read(M.self2Key) };
    const extTls = { cert: read(M.extCert) + read(M.caCert),
                     key: read(M.extKey) };

    // --- a. pinned ---------------------------------------------------------
    setting('gnap.mtlsTrust', 'pinned');
    create('g-pin', { gnapKey: JSON.stringify(certKey(read(M.selfCert))) });
    let r = await grant({ key: certKey(read(M.selfCert)) }, selfTls);
    note(issued(r), '2a1. pinned: a registered self-signed certificate ' +
         'proves its key by value (RFC 9635 section 7.3.2)',
         JSON.stringify(r.json).slice(0, 300));
    r = await raises('STS-GNAP-0277', function () {
      return grant({ key: certKey(read(M.selfCert)) }, null);
    });
    note(invalidClient(r) && r.coded, '2a2. an mtls key on a connection with ' +
         'no client certificate: invalid_client, STS-GNAP-0277',
         JSON.stringify(r.json));
    r = await raises('STS-GNAP-0278', function () {
      return grant({ key: certKey(read(M.selfCert)) }, self2Tls);
    });
    note(invalidClient(r) && r.coded, '2a3. a certificate key on a ' +
         'connection made with another certificate: STS-GNAP-0278',
         JSON.stringify(r.json));
    const selfJwk = crypto.createPublicKey(read(M.selfKey))
      .export({ format: 'jwk' });
    selfJwk.kid = 'gnap-self-jwk';
    selfJwk.alg = 'ES256';
    const jwkKey = { proof: 'mtls', jwk: selfJwk };
    create('g-pin-jwk', { gnapKey: JSON.stringify(jwkKey) });
    r = await grant({ key: jwkKey }, selfTls);
    note(issued(r), '2a4. a JWK proved by mutual TLS on a certificate ' +
         'carrying that public key', JSON.stringify(r.json).slice(0, 300));
    r = await raises('STS-GNAP-0278', function () {
      return grant({ key: jwkKey }, self2Tls);
    });
    note(invalidClient(r) && r.coded, '2a5. the same JWK on a certificate ' +
         'carrying another key: STS-GNAP-0278', JSON.stringify(r.json));
    create('g-pin-rev');
    const pinRev = await issueTo('g-pin-rev');
    if (pinRev) {
      applications.updateApplication('g-pin-rev', { mode: 'set',
        attribute: 'gnapKey', value: JSON.stringify(certKey(pinRev.leaf)) });
      r = await grant({ key: certKey(pinRev.leaf) }, pinRev.tls);
      note(issued(r), '2a6. pinned: a certificate this realm issued, pinned ' +
           'on the entry, proves its key', JSON.stringify(r.json).slice(0,
                                                                        300));
      const revoked = await api('/applications/revoke-tls-client-certificate',
        { application: 'g-pin-rev', serialHex: pinRev.serialHex,
          reason: 'keyCompromise' });
      note(revoked.status === 200, 'setup: revoked the pinned certificate',
           JSON.stringify(revoked.json).slice(0, 200));
      r = await raises('STS-PKI-0118', function () {
        return grant({ key: certKey(pinRev.leaf) }, pinRev.tls);
      });
      note(invalidClient(r) && r.coded, '2a7. pinned: the revoked ' +
           'certificate is refused on revocation, STS-PKI-0118 — revocation ' +
           'is consulted in both models', JSON.stringify(r.json));
    }

    // --- b. pki --------------------------------------------------------------
    setting('gnap.mtlsTrust', 'pki');
    r = await raises('STS-GNAP-0287', function () {
      return grant({ key: certKey(read(M.selfCert)) }, selfTls);
    });
    note(invalidClient(r) && r.coded, '2b1. pki: the registered self-signed ' +
         'certificate is refused, STS-GNAP-0287 (RFC 9635 section 11.4)',
         JSON.stringify(r.json));
    create('g-issued');
    const c1 = await issueTo('g-issued', 'one');
    if (c1) {
      r = await grant({ key: certKey(c1.leaf) }, c1.tls);
      note(issued(r) && identityOf('g-issued') === x5t(c1.leaf),
           '2b2. pki: a certificate this realm issued to the entry binds by ' +
           'value with nothing pinned, and its thumbprint is recorded',
           JSON.stringify(r.json).slice(0, 200) + ' ' +
           identityOf('g-issued'));
    }
    const c2 = await issueTo('g-issued', 'two');
    if (c2) {
      r = await grant({ key: certKey(c2.leaf) }, c2.tls);
      note(issued(r) && identityOf('g-issued') === x5t(c2.leaf),
           '2b3. rotation at the authority: a second certificate binds with ' +
           'no new registration, and is recorded',
           JSON.stringify(r.json).slice(0, 200) + ' ' +
           identityOf('g-issued'));
    }
    create('g-inst', { gnapInstanceId: 'inst-g-inst' });
    const i1 = await issueTo('g-inst', 'pinned');
    const i2 = await issueTo('g-inst', 'rotated');
    if (i1 && i2) {
      applications.updateApplication('g-inst', { mode: 'set',
        attribute: 'gnapKey', value: JSON.stringify(certKey(i1.leaf)) });
      r = await grant('inst-g-inst', i2.tls);
      note(issued(r), '2b4. an instance identifier whose pinned certificate ' +
           'was superseded at the authority binds the newer one',
           JSON.stringify(r.json).slice(0, 200));
    }
    if (c2) {
      r = await raises('STS-GNAP-0291', function () {
        return grant('inst-g-inst', c2.tls);
      });
      note(invalidClient(r) && r.coded, '2b5. another entry\'s certificate ' +
           'under this instance identifier: STS-GNAP-0291',
           JSON.stringify(r.json));
    }
    const c3 = await issueTo('g-issued', 'forgotten');
    if (c3) {
      const forgotten = pki.certificatesFor('', 'tls-client')
        .filter(function (c) {
          const holder = tlsClient.slotHolder(c.slot);
          return holder && holder.id === 'g-issued' &&
                 c.serialHex === c3.serialHex;
        })[0];
      pki.forgetCertificate('', 'tls-client', forgotten.slot);
      r = await raises('STS-GNAP-0292', function () {
        return grant({ key: certKey(c3.leaf) }, c3.tls);
      });
      note(invalidClient(r) && r.coded, '2b6. a certificate the entry\'s ' +
           'record no longer lists: STS-GNAP-0292', JSON.stringify(r.json));
    }
    if (c1) {
      await api('/applications/revoke-tls-client-certificate',
        { application: 'g-issued', serialHex: c1.serialHex,
          reason: 'keyCompromise' });
      r = await raises('STS-PKI-0118', function () {
        return grant({ key: certKey(c1.leaf) }, c1.tls);
      });
      note(invalidClient(r) && r.coded, '2b7. pki: a revoked certificate is ' +
           'refused on revocation, STS-PKI-0118', JSON.stringify(r.json));
    }
    create('g-ext', { oauthTlsClientAuthSanDns: 'ext.example.com' });
    r = await grant({ key: certKey(read(M.extCert)) }, extTls);
    note(issued(r) && identityOf('g-ext') === x5t(read(M.extCert)),
         '2b8. a foreign authority\'s certificate binds by the entry\'s RFC ' +
         '8705 subject, found by it with nothing pinned',
         JSON.stringify(r.json).slice(0, 200) + ' ' + identityOf('g-ext'));
    create('g-ext-wrong', { gnapInstanceId: 'inst-ext-wrong',
      gnapKey: JSON.stringify(certKey(read(M.extCert))),
      oauthTlsClientAuthSanDns: 'other.example.com' });
    r = await raises('STS-GNAP-0290', function () {
      return grant('inst-ext-wrong', extTls);
    });
    note(invalidClient(r) && r.coded && /other\.example\.com/.test(
      String(r.json.error.description || '')), '2b9. a subject the ' +
         'certificate does not carry: STS-GNAP-0290', JSON.stringify(r.json));
    create('g-ext-none', { gnapInstanceId: 'inst-ext-none',
      gnapKey: JSON.stringify(certKey(read(M.extCert))) });
    r = await raises('STS-GNAP-0288', function () {
      return grant('inst-ext-none', extTls);
    });
    note(invalidClient(r) && r.coded, '2b10. nothing to bind a foreign ' +
         'certificate by: STS-GNAP-0288', JSON.stringify(r.json));
    create('g-ext-two', { gnapInstanceId: 'inst-ext-two',
      gnapKey: JSON.stringify(certKey(read(M.extCert))),
      oauthTlsClientAuthSanDns: 'ext.example.com' });
    let wroteTwo = false;
    try {
      const store = applications.directoryInstalled();
      const held = store.readApplication('g-ext-two');
      const attrs = Object.assign({}, held.attributes);
      attrs.oauthTlsClientAuthSanEmail = ['Ops@example.com'];
      wroteTwo = !!store.writeApplication('g-ext-two', attrs);
    } catch (e) {
      wroteTwo = false;
    }
    note(wroteTwo, 'setup: a second subject parameter written past the ' +
         'registry, as an ldapmodify would');
    r = await raises('STS-GNAP-0289', function () {
      return grant('inst-ext-two', extTls);
    });
    note(invalidClient(r) && r.coded, '2b11. two subject parameters: ' +
         'STS-GNAP-0289', JSON.stringify(r.json));

    // --- c. the per-client override ------------------------------------------
    setting('gnap.mtlsTrust', 'pinned');
    create('g-strict', { gnapInstanceId: 'inst-strict',
      gnapKey: JSON.stringify(certKey(read(M.self2Cert))) });
    const strict = applications.updateApplication('g-strict', {
      mode: 'set', attribute: 'gnapMtlsTrust', value: 'pki' });
    note(strict.ok, 'setup: gnapMtlsTrust=pki is written in a pinned realm',
         JSON.stringify(strict.errors || ''));
    r = await raises('STS-GNAP-0287', function () {
      return grant('inst-strict', self2Tls);
    });
    note(invalidClient(r) && r.coded, '2c1. an entry holding itself to pki ' +
         'in a pinned realm refuses its self-signed key, STS-GNAP-0287',
         JSON.stringify(r.json));
    const weak = applications.updateApplication('g-pin', {
      mode: 'set', attribute: 'gnapMtlsTrust', value: 'pinned' });
    note(weak.ok, 'setup: gnapMtlsTrust=pinned is written in a pinned realm');
    setting('gnap.mtlsTrust', 'pki');
    const refusedWrite = applications.updateApplication('g-pin', {
      mode: 'set', attribute: 'gnapMtlsTrust', value: 'pinned' });
    note(!refusedWrite.ok && JSON.stringify(refusedWrite.errors)
      .indexOf('never weaker') >= 0, '2c2. writing pinned in a pki realm is ' +
         'refused (STS-REG-0196)', JSON.stringify(refusedWrite.errors));
    r = await raises('STS-GNAP-0287', function () {
      return grant({ key: certKey(read(M.selfCert)) }, selfTls);
    });
    note(invalidClient(r) && r.coded, '2c3. and a pinned value stored ' +
         'before the realm became pki is ignored, STS-GNAP-0287',
         JSON.stringify(r.json));

    // --- d. the product default ---------------------------------------------
    setting('gnap.mtlsTrust', null);
    const before = await codeCount('STS-GNAP-0287');
    setting('global.mode', 'product');
    const inProduct = await grant({ key: certKey(read(M.selfCert)) }, selfTls);
    setting('global.mode', 'development');
    const after = await codeCount('STS-GNAP-0287');
    note(invalidClient(inProduct) && after > before, '2d1. with ' +
         'gnap.mtlsTrust at auto, product refuses the pinned self-signed ' +
         'key: STS-GNAP-0287', JSON.stringify(inProduct.json));
    applications.updateApplication('g-pin', { mode: 'set',
      attribute: 'gnapMtlsTrust', value: '' });
    r = await grant({ key: certKey(read(M.selfCert)) }, selfTls);
    note(issued(r), '2d2. and development accepts it',
         JSON.stringify(r.json).slice(0, 200));
    setting('global.mode', null);

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

// ---------------------------------------------------------------------------
// THE CERTIFICATES NOBODY HERE ISSUED, made with OpenSSL.
// ---------------------------------------------------------------------------
function openssl(dir, args) {
  log.debug("Entering openssl().");
  childProcess.execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  log.debug("Leaving openssl().");
}

function makeMaterial() {
  log.debug("Entering makeMaterial().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gnap-mtls-'));
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  openssl(dir, ['req', '-x509'].concat(ec, ['-keyout', 'ca.key', '-out',
    'ca.pem', '-days', '2', '-subj', '/CN=GNAP mTLS Test Foreign CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign']));
  fs.writeFileSync(path.join(dir, 'ext.cnf'),
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' +
    'extendedKeyUsage=clientAuth\nsubjectAltName=@alt\n[alt]\n' +
    'DNS.1=ext.example.com\n');
  openssl(dir, ['req'].concat(ec, ['-keyout', 'ext.key', '-out', 'ext.csr',
    '-subj', '/O=Example GNAP/CN=gnap-ext-client']));
  openssl(dir, ['x509', '-req', '-in', 'ext.csr', '-CA', 'ca.pem', '-CAkey',
    'ca.key', '-CAcreateserial', '-out', 'ext.pem', '-days', '1',
    '-extfile', 'ext.cnf']);
  ['self', 'self2'].forEach(function (name) {
    openssl(dir, ['req', '-x509'].concat(ec, ['-keyout', name + '.key',
      '-out', name + '.pem', '-days', '1', '-subj',
      '/CN=gnap-' + name + '-client',
      '-addext', 'extendedKeyUsage=clientAuth']));
  });
  log.debug("Leaving makeMaterial().");
  return {
    dir: dir,
    caCert: path.join(dir, 'ca.pem'),
    extCert: path.join(dir, 'ext.pem'), extKey: path.join(dir, 'ext.key'),
    selfCert: path.join(dir, 'self.pem'), selfKey: path.join(dir, 'self.key'),
    self2Cert: path.join(dir, 'self2.pem'),
    self2Key: path.join(dir, 'self2.key')
  };
}

function inAChild(t, material) {
  log.debug("Entering inAChild().");
  t.log.info('=== 2. the grant endpoint, over HTTPS with client ' +
             'certificates ===');
  const out = path.join(os.tmpdir(), 'gnap-mtls-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|LDAPS_|KRB5_|GNAP_|CONFIG_FILE$)/
      .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', M_ROOT: ROOT, M_OUT: out,
                                  M_MATERIAL: JSON.stringify(material),
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
  let material = null;
  try {
    material = makeMaterial();
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('openssl made the foreign CA and the self-signed certificates',
          (e && e.message) || e);
    log.debug("Leaving run(). No openssl.");
    return;
  }
  registry(t);
  inAChild(t, material);
  try {
    fs.rmSync(material.dir, { recursive: true, force: true });
  } catch (e) {
    // A temporary directory left behind is not a test result.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'GNAP mutual TLS trust',
  describe: 'RFC 9635 sections 7.3.2 and 11.4: the pinned and PKI trust ' +
            'models for a key proved by mutual TLS, revocation in both, the ' +
            'binding to an application entry by issuance or by its RFC 8705 ' +
            'subject, rotation at the authority, the per-client override ' +
            'and the product default',
  run: run
};
