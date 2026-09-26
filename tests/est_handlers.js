'use strict';
//
// File: est_handlers.js
//
// ===========================================================================
// THE EST ROUTE FUNCTIONS, THE VIEW MODEL AND THE REALM BOUNDARY, WITH NO PORT
// (2026-09-13).
//
// `tests/vendored/sts_est_enrollment.js` drives EST over HTTPS against a
// running service. What is here is what that job cannot choose or cannot see:
//
//   * THE ERROR CODE of each refusal — never on the wire, so only a caller
//     holding the response OBJECT can read it (`errorCodes.codeOf(res)`);
//   * A PLAIN-HTTP REQUEST IN A PRODUCT-MODE REALM, which a service started
//     HTTPS by every launcher cannot be sent;
//   * A CSR CARRYING DecryptKeyIdentifier, which the vendored CSR builder a
//     client uses cannot add;
//   * the two EST name-set spellings compared directly, the Basic header
//     parser's malformed shapes, and the view model's refusals;
//   * and the REALM BOUNDARY as a property of the stores: a certificate and a
//     monitor count made in one realm, absent in another.
//
// IT RUNS IN A CHILD PROCESS, spawning this file, because it loads the protocol
// stack (the directory, the console, the family) and creates realms — shared
// state `run.js`'s one process would hand to every file after this one
// (`tests/protocol_endpoints.js`'s arrangement).
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'est_handlers',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// THE CHILD.
// ---------------------------------------------------------------------------
async function childMain() {
  log.debug("Entering childMain().");
  const nodeCrypto = require('crypto');
  const asn1js = require('asn1js');
  const pkijs = require('pkijs');
  const realms = require(path.join(ROOT, 'common', 'realms'));
  const config = require(path.join(ROOT, 'common', 'config'));
  const errorCodes = require(path.join(ROOT, 'common', 'error_codes'));
  const pki = require(path.join(ROOT, 'common', 'pki'));
  const ldap = require(path.join(ROOT, 'ldap', 'ldap_server'));
  const credentials = require(path.join(ROOT, 'common', 'credentials'));
  const core = require(path.join(ROOT, 'common', 'cert_enrollment'));
  const monitor = require(path.join(ROOT, 'common', 'enrollment_monitor'));
  const x509 = require(path.join(ROOT, 'common', 'vendored', 'x509'));
  const keys = require(path.join(ROOT, 'common', 'vendored', 'key_material'));
  const est = require(path.join(ROOT, 'est', 'est'));
  const estConsole = require(path.join(ROOT, 'est', 'est_console'));
  pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node',
    crypto: nodeCrypto.webcrypto }));

  const findings = [];
  function note(ok, what, detail) {
    log.debug("Entering note().");
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    log.debug("Leaving note().");
  }

  if (!pki.hasRoot()) {
    await pki.start({});
  }
  const stamp = Date.now().toString(36);
  const A = 'esth-a-' + stamp;
  const B = 'esth-b-' + stamp;
  const P = 'esth-p-' + stamp;
  // Not `alice`: development mode seeds her into every realm, which would
  // make the realm-boundary assertions about a person who is in both.
  const WHO = 'esthperson' + stamp;
  realms.create({ id: A, name: A });
  realms.create({ id: B, name: B });
  realms.create({ id: P, name: P, overrides: { 'global.mode': 'product' } });

  function inRealm(id, fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(id), fn);
  }

  function fakeRes() {
    log.debug("Entering fakeRes().");
    const res = { headers: {}, body: null, statusCode: 200, locals: {},
                  headersSent: false };
    res.set = function (k, v) {
      res.headers[String(k).toLowerCase()] = v;
      return res;
    };
    res.status = function (code) {
      res.statusCode = code;
      return res;
    };
    res.type = function (t) {
      res.headers['content-type'] = res.headers['content-type'] || t;
      return res;
    };
    res.send = function (body) {
      res.body = body;
      res.headersSent = true;
      return res;
    };
    log.debug("Leaving fakeRes().");
    return res;
  }

  function fakeReq(spec) {
    log.debug("Entering fakeReq().");
    const encrypted = spec.encrypted !== false;
    const headers = {};
    Object.keys(spec.headers || {}).forEach(function (k) {
      headers[k.toLowerCase()] = spec.headers[k];
    });
    if (spec.basic) {
      headers.authorization = 'Basic ' + Buffer.from(spec.basic[0] + ':' +
                                                     spec.basic[1])
        .toString('base64');
    }
    log.debug("Leaving fakeReq().");
    return {
      method: spec.method || 'GET', path: spec.path || '/',
      url: spec.path || '/', originalUrl: spec.path || '/',
      params: spec.label ? { label: spec.label } : {},
      query: spec.query || {}, headers: headers,
      body: spec.body === undefined ? undefined : spec.body,
      protocol: encrypted ? 'https' : 'http', ip: '127.0.0.9',
      socket: { encrypted: encrypted, remoteAddress: '127.0.0.9',
                getPeerCertificate: function () {
                  return spec.peer ? { raw: spec.peer,
                    serialNumber: spec.peerSerial || '' } : {};
                } },
      get: function (h) {
        return headers[String(h).toLowerCase()];
      }
    };
  }

  async function call(realmId, opName, spec) {
    log.debug("Entering call().");
    const op = est.OPERATIONS.filter(function (one) {
      return one.name === opName;
    })[0];
    const res = fakeRes();
    await inRealm(realmId, function () {
      return est.handlers.operation(op)(fakeReq(Object.assign({
        method: op.method, path: '/.well-known/est/' + opName }, spec || {})),
                                        res);
    });
    log.debug("Leaving call().");
    return { status: res.statusCode, headers: res.headers, body: res.body,
             code: errorCodes.codeOf(res) || '' };
  }

  function b64Body(der) {
    log.debug("Entering b64Body().");
    log.debug("Leaving b64Body().");
    return Buffer.from(Buffer.from(der).toString('base64')
      .replace(/(.{64})/g, '$1\r\n'), 'latin1');
  }

  async function csr(alg, subject, names, pair) {
    log.debug("Entering csr().");
    const kp = pair || await keys.generateKeyPair(alg);
    const built = await x509.certificationRequest({ subject: subject,
      publicKeyPem: kp.publicPem, privateKeyPem: kp.privatePem,
      subjectAltName: names || [] });
    log.debug("Leaving csr().");
    return { der: Buffer.from(built.der), pair: kp };
  }

  function certsOf(body) {
    log.debug("Entering certsOf().");
    const der = Buffer.from(Buffer.from(body).toString('latin1')
      .replace(/\s+/g, ''), 'base64');
    const info = new pkijs.ContentInfo({ schema: asn1js.fromBER(
      der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength))
      .result });
    const signed = new pkijs.SignedData({ schema: info.content });
    log.debug("Leaving certsOf().");
    return (signed.certificates || []).map(function (cert) {
      return new nodeCrypto.X509Certificate(Buffer.from(
        cert.toSchema(true).toBER(false)));
    });
  }

  const PKCS10 = { 'Content-Type': 'application/pkcs10' };

  // --- A: the directory ------------------------------------------------------
  await inRealm(A, function () {
    ldap.createUser(WHO, { invent: false,
                               attributes: { mail: 'alice@esth.test' } });
  });

  // --- 1. cacerts -----------------------------------------------------------
  const ca = await call(A, 'cacerts');
  note(ca.status === 200 && /certs-only/.test(ca.headers['content-type']) &&
       ca.headers['content-transfer-encoding'] === 'base64',
       '/cacerts answers 200 certs-only, base64', ca.status + ' ' +
       JSON.stringify(ca.headers));
  let chain = [];
  try {
    chain = certsOf(ca.body);
  } catch (e) {
    note(false, 'the /cacerts body parses', e.message);
  }
  note(chain.length === 3 && chain[0].verify(chain[1].publicKey) &&
       chain[1].verify(chain[2].publicKey),
       'it carries the EST Issuing CA, the Intermediate and the Root, as a ' +
       'path', chain.length);

  // --- 2. simpleenroll ------------------------------------------------------
  const aliceCsr = await csr('ec-p256', 'CN=' + WHO,
                             [{ kind: 'uri', value: 'urn:sts:person:' + WHO }]);
  const issued = await call(A, 'simpleenroll', { headers: PKCS10,
    basic: [WHO, 'x'], body: b64Body(aliceCsr.der) });
  let aliceCert = null;
  try {
    aliceCert = certsOf(issued.body)[0];
  } catch (e) {
    note(false, 'the issued certificate parses', e.message);
  }
  note(issued.status === 200 && aliceCert &&
       aliceCert.subjectAltName.indexOf('urn:sts:person:' + WHO) >= 0,
       'a person enrolls for themselves (development mode)',
       issued.status + ' ' + String(issued.body).slice(0, 200));
  note(aliceCert && aliceCert.verify(chain[0].publicKey),
       'and the certificate is signed by the EST Issuing CA');

  // --- 3. refusals and their codes -------------------------------------------
  const noCred = await call(A, 'simpleenroll', { headers: PKCS10,
    body: b64Body(aliceCsr.der) });
  note(noCred.status === 401 && noCred.code === 'STS-EST-0009' &&
       noCred.headers['www-authenticate'] === 'Basic realm="EST"',
       'no credential: 401, STS-EST-0009, the Basic challenge',
       noCred.status + ' ' + noCred.code);
  note(!/STS-/.test(String(noCred.body)),
       'and the code is not in the body');
  const wrongType = await call(A, 'simpleenroll', { headers: {
    'Content-Type': 'text/plain' }, basic: [WHO, 'x'],
    body: b64Body(aliceCsr.der) });
  note(wrongType.status === 415 && wrongType.code === 'STS-EST-0006',
       'a body that is not application/pkcs10: 415, STS-EST-0006',
       wrongType.status + ' ' + wrongType.code);
  const badB64 = await call(A, 'simpleenroll', { headers: PKCS10,
    basic: [WHO, 'x'], body: Buffer.from('MII@@@', 'latin1') });
  note(badB64.status === 400 && badB64.code === 'STS-EST-0008',
       'illegal base64: 400, STS-EST-0008', badB64.status + ' ' + badB64.code);
  const tooBig = await call(A, 'simpleenroll', { headers: Object.assign({
    'Content-Length': '999999' }, PKCS10), basic: [WHO, 'x'],
    body: Buffer.alloc(10) });
  note(tooBig.status === 413 && tooBig.code === 'STS-EST-0007',
       'a declared length over est.maxRequestBytes: 413 before the body is ' +
       'read', tooBig.status + ' ' + tooBig.code);
  const unknownLabel = await call(A, 'cacerts', { label: 'nope' });
  note(unknownLabel.status === 404 && unknownLabel.code === 'STS-EST-0002',
       'an unknown label: 404, STS-EST-0002', unknownLabel.code);
  const refusedLabel = await call(A, 'simpleenroll', { label: 'kdc',
    headers: PKCS10, basic: [WHO, 'x'], body: b64Body(aliceCsr.der) });
  note(refusedLabel.status === 403 && refusedLabel.code === 'STS-ENROLL-0002',
       'a refused profile as a label: 403, the core\'s code',
       refusedLabel.code);
  const fullcmc = await call(A, 'fullcmc', {});
  note(fullcmc.status === 501 && fullcmc.code === 'STS-EST-0004',
       '/fullcmc: 501, STS-EST-0004', fullcmc.code);
  const query = await call(A, 'cacerts', { query: { x: '1' } });
  note(query.status === 400 && query.code === 'STS-EST-0019',
       'a query string: 400, STS-EST-0019', query.status + ' ' + query.code);
  const bearer = await call(A, 'simpleenroll', { headers: Object.assign({
    Authorization: 'Bearer abc' }, PKCS10), body: b64Body(aliceCsr.der) });
  note(bearer.status === 401 && bearer.code === 'STS-EST-0013',
       'a Bearer header: 401, STS-EST-0013', bearer.code);
  const wrongMethodRes = fakeRes();
  est.handlers.wrongMethod({ name: 'simpleenroll', method: 'POST' })(
    fakeReq({ method: 'GET' }), wrongMethodRes);
  note(wrongMethodRes.statusCode === 405 &&
       wrongMethodRes.headers.allow === 'POST' &&
       errorCodes.codeOf(wrongMethodRes) === 'STS-EST-0003',
       'the wrong method: 405 with Allow, STS-EST-0003');

  // --- 4. transport ---------------------------------------------------------
  const plainDev = await call(A, 'cacerts', { encrypted: false });
  note(plainDev.status === 200,
       'development mode answers a request that did not arrive over TLS',
       plainDev.status);
  const plainProduct = await call(P, 'cacerts', { encrypted: false });
  note(plainProduct.status === 403 &&
       plainProduct.code === 'STS-ENROLL-0060',
       'PRODUCT MODE REFUSES a request that did not arrive over TLS',
       plainProduct.status + ' ' + plainProduct.code);

  // --- 5. product mode passwords --------------------------------------------
  const strong = 'Est-Handlers-9x!Longer';
  await inRealm(P, function () {
    ldap.createUser(WHO + 'b', { invent: false,
                             attributes: { mail: 'bob@esth.test' } });
    return credentials.setPassword(WHO + 'b', strong);
  });
  const bobCsr = await csr('ec-p256', 'CN=' + WHO + 'b', []);
  const bobWrong = await call(P, 'simpleenroll', { headers: PKCS10,
    basic: [WHO + 'b', 'not-the-password'], body: b64Body(bobCsr.der) });
  note(bobWrong.status === 401 && /^STS-ENROLL-001[45]$/.test(bobWrong.code),
       'product mode: a wrong password is refused 401', bobWrong.status + ' ' +
       bobWrong.code);
  const bobRight = await call(P, 'simpleenroll', { headers: PKCS10,
    basic: [WHO + 'b', strong], body: b64Body(bobCsr.der) });
  note(bobRight.status === 200, 'product mode: the right password is issued',
       bobRight.status + ' ' + String(bobRight.body).slice(0, 300));

  // --- 5b. a realm in the EST label position (#251) -------------------------
  const viaLabel = realms.matchPath('/.well-known/est/' + A + '/cacerts');
  note(viaLabel && viaLabel.realm.id === A &&
       viaLabel.rest === '/.well-known/est/cacerts',
       'the label position names a realm: /.well-known/est/<realm>/cacerts ' +
       'enters it, rewritten to /.well-known/est/cacerts',
       JSON.stringify(viaLabel && { id: viaLabel.realm.id,
                                    rest: viaLabel.rest }));
  const pairForm = realms.matchPath('/.well-known/est/' + A +
                                    '/tls-server/simpleenroll');
  note(pairForm && pairForm.realm.id === A &&
       pairForm.rest === '/.well-known/est/tls-server/simpleenroll',
       'and /.well-known/est/<realm>/<profile>/<op> keeps the profile label',
       JSON.stringify(pairForm && pairForm.rest));
  note(realms.matchPath('/.well-known/est/tls-server/simpleenroll') === null,
       'a profile label is not a realm');
  note(realms.matchPath('/.well-known/est/nosuch-' + stamp + '/cacerts') ===
       null, 'an unknown name in the label position is not a realm');
  note(realms.matchPath('/.well-known/est/' + A) === null,
       'a lone segment after /.well-known/est/ is an operation, not a realm');
  const prefixed = realms.matchPath('/' + realms.pathSegment() + '/' + A +
                                    '/.well-known/est/' + B + '/cacerts');
  note(prefixed && prefixed.realm.id === A &&
       prefixed.rest === '/.well-known/est/' + B + '/cacerts',
       'with the prefix the prefix decides, and a realm in the label is ' +
       'left for est.ts to refuse — never a mix',
       JSON.stringify(prefixed && prefixed.rest));
  const twice = await call(A, 'cacerts', { label: B });
  note(twice.status === 404 && twice.code === 'STS-EST-0022',
       'a label naming a realm after the realm was named is 404 ' +
       'STS-EST-0022', twice.status + ' ' + twice.code);
  const selfTwice = await call(A, 'cacerts', { label: A });
  note(selfTwice.status === 404 && selfTwice.code === 'STS-EST-0022',
       'even when it names the same realm again',
       selfTwice.status + ' ' + selfTwice.code);
  const nosuchLabel = await call(A, 'cacerts', { label: 'nosuch' });
  note(nosuchLabel.status === 404 && nosuchLabel.code === 'STS-EST-0002',
       'an unknown label is still STS-EST-0002', nosuchLabel.code);
  const labelIds = ['tls-server', 'email', 'kdc', 'root-ca'];
  labelIds.forEach(function (id) {
    const errors = realms.validateId(id);
    note(errors.length > 0 && errors.some(function (one) {
      return /EST label/.test(one);
    }), 'a realm may not be called "' + id + '", an EST label',
         JSON.stringify(errors));
  });
  note(errorCodes.codeOf(realms.validateId('smartcard-logon')) ===
       'STS-CORE-0107', 'and the refusal is STS-CORE-0107',
       errorCodes.codeOf(realms.validateId('smartcard-logon')));
  note(realms.validateId('est-ok-' + stamp).length === 0,
       'a name that is not a label is still accepted');
  note(realms.estLabelPath(realms.get(A)) === '/.well-known/est/' + A &&
       realms.estLabelPath(realms.get('default')) === null,
       'estLabelPath() names a realm\'s label form, and none for the default');
  note(realms.unknownRealmPath('/.well-known/est/later-' + stamp +
                               '/cacerts') === true &&
       realms.unknownRealmPath('/.well-known/est/tls-server/cacerts') ===
         false &&
       realms.unknownRealmPath('/.well-known/est/' + A + '/cacerts') ===
         false,
       'unknownRealmPath() catches up on the label position too, and not ' +
       'for a label or a realm already held');
  await inRealm(A, function () {
    const view = estConsole.estView(fakeReq({ path: '/admin/est' }));
    note(view.labelForm && /\/\.well-known\/est\/[^/]+$/
      .test(view.labelForm.base) &&
         view.labelForm.base.indexOf('/realm/') < 0 &&
         view.endpoints[0].labelFormUrl ===
           view.labelForm.base + '/cacerts',
         '/admin/est in a realm shows the label form at the origin root',
         JSON.stringify(view.labelForm));
  });
  await inRealm('default', function () {
    const view = estConsole.estView(fakeReq({ path: '/admin/est' }));
    note(view.labelForm === null && view.endpoints[0].labelFormUrl === null,
         'and the default realm shows none');
  });

  // --- 6. the realm boundary ------------------------------------------------
  const inB = await call(B, 'simpleenroll', { headers: PKCS10,
    basic: [WHO, 'x'], body: b64Body(aliceCsr.der) });
  note(inB.status === 401,
       'a realm A person\'s credential is refused at realm B', inB.status);
  const held = { A: 0, B: 0, monitorA: 0, monitorB: 0 };
  await inRealm(A, function () {
    held.A = core.certificatesInRealm('est').length;
    held.monitorA = monitor.snapshot('est').issued;
  });
  await inRealm(B, function () {
    held.B = core.certificatesInRealm('est').length;
    held.monitorB = monitor.snapshot('est').issued;
  });
  note(held.A >= 1 && held.B === 0,
       'the certificates enrolled in A are not listed in B', JSON.stringify(
         held));
  note(held.monitorA >= 1 && held.monitorB === 0,
       'the EST monitor counts A\'s issuance in A and not in B',
       JSON.stringify(held));

  // --- 7. the family switched off --------------------------------------------
  await inRealm(A, function () {
    config.setOverride('est.enabled', false);
  });
  const off = await call(A, 'cacerts', {});
  await inRealm(A, function () {
    config.clearOverride('est.enabled');
  });
  note(off.status === 503 && off.code === 'STS-EST-0001',
       'est.enabled off: 503, STS-EST-0001', off.status + ' ' + off.code);

  // --- 8. serverkeygen asking for an encrypted key ---------------------------
  const pair = await nodeCrypto.webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const request = new pkijs.CertificationRequest();
  request.version = 0;
  request.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: '2.5.4.3', value: new asn1js.Utf8String({ value: WHO }) }));
  await request.subjectPublicKeyInfo.importKey(pair.publicKey);
  request.attributes = [new pkijs.Attribute({
    type: '1.2.840.113549.1.9.16.2.37',
    values: [new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3])
      .buffer })] })];
  await request.sign(pair.privateKey, 'SHA-256');
  const decryptCsr = Buffer.from(request.toSchema(true).toBER(false));
  const encrypted = await call(A, 'serverkeygen', { headers: PKCS10,
    basic: [WHO, 'x'], body: b64Body(decryptCsr) });
  note(encrypted.status === 501 && encrypted.code === 'STS-EST-0018',
       'a /serverkeygen template asking for DecryptKeyIdentifier: 501, ' +
       'STS-EST-0018', encrypted.status + ' ' + encrypted.code + ' ' +
       String(encrypted.body).slice(0, 200));

  // --- 9. re-enrollment with the client certificate --------------------------
  const peerDer = aliceCert ? aliceCert.raw : Buffer.alloc(0);
  const renewCsr = await csr('ec-p256', aliceCert
    ? String(aliceCert.subject).split('\n').join(', ') : 'CN=' + WHO,
                             [{ kind: 'uri', value: 'urn:sts:person:' + WHO }]);
  const renewed = await call(A, 'simplereenroll', { headers: PKCS10,
    peer: peerDer, body: b64Body(renewCsr.der) });
  note(renewed.status === 200,
       'a re-enrollment authenticated by the client certificate is issued',
       renewed.status + ' ' + String(renewed.body).slice(0, 300));
  let oldStatus = '';
  await inRealm(A, function () {
    const record = core.enrolledOf({ kind: 'person', id: WHO })
      .filter(function (one) {
        return aliceCert && one.serialHex === core.normalSerial(
          aliceCert.serialNumber);
      })[0];
    oldStatus = record ? record.status : 'missing';
  });
  note(oldStatus === 'revoked',
       'and the renewed certificate is superseded on the entry', oldStatus);
  const otherSubject = await csr('ec-p256', 'CN=mallory',
                                 [{ kind: 'uri',
                                    value: 'urn:sts:person:' + WHO }]);
  const renewedCert = renewed.status === 200 ? certsOf(renewed.body)[0] : null;
  const differs = await call(A, 'simplereenroll', { headers: PKCS10,
    peer: renewedCert ? renewedCert.raw : peerDer,
    body: b64Body(otherSubject.der) });
  note(differs.status === 400 && differs.code === 'STS-EST-0016',
       'a re-enrollment whose subject differs from the client certificate: ' +
       '400, STS-EST-0016', differs.status + ' ' + differs.code);

  // --- 10. the name sets a re-enrollment compares ----------------------------
  const requested = { uris: ['urn:sts:person:alice'], dns: ['Host.Example.'],
                      ips: [], emails: ['Alice@Esth.Test'], upns: [] };
  const record = { names: ['uri:urn:sts:person:alice', 'dns:host.example',
                           'email:alice@esth.test'] };
  note(JSON.stringify(est.requestedNameSet(requested)) ===
       JSON.stringify(est.recordNameSet(record)),
       'a request\'s names and a record\'s compare equal across case and a ' +
       'trailing dot', JSON.stringify(est.requestedNameSet(requested)));
  note(JSON.stringify(est.requestedNameSet({
         uris: ['urn:sts:person:bob'] })) !==
       JSON.stringify(est.recordNameSet({ names: ['uri:urn:sts:person:alice']
       })), 'and a different URN does not');

  // --- 11. the Basic header -------------------------------------------------
  function basicOf(value) {
    log.debug("Entering basicOf().");
    log.debug("Leaving basicOf().");
    return est.basicCredentialOf({ headers: value === undefined ? {}
                                   : { authorization: value } });
  }
  note(!basicOf().present, 'no header is no credential');
  note(basicOf('Basic ' + Buffer.from('a:b:c').toString('base64')).password ===
       'b:c', 'a password may contain a colon (RFC 7617)');
  note(basicOf('Basic !!!').malformed &&
       basicOf('Basic ' + Buffer.from('nocolon').toString('base64'))
         .malformed &&
       basicOf('Basic ' + Buffer.from(':empty').toString('base64')).malformed,
       'not base64, no colon, or an empty name is MALFORMED');
  note(basicOf('Basic QR==').malformed,
       'non-canonical base64 in the header is malformed');
  note(basicOf('Digest x').present && basicOf('Digest x').basic === false,
       'another scheme is present and not Basic');

  // --- 12. the view model ----------------------------------------------------
  const viewReq = fakeReq({ path: '/admin/est', query: {} });
  viewReq.get = function () {
    return 'esth.test';
  };
  let view = null;
  await inRealm(A, function () {
    view = estConsole.estView(viewReq);
  });
  note(view.profiles.length === 10 && view.refusedProfiles.length === 5,
       'the view lists the nine profiles, the device profile (#164) and ' +
       'the five refused',
       view.profiles.length + '/' + view.refusedProfiles.length);
  note(JSON.stringify(view.endpoints.map(function (e) {
    return e.operation + ' ' + e.method;
  })) === JSON.stringify(est.OPERATIONS.map(function (op) {
    return op.name + ' ' + op.method;
  })), 'the view\'s operation table and the router\'s agree');
  note(est.PATHS.length === 12, 'twelve paths are registered', est.PATHS);
  note(view.certificates.paging.total >= 1 &&
       !/PRIVATE KEY/.test(JSON.stringify(view)),
       'the enrolled certificates are listed and no private key is in the ' +
       'view', view.certificates.paging.total);
  const unknownAction = await inRealm(A, function () {
    return estConsole.estAction({ action: 'nope' }, { via: 'api' });
  });
  note(!unknownAction.ok && errorCodes.codeOf(unknownAction) === 'STS-EST-0032',
       'an unknown action: STS-EST-0032', JSON.stringify(unknownAction));
  const missing = await inRealm(A, function () {
    return estConsole.estAction({ action: 'issue-server-key' },
                                { via: 'api' });
  });
  note(!missing.ok && errorCodes.codeOf(missing) === 'STS-EST-0031',
       'an action missing its fields: STS-EST-0031');
  const kemSigning = await inRealm(A, function () {
    return estConsole.estAction({ action: 'issue-server-key', kind: 'person',
      identifier: WHO, profile: 'tls-client', keyAlg: 'ml-kem-768' },
                                { via: 'api' });
  });
  note(!kemSigning.ok && errorCodes.codeOf(kemSigning) === 'STS-EST-0017',
       'a KEM key for a signing profile: STS-EST-0017');
  const serverKey = await inRealm(A, function () {
    return estConsole.estAction({ action: 'issue-server-key', kind: 'person',
      identifier: WHO, profile: 'digital-signature', keyAlg: 'ec-p256' },
                                { via: 'api' });
  });
  note(serverKey.ok && /PRIVATE KEY/.test(serverKey.privateKeyPem || '') &&
       serverKey.record && serverKey.record.keySource === 'server',
       'issue-server-key returns the private key once, with a server-key ' +
       'record', JSON.stringify(serverKey).slice(0, 300));
  let viewAfter = null;
  await inRealm(A, function () {
    viewAfter = estConsole.estView(viewReq);
  });
  note(!/PRIVATE KEY/.test(JSON.stringify(viewAfter)),
       'and the view still carries no private key');
  const monitorView = await inRealm(A, function () {
    return estConsole.estMonitorView(viewReq);
  });
  note(monitorView.totals.issued >= 3 && monitorView.totals.refused >= 5 &&
       monitorView.errorCodes.some(function (row) {
         return row.name === 'STS-EST-0006';
       }), 'the monitor view counts issuances, refusals and their codes',
       JSON.stringify(monitorView.totals));

  fs.writeFileSync(process.env.EST_HANDLERS_OUT, JSON.stringify(findings));
  log.debug("Leaving childMain().");
}

// ---------------------------------------------------------------------------
// THE PARENT.
// ---------------------------------------------------------------------------
function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'est-handlers-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
    STS_LOG_LEVEL: 'fatal', EST_HANDLERS_CHILD: '1',
    EST_HANDLERS_OUT: outFile });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 300000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No file is the child dying before it wrote one; its stderr says why.
    t.bad('the child process reported nothing',
          (child.stderr || '').slice(-3000));
    findings = null;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  (findings || []).forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.EST_HANDLERS_CHILD) {
  childMain().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write('est_handlers child threw: ' + (e && e.stack) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'est_handlers',
  describe: 'the EST route functions, their error codes, the view model and ' +
            'the realm boundary, driven with a fake request in a child process',
  run: run
};
