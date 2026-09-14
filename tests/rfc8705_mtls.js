'use strict';
//
// File: rfc8705_mtls.js
//
// ===========================================================================
// RFC 8705 — MUTUAL-TLS CLIENT AUTHENTICATION AND CERTIFICATE-BOUND ACCESS
// TOKENS, BOTH HALVES, OVER REAL HANDSHAKES (2026-09-13).
//
// `oauth-oidc/client_auth.js`, `oauth-oidc/mtls.js`,
// `common/certificate_subject.js` and `common/tls_client_certificates.js`
// argue the design. What is held here, each feature with the request that must
// work and the requests that must not:
//
//   1. THE SUBJECT LIBRARY, in process: a DN compared as a name (types, OIDs,
//      escapes, a multi-valued RDN in either order), the four subjectAltName
//      kinds (a host name without regard to case, an IPv6 address by value,
//      an email's local part case-sensitive), and the registration grammar.
//   2. THE REGISTRY, in process: at most one subject parameter at every write
//      door, a value's grammar, the section 3.4 flag's.
//   3. THE ENDPOINTS, in a child process on an HTTPS listener that asks for a
//      client certificate, exactly as the main port does:
//        a. discovery advertises both methods and bound tokens;
//        b. the IMPLICIT mapping — a certificate issued to the application
//           from its Credentials door (`/admin-api/applications/issue-tls-
//           client-certificate`) authenticates it with nothing registered,
//           and the access token is bound to it;
//        c. its refusals — no certificate, another application's certificate,
//           a certificate its record no longer lists, a revoked one, the
//           door's own refusals (password, cap, unknown application, another
//           application's serial);
//        d. the EXPLICIT mapping — a foreign CA's certificate by subject DN
//           spelt differently, by each of the four subjectAltNames, and
//           refused for a subject that does not match, for nothing
//           registered, for an unverified chain, and for two parameters an
//           ldapmodify left behind;
//        e. self_signed_tls_client_auth by a jwks x5c and by thumbprint, and
//           refused for another certificate and for nothing registered;
//        f. the declaration held in every mode (development here), at the
//           token endpoint and at PAR;
//        g. section 3.4 — a client that declared bound tokens refused without
//           a certificate, and bound with one;
//        h. section 3.1 at a resource server (UserInfo): with the certificate,
//           with none, with another; section 3.2's cnf at introspection;
//        i. section 7.1 — a refresh by a certificate-authenticated client
//           with a NEW certificate succeeds and rebinds; a refresh by a
//           secret client with another certificate does not; and a
//           certificate client presenting ANOTHER client's refresh token
//           still meets the binding;
//        j. RFC 7591 registration of the five parameters and the flag, and
//           its refusals.
//
// Every refusal is asserted by its protocol error AND by its STS code, read
// back off `/admin-api/audit`, because a code is recorded and never sent.
//
// **THE CERTIFICATES OUTSIDE THIS SERVICE'S AUTHORITY ARE OPENSSL'S** — a
// foreign CA, a leaf it signs with every subjectAltName kind, and two
// self-signed certificates — so the explicit mapping is checked against a
// certificate this service did not build. The file needs `openssl`, which
// `tests/tls_client_certificates.js` already does.
//
// **A CHILD**, for `tests/acme_protocol.js`'s reason: it loads the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'rfc8705_mtls',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE SUBJECT LIBRARY.
// ---------------------------------------------------------------------------
function subjectLibrary(t, material) {
  log.debug("Entering subjectLibrary().");
  t.log.info('=== 1. certificate_subject.js ===');
  const cs = require('../common/certificate_subject');
  const ext = fs.readFileSync(material.extCert);
  const raw = new nodeCrypto.X509Certificate(ext).raw;
  t.equal(cs.subjectOf(new nodeCrypto.X509Certificate(ext)).text,
          'CN=ext-client,O=Example Corp\\, Inc.,C=US',
          '1a. the certificate subject is read leaf first, escaped');
  t.check(cs.matches('tls_client_auth_subject_dn',
                     'cn=EXT-client, o=example corp\\2c inc., 2.5.4.6=us',
                     raw).ok,
          '1b. a DN spelt with other case, spaces, an OID and a hex escape ' +
          'is the same name');
  t.check(!cs.matches('tls_client_auth_subject_dn',
                      'C=US,O=Example Corp\\, Inc.,CN=ext-client', raw).ok,
          '1c. the same RDNs in the other order are a different name');
  t.check(cs.normalDn('CN=a+UID=b,O=x') === cs.normalDn('uid=B + cn=A, o=X'),
          '1d. a multi-valued RDN matches in either order');
  t.check(cs.matches('tls_client_auth_san_dns', 'EXT.Example.com.', raw).ok &&
          !cs.matches('tls_client_auth_san_dns', 'other.example.com', raw).ok,
          '1e. a dNSName ignores case and a trailing dot, and nothing else');
  t.check(cs.matches('tls_client_auth_san_ip', '2001:db8:0:0::7', raw).ok &&
          cs.matches('tls_client_auth_san_ip', '192.0.2.10', raw).ok &&
          !cs.matches('tls_client_auth_san_ip', '192.0.2.11', raw).ok,
          '1f. an iPAddress is compared by value, v4 and v6');
  t.check(cs.matches('tls_client_auth_san_email', 'Ops@EXAMPLE.com', raw).ok &&
          !cs.matches('tls_client_auth_san_email', 'ops@example.com', raw).ok,
          '1g. an rfc822Name\'s domain ignores case and its local part does ' +
          'not');
  t.check(cs.matches('tls_client_auth_san_uri',
                     'https://client.example.com/id', raw).ok &&
          !cs.matches('tls_client_auth_san_uri',
                      'https://CLIENT.example.com/id', raw).ok,
          '1h. a URI is compared exactly');
  t.check(!!cs.valueProblem('tls_client_auth_subject_dn', 'CN=a,') &&
          !!cs.valueProblem('tls_client_auth_subject_dn', 'CN="a"') &&
          !!cs.valueProblem('tls_client_auth_san_dns', '*.example.com') &&
          !!cs.valueProblem('tls_client_auth_san_ip', '300.1.1.1') &&
          !!cs.valueProblem('tls_client_auth_san_email', 'nobody') &&
          !!cs.valueProblem('tls_client_auth_san_uri', 'not a uri') &&
          !cs.valueProblem('tls_client_auth_san_uri', 'urn:x:y'),
          '1i. the grammar refuses a bad DN, a wildcard, a bad address, a ' +
          'bad mailbox and a relative URI, and takes a URN');
  log.debug("Leaving subjectLibrary().");
}

// ---------------------------------------------------------------------------
// 2. THE REGISTRY'S CHECKS.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 2. applications.js ===');
  const applications = require('../common/applications');
  let p = applications.mtlsMetadataProblem({
    tls_client_auth_subject_dn: 'CN=a', tls_client_auth_san_dns: 'a.example' });
  t.check(p && p.errorCode === 'STS-REG-0131' &&
          p.error === 'invalid_client_metadata',
          '2a. a registration with two subject parameters is refused',
          JSON.stringify(p));
  p = applications.mtlsMetadataProblem({ tls_client_auth_san_ip: 'nope' });
  t.check(p && p.errorCode === 'STS-REG-0130', '2b. a value that is not what ' +
          'its member names is refused', JSON.stringify(p));
  p = applications.mtlsMetadataProblem({
    tls_client_certificate_bound_access_tokens: 'true' });
  t.check(p && p.errorCode === 'STS-REG-0132',
          '2c. the section 3.4 flag must be a boolean', JSON.stringify(p));
  t.check(applications.mtlsMetadataProblem({
    tls_client_auth_san_uri: 'https://c.example/id',
    tls_client_certificate_bound_access_tokens: true }) === null,
          '2d. one parameter and a boolean flag are accepted');
  let a = applications.mtlsAttributeProblem('oauthTlsClientAuthSanDns',
    'b.example', { oauthTlsClientAuthSubjectDn: 'CN=a' });
  t.check(a && a.code === 'STS-REG-0135', '2e. a console write of a second ' +
          'parameter is refused, naming the one to clear', JSON.stringify(a));
  a = applications.mtlsAttributeProblem('oauthTlsClientAuthSubjectDn',
    'CN=b', { oauthTlsClientAuthSubjectDn: 'CN=a' });
  t.check(a === null, '2f. replacing the parameter already held is not');
  a = applications.mtlsAttributeProblem('oauthTlsClientAuthSanEmail', 'x', {});
  t.check(a && a.code === 'STS-REG-0134', '2g. a console write of a bad value',
          JSON.stringify(a));
  a = applications.mtlsAttributeProblem(
    'oauthTlsClientCertificateBoundAccessTokens', 'yes', {});
  t.check(a && a.code === 'STS-REG-0136', '2h. a console flag that is not ' +
          'TRUE or FALSE', JSON.stringify(a));
  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS. Shipped as source into a child.
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
    tlsServer.trustClientCertificatesOn(server, 'the RFC 8705 test listener');
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const added = tlsServer.addAnchors(read(M.caCert));
    note(added.added === 1, 'setup: the foreign CA is a client trust anchor',
         JSON.stringify(added));
    config.setOverride('oauth2.consentRequired', false);

    const thumb = function (pem) {
      return crypto.createHash('sha256')
        .update(new crypto.X509Certificate(pem).raw).digest('base64url');
    };
    const request = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.json !== undefined ? JSON.stringify(o.json)
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({}, o.headers || {});
        if (method !== 'GET') {
          headers['content-type'] = o.json !== undefined
            ? 'application/json' : 'application/x-www-form-urlencoded';
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
            resolve({ status: res.statusCode, json: parsed, text: text,
                      headers: res.headers });
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
    // The newest audit row carrying `code` whose target names `where`, or
    // null. Asked immediately after the request it is about, and compared
    // with the count before it, so an older row cannot answer for a new one.
    const codeCount = async function (code, where) {
      await settle();
      const r = await api('/audit?per=500&code=' + encodeURIComponent(code));
      const rows = (r.json && (r.json.rows || r.json.events)) || [];
      return rows.filter(function (row) {
        return !where || JSON.stringify(row).indexOf(where) >= 0;
      }).length;
    };
    const raises = async function (code, where, fn) {
      const before = await codeCount(code, where);
      const answer = await fn();
      const after = await codeCount(code, where);
      answer.coded = after > before;
      return answer;
    };
    const claimsOf = function (jwt) {
      try {
        return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
          .toString('utf8'));
      } catch (e) {
        return {};
      }
    };
    const token = function (form, tlsOpts) {
      return request('POST', '/oauth2/token', { form: form, tls: tlsOpts });
    };
    const refused = function (r, status, error) {
      return r.status === status && r.json && r.json.error === error;
    };
    const create = function (id, fields) {
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: Object.assign({ oauthClientId: id }, fields || {}) });
    };
    const PASSWORD = 'correct horse battery';
    const issueTo = async function (id, extra) {
      const r = await api('/applications/issue-tls-client-certificate',
        Object.assign({ application: id, password: PASSWORD,
                        keyAlg: 'ec-p256' }, extra || {}));
      if (r.status !== 200 || !r.json.files) {
        return { response: r };
      }
      const key = crypto.createPrivateKey({ key: r.json.files.key.text,
                                            format: 'pem',
                                            passphrase: PASSWORD })
        .export({ type: 'pkcs8', format: 'pem' });
      return { response: r, tls: { cert: r.json.files.chain.text, key: key },
               leaf: r.json.certificate.certificatePem,
               serialHex: r.json.certificate.serialHex };
    };
    const extTls = { cert: read(M.extCert) + read(M.caCert),
                     key: read(M.extKey) };
    const selfTls = { cert: read(M.selfCert), key: read(M.selfKey) };
    const self2Tls = { cert: read(M.self2Cert), key: read(M.self2Key) };

    // --- a. discovery -------------------------------------------------------
    const meta = await request('GET', '/.well-known/oauth-authorization-server');
    const methods = (meta.json &&
                     meta.json.token_endpoint_auth_methods_supported) || [];
    note(meta.json && meta.json.tls_client_certificate_bound_access_tokens ===
         true && methods.indexOf('tls_client_auth') >= 0 &&
         methods.indexOf('self_signed_tls_client_auth') >= 0,
         '3a. discovery advertises bound tokens and both RFC 8705 methods',
         JSON.stringify(methods));

    // --- b. the implicit mapping -------------------------------------------
    create('mtls-impl', { oauthTokenEndpointAuthMethod: 'tls_client_auth' });
    create('mtls-other', { oauthTokenEndpointAuthMethod: 'tls_client_auth' });
    const impl = await issueTo('mtls-impl', { label: 'instance 1' });
    const implLeaf = impl.leaf ? new crypto.X509Certificate(impl.leaf) : null;
    note(impl.tls && impl.response.json.certificate.implicitName ===
         'urn:sts:application:mtls-impl' && implLeaf &&
         String(implLeaf.subjectAltName)
           .indexOf('URI:urn:sts:application:mtls-impl') >= 0 &&
         (implLeaf.keyUsage || []).indexOf('1.3.6.1.5.5.7.3.2') >= 0 &&
         /CN=mtls-impl/.test(implLeaf.subject),
         '3b1. the Credentials door issues a clientAuth certificate naming ' +
         'the application, and hands back its files once',
         JSON.stringify(impl.response.json).slice(0, 400));
    note(impl.response.json && impl.response.json.files &&
         /ENCRYPTED PRIVATE KEY/.test(impl.response.json.files.key.text) &&
         impl.response.json.files.pkcs12.base64.length > 100,
         '3b2. the key file is encrypted under the password and a PKCS#12 ' +
         'is built');
    const view = await api('/applications?application=mtls-impl');
    const mtlsView = view.json && view.json.credentials &&
                     view.json.credentials.mtls;
    note(mtlsView && mtlsView.certificates.length === 1 &&
         mtlsView.certificates[0].state === 'valid' &&
         mtlsView.certificateMethod === true &&
         JSON.stringify(view.json).indexOf('PRIVATE KEY') < 0,
         '3b3. the application page lists the certificate, valid, and no ' +
         'private key anywhere', JSON.stringify(mtlsView || view.json)
           .slice(0, 400));
    let r = await token({ grant_type: 'client_credentials',
                          client_id: 'mtls-impl' }, impl.tls);
    const implClaims = claimsOf(r.json && r.json.access_token);
    note(r.status === 200 && implClaims.cnf &&
         implClaims.cnf['x5t#S256'] === thumb(impl.leaf),
         '3b4. tls_client_auth authenticates the application by the ' +
         'certificate issued to it, with nothing registered, and the access ' +
         'token is bound to that certificate (RFC 8705 sections 2.1 and 3.1)',
         JSON.stringify(r.json).slice(0, 300));

    // --- c. the implicit mapping's refusals --------------------------------
    r = await raises('STS-OAUTH-0014', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-impl' });
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3c1. no certificate: invalid_client in development mode, ' +
         'STS-OAUTH-0014', JSON.stringify(r.json));
    r = await raises('STS-OAUTH-0484', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-other' }, impl.tls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3c2. another application\'s certificate does not authenticate ' +
         'this one: STS-OAUTH-0484', JSON.stringify(r.json));
    const rotated = await issueTo('mtls-impl', { label: 'instance 2' });
    note(!!rotated.tls, '3c3. a second certificate is issued for rotation');
    const forgotten = pki.certificatesFor('', 'tls-client').filter(function (c) {
      const holder = tlsClient.slotHolder(c.slot);
      return holder && holder.id === 'mtls-impl' &&
             c.serialHex === rotated.serialHex;
    })[0];
    pki.forgetCertificate('', 'tls-client', forgotten.slot);
    r = await raises('STS-OAUTH-0483', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-impl' }, rotated.tls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3c4. a certificate the application\'s record no longer lists: ' +
         'STS-OAUTH-0483', JSON.stringify(r.json));
    r = await api('/applications/issue-tls-client-certificate',
                  { application: 'mtls-impl', password: PASSWORD,
                    confirm: 'another password entirely' });
    note(r.status === 400 && (await codeCount('STS-ADMIN-0721')) >= 1,
         '3c5. the door refuses a file password typed differently twice: ' +
         'STS-ADMIN-0721',
         JSON.stringify(r.json));
    r = await api('/applications/issue-tls-client-certificate',
                  { application: 'mtls-nobody', password: PASSWORD });
    note(r.status === 400 && (await codeCount('STS-ADMIN-0722')) >= 1,
         '3c6. and an application that does not exist: STS-ADMIN-0722',
         JSON.stringify(r.json));
    config.setOverride('pki.applicationTlsClientCertificateMax', '1');
    r = await api('/applications/issue-tls-client-certificate',
                  { application: 'mtls-impl', password: PASSWORD });
    config.clearOverride('pki.applicationTlsClientCertificateMax');
    note(r.status === 400 && (await codeCount('STS-PKI-0180')) >= 1,
         '3c7. and past pki.applicationTlsClientCertificateMax: STS-PKI-0180',
         JSON.stringify(r.json));
    const otherIssued = await issueTo('mtls-other');
    r = await api('/applications/revoke-tls-client-certificate',
                  { application: 'mtls-impl',
                    serialHex: otherIssued.serialHex });
    note(r.status === 400 && (await codeCount('STS-PKI-0181')) >= 1,
         '3c8. one application cannot revoke another\'s: STS-PKI-0181',
         JSON.stringify(r.json));
    const doomed = await issueTo('mtls-other', { label: 'doomed' });
    r = await api('/applications/revoke-tls-client-certificate',
                  { application: 'mtls-other', serialHex: doomed.serialHex,
                    reason: 'keyCompromise' });
    note(r.status === 200, '3c9. the holder\'s certificate is revoked',
         JSON.stringify(r.json).slice(0, 300));
    r = await token({ grant_type: 'client_credentials',
                      client_id: 'mtls-other' }, doomed.tls);
    note(refused(r, 401, 'invalid_client') &&
         /revocation/i.test(r.json.error_description || ''),
         '3c10. a revoked certificate no longer authenticates it',
         JSON.stringify(r.json));
    r = await token({ grant_type: 'client_credentials',
                      client_id: 'mtls-other' }, otherIssued.tls);
    note(r.status === 200, '3c11. its other certificate still does',
         JSON.stringify(r.json).slice(0, 200));

    // A leaf from the TLS client authority whose CN names one application and
    // whose urn:sts:application: names another — and which is even filed under
    // the second's slot — is not an identity at all: `issue()` never builds
    // one, so the gate refuses it rather than believing either name.
    const mixedPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const mixed = await pki.certify('', 'tls-client', {
      slot: 'application:mtls-other:' + crypto.randomBytes(6).toString('hex'),
      commonName: 'mtls-impl', keyAlg: 'ec-p256',
      publicKeyPem: mixedPair.publicKey.export({ type: 'spki', format: 'pem' }),
      keyUsage: ['digitalSignature'],
      extensions: {
        extKeyUsage: { present: true, critical: false, usages: ['clientAuth'] },
        subjectAltName: { present: true, critical: false, names: [
          { kind: 'uri', value: 'urn:sts:application:mtls-other' }] } } });
    r = await raises('STS-OAUTH-0481', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-other' }, {
        cert: mixed.record.certificatePem + mixed.record.chainPem.join(''),
        key: mixedPair.privateKey.export({ type: 'pkcs8', format: 'pem' }) });
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3c12. a TLS client leaf whose CN and urn:sts:application: name ' +
         'disagree authenticates nobody: STS-OAUTH-0481',
         JSON.stringify(r.json));

    // --- d. the explicit mapping -------------------------------------------
    const explicit = [
      ['mtls-dn', 'oauthTlsClientAuthSubjectDn',
       'cn=EXT-CLIENT, o=Example Corp\\, Inc., c=US'],
      ['mtls-dns', 'oauthTlsClientAuthSanDns', 'ext.example.com'],
      ['mtls-uri', 'oauthTlsClientAuthSanUri', 'https://client.example.com/id'],
      ['mtls-ip', 'oauthTlsClientAuthSanIp', '2001:db8::7'],
      ['mtls-email', 'oauthTlsClientAuthSanEmail', 'Ops@example.com']
    ];
    for (const row of explicit) {
      const fields = { oauthTokenEndpointAuthMethod: 'tls_client_auth' };
      fields[row[1]] = row[2];
      create(row[0], fields);
      r = await token({ grant_type: 'client_credentials', client_id: row[0] },
                      extTls);
      const c = claimsOf(r.json && r.json.access_token);
      note(r.status === 200 && c.cnf && c.cnf['x5t#S256'] ===
           thumb(read(M.extCert)),
           '3d. a foreign CA\'s certificate authenticates a client that ' +
           'registered ' + row[1] + ' "' + row[2] + '"',
           JSON.stringify(r.json).slice(0, 300));
    }
    create('mtls-dn-wrong', { oauthTokenEndpointAuthMethod: 'tls_client_auth',
      oauthTlsClientAuthSubjectDn: 'CN=someone-else,O=Example Corp\\, Inc.,C=US' });
    r = await raises('STS-OAUTH-0485', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-dn-wrong' }, extTls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded &&
         /CN=ext-client/.test(r.json.error_description || ''),
         '3d2. a subject that does not match is refused, quoting the one ' +
         'presented: STS-OAUTH-0485', JSON.stringify(r.json));
    create('mtls-none', { oauthTokenEndpointAuthMethod: 'tls_client_auth' });
    r = await raises('STS-OAUTH-0486', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-none' }, extTls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3d3. a foreign certificate with nothing registered: STS-OAUTH-0486',
         JSON.stringify(r.json));
    create('mtls-selfdn', { oauthTokenEndpointAuthMethod: 'tls_client_auth',
                            oauthTlsClientAuthSubjectDn: 'CN=self-client' });
    r = await raises('STS-OAUTH-0480', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-selfdn' }, selfTls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3d4. a matching subject on a certificate whose chain did not ' +
         'verify is refused: STS-OAUTH-0480', JSON.stringify(r.json));
    // Two parameters, as an ldapmodify could leave them — written past the
    // registry's own refusal.
    create('mtls-two', { oauthTokenEndpointAuthMethod: 'tls_client_auth',
                         oauthTlsClientAuthSanDns: 'ext.example.com' });
    const refusedSecond = applications.updateApplication('mtls-two', {
      mode: 'set', attribute: 'oauthTlsClientAuthSanEmail',
      value: 'Ops@example.com' });
    note(!refusedSecond.ok, '3d5. the registry refuses a second parameter',
         JSON.stringify(refusedSecond.errors || ''));
    let wroteTwo = false;
    try {
      const store = applications.directoryInstalled();
      const held = store.readApplication('mtls-two');
      const attrs = Object.assign({}, held.attributes);
      attrs.oauthTlsClientAuthSanEmail = ['Ops@example.com'];
      wroteTwo = !!store.writeApplication('mtls-two', attrs) &&
        applications.clientConfigOf('mtls-two').tls_client_auth_san_email ===
          'Ops@example.com';
    } catch (e) {
      wroteTwo = false;
    }
    note(wroteTwo, '3d6a. a second parameter written past the registry, as ' +
         'an ldapmodify would');
    if (wroteTwo) {
      r = await raises('STS-OAUTH-0482', '/oauth2/token', function () {
        return token({ grant_type: 'client_credentials',
                       client_id: 'mtls-two' }, extTls);
      });
      note(refused(r, 401, 'invalid_client') && r.coded,
           '3d6. two parameters an ldapmodify left are refused at use: ' +
           'STS-OAUTH-0482', JSON.stringify(r.json));
    }

    // --- e. self_signed_tls_client_auth -------------------------------------
    const selfDer = new crypto.X509Certificate(read(M.selfCert)).raw
      .toString('base64');
    const selfJwk = Object.assign(crypto.createPublicKey(read(M.selfKey))
      .export({ format: 'jwk' }), { kid: 'self', x5c: [selfDer] });
    create('mtls-self-jwks', {
      oauthTokenEndpointAuthMethod: 'self_signed_tls_client_auth',
      oauthJwks: JSON.stringify({ keys: [selfJwk] }) });
    create('mtls-self-thumb', {
      oauthTokenEndpointAuthMethod: 'self_signed_tls_client_auth',
      oauthTlsClientCertificateThumbprint: thumb(read(M.selfCert)) });
    create('mtls-self-empty', {
      oauthTokenEndpointAuthMethod: 'self_signed_tls_client_auth' });
    r = await token({ grant_type: 'client_credentials',
                      client_id: 'mtls-self-jwks' }, selfTls);
    note(r.status === 200 &&
         claimsOf(r.json.access_token).cnf['x5t#S256'] ===
           thumb(read(M.selfCert)),
         '3e1. a self-signed certificate that is the x5c of a key in the ' +
         'client\'s jwks authenticates it (section 2.2.2) and binds the token',
         JSON.stringify(r.json).slice(0, 300));
    r = await token({ grant_type: 'client_credentials',
                      client_id: 'mtls-self-thumb' }, selfTls);
    note(r.status === 200, '3e2. and by the registered thumbprint',
         JSON.stringify(r.json).slice(0, 200));
    r = await raises('STS-OAUTH-0016', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-self-jwks' }, self2Tls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3e3. another self-signed certificate is refused: STS-OAUTH-0016',
         JSON.stringify(r.json));
    r = await raises('STS-OAUTH-0015', '/oauth2/token', function () {
      return token({ grant_type: 'client_credentials',
                     client_id: 'mtls-self-empty' }, selfTls);
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3e4. nothing registered: STS-OAUTH-0015', JSON.stringify(r.json));

    // --- f. the declaration at PAR -----------------------------------------
    r = await raises('STS-OAUTH-0014', '/oauth2/par', function () {
      return request('POST', '/oauth2/par', { form: {
        client_id: 'mtls-impl', response_type: 'code',
        redirect_uri: 'https://mtls.example/cb',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256' } });
    });
    note(refused(r, 401, 'invalid_client') && r.coded,
         '3f. a pushed authorization request from a tls_client_auth client ' +
         'with no certificate is refused in development mode',
         JSON.stringify(r.json));

    // --- g. section 3.4 ------------------------------------------------------
    create('mtls-bound-public', { oauthTokenEndpointAuthMethod: 'none',
      oauthTlsClientCertificateBoundAccessTokens: 'TRUE' });
    r = await raises('STS-OAUTH-0487', '/oauth2/token', function () {
      return token({ grant_type: 'password', client_id: 'mtls-bound-public',
                     username: 'mtls-alice', password: 'anything',
                     scope: 'openid' });
    });
    note(refused(r, 400, 'invalid_request') && r.coded,
         '3g1. a client that declared bound tokens is refused a token with ' +
         'no certificate: STS-OAUTH-0487', JSON.stringify(r.json));
    r = await token({ grant_type: 'password', client_id: 'mtls-bound-public',
                      username: 'mtls-alice', password: 'anything',
                      scope: 'openid' }, selfTls);
    const publicAccess = r.json && r.json.access_token;
    const publicRefresh = r.json && r.json.refresh_token;
    note(r.status === 200 && claimsOf(publicAccess).cnf['x5t#S256'] ===
         thumb(read(M.selfCert)),
         '3g2. and bound to the certificate when it presents one — a public ' +
         'client, section 4', JSON.stringify(r.json).slice(0, 300));

    // --- h. the resource server and introspection ----------------------------
    const userinfo = function (accessToken, tlsOpts) {
      return request('GET', '/oauth2/userinfo', {
        headers: { authorization: 'Bearer ' + accessToken }, tls: tlsOpts });
    };
    r = await userinfo(publicAccess, selfTls);
    note(r.status === 200, '3h1. UserInfo answers a bound token on a ' +
         'connection made with its certificate', r.text.slice(0, 200));
    r = await raises('STS-OAUTH-0091', '/oauth2/userinfo', function () {
      return userinfo(publicAccess);
    });
    note(r.status === 401 && r.coded &&
         /invalid_token/.test(String(r.headers['www-authenticate'] || '')),
         '3h2. and refuses it with no certificate: 401 invalid_token, ' +
         'STS-OAUTH-0091', r.text.slice(0, 200));
    r = await raises('STS-OAUTH-0092', '/oauth2/userinfo', function () {
      return userinfo(publicAccess, self2Tls);
    });
    note(r.status === 401 && r.coded,
         '3h3. and with another certificate: STS-OAUTH-0092',
         r.text.slice(0, 200));
    r = await request('POST', '/oauth2/introspect',
                      { form: { token: publicAccess } });
    note(r.status === 200 && r.json.active === true && r.json.cnf &&
         r.json.cnf['x5t#S256'] === thumb(read(M.selfCert)),
         '3h4. introspection carries the cnf x5t#S256 (section 3.2)',
         JSON.stringify(r.json).slice(0, 300));

    // --- i. section 7.1 ------------------------------------------------------
    r = await raises('STS-OAUTH-0092', '/oauth2/token', function () {
      return token({ grant_type: 'refresh_token',
                     client_id: 'mtls-bound-public',
                     refresh_token: publicRefresh }, self2Tls);
    });
    note(refused(r, 400, 'invalid_grant') && r.coded,
         '3i1. a public client\'s refresh token is refused on another ' +
         'certificate — it is bound to the certificate (section 4)',
         JSON.stringify(r.json));
    r = await token({ grant_type: 'password', client_id: 'mtls-impl',
                      username: 'mtls-alice', password: 'anything',
                      scope: 'openid' }, impl.tls);
    const implRefresh = r.json && r.json.refresh_token;
    note(r.status === 200 && !!implRefresh &&
         claimsOf(r.json.access_token).cnf['x5t#S256'] === thumb(impl.leaf),
         '3i2. a certificate client gets a bound access token and a refresh ' +
         'token', JSON.stringify(r.json).slice(0, 200));
    const renewed = await issueTo('mtls-impl', { label: 'renewed' });
    r = await token({ grant_type: 'refresh_token', client_id: 'mtls-impl',
                      refresh_token: implRefresh }, renewed.tls);
    note(r.status === 200 && claimsOf(r.json.access_token).cnf['x5t#S256'] ===
         thumb(renewed.leaf),
         '3i3. its refresh on a NEW certificate succeeds, and the new access ' +
         'token is bound to the new certificate (sections 6.3 and 7.1)',
         JSON.stringify(r.json).slice(0, 300));
    r = await raises('STS-OAUTH-0092', '/oauth2/token', function () {
      return token({ grant_type: 'refresh_token', client_id: 'mtls-other',
                     refresh_token: implRefresh }, otherIssued.tls);
    });
    note(r.status === 400 && r.coded,
         '3i4. another certificate client presenting that refresh token ' +
         'still meets its binding — the indirect binding is the token\'s ' +
         'own client\'s only', JSON.stringify(r.json));

    // --- j. RFC 7591 registration --------------------------------------------
    const register = function (metadata) {
      return request('POST', '/oauth2/register', { json: metadata });
    };
    r = await register({ redirect_uris: ['https://mtls.example/cb'],
      token_endpoint_auth_method: 'tls_client_auth',
      tls_client_auth_san_dns: 'ext.example.com',
      tls_client_certificate_bound_access_tokens: true });
    const regId = r.json && r.json.client_id;
    note(r.status === 201 && r.json.tls_client_auth_san_dns ===
         'ext.example.com' &&
         r.json.tls_client_certificate_bound_access_tokens === true,
         '3j1. a registration carrying a subject parameter and the flag is ' +
         'accepted and echoed', JSON.stringify(r.json).slice(0, 300));
    const regConfig = applications.clientConfigOf(regId);
    note(regConfig.tls_client_auth_san_dns === 'ext.example.com' &&
         regConfig.tls_client_certificate_bound_access_tokens === true,
         '3j2. and written to the entry the token endpoint reads',
         JSON.stringify(regConfig).slice(0, 300));
    r = await token({ grant_type: 'client_credentials', client_id: regId },
                    extTls);
    note(r.status === 200, '3j3. that registered client authenticates with ' +
         'the foreign certificate', JSON.stringify(r.json).slice(0, 200));
    r = await raises('STS-REG-0131', '/oauth2/register', function () {
      return register({ redirect_uris: ['https://mtls.example/cb'],
        token_endpoint_auth_method: 'tls_client_auth',
        tls_client_auth_subject_dn: 'CN=a', tls_client_auth_san_dns: 'a.b' });
    });
    note(refused(r, 400, 'invalid_client_metadata') && r.coded,
         '3j4. two subject parameters are refused: STS-REG-0131',
         JSON.stringify(r.json));
    r = await raises('STS-REG-0130', '/oauth2/register', function () {
      return register({ redirect_uris: ['https://mtls.example/cb'],
        token_endpoint_auth_method: 'tls_client_auth',
        tls_client_auth_subject_dn: 'CN=a,' });
    });
    note(refused(r, 400, 'invalid_client_metadata') && r.coded,
         '3j5. a DN that is not one is refused: STS-REG-0130',
         JSON.stringify(r.json));
    process.env.STS_HTTPS = 'false';
    r = await raises('STS-REG-0133', '/oauth2/register', function () {
      return register({ redirect_uris: ['https://mtls.example/cb'],
        tls_client_certificate_bound_access_tokens: true });
    });
    process.env.STS_HTTPS = 'true';
    note(refused(r, 400, 'invalid_client_metadata') && r.coded,
         '3j6. bound tokens asked of a service whose main port is not TLS ' +
         'are refused: STS-REG-0133', JSON.stringify(r.json));

    // --- k. /admin-api as a resource server -----------------------------------
    config.setOverride('adminApi.authRequired', true);
    const adminBasic = 'Basic ' + Buffer.from('sts-management-api:' +
      process.env.ADMIN_API_CLIENT_SECRET).toString('base64');
    r = await request('POST', '/oauth2/token', {
      headers: { authorization: adminBasic },
      form: { grant_type: 'client_credentials', scope: 'admin:read',
              resource: 'https://127.0.0.1:' + port + '/admin-api' },
      tls: selfTls });
    const adminToken = r.json && r.json.access_token;
    note(r.status === 200 && claimsOf(adminToken).cnf &&
         claimsOf(adminToken).cnf['x5t#S256'] === thumb(read(M.selfCert)),
         '3k1. an /admin-api access token asked for over a certificate is ' +
         'bound to it', JSON.stringify(r.json).slice(0, 300));
    r = await request('GET', '/admin-api/status', {
      headers: { authorization: 'Bearer ' + adminToken }, tls: selfTls });
    note(r.status === 200, '3k2. /admin-api answers it on a connection made ' +
         'with that certificate', r.text.slice(0, 200));
    r = await request('GET', '/admin-api/status', {
      headers: { authorization: 'Bearer ' + adminToken } });
    config.setOverride('adminApi.authRequired', false);
    note(r.status === 401 && r.json.error === 'invalid_token' &&
         (await codeCount('STS-API-0110')) >= 1,
         '3k3. and refuses it without the certificate: 401 invalid_token, ' +
         'STS-API-0110', r.text.slice(0, 300));

    // --- l. an application's certificate at the TLS listeners -----------------
    await tlsServer.listen().whenReady;
    const whoami = await new Promise(function (resolve) {
      const req = https.request({ host: '127.0.0.1',
        port: tlsServer.ports().mtls, path: '/tls/whoami', method: 'GET',
        cert: otherIssued.tls.cert, key: otherIssued.tls.key,
        rejectUnauthorized: false, agent: false }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let body = {};
          try {
            body = JSON.parse(text);
          } catch (e) {
            body = { raw: text.slice(0, 200) };
          }
          resolve({ status: res.statusCode, body: body });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, body: { error: e.message } });
      });
      req.end();
    });
    note(whoami.status === 200 && whoami.body.session &&
         whoami.body.session.started === false &&
         whoami.body.session.application === 'mtls-other',
         '3l. an application\'s TLS client certificate at 9443 verifies and ' +
         'starts NO browser session in the application\'s name',
         JSON.stringify({ status: whoami.status,
                          session: whoami.body.session }));
    tlsServer.close();

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rfc8705-'));
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  openssl(dir, ['req', '-x509'].concat(ec, ['-keyout', 'ca.key', '-out',
    'ca.pem', '-days', '2', '-subj', '/CN=RFC 8705 Test Foreign CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign']));
  fs.writeFileSync(path.join(dir, 'ext.cnf'),
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' +
    'extendedKeyUsage=clientAuth\nsubjectAltName=@alt\n[alt]\n' +
    'DNS.1=ext.example.com\nURI.1=https://client.example.com/id\n' +
    'IP.1=192.0.2.10\nIP.2=2001:db8::7\nemail.1=Ops@example.com\n');
  openssl(dir, ['req'].concat(ec, ['-keyout', 'ext.key', '-out', 'ext.csr',
    '-subj', '/C=US/O=Example Corp, Inc./CN=ext-client']));
  openssl(dir, ['x509', '-req', '-in', 'ext.csr', '-CA', 'ca.pem', '-CAkey',
    'ca.key', '-CAcreateserial', '-out', 'ext.pem', '-days', '1',
    '-extfile', 'ext.cnf']);
  ['self', 'self2'].forEach(function (name) {
    openssl(dir, ['req', '-x509'].concat(ec, ['-keyout', name + '.key',
      '-out', name + '.pem', '-days', '1', '-subj',
      '/CN=' + (name === 'self' ? 'self-client' : 'self-client-two'),
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
  t.log.info('=== 3. the endpoints, over HTTPS with client certificates ===');
  const out = path.join(os.tmpdir(), 'rfc8705-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|LDAPS_|KRB5_|CONFIG_FILE$)/
      .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', M_ROOT: ROOT, M_OUT: out,
                                  M_MATERIAL: JSON.stringify(material),
                                  STS_HTTPS: 'true', STS_TLS_PORT: '0',
                                  ADMIN_API_AUTH_REQUIRED: 'false',
                                  ADMIN_API_CLIENT_SECRET:
                                    nodeCrypto.randomBytes(24)
                                      .toString('base64url'),
                                  STS_MTLS_PORT: '0' }),
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
  subjectLibrary(t, material);
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
  name: 'rfc8705 mutual TLS',
  describe: 'RFC 8705: tls_client_auth by a certificate issued to the ' +
            'application and by each of the five registered subjects, ' +
            'self_signed_tls_client_auth, the declaration held in every mode, ' +
            'certificate-bound tokens at the resource server and ' +
            'introspection, section 7.1 refresh, registration, and the ' +
            'Credentials door',
  run: run
};
