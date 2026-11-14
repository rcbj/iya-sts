// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_client_certificate.js
//
// ===========================================================================
// THE REQUESTER AUTHENTICATED BY ITS TLS CLIENT CERTIFICATE (#1046).
//
// A request to /sts whose wsse:Security carries no credential is
// authenticated by the verified TLS client certificate on the connection,
// mapped to a person or an application by `common/tls_client_certificates.js`
// and no other way. Asserted, through `handleRst()` with the connection a
// route hands it (`{ socket, revocation }`):
//
//   A. product: a person's certificate is the requester — SAML 2.0 says
//      TLSClient, SAML 1.1 says urn:ietf:rfc:2246, a JWT carries `amr`
//      ["swk"] and the person's `urn:uuid:` subject, and the session it
//      starts is `swk`; a JWT from a UsernameToken carries ["pwd"];
//   B. a UsernameToken in the message wins over the certificate;
//   C. an application's certificate is the application, and starts no
//      session;
//   D. refusals, each wst:FailedAuthentication: revoked (0034), another
//      realm's authority (0035), a disabled person (0037) — in product, and
//      the revoked one in development too;
//   E. not this credential: an unverified certificate, and any certificate
//      with `wstrust.acceptClientCertificate` off — product then refuses
//      for want of a credential (0010);
//   F. an outside authority's certificate (#1061): refused stored on no
//      entry (0038) though its CN names a person, accepted as the person
//      whose entry stores it, a renewed one with the same subject refused,
//      the stored one refused on revocation (0034), and refused stored on
//      two entries (0039).
//
// `STS-WSTRUST-0036` (the holder's record no longer lists the certificate)
// is `stillHeld()`'s answer, held by `certificate_holder_rename.js` and
// `rfc8705_mtls.js`; nothing here can make a certificate the register
// forgets while it still verifies.
//
// IN A CHILD PROCESS, for `certificate_holder_rename.js`'s reason: it loads
// the stack for the directory's subject resolver and builds a certificate
// authority, both process state `run.js` shares with every other file. A
// request over the main port would need a certificate the suite's client
// presents, and no stack job's client presents one to /sts; the socket is
// therefore the one thing faked, in the shape `revocation_status.fromSocket()`
// reads from a real one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_WSTRUST_CLIENT_CERT_CHILD';
const MARK = 'WSTRUST-CERT-CHILD ';

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const BACK = 'https://wcc-back.example';
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const SAML11_TYPE = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-saml-token-profile-1.1#SAMLV1.1';
const BASE = 'https://sts.example';

const log = require('bunyan').createLogger({
  name: 'wstrust_client_certificate',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// A TLS socket whose handshake verified `pem` with `chain` above it, as
// `getPeerCertificate(true)` describes one: each certificate's DER and its
// issuer's, the top one its own issuer.
function socketFor(pem, chain, authorized) {
  log.debug("Entering socketFor().");
  const certs = [pem].concat(chain || []).map(function (one) {
    return { raw: new nodeCrypto.X509Certificate(one).raw };
  });
  certs.forEach(function (one, i) {
    one.issuerCertificate = certs[i + 1] || one;
  });
  log.debug("Leaving socketFor().");
  return {
    authorized: authorized !== false,
    getPeerCertificate: function () {
      return certs[0];
    }
  };
}

function rst(opts) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' +
    (opts.security || '') + '</wsse:Security></s:Header><s:Body>' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '">' +
    '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
    (opts.tokenType ? '<wst:TokenType>' + opts.tokenType +
      '</wst:TokenType>' : '') +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
    '08/addressing"><wsa:Address>' + BACK + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function jwtClaimsOf(body) {
  log.debug("Entering jwtClaimsOf().");
  const found = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(String(body));
  if (!found) {
    log.debug("Leaving jwtClaimsOf(). None.");
    return null;
  }
  try {
    const claims = JSON.parse(Buffer.from(found[1].split('.')[1],
                                          'base64url').toString('utf8'));
    log.debug("Leaving jwtClaimsOf().");
    return claims;
  } catch (e) {
    log.debug("Caught in jwtClaimsOf(): " + ((e && e.message) || e));
    log.debug("Leaving jwtClaimsOf(). Unreadable.");
    return null;
  }
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const config = require(ROOT + '/common/config');
  const realms = require(ROOT + '/common/realms');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const applications = require(ROOT + '/common/applications');
  const accountState = require(ROOT + '/common/account_state');
  const tlsClient = require(ROOT + '/common/tls_client_certificates');
  const wstrust = require(ROOT + '/ws-trust/wstrust');

  await keystore.start();
  const otherId = 'wccother';
  const made = realms.create({ id: otherId, name: otherId,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'precondition: a second realm exists',
          JSON.stringify(made.errors || ''));
  await pki.start({ realmIds: ['', otherId],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(realms.currentId());
  await pki.ensureScope(otherId);

  ldap.createUser('wccalice', { invent: false });
  ldap.createUser('wccbob', { invent: false });
  ldap.createUser('wcccarol', { invent: false });
  const app = applications.createApplication({ identifier: 'wccback',
    protocols: ['wstrust'],
    fields: { oauthClientId: 'wccback', wstrustAppliesTo: [BACK] } });
  const svc = applications.createApplication({ identifier: 'wccsvc',
    protocols: ['wstrust'], fields: { oauthClientId: 'wccsvc' } });
  t.check(app && app.ok && svc && svc.ok,
          'precondition: the applications were created',
          JSON.stringify([app, svc]));

  const issued = {};
  const issueFor = async function (key, spec, realmId) {
    log.debug("Entering issueFor(). " + key);
    const r = await tlsClient.issue(realmId,
      Object.assign({ label: key, keyAlg: 'ec-p256' }, spec));
    t.check(r.ok, 'precondition: a TLS client certificate for ' + key,
            JSON.stringify(r.errors || ''));
    issued[key] = r.ok ? socketFor(r.issued.certificatePem,
                                   r.issued.chainPem) : null;
    log.debug("Leaving issueFor().");
  };
  await issueFor('alice', { username: 'wccalice' });
  await issueFor('carol', { username: 'wcccarol' });
  await issueFor('svc', { kind: 'application', application: 'wccsvc' });
  await realms.run(realms.get(otherId), async function () {
    ldap.createUser('wccalice', { invent: false });
    await issueFor('other', { username: 'wccalice' }, otherId);
  });

  const ask = function (m, opts, connection) {
    log.debug("Entering ask(). " + m);
    config.setOverride('global.mode', m);
    try {
      log.debug("Leaving ask().");
      return wstrust.handleRst(rst(opts), 'application/soap+xml',
                               { base: BASE, connection: connection });
    } finally {
      config.clearOverride('global.mode');
    }
  };
  const conn = function (key, revocation) {
    log.debug("Entering conn().");
    log.debug("Leaving conn().");
    return { socket: issued[key], revocation: revocation || null };
  };
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return JSON.stringify({ status: r.status, errorCode: r.errorCode,
                            signIn: r.signIn,
                            body: String(r.body || '').slice(0, 600) });
  };

  // -------------------------------------------------------------------------
  // A. A PERSON'S CERTIFICATE, IN PRODUCT
  // -------------------------------------------------------------------------
  let r = ask('product', {}, conn('alice'));
  t.check(r.status === 200 && /TLSClient/.test(r.body) &&
          />wccalice</.test(r.body),
          'A1. product: the certificate alone authenticates its person; the ' +
          'SAML 2.0 assertion is about them and says TLSClient', brief(r));
  t.check(r.signIn && r.signIn.username === 'wccalice' &&
          JSON.stringify(r.signIn.amr) === '["swk"]',
          'A2. the session it starts is the person\'s, with amr swk',
          brief(r));
  r = ask('product', { tokenType: SAML11_TYPE }, conn('alice'));
  t.check(r.status === 200 &&
          /AuthenticationMethod="urn:ietf:rfc:2246"/.test(r.body),
          'A3. a SAML 1.1 assertion says urn:ietf:rfc:2246', brief(r));
  r = ask('product', { tokenType: JWT_TYPE }, conn('alice'));
  let claims = jwtClaimsOf(r.body);
  t.check(r.status === 200 && claims &&
          JSON.stringify(claims.amr) === '["swk"]' &&
          String(claims.sub) === String(helpers.subjectForName('wccalice')) &&
          /^urn:uuid:/.test(String(claims.sub)),
          'A4. a JWT carries amr ["swk"] and the person\'s urn:uuid: subject',
          JSON.stringify(claims));
  r = ask('development', { tokenType: JWT_TYPE,
    security: '<wsse:UsernameToken><wsse:Username>wccbob</wsse:Username>' +
      '<wsse:Password>anything</wsse:Password></wsse:UsernameToken>' }, null);
  claims = jwtClaimsOf(r.body);
  t.check(r.status === 200 && claims &&
          JSON.stringify(claims.amr) === '["pwd"]',
          'A5. a JWT from a UsernameToken carries amr ["pwd"]',
          JSON.stringify(claims));

  // -------------------------------------------------------------------------
  // B. THE MESSAGE WINS
  // -------------------------------------------------------------------------
  r = ask('development', {
    security: '<wsse:UsernameToken><wsse:Username>wccbob</wsse:Username>' +
      '<wsse:Password>anything</wsse:Password></wsse:UsernameToken>' },
          conn('alice'));
  t.check(r.status === 200 && />wccbob</.test(r.body) &&
          !/TLSClient/.test(r.body) &&
          /PasswordProtectedTransport/.test(r.body),
          'B1. a UsernameToken in the message is the requester, not the ' +
          'certificate on the connection', brief(r));

  // -------------------------------------------------------------------------
  // C. AN APPLICATION'S CERTIFICATE
  // -------------------------------------------------------------------------
  r = ask('product', { tokenType: JWT_TYPE }, conn('svc'));
  claims = jwtClaimsOf(r.body);
  t.check(r.status === 200 && claims && claims.client_id === 'wccsvc' &&
          /wccsvc$/.test(String(claims.sub)) &&
          JSON.stringify(claims.amr) === '["swk"]' && !r.signIn,
          'C1. an application\'s certificate is the application: its own ' +
          'token, client_id its own, and no session', brief(r));

  // -------------------------------------------------------------------------
  // D. REFUSALS
  // -------------------------------------------------------------------------
  const failed = function (res, code) {
    log.debug("Entering failed().");
    log.debug("Leaving failed().");
    return res.status === 500 && res.errorCode === code &&
      /wst:FailedAuthentication/.test(String(res.body)) && !res.signIn;
  };
  const revoked = { refused: true, why: 'the test says it is revoked',
                    policy: 'test' };
  r = ask('product', {}, conn('alice', revoked));
  t.check(failed(r, 'STS-WSTRUST-0034'),
          'D1. product: a revoked certificate is FailedAuthentication, ' +
          'STS-WSTRUST-0034', brief(r));
  r = ask('development', {}, conn('alice', revoked));
  t.check(failed(r, 'STS-WSTRUST-0034'),
          'D2. development refuses it too, rather than issuing to anonymous',
          brief(r));
  r = ask('product', {}, conn('other'));
  t.check(failed(r, 'STS-WSTRUST-0035'),
          'D3. a certificate from another realm\'s authority is ' +
          'STS-WSTRUST-0035', brief(r));
  const off = accountState.setDisabled('wcccarol', true);
  t.check(off && off.ok !== false, 'precondition: wcccarol is disabled',
          JSON.stringify(off));
  r = ask('product', {}, conn('carol'));
  t.check(failed(r, 'STS-WSTRUST-0037'),
          'D4. a disabled person\'s certificate is STS-WSTRUST-0037',
          brief(r));

  // -------------------------------------------------------------------------
  // E. NOT THIS CREDENTIAL
  // -------------------------------------------------------------------------
  const unverified = { socket: Object.assign({}, issued.alice,
                                             { authorized: false }),
                       revocation: null };
  r = ask('product', {}, unverified);
  t.check(failed(r, 'STS-WSTRUST-0010'),
          'E1. an unverified certificate is no credential: product refuses ' +
          'for want of one (0010)', brief(r));
  config.setOverride('wstrust.acceptClientCertificate', false);
  try {
    r = ask('product', {}, conn('alice'));
  } finally {
    config.clearOverride('wstrust.acceptClientCertificate');
  }
  t.check(failed(r, 'STS-WSTRUST-0010'),
          'E2. with wstrust.acceptClientCertificate off the certificate is ' +
          'ignored (0010)', brief(r));
  r = ask('development', {}, unverified);
  t.check(r.status === 200 && />anonymous</.test(r.body),
          'E3. development, with no credential it can use, is anonymous as ' +
          'before', brief(r));

  // -------------------------------------------------------------------------
  // F. AN OUTSIDE AUTHORITY'S CERTIFICATE (#1061): the one entry storing it
  // -------------------------------------------------------------------------
  const outsideCa = require(ROOT + '/tests/tools/pep-credential.js');
  const first = await outsideCa.mint({ subject: 'CN=wccdave,O=Outside',
                                       crlBase: '' });
  const renewed = await outsideCa.mint({ subject: 'CN=wccdave,O=Outside',
                                         crlBase: '' });
  ldap.createUser('wccdave', { invent: false });
  const derOf = function (pem) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(pem).raw;
  };
  const outsideConn = function (minted, revocation) {
    log.debug("Entering outsideConn().");
    log.debug("Leaving outsideConn().");
    return { socket: socketFor(minted.leaf.pem, [minted.issuing.pem]),
             revocation: revocation || null };
  };
  r = ask('product', {}, outsideConn(first));
  t.check(failed(r, 'STS-WSTRUST-0038') && !/>wccdave</.test(r.body),
          'F1. an outside certificate stored on no entry is ' +
          'STS-WSTRUST-0038, though its CN names a person who exists',
          brief(r));
  const stored = ldap.changeStoredCertificate('person', 'wccdave',
                                              { add: derOf(first.leaf.pem) });
  t.check(stored.ok && stored.changed,
          'precondition: the certificate is stored on wccdave',
          JSON.stringify(stored));
  r = ask('product', {}, outsideConn(first));
  t.check(r.status === 200 && />wccdave</.test(r.body) &&
          /TLSClient/.test(r.body) && r.signIn &&
          r.signIn.username === 'wccdave',
          'F2. stored on wccdave\'s entry, it authenticates wccdave',
          brief(r));
  r = ask('product', {}, outsideConn(renewed));
  t.check(failed(r, 'STS-WSTRUST-0038'),
          'F3. a renewed certificate with the same subject is not the one ' +
          'stored: STS-WSTRUST-0038 until it is stored too', brief(r));
  r = ask('product', {}, outsideConn(first, revoked));
  t.check(failed(r, 'STS-WSTRUST-0034'),
          'F4. the stored certificate refused on revocation is ' +
          'STS-WSTRUST-0034', brief(r));
  ldap.changeStoredCertificate('person', 'wccbob',
                               { add: derOf(first.leaf.pem) });
  r = ask('product', {}, outsideConn(first));
  t.check(failed(r, 'STS-WSTRUST-0039'),
          'F5. stored on two entries it names nobody: STS-WSTRUST-0039',
          brief(r));
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (got.error) {
    log.debug("Leaving run(). The child failed.");
    throw new Error(got.error);
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'wstrust_client_certificate',
  describe: 'WS-Trust: the TLS client certificate on the connection is the ' +
            'requester\'s fourth credential, mapped by the identity gate, ' +
            'and refused when revoked, another realm\'s or disabled (#1046)',
  run: run
};
