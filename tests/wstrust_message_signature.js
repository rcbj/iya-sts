// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_message_signature.js
//
// ===========================================================================
// THE REQUESTER AUTHENTICATED BY A WS-SECURITY SIGNATURE ON THE MESSAGE
// (#521).
//
// A WS-Trust RST whose wsse:Security carries an XML Signature over THE SOAP
// Body and THE wsu:Timestamp, made with the key of a certificate the header
// names, authenticates the person or application that certificate maps to:
// one issued by the realm's `message-signing` Issuing CA naming them, or an
// outside certificate stored in their `userCertificate`. Requests are signed
// here with keys made at run time. Asserted, each refusal by its code:
//
//   A. product: a person's signing certificate in a BinarySecurityToken is
//      the requester — SAML 2.0 says X509, SAML 1.1 says X509-PKI, a JWT
//      carries amr ["swk"] and the urn:uuid: subject, a session is started;
//      the certificate by thumbprint, by issuer and serial and by Subject
//      Key Identifier; an application's is the application, no session;
//   B. replay: the same signed request twice is 0050; one the endpoint did
//      not check against the history is 0051;
//   C. the signature: a Body altered after signing and a signature by
//      another key are 0045; signature wrapping — an unsigned RST in a header
//      (0046), the Body's id on a second element (0040), a signature over
//      the Body alone (0040, wst:AuthenticationBadElements); SHA-1 (0040);
//   D. freshness: an expired Timestamp (0048, wst:ExpiredData), one Created
//      in the future (0047);
//   E. the certificate: a TLS client certificate of this service (0042),
//      another realm's signing certificate (0042), a revoked one (0049), a
//      reference to nothing issued (0041), an outside certificate stored on
//      nobody (0043), stored on one entry (accepted; refused on revocation
//      when its issuer names no list and the policy wants one, 0049), stored
//      on two (0044), a disabled person (0052);
//   F. precedence: a UsernameToken beside the signature naming the same
//      person is accepted and named; naming somebody else is 0053;
//   G. development: an altered Body is believed, and the note says so; a
//      signed ActAs is a token about its subject with the signer acting;
//   H. the endpoint: over HTTP a signed request is issued and the same
//      request again is refused.
//
// IN A CHILD PROCESS, for `wstrust_client_certificate.js`'s reason: it loads
// the stack and builds a certificate authority, both process state `run.js`
// shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const http = require('http');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_WSTRUST_MESSAGE_SIGNATURE_CHILD';
const MARK = 'WSTRUST-SIG-CHILD ';

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const WST14 = 'http://docs.oasis-open.org/ws-sx/ws-trust/200802';
const WSSE = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-secext-1.0.xsd';
const WSU = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-utility-1.0.xsd';
const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509v3';
const THUMBPRINT = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-soap-message-security-1.1#ThumbprintSHA1';
const SKI = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
const BASE64 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const BACK = 'https://wms-back.example';
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const SAML11_TYPE = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-saml-token-profile-1.1#SAMLV1.1';
const BASE = 'https://sts.example';

const log = require('bunyan').createLogger({
  name: 'wstrust_message_signature',
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

// An RST, unsigned, with the ids a signer references.
function envelope(opts) {
  log.debug("Entering envelope().");
  const now = Date.now();
  const created = new Date(now + (opts.createdOffsetMs || 0)).toISOString();
  const expires = new Date(now + (opts.expiresOffsetMs === undefined
    ? 300000 : opts.expiresOffsetMs)).toISOString();
  const certB64 = opts.certPem ? String(opts.certPem)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') : '';
  log.debug("Leaving envelope().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '"><s:Header>' +
    (opts.header || '') + '<wsse:Security>' +
    '<wsu:Timestamp wsu:Id="ts"><wsu:Created>' + created +
    '</wsu:Created><wsu:Expires>' + expires + '</wsu:Expires>' +
    '</wsu:Timestamp>' +
    (certB64 ? '<wsse:BinarySecurityToken wsu:Id="x509" ValueType="' +
      X509V3 + '" EncodingType="' + BASE64 + '">' + certB64 +
      '</wsse:BinarySecurityToken>' : '') +
    (opts.security || '') + '</wsse:Security></s:Header>' +
    '<s:Body wsu:Id="body">' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '" Context="urn:uuid:' +
    nodeCrypto.randomUUID() + '">' +
    '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
    (opts.tokenType ? '<wst:TokenType>' + opts.tokenType +
      '</wst:TokenType>' : '') +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
    '08/addressing"><wsa:Address>' + BACK + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' + (opts.inner || '') +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

// The KeyInfo a reference form puts in place of the signer's X509Data.
function keyInfoFor(form, certPem, pkiModule) {
  log.debug("Entering keyInfoFor(). " + form);
  const x509 = new nodeCrypto.X509Certificate(certPem);
  let inner = '<wsse:Reference URI="#x509" ValueType="' + X509V3 + '"/>';
  if (form === 'thumbprint') {
    inner = '<wsse:KeyIdentifier ValueType="' + THUMBPRINT +
      '" EncodingType="' + BASE64 + '">' +
      nodeCrypto.createHash('sha1').update(x509.raw).digest('base64') +
      '</wsse:KeyIdentifier>';
  } else if (form === 'ski') {
    const hex = pkiModule.pathFactsOf(pkiModule.certificateFromDer(x509.raw))
      .keyIdentifier;
    inner = '<wsse:KeyIdentifier ValueType="' + SKI + '" EncodingType="' +
      BASE64 + '">' + Buffer.from(hex, 'hex').toString('base64') +
      '</wsse:KeyIdentifier>';
  } else if (form === 'issuer-serial') {
    inner = '<ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      '<ds:X509IssuerSerial><ds:X509IssuerName>' +
      x509.issuer.split('\n').join(',') + '</ds:X509IssuerName>' +
      '<ds:X509SerialNumber>' + BigInt('0x' + x509.serialNumber).toString() +
      '</ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data>';
  }
  log.debug("Leaving keyInfoFor().");
  return '<ds:KeyInfo><wsse:SecurityTokenReference>' + inner +
    '</wsse:SecurityTokenReference></ds:KeyInfo>';
}

// A signed RST: the engine's WS-Security signer over the Body and the
// Timestamp, its KeyInfo then replaced with a SecurityTokenReference (the
// KeyInfo is not signed, so the replacement changes nothing it covers).
function signedRst(xmldsig, pkiModule, opts) {
  log.debug("Entering signedRst().");
  const xml = envelope(Object.assign({}, opts,
    { certPem: opts.form === 'token' || !opts.form ? opts.certPem : '' }));
  let signed = xmldsig.signWsSecurity(xml, {
    privateKeyPem: opts.signKeyPem || opts.keyPem, certPem: opts.certPem,
    signTimestamp: opts.signTimestamp !== false,
    sigAlg: opts.sigAlg || undefined });
  signed = signed.replace(/<ds:KeyInfo>[\s\S]*?<\/ds:KeyInfo>/,
                          keyInfoFor(opts.form || 'token', opts.certPem,
                                     pkiModule));
  log.debug("Leaving signedRst().");
  return opts.after ? opts.after(signed) : signed;
}

function claimsOf(body) {
  log.debug("Entering claimsOf().");
  const found = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(String(body));
  try {
    log.debug("Leaving claimsOf().");
    return found ? JSON.parse(Buffer.from(found[1].split('.')[1],
                                          'base64url').toString('utf8'))
                 : null;
  } catch (e) {
    log.debug("Caught in claimsOf(): " + ((e && e.message) || e));
    return null;
  }
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const config = require(ROOT + '/common/config');
  const realms = require(ROOT + '/common/realms');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const applications = require(ROOT + '/common/applications');
  const accountState = require(ROOT + '/common/account_state');
  const tlsClient = require(ROOT + '/common/tls_client_certificates');
  const xmldsig = require(ROOT + '/common/crypto_impl/xmldsig.js');
  const xmldom = require('@xmldom/xmldom');
  const wstrustModule = require(ROOT + '/ws-trust/wstrust');
  const wstrust = new wstrustModule.WsTrust(
    wstrustModule.WsTrust.defaultDeps());

  await keystore.start();
  const otherId = 'wmsother';
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

  ['wmsalice', 'wmsbob', 'wmscarol', 'wmsdave'].forEach(function (name) {
    ldap.createUser(name, { invent: false });
  });
  const back = applications.createApplication({ identifier: 'wmsback',
    protocols: ['wstrust'],
    fields: { oauthClientId: 'wmsback', wstrustAppliesTo: [BACK] } });
  const svc = applications.createApplication({ identifier: 'wmssvc',
    protocols: ['wstrust'], fields: { oauthClientId: 'wmssvc' } });
  t.check(back && back.ok && svc && svc.ok,
          'precondition: the applications were created',
          JSON.stringify([back, svc]));

  const issued = {};
  const issueFor = async function (key, spec, realmId) {
    log.debug("Entering issueFor(). " + key);
    const r = await tlsClient.issue(realmId, Object.assign(
      { label: key, keyAlg: 'rsa-2048', purpose: 'message-signing' }, spec));
    t.check(r.ok, 'precondition: a certificate for ' + key,
            JSON.stringify(r.errors || ''));
    issued[key] = r.ok ? { certPem: r.issued.certificatePem,
                           keyPem: r.issued.privateKeyPem,
                           serialHex: r.issued.serialHex } : null;
    log.debug("Leaving issueFor().");
  };
  await issueFor('alice', { username: 'wmsalice' });
  await issueFor('alice2', { username: 'wmsalice' });
  await issueFor('carol', { username: 'wmscarol' });
  await issueFor('bob', { username: 'wmsbob' });
  await issueFor('svc', { kind: 'application', application: 'wmssvc' });
  await issueFor('tls', { username: 'wmsalice', purpose: 'tls-client' });
  await realms.run(realms.get(otherId), async function () {
    ldap.createUser('wmsalice', { invent: false });
    await issueFor('other', { username: 'wmsalice' }, otherId);
  });
  t.check(issued.alice && !/1\.3\.6\.1\.5\.5\.7\.3\.2/.test(String(
            new nodeCrypto.X509Certificate(issued.alice.certPem).keyUsage ||
            '')),
          'precondition: a message-signing certificate carries no clientAuth',
          issued.alice ? String(new nodeCrypto.X509Certificate(
            issued.alice.certPem).keyUsage) : '');

  // One request, through the endpoint's two halves: the asynchronous
  // revocation and replay answers (unless `unprepared`), then handleRst().
  const ask = async function (m, xml, opts) {
    log.debug("Entering ask(). " + m);
    const o = opts || {};
    config.setOverride('global.mode', m);
    try {
      const req = {};
      if (!o.unprepared) {
        const doc = new xmldom.DOMParser().parseFromString(xml, 'text/xml');
        await wstrust.prepareMessageSignature(req, doc);
      }
      log.debug("Leaving ask().");
      return wstrust.handleRst(xml, 'application/soap+xml', {
        base: BASE,
        connection: { socket: null, revocation: null,
                      signature: req.stsMessageSignature || null } });
    } finally {
      config.clearOverride('global.mode');
    }
  };
  const sign = function (key, opts) {
    log.debug("Entering sign(). " + key);
    log.debug("Leaving sign().");
    return signedRst(xmldsig, pki, Object.assign({}, issued[key], opts || {}));
  };
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return JSON.stringify({ status: r.status, errorCode: r.errorCode,
                            signIn: r.signIn,
                            body: String(r.body || '').slice(0, 700) });
  };
  const failed = function (r, code, fault) {
    log.debug("Entering failed().");
    log.debug("Leaving failed().");
    return r.status === 500 && r.errorCode === code && !r.signIn &&
      new RegExp('wst:' + (fault || 'FailedAuthentication'))
        .test(String(r.body));
  };

  // -------------------------------------------------------------------------
  // A. ISSUED SIGNING CERTIFICATES, IN PRODUCT
  // -------------------------------------------------------------------------
  let r = await ask('product', sign('alice'));
  t.check(r.status === 200 && />wmsalice</.test(r.body) &&
          /ac:classes:X509</.test(r.body),
          'A1. product: a signature by a person\'s message-signing ' +
          'certificate authenticates them; the SAML 2.0 assertion says X509',
          brief(r));
  t.check(r.signIn && r.signIn.username === 'wmsalice' &&
          JSON.stringify(r.signIn.amr) === '["swk"]',
          'A2. the session it starts is the person\'s, with amr swk',
          brief(r));
  r = await ask('product', sign('alice', { tokenType: SAML11_TYPE }));
  t.check(r.status === 200 && /AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:X509-PKI"/.test(r.body),
          'A3. a SAML 1.1 assertion says X509-PKI', brief(r));
  r = await ask('product', sign('alice', { tokenType: JWT_TYPE }));
  let claims = claimsOf(r.body);
  t.check(r.status === 200 && claims &&
          JSON.stringify(claims.amr) === '["swk"]' &&
          String(claims.sub) === String(helpers.subjectForName('wmsalice')),
          'A4. a JWT carries amr ["swk"] and the person\'s urn:uuid: subject',
          JSON.stringify(claims));
  for (const form of ['thumbprint', 'issuer-serial', 'ski']) {
    r = await ask('product', sign('alice2', { form: form }));
    t.check(r.status === 200 && />wmsalice</.test(r.body),
            'A5. the certificate named by ' + form + ', not carried, is ' +
            'found among the realm\'s issued ones', brief(r));
  }
  r = await ask('product', sign('svc', { tokenType: JWT_TYPE }));
  claims = claimsOf(r.body);
  t.check(r.status === 200 && claims && claims.client_id === 'wmssvc' &&
          /wmssvc$/.test(String(claims.sub)) && !r.signIn,
          'A6. an application\'s signing certificate is the application: ' +
          'its own token and no session', brief(r));

  // -------------------------------------------------------------------------
  // B. REPLAY
  // -------------------------------------------------------------------------
  const once = sign('alice');
  r = await ask('product', once);
  t.check(r.status === 200, 'B1. precondition: a signed request accepted',
          brief(r));
  r = await ask('product', once);
  t.check(failed(r, 'STS-WSTRUST-0050'),
          'B2. the same signed request again is a replay, STS-WSTRUST-0050',
          brief(r));
  r = await ask('product', sign('alice'), { unprepared: true });
  t.check(failed(r, 'STS-WSTRUST-0051', 'RequestFailed'),
          'B3. a signed request never checked against the history is ' +
          'refused, STS-WSTRUST-0051', brief(r));

  // -------------------------------------------------------------------------
  // C. THE SIGNATURE, AND WRAPPING
  // -------------------------------------------------------------------------
  r = await ask('product', sign('alice', { after: function (xml) {
    return xml.replace(BACK, 'https://elsewhere.example');
  } }));
  t.check(failed(r, 'STS-WSTRUST-0045'),
          'C1. a Body altered after signing is STS-WSTRUST-0045', brief(r));
  r = await ask('product', sign('alice', { signKeyPem: issued.bob.keyPem }));
  t.check(failed(r, 'STS-WSTRUST-0045'),
          'C2. a signature by a key that is not the named certificate\'s is ' +
          'STS-WSTRUST-0045', brief(r));
  r = await ask('product', sign('alice', {
    header: '<x:Smuggled xmlns:x="urn:x"><wst:RequestSecurityToken ' +
      'xmlns:wst="' + WST + '"><wst:RequestType>' + WST +
      '/Issue</wst:RequestType></wst:RequestSecurityToken></x:Smuggled>' }));
  t.check(failed(r, 'STS-WSTRUST-0046'),
          'C3. an unsigned RequestSecurityToken in a header, read first in ' +
          'document order, is STS-WSTRUST-0046', brief(r));
  r = await ask('product', sign('alice', { after: function (xml) {
    return xml.replace('<s:Header>', '<s:Header><x:Copy xmlns:x="urn:x" ' +
                       'wsu:Id="body"/>');
  } }));
  t.check(failed(r, 'STS-WSTRUST-0040'),
          'C4. the Body\'s id on a second element is STS-WSTRUST-0040',
          brief(r));
  r = await ask('product', sign('alice', { signTimestamp: false }));
  t.check(failed(r, 'STS-WSTRUST-0040', 'AuthenticationBadElements'),
          'C5. a signature over the Body and not the Timestamp is ' +
          'STS-WSTRUST-0040, wst:AuthenticationBadElements', brief(r));
  r = await ask('product', sign('alice', { sigAlg: RSA_SHA1 }));
  t.check(failed(r, 'STS-WSTRUST-0040'),
          'C6. SHA-1, with saml.allowSha1Signatures off, is STS-WSTRUST-0040',
          brief(r));

  // -------------------------------------------------------------------------
  // D. FRESHNESS
  // -------------------------------------------------------------------------
  r = await ask('product', sign('alice', { createdOffsetMs: -3600000,
                                           expiresOffsetMs: -1800000 }));
  t.check(failed(r, 'STS-WSTRUST-0048', 'ExpiredData'),
          'D1. an expired Timestamp is STS-WSTRUST-0048, wst:ExpiredData',
          brief(r));
  r = await ask('product', sign('alice', { createdOffsetMs: 3600000,
                                           expiresOffsetMs: 7200000 }));
  t.check(failed(r, 'STS-WSTRUST-0047'),
          'D2. a Timestamp Created an hour ahead is STS-WSTRUST-0047',
          brief(r));

  // -------------------------------------------------------------------------
  // E. THE CERTIFICATE
  // -------------------------------------------------------------------------
  r = await ask('product', sign('tls'));
  t.check(failed(r, 'STS-WSTRUST-0042'),
          'E1. a TLS client certificate of this realm signs nobody in: ' +
          'STS-WSTRUST-0042', brief(r));
  r = await ask('product', sign('other'));
  t.check(failed(r, 'STS-WSTRUST-0042'),
          'E2. another realm\'s message-signing certificate is ' +
          'STS-WSTRUST-0042', brief(r));
  r = await ask('product', sign('tls', { form: 'thumbprint' }));
  t.check(failed(r, 'STS-WSTRUST-0041'),
          'E3. a thumbprint naming no issued message-signing certificate is ' +
          'STS-WSTRUST-0041', brief(r));
  const revoked = tlsClient.revoke(undefined, 'wmsbob', issued.bob.serialHex,
                                   'keyCompromise', 'person',
                                   'message-signing');
  t.check(revoked.ok, 'precondition: bob\'s certificate is revoked',
          JSON.stringify(revoked.errors || ''));
  r = await ask('product', sign('bob'));
  t.check(failed(r, 'STS-WSTRUST-0049'),
          'E4. a revoked message-signing certificate is STS-WSTRUST-0049',
          brief(r));
  const off = accountState.setDisabled('wmscarol', true);
  t.check(off && off.ok !== false, 'precondition: wmscarol is disabled',
          JSON.stringify(off));
  r = await ask('product', sign('carol'));
  t.check(failed(r, 'STS-WSTRUST-0052'),
          'E5. a disabled person\'s signature is STS-WSTRUST-0052', brief(r));

  const outsideCa = require(ROOT + '/tests/tools/pep-credential.js');
  const outside = await outsideCa.mint({ subject: 'CN=wmsdave,O=Outside',
                                         crlBase: '' });
  const dave = { certPem: outside.leaf.pem, keyPem: outside.leaf.privateKeyPem };
  r = await ask('product', signedRst(xmldsig, pki, dave));
  t.check(failed(r, 'STS-WSTRUST-0043') && !/>wmsdave</.test(r.body),
          'E6. an outside certificate stored on no entry is ' +
          'STS-WSTRUST-0043, though its CN names a person', brief(r));
  const der = new nodeCrypto.X509Certificate(outside.leaf.pem).raw;
  const stored = ldap.changeStoredCertificate('person', 'wmsdave',
                                              { add: der });
  t.check(stored.ok, 'precondition: the certificate is stored on wmsdave',
          JSON.stringify(stored));
  config.setOverride('pki.revocationRequireDistributionPoint', 'off');
  try {
    r = await ask('product', signedRst(xmldsig, pki, dave));
  } finally {
    config.clearOverride('pki.revocationRequireDistributionPoint');
  }
  t.check(r.status === 200 && />wmsdave</.test(r.body),
          'E7. stored in wmsdave\'s userCertificate, it authenticates wmsdave',
          brief(r));
  config.setOverride('pki.revocationRequireDistributionPoint', 'on');
  config.setOverride('pki.revocationCheck', 'hard-fail');
  try {
    r = await ask('product', signedRst(xmldsig, pki, dave));
  } finally {
    config.clearOverride('pki.revocationRequireDistributionPoint');
    config.clearOverride('pki.revocationCheck');
  }
  t.check(failed(r, 'STS-WSTRUST-0049'),
          'E8. revocation is consulted for a stored certificate: one whose ' +
          'issuer names no list, under a policy that wants one, is ' +
          'STS-WSTRUST-0049', brief(r));
  ldap.changeStoredCertificate('person', 'wmsbob', { add: der });
  r = await ask('product', signedRst(xmldsig, pki, dave));
  t.check(failed(r, 'STS-WSTRUST-0044'),
          'E9. stored on two entries it names nobody: STS-WSTRUST-0044',
          brief(r));

  // -------------------------------------------------------------------------
  // F. PRECEDENCE
  // -------------------------------------------------------------------------
  const token = function (name) {
    log.debug("Entering token().");
    log.debug("Leaving token().");
    return '<wsse:UsernameToken><wsse:Username>' + name +
      '</wsse:Username><wsse:Password>anything</wsse:Password>' +
      '</wsse:UsernameToken>';
  };
  r = await ask('development', sign('alice', { security: token('wmsalice') }));
  t.check(r.status === 200 && />wmsalice</.test(r.body) &&
          /ac:classes:X509</.test(r.body),
          'F1. a UsernameToken naming the signer beside the signature: the ' +
          'signature authenticates', brief(r));
  r = await ask('development', sign('alice', { security: token('wmsbob') }));
  t.check(failed(r, 'STS-WSTRUST-0053'),
          'F2. a UsernameToken naming somebody else is STS-WSTRUST-0053, in ' +
          'development too', brief(r));

  // -------------------------------------------------------------------------
  // G. DEVELOPMENT
  // -------------------------------------------------------------------------
  r = await ask('development', sign('alice', { after: function (xml) {
    return xml.replace(BACK, BACK + '/');
  } }));
  t.check(r.status === 200 && />wmsalice</.test(r.body),
          'G1. development believes the certificate: an altered Body is ' +
          'issued for its holder', brief(r));
  r = await ask('development', sign('alice', { inner:
    '<wst14:ActAs xmlns:wst14="' + WST14 + '"><saml:Assertion xmlns:saml=' +
    '"urn:oasis:names:tc:SAML:2.0:assertion" ID="_wms" Version="2.0">' +
    '<saml:Subject><saml:NameID>wmsbob</saml:NameID></saml:Subject>' +
    '</saml:Assertion></wst14:ActAs>' }));
  t.check(r.status === 200 && />wmsbob</.test(r.body) && !r.signIn,
          'G2. a signed ActAs is a token about its subject, and signs nobody ' +
          'in', brief(r));

  // -------------------------------------------------------------------------
  // H. THE ENDPOINT
  // -------------------------------------------------------------------------
  config.setOverride('global.mode', 'product');
  const server = http.createServer(app);
  await new Promise(function (done) {
    server.listen(0, '127.0.0.1', done);
  });
  try {
    const post = function (body) {
      log.debug("Entering post().");
      log.debug("Leaving post().");
      return new Promise(function (resolve, reject) {
        const req = http.request({
          host: '127.0.0.1', port: server.address().port, path: '/sts',
          method: 'POST',
          headers: { 'content-type': 'application/soap+xml' } },
        function (res) {
          let text = '';
          res.on('data', function (chunk) {
            text += chunk;
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, body: text });
          });
        });
        req.on('error', reject);
        req.end(body);
      });
    };
    const over = sign('alice');
    let got = await post(over);
    t.check(got.status === 200 && />wmsalice</.test(got.body),
            'H1. over HTTP, the endpoint issues for a signed request',
            got.status + ' ' + got.body.slice(0, 500));
    got = await post(over);
    t.check(got.status === 500 && /FailedAuthentication/.test(got.body),
            'H2. and refuses the same request sent again',
            got.status + ' ' + got.body.slice(0, 500));
  } finally {
    server.close();
    config.clearOverride('global.mode');
  }
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
  clean.STS_HTTPS = 'false';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
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
  name: 'wstrust_message_signature',
  describe: 'WS-Trust: a WS-Security signature over the Body and Timestamp ' +
            'authenticates the requester its certificate maps to, and is ' +
            'refused when it does not verify, is wrapped, stale, replayed, ' +
            'revoked or nobody\'s (#521)',
  run: run
};
