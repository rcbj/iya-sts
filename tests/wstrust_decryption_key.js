// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_decryption_key.js
//
// ===========================================================================
// AN APPLICATION'S OWN WS-TRUST DECRYPTION KEY PAIR (#1668, rcbj's request
// of 2026-11-19).
//
// `ws-trust/ws_decryption_key.ts` issues an application a key pair from the
// realm's CA, or stores one uploaded, and `ws-trust/ws_encryption.ts`
// decrypts a request for it with that key, chosen by the recipient the
// EncryptedKey names. This file holds:
//
//   G. GENERATION: `issue-wstrust-decryption-key` writes a leaf whose
//      subject is exactly `CN=<identifier>-encrypt` and the realm's
//      organisation, issued and signed by the realm's Issuing CA, keyUsage
//      keyEncipherment alone (RSA) or keyAgreement alone (EC), the
//      `urn:sts:application:` name; audited; an unknown key type is
//      STS-ADMIN-0945 and an unknown application STS-ADMIN-0950.
//   S. STORAGE: no answer, view, drawn page, audit row or log line carries
//      the private key; where keys persist it is sealed on the entry and
//      opens for the decryption.
//   D. DECRYPTION: a wholly encrypted request (the AppliesTo inside the
//      ciphertext) opens with the application's key, its EncryptedKey
//      naming the certificate inline, by #ThumbprintSHA1, by Subject Key
//      Identifier or by issuer and serial; the realm's key for an
//      application with its own is STS-WSTRUST-0083; the application's key
//      for another application's request is STS-WSTRUST-0082; another
//      application keeps the realm's key; removed, the realm's key opens
//      again and the old one opens nothing (0075).
//   U. UPLOAD: not one certificate, an encrypted or unreadable key
//      (STS-ADMIN-0946), a key that is not the certificate's (0947), RSA of
//      1024 bits (0948), a keyUsage of digitalSignature only or an expired
//      certificate (0949), a certificate another application holds (0950);
//      an RSA certificate with no keyUsage and an EC pair are stored.
//   C. THE CONSOLE: the Credentials tab draws the certificate, its
//      download and the three forms, or no form without Admin Write.
//
// IN A CHILD PROCESS, for `wstrust_message_signature.js`'s reason: it loads
// the stack and builds a certificate authority, both process state that
// `run.js` shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_WSTRUST_DECRYPTION_KEY_CHILD';
const MARK = 'WSTRUST-DECRYPTION-KEY-CHILD ';

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const WSSE = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-secext-1.0.xsd';
const WSU = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-utility-1.0.xsd';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const DSNS = 'http://www.w3.org/2000/09/xmldsig#';
const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
const THUMBPRINT = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-soap-message-security-1.1#ThumbprintSHA1';
const SKI = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
const BASE64 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const APP = 'wdkback';
const OTHER = 'wdkother';
const THIRD = 'wdkthird';
const BACK = 'https://wdk-back.example';
const OTHER_URL = 'https://wdk-other.example';
const BASE = 'https://sts.example';
// A PEM private key's armour followed by its base64, raw or in JSON.
const KEY_MATERIAL = /PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/]{16}/;

const log = require('bunyan').createLogger({
  name: 'wstrust_decryption_key',
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

// A development-mode RST for `appliesTo`, authenticated by a UsernameToken.
function envelope(appliesTo, who) {
  log.debug("Entering envelope().");
  log.debug("Leaving envelope().");
  return '<s:Envelope xmlns:s="' + SOAP12 + '" xmlns:wsse="' + WSSE +
    '" xmlns:wsu="' + WSU + '"><s:Header><wsse:Security>' +
    '<wsse:UsernameToken><wsse:Username>' + who + '</wsse:Username>' +
    '<wsse:Password>x</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security></s:Header><s:Body>' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '" Context="urn:uuid:' +
    nodeCrypto.randomUUID() + '">' +
    '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
    '08/addressing"><wsa:Address>' + appliesTo + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

// What a recipient form puts in an EncryptedKey's KeyInfo in place of the
// certificate `crypto.encryptElement()` writes.
function recipientFor(form, certPem, pkiModule) {
  log.debug("Entering recipientFor(). " + form);
  const x509 = new nodeCrypto.X509Certificate(certPem);
  if (form === 'thumbprint') {
    log.debug("Leaving recipientFor().");
    return '<wsse:SecurityTokenReference><wsse:KeyIdentifier ValueType="' +
      THUMBPRINT + '" EncodingType="' + BASE64 + '">' +
      nodeCrypto.createHash('sha1').update(x509.raw).digest('base64') +
      '</wsse:KeyIdentifier></wsse:SecurityTokenReference>';
  }
  if (form === 'ski') {
    const hex = pkiModule.pathFactsOf(pkiModule.certificateFromDer(x509.raw))
      .keyIdentifier;
    log.debug("Leaving recipientFor().");
    return '<wsse:SecurityTokenReference><wsse:KeyIdentifier ValueType="' +
      SKI + '" EncodingType="' + BASE64 + '">' +
      Buffer.from(hex, 'hex').toString('base64') +
      '</wsse:KeyIdentifier></wsse:SecurityTokenReference>';
  }
  log.debug("Leaving recipientFor(). Issuer and serial.");
  return '<wsse:SecurityTokenReference><ds:X509Data xmlns:ds="' + DSNS +
    '"><ds:X509IssuerSerial><ds:X509IssuerName>' +
    x509.issuer.split('\n').reverse().join(', ') + '</ds:X509IssuerName>' +
    '<ds:X509SerialNumber>' + BigInt('0x' + x509.serialNumber).toString() +
    '</ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data>' +
    '</wsse:SecurityTokenReference>';
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  require(ROOT + '/common/i18n');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const config = require(ROOT + '/common/config');
  const audit = require(ROOT + '/common/audit');
  const errorCodes = require(ROOT + '/common/error_codes');
  const applications = require(ROOT + '/common/applications');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const adminViews = require(ROOT + '/admin-core/admin_views');
  const page = require(ROOT + '/admin-ui/web_applications');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const stsCrypto = require(ROOT + '/common/crypto');
  const xmldom = require('@xmldom/xmldom');
  const wstrustModule = require(ROOT + '/ws-trust/wstrust');
  const wstrust = new wstrustModule.WsTrust(
    wstrustModule.WsTrust.defaultDeps());

  await keystore.start();
  await pki.start({ realmIds: [''],
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

  ldap.createUser('wdkalice', { invent: false });
  const made = [
    applications.createApplication({ identifier: APP,
      protocols: ['wstrust'],
      fields: { oauthClientId: APP, wstrustAppliesTo: [BACK] } }),
    applications.createApplication({ identifier: OTHER,
      protocols: ['wstrust'],
      fields: { oauthClientId: OTHER, wstrustAppliesTo: [OTHER_URL] } }),
    applications.createApplication({ identifier: THIRD,
      protocols: ['wstrust'], fields: { oauthClientId: THIRD } })];
  // Ciphertext anywhere is accepted, so the request map is not the
  // question here (`wstrust_message_signature.js` J holds it).
  [APP, OTHER].forEach(function (id) {
    made.push(applications.updateApplication(id, { mode: 'set',
      attribute: 'wstrustAcceptEncryptedElements', value: 'TRUE' }));
  });
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the applications exist and accept ciphertext',
          JSON.stringify(made));

  const ctx = { actor: 'wdktester', via: 'test' };
  const act = function (body) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return adminActions.applicationsAction(body, [], ctx);
  };
  const audited = function (action, target) {
    log.debug("Entering audited(). " + action);
    log.debug("Leaving audited().");
    return audit.list().filter(function (row) {
      return row && row.action === action && row.target === target;
    });
  };
  const noKey = function (value) {
    log.debug("Entering noKey().");
    log.debug("Leaving noKey().");
    // KEY MATERIAL, not the words: a form's placeholder names a PEM.
    return !KEY_MATERIAL.test(typeof value === 'string' ? value
      : JSON.stringify(value === undefined ? null : value));
  };

  // -------------------------------------------------------------------------
  // G. GENERATION
  // -------------------------------------------------------------------------
  // SEALED WHERE KEYS PERSIST: the stand-in seals for the length of the
  // issue, as `certificate_listing_bounds.js` does, and opens what it sealed.
  const realPersists = keystore.persists;
  const realSeal = keystore.seal;
  const realOpen = keystore.open;
  const sealedWith = [];
  keystore.persists = function () {
    return true;
  };
  keystore.seal = function (plain, label) {
    sealedWith.push({ label: label, pem: /PRIVATE KEY/.test(String(plain)) });
    return '$aesgcm$' + Buffer.from(String(plain)).toString('base64');
  };
  keystore.open = function (text, label) {
    const value = String(text || '');
    return value.indexOf('$aesgcm$') === 0
      ? Buffer.from(value.slice(8), 'base64').toString()
      : realOpen.call(keystore, text, label);
  };
  let issued;
  try {
    issued = await act({ action: 'issue-wstrust-decryption-key',
                         application: APP });
  } finally {
    keystore.persists = realPersists;
    keystore.seal = realSeal;
  }
  const state = (issued && issued.wstrustDecryption) || {};
  t.check(issued && issued.ok && state.held && state.source === 'issued' &&
          /BEGIN CERTIFICATE/.test(state.certificatePem || ''),
          'G1. issue-wstrust-decryption-key gives the application a key ' +
          'pair, source issued, and answers its certificate',
          JSON.stringify(issued));
  const leaf = new nodeCrypto.X509Certificate(state.certificatePem);
  const lines = leaf.subject.split('\n');
  const issuerCert = new nodeCrypto.X509Certificate(
    String((state.chain || [])[0] ? pki.chainPemFor('')[0] : ''));
  const organisation = issuerCert.subject.split('\n').filter(function (one) {
    return one.indexOf('O=') === 0;
  });
  t.check(lines[0] === 'CN=' + APP + '-encrypt' &&
          lines.filter(function (one) {
            return one.indexOf('O=') === 0;
          }).join() === organisation.join() && organisation.length === 1 &&
          lines.every(function (one) {
            return /^(CN|O|C)=/.test(one);
          }),
          'G2. its subject is exactly CN=' + APP + '-encrypt with the ' +
          'realm\'s organisation, as every leaf of the realm is named',
          leaf.subject);
  t.check(leaf.issuer === issuerCert.subject &&
          leaf.verify(issuerCert.publicKey) &&
          state.chain.length >= 1 &&
          state.chain[0].subject === issuerCert.subject.split('\n')
            .join(', '),
          'G3. it is issued and signed by the realm\'s Issuing CA, whose ' +
          'certificate is the chain\'s first',
          leaf.issuer + ' / ' + JSON.stringify(state.chain));
  const facts = stsCrypto.certificateFacts(leaf);
  t.check(JSON.stringify(facts.keyUsage) === '["keyEncipherment"]' &&
          facts.keyAlg === 'rsa' && facts.keyBits === 3072 &&
          facts.san.uri.indexOf('urn:sts:application:' + APP) >= 0 &&
          state.certificate.keyDetail === 'RSA 3072',
          'G4. the key-encipherment profile: an RSA 3072 key, keyUsage ' +
          'keyEncipherment alone, named urn:sts:application:' + APP,
          JSON.stringify(facts));
  t.check(audited('wstrust.decryption-key.issue', APP).some(function (row) {
    return row.actor === 'wdktester' && noKey(row);
  }), 'G5. the issue is audited wstrust.decryption-key.issue, naming the ' +
      'actor, and the row carries no key');
  const ec = await act({ action: 'issue-wstrust-decryption-key',
                         application: THIRD, keyAlg: 'ec-p256' });
  const ecFacts = ec && ec.ok ? stsCrypto.certificateFacts(
    ec.wstrustDecryption.certificatePem) : {};
  t.check(ec && ec.ok && JSON.stringify(ecFacts.keyUsage) ===
            '["keyAgreement"]' && ecFacts.curve === 'prime256v1',
          'G6. an ec-p256 key pair carries keyAgreement alone',
          JSON.stringify([ec, ecFacts]));
  const badAlg = await act({ action: 'issue-wstrust-decryption-key',
                             application: APP, keyAlg: 'ed25519' });
  t.check(!badAlg.ok && errorCodes.codeOf(badAlg) === 'STS-ADMIN-0945' &&
          applications.wstrustDecryptionKeyOf(APP).certificate ===
            state.certificatePem,
          'G7. a key type other than rsa-3072 or ec-p256 is ' +
          'STS-ADMIN-0945, and the key pair held is kept',
          JSON.stringify(badAlg));
  const nobody = await act({ action: 'issue-wstrust-decryption-key',
                             application: 'wdknobody' });
  t.check(!nobody.ok && errorCodes.codeOf(nobody) === 'STS-ADMIN-0950' &&
          !applications.get('wdknobody'),
          'G8. an application the registry does not hold is ' +
          'STS-ADMIN-0950, and none is made', JSON.stringify(nobody));

  // -------------------------------------------------------------------------
  // S. STORAGE
  // -------------------------------------------------------------------------
  const kept = applications.wstrustDecryptionKeyFacts(APP);
  t.check(sealedWith.some(function (one) {
    return one.pem && one.label === 'wstrust-decryption-key';
  }) && kept.held && kept.privateKeyHeld && kept.sealed &&
          state.sealedAtRest === true,
          'S1. where keys persist the private key is sealed on the entry, ' +
          'under the wstrust-decryption-key label',
          JSON.stringify([kept, sealedWith]));
  const opened = applications.wstrustDecryptionKeyOf(APP);
  t.check(opened && /PRIVATE KEY/.test(opened.privateKey) &&
          new nodeCrypto.X509Certificate(state.certificatePem)
            .checkPrivateKey(nodeCrypto.createPrivateKey(opened.privateKey)),
          'S2. it opens, for the decryption, to the certificate\'s ' +
          'private half');
  const view = applications.get(APP);
  t.check(noKey(issued) && noKey(view) &&
          /withheld/.test(String(view.fields.wstrustDecryptionPrivateKey)),
          'S3. neither the answer nor the registry\'s view carries the ' +
          'private key; the view says it is withheld',
          String(view.fields.wstrustDecryptionPrivateKey));
  const json = adminViews.applicationsJson({
    query: { application: APP }, headers: { host: '127.0.0.1' },
    protocol: 'http',
    get: function () {
      return '';
    } });
  const listed = ((json.credentials || {}).wstrustDecryption) || {};
  t.check(listed.held && listed.certificatePem === state.certificatePem &&
          listed.certificate.thumbprintSha1 ===
            nodeCrypto.createHash('sha1').update(leaf.raw).digest('base64') &&
          noKey(json),
          'S4. credentials.wstrustDecryption of GET /admin-api/applications' +
          '?application= gives the certificate and its #ThumbprintSHA1, ' +
          'and the answer carries no private key', JSON.stringify(listed));

  // -------------------------------------------------------------------------
  // D. DECRYPTION
  // -------------------------------------------------------------------------
  const ask = async function (xml) {
    log.debug("Entering ask().");
    config.setOverride('global.mode', 'development');
    try {
      log.debug("Leaving ask().");
      return await wstrust.handleRst(xml, 'application/soap+xml', {
        base: BASE,
        connection: { socket: null, revocation: null, signature: null } });
    } finally {
      config.clearOverride('global.mode');
    }
  };
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return JSON.stringify({ status: r.status, errorCode: r.errorCode,
                            body: String(r.body || '').slice(0, 600) });
  };
  const parseX = function (xml) {
    log.debug("Entering parseX().");
    log.debug("Leaving parseX().");
    return new xmldom.DOMParser().parseFromString(String(xml), 'text/xml');
  };
  const serial = function (node) {
    log.debug("Entering serial().");
    log.debug("Leaving serial().");
    return new xmldom.XMLSerializer().serializeToString(node);
  };
  // The whole RequestSecurityToken encrypted (the Body's content), to
  // `certPem`. `form` '' keeps the certificate `encryptElement()` writes
  // inside the EncryptedData's own key; any other form moves the
  // EncryptedKey to the security header, WSS4J's way, naming its recipient
  // so.
  const sealedBody = function (xml, certPem, form) {
    log.debug("Entering sealedBody(). " + (form || 'inline'));
    const doc = parseX(xml);
    const body = doc.getElementsByTagNameNS(SOAP12, 'Body')[0];
    let plain = '';
    for (let i = 0; i < body.childNodes.length; i++) {
      plain += serial(body.childNodes[i]);
    }
    const data = parseX(stsCrypto.encryptElement(plain, certPem,
      { bare: true, algorithm: 'aes256-gcm', keyTransport: 'rsa-oaep' }))
      .documentElement;
    data.setAttribute('Type', XENC + 'Content');
    data.setAttribute('Id', 'ED-body');
    while (body.firstChild) {
      body.removeChild(body.firstChild);
    }
    if (form) {
      const keyInfo = data.getElementsByTagNameNS(DSNS, 'KeyInfo')[0];
      const key = keyInfo.getElementsByTagNameNS(XENC, 'EncryptedKey')[0];
      keyInfo.removeChild(key);
      key.setAttribute('Id', 'EK-body');
      const ownInfo = key.getElementsByTagNameNS(DSNS, 'KeyInfo')[0];
      while (ownInfo.firstChild) {
        ownInfo.removeChild(ownInfo.firstChild);
      }
      ownInfo.appendChild(key.ownerDocument.importNode(parseX(
        '<w xmlns:wsse="' + WSSE + '">' + recipientFor(form, certPem, pki) +
        '</w>').documentElement.firstChild, true));
      const list = key.ownerDocument.createElementNS(XENC,
                                                     'xenc:ReferenceList');
      const ref = key.ownerDocument.createElementNS(XENC,
                                                    'xenc:DataReference');
      ref.setAttribute('URI', '#ED-body');
      list.appendChild(ref);
      key.appendChild(list);
      const security = doc.getElementsByTagNameNS(WSSE, 'Security')[0];
      security.insertBefore(doc.importNode(key, true), security.firstChild);
    }
    body.appendChild(doc.importNode(data, true));
    log.debug("Leaving sealedBody().");
    return serial(doc);
  };
  const issuedTo = function (r) {
    log.debug("Entering issuedTo().");
    log.debug("Leaving issuedTo().");
    return r.status === 200 && />wdkalice</.test(String(r.body));
  };
  const refused = function (r, code) {
    log.debug("Entering refused(). " + code);
    log.debug("Leaving refused().");
    return r.status === 500 && r.errorCode === code &&
      /FailedCheck/.test(String(r.body));
  };
  const appPem = state.certificatePem;
  const realmPem = helpers.STS.xml.certPem;
  let r = await ask(sealedBody(envelope(BACK, 'wdkalice'), appPem, ''));
  t.check(issuedTo(r),
          'D1. a wholly encrypted request (its AppliesTo inside the ' +
          'ciphertext) whose EncryptedKey carries the application\'s ' +
          'certificate opens with the application\'s key', brief(r));
  const forms = ['thumbprint', 'ski', 'issuer-serial'];
  for (let i = 0; i < forms.length; i++) {
    r = await ask(sealedBody(envelope(BACK, 'wdkalice'), appPem, forms[i]));
    t.check(issuedTo(r),
            'D2. the key in the security header naming its recipient by ' +
            forms[i] + ' opens with the application\'s key', brief(r));
  }
  r = await ask(sealedBody(envelope(BACK, 'wdkalice'), realmPem,
                           'thumbprint'));
  t.check(refused(r, 'STS-WSTRUST-0083'),
          'D3. a request for the application encrypted to the realm\'s key ' +
          'is STS-WSTRUST-0083, wsse:FailedCheck', brief(r));
  r = await ask(sealedBody(envelope(BACK, 'wdkalice'), realmPem, ''));
  t.check(refused(r, 'STS-WSTRUST-0083'),
          'D3. the same with the realm\'s certificate inline', brief(r));
  r = await ask(sealedBody(envelope(OTHER_URL, 'wdkalice'), appPem, ''));
  t.check(refused(r, 'STS-WSTRUST-0082') && !/>wdkalice</.test(r.body),
          'D4. another application\'s request encrypted to this ' +
          'application\'s key is STS-WSTRUST-0082: the key that opened it ' +
          'does not choose whose it is', brief(r));
  r = await ask(sealedBody(envelope(OTHER_URL, 'wdkalice'), realmPem, ''));
  t.check(issuedTo(r),
          'D5. an application without a key of its own still opens with ' +
          'the realm\'s key', brief(r));

  // -------------------------------------------------------------------------
  // C. THE CONSOLE
  // -------------------------------------------------------------------------
  const tabOf = function (write) {
    log.debug("Entering tabOf().");
    const html = page.detail(kit.context({ application: APP }, write), json);
    const at = html.indexOf('id="credentials-wstrust-decryption"');
    log.debug("Leaving tabOf().");
    return at < 0 ? '' : html.slice(at, at + 12000);
  };
  const drawn = tabOf(true);
  t.check(drawn.indexOf('WS-Trust decryption key pair') >= 0 &&
          drawn.indexOf(listed.certificate.thumbprint) >= 0 &&
          drawn.indexOf('data:application/x-pem-file;base64,') >= 0 &&
          drawn.indexOf('value="issue-wstrust-decryption-key"') >= 0 &&
          drawn.indexOf('value="upload-wstrust-decryption-key"') >= 0 &&
          drawn.indexOf('value="remove-wstrust-decryption-key"') >= 0 &&
          drawn.indexOf('name="privateKey"') >= 0 && noKey(drawn),
          'C1. the Credentials tab draws the certificate, its thumbprints ' +
          'and download, and the issue, upload and remove forms',
          drawn.slice(0, 800));
  const readOnly = tabOf(false);
  t.check(readOnly.indexOf(listed.certificate.thumbprint) >= 0 &&
          readOnly.indexOf('wstrust-decryption-key"') < 0 &&
          readOnly.indexOf('Admin Write') >= 0,
          'C2. without Admin Write it is drawn with no form',
          readOnly.slice(0, 800));

  // -------------------------------------------------------------------------
  // U. UPLOAD
  // -------------------------------------------------------------------------
  const upload = function (application, certificate, privateKey) {
    log.debug("Entering upload().");
    log.debug("Leaving upload().");
    return act({ action: 'upload-wstrust-decryption-key',
                 application: application, certificate: certificate,
                 privateKey: privateKey });
  };
  const good = stsCrypto.selfSignedRsaCertificate({ commonName: 'wdk-up' });
  const other = stsCrypto.selfSignedRsaCertificate({ commonName: 'wdk-x' });
  const weak = stsCrypto.selfSignedRsaCertificate({ commonName: 'wdk-weak',
                                                    bits: 1024 });
  const signing = stsCrypto.selfSignedRsaCertificate({
    commonName: 'wdk-sign',
    extensions: [{ name: 'keyUsage', digitalSignature: true }] });
  const expired = stsCrypto.selfSignedRsaCertificate({
    commonName: 'wdk-old', years: -1 });
  const encryptedKey = nodeCrypto.createPrivateKey(good.privateKeyPem)
    .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc',
              passphrase: 'wdk-passphrase' });
  const cases = [
    ['U1', 'not a certificate', 'STS-ADMIN-0946',
     upload(OTHER, 'not a certificate', good.privateKeyPem)],
    ['U2', 'two certificates', 'STS-ADMIN-0946',
     upload(OTHER, good.certPem + other.certPem, good.privateKeyPem)],
    ['U3', 'an encrypted private key', 'STS-ADMIN-0946',
     upload(OTHER, good.certPem, encryptedKey)],
    ['U3', 'a private key that does not parse', 'STS-ADMIN-0946',
     upload(OTHER, good.certPem, '-----BEGIN PRIVATE KEY-----\nAAAA\n' +
            '-----END PRIVATE KEY-----')],
    ['U4', 'a key that is not the certificate\'s', 'STS-ADMIN-0947',
     upload(OTHER, good.certPem, other.privateKeyPem)],
    ['U5', 'an RSA key of 1024 bits', 'STS-ADMIN-0948',
     upload(OTHER, weak.certPem, weak.privateKeyPem)],
    ['U6', 'a keyUsage of digitalSignature only', 'STS-ADMIN-0949',
     upload(OTHER, signing.certPem, signing.privateKeyPem)],
    ['U7', 'an expired certificate', 'STS-ADMIN-0949',
     upload(OTHER, expired.certPem, expired.privateKeyPem)],
    ['U8', 'the certificate another application holds', 'STS-ADMIN-0950',
     upload(OTHER, appPem, opened.privateKey)]
  ];
  cases.forEach(function (one) {
    t.check(!one[3].ok && errorCodes.codeOf(one[3]) === one[2] &&
            noKey(one[3]),
            one[0] + '. ' + one[1] + ' is ' + one[2] + ', and the refusal ' +
            'carries no key', JSON.stringify(one[3]));
  });
  t.check(!applications.wstrustDecryptionKeyFacts(OTHER).held,
          'U9. no refused upload wrote anything');
  const stored = upload(OTHER, good.certPem, good.privateKeyPem);
  t.check(stored.ok && stored.wstrustDecryption.source === 'uploaded' &&
          stored.wstrustDecryption.certificatePem.indexOf(
            good.certPem.trim()) === 0 && noKey(stored) &&
          audited('wstrust.decryption-key.upload', OTHER).length === 1,
          'U10. an RSA 2048 certificate with no keyUsage and its key are ' +
          'stored, source uploaded, audited', JSON.stringify(stored));
  r = await ask(sealedBody(envelope(OTHER_URL, 'wdkalice'), good.certPem,
                           'issuer-serial'));
  t.check(issuedTo(r),
          'U11. a request for it encrypted to the uploaded certificate ' +
          'opens with the uploaded key', brief(r));
  const ecPair = await pki.issueEncryptionKeyPair(undefined, {
    identifier: 'wdk-ec', keyAlg: 'ec-p256' });
  const ecStored = upload(THIRD, ecPair.issued.certificatePem,
                          ecPair.issued.privateKeyPem);
  t.check(ecStored.ok && ecStored.wstrustDecryption.certificate.keyDetail ===
            'EC P-256',
          'U12. an EC P-256 pair with keyAgreement is stored',
          JSON.stringify(ecStored));

  // -------------------------------------------------------------------------
  // D, REMOVED
  // -------------------------------------------------------------------------
  const removed = act({ action: 'remove-wstrust-decryption-key',
                        application: APP });
  t.check(removed.ok && !removed.wstrustDecryption.held &&
          !applications.wstrustDecryptionKeyFacts(APP).privateKeyHeld &&
          audited('wstrust.decryption-key.remove', APP).length === 1,
          'D6. remove-wstrust-decryption-key takes all of it off, audited',
          JSON.stringify(removed));
  const again = act({ action: 'remove-wstrust-decryption-key',
                      application: APP });
  t.check(!again.ok && errorCodes.codeOf(again) === 'STS-ADMIN-0950',
          'D6. removing it again is STS-ADMIN-0950', JSON.stringify(again));
  r = await ask(sealedBody(envelope(BACK, 'wdkalice'), realmPem, ''));
  t.check(issuedTo(r),
          'D7. removed, a request for the application opens with the ' +
          'realm\'s key again', brief(r));
  r = await ask(sealedBody(envelope(BACK, 'wdkalice'), appPem,
                           'thumbprint'));
  t.check(refused(r, 'STS-WSTRUST-0075'),
          'D8. and one encrypted to the removed key opens with nothing, ' +
          'STS-WSTRUST-0075', brief(r));

  keystore.open = realOpen;
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
  // At info, so what is logged can be read for a private key (S5); the
  // per-function debug lines are not wanted.
  clean.LOG_LEVEL = 'info';
  clean.STS_LOG_LEVEL = 'info';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 256 * 1024 * 1024
  });
  const out = String(result.stdout || '');
  const line = out.split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  const logged = out.split('\n').filter(function (one) {
    return one.indexOf(MARK) !== 0;
  }).join('\n') + String(result.stderr || '');
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)), logged: logged };
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
  t.check(got.logged.length > 0 && !KEY_MATERIAL.test(got.logged),
          'S5. nothing the child logged carries a private key',
          String(got.logged.length));
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
  name: 'wstrust_decryption_key',
  describe: 'An application\'s own WS-Trust decryption key pair (#1668): ' +
            'issued from the realm\'s CA with its DN and profile, uploaded ' +
            'with every refusal, sealed and never answered or logged, and ' +
            'chosen by the EncryptedKey\'s recipient to open a request — ' +
            'the realm\'s key refused for an application with its own, ' +
            'and its key refused for another application\'s request',
  run: run
};
