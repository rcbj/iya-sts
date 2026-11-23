// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_message_integrity.js
//
// ===========================================================================
// WS-SECURITY MESSAGE INTEGRITY, PER APPLICATION (#1917, with #1918's
// response signing).
//
// An application may require a WS-Trust request signed and name what its
// signature must cover, and may have its answers signed with the realm's XML
// signing key, in either order with #1668's encryption, the signature
// encrypted too. Requests are signed here with keys made at run time, and
// every signed answer is verified with `crypto.verifyWsSecuritySignature()`
// against the certificate its BinarySecurityToken carries. Asserted:
//
//   K. the request: off by default; on, an unsigned request is
//      STS-WSTRUST-0084 (wsse:FailedCheck); a signed one passes with no map
//      (the Body); the Header preset holds every header block but the
//      security header to the signature (0085 until the sender signs it);
//      an expression that matches nothing is 0085; product as development;
//   L. the response: off by default; on, a Timestamp, a BinarySecurityToken
//      and a signature over both and the Body that verifies, in development
//      and product, on Issue and on Validate; a map that matches nothing,
//      or selects the security header itself, is STS-WSTRUST-0086 and
//      nothing is signed or sent;
//   M. with encryption: sign-then-encrypt (the keys first in the header,
//      the signature over the plaintext), encrypt-then-sign (the signature
//      first, over the ciphertext), and the signature encrypted too;
//   N. the presets: the Header expression selects every header block but
//      wsse:Security, under both SOAP versions, and not() is in the subset;
//   O. the WSDL: sp:IncludeTimestamp, sp:EncryptBeforeSigning and
//      sp:EncryptSignature in the binding follow the realm's settings, and
//      ResponseProtection offers signing while answers are signed.
//
// IN A CHILD PROCESS, for `wstrust_message_signature.js`'s reason: it loads
// the stack and builds a certificate authority, both process state `run.js`
// shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_WSTRUST_MESSAGE_INTEGRITY_CHILD';
const MARK = 'WSTRUST-INTEGRITY-CHILD ';

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const WSSE = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-secext-1.0.xsd';
const WSU = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-utility-1.0.xsd';
const WSA = 'http://www.w3.org/2005/08/addressing';
const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509v3';
const BASE64 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const BACK = 'https://wmi-back.example';
const BASE = 'https://sts.example';

const log = require('bunyan').createLogger({
  name: 'wstrust_message_integrity',
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

// An RST, unsigned, with the ids a signer references, and an optional
// WS-Addressing Action header carrying `wsa`.
function envelope(opts) {
  log.debug("Entering envelope().");
  const now = Date.now();
  const certB64 = opts.certPem ? String(opts.certPem)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') : '';
  log.debug("Leaving envelope().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '"><s:Header>' +
    (opts.wsa ? '<wsa:Action xmlns:wsa="' + WSA + '" wsu:Id="wsa">' + WST +
      '/RST/Issue</wsa:Action>' : '') +
    '<wsse:Security>' +
    '<wsu:Timestamp wsu:Id="ts"><wsu:Created>' +
    new Date(now).toISOString() + '</wsu:Created><wsu:Expires>' +
    new Date(now + 300000).toISOString() + '</wsu:Expires>' +
    '</wsu:Timestamp>' +
    (certB64 ? '<wsse:BinarySecurityToken wsu:Id="x509" ValueType="' +
      X509V3 + '" EncodingType="' + BASE64 + '">' + certB64 +
      '</wsse:BinarySecurityToken>' : '') +
    '</wsse:Security></s:Header>' +
    '<s:Body wsu:Id="body">' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '" Context="urn:uuid:' +
    nodeCrypto.randomUUID() + '">' +
    '<wst:RequestType>' + WST + '/' + (opts.op || 'Issue') +
    '</wst:RequestType>' + (opts.inner || '') +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="' + WSA + '"><wsa:Address>' +
    BACK + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

// A signed RST: the engine's WS-Security signer over the Body, the
// Timestamp and any `signIds`, its KeyInfo a Reference to the token.
function signedRst(xmldsig, opts) {
  log.debug("Entering signedRst().");
  let signed = xmldsig.signWsSecurity(envelope(opts), {
    privateKeyPem: opts.keyPem, certPem: opts.certPem,
    signTimestamp: true, signIds: opts.signIds || undefined });
  signed = signed.replace(/<ds:KeyInfo>[\s\S]*?<\/ds:KeyInfo>/,
    '<ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference ' +
    'URI="#x509" ValueType="' + X509V3 + '"/>' +
    '</wsse:SecurityTokenReference></ds:KeyInfo>');
  log.debug("Leaving signedRst().");
  return signed;
}

// The certificate an answer's BinarySecurityToken carries, as PEM.
function tokenPemOf(body) {
  log.debug("Entering tokenPemOf().");
  const found = /<wsse:BinarySecurityToken[^>]*wsu:Id="iya-bst"[^>]*>([^<]+)</
    .exec(String(body));
  log.debug("Leaving tokenPemOf().");
  return found ? '-----BEGIN CERTIFICATE-----\n' + found[1] +
    '\n-----END CERTIFICATE-----\n' : '';
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
  const tlsClient = require(ROOT + '/common/tls_client_certificates');
  const xmldsig = require(ROOT + '/common/crypto_impl/xmldsig.js');
  const stsCrypto = require(ROOT + '/common/crypto');
  const xmldom = require('@xmldom/xmldom');
  const WsEncryption = require(ROOT + '/ws-trust/ws_encryption');
  const WebWsProtection = require(ROOT + '/ws-trust/web_ws_protection');
  const WsTrustMetadata = require(ROOT + '/ws-trust/wstrust_metadata');
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
  await pki.ensureScope(realms.currentId());

  ldap.createUser('wmialice', { invent: false });
  const back = applications.createApplication({ identifier: 'wmiback',
    protocols: ['wstrust'],
    fields: { oauthClientId: 'wmiback', wstrustAppliesTo: [BACK] } });
  t.check(back && back.ok, 'precondition: the application was created',
          JSON.stringify(back));
  const made = await tlsClient.issue('', { label: 'alice',
    keyAlg: 'rsa-2048', purpose: 'message-signing', username: 'wmialice' });
  t.check(made.ok, 'precondition: a message-signing certificate',
          JSON.stringify(made.errors || ''));
  const alice = { certPem: made.issued.certificatePem,
                  keyPem: made.issued.privateKeyPem };
  // An encryption recipient: a key pair of its own, so development
  // encrypts to it (product's paranoid PKI is #1668's business, not this).
  const encKeys = nodeCrypto.generateKeyPairSync('rsa',
                                                  { modulusLength: 2048 });
  const encKeyPem = encKeys.privateKey.export({ type: 'pkcs8',
                                                format: 'pem' });

  const set = function (attribute, value) {
    log.debug("Entering set(). " + attribute);
    const multi = Array.isArray(value);
    let ok = true;
    if (multi) {
      // A multi-valued attribute is emptied value by value: a `set` of ''
      // leaves the list as it was.
      const app = applications.get('wmiback');
      [].concat((app && app.fields && app.fields[attribute]) || [])
        .forEach(function (one) {
          applications.updateApplication('wmiback', { mode: 'remove',
            attribute: attribute, value: one });
        });
      value.forEach(function (one) {
        const r = applications.updateApplication('wmiback', { mode: 'add',
          attribute: attribute, value: one });
        ok = ok && !!(r && r.ok);
      });
    } else {
      const r = applications.updateApplication('wmiback', { mode: 'set',
        attribute: attribute, value: value });
      ok = !!(r && r.ok);
    }
    log.debug("Leaving set().");
    return ok;
  };
  const ask = async function (m, xml) {
    log.debug("Entering ask(). " + m);
    config.setOverride('global.mode', m);
    try {
      const req = {};
      const doc = new xmldom.DOMParser().parseFromString(xml, 'text/xml');
      await wstrust.prepareMessageSignature(req, doc);
      const out = await wstrust.handleRst(xml, 'application/soap+xml', {
        base: BASE,
        connection: { socket: null, revocation: null,
                      signature: req.stsMessageSignature || null } });
      log.debug("Leaving ask().");
      return out;
    } finally {
      config.clearOverride('global.mode');
    }
  };
  const sign = function (opts) {
    log.debug("Entering sign().");
    log.debug("Leaving sign().");
    return signedRst(xmldsig, Object.assign({}, alice, opts || {}));
  };
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return JSON.stringify({ status: r.status, errorCode: r.errorCode,
                            body: String(r.body || '').slice(0, 900) });
  };
  const verified = function (body) {
    log.debug("Entering verified().");
    const pem = tokenPemOf(body);
    const v = pem ? stsCrypto.verifyWsSecuritySignature(String(body),
                                                         { certPem: pem })
                  : { ok: false, why: 'no token' };
    log.debug("Leaving verified().");
    return v;
  };

  // -------------------------------------------------------------------------
  // K. THE REQUEST
  // -------------------------------------------------------------------------
  let r = await ask('development', envelope({}));
  t.check(r.status === 200,
          'K1. off by default: an unsigned development request is answered',
          brief(r));
  t.check(set('wstrustSignRequest', 'true'),
          'precondition: wmiback requires a signed request');
  r = await ask('development', envelope({}));
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0084' &&
          /FailedCheck/.test(String(r.body)),
          'K2. on, an unsigned request is STS-WSTRUST-0084, wsse:FailedCheck',
          brief(r));
  r = await ask('development', sign());
  t.check(r.status === 200,
          'K3. a signed request passes with no map: the Body', brief(r));
  set('wstrustSignRequestElements', WebWsProtection.expressions(
    'wstrustSignRequestElements', 'header'));
  r = await ask('development', sign({ wsa: true }));
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0085' &&
          /FailedCheck/.test(String(r.body)),
          'K4. the Header preset: an unsigned wsa:Action is STS-WSTRUST-0085',
          brief(r));
  r = await ask('development', sign({ wsa: true, signIds: ['wsa'] }));
  t.check(r.status === 200,
          'K4. and passes once the sender signs it', brief(r));
  set('wstrustSignRequestElements', ["//*[local-name()='Nothing']"]);
  r = await ask('development', sign());
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0085',
          'K5. an expression that matches nothing is STS-WSTRUST-0085',
          brief(r));
  set('wstrustSignRequestElements', WebWsProtection.expressions(
    'wstrustSignRequestElements', 'body'));
  r = await ask('product', sign());
  t.check(r.status === 200 && />wmialice</.test(String(r.body)),
          'K6. product: a verified signature over the Body passes the Body ' +
          'preset', brief(r));
  r = await ask('product', envelope({}));
  t.check(r.status === 500 && /FailedCheck|FailedAuthentication/.test(
            String(r.body)),
          'K6. product: an unsigned request is refused', brief(r));
  set('wstrustSignRequest', '');
  set('wstrustSignRequestElements', []);

  // -------------------------------------------------------------------------
  // L. THE RESPONSE
  // -------------------------------------------------------------------------
  r = await ask('development', sign());
  t.check(r.status === 200 && !/ds:Signature[^>]*Id="iya-sig"/.test(
            String(r.body)),
          'L1. off by default: the answer carries no message signature',
          brief(r));
  t.check(set('wstrustSignResponse', 'true'),
          'precondition: wmiback signs its answers');
  for (const m of ['development', 'product']) {
    r = await ask(m, sign());
    const v = verified(r.body);
    t.check(r.status === 200 && v.ok &&
            /<wsu:Timestamp[^>]*wsu:Id="iya-ts"/.test(String(r.body)) &&
            tokenPemOf(r.body).indexOf(String(helpers.STS.xmlSigner.certPem)
              .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
              .slice(0, 60)) >= 0,
            'L2. ' + m + ': the answer is signed over its Timestamp and ' +
            'Body with the realm\'s XML signing key, and verifies',
            (v.why || '') + ' ' + brief(r));
  }
  const validate = signedRst(xmldsig, Object.assign({}, alice, { op:
    'Validate', inner: '<wst:TokenType>' + WST + '/RSTR/Status' +
      '</wst:TokenType><wst:ValidateTarget/>' }));
  r = await ask('development', validate);
  t.check(r.status === 200 && verified(r.body).ok,
          'L3. a Validate answer is signed too', brief(r));
  set('wstrustSignResponseElements', ["//*[local-name()='Nothing']"]);
  r = await ask('development', sign());
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0086' &&
          /RequestFailed/.test(String(r.body)) &&
          !/Assertion/.test(String(r.body)),
          'L4. a map that matches nothing is STS-WSTRUST-0086, and the ' +
          'token is not sent', brief(r));
  set('wstrustSignResponseElements', ['//wsse:Security']);
  r = await ask('development', sign());
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0086',
          'L5. a map that selects the security header itself is ' +
          'STS-WSTRUST-0086', brief(r));
  set('wstrustSignResponseElements', []);

  // -------------------------------------------------------------------------
  // M. SIGNING AND ENCRYPTION TOGETHER
  // -------------------------------------------------------------------------
  const certFor = function (keys) {
    log.debug("Entering certFor().");
    const forge = xmldsig.forge;
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey.export(
      { type: 'spki', format: 'pem' }));
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date(Date.now() - 60000);
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    cert.setSubject([{ name: 'commonName', value: 'wmi-recipient' }]);
    cert.setIssuer([{ name: 'commonName', value: 'wmi-recipient' }]);
    cert.sign(forge.pki.privateKeyFromPem(keys.privateKey.export(
      { type: 'pkcs8', format: 'pem' })), forge.md.sha256.create());
    log.debug("Leaving certFor().");
    return forge.pki.certificateToPem(cert);
  };
  set('wstrustEncryptResponse', 'true');
  set('wstrustEncryptResponseElements', WebWsProtection.expressions(
    'wstrustEncryptResponseElements', 'body'));
  set('wstrustEncryptionCertificate', certFor(encKeys));
  // Every EncryptedData opened with the recipient's key and put back where
  // it stood, as a receiver does before it verifies a signature made first:
  // each EncryptedKey in the header, in order, opens the EncryptedData its
  // ReferenceList names. `decryptElement()` pairs the first EncryptedData
  // with the first EncryptedKey, so each is opened from a copy holding that
  // pair alone.
  const XENC = 'http://www.w3.org/2001/04/xmlenc#';
  let openedWhy = '';
  const opened = function (body) {
    log.debug("Entering opened().");
    config.setOverride('global.mode', 'development');
    let xml = String(body);
    try {
      const parse = function (text) {
        return new xmldom.DOMParser().parseFromString(text, 'text/xml');
      };
      const keyCount = parse(xml).getElementsByTagNameNS(XENC,
                                                         'EncryptedKey')
        .length;
      for (let k = 0; k < keyCount; k++) {
        const doc = parse(xml);
        const key = doc.getElementsByTagNameNS(XENC, 'EncryptedKey')[0];
        const ref = key.getElementsByTagNameNS(XENC, 'DataReference')[0];
        const id = String(ref.getAttribute('URI')).replace(/^#/, '');
        const copy = parse(xml);
        const keys = copy.getElementsByTagNameNS(XENC, 'EncryptedKey');
        for (let i = keys.length - 1; i > 0; i--) {
          keys[i].parentNode.removeChild(keys[i]);
        }
        const datas = copy.getElementsByTagNameNS(XENC, 'EncryptedData');
        for (let i = datas.length - 1; i >= 0; i--) {
          if (datas[i].getAttribute('Id') !== id) {
            datas[i].parentNode.removeChild(datas[i]);
          }
        }
        const one = stsCrypto.decryptElement(
          new xmldom.XMLSerializer().serializeToString(copy), encKeyPem);
        if (!one || !one.ok) {
          openedWhy = JSON.stringify(one).slice(0, 400);
          xml = '';
          break;
        }
        const all = doc.getElementsByTagNameNS(XENC, 'EncryptedData');
        let data = null;
        for (let i = 0; i < all.length; i++) {
          if (all[i].getAttribute('Id') === id) {
            data = all[i];
          }
        }
        data.parentNode.replaceChild(doc.importNode(
          parse(String(one.xml)).documentElement, true), data);
        key.parentNode.removeChild(key);
        xml = new xmldom.XMLSerializer().serializeToString(doc);
      }
    } catch (e) {
      log.debug("Caught in opened(): " + ((e && e.message) || e));
      openedWhy = String((e && e.message) || e);
      xml = '';
    } finally {
      config.clearOverride('global.mode');
    }
    log.debug("Leaving opened().");
    return xml;
  };
  r = await ask('development', sign());
  let body = String(r.body);
  t.check(r.status === 200 && /<xenc:EncryptedData/.test(body) &&
          body.indexOf('xenc:EncryptedKey') < body.indexOf('wsu:Timestamp') &&
          body.indexOf('wsu:Timestamp') < body.indexOf('ds:Signature') &&
          !verified(body).ok && verified(opened(body)).ok,
          'M1. sign-then-encrypt: the keys come first in the header, and ' +
          'the signature verifies once the Body is opened, not before',
          JSON.stringify(verified(opened(body)).why || '') + ' ' +
          opened(body).slice(0, 3000));
  set('wstrustResponseProtectionOrder', 'encrypt-then-sign');
  r = await ask('development', sign());
  body = String(r.body);
  t.check(r.status === 200 && /<xenc:EncryptedData/.test(body) &&
          body.indexOf('ds:Signature') < body.indexOf('xenc:EncryptedKey') &&
          verified(body).ok,
          'M2. encrypt-then-sign: the signature comes first and verifies ' +
          'over the ciphertext', brief(r));
  set('wstrustResponseProtectionOrder', '');
  set('wstrustEncryptSignature', 'true');
  r = await ask('development', sign());
  body = String(r.body);
  const security = (/<wsse:Security[\s\S]*?<\/wsse:Security>/.exec(body) ||
                    [''])[0];
  t.check(r.status === 200 && !/<ds:Signature/.test(security) &&
          /<xenc:EncryptedData/.test(security) &&
          verified(opened(body)).ok,
          'M3. sp:EncryptSignature: the signature is encrypted in the ' +
          'header, and verifies once opened',
          JSON.stringify(verified(opened(body)).why || '') + ' ' +
          openedWhy + ' ' +
          opened(body).slice(0, 3000));
  set('wstrustEncryptSignature', '');
  set('wstrustEncryptResponse', '');
  set('wstrustEncryptResponseElements', []);
  set('wstrustEncryptionCertificate', '');
  set('wstrustSignResponse', '');

  // -------------------------------------------------------------------------
  // N. THE PRESETS AND THE SUBSET
  // -------------------------------------------------------------------------
  const both = ['http://schemas.xmlsoap.org/soap/envelope/',
                'http://www.w3.org/2003/05/soap-envelope'];
  both.forEach(function (soapNs) {
    const doc = new xmldom.DOMParser().parseFromString(
      '<e:Envelope xmlns:e="' + soapNs + '"><e:Header>' +
      '<a:Action xmlns:a="' + WSA + '"/><wsse:Security xmlns:wsse="' + WSSE +
      '"/><a:To xmlns:a="' + WSA + '"/></e:Header><e:Body><x:A ' +
      'xmlns:x="urn:x"/></e:Body></e:Envelope>', 'text/xml');
    const header = WsEncryption.select(doc, WebWsProtection.expressions(
      'wstrustSignRequestElements', 'header')[0]);
    const content = WsEncryption.select(doc, WebWsProtection.expressions(
      'wstrustEncryptRequestElements', 'body')[0]);
    const whole = WsEncryption.select(doc, WebWsProtection.expressions(
      'wstrustSignRequestElements', 'body')[0]);
    t.check(header.ok && header.nodes.map(function (n) {
      return n.localName;
    }).join(',') === 'Action,To' && content.ok &&
            content.nodes.length === 1 && content.nodes[0].localName === 'A' &&
            whole.ok && whole.nodes.length === 1 &&
            whole.nodes[0].localName === 'Body',
            'N1. ' + soapNs + ': the Header preset is every block but ' +
            'wsse:Security, the Body presets the Body and its content',
            JSON.stringify([header, content, whole].map(function (x) {
              return x.ok ? x.nodes.length : x.reason;
            })));
  });
  const nested = WsEncryption.select(new xmldom.DOMParser().parseFromString(
    '<a/>', 'text/xml'), "/*[not(not(local-name()='a'))]");
  t.check(!nested.ok && nested.code === 'STS-WSTRUST-0079',
          'N2. a not() inside a not() is outside the subset, ' +
          'STS-WSTRUST-0079', JSON.stringify(nested));
  const values = WebWsProtection.applied(['//x'], 'wstrustSignRequestElements',
                                         'header', true);
  t.check(WebWsProtection.isOn(values, 'wstrustSignRequestElements',
                               'header') &&
          !WebWsProtection.isOn(WebWsProtection.applied(values,
            'wstrustSignRequestElements', 'header', false),
            'wstrustSignRequestElements', 'header') &&
          values[0] === '//x',
          'N3. a preset is ticked exactly when its expressions are in the ' +
          'map, and taking it out keeps the rest', JSON.stringify(values));

  // -------------------------------------------------------------------------
  // O. THE WSDL
  // -------------------------------------------------------------------------
  const flags = WsTrustMetadata.liveFlags();
  const plain = WsTrustMetadata.document(BASE, BASE, flags);
  t.check(!/sp:IncludeTimestamp/.test(plain) &&
          !/Answers are signed/.test(plain),
          'O1. answers unsigned: no sp:IncludeTimestamp in the binding');
  const signing = WsTrustMetadata.document(BASE, BASE, Object.assign({},
    flags, { signsResponses: true, encryptsSignature: true }));
  t.check(/<sp:IncludeTimestamp\/>/.test(signing) &&
          /<sp:EncryptSignature\/>/.test(signing) &&
          !/<sp:EncryptBeforeSigning\/>/.test(signing) &&
          /wsu:Id="ResponseProtection"/.test(signing) &&
          /URI="#ResponseProtection"/.test(signing),
          'O2. answers signed: sp:IncludeTimestamp and sp:EncryptSignature ' +
          'in the binding, and ResponseProtection on every output');
  const after = WsTrustMetadata.document(BASE, BASE, Object.assign({},
    flags, { signsResponses: true, encryptsBeforeSigning: true,
             encryptsSignature: true }));
  t.check(/<sp:EncryptBeforeSigning\/>/.test(after) &&
          !/<sp:EncryptSignature\/>/.test(after),
          'O3. encrypt-then-sign: sp:EncryptBeforeSigning, and no ' +
          'sp:EncryptSignature (it protects a signature made first)');
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
  name: 'wstrust_message_integrity',
  describe: 'WS-Trust: an application requires a request signed over the ' +
            'elements it names, and has its answers signed with the realm\'s ' +
            'XML signing key, in either order with encryption, the ' +
            'signature encrypted too (#1917, #1918)',
  run: run
};
