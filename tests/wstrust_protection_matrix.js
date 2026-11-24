// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_protection_matrix.js
//
// ===========================================================================
// THE WS-TRUST MESSAGE PROTECTION MAPS, EVERY COMBINATION, WITH REAL
// MESSAGES (#2046, rcbj 2026-11-23): "build tests for every combination of
// whole soap body and whole soap header fields checked using WS-Trust
// messages... the actual messages need to be real and valid and validated
// (encrypted / decrypted). Then, build tests to exercise custom xpaths in
// each field (and in different combinations)."
//
// Every request is built by Apache WSS4J (tests/tools/wss4j-driver's
// `protect`), the way a WSS4J client signs and encrypts one: a
// BinarySecurityToken and a signature over the Timestamp and the parts the
// application's request signing map names, and AES-256-GCM content
// encrypted with RSA-OAEP to the realm's XML encryption certificate for the
// parts its request encryption map names (a header block as a
// wsse11:EncryptedHeader). The service decrypts it, verifies the signature
// against the realm's certificate authority (product mode, where a
// signature is verified rather than believed), holds each map, and answers.
// Every answer is opened and verified by WSS4J (`verify`): decrypted with
// the recipient's key and its signature checked against the realm's XML
// signing certificate alone, the Basic Security Profile enforced. WSS4J's
// own account of what it decrypted and what the signature covered is what
// each check reads, never this service's.
//
//   A. THE PRESETS: all 256 combinations of the eight Whole SOAP Body /
//      Whole SOAP Header boxes — the four maps, each with neither, Body,
//      Header or both — under SOAP 1.2 and SOAP 1.1 (512 exchanges). A
//      map's switch is on exactly when one of its boxes is ticked, and the
//      client protects exactly what the request maps name. Each exchange
//      must be answered; the answer must open and verify in WSS4J; WSS4J
//      must report as encrypted exactly the parts the response encryption
//      map names (the token collection for Body, wsa:Action for Header),
//      and as signed exactly the parts the response signing map names
//      (beside the Timestamp); nothing it names may be readable before it
//      is opened; and the opened answer must carry the issued token.
//   B. THE PRESETS REFUSED: for each request map and box, a client that
//      leaves out what the box asks for is refused with the fault the
//      service documents (STS-WSTRUST-0075 for encryption, 0085 for
//      signing), and ciphertext where no map names it is 0075 too.
//   C. CUSTOM EXPRESSIONS, ONE FIELD AT A TIME: for each of the five
//      fields, expressions naming single elements — a header block, an
//      element inside the RST, an element of the RSTR — met by a WSS4J
//      client (or produced by the service) and checked in WSS4J's account
//      of the message; each with a refusal when it is not met.
//      The recipient of an encrypted answer, each way it is chosen: the
//      application's certificate; with none, the certificate the request's
//      signature names (the requester's own key opens it, and only it);
//      and wstrustResponseRecipientXPath naming the signer's
//      BinarySecurityToken or a certificate in a header the requester
//      signed (that key opens it, the application's does not), with the
//      application's certificate winning when both are set, and the
//      refusals when nothing names a recipient, the expression matches
//      nothing or no certificate, or what it names is not signed. The
//      request's signing certificate is refused as a recipient when its
//      keyUsage is digitalSignature only (the realm's own), unless the
//      application or the realm waives that check (rcbj, 2026-11-24:
//      wstrustRecipientIgnoresKeyUsage, wstrust.recipientIgnoresKeyUsage);
//      one that also permits keyEncipherment — the requester's own, stored
//      on their entry — is a recipient in product.
//   D. CUSTOM EXPRESSIONS IN COMBINATION: several expressions in one map,
//      a custom expression beside a preset, all four maps custom at once,
//      the same element signed and encrypted in both orders, the signature
//      encrypted too, the recipient chosen by expression together with the
//      maps, and SOAP 1.1.
//   E. A TAMPERED ANSWER: WSS4J refuses an answer altered after signing.
//   F. SIGNING AND ENCRYPTION MIXED, BOTH WAYS: the request signed and
//      encrypted in either order, the answer in either order or with its
//      signature encrypted too, with the presets and with custom
//      expressions in all four maps at once.
//
// IN A CHILD PROCESS, for `wstrust_message_integrity.js`'s reason: it loads
// the stack and builds a certificate authority, both process state `run.js`
// shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_WSTRUST_PROTECTION_MATRIX_CHILD';
const MARK = 'WSTRUST-MATRIX-CHILD ';

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const WSA = 'http://www.w3.org/2005/08/addressing';
const WSP = 'http://schemas.xmlsoap.org/ws/2004/09/policy';
const WSU = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-utility-1.0.xsd';
const SOAP = {
  '1.2': { ns: 'http://www.w3.org/2003/05/soap-envelope', prefix: 'soap12',
           type: 'application/soap+xml' },
  '1.1': { ns: 'http://schemas.xmlsoap.org/soap/envelope/',
           prefix: 'soap11', type: 'text/xml' }
};
const SAML2_TOKEN = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-saml-token-profile-1.1#SAMLV2.0';
const BACK = 'https://wpm-back.example';
const BASE = 'https://sts.example';
const APP = 'wpmback';
const USER = 'wpmalice';

// The eight boxes, in the order a combination's bits are read.
const BOXES = [
  { map: 'wstrustEncryptRequestElements', part: 'body' },
  { map: 'wstrustEncryptRequestElements', part: 'header' },
  { map: 'wstrustEncryptResponseElements', part: 'body' },
  { map: 'wstrustEncryptResponseElements', part: 'header' },
  { map: 'wstrustSignRequestElements', part: 'body' },
  { map: 'wstrustSignRequestElements', part: 'header' },
  { map: 'wstrustSignResponseElements', part: 'body' },
  { map: 'wstrustSignResponseElements', part: 'header' }
];
// Each map's switch.
const SWITCHES = {
  wstrustEncryptRequestElements: 'wstrustEncryptRequest',
  wstrustEncryptResponseElements: 'wstrustEncryptResponse',
  wstrustSignRequestElements: 'wstrustSignRequest',
  wstrustSignResponseElements: 'wstrustSignResponse'
};
// The header blocks every request carries, which the Header preset names.
const HEADERS = ['Action', 'MessageID', 'To'];

const log = require('bunyan').createLogger({
  name: 'wstrust_protection_matrix',
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

// An RST as a client writes it before WSS4J protects it: three WS-Addressing
// header blocks, and an Issue for a SAML 2.0 token for the application. No
// security header: WSS4J writes its own. `extraHeader` is put after the
// addressing blocks.
function envelope(soap, extraHeader) {
  log.debug("Entering envelope().");
  const ns = SOAP[soap].ns;
  log.debug("Leaving envelope().");
  return '<s:Envelope xmlns:s="' + ns + '"><s:Header>' +
    '<wsa:Action xmlns:wsa="' + WSA + '">' + WST + '/RST/Issue' +
    '</wsa:Action>' +
    '<wsa:MessageID xmlns:wsa="' + WSA + '">urn:uuid:' +
    nodeCrypto.randomUUID() + '</wsa:MessageID>' +
    '<wsa:To xmlns:wsa="' + WSA + '">' + BASE + '/sts</wsa:To>' +
    (extraHeader || '') + '</s:Header><s:Body>' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '">' +
    '<wst:TokenType>' + SAML2_TOKEN + '</wst:TokenType>' +
    '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="' + WSP + '"><wsa:EndpointReference ' +
    'xmlns:wsa="' + WSA + '"><wsa:Address>' + BACK + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

// The parts a request map's boxes name, as WSS4J parts: the Body (its
// content when encrypting), and each header block (as an EncryptedHeader
// when encrypting).
function presetParts(body, header, encrypting) {
  log.debug("Entering presetParts().");
  const parts = [];
  if (body) {
    parts.push(encrypting ? { local: 'Body', mode: 'Content' }
                          : { local: 'Body' });
  }
  if (header) {
    HEADERS.forEach(function (local) {
      parts.push(encrypting ? { local: local, ns: WSA, mode: 'Header' }
                            : { local: local, ns: WSA });
    });
  }
  log.debug("Leaving presetParts().");
  return parts;
}

// WSS4J's names for what it decrypted or what a signature covered, as
// local names, in its order.
function namesOf(got, action) {
  log.debug("Entering namesOf(). " + action);
  const out = [];
  (got.actions || []).filter(function (one) {
    return one.action === action;
  }).forEach(function (one) {
    one.refs.forEach(function (ref) {
      out.push(String(ref.name).replace(/^\{[^}]*\}/, ''));
    });
  });
  log.debug("Leaving namesOf().");
  return out;
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
  const xmldom = require('@xmldom/xmldom');
  const WebWsProtection = require(ROOT + '/ws-trust/web_ws_protection');
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

  ldap.createUser(USER, { invent: false });
  const made = applications.createApplication({ identifier: APP,
    protocols: ['wstrust'],
    fields: { oauthClientId: APP, wstrustAppliesTo: [BACK] } });
  t.check(made && made.ok, 'precondition: the application was created',
          JSON.stringify(made));
  // The requester's message-signing certificate, issued by the realm's CA,
  // so product verifies the signature and knows who signed.
  const issued = await tlsClient.issue('', { label: 'alice',
    keyAlg: 'rsa-2048', purpose: 'message-signing', username: USER });
  t.check(issued.ok, 'precondition: a message-signing certificate',
          JSON.stringify(issued.errors || ''));
  const signer = {
    certPem: issued.issued.certificatePem,
    keyPem: nodeCrypto.createPrivateKey(issued.issued.privateKeyPem)
      .export({ type: 'pkcs8', format: 'pem' })
  };
  // The answer's recipient: a key pair of its own, its certificate on the
  // application, and its private key handed to WSS4J alone.
  const certFor = function (keys, name) {
    log.debug("Entering certFor(). " + name);
    const forge = xmldsig.forge;
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey.export(
      { type: 'spki', format: 'pem' }));
    cert.serialNumber = '0' + nodeCrypto.randomBytes(8).toString('hex');
    cert.validity.notBefore = new Date(Date.now() - 60000);
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    cert.setSubject([{ name: 'commonName', value: name }]);
    cert.setIssuer([{ name: 'commonName', value: name }]);
    cert.sign(forge.pki.privateKeyFromPem(keys.privateKey.export(
      { type: 'pkcs8', format: 'pem' })), forge.md.sha256.create());
    log.debug("Leaving certFor().");
    return forge.pki.certificateToPem(cert);
  };
  const recipientKeys = nodeCrypto.generateKeyPairSync('rsa',
    { modulusLength: 2048 });
  const recipient = {
    certPem: certFor(recipientKeys, 'wpm-recipient'),
    keyPem: recipientKeys.privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
  // A SIGNER WHOSE CERTIFICATE ALSO PERMITS keyEncipherment (rcbj,
  // 2026-11-24), for an answer encrypted to the request's signing
  // certificate: the realm's message-signing CA issues digitalSignature
  // only, and the service refuses to encrypt to such a certificate
  // (STS-WSTRUST-0077) unless the application waives that check. This one is
  // the requester's own, stored on their entry, which is how product
  // believes a certificate the realm did not issue (wstrust_message_signature
  // E7).
  const dualKeys = nodeCrypto.generateKeyPairSync('rsa',
    { modulusLength: 2048 });
  const dual = (function () {
    log.debug("Entering dual().");
    const forge = xmldsig.forge;
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(dualKeys.publicKey.export(
      { type: 'spki', format: 'pem' }));
    cert.serialNumber = '0' + nodeCrypto.randomBytes(8).toString('hex');
    cert.validity.notBefore = new Date(Date.now() - 60000);
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    cert.setSubject([{ name: 'commonName', value: USER }]);
    cert.setIssuer([{ name: 'commonName', value: USER }]);
    cert.setExtensions([{ name: 'keyUsage', digitalSignature: true,
                          keyEncipherment: true }]);
    cert.sign(forge.pki.privateKeyFromPem(dualKeys.privateKey.export(
      { type: 'pkcs8', format: 'pem' })), forge.md.sha256.create());
    log.debug("Leaving dual().");
    return { certPem: forge.pki.certificateToPem(cert),
             keyPem: dualKeys.privateKey.export({ type: 'pkcs8',
                                                  format: 'pem' }) };
  })();
  const dualStored = ldap.changeStoredCertificate('person', USER,
    { add: new nodeCrypto.X509Certificate(dual.certPem).raw });
  t.check(dualStored && dualStored.ok,
          'precondition: the dual-use certificate is stored on ' + USER,
          JSON.stringify(dualStored));
  // A second recipient, named by a header the requester signs (D).
  const otherKeys = nodeCrypto.generateKeyPairSync('rsa',
    { modulusLength: 2048 });
  const other = {
    certPem: certFor(otherKeys, 'wpm-other'),
    keyPem: otherKeys.privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
  const realmEncryptionPem = String(helpers.STS.xml.certPem);
  const realmSignerPem = String(helpers.STS.xmlSigner.certPem);

  // -------------------------------------------------------------------------
  // THE TOOLS
  // -------------------------------------------------------------------------
  const wss4j = function (command, request) {
    log.debug("Entering wss4j(). " + command);
    const got = childProcess.spawnSync('wss4j-driver', [command], {
      input: JSON.stringify(request), encoding: 'utf8', timeout: 600000,
      maxBuffer: 512 * 1024 * 1024 });
    let out = null;
    try {
      out = JSON.parse(String(got.stdout || '').trim().split('\n').pop());
    } catch (e) {
      log.debug("Caught in wss4j(): " + ((e && e.message) || e));
      // No answer: the error the child gave is the reason.
      out = { ok: false, message: String((got.error && got.error.message) ||
        got.stderr || 'no answer').slice(0, 600) };
    }
    log.debug("Leaving wss4j().");
    return out;
  };
  // Many items, one JVM; a failed batch is a failed answer for every item.
  const batch = function (items) {
    log.debug("Entering batch(). " + items.length);
    const got = wss4j('batch', { items: items });
    const results = got && got.ok && Array.isArray(got.results)
      ? got.results : items.map(function () {
        return { ok: false, message: 'the batch failed: ' +
          String((got && got.message) || '') };
      });
    log.debug("Leaving batch().");
    return results;
  };
  // What WSS4J needs to open and check an answer.
  const verifyItem = function (xml, key) {
    log.debug("Entering verifyItem().");
    const to = key === 'signer' ? signer
      : (key === 'dual' ? dual : (key || recipient));
    log.debug("Leaving verifyItem().");
    return { command: 'verify', xml: String(xml), trustPems: [realmSignerPem],
             recipientKeyPem: to.keyPem, recipientCertPem: to.certPem };
  };
  // A request protected by WSS4J: `sign` and `encrypt` are part lists, null
  // for none.
  const protectItem = function (xml, sign, encrypt, opts) {
    log.debug("Entering protectItem().");
    const o = opts || {};
    const item = { command: 'protect', xml: xml,
                   order: o.order || 'sign-then-encrypt' };
    if (sign) {
      const by = o.signer === 'dual' ? dual : signer;
      item.sign = { certPem: by.certPem, keyPem: by.keyPem, parts: sign };
    }
    if (encrypt) {
      item.encrypt = { certPem: realmEncryptionPem, parts: encrypt,
                       keyIdentifier: o.keyIdentifier || 'IssuerSerial',
                       keyTransport: o.keyTransport || 'rsa-oaep' };
    }
    log.debug("Leaving protectItem().");
    return item;
  };

  // The application's protection settings, written only where they change.
  const held = {};
  const set = function (attribute, value) {
    log.debug("Entering set(). " + attribute);
    const wanted = Array.isArray(value) ? value.slice() : String(value || '');
    if (JSON.stringify(held[attribute]) === JSON.stringify(wanted)) {
      log.debug("Leaving set(). Unchanged.");
      return true;
    }
    let ok = true;
    if (Array.isArray(wanted)) {
      // A multi-valued attribute is emptied value by value: a `set` of ''
      // leaves the list as it was.
      const app = applications.get(APP);
      [].concat((app && app.fields && app.fields[attribute]) || [])
        .forEach(function (one) {
          applications.updateApplication(APP, { mode: 'remove',
            attribute: attribute, value: one });
        });
      wanted.forEach(function (one) {
        const r = applications.updateApplication(APP, { mode: 'add',
          attribute: attribute, value: one });
        ok = ok && !!(r && r.ok);
      });
    } else {
      const r = applications.updateApplication(APP, { mode: 'set',
        attribute: attribute, value: wanted });
      ok = !!(r && r.ok);
    }
    held[attribute] = wanted;
    log.debug("Leaving set().");
    return ok;
  };
  // Four maps at once, each switch on exactly when its map is not empty.
  const configure = function (maps) {
    log.debug("Entering configure().");
    let ok = true;
    Object.keys(SWITCHES).forEach(function (map) {
      const values = maps[map] || [];
      ok = set(map, values) && ok;
      ok = set(SWITCHES[map], values.length ? 'TRUE' : '') && ok;
    });
    log.debug("Leaving configure().");
    return ok;
  };
  const ask = async function (soap, xml, mode) {
    log.debug("Entering ask().");
    config.setOverride('global.mode', mode || 'product');
    try {
      const req = {};
      const doc = new xmldom.DOMParser().parseFromString(xml, 'text/xml');
      await wstrust.prepareMessageSignature(req, doc);
      const out = await wstrust.handleRst(xml, SOAP[soap].type, {
        base: BASE,
        connection: { socket: null, revocation: null,
                      signature: req.stsMessageSignature || null } });
      log.debug("Leaving ask().");
      return out;
    } finally {
      config.clearOverride('global.mode');
    }
  };
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return JSON.stringify({ status: r.status, errorCode: r.errorCode,
                            body: String(r.body || '').slice(0, 700) });
  };
  const presets = function (map, body, header) {
    log.debug("Entering presets().");
    log.debug("Leaving presets().");
    return (body ? WebWsProtection.expressions(map, 'body') : [])
      .concat(header ? WebWsProtection.expressions(map, 'header') : []);
  };
  // Elements a reader can see before anything is opened.
  const clearNames = function (xml) {
    log.debug("Entering clearNames().");
    const doc = new xmldom.DOMParser().parseFromString(String(xml),
                                                       'text/xml');
    const names = [];
    const all = doc.getElementsByTagName('*');
    for (let i = 0; i < all.length; i++) {
      names.push(all[i].localName);
    }
    log.debug("Leaving clearNames().");
    return names;
  };
  const same = function (a, b) {
    log.debug("Entering same().");
    log.debug("Leaving same().");
    return JSON.stringify(a.slice(0).sort()) ===
      JSON.stringify(b.slice(0).sort());
  };
  const counts = function (list) {
    log.debug("Entering counts().");
    const out = {};
    list.forEach(function (one) {
      out[one] = (out[one] || 0) + 1;
    });
    log.debug("Leaving counts().");
    return out;
  };

  const probe = wss4j('verify', { xml: '<a/>', trustPems: [] });
  t.check(probe && (probe.ok === true || /Exception|Error/.test(
            String(probe.message || ''))) &&
          !/ENOENT|no answer/.test(String(probe.message || '')),
          'precondition: the WSS4J driver answers (tests/tools/wss4j-driver)',
          JSON.stringify(probe));
  set('wstrustEncryptionCertificate', recipient.certPem);

  // -------------------------------------------------------------------------
  // A. EVERY COMBINATION OF THE EIGHT BOXES, BOTH SOAP VERSIONS
  // -------------------------------------------------------------------------
  for (const soap of ['1.2', '1.1']) {
    const started = Date.now();
    const combos = [];
    for (let mask = 0; mask < 256; mask++) {
      const on = BOXES.map(function (box, i) {
        return !!(mask & (1 << i));
      });
      const ticked = function (map, part) {
        return on[BOXES.findIndex(function (box) {
          return box.map === map && box.part === part;
        })];
      };
      const maps = {};
      Object.keys(SWITCHES).forEach(function (map) {
        maps[map] = presets(map, ticked(map, 'body'), ticked(map, 'header'));
      });
      const signBody = ticked('wstrustSignRequestElements', 'body');
      const signHeader = ticked('wstrustSignRequestElements', 'header');
      // The client signs what the signing map names, and always its Body:
      // the service holds every request signature to cover the Body, where
      // the RST is (#521, STS-WSTRUST-0040), so a real client does too.
      const sign = presetParts(true, signHeader, false);
      void signBody;
      const encrypt = presetParts(
        ticked('wstrustEncryptRequestElements', 'body'),
        ticked('wstrustEncryptRequestElements', 'header'), true);
      combos.push({ mask: mask, maps: maps, ticked: ticked,
        label: BOXES.filter(function (box, i) {
          return on[i];
        }).map(function (box) {
          return box.map.replace(/^wstrust|Elements$/g, '') + ':' + box.part;
        }).join(' ') || 'nothing ticked',
        item: protectItem(envelope(soap), sign,
                          encrypt.length ? encrypt : null) });
    }
    const requests = batch(combos.map(function (c) {
      return c.item;
    }));
    const answers = [];
    for (let i = 0; i < combos.length; i++) {
      const c = combos[i];
      const built = requests[i];
      if (!built || !built.ok) {
        answers.push({ status: 0, body: '', built: built });
        continue;
      }
      if (!configure(c.maps)) {
        answers.push({ status: 0, body: 'the maps could not be written' });
        continue;
      }
      answers.push(await ask(soap, String(built.xml)));
    }
    const opened = batch(answers.map(function (r) {
      return verifyItem(r.status === 200 ? r.body : '<x/>');
    }));
    let passed = 0;
    combos.forEach(function (c, i) {
      const r = answers[i];
      const got = opened[i] || {};
      const encRespBody = c.ticked('wstrustEncryptResponseElements', 'body');
      const encRespHeader = c.ticked('wstrustEncryptResponseElements',
                                     'header');
      const sigRespBody = c.ticked('wstrustSignResponseElements', 'body');
      const sigRespHeader = c.ticked('wstrustSignResponseElements',
                                     'header');
      const encReqBody = c.ticked('wstrustEncryptRequestElements', 'body');
      const encReqHeader = c.ticked('wstrustEncryptRequestElements',
                                    'header');
      const sent = String((requests[i] && requests[i].xml) || '');
      const sentNames = clearNames(sent);
      const wantEnc = (encRespBody
        ? ['RequestSecurityTokenResponseCollection'] : [])
        .concat(encRespHeader ? ['Action'] : []);
      const wantSig = (sigRespBody || sigRespHeader ? ['Timestamp'] : [])
        .concat(sigRespBody ? ['Body'] : [])
        .concat(sigRespHeader ? ['Action'] : []);
      const clear = clearNames(r.body);
      const problems = [];
      if (encReqBody && sentNames.indexOf('RequestSecurityToken') >= 0) {
        problems.push('the client left the RST readable');
      }
      if (encReqHeader && (sentNames.indexOf('MessageID') >= 0 ||
                           counts(sentNames).EncryptedHeader !== 3)) {
        problems.push('the client left a header block readable');
      }
      if (r.status !== 200) {
        problems.push('not answered: ' + brief(r));
      } else if (!got.ok) {
        problems.push('WSS4J refused the answer: ' + got.message);
      } else {
        if (!same(namesOf(got, 'encryption'), wantEnc)) {
          problems.push('WSS4J decrypted ' +
            JSON.stringify(namesOf(got, 'encryption')) + ', wanted ' +
            JSON.stringify(wantEnc));
        }
        if (!same(namesOf(got, 'signature'), wantSig)) {
          problems.push('WSS4J found signed ' +
            JSON.stringify(namesOf(got, 'signature')) + ', wanted ' +
            JSON.stringify(wantSig));
        }
        if (encRespBody && (clear.indexOf('RequestedSecurityToken') >= 0 ||
                            clear.indexOf('Assertion') >= 0)) {
          problems.push('the token was readable before it was opened');
        }
        if (encRespHeader && clear.indexOf('Action') >= 0) {
          problems.push('wsa:Action was readable before it was opened');
        }
        if (!encRespBody && !encRespHeader &&
            clear.indexOf('EncryptedData') >= 0) {
          problems.push('an answer no map encrypts carries ciphertext');
        }
        if (clearNames(got.xml).indexOf('RequestedSecurityToken') < 0 ||
            String(got.xml).indexOf(USER) < 0) {
          problems.push('the opened answer carries no token for ' + USER);
        }
      }
      if (!problems.length) {
        passed += 1;
      }
      t.check(!problems.length,
              'A. SOAP ' + soap + ', ' + c.label + ': answered, and WSS4J ' +
              'opens and verifies exactly what the maps name',
              problems.join('; ') + (problems.length
                ? ' — request: ' + sent.slice(0, 1500) : ''));
    });
    log.info('A. SOAP ' + soap + ': ' + passed + ' of ' + combos.length +
             ' combinations in ' + (Date.now() - started) + ' ms.');
  }
  configure({});

  // -------------------------------------------------------------------------
  // B. EACH REQUEST BOX REFUSES A CLIENT THAT DOES NOT MEET IT
  // -------------------------------------------------------------------------
  const refusals = [
    { what: 'Encrypt request Body ticked, the Body sent in the clear',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', true, false) },
      sign: presetParts(true, false, false), encrypt: null,
      code: 'STS-WSTRUST-0075' },
    { what: 'Encrypt request Header ticked, the header blocks in the clear',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', false, true) },
      sign: presetParts(true, false, false), encrypt: null,
      code: 'STS-WSTRUST-0075' },
    { what: 'Encrypt request Header ticked, the Body encrypted instead ' +
            '(ciphertext no map names)',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', false, true) },
      sign: presetParts(true, false, false),
      encrypt: presetParts(true, false, true), code: 'STS-WSTRUST-0080' },
    { what: 'Encrypt request Header ticked, one header block in the clear',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', false, true) },
      sign: presetParts(true, false, false),
      encrypt: [{ local: 'Action', ns: WSA, mode: 'Header' },
                { local: 'MessageID', ns: WSA, mode: 'Header' }],
      code: 'STS-WSTRUST-0075' },
    { what: 'Encrypt request Body ticked alone, the headers encrypted too ' +
            '(ciphertext no map names)',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', true, false) },
      sign: presetParts(true, false, false),
      encrypt: presetParts(true, true, true), code: 'STS-WSTRUST-0080' },
    { what: 'Sign request Body ticked, the Body not signed (a request ' +
            'signature must cover the Body in any case)',
      maps: { wstrustSignRequestElements: presets(
        'wstrustSignRequestElements', true, false) },
      sign: presetParts(false, true, false), encrypt: null,
      code: 'STS-WSTRUST-0040' },
    { what: 'Encrypt request Header ticked, the key wrapped with OAEP ' +
            'over SHA-1 (refused unless crypto.allowLegacyHashes)',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', false, true) },
      sign: presetParts(true, false, false),
      encrypt: presetParts(false, true, true), keyTransport: 'rsa-oaep-mgf1p',
      code: 'STS-WSTRUST-0075' },
    { what: 'Sign request Header ticked, the header blocks not signed',
      maps: { wstrustSignRequestElements: presets(
        'wstrustSignRequestElements', false, true) },
      sign: presetParts(true, false, false), encrypt: null,
      code: 'STS-WSTRUST-0085' },
    { what: 'Sign request Header ticked, wsa:To not signed',
      maps: { wstrustSignRequestElements: presets(
        'wstrustSignRequestElements', false, true) },
      sign: [{ local: 'Body' }, { local: 'Action', ns: WSA },
             { local: 'MessageID', ns: WSA }], encrypt: null,
      code: 'STS-WSTRUST-0085' },
    { what: 'Sign request Body and Header ticked, nothing signed',
      maps: { wstrustSignRequestElements: presets(
        'wstrustSignRequestElements', true, true) },
      sign: null, encrypt: null, code: 'STS-WSTRUST-0084' }
  ];
  for (const soap of ['1.2', '1.1']) {
    const built = batch(refusals.map(function (one) {
      return protectItem(envelope(soap), one.sign, one.encrypt,
                         { keyTransport: one.keyTransport });
    }));
    for (let i = 0; i < refusals.length; i++) {
      const one = refusals[i];
      configure(one.maps);
      const r = built[i] && built[i].ok
        ? await ask(soap, String(built[i].xml))
        : { status: 0, body: JSON.stringify(built[i]) };
      // The SOAP fault each code is documented to carry.
      const product = one.code === 'STS-WSTRUST-0084'
        ? /FailedCheck|FailedAuthentication/
        : (one.code === 'STS-WSTRUST-0040' ? /AuthenticationBadElements/
                                           : /FailedCheck|InvalidRequest/);
      t.check(r.status === 500 && (r.errorCode === one.code ||
                (one.code === 'STS-WSTRUST-0084' &&
                 /FailedAuthentication/.test(String(r.body)))) &&
              product.test(String(r.body)),
              'B. SOAP ' + soap + ': ' + one.what + ' is ' + one.code,
              brief(r));
    }
  }
  configure({});

  // -------------------------------------------------------------------------
  // C AND D. CUSTOM EXPRESSIONS
  //
  // Each case names the maps (custom expressions, presets beside them where
  // the case says so), how the client protects its request, and what WSS4J
  // must find in the answer: `enc` and `sig` are the local names it must
  // report decrypted and signed (the signature's Timestamp included), and
  // `refused` a fault the request must get instead. `soap` is 1.2 unless
  // given; `$` in an expression is the version's SOAP prefix.
  // -------------------------------------------------------------------------
  const xp = function (soap, expr) {
    log.debug("Entering xp().");
    log.debug("Leaving xp().");
    return expr.replace(/\$/g, SOAP[soap].prefix);
  };
  const H = '/$:Envelope/$:Header/';
  const R = '/$:Envelope/$:Body/wst:RequestSecurityToken/';
  const RSTR = '/$:Envelope/$:Body/wst:RequestSecurityTokenResponseCollection' +
    '/wst:RequestSecurityTokenResponse/';
  const B64 = function (pem) {
    log.debug("Entering B64().");
    log.debug("Leaving B64().");
    return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  };
  // A header the requester can put its own encryption certificate in, for
  // the recipient expression.
  const EXTRA = '<x:EncryptTo xmlns:x="urn:example:wpm"><ds:X509Certificate ' +
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' + B64(other.certPem) +
    '</ds:X509Certificate></x:EncryptTo>';
  const ENCRYPT_TO = H + "*[local-name()='EncryptTo' and " +
    "namespace-uri()='urn:example:wpm']/ds:X509Certificate";
  const SIGN_BODY = [{ local: 'Body' }];
  const cases = [
    // --- C. Request encryption, custom ----------------------------------
    { what: 'C. request encryption: wsa:To alone, as an EncryptedHeader',
      maps: { wstrustEncryptRequestElements: [H + 'wsa:To'] },
      sign: SIGN_BODY, encrypt: [{ local: 'To', ns: WSA, mode: 'Header' }] },
    { what: 'C. request encryption: wsp:AppliesTo inside the RST, as an ' +
            'Element (the service reads the AppliesTo once it is open)',
      maps: { wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' }] },
    { what: 'C. request encryption: wst:TokenType, by //',
      maps: { wstrustEncryptRequestElements: ['//wst:TokenType'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'TokenType', ns: WST, mode: 'Element' }] },
    { what: 'C. request encryption: wsp:AppliesTo named, sent in the clear',
      maps: { wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0075' },
    { what: 'C. request encryption: wsa:To named, wsa:Action encrypted ' +
            'instead',
      maps: { wstrustEncryptRequestElements: [H + 'wsa:To'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'Action', ns: WSA, mode: 'Header' }],
      refused: 'STS-WSTRUST-0080' },
    // --- C. Request signing, custom -------------------------------------
    { what: 'C. request signing: wsa:MessageID alone',
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID'] },
      sign: [{ local: 'Body' }, { local: 'MessageID', ns: WSA }],
      encrypt: null },
    { what: 'C. request signing: wst:TokenType inside the RST, by its own ' +
            'reference',
      maps: { wstrustSignRequestElements: [R + 'wst:TokenType'] },
      sign: [{ local: 'Body' }, { local: 'TokenType', ns: WST }],
      encrypt: null },
    { what: 'C. request signing: wst:TokenType inside the RST, covered by ' +
            'the signed Body',
      maps: { wstrustSignRequestElements: [R + 'wst:TokenType'] },
      sign: SIGN_BODY, encrypt: null },
    { what: 'C. request signing: wsa:MessageID named, only the Body signed',
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID'] },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0085' },
    { what: 'C. request signing: an expression that matches nothing',
      maps: { wstrustSignRequestElements: [H + 'wsa:ReplyTo'] },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0085' },
    // --- C. Response encryption, custom ---------------------------------
    { what: 'C. response encryption: wst:RequestedSecurityToken alone',
      maps: { wstrustEncryptResponseElements:
                [RSTR + 'wst:RequestedSecurityToken'] },
      sign: SIGN_BODY, encrypt: null, enc: ['RequestedSecurityToken'] },
    { what: 'C. response encryption: wst:Lifetime, by //',
      maps: { wstrustEncryptResponseElements: ['//wst:Lifetime'] },
      sign: SIGN_BODY, encrypt: null, enc: ['Lifetime'] },
    { what: 'C. response encryption: an expression that matches nothing',
      maps: { wstrustEncryptResponseElements: ['//wst:RequestedProofToken' +
                                               '/wst:Nothing'] },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0077' },
    // --- C. Response signing, custom ------------------------------------
    { what: 'C. response signing: wst:RequestedSecurityToken alone',
      maps: { wstrustSignResponseElements:
                [RSTR + 'wst:RequestedSecurityToken'] },
      sign: SIGN_BODY, encrypt: null,
      sig: ['Timestamp', 'RequestedSecurityToken'] },
    { what: 'C. response signing: wst:Lifetime and wsa:Action',
      maps: { wstrustSignResponseElements: ['//wst:Lifetime',
                                            H + 'wsa:Action'] },
      sign: SIGN_BODY, encrypt: null,
      sig: ['Timestamp', 'Lifetime', 'Action'] },
    { what: 'C. response signing: the security header itself is refused',
      maps: { wstrustSignResponseElements: ['//wsse:Security'] },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0086' },
    // --- C. The recipient expression ------------------------------------
    { what: 'C. recipient expression: a header the requester signed names ' +
            'the certificate the answer is encrypted to',
      recipientXPath: ENCRYPT_TO, extra: EXTRA,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: [{ local: 'Body' },
             { local: 'EncryptTo', ns: 'urn:example:wpm' }],
      encrypt: null, to: other,
      enc: ['RequestSecurityTokenResponseCollection'] },
    // THE REQUEST'S OWN SIGNING CERTIFICATE (rcbj, 2026-11-23): with no
    // certificate on the application and no expression, the answer is
    // encrypted to the certificate the request's signature names — the
    // BinarySecurityToken WSS4J wrote — and only that key opens it.
    { what: 'C. no certificate on the application and no expression: a ' +
            'request signed with the realm\'s message-signing ' +
            'certificate (digitalSignature only) gets no answer encrypted ' +
            'to it',
      recipientNone: true,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0077' },
    // THE KEYUSAGE WAIVER (rcbj, 2026-11-24): the application may have its
    // answers encrypted to a certificate whose keyUsage does not permit it.
    { what: 'C. wstrustRecipientIgnoresKeyUsage TRUE: the answer is ' +
            'encrypted to the realm\'s digitalSignature-only signing ' +
            'certificate',
      recipientNone: true, ignoresKeyUsage: 'TRUE',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, to: 'signer',
      enc: ['RequestSecurityTokenResponseCollection'] },
    { what: 'C. wstrust.recipientIgnoresKeyUsage on for the realm, the ' +
            'application silent: the same',
      recipientNone: true, realmIgnoresKeyUsage: true,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, true),
              wstrustSignResponseElements: presets(
        'wstrustSignResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, to: 'signer',
      enc: ['RequestSecurityTokenResponseCollection', 'Action'],
      sig: ['Timestamp', 'Body'] },
    { what: 'C. the realm waives keyUsage and the application says FALSE: ' +
            'refused',
      recipientNone: true, realmIgnoresKeyUsage: true,
      ignoresKeyUsage: 'FALSE',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0077' },
    { what: 'C. wstrustRecipientIgnoresKeyUsage TRUE with a recipient ' +
            'expression naming the signer\'s BinarySecurityToken',
      recipientXPath: H + 'wsse:Security/wsse:BinarySecurityToken',
      ignoresKeyUsage: 'TRUE',
      maps: { wstrustEncryptResponseElements:
                ['//wst:RequestedSecurityToken'] },
      sign: SIGN_BODY, encrypt: null, to: 'signer',
      enc: ['RequestedSecurityToken'] },
    { what: 'C. no certificate on the application and no expression: the ' +
            'answer is encrypted to the request\'s signing certificate ' +
            '(the requester\'s own, stored on their entry, permitting ' +
            'keyEncipherment)',
      recipientNone: true, signer: 'dual',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, to: 'dual',
      enc: ['RequestSecurityTokenResponseCollection'] },
    { what: 'C. the request\'s signing certificate, Body and Header ' +
            'encrypted and the answer signed',
      recipientNone: true, signer: 'dual',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, true),
              wstrustSignResponseElements: presets(
        'wstrustSignResponseElements', true, true) },
      sign: SIGN_BODY, encrypt: null, to: 'dual',
      enc: ['RequestSecurityTokenResponseCollection', 'Action'],
      sig: ['Timestamp', 'Body', 'Action'] },
    { what: 'C. the request\'s signing certificate, with a custom ' +
            'expression and the request encrypted too',
      recipientNone: true, signer: 'dual',
      maps: { wstrustEncryptResponseElements:
                ['//wst:RequestedSecurityToken'],
              wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' }],
      to: 'dual', enc: ['RequestedSecurityToken'] },
    { what: 'C. no certificate, no expression, no signature: nothing names ' +
            'a recipient',
      recipientNone: true, product: false,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: null, encrypt: null, refused: 'STS-WSTRUST-0076' },
    // A RECIPIENT CHOSEN BY wstrustResponseRecipientXPath (rcbj,
    // 2026-11-23): the expression names the certificate element, and the
    // answer opens only with that certificate's key.
    { what: 'C. recipient expression naming the signer\'s own ' +
            'BinarySecurityToken',
      recipientXPath: H + 'wsse:Security/wsse:BinarySecurityToken',
      signer: 'dual',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, to: 'dual',
      enc: ['RequestSecurityTokenResponseCollection'] },
    { what: 'C. recipient expression naming a signed header\'s ' +
            'certificate, with a certificate on the application as well ' +
            '(the application\'s certificate wins)',
      recipientXPath: ENCRYPT_TO, extra: EXTRA, keepCertificate: true,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: [{ local: 'Body' },
             { local: 'EncryptTo', ns: 'urn:example:wpm' }],
      encrypt: null, enc: ['RequestSecurityTokenResponseCollection'] },
    { what: 'C. recipient expression naming a signed header\'s ' +
            'certificate, Body and Header encrypted and the answer signed',
      recipientXPath: ENCRYPT_TO, extra: EXTRA,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, true),
              wstrustSignResponseElements: presets(
        'wstrustSignResponseElements', true, false) },
      sign: [{ local: 'Body' },
             { local: 'EncryptTo', ns: 'urn:example:wpm' }],
      encrypt: null, to: other,
      enc: ['RequestSecurityTokenResponseCollection', 'Action'],
      sig: ['Timestamp', 'Body'] },
    { what: 'C. recipient expression that matches nothing',
      recipientXPath: H + "*[local-name()='Nothing']",
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0076' },
    { what: 'C. recipient expression: the same header unsigned is refused',
      recipientXPath: ENCRYPT_TO, extra: EXTRA,
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0081' },
    { what: 'C. recipient expression: an element that is not a ' +
            'certificate is refused',
      recipientXPath: H + 'wsa:To',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', true, false) },
      sign: SIGN_BODY, encrypt: null, refused: 'STS-WSTRUST-0076' },
    // --- D. Combinations ------------------------------------------------
    { what: 'D. request encryption: wsa:To and wsp:AppliesTo, two ' +
            'expressions in one map',
      maps: { wstrustEncryptRequestElements: [H + 'wsa:To',
                                              R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'To', ns: WSA, mode: 'Header' },
                { local: 'AppliesTo', ns: WSP, mode: 'Element' }] },
    { what: 'D. request encryption: the Body preset beside a custom header',
      maps: { wstrustEncryptRequestElements: presets(
        'wstrustEncryptRequestElements', true, false).concat(
        [H + 'wsa:MessageID']) },
      sign: SIGN_BODY,
      encrypt: [{ local: 'Body', mode: 'Content' },
                { local: 'MessageID', ns: WSA, mode: 'Header' }] },
    { what: 'D. request signing: the Header preset beside wst:TokenType',
      maps: { wstrustSignRequestElements: presets(
        'wstrustSignRequestElements', false, true).concat(
        [R + 'wst:TokenType']) },
      sign: presetParts(true, true, false).concat(
        [{ local: 'TokenType', ns: WST }]), encrypt: null },
    { what: 'D. request: wsa:MessageID signed and wsa:To encrypted, the ' +
            'RST\'s TokenType signed and its AppliesTo encrypted',
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID',
                                           R + 'wst:TokenType'],
              wstrustEncryptRequestElements: [H + 'wsa:To',
                                              R + 'wsp:AppliesTo'] },
      sign: [{ local: 'Body' }, { local: 'MessageID', ns: WSA },
             { local: 'TokenType', ns: WST }],
      encrypt: [{ local: 'To', ns: WSA, mode: 'Header' },
                { local: 'AppliesTo', ns: WSP, mode: 'Element' }] },
    { what: 'D. request: the same header block signed and then encrypted',
      maps: { wstrustSignRequestElements: [H + 'wsa:To'],
              wstrustEncryptRequestElements: [H + 'wsa:To'] },
      sign: [{ local: 'Body' }, { local: 'To', ns: WSA }],
      encrypt: [{ local: 'To', ns: WSA, mode: 'Header' }] },
    { what: 'D. request: a header block encrypted and then the RST\'s ' +
            'TokenType signed (encrypt-then-sign)',
      order: 'encrypt-then-sign',
      maps: { wstrustSignRequestElements: [R + 'wst:TokenType'],
              wstrustEncryptRequestElements: [H + 'wsa:To'] },
      sign: [{ local: 'Body' }, { local: 'TokenType', ns: WST }],
      encrypt: [{ local: 'To', ns: WSA, mode: 'Header' }] },
    { what: 'D. response: wst:RequestedSecurityToken encrypted and ' +
            'wst:Lifetime signed',
      maps: { wstrustEncryptResponseElements: ['//wst:RequestedSecurityToken'],
              wstrustSignResponseElements: ['//wst:Lifetime'] },
      sign: SIGN_BODY, encrypt: null, enc: ['RequestedSecurityToken'],
      sig: ['Timestamp', 'Lifetime'] },
    { what: 'D. response: the same element signed and then encrypted',
      maps: { wstrustEncryptResponseElements: ['//wst:RequestedSecurityToken'],
              wstrustSignResponseElements: ['//wst:RequestedSecurityToken'] },
      sign: SIGN_BODY, encrypt: null, enc: ['RequestedSecurityToken'],
      sig: ['Timestamp', 'RequestedSecurityToken'] },
    { what: 'D. response: one element encrypted and then another signed ' +
            '(encrypt-then-sign)',
      responseOrder: 'encrypt-then-sign',
      maps: { wstrustEncryptResponseElements: ['//wst:RequestedSecurityToken'],
              wstrustSignResponseElements: ['//wst:Lifetime'] },
      sign: SIGN_BODY, encrypt: null, enc: ['RequestedSecurityToken'],
      sig: ['Timestamp', 'Lifetime'] },
    { what: 'D. response: custom signing and encryption with the signature ' +
            'encrypted too',
      encryptSignature: true,
      maps: { wstrustEncryptResponseElements: ['//wst:RequestedSecurityToken'],
              wstrustSignResponseElements: ['//wst:Lifetime',
                                            H + 'wsa:Action'] },
      sign: SIGN_BODY, encrypt: null,
      enc: ['RequestedSecurityToken', 'Signature'],
      sig: ['Timestamp', 'Lifetime', 'Action'] },
    { what: 'D. response: the Header preset beside a custom ' +
            'wst:RequestedSecurityToken, both maps',
      maps: { wstrustEncryptResponseElements: presets(
        'wstrustEncryptResponseElements', false, true).concat(
        ['//wst:RequestedSecurityToken']),
              wstrustSignResponseElements: presets(
        'wstrustSignResponseElements', false, true).concat(
        ['//wst:Lifetime']) },
      sign: SIGN_BODY, encrypt: null,
      enc: ['Action', 'RequestedSecurityToken'],
      sig: ['Timestamp', 'Action', 'Lifetime'] },
    { what: 'D. all four maps custom at once',
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID'],
              wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'],
              wstrustSignResponseElements: ['//wst:Lifetime'],
              wstrustEncryptResponseElements:
                ['//wst:RequestedSecurityToken'] },
      sign: [{ local: 'Body' }, { local: 'MessageID', ns: WSA }],
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' }],
      enc: ['RequestedSecurityToken'], sig: ['Timestamp', 'Lifetime'] },
    { what: 'D. all four maps custom, with the recipient by expression',
      recipientXPath: ENCRYPT_TO, extra: EXTRA,
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID'],
              wstrustEncryptRequestElements: [H + 'wsa:To'],
              wstrustSignResponseElements: ['//wst:Lifetime'],
              wstrustEncryptResponseElements:
                ['//wst:RequestedSecurityToken'] },
      sign: [{ local: 'Body' }, { local: 'MessageID', ns: WSA },
             { local: 'EncryptTo', ns: 'urn:example:wpm' }],
      encrypt: [{ local: 'To', ns: WSA, mode: 'Header' }], to: other,
      enc: ['RequestedSecurityToken'], sig: ['Timestamp', 'Lifetime'] },
    { what: 'D. SOAP 1.1: all four maps custom at once', soap: '1.1',
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID'],
              wstrustEncryptRequestElements: [R + 'wsp:AppliesTo',
                                              H + 'wsa:To'],
              wstrustSignResponseElements: ['//wst:Lifetime',
                                            H + 'wsa:Action'],
              wstrustEncryptResponseElements:
                ['//wst:RequestedSecurityToken'] },
      sign: [{ local: 'Body' }, { local: 'MessageID', ns: WSA }],
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' },
                { local: 'To', ns: WSA, mode: 'Header' }],
      enc: ['RequestedSecurityToken'],
      sig: ['Timestamp', 'Lifetime', 'Action'] },
    { what: 'D. the recipient by each key reference WSS4J writes: ' +
            'DirectReference', keyIdentifier: 'DirectReference',
      maps: { wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' }] },
    { what: 'D. the recipient by each key reference WSS4J writes: SKI',
      keyIdentifier: 'SKI',
      maps: { wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' }] },
    { what: 'D. the recipient by each key reference WSS4J writes: ' +
            'Thumbprint', keyIdentifier: 'Thumbprint',
      maps: { wstrustEncryptRequestElements: [R + 'wsp:AppliesTo'] },
      sign: SIGN_BODY,
      encrypt: [{ local: 'AppliesTo', ns: WSP, mode: 'Element' }] }
  ];
  // -------------------------------------------------------------------------
  // F. SIGNING AND ENCRYPTION MIXED, BOTH WAYS (rcbj, 2026-11-23): the
  // request signed and encrypted in either order, the answer signed and
  // encrypted in either order or with its signature encrypted too, each
  // with every map on — the Body and Header presets, and custom
  // expressions. Encrypt-then-sign on a request signs what is there once
  // encrypted: the Body (its content ciphertext) and each EncryptedHeader,
  // which the service holds to be the signed header once it is open.
  // -------------------------------------------------------------------------
  const WSSE11 = 'http://docs.oasis-open.org/wss/' +
    'oasis-wss-wssecurity-secext-1.1.xsd';
  const STYLES = {
    presets: {
      maps: { wstrustSignRequestElements: presets(
                'wstrustSignRequestElements', true, true),
              wstrustEncryptRequestElements: presets(
                'wstrustEncryptRequestElements', true, true),
              wstrustSignResponseElements: presets(
                'wstrustSignResponseElements', true, true),
              wstrustEncryptResponseElements: presets(
                'wstrustEncryptResponseElements', true, true) },
      sign: { 'sign-then-encrypt': presetParts(true, true, false),
              'encrypt-then-sign': [{ local: 'Body' },
                                    { local: 'EncryptedHeader',
                                      ns: WSSE11 }] },
      encrypt: presetParts(true, true, true),
      enc: ['RequestSecurityTokenResponseCollection', 'Action'],
      sig: ['Timestamp', 'Body', 'Action']
    },
    custom: {
      maps: { wstrustSignRequestElements: [H + 'wsa:MessageID'],
              wstrustEncryptRequestElements: [H + 'wsa:To',
                                              R + 'wsp:AppliesTo'],
              wstrustSignResponseElements: ['//wst:Lifetime',
                                            H + 'wsa:Action'],
              wstrustEncryptResponseElements:
                ['//wst:RequestedSecurityToken'] },
      sign: { 'sign-then-encrypt': [{ local: 'Body' },
                                    { local: 'MessageID', ns: WSA }],
              'encrypt-then-sign': [{ local: 'Body' },
                                    { local: 'MessageID', ns: WSA }] },
      encrypt: [{ local: 'To', ns: WSA, mode: 'Header' },
                { local: 'AppliesTo', ns: WSP, mode: 'Element' }],
      enc: ['RequestedSecurityToken'],
      sig: ['Timestamp', 'Lifetime', 'Action']
    }
  };
  ['presets', 'custom'].forEach(function (style) {
    ['sign-then-encrypt', 'encrypt-then-sign'].forEach(function (inOrder) {
      [{ order: '', encSig: false, label: 'signed then encrypted' },
       { order: 'encrypt-then-sign', encSig: false,
         label: 'encrypted then signed' },
       { order: '', encSig: true,
         label: 'signed then encrypted, the signature encrypted too' }]
        .forEach(function (out) {
          const st = STYLES[style];
          // An answer encrypted first is signed over what is then there:
          // the Header preset names the wsse11:EncryptedHeader that now
          // holds wsa:Action.
          const sig = out.order === 'encrypt-then-sign' && style === 'presets'
            ? ['Timestamp', 'Body', 'EncryptedHeader'] : st.sig;
          cases.push({
            what: 'F. ' + style + ': the request ' + inOrder.replace(
              /-/g, ' ') + ', the answer ' + out.label,
            order: inOrder, responseOrder: out.order,
            encryptSignature: out.encSig, maps: st.maps,
            sign: st.sign[inOrder], encrypt: st.encrypt,
            enc: st.enc.concat(out.encSig ? ['Signature'] : []), sig: sig });
        });
    });
  });
  const builtCases = batch(cases.map(function (c) {
    const soap = c.soap || '1.2';
    return protectItem(envelope(soap, c.extra), c.sign, c.encrypt,
                       { order: c.order === 'encrypt-then-sign'
                           ? 'encrypt-then-sign' : 'sign-then-encrypt',
                         keyIdentifier: c.keyIdentifier,
                         signer: c.signer });
  }));
  const caseAnswers = [];
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const soap = c.soap || '1.2';
    const maps = {};
    Object.keys(c.maps).forEach(function (map) {
      maps[map] = c.maps[map].map(function (expr) {
        return xp(soap, expr);
      });
    });
    configure(maps);
    set('wstrustEncryptionCertificate',
        (c.recipientXPath && !c.keepCertificate) || c.recipientNone
          ? '' : recipient.certPem);
    set('wstrustResponseRecipientXPath', c.recipientXPath
      ? xp(soap, c.recipientXPath) : '');
    set('wstrustResponseProtectionOrder', c.responseOrder || '');
    set('wstrustEncryptSignature', c.encryptSignature ? 'TRUE' : '');
    set('wstrustRecipientIgnoresKeyUsage', c.ignoresKeyUsage || '');
    if (c.realmIgnoresKeyUsage) {
      config.setOverride('wstrust.recipientIgnoresKeyUsage', 'true');
    }
    // The requester's own certificate names no revocation source
    // (wstrust_message_signature E7's arrangement).
    if (c.signer === 'dual') {
      config.setOverride('pki.revocationRequireDistributionPoint', 'off');
    }
    try {
      caseAnswers.push(builtCases[i] && builtCases[i].ok
        ? await ask(soap, String(builtCases[i].xml),
                    c.product === false ? 'development' : 'product')
        : { status: 0, body: JSON.stringify(builtCases[i]) });
    } finally {
      config.clearOverride('wstrust.recipientIgnoresKeyUsage');
      config.clearOverride('pki.revocationRequireDistributionPoint');
    }
  }
  configure({});
  set('wstrustEncryptionCertificate', recipient.certPem);
  set('wstrustResponseRecipientXPath', '');
  set('wstrustResponseProtectionOrder', '');
  set('wstrustEncryptSignature', '');
  set('wstrustRecipientIgnoresKeyUsage', '');
  const caseOpened = batch(cases.map(function (c, i) {
    return verifyItem(caseAnswers[i].status === 200 ? caseAnswers[i].body
                                                    : '<x/>', c.to);
  }));
  cases.forEach(function (c, i) {
    const r = caseAnswers[i];
    const got = caseOpened[i] || {};
    const problems = [];
    if (c.refused) {
      if (!(r.status === 500 && r.errorCode === c.refused)) {
        problems.push('wanted ' + c.refused + ': ' + brief(r));
      }
    } else if (r.status !== 200) {
      problems.push('not answered: ' + brief(r));
    } else if (!got.ok) {
      problems.push('WSS4J refused the answer: ' + got.message);
    } else {
      const enc = namesOf(got, 'encryption');
      const sig = namesOf(got, 'signature');
      if (!same(enc, c.enc || [])) {
        problems.push('WSS4J decrypted ' + JSON.stringify(enc) +
                      ', wanted ' + JSON.stringify(c.enc || []));
      }
      if (!same(sig, c.sig || [])) {
        problems.push('WSS4J found signed ' + JSON.stringify(sig) +
                      ', wanted ' + JSON.stringify(c.sig || []));
      }
      const clear = clearNames(r.body);
      (c.enc || []).forEach(function (name) {
        if (name !== 'Signature' && clear.indexOf(name) >= 0) {
          problems.push(name + ' was readable before it was opened');
        }
      });
      if (String(got.xml).indexOf(USER) < 0) {
        problems.push('the opened answer carries no token for ' + USER);
      }
      if (c.to) {
        const wrong = wss4j('verify', verifyItem(r.body, recipient));
        if (wrong.ok) {
          problems.push('the answer opened with the application\'s ' +
                        'recipient key too');
        }
      }
    }
    t.check(!problems.length, c.what + (c.refused ? ' (refused ' +
              c.refused + ')' : ''),
            problems.join('; ') + (problems.length ? ' — request: ' +
              String((builtCases[i] && builtCases[i].xml) || '')
                .slice(0, 1500) : ''));
  });

  // -------------------------------------------------------------------------
  // E. A TAMPERED ANSWER
  // -------------------------------------------------------------------------
  configure({ wstrustSignResponseElements: presets(
    'wstrustSignResponseElements', true, true) });
  const tamperBuilt = batch([protectItem(envelope('1.2'), SIGN_BODY, null)]);
  const answered = await ask('1.2', String(tamperBuilt[0].xml));
  const altered = String(answered.body).replace(/(<saml:Issuer[^>]*>)/,
                                                '$1x');
  const tamper = batch([verifyItem(answered.body), verifyItem(altered)]);
  t.check(answered.status === 200 && tamper[0].ok && altered !==
            String(answered.body) && tamper[1].ok === false,
          'E. WSS4J verifies the signed answer and refuses it once the Body ' +
          'is altered', JSON.stringify(tamper.map(function (one) {
            return one.ok ? 'ok' : one.message;
          })));
  configure({});
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
  // THE ROWS COME BACK IN A FILE: several hundred rows with their details
  // are more than a pipe holds, and a child that exits once it has written
  // to one loses what node had not yet flushed.
  const out = path.join(require('os').tmpdir(), 'wstrust-matrix-' +
    process.pid + '-' + nodeCrypto.randomBytes(8).toString('hex') + '.json');
  clean[CHILD_FLAG] = '1';
  clean.STS_WSTRUST_MATRIX_OUT = out;
  clean.LOG_LEVEL = process.env.LOG_LEVEL === 'debug' ? 'debug' : 'info';
  clean.STS_HTTPS = 'false';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 1800000,
    maxBuffer: 256 * 1024 * 1024
  });
  let line = '';
  try {
    line = MARK + require('fs').readFileSync(out, 'utf8');
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
    // No file: the child died before writing one, reported below.
    line = '';
  }
  try {
    require('fs').unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
  }
  // The timings the child logged, for whoever reads the run.
  String(result.stdout || '').split('\n').forEach(function (one) {
    if (/"msg":"A\. SOAP/.test(one)) {
      log.info(JSON.parse(one).msg);
    }
  });
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
    require('fs').writeFileSync(process.env.STS_WSTRUST_MATRIX_OUT,
                                JSON.stringify(rows));
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'wstrust_protection_matrix',
  describe: 'WS-Trust message protection: every combination of the Whole ' +
            'SOAP Body / Header boxes, and custom expressions in each field ' +
            'and in combination, with requests WSS4J signs and encrypts and ' +
            'answers WSS4J opens and verifies (#2046)',
  run: run
};
