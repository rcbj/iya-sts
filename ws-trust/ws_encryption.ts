// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws_encryption.ts
//
// XML Encryption of a WS-Trust request and response (#1668). Which elements,
// and which certificate a response is encrypted to, are the application's.
// The two switches override wstrust.encryptRequest and wstrust.encryptResponse.
// A library: it registers nothing and does not require ws-trust/wstrust.ts.

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import applications = require('../common/applications');
import config = require('../common/config');
import mode = require('../common/mode');
import DomainMap = require('../common/domain_map');
import CertificateTrust = require('../common/certificate_trust');
import xmldom = require('../common/xml_parser');

const { DOMParser, XMLSerializer } = xmldom;
const log = helpers.log;

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const ELEMENT = XENC + 'Element';
const CONTENT = XENC + 'Content';
// WS-Security 1.1's own namespace, where EncryptedHeader is.
const WSSE11 = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-wssecurity-secext-1.1.xsd';
// The holder a decrypted fragment is parsed in, never sent.
const FRAGMENT = 'urn:iya-sts:ws-encryption:fragment';
const HOLDER = 'iyaWsEncryptionHolder';

// Prefixes a WS-Trust message uses, applied only when the element does not
// declare them. An unprefixed name still matches the null namespace only,
// which is what XPath 1.0 does with a name test.
const PREFIXES = {
  soap: 'http://schemas.xmlsoap.org/soap/envelope/',
  soap12: 'http://www.w3.org/2003/05/soap-envelope',
  wsse: 'http://docs.oasis-open.org/wss/2004/01/' +
    'oasis-200401-wss-wssecurity-secext-1.0.xsd',
  wsu: 'http://docs.oasis-open.org/wss/2004/01/' +
    'oasis-200401-wss-wssecurity-utility-1.0.xsd',
  wst: 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
  wsa: 'http://www.w3.org/2005/08/addressing',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  ds: DS,
  xenc: XENC,
  wsp: 'http://schemas.xmlsoap.org/ws/2004/09/policy'
};

const NOT_AN_ELEMENT = {
  thumbprint: true, ski: true, 'issuer-serial': true,
  kerberos: true, 'kerberos-id': true
};

/**
 * XML Encryption for one WS-Trust exchange: open a request, choose the
 * response recipient, and replace the named response elements.
 */
export = class WsEncryption {
  /**
   * Opens every encrypted element of a request, then holds it to the
   * application's map where the application's request switch is on.
   *
   * ENCRYPTION IS OPTIONAL ON THE WIRE (rcbj on #1908, 2026-11-18): the
   * WSDL's policy tells a WS-SecurityPolicy client that any header or the
   * Body may be encrypted, so whatever arrives encrypted to this realm is
   * opened whether or not a switch is on. The switch makes it REQUIRED:
   * each expression of the application's map must match an element that
   * arrived encrypted. Until then a wholly encrypted request was opened
   * only under the service-wide switch, and one for an application whose
   * switch was off was a fault, so a client following the policy was
   * refused by default.
   *
   * @param doc - the request document, modified in place
   * @returns ok, or the fault
   */
  static openRequest(doc): any {
    log.debug("Entering WsEncryption.openRequest().");
    if (WsEncryption.hasCiphertext(doc)) {
      const opened = WsEncryption.decryptAll(doc);
      if (!opened.ok) {
        log.debug("Leaving WsEncryption.openRequest(). It would not open.");
        return opened;
      }
    }
    // The application is read from the opened request: an AppliesTo inside
    // the ciphertext names it only now.
    const appId = WsEncryption.applicationId(doc);
    if (!WsEncryption.on(appId, 'wstrust.encryptRequest')) {
      log.debug("Leaving WsEncryption.openRequest(). Not required.");
      return { ok: true };
    }
    const held = WsEncryption.enforce(doc,
      WsEncryption.stringsOf(appId, 'requestElements'));
    log.debug("Leaving WsEncryption.openRequest(). " + held.ok);
    return held;
  }

  /**
   * Tells whether a document carries an element encrypted the ways this
   * service opens: an `xenc:EncryptedData` of type Element or Content, on
   * its own or inside a WS-Security 1.1 `EncryptedHeader`.
   *
   * @param doc - the document
   * @returns true when there is something to open
   */
  static hasCiphertext(doc): boolean {
    log.debug("Entering WsEncryption.hasCiphertext().");
    const found = !!doc && WsEncryption.ciphertexts(doc).length > 0;
    log.debug("Leaving WsEncryption.hasCiphertext(). " + found);
    return found;
  }

  /**
   * A copy of the request with every encrypted element opened, for reading
   * a signature that was made before the encryption (WS-SecurityPolicy's
   * default protection order, SignBeforeEncrypting), or that was itself
   * encrypted. The request is not changed and no map is applied.
   *
   * @param doc - the request as it arrived
   * @returns the opened copy, or null when it would not open
   */
  static openedCopy(doc): any {
    log.debug("Entering WsEncryption.openedCopy().");
    let copy;
    try {
      copy = new DOMParser().parseFromString(
        new XMLSerializer().serializeToString(doc), 'text/xml');
    } catch (e) {
      log.debug("Caught in WsEncryption.openedCopy(): " +
                ((e && e.message) || e));
      // A document that will not round-trip has no other reading.
      log.debug("Leaving WsEncryption.openedCopy(). Unreadable.");
      return null;
    }
    const opened = WsEncryption.decryptAll(copy);
    log.debug("Leaving WsEncryption.openedCopy(). " + opened.ok);
    return opened.ok ? copy : null;
  }

  /**
   * Which document a request's WS-Security signature is read from first.
   * WS-Security 1.1 section 5.2 and WS-SecurityPolicy 1.3 section 6.5: the
   * security header's elements are prepended as each step is taken, so a
   * receiver takes them in order. An EncryptedKey, a ReferenceList or an
   * EncryptedData ahead of the ds:Signature, or no ds:Signature to be seen,
   * means the signature was made before the encryption and is read from
   * the opened copy. Otherwise it is read as the message arrived. The
   * caller tries the other reading when the first does not verify, because
   * an EncryptedData carrying its own key sits in no header at all.
   *
   * @param doc - the request as it arrived
   * @returns true when the opened copy is read first
   */
  static decryptsBeforeVerifying(doc): boolean {
    log.debug("Entering WsEncryption.decryptsBeforeVerifying().");
    if (!WsEncryption.hasCiphertext(doc)) {
      log.debug("Leaving WsEncryption.decryptsBeforeVerifying(). Clear.");
      return false;
    }
    const security = helpers.firstByLocal(doc, 'Security');
    const kids = (security && security.childNodes) || [];
    for (let i = 0; i < kids.length; i++) {
      const kid = kids[i];
      if (kid.nodeType !== 1) {
        continue;
      }
      if (kid.localName === 'Signature' && kid.namespaceURI === DS) {
        log.debug("Leaving WsEncryption.decryptsBeforeVerifying(). The " +
                  "signature comes first.");
        return false;
      }
      if (kid.namespaceURI === XENC || kid.localName === 'EncryptedHeader') {
        log.debug("Leaving WsEncryption.decryptsBeforeVerifying(). " +
                  kid.localName + " comes first.");
        return true;
      }
    }
    log.debug("Leaving WsEncryption.decryptsBeforeVerifying(). No " +
              "signature in the clear.");
    return true;
  }

  /**
   * Replaces the named elements of a response. The body is unchanged when
   * response encryption is off. A map that does not match — empty, or an
   * expression that selects nothing — is a fault. The caller returns that
   * fault in the clear and does not send the response.
   *
   * @param xml - the clear response
   * @param requestDoc - the request, where the recipient is read
   * @param appId - the AppliesTo's application, or ''
   * @returns `{ ok, xml }` or the fault
   */
  static protectResponse(xml, requestDoc, appId): any {
    log.debug("Entering WsEncryption.protectResponse().");
    const id = String(appId || '');
    if (!WsEncryption.on(id, 'wstrust.encryptResponse')) {
      log.debug("Leaving WsEncryption.protectResponse(). Off.");
      return { ok: true, xml: xml };
    }
    const paths = WsEncryption.stringsOf(id, 'responseElements');
    if (!paths.length) {
      log.debug("Leaving WsEncryption.protectResponse(). No expressions.");
      return WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
        'response encryption is on and no element is named');
    }
    const recipient = WsEncryption.recipientOf(requestDoc, id);
    if (!recipient.ok) {
      log.debug("Leaving WsEncryption.protectResponse(). No recipient.");
      return recipient;
    }
    const held = CertificateTrust.pinnedSync('encryption-recipient',
                                             recipient.pem);
    if (!held.ok) {
      log.debug("Leaving WsEncryption.protectResponse(). Refused.");
      return WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
        'the recipient certificate is refused: ' + held.why);
    }
    let response;
    try {
      response = new DOMParser().parseFromString(String(xml), 'text/xml');
    } catch (e) {
      log.debug("Caught in WsEncryption.protectResponse(): " +
                ((e && e.message) || e));
      // The envelope this service just built did not parse, so there is
      // nothing that can be encrypted.
      log.debug("Leaving WsEncryption.protectResponse(). Unreadable.");
      return WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
        'the response could not be read for encryption');
    }
    const sealed = WsEncryption.seal(response, paths, recipient.pem, id);
    if (!sealed.ok) {
      log.debug("Leaving WsEncryption.protectResponse(). Not sealed.");
      return sealed;
    }
    log.debug("Leaving WsEncryption.protectResponse(). Sealed.");
    return { ok: true,
             xml: new XMLSerializer().serializeToString(response) };
  }

  /**
   * Refuses wst:EncryptionAlgorithm or wst:EncryptWith when response
   * encryption is off, or when the name is not the configured one.
   *
   * @param doc - the request
   * @param appId - the AppliesTo's application, or ''
   * @returns ok, or STS-WSTRUST-0078
   */
  static beyondPolicy(doc, appId): any {
    log.debug("Entering WsEncryption.beyondPolicy().");
    const ciphers = WsEncryption.texts(doc, 'EncryptionAlgorithm');
    const transports = WsEncryption.texts(doc, 'EncryptWith');
    if (!ciphers.length && !transports.length) {
      log.debug("Leaving WsEncryption.beyondPolicy(). Neither element.");
      return { ok: true };
    }
    const id = String(appId || '');
    if (!WsEncryption.on(id, 'wstrust.encryptResponse')) {
      log.debug("Leaving WsEncryption.beyondPolicy(). Encryption is off.");
      return WsEncryption.fail('STS-WSTRUST-0078', 'InvalidRequest',
        'the request names an encryption algorithm and response ' +
        'encryption is off');
    }
    const cipher = WsEncryption.effectiveCipher(id);
    const transport = WsEncryption.effectiveTransport(id);
    for (let i = 0; i < ciphers.length; i++) {
      if (!WsEncryption.sameCipher(ciphers[i], cipher)) {
        log.debug("Leaving WsEncryption.beyondPolicy(). The cipher.");
        return WsEncryption.fail('STS-WSTRUST-0078', 'InvalidRequest',
          'wst:EncryptionAlgorithm names "' + ciphers[i] +
          '", not ' + cipher);
      }
    }
    for (let i = 0; i < transports.length; i++) {
      if (!WsEncryption.sameTransport(transports[i], transport)) {
        log.debug("Leaving WsEncryption.beyondPolicy(). The transport.");
        return WsEncryption.fail('STS-WSTRUST-0078', 'InvalidRequest',
          'wst:EncryptWith names "' + transports[i] + '", not ' +
          transport);
      }
    }
    log.debug("Leaving WsEncryption.beyondPolicy(). As configured.");
    return { ok: true };
  }

  private static fail(code, trustFault, reason): any {
    log.debug("Entering WsEncryption.fail().");
    log.debug("Leaving WsEncryption.fail().");
    return { ok: false, code: code, trustFault: trustFault,
             reason: reason };
  }

  private static on(appId, key): boolean {
    log.debug("Entering WsEncryption.on().");
    const value = !!applications.settingFor(appId || '', key, config);
    log.debug("Leaving WsEncryption.on(). " + value);
    return value;
  }

  private static applicationId(doc): string {
    log.debug("Entering WsEncryption.applicationId().");
    const applies = helpers.firstByLocal(doc, 'AppliesTo');
    const address = applies
      ? (helpers.textByLocal(applies, 'Address') ||
         String(applies.textContent || '').trim()) : '';
    const found: any = address
      ? (applications.forAppliesTo(address) || applications.get(address))
      : null;
    const id = found ? String(found.identifier) : '';
    log.debug("Leaving WsEncryption.applicationId(). " + (id || 'none'));
    return id;
  }

  private static record(appId): any {
    log.debug("Entering WsEncryption.record().");
    const found = appId ? applications.get(appId) : null;
    log.debug("Leaving WsEncryption.record(). " + !!found);
    return found && found.fields ? found : null;
  }

  private static stringsOf(appId, field): string[] {
    log.debug("Entering WsEncryption.stringsOf().");
    const app = WsEncryption.record(appId);
    const value = app ? DomainMap.fieldOf('WsTrustRelyingParty', field,
                                          app.fields) : undefined;
    const list = Array.isArray(value) ? value : (value ? [value] : []);
    const out = list.map(function (one) {
      return String(one).trim();
    }).filter(function (one) {
      return !!one;
    });
    log.debug("Leaving WsEncryption.stringsOf(). " + out.length);
    return out;
  }

  private static stringOf(appId, field): string {
    log.debug("Entering WsEncryption.stringOf().");
    const app = WsEncryption.record(appId);
    const value = app ? DomainMap.fieldOf('WsTrustRelyingParty', field,
                                          app.fields) : '';
    const out = value == null ? '' : String(value).trim();
    log.debug("Leaving WsEncryption.stringOf().");
    return out;
  }

  // At most this many ciphertexts in one request, each a private-key
  // operation taken before the requester is authenticated.
  private static readonly MOST = 64;

  private static decryptAll(doc): any {
    log.debug("Entering WsEncryption.decryptAll().");
    let count = 0;
    for (let round = 0; round < 8; round++) {
      const nodes = WsEncryption.ciphertexts(doc);
      if (!nodes.length) {
        log.debug("Leaving WsEncryption.decryptAll(). Open.");
        return { ok: true };
      }
      count += nodes.length;
      if (count > WsEncryption.MOST) {
        log.debug("Leaving WsEncryption.decryptAll(). Too many.");
        return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
          'the request carries more than ' + WsEncryption.MOST +
          ' ciphertexts');
      }
      for (let i = 0; i < nodes.length; i++) {
        const replaced = WsEncryption.decryptOne(doc, nodes[i]);
        if (!replaced.ok) {
          log.debug("Leaving WsEncryption.decryptAll(). Refused.");
          return replaced;
        }
      }
    }
    log.debug("Leaving WsEncryption.decryptAll(). Nested too deep.");
    return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
      'the ciphertext is nested more than eight deep');
  }

  // XML Encryption 1.0 section 3.5.1's two types. An EncryptedData of no
  // other type is not an element this service can put back.
  private static ciphertexts(doc): any[] {
    log.debug("Entering WsEncryption.ciphertexts().");
    const all = doc.getElementsByTagNameNS(XENC, 'EncryptedData');
    const out = [];
    for (let i = 0; i < all.length; i++) {
      const type = String(all[i].getAttribute('Type') || '');
      if (type !== ELEMENT && type !== CONTENT) {
        continue;
      }
      if (!WsEncryption.insideEncrypted(all[i])) {
        out.push(all[i]);
      }
    }
    log.debug("Leaving WsEncryption.ciphertexts(). " + out.length);
    return out;
  }

  // Once per ancestor of a ciphertext. A debug line on each would bury the
  // request that asked to be opened.
  private static insideEncrypted(node): boolean {
    let cur = node.parentNode;
    while (cur) {
      if (cur.localName === 'EncryptedData' &&
          cur.namespaceURI === XENC) {
        return true;
      }
      cur = cur.parentNode;
    }
    return false;
  }

  // THE KEY, WHERE WS-SECURITY PUTS IT (WS-Security 1.1 section 9). An
  // EncryptedData may carry its own EncryptedKey in its KeyInfo, which is
  // what this service writes. A WS-SecurityPolicy sender (Apache WSS4J,
  // WCF, Metro) puts ONE EncryptedKey in the security header instead, its
  // ReferenceList naming every EncryptedData it opens, and the
  // EncryptedData's KeyInfo a SecurityTokenReference to it, or nothing.
  // Only an EncryptedKey in a wsse:Security header is looked for: one
  // anywhere else is somebody's content.
  private static headerKeyFor(doc, node): any {
    log.debug("Entering WsEncryption.headerKeyFor().");
    const keyInfo = WsEncryption.childNamed(node, DS, 'KeyInfo');
    if (keyInfo && WsEncryption.childNamed(keyInfo, XENC, 'EncryptedKey')) {
      log.debug("Leaving WsEncryption.headerKeyFor(). Its own.");
      return null;
    }
    const id = String(node.getAttribute('Id') ||
      node.getAttributeNS(PREFIXES.wsu, 'Id') || '');
    const str = keyInfo
      ? keyInfo.getElementsByTagNameNS(PREFIXES.wsse, 'Reference')[0] : null;
    const named = str ? String(str.getAttribute('URI') || '') : '';
    const keys = doc.getElementsByTagNameNS(XENC, 'EncryptedKey');
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const parent = key.parentNode;
      if (!parent || parent.localName !== 'Security' ||
          parent.namespaceURI !== PREFIXES.wsse) {
        continue;
      }
      const keyId = String(key.getAttribute('Id') ||
        key.getAttributeNS(PREFIXES.wsu, 'Id') || '');
      if (named && keyId && named === '#' + keyId) {
        log.debug("Leaving WsEncryption.headerKeyFor(). By reference.");
        return key;
      }
      const refs = key.getElementsByTagNameNS(XENC, 'DataReference');
      for (let r = 0; r < refs.length; r++) {
        if (id && String(refs[r].getAttribute('URI') || '') === '#' + id) {
          log.debug("Leaving WsEncryption.headerKeyFor(). Listed.");
          return key;
        }
      }
    }
    log.debug("Leaving WsEncryption.headerKeyFor(). None.");
    return null;
  }

  private static childNamed(node, ns, local): any {
    log.debug("Entering WsEncryption.childNamed().");
    const kids = (node && node.childNodes) || [];
    for (let i = 0; i < kids.length; i++) {
      if (kids[i].nodeType === 1 && kids[i].localName === local &&
          kids[i].namespaceURI === ns) {
        log.debug("Leaving WsEncryption.childNamed(). Found.");
        return kids[i];
      }
    }
    log.debug("Leaving WsEncryption.childNamed(). None.");
    return null;
  }

  // The namespace declarations in scope at a node, nearest first, as
  // `{ 'xmlns:p': uri }`: what a decrypted fragment inherits where it is
  // put back (XML Encryption 1.0 section 4.5, "in the context of").
  private static inScope(node): any {
    log.debug("Entering WsEncryption.inScope().");
    const declared = {};
    let cur = node;
    while (cur && cur.nodeType === 1) {
      const attrs = cur.attributes || [];
      for (let i = 0; i < attrs.length; i++) {
        const name = String(attrs[i].name || attrs[i].nodeName || '');
        if ((name === 'xmlns' || name.indexOf('xmlns:') === 0) &&
            !Object.prototype.hasOwnProperty.call(declared, name)) {
          declared[name] = String(attrs[i].value || '');
        }
      }
      cur = cur.parentNode;
    }
    log.debug("Leaving WsEncryption.inScope().");
    return declared;
  }

  private static decryptOne(doc, node): any {
    log.debug("Entering WsEncryption.decryptOne().");
    const parent = node.parentNode;
    // WS-Security 1.1 section 9.3: a header encrypted as a whole is an
    // EncryptedHeader holding the EncryptedData, and the header it opens to
    // takes the EncryptedHeader's place.
    const target = parent && parent.localName === 'EncryptedHeader' &&
      parent.namespaceURI === WSSE11 ? parent : node;
    const context = target.parentNode;
    const type = String(node.getAttribute('Type') || '');
    const key = WsEncryption.headerKeyFor(doc, node);
    const serializer = new XMLSerializer();
    // The header's EncryptedKey travels beside the EncryptedData, which is
    // the shape `crypto.decryptElement()` reads a separate key from (SAML
    // 2.0 core section 2.3.4's, for an EncryptedAssertion).
    const xml = key
      ? '<' + HOLDER + ':Ciphertext xmlns:' + HOLDER + '="' + FRAGMENT +
        '">' + serializer.serializeToString(key) +
        serializer.serializeToString(node) + '</' + HOLDER + ':Ciphertext>'
      : serializer.serializeToString(node);
    const namespaces = WsEncryption.inScope(context);
    const opened = helpers.decryptOwnElement(xml,
                                             { namespaces: namespaces });
    if (!opened || !opened.ok || !opened.xml) {
      log.debug("Leaving WsEncryption.decryptOne(). It did not open.");
      return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
        'a ciphertext would not open with this realm\'s keys' +
        (opened && opened.why ? ': ' + opened.why : ''));
    }
    const declared = Object.keys(namespaces).filter(function (name) {
      return name !== 'xmlns:' + HOLDER;
    }).map(function (name) {
      return ' ' + name + '="' + String(namespaces[name])
        .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
        .replace(/</g, '&lt;') + '"';
    }).join('');
    let parsed;
    try {
      parsed = new DOMParser().parseFromString('<' + HOLDER + ':Fragment ' +
        'xmlns:' + HOLDER + '="' + FRAGMENT + '"' + declared + '>' +
        String(opened.xml) + '</' + HOLDER + ':Fragment>', 'text/xml');
    } catch (e) {
      log.debug("Caught in WsEncryption.decryptOne(): " +
                ((e && e.message) || e));
      // The decrypted bytes are not XML, which is the same refusal as a
      // key that does not open them.
      log.debug("Leaving WsEncryption.decryptOne(). Not XML.");
      return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
        'a ciphertext opened to something that is not XML');
    }
    const holder = parsed && parsed.documentElement;
    if (!holder || holder.localName !== 'Fragment') {
      log.debug("Leaving WsEncryption.decryptOne(). Not a fragment.");
      return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
        'a ciphertext opened to something that is not XML');
    }
    const kids = [];
    for (let i = 0; i < holder.childNodes.length; i++) {
      kids.push(holder.childNodes[i]);
    }
    const elements = kids.filter(function (one) {
      return one.nodeType === 1;
    });
    const loose = kids.filter(function (one) {
      return one.nodeType !== 1 &&
        !(one.nodeType === 3 && !String(one.nodeValue || '').trim());
    });
    // Type Element is one element and nothing else (section 3.5.1); an
    // EncryptedHeader opens to one header.
    if ((type === ELEMENT || target !== node) &&
        (elements.length !== 1 || loose.length)) {
      log.debug("Leaving WsEncryption.decryptOne(). Not an element.");
      return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
        'a ciphertext opened to something that is not an element');
    }
    for (let i = 0; i < kids.length; i++) {
      const imported = doc.importNode(kids[i], true);
      if (imported.nodeType === 1) {
        imported._stsRestored = true;
      }
      context.insertBefore(imported, target);
    }
    context.removeChild(target);
    log.debug("Leaving WsEncryption.decryptOne(). Restored " +
              elements.length + ".");
    return { ok: true };
  }

  private static enforce(doc, paths): any {
    log.debug("Entering WsEncryption.enforce().");
    if (!paths.length) {
      log.debug("Leaving WsEncryption.enforce(). No expressions.");
      return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
        'request encryption is on and no element is named');
    }
    for (let i = 0; i < paths.length; i++) {
      const found = WsEncryption.select(doc, paths[i]);
      if (!found.ok) {
        log.debug("Leaving WsEncryption.enforce(). The expression.");
        return found;
      }
      if (!found.nodes.length) {
        log.debug("Leaving WsEncryption.enforce(). Nothing matched.");
        return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
          'the expression matched nothing that was encrypted');
      }
      for (let n = 0; n < found.nodes.length; n++) {
        if (!WsEncryption.wasRestored(found.nodes[n])) {
          log.debug("Leaving WsEncryption.enforce(). In the clear.");
          return WsEncryption.fail('STS-WSTRUST-0075', 'FailedCheck',
            'the expression matched an element that arrived in the clear');
        }
      }
    }
    log.debug("Leaving WsEncryption.enforce(). Held.");
    return { ok: true };
  }

  // Once per ancestor. The same reason as insideEncrypted().
  private static wasRestored(node): boolean {
    let cur = node;
    while (cur) {
      if (cur._stsRestored) {
        return true;
      }
      cur = cur.parentNode;
    }
    return false;
  }

  private static recipientOf(doc, appId): any {
    log.debug("Entering WsEncryption.recipientOf().");
    const explicit = WsEncryption.stringOf(appId, 'encryptionCertificate');
    if (explicit) {
      const pem = WsEncryption.pemOf(explicit);
      log.debug("Leaving WsEncryption.recipientOf(). The certificate " +
                "on the application.");
      return pem ? { ok: true, pem: pem }
        : WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
            'wstrustEncryptionCertificate is not a certificate');
    }
    const xpath = WsEncryption.stringOf(appId, 'responseRecipientXPath');
    if (xpath) {
      const found = WsEncryption.select(doc, xpath);
      if (!found.ok) {
        log.debug("Leaving WsEncryption.recipientOf(). The expression.");
        return found;
      }
      const shaped = found.nodes.length
        ? WsEncryption.certificateElement(found.nodes[0]) : null;
      log.debug("Leaving WsEncryption.recipientOf(). The expression's " +
                "element.");
      if (!shaped) {
        return WsEncryption.fail('STS-WSTRUST-0076', 'InvalidRequest',
          'the recipient expression did not select a certificate element');
      }
      // The element is a certificate element. Text that is not a certificate
      // is a completed-encryption fault, and the next source is not tried.
      return shaped.pem ? { ok: true, pem: shaped.pem }
        : WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
            'the selected element is not a certificate');
    }
    const named = WsEncryption.signerCertificate(doc);
    log.debug("Leaving WsEncryption.recipientOf(). The signer.");
    return named ? { ok: true, pem: named }
      : WsEncryption.fail('STS-WSTRUST-0076', 'InvalidRequest',
          'the request\'s signature names no certificate element');
  }

  private static signerCertificate(doc): string {
    log.debug("Entering WsEncryption.signerCertificate().");
    let reading: any = null;
    try {
      reading = stsCrypto.readWsSecuritySignature(
        new XMLSerializer().serializeToString(doc));
    } catch (e) {
      log.debug("Caught in WsEncryption.signerCertificate(): " +
                ((e && e.message) || e));
      // A document that cannot be serialized has no signature to read.
      log.debug("Leaving WsEncryption.signerCertificate(). Unreadable.");
      return '';
    }
    if (!reading || !reading.present || !reading.ok) {
      log.debug("Leaving WsEncryption.signerCertificate(). No signature.");
      return '';
    }
    const reference = reading.keyReference || {};
    const kind = String(reference.kind || '');
    if (NOT_AN_ELEMENT[kind]) {
      log.debug("Leaving WsEncryption.signerCertificate(). " + kind +
                " is not an element.");
      return '';
    }
    if (kind === 'token' && reference.certB64) {
      log.debug("Leaving WsEncryption.signerCertificate(). The token.");
      return WsEncryption.pemOf(reference.certB64);
    }
    const pem = WsEncryption.inlineCertificate(doc);
    log.debug("Leaving WsEncryption.signerCertificate(). " + !!pem);
    return pem;
  }

  private static inlineCertificate(doc): string {
    log.debug("Entering WsEncryption.inlineCertificate().");
    const security = helpers.firstByLocal(doc, 'Security');
    const kids = (security && security.childNodes) || [];
    for (let i = 0; i < kids.length; i++) {
      const kid = kids[i];
      if (kid.nodeType === 1 && kid.localName === 'Signature' &&
          kid.namespaceURI === DS) {
        const certs = kid.getElementsByTagNameNS(DS, 'X509Certificate');
        if (certs.length) {
          log.debug("Leaving WsEncryption.inlineCertificate(). Found.");
          return WsEncryption.pemOf(certs[0].textContent);
        }
      }
    }
    log.debug("Leaving WsEncryption.inlineCertificate(). None.");
    return '';
  }

  // A certificate-shaped element is { element: true, pem }, with pem empty
  // when the text is not a certificate this process can read. Anything else
  // is null: no recipient element (0076), distinct from a certificate
  // element whose text will not parse (0077).
  private static certificateElement(node): any {
    log.debug("Entering WsEncryption.certificateElement().");
    if (!node || node.nodeType !== 1) {
      log.debug("Leaving WsEncryption.certificateElement(). Not an element.");
      return null;
    }
    const valueType = String(node.getAttribute('ValueType') || '');
    const shaped = (node.localName === 'X509Certificate' &&
        (node.namespaceURI === DS || !node.namespaceURI)) ||
      (node.localName === 'BinarySecurityToken' &&
        /#X509v3$/.test(valueType));
    if (!shaped) {
      log.debug("Leaving WsEncryption.certificateElement(). Neither.");
      return null;
    }
    const pem = WsEncryption.pemOf(node.textContent);
    log.debug("Leaving WsEncryption.certificateElement(). " + !!pem);
    return { element: true, pem: pem };
  }

  private static pemOf(text): string {
    log.debug("Entering WsEncryption.pemOf().");
    const raw = String(text || '').trim();
    if (!raw) {
      log.debug("Leaving WsEncryption.pemOf(). Empty.");
      return '';
    }
    const body = raw.indexOf('BEGIN CERTIFICATE') >= 0 ? raw
      : ('-----BEGIN CERTIFICATE-----\n' +
         (raw.replace(/\s+/g, '').match(/.{1,64}/g) || []).join('\n') +
         '\n-----END CERTIFICATE-----\n');
    try {
      // Parsed by crypto.js, the one module that touches node's crypto
      // (tests/crypto_centralised.js).
      const cert = stsCrypto.parseCertificate(body);
      if (!cert.publicKey) {
        log.debug("Leaving WsEncryption.pemOf(). No key.");
        return '';
      }
    } catch (e) {
      log.debug("Caught in WsEncryption.pemOf(): " +
                ((e && e.message) || e));
      // Not a certificate this process can read. Empty tells the caller
      // the step cannot be used.
      log.debug("Leaving WsEncryption.pemOf(). Unreadable.");
      return '';
    }
    log.debug("Leaving WsEncryption.pemOf(). Read.");
    return body;
  }

  private static seal(doc, paths, pem, appId): any {
    log.debug("Entering WsEncryption.seal().");
    const algorithm = String(applications.settingFor(appId,
      'wstrust.encryptionAlgorithm', config) || '');
    const keyTransport = String(applications.settingFor(appId,
      'wstrust.keyTransportAlgorithm', config) || '');
    const chosen = [];
    for (let i = 0; i < paths.length; i++) {
      const found = WsEncryption.select(doc, paths[i]);
      if (!found.ok) {
        log.debug("Leaving WsEncryption.seal(). The expression.");
        return found;
      }
      if (!found.nodes.length) {
        log.debug("Leaving WsEncryption.seal(). Nothing matched.");
        return WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
          'the response expression matched nothing');
      }
      for (let n = 0; n < found.nodes.length; n++) {
        chosen.push(found.nodes[n]);
      }
    }
    const ordered = WsEncryption.inOrder(chosen).sort(function (a, b) {
      return WsEncryption.depth(b) - WsEncryption.depth(a);
    });
    for (let i = 0; i < ordered.length; i++) {
      const node = ordered[i];
      if (!node.parentNode) {
        continue;
      }
      try {
        const plain = WsEncryption.withNamespaces(node);
        const encrypted = stsCrypto.encryptElement(plain, pem, {
          bare: true, algorithm: algorithm, keyTransport: keyTransport
        });
        const parsed = new DOMParser().parseFromString(encrypted, 'text/xml');
        const fresh = parsed.documentElement;
        if (!fresh || fresh.localName === 'parsererror') {
          log.debug("Leaving WsEncryption.seal(). No element.");
          return WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
            'encryption did not produce an element');
        }
        node.parentNode.replaceChild(doc.importNode(fresh, true), node);
      } catch (e) {
        log.debug("Caught in WsEncryption.seal(): " +
                  ((e && e.message) || e));
        // The cipher or the recipient key refused the element. The
        // response is not sent in the clear.
        log.debug("Leaving WsEncryption.seal(). The cipher.");
        return WsEncryption.fail('STS-WSTRUST-0077', 'RequestFailed',
          'the element could not be encrypted: ' +
          ((e && e.message) || e));
      }
    }
    log.debug("Leaving WsEncryption.seal(). Sealed.");
    return { ok: true };
  }

  private static withNamespaces(node): string {
    log.debug("Entering WsEncryption.withNamespaces().");
    const clone = node.cloneNode(true);
    const declared = {};
    let cur = node.parentNode;
    while (cur && cur.nodeType === 1) {
      const attrs = cur.attributes || [];
      for (let i = 0; i < attrs.length; i++) {
        const name = String(attrs[i].name || attrs[i].nodeName || '');
        if ((name === 'xmlns' || name.indexOf('xmlns:') === 0) &&
            !Object.prototype.hasOwnProperty.call(declared, name)) {
          declared[name] = String(attrs[i].value || '');
        }
      }
      cur = cur.parentNode;
    }
    Object.keys(declared).forEach(function (name) {
      if (!clone.getAttribute(name)) {
        clone.setAttribute(name, declared[name]);
      }
    });
    log.debug("Leaving WsEncryption.withNamespaces().");
    return new XMLSerializer().serializeToString(clone);
  }

  // Once per node while the deepest match is chosen. A line each would
  // bury the request.
  private static depth(node): number {
    let n = 0;
    let cur = node;
    while (cur) {
      n += 1;
      cur = cur.parentNode;
    }
    return n;
  }

  private static texts(doc, local): string[] {
    log.debug("Entering WsEncryption.texts().");
    const all = doc.getElementsByTagNameNS('*', local);
    const out = [];
    for (let i = 0; i < all.length; i++) {
      out.push(String(all[i].textContent || '').trim());
    }
    log.debug("Leaving WsEncryption.texts(). " + out.length);
    return out;
  }

  static effectiveCipher(appId): string {
    log.debug("Entering WsEncryption.effectiveCipher().");
    const named = String(applications.settingFor(appId,
      'wstrust.encryptionAlgorithm', config) || 'aes256-gcm');
    log.debug("Leaving WsEncryption.effectiveCipher(). " + named);
    return named;
  }

  static effectiveTransport(appId): string {
    log.debug("Entering WsEncryption.effectiveTransport().");
    let named = String(applications.settingFor(appId,
      'wstrust.keyTransportAlgorithm', config) || 'rsa-oaep-mgf1p');
    if (named === 'rsa-oaep-mgf1p' && !mode.allowsLegacyHashes()) {
      named = 'rsa-oaep';
    }
    log.debug("Leaving WsEncryption.effectiveTransport(). " + named);
    return named;
  }

  private static sameCipher(text, expected): boolean {
    log.debug("Entering WsEncryption.sameCipher().");
    const raw = String(text || '').trim();
    const by = stsCrypto.cipherByUri(raw);
    const ok = raw === expected || !!(by && by.name === expected);
    log.debug("Leaving WsEncryption.sameCipher(). " + ok);
    return ok;
  }

  private static sameTransport(text, expected): boolean {
    log.debug("Entering WsEncryption.sameTransport().");
    const raw = String(text || '').trim();
    const by = stsCrypto.transportByUri(raw);
    const ok = raw === expected || !!(by && by.name === expected);
    log.debug("Leaving WsEncryption.sameTransport(). " + ok);
    return ok;
  }

  /**
   * The XPath subset: `/`, `//`, `*`, a name, `prefix:local`, `|`, and
   * predicates `local-name()`, `namespace-uri()` and `@attr` joined by
   * `and`. Anything else is STS-WSTRUST-0079.
   *
   * @param doc - the document
   * @param expr - the expression
   * @returns `{ ok, nodes }` or the fault
   */
  static select(doc, expr): any {
    log.debug("Entering WsEncryption.select().");
    try {
      const branches = WsEncryption.splitOutside(String(expr || ''), '|');
      if (!branches.length || !String(expr || '').trim()) {
        log.debug("Leaving WsEncryption.select(). Empty.");
        return WsEncryption.fail('STS-WSTRUST-0079', 'RequestFailed',
          'the XPath expression is empty');
      }
      let nodes = [];
      for (let i = 0; i < branches.length; i++) {
        const branch = branches[i].trim();
        if (!branch) {
          log.debug("Leaving WsEncryption.select(). An empty branch.");
          return WsEncryption.fail('STS-WSTRUST-0079', 'RequestFailed',
            'the XPath expression has an empty branch');
        }
        nodes = nodes.concat(WsEncryption.evalPath(doc, branch));
      }
      log.debug("Leaving WsEncryption.select(). " + nodes.length);
      return { ok: true, nodes: WsEncryption.inOrder(nodes) };
    } catch (e) {
      log.debug("Caught in WsEncryption.select(): " +
                ((e && e.message) || e));
      // The expression is outside the subset, or a prefix is unknown.
      // That is a fault, not a miss.
      log.debug("Leaving WsEncryption.select(). Unsupported.");
      return WsEncryption.fail('STS-WSTRUST-0079', 'RequestFailed',
        'the XPath expression is not in the subset this service ' +
        'evaluates: ' + ((e && e.message) || e));
    }
  }

  private static evalPath(doc, expr): any[] {
    log.debug("Entering WsEncryption.evalPath().");
    let nodes = [doc];
    let i = 0;
    const text = String(expr || '');
    if (text.charAt(0) !== '/') {
      throw new Error('a relative path is not in the subset');
    }
    while (i < text.length) {
      const deep = text.startsWith('//', i);
      i += deep ? 2 : 1;
      if (i >= text.length) {
        throw new Error('a trailing slash is not in the subset');
      }
      const step = WsEncryption.parseStep(text, i);
      i = step.next;
      const base = deep ? WsEncryption.expand(nodes) : nodes;
      nodes = WsEncryption.childAxis(base, step);
    }
    log.debug("Leaving WsEncryption.evalPath(). " + nodes.length);
    return nodes;
  }

  private static parseStep(text, start): any {
    log.debug("Entering WsEncryption.parseStep().");
    let i = start;
    let kind = 'name';
    let prefix = '';
    let local = '';
    if (text.charAt(i) === '*') {
      kind = 'star';
      i += 1;
    } else {
      const matched = /^([A-Za-z_][\w.-]*)(?::([A-Za-z_][\w.-]*|\*))?/
        .exec(text.slice(i));
      if (!matched) {
        throw new Error('a step is not a name or *');
      }
      if (matched[2] === '*') {
        throw new Error('a prefix:* test is not in the subset');
      }
      i += matched[0].length;
      if (matched[2]) {
        prefix = matched[1];
        local = matched[2];
      } else {
        local = matched[1];
      }
    }
    let predicates = [];
    if (text.charAt(i) === '[') {
      const closed = WsEncryption.bracket(text, i);
      predicates = WsEncryption.predicatesOf(
        text.slice(i + 1, closed));
      i = closed + 1;
    }
    log.debug("Leaving WsEncryption.parseStep().");
    return { kind: kind, prefix: prefix, local: local,
             predicates: predicates, next: i };
  }

  private static bracket(text, open): number {
    log.debug("Entering WsEncryption.bracket().");
    let depth = 0;
    let quote = false;
    for (let i = open; i < text.length; i++) {
      const ch = text.charAt(i);
      if (ch === "'") {
        quote = !quote;
      } else if (!quote && ch === '[') {
        depth += 1;
      } else if (!quote && ch === ']') {
        depth -= 1;
        if (depth === 0) {
          log.debug("Leaving WsEncryption.bracket().");
          return i;
        }
      }
    }
    throw new Error('a predicate is not closed');
  }

  private static predicatesOf(body): any[] {
    log.debug("Entering WsEncryption.predicatesOf().");
    const parts = WsEncryption.splitOutside(body, ' and ');
    const out = parts.map(function (part) {
      return WsEncryption.onePredicate(part.trim());
    });
    log.debug("Leaving WsEncryption.predicatesOf(). " + out.length);
    return out;
  }

  private static onePredicate(term): any {
    log.debug("Entering WsEncryption.onePredicate().");
    let matched = /^local-name\(\)\s*=\s*'([^']*)'$/.exec(term);
    if (matched) {
      log.debug("Leaving WsEncryption.onePredicate(). local-name.");
      return { kind: 'local-name', value: matched[1] };
    }
    matched = /^namespace-uri\(\)\s*=\s*'([^']*)'$/.exec(term);
    if (matched) {
      log.debug("Leaving WsEncryption.onePredicate(). namespace-uri.");
      return { kind: 'namespace-uri', value: matched[1] };
    }
    matched = /^@([A-Za-z_][\w.-]*)(?::([A-Za-z_][\w.-]*))?/.exec(term);
    const rest = matched
      ? /^(?:\s*=\s*'([^']*)')?$/.exec(term.slice(matched[0].length)) : null;
    if (matched && rest) {
      log.debug("Leaving WsEncryption.onePredicate(). An attribute.");
      return { kind: 'attr',
               prefix: matched[2] ? matched[1] : '',
               local: matched[2] || matched[1],
               value: rest[1], exists: rest[1] === undefined };
    }
    throw new Error('a predicate is not local-name(), namespace-uri() ' +
                    'or @attr');
  }

  private static splitOutside(text, sep): string[] {
    log.debug("Entering WsEncryption.splitOutside().");
    const parts = [];
    let start = 0;
    let depth = 0;
    let quote = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text.charAt(i);
      if (ch === "'") {
        quote = !quote;
      } else if (!quote && ch === '[') {
        depth += 1;
      } else if (!quote && ch === ']') {
        depth -= 1;
        if (depth < 0) {
          throw new Error('a bracket is not opened');
        }
      } else if (!quote && depth === 0 && text.startsWith(sep, i)) {
        parts.push(text.slice(start, i));
        i += sep.length - 1;
        start = i + 1;
      }
    }
    parts.push(text.slice(start));
    log.debug("Leaving WsEncryption.splitOutside(). " + parts.length);
    return parts;
  }

  // Once per node of the document the expression walks.
  private static expand(nodes): any[] {
    const out = [];
    const seen = new Set();
    // A debug line on this walk would bury the request: once per node.
    const walk = function (node): void {
      if (!node || seen.has(node)) {
        return;
      }
      seen.add(node);
      out.push(node);
      const kids = node.childNodes || [];
      for (let i = 0; i < kids.length; i++) {
        walk(kids[i]);
      }
    };
    for (let i = 0; i < nodes.length; i++) {
      walk(nodes[i]);
    }
    return out;
  }

  // Once per node the step is tried against.
  private static childAxis(nodes, step): any[] {
    const out = [];
    for (let i = 0; i < nodes.length; i++) {
      const kids = nodes[i].childNodes || [];
      for (let k = 0; k < kids.length; k++) {
        if (kids[k].nodeType === 1 &&
            WsEncryption.stepMatches(kids[k], step)) {
          out.push(kids[k]);
        }
      }
    }
    return out;
  }

  // Once per element a step considers.
  private static stepMatches(node, step): boolean {
    if (step.kind === 'name') {
      const ns = node.namespaceURI || null;
      if (step.prefix) {
        const want = WsEncryption.prefixOf(node, step.prefix);
        if (want == null) {
          throw new Error('the prefix ' + step.prefix + ' is not declared');
        }
        if (node.localName !== step.local || ns !== want) {
          return false;
        }
      } else if (node.localName !== step.local || ns) {
        return false;
      }
    }
    for (let i = 0; i < step.predicates.length; i++) {
      if (!WsEncryption.predicateMatches(node, step.predicates[i])) {
        return false;
      }
    }
    return true;
  }

  // Once per element a predicate considers.
  private static predicateMatches(node, pred): boolean {
    if (pred.kind === 'local-name') {
      return node.localName === pred.value;
    }
    if (pred.kind === 'namespace-uri') {
      return String(node.namespaceURI || '') === pred.value;
    }
    const attrs = node.attributes || [];
    for (let i = 0; i < attrs.length; i++) {
      const attr = attrs[i];
      const local = attr.localName || attr.name;
      if (pred.prefix) {
        const want = WsEncryption.prefixOf(node, pred.prefix);
        if ((attr.namespaceURI || null) !== want || local !== pred.local) {
          continue;
        }
      } else if (local !== pred.local && attr.name !== pred.local) {
        continue;
      }
      return pred.exists || String(attr.value) === pred.value;
    }
    return false;
  }

  // Once per name test. The comment on expand() is the reason.
  private static prefixOf(node, prefix): string | null {
    let declared = null;
    if (node && typeof node.lookupNamespaceURI === 'function') {
      declared = node.lookupNamespaceURI(prefix);
    }
    if (declared) {
      return String(declared);
    }
    return PREFIXES[prefix] || null;
  }

  private static inOrder(nodes): any[] {
    log.debug("Entering WsEncryption.inOrder().");
    const unique = [];
    nodes.forEach(function (node) {
      if (unique.indexOf(node) < 0) {
        unique.push(node);
      }
    });
    unique.sort(function (a, b) {
      if (a === b) {
        return 0;
      }
      const pos = a.compareDocumentPosition(b);
      if (pos & 4) {
        return -1;
      }
      if (pos & 2) {
        return 1;
      }
      return 0;
    });
    log.debug("Leaving WsEncryption.inOrder(). " + unique.length);
    return unique;
  }
};
