// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws_integrity.ts
//
// WS-Security message integrity for one WS-Trust exchange, per application
// (#1917, with #1918's response signing). Two halves:
//
//   * THE REQUEST: an application may require a request signed
//     (`wstrustSignRequest`, over `wstrust.signRequest`) and name what the
//     signature must cover (`wstrustSignRequestElements`). The signature
//     itself is read, verified and refused where it always was
//     (`wstrust.ts`'s `messageSignature()`); this holds an ACCEPTED
//     signature to the application's map.
//   * THE RESPONSE: a success answer may be signed (`wstrustSignResponse`,
//     over `wstrust.signResponse`) with this realm's XML signing key, over a
//     wsu:Timestamp and what `wstrustSignResponseElements` names, and
//     combined with `ws_encryption.ts`'s encryption in a declared order
//     (`wstrustResponseProtectionOrder`), the signature itself encrypted
//     where `wstrustEncryptSignature` asks.
//
// The maps are XPath in `ws_encryption.ts`'s subset, evaluated by its
// `select()` with `web_ws_protection.ts`'s prefixes, so one expression means
// one thing in all six maps. A library: it registers nothing and does not
// require ws-trust/wstrust.ts.

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import applications = require('../common/applications');
import config = require('../common/config');
import DomainMap = require('../common/domain_map');
import errorCodes = require('../common/error_codes');
import xmldom = require('../common/xml_parser');
import documentSettings = require('../saml/document_settings');
import WsEncryption = require('./ws_encryption');
import WebWsProtection = require('./web_ws_protection');

const { DOMParser, XMLSerializer } = xmldom;
const log = helpers.log;
const PREFIXES = WebWsProtection.PREFIXES;

// A response's Timestamp lasts five minutes, WSS4J's default for the
// Timestamp it writes, and what a receiver's clock-skew allowance is set
// against. A WS-Trust answer is read the moment it arrives; the token inside
// carries its own Lifetime.
const TIMESTAMP_SECONDS = 300;

const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509v3';
const BASE64 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-soap-message-security-1.0#Base64Binary';

// THE SIGNATURE, for sp:EncryptSignature: the ds:Signature that is a direct
// child of the security header, under either SOAP version.
const SIGNATURE_PATH = '/soap11:Envelope/soap11:Header/wsse:Security/' +
  'ds:Signature | /soap12:Envelope/soap12:Header/wsse:Security/ds:Signature';

// The ids this module gives the parts it lays out. Each response is a
// document of its own, so a fixed id is unique within it; a part that
// already carries an id keeps it (a SAML assertion's own enveloped
// signature covers its attributes, so one added there would break it).
const TIMESTAMP_ID = 'iya-ts';
const TOKEN_ID = 'iya-bst';
const SIGNATURE_ID = 'iya-sig';
const PART_ID = 'iya-signed-';

// THE MOST ELEMENTS ONE MAP MAY SELECT in one message (#2007's review): a
// broad expression (`soap:Body//*`) on a large request is a walk per node,
// and no signed part a client sends is near this many.
const MOST_SELECTED = 256;

/**
 * WS-Security message integrity for WS-Trust: a request held to what its
 * application requires signed, and a response signed.
 */
export = class WsIntegrity {
  /**
   * Holds a request to its application's signing requirement. Off, nothing
   * is asked. On, a request whose signature was not accepted is
   * `STS-WSTRUST-0084`, and every element the map selects must be one the
   * accepted signature references or is inside (`STS-WSTRUST-0085`); an
   * empty map is the SOAP Body.
   *
   * @param doc - the opened request
   * @param accepted - whether its WS-Security signature was accepted
   * @returns ok, or the fault
   */
  static holdRequest(doc, accepted: boolean): any {
    log.debug("Entering WsIntegrity.holdRequest().");
    const appId = WsEncryption.applicationId(doc);
    if (!WsIntegrity.requiresSignedRequest(appId)) {
      log.debug("Leaving WsIntegrity.holdRequest(). Not required.");
      return { ok: true };
    }
    if (!accepted) {
      log.debug("Leaving WsIntegrity.holdRequest(). Unsigned.");
      return WsEncryption.fail('STS-WSTRUST-0084', 'FailedCheck',
        'the request carries no accepted WS-Security message signature, ' +
        'and its application requires one');
    }
    const named = WsIntegrity.stringsOf(appId, 'signRequestElements');
    const paths = named.length ? named
      : WebWsProtection.expressions('wstrustSignRequestElements', 'body');
    let selected = 0;
    for (let i = 0; i < paths.length; i++) {
      const found = WsEncryption.select(doc, paths[i]);
      if (!found.ok) {
        log.debug("Leaving WsIntegrity.holdRequest(). The expression.");
        return found;
      }
      if (!found.nodes.length) {
        log.debug("Leaving WsIntegrity.holdRequest(). Nothing matched.");
        return WsEncryption.fail('STS-WSTRUST-0085', 'FailedCheck',
          'an expression of the request signing map matched nothing');
      }
      selected += found.nodes.length;
      if (selected > MOST_SELECTED) {
        log.debug("Leaving WsIntegrity.holdRequest(). Too many.");
        return WsEncryption.fail('STS-WSTRUST-0087', 'FailedCheck',
          'the request signing map selects more than ' + MOST_SELECTED +
          ' elements');
      }
      for (let n = 0; n < found.nodes.length; n++) {
        if (!WsEncryption.coveredBySignature(doc, found.nodes[n])) {
          log.debug("Leaving WsIntegrity.holdRequest(). " +
                    found.nodes[n].localName + " is not signed.");
          return WsEncryption.fail('STS-WSTRUST-0085', 'FailedCheck',
            'the request signing map names ' + found.nodes[n].localName +
            ', which the request\'s signature does not cover');
        }
      }
    }
    log.debug("Leaving WsIntegrity.holdRequest(). Held.");
    return { ok: true };
  }

  /**
   * Protects a success response as its application asks: signed, encrypted,
   * both in the configured order, or neither. A realm whose signing key is
   * in the HSM signs off the event loop, and the answer is then a Promise of
   * the same `{ ok, xml }` or fault.
   *
   * @param xml - the clear response
   * @param requestDoc - the request, where an encryption recipient is read
   * @param appId - the AppliesTo's application, or ''
   * @returns `{ ok, xml }` or the fault, or a Promise of one
   */
  static protect(xml, requestDoc, appId): any {
    log.debug("Entering WsIntegrity.protect().");
    const id = String(appId || '');
    if (!WsIntegrity.on(id, 'wstrust.signResponse')) {
      log.debug("Leaving WsIntegrity.protect(). Encryption alone.");
      return WsEncryption.protectResponse(xml, requestDoc, id);
    }
    const order = String(applications.settingFor(id,
      'wstrust.responseProtectionOrder', config) || 'sign-then-encrypt');
    if (order === 'encrypt-then-sign') {
      const sealed = WsEncryption.protectResponse(xml, requestDoc, id);
      if (!sealed.ok) {
        log.debug("Leaving WsIntegrity.protect(). Not encrypted.");
        return sealed;
      }
      log.debug("Leaving WsIntegrity.protect(). Encrypt, then sign.");
      return WsIntegrity.signResponse(sealed.xml, id, true);
    }
    const also = WsIntegrity.on(id, 'wstrust.encryptSignature')
      ? [SIGNATURE_PATH] : [];
    const encrypt = (signed: any): any => {
      return signed.ok
        ? WsEncryption.protectResponse(signed.xml, requestDoc, id, also)
        : signed;
    };
    const signing = WsIntegrity.signResponse(xml, id, false);
    log.debug("Leaving WsIntegrity.protect(). Sign, then encrypt.");
    return signing && typeof signing.then === 'function'
      ? signing.then(encrypt) : encrypt(signing);
  }

  /**
   * Signs a response: a wsu:Timestamp, a BinarySecurityToken holding the
   * realm's XML signing certificate, and a ds:Signature over the Timestamp
   * and every element the map selects (the Body where it is empty), in the
   * response's wsse:Security header.
   *
   * @param xml - the response, clear or already encrypted
   * @param appId - the AppliesTo's application, or ''
   * @param encrypted - the response was encrypted first, so the signature
   *   goes ahead of the encrypted keys in the header
   * @returns `{ ok, xml }` or STS-WSTRUST-0086, or a Promise of one
   */
  static signResponse(xml, appId, encrypted: boolean): any {
    log.debug("Entering WsIntegrity.signResponse().");
    const signer = helpers.STS.xmlSigner;
    const certPem = signer && signer.certPem ? String(signer.certPem) : '';
    if (!certPem) {
      log.debug("Leaving WsIntegrity.signResponse(). No certificate.");
      return WsEncryption.fail('STS-WSTRUST-0086', 'RequestFailed',
        'the realm\'s XML signing key has no certificate, so the ' +
        'response signature would reference no token');
    }
    let doc;
    try {
      doc = new DOMParser().parseFromString(String(xml), 'text/xml');
    } catch (e) {
      log.debug("Caught in WsIntegrity.signResponse(): " +
                ((e && e.message) || e));
      // The envelope this service just built did not parse: nothing can be
      // signed, and the answer is not sent.
      log.debug("Leaving WsIntegrity.signResponse(). Unreadable.");
      return WsEncryption.fail('STS-WSTRUST-0086', 'RequestFailed',
        'the response could not be read for signing');
    }
    const ids = WsIntegrity.partIds(doc, appId);
    if (!ids.ok) {
      log.debug("Leaving WsIntegrity.signResponse(). The map.");
      return ids;
    }
    WsIntegrity.layOut(doc, certPem, encrypted);
    const how = documentSettings.signatureOptions();
    const opts = {
      privateKeyPem: signer.privateKeyPem,
      privateKey: signer.privateKey,
      sigAlg: how.sigAlg,
      ids: [TIMESTAMP_ID].concat(ids.ids),
      tokenId: TOKEN_ID,
      after: TOKEN_ID,
      signatureId: SIGNATURE_ID
    };
    const laidOut = new XMLSerializer().serializeToString(doc);
    const refused = (e): any => {
      log.info('wstrust: the response could not be signed — ' +
               ((e && e.message) || e) + '.');
      return WsEncryption.fail('STS-WSTRUST-0086', 'RequestFailed',
        'the response could not be signed');
    };
    if (helpers.keysInHsm()) {
      log.debug("Leaving WsIntegrity.signResponse(). Off the event loop.");
      return stsCrypto.signWsSecurityMessageOffLoop(laidOut, opts)
        .then(function (signed) {
          return { ok: true, xml: signed };
        }, refused);
    }
    try {
      const signed = stsCrypto.signWsSecurityMessage(laidOut, opts);
      log.debug("Leaving WsIntegrity.signResponse(). Signed.");
      return { ok: true, xml: signed };
    } catch (e) {
      log.debug("Caught in WsIntegrity.signResponse(): " +
                ((e && e.message) || e));
      log.debug("Leaving WsIntegrity.signResponse(). Refused.");
      return refused(e);
    }
  }

  // THE PARTS THE SIGNATURE COVERS beside the Timestamp: what the map
  // selects, the Body where it is empty. Each gets a wsu:Id unless it
  // carries an id already. The security header itself cannot be one: it
  // holds the signature.
  private static partIds(doc, appId): any {
    log.debug("Entering WsIntegrity.partIds().");
    const named = WsIntegrity.stringsOf(appId, 'signResponseElements');
    const paths = named.length ? named
      : WebWsProtection.expressions('wstrustSignResponseElements', 'body');
    const out: string[] = [];
    let n = 0;
    for (let i = 0; i < paths.length; i++) {
      const found = WsEncryption.select(doc, paths[i]);
      if (!found.ok) {
        log.debug("Leaving WsIntegrity.partIds(). The expression.");
        return found;
      }
      if (!found.nodes.length) {
        log.debug("Leaving WsIntegrity.partIds(). Nothing matched.");
        return WsEncryption.fail('STS-WSTRUST-0086', 'RequestFailed',
          'an expression of the response signing map matched nothing');
      }
      if (out.length + found.nodes.length > MOST_SELECTED) {
        log.debug("Leaving WsIntegrity.partIds(). Too many.");
        return WsEncryption.fail('STS-WSTRUST-0086', 'RequestFailed',
          'the response signing map selects more than ' + MOST_SELECTED +
          ' elements');
      }
      for (let k = 0; k < found.nodes.length; k++) {
        const node = found.nodes[k];
        if (node.localName === 'Security' &&
            node.namespaceURI === PREFIXES.wsse) {
          log.debug("Leaving WsIntegrity.partIds(). The security header.");
          return WsEncryption.fail('STS-WSTRUST-0086', 'RequestFailed',
            'the response signing map selects the wsse:Security header, ' +
            'which holds the signature and cannot be signed whole');
        }
        let id = WsIntegrity.idOf(node);
        if (!id) {
          n += 1;
          id = PART_ID + n;
          node.setAttributeNS(PREFIXES.wsu, 'wsu:Id', id);
        }
        if (out.indexOf(id) < 0) {
          out.push(id);
        }
      }
    }
    log.debug("Leaving WsIntegrity.partIds(). " + out.length);
    return { ok: true, ids: out };
  }

  // The id an element already carries, in the spellings a signature's
  // Reference resolves: wsu:Id first, then ID, AssertionID and Id.
  private static idOf(node): string {
    log.debug("Entering WsIntegrity.idOf().");
    const out = String(node.getAttributeNS(PREFIXES.wsu, 'Id') ||
                       node.getAttribute('ID') ||
                       node.getAttribute('AssertionID') ||
                       node.getAttribute('Id') || '');
    log.debug("Leaving WsIntegrity.idOf().");
    return out;
  }

  // THE SECURITY HEADER, IN THE ORDER A RECEIVER PROCESSES IT. Signed
  // first, the Timestamp and the token go last, and the encryption that
  // follows puts its keys above them, so a receiver decrypts and then
  // verifies. Encrypted first, they go first, ahead of the keys already
  // there, so it verifies and then decrypts. The signature is put right
  // after the token by the signer.
  private static layOut(doc, certPem: string, encrypted: boolean): void {
    log.debug("Entering WsIntegrity.layOut().");
    const security = WsEncryption.answerSecurity(doc);
    const now = Date.now();
    const stamp = doc.createElementNS(PREFIXES.wsu, 'wsu:Timestamp');
    stamp.setAttributeNS(PREFIXES.wsu, 'wsu:Id', TIMESTAMP_ID);
    const created = doc.createElementNS(PREFIXES.wsu, 'wsu:Created');
    created.appendChild(doc.createTextNode(new Date(now).toISOString()));
    const expires = doc.createElementNS(PREFIXES.wsu, 'wsu:Expires');
    expires.appendChild(doc.createTextNode(
      new Date(now + TIMESTAMP_SECONDS * 1000).toISOString()));
    stamp.appendChild(created);
    stamp.appendChild(expires);
    const token = doc.createElementNS(PREFIXES.wsse,
                                      'wsse:BinarySecurityToken');
    token.setAttributeNS(PREFIXES.wsu, 'wsu:Id', TOKEN_ID);
    token.setAttribute('ValueType', X509V3);
    token.setAttribute('EncodingType', BASE64);
    token.appendChild(doc.createTextNode(
      certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')));
    if (encrypted) {
      security.insertBefore(token, security.firstChild);
      security.insertBefore(stamp, token);
    } else {
      security.appendChild(stamp);
      security.appendChild(token);
    }
    log.debug("Leaving WsIntegrity.layOut().");
  }

  // WHETHER A REQUEST MUST BE SIGNED, FAILING CLOSED (#2007's review). An
  // application's wstrustSignRequest that does not parse as a boolean is
  // `applications.settingFor()`'s warning and the service-wide value, which
  // for this switch would be a typo that turned the requirement off. A
  // value is there, so the application asked for something: it is
  // required.
  private static requiresSignedRequest(appId): boolean {
    log.debug("Entering WsIntegrity.requiresSignedRequest().");
    const app: any = appId ? applications.get(appId) : null;
    const raw = app && app.fields
      ? [].concat(app.fields.wstrustSignRequest || [])[0] : undefined;
    if (raw !== undefined && raw !== null && String(raw).trim() !== '' &&
        !config.parseAs('wstrust.signRequest', raw).ok) {
      log.warn(errorCodes.tag('STS-REG-0025') + 'wstrust: ' + appId +
               ' carries wstrustSignRequest="' + String(raw) + '", which ' +
               'is not TRUE or FALSE; its requests are held to the ' +
               'requirement, as if it were TRUE.');
      log.debug("Leaving WsIntegrity.requiresSignedRequest(). Unreadable.");
      return true;
    }
    const out = WsIntegrity.on(appId, 'wstrust.signRequest');
    log.debug("Leaving WsIntegrity.requiresSignedRequest(). " + out);
    return out;
  }

  private static on(appId, key): boolean {
    log.debug("Entering WsIntegrity.on().");
    const value = !!applications.settingFor(appId || '', key, config);
    log.debug("Leaving WsIntegrity.on(). " + value);
    return value;
  }

  private static stringsOf(appId, field): string[] {
    log.debug("Entering WsIntegrity.stringsOf().");
    const app: any = appId ? applications.get(appId) : null;
    const value = app && app.fields
      ? DomainMap.fieldOf('WsTrustRelyingParty', field, app.fields)
      : undefined;
    const list = Array.isArray(value) ? value : (value ? [value] : []);
    const out = list.map(function (one) {
      return String(one).trim();
    }).filter(function (one) {
      return !!one;
    });
    log.debug("Leaving WsIntegrity.stringsOf(). " + out.length);
    return out;
  }
};
