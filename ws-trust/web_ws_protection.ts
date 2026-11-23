// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws-trust/web_ws_protection.ts
//
// ===========================================================================
// THE MESSAGE-PROTECTION PRESETS AND THE PREFIXES (#1917). A `web_` module
// with no requires, read by three parties, so all three use one copy:
//
//   * the console's WS-Trust tab (`admin-ui/web_applications.ts`), whose
//     *Body* and *Header* checkboxes add these expressions to an XPath map
//     or take them out, and whose XPath builder writes an expression with
//     these prefixes;
//   * `ws_encryption.ts` and `ws_integrity.ts`, which evaluate every map
//     with `PREFIXES` and nothing else;
//   * the tests, which hold each preset to what it selects.
//
// A CHECKBOX STORES NOTHING (rcbj on #1917: "everything comes down to the
// XPath maps"). A box is ticked exactly when every expression of its
// preset is in the map, and saving the form saves the map. So a map typed
// by hand, by the API or by an LDIF import is read the same way, and there
// is no second record of the setting to disagree with the first.
//
// WHY THE EXPRESSIONS ARE THESE:
//
//   * ENCRYPTING THE BODY means its CONTENT (`soap:Body/*`), as
//     WS-SecurityPolicy's sp:EncryptedParts/sp:Body does (section 4.2.1):
//     an xenc:EncryptedData in place of soap:Body itself is no SOAP
//     message at all.
//   * SIGNING THE BODY means the element itself (`soap:Body`), as
//     sp:SignedParts/sp:Body does (section 4.1.1): the signature's
//     Reference names the Body's wsu:Id.
//   * THE HEADER is every header block BUT wsse:Security, for both: that
//     header holds the signature and the keys, so it can be neither signed
//     nor encrypted whole, and WS-SecurityPolicy's sp:Header with no Name
//     means the same set (section 4.1.1). The Timestamp inside it is always
//     signed where anything is.
//
// Each expression is written for SOAP 1.1 and SOAP 1.2, joined by `|`, so
// one map serves an application whichever version its client speaks.
// ===========================================================================

// THE ONLY PREFIXES AN EXPRESSION MAY USE (#1668, rcbj on #1908,
// 2026-11-18; moved here from ws_encryption.ts by #1917). XPath 1.0
// resolves a prefix from the expression's context, never from the
// document: an expression is the service's, and the request is the
// requester's. A request that bound `wst:` to a namespace of its own could
// otherwise offer a decoy the map matched. An unprefixed name matches the
// null namespace only, as XPath 1.0 says.
const PREFIXES: Record<string, string> = {
  soap: 'http://schemas.xmlsoap.org/soap/envelope/',
  soap11: 'http://schemas.xmlsoap.org/soap/envelope/',
  soap12: 'http://www.w3.org/2003/05/soap-envelope',
  wsse: 'http://docs.oasis-open.org/wss/2004/01/' +
    'oasis-200401-wss-wssecurity-secext-1.0.xsd',
  wsse11: 'http://docs.oasis-open.org/wss/' +
    'oasis-wss-wssecurity-secext-1.1.xsd',
  wsu: 'http://docs.oasis-open.org/wss/2004/01/' +
    'oasis-200401-wss-wssecurity-utility-1.0.xsd',
  wst: 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
  wst14: 'http://docs.oasis-open.org/ws-sx/ws-trust/200802',
  wst2005: 'http://schemas.xmlsoap.org/ws/2005/02/trust',
  wst2004: 'http://schemas.xmlsoap.org/ws/2004/04/trust',
  wsa: 'http://www.w3.org/2005/08/addressing',
  wsa2004: 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  saml11: 'urn:oasis:names:tc:SAML:1.0:assertion',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  xenc: 'http://www.w3.org/2001/04/xmlenc#',
  wsp: 'http://schemas.xmlsoap.org/ws/2004/09/policy'
};

// Every header block but the security header, under one SOAP prefix.
const NOT_SECURITY = "[not(local-name()='Security' and namespace-uri()='" +
  PREFIXES.wsse + "')]";

const BODY_CONTENT = '/soap11:Envelope/soap11:Body/* | ' +
  '/soap12:Envelope/soap12:Body/*';
const BODY = '/soap11:Envelope/soap11:Body | /soap12:Envelope/soap12:Body';
const HEADER_BLOCKS = '/soap11:Envelope/soap11:Header/*' + NOT_SECURITY +
  ' | /soap12:Envelope/soap12:Header/*' + NOT_SECURITY;

// THE FOUR MAPS A PRESET WRITES INTO, by attribute, with the two presets
// each offers. `what` is a key under `consoleApplications.protection.` in
// the console's catalog; the expressions are data, never translated.
const MAPS: Record<string, { body: string[], header: string[] }> = {
  wstrustEncryptRequestElements: { body: [BODY_CONTENT],
                                   header: [HEADER_BLOCKS] },
  wstrustEncryptResponseElements: { body: [BODY_CONTENT],
                                    header: [HEADER_BLOCKS] },
  wstrustSignRequestElements: { body: [BODY], header: [HEADER_BLOCKS] },
  wstrustSignResponseElements: { body: [BODY], header: [HEADER_BLOCKS] }
};

// The switch each map is read under, so the console can say "on" beside a
// map whose switch is off.
const SWITCHES: Record<string, string> = {
  wstrustEncryptRequestElements: 'wstrustEncryptRequest',
  wstrustEncryptResponseElements: 'wstrustEncryptResponse',
  wstrustSignRequestElements: 'wstrustSignRequest',
  wstrustSignResponseElements: 'wstrustSignResponse'
};

// The fields an XPath builder may add an expression to: the four maps and
// the response recipient's one expression.
const TARGETS: string[] = Object.keys(MAPS)
  .concat(['wstrustResponseRecipientXPath']);

class WebWsProtection {
  static readonly PREFIXES = PREFIXES;
  static readonly MAPS = MAPS;
  static readonly SWITCHES = SWITCHES;
  static readonly TARGETS = TARGETS;

  /**
   * The expressions one preset writes into one map.
   *
   * @param map - a map's attribute name
   * @param part - `body` or `header`
   * @returns the expressions, or none for a map or part there is no preset
   *   for
   */
  static expressions(map: string, part: string): string[] {
    const row = Object.prototype.hasOwnProperty.call(MAPS, map)
      ? MAPS[map] : null;
    if (!row || (part !== 'body' && part !== 'header')) {
      return [];
    }
    return row[part].slice();
  }

  /**
   * Whether a preset is ticked: every one of its expressions is a value of
   * the map, compared with its surrounding white space removed.
   *
   * @param values - the map's values
   * @param map - the map's attribute name
   * @param part - `body` or `header`
   * @returns true when the box is ticked
   */
  static isOn(values: string[], map: string, part: string): boolean {
    const held = WebWsProtection.trimmed(values);
    const wanted = WebWsProtection.expressions(map, part);
    return wanted.length > 0 && wanted.every(function (one) {
      return held.indexOf(one) >= 0;
    });
  }

  /**
   * The map's values with one preset added or taken out. Every other value
   * is kept, in its order; an added expression goes last, once.
   *
   * @param values - the map's values
   * @param map - the map's attribute name
   * @param part - `body` or `header`
   * @param on - add when true, take out when false
   * @returns the new values
   */
  static applied(values: string[], map: string, part: string,
                 on: boolean): string[] {
    const wanted = WebWsProtection.expressions(map, part);
    const kept = WebWsProtection.trimmed(values).filter(function (one) {
      return wanted.indexOf(one) < 0;
    });
    return on ? kept.concat(wanted) : kept;
  }

  /**
   * An element's name as a step of an expression: `prefix:local` with this
   * service's prefix for its namespace, else `*[local-name()='…' and
   * namespace-uri()='…']`, else the bare name for no namespace. The XPath
   * builder writes each step this way, so what it writes is in the subset
   * the service evaluates.
   *
   * @param local - the local name
   * @param ns - the namespace, or '' for none
   * @returns the step
   */
  static stepFor(local: string, ns: string): string {
    if (!ns) {
      return local;
    }
    const prefix = Object.keys(PREFIXES).filter(function (one) {
      // soap is soap11's alias: the builder writes the explicit one.
      return one !== 'soap' && PREFIXES[one] === ns;
    })[0];
    if (prefix) {
      return prefix + ':' + local;
    }
    return "*[local-name()='" + local + "' and namespace-uri()='" + ns +
      "']";
  }

  /**
   * An absolute expression for one element: a step for it and for each
   * ancestor, from the document element down.
   *
   * @param chain - `{ local, ns }` from the document element to the element
   * @returns the expression
   */
  static pathFor(chain: { local: string, ns: string }[]): string {
    return chain.map(function (one) {
      return '/' + WebWsProtection.stepFor(one.local, one.ns);
    }).join('');
  }

  // The values, each trimmed, the empty ones left out.
  private static trimmed(values: string[]): string[] {
    return (values || []).map(function (one) {
      return String(one == null ? '' : one).trim();
    }).filter(function (one) {
      return !!one;
    });
  }
}

export = WebWsProtection;
