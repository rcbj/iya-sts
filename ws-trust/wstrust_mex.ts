// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws-trust/wstrust_mex.ts
//
// ---------------------------------------------------------------------------
// WS-METADATAEXCHANGE FOR `/sts`, AT `POST /sts/mex` (#958).
//
// WS-MetadataExchange (the 2004/09 submission, which is what WS-Trust
// clients ask) gives a client two requests, both SOAP, both answered here
// in the request's own SOAP version:
//
//   * WS-Transfer Get (`.../2004/09/transfer/Get`, an empty Body), which
//     WCF's svcutil and most .NET and Java stacks send: answered with every
//     section, action `.../transfer/GetResponse`;
//   * `mex:GetMetadata` (`.../2004/09/mex/GetMetadata/Request`), optionally
//     narrowed by `mex:Dialect` and `mex:Identifier`: answered with the
//     sections that match, action `.../GetMetadata/Response`. A dialect this
//     service has nothing in is an empty `mex:Metadata`, as section 6
//     requires, never a fault.
//
// THE SECTIONS are the three documents `GET /sts/metadata` and its two
// siblings answer, embedded, so nothing has to be fetched a second time:
// the WSDL (dialect WSDL 1.1), the token capability document (dialect and
// identifier the extension's namespace) and its schema (dialect XML
// Schema). They are built from the same flags at the same moment.
//
// IT IS AN ADDRESS OF ITS OWN, NOT A SECOND MEANING OF `POST /sts`. A
// WS-Transfer Get sent to `/sts` is answered as `/sts` always answered it.
// The WSDL names this address.
//
// A body that is not a SOAP envelope (STS-WSTRUST-0072) and an action that
// is neither request (STS-WSTRUST-0073) are each a Client (SOAP 1.2:
// Sender) fault, and its reason names the two actions answered. Neither
// code is sent.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import Html = require('../common/html');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import IssuerNames = require('../common/issuer_names');
import WsModel = require('./ws_model');
import WsTrustMetadata = require('./wstrust_metadata');
import WsTrustCapabilities = require('./wstrust_capabilities');

const { log } = helpers;

const MEX_NS = 'http://schemas.xmlsoap.org/ws/2004/09/mex';
const TRANSFER_NS = 'http://schemas.xmlsoap.org/ws/2004/09/transfer';
const GET = TRANSFER_NS + '/Get';
const GET_RESPONSE = TRANSFER_NS + '/GetResponse';
const GET_METADATA = MEX_NS + '/GetMetadata/Request';
const GET_METADATA_RESPONSE = MEX_NS + '/GetMetadata/Response';
const WSDL_DIALECT = 'http://schemas.xmlsoap.org/wsdl/';
const XSD_DIALECT = 'http://www.w3.org/2001/XMLSchema';
// The two WS-Addressing namespaces a WS-MEX client writes in: 1.0, and the
// 2004/08 submission the 2004/09 specifications were written against.
const WSA_2004 = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';

type Section = { dialect: string; identifier: string; body: string };

/**
 * `POST /sts/mex` (#958).
 */
class WsTrustMex {
  /** The address, relative to the realm's base. */
  static readonly PATH = '/sts/mex';

  /**
   * The sections, in the order a client reads them.
   *
   * @param base - the realm's base URL
   * @param issuer - this STS's issuer
   * @param flags - the runtime flags
   * @returns the sections
   */
  static sections(base: string, issuer: string, flags: any): Section[] {
    log.debug("Entering WsTrustMex.sections().");
    const bare = (xml: string): string => {
      return String(xml).replace(/^<\?xml[^>]*\?>\s*/, '').trim();
    };
    const out = [
      { dialect: WSDL_DIALECT, identifier: WsTrustMetadata.NAMESPACE,
        body: bare(WsTrustMetadata.document(base, issuer, flags)) },
      { dialect: WsTrustCapabilities.NAMESPACE,
        identifier: WsTrustCapabilities.NAMESPACE,
        body: bare(WsTrustCapabilities.document(base, issuer, flags)) },
      { dialect: XSD_DIALECT, identifier: WsTrustCapabilities.NAMESPACE,
        body: bare(WsTrustCapabilities.schema()) }
    ];
    log.debug("Leaving WsTrustMex.sections().");
    return out;
  }

  /**
   * Answers one request body. Pure apart from the log, so a test can drive
   * it without a socket.
   *
   * @param text - the request body
   * @param base - the realm's base URL
   * @param issuer - this STS's issuer
   * @param flags - the runtime flags
   * @returns the status, content type, body and error code
   */
  static answer(text: string, base: string, issuer: string,
                flags: any): { status: number; type: string; body: string;
                               errorCode?: string } {
    log.debug("Entering WsTrustMex.answer().");
    const soap11 = WsModel.term('soap.namespace', 'soap11');
    const soap12 = WsModel.term('soap.namespace', 'soap12');
    const read = validation.parseXml(String(text || ''), 'request');
    const doc: any = read.ok ? read.value : null;
    const root: any = doc && doc.documentElement;
    const envNs = root && root.localName === 'Envelope'
      ? String(root.namespaceURI || '') : '';
    if (envNs !== soap11 && envNs !== soap12) {
      log.debug("Leaving WsTrustMex.answer(). Not a SOAP envelope.");
      return this.fault(soap11, '', 'Client', 'The request is not a SOAP ' +
                        '1.1 or SOAP 1.2 envelope.', 'STS-WSTRUST-0072');
    }
    const header = this.child(root, envNs, 'Header');
    const body = this.child(root, envNs, 'Body');
    const action = this.headerText(header, 'Action');
    const wsaNs = this.headerNs(header) || WsModel.term('wsa.namespace',
                                                       'addressing');
    const messageId = this.headerText(header, 'MessageID');
    let sections = this.sections(base, issuer, flags);
    let reply = '';
    if (action === GET) {
      reply = GET_RESPONSE;
    } else if (action === GET_METADATA) {
      reply = GET_METADATA_RESPONSE;
      const ask = body ? this.child(body, MEX_NS, 'GetMetadata') : null;
      const dialect = ask ? this.text(this.child(ask, MEX_NS, 'Dialect'))
                          : '';
      const identifier = ask
        ? this.text(this.child(ask, MEX_NS, 'Identifier')) : '';
      sections = sections.filter((one) => {
        return (!dialect || one.dialect === dialect) &&
               (!identifier || one.identifier === identifier);
      });
    } else {
      log.debug("Leaving WsTrustMex.answer(). Action not supported.");
      return this.fault(envNs, wsaNs, 'Client', 'The action "' + action +
                        '" is not one this address answers: it answers ' +
                        GET + ' and ' + GET_METADATA + '.',
                        'STS-WSTRUST-0073');
    }
    const metadata = '<mex:Metadata xmlns:mex="' + MEX_NS + '">' +
      sections.map((one) => {
        return '<mex:MetadataSection Dialect="' + Html.esc(one.dialect) +
          '" Identifier="' + Html.esc(one.identifier) + '">' + one.body +
          '</mex:MetadataSection>';
      }).join('') + '</mex:Metadata>';
    const headers = '<wsa:Action>' + Html.esc(reply) + '</wsa:Action>' +
      (messageId ? '<wsa:RelatesTo>' + Html.esc(messageId) +
        '</wsa:RelatesTo>' : '');
    const out = { status: 200, type: this.typeOf(envNs, soap11),
                  body: this.envelope(envNs, wsaNs, headers, metadata) };
    log.debug("Leaving WsTrustMex.answer(). " + sections.length +
              " section(s).");
    return out;
  }

  /**
   * The route: `POST /sts/mex`.
   *
   * @param req - the request
   * @param res - the response
   */
  static send(req, res): void {
    log.debug("Entering WsTrustMex.send().");
    const base = helpers.baseUrlOf(req);
    const out = this.answer(typeof req.body === 'string' ? req.body : '',
                            base, IssuerNames.issuer(base),
                            WsTrustMetadata.liveFlags());
    if (out.errorCode) {
      errorCodes.mark(res, out.errorCode);
    }
    res.status(out.status);
    res.set('Content-Type', out.type);
    res.set('Cache-Control', 'no-store');
    res.send(out.body);
    log.debug("Leaving WsTrustMex.send(). " + out.status);
  }

  /**
   * A SOAP fault in the request's version (SOAP 1.1 when it had none).
   *
   * @param envNs - the envelope namespace
   * @param wsaNs - the addressing namespace, or ''
   * @param who - Client or Server
   * @param why - the reason
   * @param code - the error code, recorded and not sent
   * @returns the answer
   */
  private static fault(envNs: string, wsaNs: string, who: string,
                       why: string, code: string): { status: number;
                         type: string; body: string; errorCode: string } {
    log.debug("Entering WsTrustMex.fault().");
    const soap11 = WsModel.term('soap.namespace', 'soap11');
    const body = envNs === soap11
      ? '<soap:Fault><faultcode>soap:' + who + '</faultcode><faultstring>' +
        Html.esc(why) + '</faultstring></soap:Fault>'
      : '<soap:Fault><soap:Code><soap:Value>soap:' +
        (who === 'Client' ? 'Sender' : 'Receiver') + '</soap:Value>' +
        '</soap:Code><soap:Reason><soap:Text xml:lang="en">' +
        Html.esc(why) + '</soap:Text></soap:Reason></soap:Fault>';
    const headers = wsaNs
      ? '<wsa:Action>' + Html.esc(wsaNs) + '/fault</wsa:Action>' : '';
    const out = { status: 500, type: this.typeOf(envNs, soap11),
                  body: this.envelope(envNs, wsaNs, headers, body),
                  errorCode: code };
    log.debug("Leaving WsTrustMex.fault().");
    return out;
  }

  /**
   * One envelope.
   *
   * @param envNs - the envelope namespace
   * @param wsaNs - the addressing namespace, or ''
   * @param headers - the header children
   * @param body - the body children
   * @returns the XML
   */
  private static envelope(envNs: string, wsaNs: string, headers: string,
                          body: string): string {
    log.debug("Entering WsTrustMex.envelope().");
    const out = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<soap:Envelope xmlns:soap="' + Html.esc(envNs) + '"' +
      (wsaNs ? ' xmlns:wsa="' + Html.esc(wsaNs) + '"' : '') + '>' +
      (headers ? '<soap:Header>' + headers + '</soap:Header>' : '') +
      '<soap:Body>' + body + '</soap:Body></soap:Envelope>';
    log.debug("Leaving WsTrustMex.envelope().");
    return out;
  }

  /**
   * The content type of an envelope's SOAP version.
   *
   * @param envNs - the envelope namespace
   * @param soap11 - SOAP 1.1's namespace
   * @returns the media type
   */
  private static typeOf(envNs: string, soap11: string): string {
    log.debug("Entering WsTrustMex.typeOf().");
    log.debug("Leaving WsTrustMex.typeOf().");
    return envNs === soap11 ? 'text/xml; charset=utf-8'
                            : 'application/soap+xml; charset=utf-8';
  }

  /**
   * The first child element with this namespace and local name.
   *
   * @param parent - the element
   * @param ns - the namespace
   * @param name - the local name
   * @returns the element, or null
   */
  private static child(parent: any, ns: string, name: string): any {
    log.debug("Entering WsTrustMex.child().");
    const nodes = parent ? parent.childNodes : null;
    for (let i = 0; nodes && i < nodes.length; i += 1) {
      const one = nodes[i];
      if (one.nodeType === 1 && one.localName === name &&
          String(one.namespaceURI || '') === ns) {
        log.debug("Leaving WsTrustMex.child().");
        return one;
      }
    }
    log.debug("Leaving WsTrustMex.child(). None.");
    return null;
  }

  /**
   * An addressing header's text, in either addressing namespace.
   *
   * @param header - the soap:Header, or null
   * @param name - Action or MessageID
   * @returns the trimmed text, or ''
   */
  private static headerText(header: any, name: string): string {
    log.debug("Entering WsTrustMex.headerText().");
    const one = this.child(header, WsModel.term('wsa.namespace',
                                                'addressing'), name) ||
      this.child(header, WSA_2004, name);
    log.debug("Leaving WsTrustMex.headerText().");
    return this.text(one);
  }

  /**
   * The addressing namespace the request's Action is in, so the answer is
   * written in the one the client reads.
   *
   * @param header - the soap:Header, or null
   * @returns the namespace, or ''
   */
  private static headerNs(header: any): string {
    log.debug("Entering WsTrustMex.headerNs().");
    const ten = WsModel.term('wsa.namespace', 'addressing');
    let out = '';
    if (this.child(header, ten, 'Action')) {
      out = ten;
    } else if (this.child(header, WSA_2004, 'Action')) {
      out = WSA_2004;
    }
    log.debug("Leaving WsTrustMex.headerNs().");
    return out;
  }

  /**
   * An element's text, trimmed.
   *
   * @param node - the element, or null
   * @returns the text, or ''
   */
  private static text(node: any): string {
    log.debug("Entering WsTrustMex.text().");
    log.debug("Leaving WsTrustMex.text().");
    return node ? String(node.textContent || '').trim() : '';
  }
}

export = WsTrustMex;
