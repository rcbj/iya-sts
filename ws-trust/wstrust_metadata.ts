// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws-trust/wstrust_metadata.ts
//
// ---------------------------------------------------------------------------
// THE WSDL FOR `/sts` (#958).
//
// `GET /sts/metadata` answers WSDL 1.1 with WS-SecurityPolicy embedded, so a
// client can read the address, the four trust versions, the four operations
// and every credential this STS actually accepts. `GET /sts` stays the plain
// text it has always been: `tests/ws_model_wire.js` records that body, and a
// query on it would be a different document pretending to be the same one.
// WS-MetadataExchange is `wstrust_mex.ts`, at `POST /sts/mex`, and the
// credential/token-type pairs are `wstrust_capabilities.ts`'s document,
// which this one names. The document is not signed and
// carries no certificate; `GET /sts/cert` is the certificate, and a copy
// embedded here would be yesterday's key after a development restart.
//
// This file exists so those URIs are not written in `wstrust.ts`.
// `tests/model_ws.js` fails when that file quotes one. The trust namespaces,
// token types, request types and the WS-Policy namespace are
// `models/ws/*.tsp`'s, read through `WsModel`. The Kerberos ValueTypes are
// `Krb5Tokens.VALUE_TYPES`. The authentication-context URIs are SAML's.
// What the model does not hold — the WSDL namespaces, the WS-SecurityPolicy
// namespace and its assertion names — is written here, because a WSDL is
// those names.
//
// NO BINDING ASSERTION THAT NAMES AN ALGORITHM SUITE. An AsymmetricBinding or
// a TransportBinding requires one, and naming Basic256 (or any other suite)
// would claim a listener and a signature algorithm this STS does not promise.
// Each credential is its own alternative in one wsp:ExactlyOne. An alternative
// is present only while the runtime flag that accepts it is on, including the
// empty alternative, which is development's missing credential and is absent
// whenever `mode.verifiesCredentials()` is true.
//
// EACH TRUST VERSION IS A CONTRACT OF ITS OWN. A port type per version
// (TrustMay2004, TrustFeb2005, Trust13, Trust14), its messages that
// version's own elements in a schema per namespace, its operations the ones
// it defines (May 2004 has no Cancel), each input and output naming its
// wsam:Action: WS-Trust's `{ns}/RST/{op}` in, and out the action
// `wstrust.ts` writes, read from the model's `wst.action`. The schemas
// declare the elements open (`xsd:any`): the children are the model's, and
// a second, weaker statement of them here would drift. 1.4 is 1.3's
// messages, because WS-Trust 1.4 keeps 1.3's namespace, with ActAs in 1.4's.
// Until 2026-11-12 the document had one port type over `xsd:anyType` in a
// private namespace, with the versions named only in prose, which no WSDL
// tool could read a version from.
//
// The RST address in all eight ports is `{base}/sts`: the endpoint reads
// the version from the request. This document's own URL is not one.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import Html = require('../common/html');
import XmlFormat = require('../common/xml_format');
import config = require('../common/config');
import mode = require('../common/mode');
import IssuerNames = require('../common/issuer_names');
import Krb5Tokens = require('../kerberos/krb5_tokens');
import SamlModel = require('../saml/saml_model');
import WsModel = require('./ws_model');
import WsTrustCapabilities = require('./wstrust_capabilities');

const { log } = helpers;

// WSDL 1.1, its SOAP bindings, and WS-SecurityPolicy 1.3. None of these is a
// term the trust model holds; the policy namespace the model does hold is
// WS-Policy 1.2, which is the one `wsp:AppliesTo` is written in, and this
// document uses that one rather than the W3C 1.5 namespace.
const WSDL_NS = 'http://schemas.xmlsoap.org/wsdl/';
const SOAP_NS = 'http://schemas.xmlsoap.org/wsdl/soap/';
const SOAP12_NS = 'http://schemas.xmlsoap.org/wsdl/soap12/';
const XSD_NS = 'http://www.w3.org/2001/XMLSchema';
const TNS = 'urn:iya-sts:ws-trust:metadata';
// WS-SecurityPolicy 1.2's namespace. 1.3's 200802 namespace declares only the
// five assertions 1.3 added (XPath2, Created, Nonce, ScopePolicy15,
// MustSupportInteractiveChallenge) and imports this one for every other: a
// UsernameToken or X509Token named in 200802 is an assertion no policy
// processor knows (tests/wstrust_metadata.js W, against the published XSDs).
const SP_NS = 'http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702';
const INCLUDE = SP_NS + '/IncludeToken/AlwaysToRecipient';
const TRANSPORT = 'http://schemas.xmlsoap.org/soap/http';
// WS-Addressing 1.0 Metadata: the wsam:Action on a WSDL input or output.
const WSAM_NS = 'http://www.w3.org/2007/05/addressing/metadata';
// The token capability extension's namespace (`wstrust_capabilities.ts`).
const CAP_NS = 'urn:iya-sts:metadata:token-capabilities:1';

type Flags = {
  acceptKerberos: boolean;
  issueKerberos: boolean;
  acceptClientCertificate: boolean;
  verifiesCredentials: boolean;
};

type TrustVersion = {
  name: string;
  prefix: string;
  ns: string;
  title: string;
  operations: string[];
  collection: boolean;
};

type Terms = {
  trust13: string;
  trust14: string;
  trust2005: string;
  trust2004: string;
  saml2: string;
  saml11: string;
  saml11Namespace: string;
  jwt: string;
  policy: string;
  addressing: string;
  utility: string;
  secext: string;
  soap11: string;
  soap12: string;
  invalidRequest: string;
  kerberos: string[];
  passwordProtectedTransport: string;
  previousSession: string;
  tlsClient: string;
  x509: string;
  kerberosClass: string;
  unspecified: string;
  amPassword: string;
  amTls: string;
  amX509: string;
};

/**
 * The WSDL a client reads before it sends a RequestSecurityToken (#958).
 *
 * A static utility: the route in `wstrust.ts` calls `send`, and a test calls
 * `document` with the flags it wants to see.
 */
class WsTrustMetadata {
  /** The WSDL's target namespace, and its WS-MEX section's identifier. */
  static readonly NAMESPACE = TNS;

  /**
   * The WSDL for one base URL, one issuer and one set of flags.
   *
   * @param base - the realm's base URL, no trailing slash
   * @param issuer - the issuer every token from this STS names
   * @param flags - which alternatives the running service accepts
   * @returns the document
   */
  static document(base: string, issuer: string, flags: Flags): string {
    log.debug("Entering WsTrustMetadata.document().");
    const root = String(base || '').replace(/\/+$/, '');
    const terms = this.terms();
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      this.open(terms) +
      '<wsdl:documentation>' + Html.esc(this.description(
        root, issuer, flags, terms)) + '</wsdl:documentation>' +
      // The capability extension (#958), named here so a client reading
      // only the WSDL finds it. Optional, so a WSDL 1.1 tool that does not
      // know it must ignore it (WSDL 1.1 section 2.1.3).
      '<iya:TokenCapabilitiesReference wsdl:required="false" ' +
      'location="' + Html.esc(root + '/sts/metadata/capabilities') +
      '" schemaLocation="' + Html.esc(root +
        '/sts/metadata/capabilities.xsd') + '" metadataExchange="' +
      Html.esc(root + '/sts/mex') + '"/>' +
      this.policy('RequesterAuthentication',
                  this.requester(flags, terms)) +
      this.policy('IssuedTokenTypes', this.issued(flags, terms)) +
      this.types(terms) +
      this.messages(terms) +
      this.portTypes(terms) +
      this.bindings(terms) +
      this.service(root, terms) +
      '</wsdl:definitions>\n';
    log.debug("Leaving WsTrustMetadata.document().");
    // ALWAYS FORMATTED (rcbj, 2026-11-13): one element a line, indented, so
    // a person reading `GET /sts/metadata` or the WS-MEX answer can read it.
    // Whitespace between elements changes nothing a WSDL reader sees.
    return XmlFormat.indent(xml, log);
  }

  /**
   * Answers `GET /sts/metadata` from the request's base and the flags the
   * process is running with.
   *
   * @param req - the request
   * @param res - the response
   */
  static send(req, res): void {
    log.debug("Entering WsTrustMetadata.send().");
    const base = helpers.baseUrlOf(req);
    const body = this.document(base, IssuerNames.issuer(base),
                                this.liveFlags());
    res.status(200);
    res.set('Content-Type', 'application/wsdl+xml; charset=utf-8');
    res.set('Cache-Control', 'no-store');
    res.send(body);
    log.debug("Leaving WsTrustMetadata.send().");
  }

  /**
   * Answers `GET /sts/metadata/capabilities`: the token capability document
   * for the request's base and the live flags.
   *
   * @param req - the request
   * @param res - the response
   */
  static sendCapabilities(req, res): void {
    log.debug("Entering WsTrustMetadata.sendCapabilities().");
    const base = helpers.baseUrlOf(req);
    res.status(200);
    res.set('Content-Type', 'application/xml; charset=utf-8');
    res.set('Cache-Control', 'no-store');
    res.send(WsTrustCapabilities.document(base, IssuerNames.issuer(base),
                                          this.liveFlags()));
    log.debug("Leaving WsTrustMetadata.sendCapabilities().");
  }

  /**
   * Answers `GET /sts/metadata/capabilities.xsd`, the extension's schema.
   *
   * @param req - the request
   * @param res - the response
   */
  static sendCapabilitySchema(req, res): void {
    log.debug("Entering WsTrustMetadata.sendCapabilitySchema().");
    res.status(200);
    res.set('Content-Type', 'application/xml; charset=utf-8');
    res.set('Cache-Control', 'no-store');
    res.send(WsTrustCapabilities.schema());
    log.debug("Leaving WsTrustMetadata.sendCapabilitySchema().");
  }

  /**
   * The flags `document` reads, as the endpoint reads them: Kerberos through
   * `Krb5Tokens.settingOn`, the client certificate off only when the setting
   * is exactly false, and the empty alternative only while credentials are
   * not verified.
   *
   * @returns the flags
   */
  static liveFlags(): Flags {
    log.debug("Entering WsTrustMetadata.liveFlags().");
    const out = {
      acceptKerberos: Krb5Tokens.settingOn('wstrust.acceptKerberos'),
      issueKerberos: Krb5Tokens.settingOn('wstrust.issueKerberos'),
      acceptClientCertificate:
        config.value('wstrust.acceptClientCertificate') !== false,
      verifiesCredentials: !!mode.verifiesCredentials()
    };
    log.debug("Leaving WsTrustMetadata.liveFlags().");
    return out;
  }

  /**
   * Every value the document quotes that the model or the Kerberos profile
   * already owns.
   *
   * @returns the terms
   */
  private static terms(): Terms {
    log.debug("Entering WsTrustMetadata.terms().");
    const value = Krb5Tokens.VALUE_TYPES;
    const out = {
      trust13: WsModel.term('wst.namespace', 'trust13'),
      trust14: WsModel.term('wst.namespace', 'trust14'),
      trust2005: WsModel.term('wst.namespace', 'trust2005'),
      trust2004: WsModel.term('wst.namespace', 'trust2004'),
      saml2: WsModel.term('wst.tokenType', 'saml2'),
      saml11: WsModel.term('wst.tokenType', 'saml11'),
      saml11Namespace: WsModel.term('wst.tokenType', 'saml11Namespace'),
      jwt: WsModel.term('wst.tokenType', 'jwt'),
      policy: WsModel.term('wsp.namespace', 'policy'),
      addressing: WsModel.term('wsa.namespace', 'addressing'),
      utility: WsModel.term('wsse.namespace', 'utility'),
      secext: WsModel.term('wsse.namespace', 'secext'),
      soap11: WsModel.term('soap.namespace', 'soap11'),
      soap12: WsModel.term('soap.namespace', 'soap12'),
      invalidRequest: WsModel.term('wst.fault', 'InvalidRequest'),
      kerberos: [value.AP_REQ, value.GSS_AP_REQ, value.AP_REQ_1510,
                 value.GSS_AP_REQ_1510, value.AP_REQ_4120,
                 value.GSS_AP_REQ_4120],
      passwordProtectedTransport: SamlModel.term('saml2.authnContext',
        'passwordProtectedTransport'),
      previousSession: SamlModel.term('saml2.authnContext',
                                      'previousSession'),
      tlsClient: SamlModel.term('saml2.authnContext', 'tlsClient'),
      x509: SamlModel.term('saml2.authnContext', 'x509'),
      kerberosClass: SamlModel.term('saml2.authnContext', 'kerberos'),
      unspecified: SamlModel.term('saml2.authnContext', 'unspecified'),
      amPassword: SamlModel.term('saml11.authnMethod', 'password'),
      amTls: SamlModel.term('saml11.authnMethod', 'tlsClient'),
      amX509: SamlModel.term('saml11.authnMethod', 'x509')
    };
    log.debug("Leaving WsTrustMetadata.terms().");
    return out;
  }

  /**
   * The opening tag. The trust prefix is 1.3's namespace, which is also
   * 1.4's for everything except ActAs.
   *
   * @param terms - the model's values
   * @returns the start tag
   */
  private static open(terms: Terms): string {
    log.debug("Entering WsTrustMetadata.open().");
    const out = '<wsdl:definitions targetNamespace="' + TNS + '" ' +
      'xmlns:wsdl="' + WSDL_NS + '" xmlns:xsd="' + XSD_NS + '" ' +
      'xmlns:soap="' + SOAP_NS + '" xmlns:soap12="' + SOAP12_NS + '" ' +
      'xmlns:wsp="' + Html.esc(terms.policy) + '" xmlns:sp="' + SP_NS +
      '" xmlns:wst="' + Html.esc(terms.trust13) + '" xmlns:wst2005="' +
      Html.esc(terms.trust2005) + '" xmlns:wst2004="' +
      Html.esc(terms.trust2004) + '" xmlns:wst14="' +
      Html.esc(terms.trust14) + '" xmlns:wsam="' + WSAM_NS +
      '" xmlns:iya="' + CAP_NS +
      '" xmlns:wsu="' +
      Html.esc(terms.utility) + '" xmlns:tns="' + TNS + '">';
    log.debug("Leaving WsTrustMetadata.open().");
    return out;
  }

  /**
   * The prose a person reads: every version, every credential, and the
   * combinations that are not supported. The policy alternatives are the
   * machine-readable half and follow the same flags.
   *
   * @param base - the realm's base URL
   * @param issuer - the issuer every token names
   * @param flags - which alternatives are present
   * @param terms - the model's values
   * @returns the text, not yet escaped
   */
  private static description(base: string, issuer: string, flags: Flags,
                             terms: Terms): string {
    log.debug("Entering WsTrustMetadata.description().");
    const address = base + '/sts';
    const issue = WsModel.relative('wst.request', 'issue', terms.trust13);
    const renew = WsModel.relative('wst.request', 'renew', terms.trust13);
    const validate = WsModel.relative('wst.request', 'validate',
                                      terms.trust13);
    const cancel = WsModel.relative('wst.request', 'cancel', terms.trust13);
    const issueFinal = WsModel.relative('wst.action', 'issueFinal',
                                        terms.trust13);
    const issue2004 = WsModel.relative('wst.action', 'issue',
                                       terms.trust2004);
    const sentences = [
      'This document is the WSDL 1.1 description of the WS-Trust security ' +
        'token service at ' + address + ', with WS-SecurityPolicy embedded.',
      'It is not signed and it does not carry the signing certificate. ' +
        'That certificate is at ' + base + '/sts/cert.',
      'WS-MetadataExchange (2004/09) answers at ' + base + '/sts/mex, ' +
        'with this document, the token capability document and its ' +
        'schema as three sections. The token capability document, at ' +
        base + '/sts/metadata/capabilities, is an IYA-STS extension ' +
        '(namespace ' + CAP_NS + ', schema ' + base +
        '/sts/metadata/capabilities.xsd) listing every credential, every ' +
        'issued type, and each pair as supported, conditional or ' +
        'unsupported.',
      'The service speaks four trust versions. WS-Trust 1.3, and 1.4 for ' +
        'everything 1.3 defines, use ' + terms.trust13 + '.',
      'ActAs alone uses the 1.4 namespace ' + terms.trust14 + '.',
      'The February 2005 namespace is ' + terms.trust2005 + '.',
      'The May 2004 member submission uses ' + terms.trust2004 + '. An ' +
        'Issue in that namespace is answered with one ' +
        'RequestSecurityTokenResponse, action ' + issue2004 + ', and ' +
        'Cancel is refused as wst:' + terms.invalidRequest + ' because ' +
        '2004/04 has no Cancel.',
      'The operation is the last segment of wst:RequestType. Under the ' +
        '1.3 namespace those are ' + issue + ', ' + renew + ', ' +
        validate + ' and ' + cancel + '. A request type that is none of ' +
        'those is answered as Issue. An Issue in 1.3 and 2005/02 is ' +
        'answered as a RequestSecurityTokenResponseCollection, action ' +
        issueFinal + '.',
      'Each version has a port type of its own, in its own namespace, ' +
        'with the operations that version defines: TrustMay2004 has ' +
        'Issue, Renew and Validate; TrustFeb2005, Trust13 and Trust14 ' +
        'have Issue, Renew, Validate and Cancel. Trust14 is Trust13\'s ' +
        'messages, because WS-Trust 1.4 keeps the 1.3 namespace, with ' +
        'ActAs in the 1.4 namespace.',
      'Each input and output names the wsa:Action WS-Trust gives it, and ' +
        'each output\'s is the one this service writes. Each SOAP 1.1 ' +
        'binding carries the input action as its soapAction. The service ' +
        'does not dispatch on SOAPAction or wsa:Action: a client may send ' +
        'either or neither. Key Exchange Token and BatchIssue are not ' +
        'implemented.',
      'Every port, eight of them (each version over SOAP 1.1, ' +
        terms.soap11 + ', and SOAP 1.2, ' + terms.soap12 + '), answers ' +
        'at ' + address + '. The address of this document is not an RST ' +
        'address.',
      'Every operation authenticates the requester first. A credential ' +
        'is read from wsse:Security (' + terms.secext + '), never from ' +
        'inside OnBehalfOf, ActAs, RenewTarget, ValidateTarget or ' +
        'CancelTarget, in the order below.',
      'First, a WS-Security signature over the SOAP Body and the ' +
        'wsu:Timestamp of that security header, exclusive ' +
        'canonicalisation. The certificate is named by a ' +
        'SecurityTokenReference in one of four forms: a Reference to an ' +
        'X.509 v3 BinarySecurityToken in the same header, a KeyIdentifier ' +
        'ThumbprintSHA1, a KeyIdentifier X509SubjectKeyIdentifier, or an ' +
        'X509IssuerSerial. A signature made with a Kerberos token\'s ' +
        'session key, HMAC-SHA256, HMAC-SHA384 or HMAC-SHA512, is that ' +
        'check\'s other branch.',
      'Then a UsernameToken. The username is a person, and a service ' +
        'account is a person, or else an application\'s identifier or ' +
        'client_id with one of that application\'s client secrets. A ' +
        'person who must hold a second factor presents an application ' +
        'password in the UsernameToken. The fault does not say whether ' +
        'the name was unknown or the password was wrong.',
      'Then a SAML 2.0 assertion, token type ' + terms.saml2 + '.',
      'Then a SAML 1.1 assertion, token type ' + terms.saml11 + ', which ' +
        'an older client may also name as ' + terms.saml11Namespace + '. ' +
        'There is no SAML 1.2.',
      'Then a JWT, token type ' + terms.jwt + ', carried in a ' +
        'BinarySecurityToken of that ValueType.',
      'Then a Kerberos token of the Web Services Security Kerberos Token ' +
        'Profile 1.1, one of ' + terms.kerberos.join(', ') + '. It is ' +
        'accepted only for this service\'s own service principal. ' +
        (flags.acceptKerberos
          ? 'wstrust.acceptKerberos is on, so that alternative is ' +
            'present.'
          : 'wstrust.acceptKerberos is off, so that alternative is ' +
            'omitted.'),
      'Then, only when the message carries none of the above, the TLS ' +
        'client certificate on the connection. ' +
        (flags.acceptClientCertificate
          ? 'wstrust.acceptClientCertificate is on, so that alternative ' +
            'is present.'
          : 'wstrust.acceptClientCertificate is off, so that alternative ' +
            'is omitted.'),
      flags.verifiesCredentials
        ? 'A request with no credential is refused. This document has ' +
          'no empty alternative.'
        : 'Credentials are not verified, so this document includes an ' +
          'empty alternative. Product mode refuses a request with no ' +
          'credential.',
      'The issued token types are SAML 2.0, which is what an omitted ' +
        'TokenType issues, SAML 1.1 and JWT. A SAML or JWT proof is ' +
        'Bearer. Kerberos is issued only when wstrust.issueKerberos is ' +
        'on, the AppliesTo is a Kerberos service and the request is over ' +
        'TLS, and then the proof key is a SymmetricKey BinarySecret. ' +
        (flags.issueKerberos
          ? 'wstrust.issueKerberos is on, so each Kerberos ValueType is ' +
            'an issued type.'
          : 'wstrust.issueKerberos is off, so no Kerberos type is ' +
            'offered as an issued type.'),
      'A Kerberos token cannot be renewed or cancelled here. SAML 2.0, ' +
        'SAML 1.1 and JWT may each be the requester\'s credential, the ' +
        'token inside OnBehalfOf or ActAs, and the issued TokenType. A ' +
        'UsernameToken, a TLS client certificate and a message signature ' +
        'are credentials, not types this STS issues. A Kerberos token ' +
        'inside OnBehalfOf or ActAs must have been obtained by ' +
        'delegation for this service\'s own service principal. Both ' +
        'OnBehalfOf and ActAs in one request are refused.',
      'A SAML 2.0 assertion names the credential as ' +
        terms.passwordProtectedTransport + ' for a UsernameToken, ' +
        terms.previousSession + ' for an assertion or a JWT, ' +
        terms.tlsClient + ' for a TLS client certificate, ' + terms.x509 +
        ' for a message signature, ' + terms.kerberosClass + ' for a ' +
        'Kerberos token, and ' + terms.unspecified + ' when the token is ' +
        'a delegation or the request carried no credential.',
      'A SAML 1.1 assertion uses ' + terms.amPassword + ', ' +
        terms.amTls + ' or ' + terms.amX509 + '.',
      'A JWT about the requester carries amr pwd for a UsernameToken and ' +
        'amr swk for a TLS client certificate or a message signature. The ' +
        'issuer of every token is ' + issuer + '.'
    ];
    log.debug("Leaving WsTrustMetadata.description().");
    return sentences.join(' ');
  }

  /**
   * One policy, attached later by wsu:Id.
   *
   * @param id - the policy id
   * @param body - the ExactlyOne
   * @returns the policy element
   */
  private static policy(id: string, body: string): string {
    log.debug("Entering WsTrustMetadata.policy().");
    const out = '<wsp:Policy wsu:Id="' + id + '">' + body + '</wsp:Policy>';
    log.debug("Leaving WsTrustMetadata.policy().");
    return out;
  }

  /**
   * The requester's alternatives, in the order the STS looks for them.
   *
   * @param flags - which alternatives are present
   * @param terms - the model's values
   * @returns the ExactlyOne
   */
  private static requester(flags: Flags, terms: Terms): string {
    log.debug("Entering WsTrustMetadata.requester().");
    const parts = [
      this.all(this.nested('X509Token', '<sp:WssX509V3Token11/>') +
               this.signedParts(terms.utility)),
      this.all(this.nested('UsernameToken', '<sp:WssUsernameToken11/>')),
      this.all(this.nested('SamlToken', '<sp:WssSamlV20Token11/>')),
      this.all(this.nested('SamlToken', '<sp:WssSamlV11Token11/>')),
      this.all(this.issuedToken(terms.jwt))
    ];
    if (flags.acceptKerberos) {
      parts.push(this.all(this.nested('KerberosToken',
                                       '<sp:WssKerberosV5ApReqToken11/>')));
    }
    if (flags.acceptClientCertificate) {
      parts.push(this.all('<sp:HttpsToken><wsp:Policy>' +
        '<sp:RequireClientCertificate/></wsp:Policy></sp:HttpsToken>'));
    }
    if (!flags.verifiesCredentials) {
      parts.push('<wsp:All/>');
    }
    log.debug("Leaving WsTrustMetadata.requester().");
    return this.exactlyOne(parts);
  }

  /**
   * The issued token types. Kerberos is one alternative per ValueType, and
   * only while issuance is on.
   *
   * @param flags - which alternatives are present
   * @param terms - the model's values
   * @returns the ExactlyOne
   */
  private static issued(flags: Flags, terms: Terms): string {
    log.debug("Entering WsTrustMetadata.issued().");
    const parts = [terms.saml2, terms.saml11, terms.jwt].map((one) => {
      return this.all(this.issuedToken(one));
    });
    if (flags.issueKerberos) {
      terms.kerberos.forEach((one) => {
        parts.push(this.all(this.issuedToken(one)));
      });
    }
    log.debug("Leaving WsTrustMetadata.issued().");
    return this.exactlyOne(parts);
  }

  /**
   * A token assertion with one nested assertion and IncludeToken always to
   * the recipient. No algorithm suite.
   *
   * @param name - the assertion's local name
   * @param inner - the nested assertion
   * @returns the element
   */
  private static nested(name: string, inner: string): string {
    log.debug("Entering WsTrustMetadata.nested().");
    const out = '<sp:' + name + ' sp:IncludeToken="' + INCLUDE + '">' +
      '<wsp:Policy>' + inner + '</wsp:Policy></sp:' + name + '>';
    log.debug("Leaving WsTrustMetadata.nested().");
    return out;
  }

  /**
   * An issued token named by wst:TokenType. JWT has no token assertion of
   * its own, and neither does a Kerberos ValueType beyond the one profile
   * assertion, so both are named this way.
   *
   * @param tokenType - the token type URI
   * @returns the element
   */
  private static issuedToken(tokenType: string): string {
    log.debug("Entering WsTrustMetadata.issuedToken().");
    const out = '<sp:IssuedToken sp:IncludeToken="' + INCLUDE + '">' +
      '<sp:RequestSecurityTokenTemplate><wst:TokenType>' +
      Html.esc(tokenType) + '</wst:TokenType>' +
      '</sp:RequestSecurityTokenTemplate></sp:IssuedToken>';
    log.debug("Leaving WsTrustMetadata.issuedToken().");
    return out;
  }

  /**
   * The parts a message signature has to cover: the Body, and the Timestamp.
   *
   * @param utility - the wsu namespace
   * @returns the SignedParts assertion
   */
  private static signedParts(utility: string): string {
    log.debug("Entering WsTrustMetadata.signedParts().");
    const out = '<sp:SignedParts><sp:Body/><sp:Header Name="Timestamp" ' +
      'Namespace="' + Html.esc(utility) + '"/></sp:SignedParts>';
    log.debug("Leaving WsTrustMetadata.signedParts().");
    return out;
  }

  /**
   * One alternative.
   *
   * @param inner - the assertions
   * @returns the All
   */
  private static all(inner: string): string {
    log.debug("Entering WsTrustMetadata.all().");
    log.debug("Leaving WsTrustMetadata.all().");
    return '<wsp:All>' + inner + '</wsp:All>';
  }

  /**
   * The alternatives of one policy.
   *
   * @param parts - each All
   * @returns the ExactlyOne
   */
  private static exactlyOne(parts: string[]): string {
    log.debug("Entering WsTrustMetadata.exactlyOne().");
    const out = '<wsp:ExactlyOne>' + parts.join('') + '</wsp:ExactlyOne>';
    log.debug("Leaving WsTrustMetadata.exactlyOne().");
    return out;
  }

  /**
   * The four trust versions as the contract describes them: the port type's
   * name, the namespace its messages are in, the operations it defines and
   * what an Issue is answered with. 2004/04 has no Cancel and answers an
   * Issue with one RSTR (#188); every other answers a collection. 1.4 keeps
   * 1.3's namespace for everything 1.3 defines.
   *
   * @param terms - the model's values
   * @returns the versions, oldest first
   */
  private static versions(terms: Terms): TrustVersion[] {
    log.debug("Entering WsTrustMetadata.versions().");
    const all = ['Issue', 'Renew', 'Validate', 'Cancel'];
    const out = [
      { name: 'TrustMay2004', prefix: 'wst2004', ns: terms.trust2004,
        title: 'WS-Trust May 2004 (member submission)',
        operations: ['Issue', 'Renew', 'Validate'], collection: false },
      { name: 'TrustFeb2005', prefix: 'wst2005', ns: terms.trust2005,
        title: 'WS-Trust February 2005', operations: all,
        collection: false },
      { name: 'Trust13', prefix: 'wst', ns: terms.trust13,
        title: 'WS-Trust 1.3 (OASIS Standard)', operations: all,
        collection: true },
      { name: 'Trust14', prefix: 'wst', ns: terms.trust13,
        title: 'WS-Trust 1.4 (OASIS Standard): 1.3\'s messages, ActAs in ' +
               terms.trust14, operations: all, collection: true }
    ];
    log.debug("Leaving WsTrustMetadata.versions().");
    return out;
  }

  /**
   * The request's action, as WS-Trust names it: the version's namespace,
   * `/RST/` and the operation. The service reads `wst:RequestType`, not
   * this, so it is what a client sends rather than what it must send.
   *
   * @param version - the version
   * @param operation - Issue, Renew, Validate or Cancel
   * @returns the action URI
   */
  private static inputAction(version: TrustVersion,
                             operation: string): string {
    log.debug("Entering WsTrustMetadata.inputAction().");
    const out = version.ns + '/RST/' + operation;
    log.debug("Leaving WsTrustMetadata.inputAction().");
    return out;
  }

  /**
   * The answer's action, as `wstrust.ts` writes it: the model's `wst.action`
   * term relative to the version's namespace.
   *
   * @param version - the version
   * @param operation - Issue, Renew, Validate or Cancel
   * @returns the action URI
   */
  private static outputAction(version: TrustVersion,
                              operation: string): string {
    log.debug("Entering WsTrustMetadata.outputAction().");
    // The same rule the endpoint answers by: the pre-OASIS versions name the
    // operation (RSTR/Issue …), 1.3 and 1.4 the "Final" actions.
    const preOasis = !version.collection;
    let term = preOasis ? operation.toLowerCase()
      : operation.toLowerCase() + 'Final';
    if (operation === 'Issue' && !preOasis) {
      term = 'issueFinal';
    }
    const out = WsModel.relative('wst.action', term, version.ns);
    log.debug("Leaving WsTrustMetadata.outputAction().");
    return out;
  }

  /**
   * One open element: the version's own name, whose children the service's
   * writer and reader define (`models/ws/wstrust.tsp`), so a schema here
   * would be a second, weaker statement of them.
   *
   * @param name - the element's local name
   * @returns the element declaration
   */
  private static openElement(name: string): string {
    log.debug("Entering WsTrustMetadata.openElement().");
    const out = '<xsd:element name="' + name + '"><xsd:complexType>' +
      '<xsd:sequence><xsd:any namespace="##any" processContents="lax" ' +
      'minOccurs="0" maxOccurs="unbounded"/></xsd:sequence>' +
      '<xsd:anyAttribute namespace="##other" processContents="lax"/>' +
      '</xsd:complexType></xsd:element>';
    log.debug("Leaving WsTrustMetadata.openElement().");
    return out;
  }

  /**
   * A schema per trust namespace, declaring the elements the messages carry
   * in that namespace, and the 1.4 namespace's ActAs.
   *
   * @param terms - the model's values
   * @returns the wsdl:types
   */
  private static types(terms: Terms): string {
    log.debug("Entering WsTrustMetadata.types().");
    const schema = (ns: string, names: string[]): string => {
      return '<xsd:schema targetNamespace="' + Html.esc(ns) + '" ' +
        'elementFormDefault="qualified">' +
        names.map((one) => this.openElement(one)).join('') +
        '</xsd:schema>';
    };
    const rst = 'RequestSecurityToken';
    const rstr = 'RequestSecurityTokenResponse';
    const rstrc = 'RequestSecurityTokenResponseCollection';
    const out = '<wsdl:types>' +
      schema(terms.trust2004, [rst, rstr]) +
      schema(terms.trust2005, [rst, rstr, rstrc]) +
      schema(terms.trust13, [rst, rstr, rstrc]) +
      schema(terms.trust14, ['ActAs']) +
      '</wsdl:types>';
    log.debug("Leaving WsTrustMetadata.types().");
    return out;
  }

  /**
   * The messages, one set per namespace (1.4 shares 1.3's).
   *
   * @param terms - the model's values
   * @returns the wsdl:message elements
   */
  private static messages(terms: Terms): string {
    log.debug("Entering WsTrustMetadata.messages().");
    let out = '';
    this.versions(terms).filter((one) => {
      return one.name !== 'Trust14';
    }).forEach((one) => {
      const message = (suffix: string, element: string): string => {
        return '<wsdl:message name="' + one.name + suffix + '">' +
          '<wsdl:part name="body" element="' + one.prefix + ':' + element +
          '"/></wsdl:message>';
      };
      out += message('RST', 'RequestSecurityToken') +
        message('RSTR', 'RequestSecurityTokenResponse');
      if (one.collection) {
        out += message('RSTRC', 'RequestSecurityTokenResponseCollection');
      }
    });
    log.debug("Leaving WsTrustMetadata.messages().");
    return out;
  }

  /**
   * The message names a version's operation reads and answers.
   *
   * @param version - the version
   * @param operation - the operation
   * @returns the input and output message QNames
   */
  private static messagesOf(version: TrustVersion,
                            operation: string): { input: string;
                                                  output: string } {
    log.debug("Entering WsTrustMetadata.messagesOf().");
    const base = version.name === 'Trust14' ? 'Trust13' : version.name;
    const output = operation === 'Issue' && version.collection
      ? base + 'RSTRC' : base + 'RSTR';
    const out = { input: 'tns:' + base + 'RST', output: 'tns:' + output };
    log.debug("Leaving WsTrustMetadata.messagesOf().");
    return out;
  }

  /**
   * A port type per version, each operation's input and output naming its
   * action.
   *
   * @param terms - the model's values
   * @returns the portType elements
   */
  private static portTypes(terms: Terms): string {
    log.debug("Entering WsTrustMetadata.portTypes().");
    let out = '';
    this.versions(terms).forEach((version) => {
      let ops = '';
      version.operations.forEach((name) => {
        const pair = this.messagesOf(version, name);
        ops += '<wsdl:operation name="' + name + '">' +
          '<wsdl:input message="' + pair.input + '" wsam:Action="' +
          Html.esc(this.inputAction(version, name)) + '"/>' +
          '<wsdl:output message="' + pair.output + '" wsam:Action="' +
          Html.esc(this.outputAction(version, name)) + '"/>' +
          '</wsdl:operation>';
      });
      out += '<wsdl:portType name="' + version.name + '">' +
        '<wsdl:documentation>' + Html.esc(version.title) +
        '</wsdl:documentation>' + ops + '</wsdl:portType>';
    });
    log.debug("Leaving WsTrustMetadata.portTypes().");
    return out;
  }

  /**
   * Two SOAP bindings per version. SOAP 1.1's soapAction and SOAP 1.2's
   * action parameter carry the input action; the service reads neither.
   *
   * @param terms - the model's values
   * @returns the binding elements
   */
  private static bindings(terms: Terms): string {
    log.debug("Entering WsTrustMetadata.bindings().");
    let out = '';
    this.versions(terms).forEach((version) => {
      [['Soap11', 'soap'], ['Soap12', 'soap12']].forEach((pair) => {
        const prefix = pair[1];
        let ops = '';
        version.operations.forEach((name) => {
          ops += '<wsdl:operation name="' + name + '">' +
            '<' + prefix + ':operation soapAction="' +
            Html.esc(this.inputAction(version, name)) + '" ' +
            'style="document"/>' +
            '<wsdl:input><' + prefix + ':body use="literal"/>' +
            '</wsdl:input>' +
            '<wsdl:output><wsp:PolicyReference URI="#IssuedTokenTypes"/>' +
            '<' + prefix + ':body use="literal"/></wsdl:output>' +
            '</wsdl:operation>';
        });
        out += '<wsdl:binding name="' + version.name + pair[0] + '" ' +
          'type="tns:' + version.name + '">' +
          '<wsp:PolicyReference URI="#RequesterAuthentication"/>' +
          '<' + prefix + ':binding style="document" transport="' +
          TRANSPORT + '"/>' + ops + '</wsdl:binding>';
      });
    });
    log.debug("Leaving WsTrustMetadata.bindings().");
    return out;
  }

  /**
   * Eight ports, every one at `{base}/sts`: the endpoint reads the version
   * from the request's own namespace.
   *
   * @param base - the realm's base URL
   * @param terms - the model's values
   * @returns the service
   */
  private static service(base: string, terms: Terms): string {
    log.debug("Entering WsTrustMetadata.service().");
    const location = Html.esc(base + '/sts');
    let ports = '';
    this.versions(terms).forEach((version) => {
      ports += '<wsdl:port name="' + version.name + 'Soap11" binding="tns:' +
        version.name + 'Soap11"><soap:address location="' + location +
        '"/></wsdl:port>' +
        '<wsdl:port name="' + version.name + 'Soap12" binding="tns:' +
        version.name + 'Soap12"><soap12:address location="' + location +
        '"/></wsdl:port>';
    });
    const out = '<wsdl:service name="SecurityTokenService">' + ports +
      '</wsdl:service>';
    log.debug("Leaving WsTrustMetadata.service().");
    return out;
  }
}

export = WsTrustMetadata;
