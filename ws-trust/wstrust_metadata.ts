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
// which this one names. The document is not signed. Each port carries the
// realm's XML Encryption certificate as its endpoint identity (#1668, rcbj
// on #1908): the document is drawn per request and served no-store, so a
// development restart's or a rotation's key is in the next one. Until then
// a copy here was refused as yesterday's key, which no-store answers.
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
// EACH CREDENTIAL IS ITS OWN ALTERNATIVE in one wsp:ExactlyOne. An
// alternative is present only while the runtime flag that accepts it is on,
// including the empty alternative, which is development's missing credential
// and is absent whenever `mode.verifiesCredentials()` is true.
//
// THE MESSAGE SIGNATURE IS AN sp:AsymmetricBinding (#1668, rcbj on #1908,
// 2026-11-18). Until then its alternative was a bare sp:X509Token beside
// sp:SignedParts, which WS-SecurityPolicy 1.3 section 4 gives no meaning: a
// protection assertion says what is protected, and only a binding says with
// what. The binding is what the endpoint verifies (`crypto.js`'s
// readWsSecuritySignature()): the requester's X.509 v3 certificate as the
// InitiatorToken, always sent to the recipient, named by a Reference, a
// KeyIdentifier (thumbprint or Subject Key Identifier) or an issuer and
// serial (sp:Wss11); this realm's encryption certificate, the ports'
// endpoint identity, as the RecipientToken, never included; any
// header order (sp:Lax); whole elements only, by wsu:Id
// (sp:OnlySignEntireHeadersAndBody). It is written once per algorithm
// suite: sp:Basic256Sha256 in RequesterAuthentication, on the eight ports
// every client reads, and the IYA-STS suite (SUITE_NS) in
// RequesterAuthenticationIyaSuite, on eight ports of its own (IYA, below).
// Each port's messages offer encryption only under its own suite
// (offers()).
//
// NO sp:IncludeTimestamp. Section 6.2 makes it a property of every message
// under the binding, and requires the Timestamp to be integrity protected:
// the answer would have to carry a signed wsu:Timestamp, and this STS does
// not sign its answers. The request's Timestamp is still required, by the
// alternative's sp:SignedParts, as before.
//
// THE MESSAGE POLICIES (RequestProtection on every wsdl:input,
// ResponseProtection on every wsdl:output, each with an IyaSuite twin on
// the suite's ports) say what MAY be protected beyond that: see
// messagePolicy().
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
import WsEncryption = require('./ws_encryption');
import stsCrypto = require('../common/crypto');

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
const NEVER = SP_NS + '/IncludeToken/Never';
// THE IYA-STS ALGORITHM SUITE (rcbj on #1908, 2026-11-18): what product
// signs and encrypts with, which no WS-SecurityPolicy 1.2 or 1.3 suite names
// (none has AES-GCM). An assertion of this service's own under
// sp:AlgorithmSuite, the extension section 6.1 leaves open and Apache CXF
// uses for its GCM suites:
//   [Dig]      SHA-256          http://www.w3.org/2001/04/xmlenc#sha256
//   [Enc]      AES-256-GCM      http://www.w3.org/2009/xmlenc11#aes256-gcm
//   [Asym KW]  RSA-OAEP         http://www.w3.org/2009/xmlenc11#rsa-oaep,
//              DigestMethod SHA-256, MGF xmlenc11#mgf1sha256
//   [Asym Sig] RSA-SHA256       http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
//   [C14n]     exclusive        http://www.w3.org/2001/10/xml-exc-c14n#
// `crypto.js` writes exactly these for `rsa-oaep` and `aes256-gcm`.
const SUITE_NS = 'urn:iya-sts:ws-securitypolicy:algorithm-suite:1';
const SUITE_PREFIX = 'iyasp';
const SUITE_NAME = 'Basic256GcmRsaOaepSha256';
// THE SUITE HAS PORTS OF ITS OWN. Apache CXF builds every policy in a WSDL
// and refuses a policy whose sp:AlgorithmSuite it has no loader for, and an
// alternative it cannot build takes the whole policy with it: with the IYA
// suite inside RequesterAuthentication, CXF 4.0.5 could use no port at all
// (#1908's review). In a policy of its own, attached to bindings and ports
// of its own (this suffix), CXF logs "Failed to build the policy" and uses
// every other port as before; a client with a loader for SUITE_NS, or one
// that reads the suite, uses these.
const IYA = 'IyaSuite';
// WS-Addressing 1.0, whose EndpointReference a port carries, and WCF's
// identity namespace, whose Identity holds the encryption certificate.
const WSA10_NS = 'http://www.w3.org/2005/08/addressing';
const WSID_NS = 'http://schemas.xmlsoap.org/ws/2006/02/addressingidentity';
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
// XPath 1.0, the version an sp:XPath is in when no attribute says (WS-SP 1.3
// section 4.1.2), written out because WCF and Metro read it.
const XPATH10 = 'http://www.w3.org/TR/1999/REC-xpath-19991116';
// WS-Addressing's two header namespaces a request is sent with: the W3C
// recommendation and the 2004/08 member submission.
const WSA_SUBMISSION = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';
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
  // #1668: a request may be encrypted at all — this realm accepts
  // ciphertext no map names (`wstrust.acceptEncryptedElements`) and its
  // encryption certificate holds the RSA key both suites transport to.
  decryptsRequests?: boolean;
  // #1668: this realm also reads sp:Basic256Sha256's AES-256-CBC and
  // RSA-OAEP with MGF1-SHA-1. Product never does (#1455).
  readsBasic256?: boolean;
  // #1668: the service-wide response cipher is one of the two suites':
  // 'basic256sha256', 'iya', or '' for neither.
  responseSuite?: string;
  // Kept for the tests that say only "an answer may be encrypted", read
  // as the IYA-STS suite.
  encryptsResponses?: boolean;
  // #1668: the realm's XML Encryption certificate, base64 DER, which the
  // ports carry as their endpoint identity.
  encryptionCertificate?: string;
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
      this.policy('RequesterAuthentication' + IYA,
                  this.exactlyOne([this.signatureAlternative('iya', terms)])) +
      this.policy('IssuedTokenTypes', this.issued(flags, terms)) +
      this.policy('RequestProtection',
                  this.messagePolicy(true, this.offers(flags, true, ''),
                                     terms)) +
      this.policy('RequestProtection' + IYA,
                  this.messagePolicy(true, this.offers(flags, true, 'iya'),
                                     terms)) +
      (this.offers(flags, false, '')
        ? this.policy('ResponseProtection',
                      this.messagePolicy(false, true, terms)) : '') +
      (this.offers(flags, false, 'iya')
        ? this.policy('ResponseProtection' + IYA,
                      this.messagePolicy(false, true, terms)) : '') +
      this.types(terms) +
      this.messages(terms) +
      this.portTypes(terms) +
      this.bindings(terms, flags) +
      this.service(root, terms, flags.encryptionCertificate || '') +
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
      verifiesCredentials: !!mode.verifiesCredentials(),
      decryptsRequests: this.acceptsCiphertext(),
      readsBasic256: !!mode.usesBrokenAlgorithms() &&
        !!mode.allowsLegacyHashes(),
      responseSuite: this.responseSuiteOf(),
      encryptionCertificate: this.encryptionCertificate()
    };
    log.debug("Leaving WsTrustMetadata.liveFlags().");
    return out;
  }

  /**
   * The realm's XML Encryption certificate, base64 DER: the first that
   * `helpers.ownXmlEncryptionCertificates()` lists, the one its SAML
   * metadata offers and `crypto.decryptElement()` opens with. Read when the
   * document is drawn, so a rotation is in the next one (served no-store).
   *
   * @returns the certificate, or '' when there is none yet
   */
  static encryptionCertificate(): string {
    log.debug("Entering WsTrustMetadata.encryptionCertificate().");
    let out = '';
    try {
      const rows = helpers.ownXmlEncryptionCertificates();
      out = rows && rows[0] ? String(rows[0].certPem || '')
        .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') : '';
    } catch (e) {
      log.debug("Caught in WsTrustMetadata.encryptionCertificate(): " +
                ((e && e.message) || e));
      // No key set in this process yet: no identity to publish.
      out = '';
    }
    log.debug("Leaving WsTrustMetadata.encryptionCertificate(). " + !!out);
    return out;
  }

  /**
   * Whether a request may carry encryption the WSDL offers: the realm
   * accepts ciphertext no map names (`wstrust.acceptEncryptedElements`,
   * off by default), and its encryption certificate holds an RSA key, which
   * both suites' key transport needs.
   *
   * @returns true when both hold
   */
  static acceptsCiphertext(): boolean {
    log.debug("Entering WsTrustMetadata.acceptsCiphertext().");
    let rsa = false;
    try {
      const der = this.encryptionCertificate();
      const cert = der ? stsCrypto.parseCertificate(
        '-----BEGIN CERTIFICATE-----\n' +
        (der.match(/.{1,64}/g) || []).join('\n') +
        '\n-----END CERTIFICATE-----\n') : null;
      rsa = !!cert && cert.publicKey.asymmetricKeyType === 'rsa';
    } catch (e) {
      log.debug("Caught in WsTrustMetadata.acceptsCiphertext(): " +
                ((e && e.message) || e));
      // A certificate that will not parse is nothing to encrypt to.
      rsa = false;
    }
    const out = rsa &&
      config.value('wstrust.acceptEncryptedElements') === true;
    log.debug("Leaving WsTrustMetadata.acceptsCiphertext(). " + out);
    return out;
  }

  /**
   * Which suite the service-wide response cipher is: sp:Basic256Sha256's
   * AES-256-CBC with RSA-OAEP-MGF1P, or the IYA-STS suite's AES-256-GCM with
   * RSA-OAEP over SHA-256 (`WsEncryption.effectiveTransport()`, which turns
   * rsa-oaep-mgf1p into rsa-oaep where legacy hashes are refused). An
   * application's own cipher is not the document's: it is one document for
   * every application.
   *
   * @returns 'basic256sha256', 'iya', or '' for neither
   */
  static responseSuiteOf(): string {
    log.debug("Entering WsTrustMetadata.responseSuiteOf().");
    const cipher = WsEncryption.effectiveCipher('');
    const transport = WsEncryption.effectiveTransport('');
    const out = cipher === 'aes256-cbc' && transport === 'rsa-oaep-mgf1p'
      ? 'basic256sha256'
      : (cipher === 'aes256-gcm' && transport === 'rsa-oaep' ? 'iya' : '');
    log.debug("Leaving WsTrustMetadata.responseSuiteOf(). " + out);
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
      'It is not signed. Each port names this realm\'s XML Encryption ' +
        'certificate as its endpoint identity, the certificate a request ' +
        'is encrypted to; the signing certificate is at ' + base +
        '/sts/cert.',
      'The message signature is an AsymmetricBinding under ' +
        'sp:Basic256Sha256 and under the IYA-STS suite ' + SUITE_NS + ' ' +
        SUITE_NAME + ': SHA-256, AES-256-GCM, RSA-OAEP with SHA-256 and ' +
        'MGF1-SHA-256, RSA-SHA256 and exclusive c14n.',
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
      'Eight more ports, each named with the suffix IyaSuite, are the ' +
        'same contract with the message signature under the IYA-STS ' +
        'suite alone, kept apart so a client that cannot build that suite ' +
        'still uses the other eight.',
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
    const parts: string[] = [this.signatureAlternative('basic256sha256',
                                                      terms)];
    parts.push(
      this.all(this.nested('UsernameToken', '<sp:WssUsernameToken11/>')),
      this.all(this.nested('SamlToken', '<sp:WssSamlV20Token11/>')),
      this.all(this.nested('SamlToken', '<sp:WssSamlV11Token11/>')),
      this.all(this.issuedToken(terms.jwt)));
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
   * assertion, so both are named this way. Its nested wsp:Policy is
   * required (WS-SecurityPolicy 1.2 section 5.4.2's syntax has no `?` on
   * it), empty here: without it Apache CXF refused to load the WSDL at all
   * ("sp:IssuedToken must have an inner wsp:Policy element"), found on
   * #1908's review.
   *
   * @param tokenType - the token type URI
   * @returns the element
   */
  private static issuedToken(tokenType: string): string {
    log.debug("Entering WsTrustMetadata.issuedToken().");
    const out = '<sp:IssuedToken sp:IncludeToken="' + INCLUDE + '">' +
      '<sp:RequestSecurityTokenTemplate><wst:TokenType>' +
      Html.esc(tokenType) + '</wst:TokenType>' +
      '</sp:RequestSecurityTokenTemplate><wsp:Policy/></sp:IssuedToken>';
    log.debug("Leaving WsTrustMetadata.issuedToken().");
    return out;
  }

  /**
   * The message signature's binding (the file's header says why each
   * property is there, and why sp:IncludeTimestamp is not).
   *
   * @returns the sp:AsymmetricBinding
   */
  private static asymmetricBinding(suite: string): string {
    log.debug("Entering WsTrustMetadata.asymmetricBinding(). " + suite);
    const named = suite === 'iya'
      ? '<' + SUITE_PREFIX + ':' + SUITE_NAME + ' xmlns:' + SUITE_PREFIX +
        '="' + SUITE_NS + '"/>'
      : '<sp:Basic256Sha256/>';
    const out = '<sp:AsymmetricBinding><wsp:Policy>' +
      '<sp:InitiatorToken><wsp:Policy>' +
      this.nested('X509Token', '<sp:WssX509V3Token11/>') +
      '</wsp:Policy></sp:InitiatorToken>' +
      '<sp:RecipientToken><wsp:Policy>' +
      '<sp:X509Token sp:IncludeToken="' + NEVER + '"><wsp:Policy>' +
      '<sp:WssX509V3Token11/></wsp:Policy></sp:X509Token>' +
      '</wsp:Policy></sp:RecipientToken>' +
      '<sp:AlgorithmSuite><wsp:Policy>' + named + '</wsp:Policy>' +
      '</sp:AlgorithmSuite>' +
      '<sp:Layout><wsp:Policy><sp:Lax/></wsp:Policy></sp:Layout>' +
      '<sp:OnlySignEntireHeadersAndBody/>' +
      '</wsp:Policy></sp:AsymmetricBinding>';
    log.debug("Leaving WsTrustMetadata.asymmetricBinding().");
    return out;
  }

  /**
   * The message signature's alternative under one suite: the binding, the
   * key references, and the parts that must be signed.
   *
   * @param suite - 'basic256sha256' or 'iya'
   * @param terms - the model's values
   * @returns the All
   */
  private static signatureAlternative(suite: string, terms: Terms): string {
    log.debug("Entering WsTrustMetadata.signatureAlternative(). " + suite);
    const out = this.all(this.asymmetricBinding(suite) + this.wss11() +
                         this.signedParts(terms.utility));
    log.debug("Leaving WsTrustMetadata.signatureAlternative().");
    return out;
  }

  /**
   * Whether a message may be encrypted under one suite. A request: the realm
   * accepts ciphertext no map names, and reads the suite's ciphers —
   * sp:Basic256Sha256's AES-256-CBC and RSA-OAEP-MGF1P only where broken
   * algorithms and legacy hashes are allowed (never in product), the
   * IYA-STS suite's always. An answer: the service-wide response cipher is
   * the suite's.
   *
   * @param flags - the realm's flags
   * @param input - the request, else the answer
   * @param suite - '' for sp:Basic256Sha256's ports, 'iya' for the others
   * @returns true when that encryption is offered
   */
  private static offers(flags: Flags, input: boolean, suite: string):
    boolean {
    log.debug("Entering WsTrustMetadata.offers().");
    let out: boolean;
    if (input) {
      out = !!flags.decryptsRequests && (suite === 'iya' ||
                                         !!flags.readsBasic256);
    } else {
      const answer = flags.encryptsResponses ? 'iya'
        : String(flags.responseSuite || '');
      out = suite === 'iya' ? answer === 'iya' : answer === 'basic256sha256';
    }
    log.debug("Leaving WsTrustMetadata.offers(). " + out);
    return out;
  }

  /**
   * The IYA-STS algorithm suite's schema: one empty assertion, in the
   * manner of WS-SecurityPolicy 1.2's own (`sp:QNameAssertionType`), for a
   * validator to read beside the published ones. Not served: the suite is
   * named, and its algorithms listed, in `docs/v1.1.0/ws-trust.md`.
   *
   * @returns the XSD
   */
  static suiteSchema(): string {
    log.debug("Entering WsTrustMetadata.suiteSchema().");
    const out = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<xs:schema xmlns:xs="' + XSD_NS + '" targetNamespace="' + SUITE_NS +
      '" elementFormDefault="qualified"><xs:element name="' + SUITE_NAME +
      '"><xs:complexType><xs:anyAttribute namespace="##any" ' +
      'processContents="lax"/></xs:complexType></xs:element></xs:schema>\n';
    log.debug("Leaving WsTrustMetadata.suiteSchema().");
    return out;
  }

  /**
   * The WS-Security 1.1 key references the endpoint resolves a signer's
   * certificate by, beside a direct Reference to a BinarySecurityToken:
   * a KeyIdentifier (a Subject Key Identifier), an issuer and serial, and
   * a SHA-1 thumbprint.
   *
   * @returns the sp:Wss11
   */
  private static wss11(): string {
    log.debug("Entering WsTrustMetadata.wss11().");
    const out = '<sp:Wss11><wsp:Policy><sp:MustSupportRefKeyIdentifier/>' +
      '<sp:MustSupportRefIssuerSerial/><sp:MustSupportRefThumbprint/>' +
      '</wsp:Policy></sp:Wss11>';
    log.debug("Leaving WsTrustMetadata.wss11().");
    return out;
  }

  /**
   * WHAT A MESSAGE MAY PROTECT BEYOND WHAT IS REQUIRED (#1668, rcbj on
   * #1908, 2026-11-18): every header and the Body may be signed, and may
   * be encrypted, and need not be. The required half is the binding
   * alternative's sp:SignedParts, the Body and the Timestamp.
   *
   * OPTIONAL AS AN EXPLICIT wsp:ExactlyOne WHOSE FIRST ALTERNATIVE IS
   * EMPTY, not wsp:Optional="true". The two are the same policy once
   * normalized (WS-Policy 1.5 section 4.3.1), but the order of the
   * alternatives Optional normalizes to is each processor's own, and the
   * order is what a client acts on: WCF and Metro take the first
   * alternative they support, Apache CXF the one with the fewest
   * assertions. Written out, every one of them chooses the message as it
   * is sent today, and a client protects more only when it is configured
   * to. Two ExactlyOnes in the policy's wsp:All make four alternatives,
   * not one per combination written out.
   *
   * SIGNING. An empty sp:SignedParts is the Body and every header block
   * (WS-SecurityPolicy 1.3 section 4.1.1); a sender leaves out its own
   * wsse:Security header. The endpoint accepts a signature with any
   * further Reference by wsu:Id under exclusive c14n, and verifies each.
   * An answer is never signed, so ResponseProtection offers no signing.
   *
   * ENCRYPTION, only where the port's suite is one this realm would
   * accept it under (offers()): a request's where
   * `wstrust.acceptEncryptedElements` is on, the encryption key is RSA and
   * the suite's ciphers are read; an answer's where the service-wide
   * cipher is the suite's. sp:EncryptedParts names the Body's content and
   * WS-Addressing's two header namespaces, which WCF reads;
   * sp:EncryptedElements names every other header block and a
   * UsernameToken in the security header by XPath 1.0, which WCF does not
   * read, so it is an alternative of its own. A request's ciphertext is
   * opened wherever it is — an EncryptedData of type Element or Content,
   * a WS-Security 1.1 EncryptedHeader, its key in its own KeyInfo or in an
   * EncryptedKey in the security header that lists it — and is held to an
   * application's map only where that application requires it
   * (`ws_encryption.ts`). An answer's elements are encrypted to the
   * InitiatorToken (the signer's certificate) unless the application names
   * another recipient, each EncryptedData carrying its EncryptedKey.
   *
   * @param input - the request's policy, else the answer's
   * @param encrypts - encryption is offered (offers())
   * @param terms - the model's values
   * @returns the policy's content
   */
  private static messagePolicy(input: boolean, encrypts: boolean,
                               terms: Terms): string {
    log.debug("Entering WsTrustMetadata.messagePolicy().");
    const envelopeHeader = "/*[local-name()='Envelope']" +
      "/*[local-name()='Header']";
    const xpaths = (paths: string[]): string => {
      return paths.map((one) => {
        return '<sp:XPath>' + Html.esc(one) + '</sp:XPath>';
      }).join('');
    };
    const headers = '<sp:Header Namespace="' + Html.esc(terms.addressing) +
      '"/>' + (input ? '<sp:Header Namespace="' + WSA_SUBMISSION + '"/>'
                     : '');
    let out = '';
    if (input) {
      out += this.exactlyOne(['<wsp:All/>',
                              this.all('<sp:SignedParts/>')]);
    }
    if (encrypts) {
      const others = [envelopeHeader + "/*[not(local-name()='Security' and " +
        "namespace-uri()='" + terms.secext + "')]"];
      if (input) {
        others.push(envelopeHeader + "/*[local-name()='Security' and " +
          "namespace-uri()='" + terms.secext + "']/*[local-name()=" +
          "'UsernameToken']");
      }
      out += this.exactlyOne(['<wsp:All/>',
        this.all('<sp:EncryptedParts><sp:Body/>' + headers +
                 '</sp:EncryptedParts>'),
        this.all('<sp:EncryptedParts><sp:Body/></sp:EncryptedParts>' +
                 '<sp:EncryptedElements XPathVersion="' + XPATH10 + '">' +
                 xpaths(others) + '</sp:EncryptedElements>')]);
    }
    log.debug("Leaving WsTrustMetadata.messagePolicy().");
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
   * Each input names RequestProtection, and each output ResponseProtection
   * while there is one (WS-Policy 1.5 Attachment section 4.1.1, a message
   * policy subject).
   *
   * @param terms - the model's values
   * @param flags - which encryption each binding's messages offer
   * @returns the binding elements
   */
  private static bindings(terms: Terms, flags: Flags): string {
    log.debug("Entering WsTrustMetadata.bindings().");
    let out = '';
    ['', IYA].forEach((suffix) => {
      const answered = this.offers(flags, false, suffix ? 'iya' : '');
      this.versions(terms).forEach((version) => {
        [['Soap11', 'soap'], ['Soap12', 'soap12']].forEach((pair) => {
          const prefix = pair[1];
          let ops = '';
          version.operations.forEach((name) => {
            ops += '<wsdl:operation name="' + name + '">' +
              '<' + prefix + ':operation soapAction="' +
              Html.esc(this.inputAction(version, name)) + '" ' +
              'style="document"/>' +
              '<wsdl:input>' +
              '<wsp:PolicyReference URI="#RequestProtection' + suffix +
              '"/><' + prefix + ':body use="literal"/></wsdl:input>' +
              '<wsdl:output><wsp:PolicyReference URI="#IssuedTokenTypes"/>' +
              (answered ? '<wsp:PolicyReference URI="#ResponseProtection' +
                          suffix + '"/>' : '') +
              '<' + prefix + ':body use="literal"/></wsdl:output>' +
              '</wsdl:operation>';
          });
          out += '<wsdl:binding name="' + version.name + pair[0] + suffix +
            '" type="tns:' + version.name + '">' +
            '<wsp:PolicyReference URI="#RequesterAuthentication' + suffix +
            '"/><' + prefix + ':binding style="document" transport="' +
            TRANSPORT + '"/>' + ops + '</wsdl:binding>';
        });
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
   * @param certificate - the encryption certificate, base64 DER, or ''
   * @returns the service
   */
  private static service(base: string, terms: Terms,
                         certificate: string): string {
    log.debug("Entering WsTrustMetadata.service().");
    const location = Html.esc(base + '/sts');
    // THE ENCRYPTION CERTIFICATE AS THE PORT'S IDENTITY (rcbj on #1908,
    // 2026-11-18), where WCF reads it: a WS-Addressing EndpointReference
    // whose Identity holds a ds:KeyInfo. It is the RecipientToken a request
    // is encrypted to, the same for every application of the realm, so
    // the one-document rule holds. The document is drawn per request and
    // served no-store, so a rotation is in the next one.
    const identity = certificate
      ? '<wsa10:EndpointReference xmlns:wsa10="' + WSA10_NS + '">' +
        '<wsa10:Address>' + location + '</wsa10:Address>' +
        '<wsid:Identity xmlns:wsid="' + WSID_NS + '">' +
        '<ds:KeyInfo xmlns:ds="' + DS_NS + '"><ds:X509Data>' +
        '<ds:X509Certificate>' + Html.esc(certificate) +
        '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></wsid:Identity>' +
        '</wsa10:EndpointReference>'
      : '';
    let ports = '';
    ['', IYA].forEach((suffix) => {
      this.versions(terms).forEach((version) => {
        ports += '<wsdl:port name="' + version.name + 'Soap11' + suffix +
          '" binding="tns:' + version.name + 'Soap11' + suffix + '">' +
          '<soap:address location="' + location + '"/>' + identity +
          '</wsdl:port>' +
          '<wsdl:port name="' + version.name + 'Soap12' + suffix +
          '" binding="tns:' + version.name + 'Soap12' + suffix + '">' +
          '<soap12:address location="' + location + '"/>' + identity +
          '</wsdl:port>';
      });
    });
    const out = '<wsdl:service name="SecurityTokenService">' + ports +
      '</wsdl:service>';
    log.debug("Leaving WsTrustMetadata.service().");
    return out;
  }
}

export = WsTrustMetadata;
