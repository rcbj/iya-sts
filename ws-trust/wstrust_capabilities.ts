// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws-trust/wstrust_capabilities.ts
//
// ---------------------------------------------------------------------------
// WHAT `/sts` ACCEPTS, WHAT IT ISSUES, AND WHICH PAIRS WORK (#958).
//
// WS-SecurityPolicy can say "a UsernameToken" or "an issued token of this
// type", but it has no way to say that a credential CAN be exchanged for a
// token type, or only under conditions. So this file holds the one
// capability model: the input credentials, the output token types, and every
// input/output pair as supported, conditional or unsupported, each with the
// conditions that decide it. It is built from the same flags the endpoint
// reads (`WsTrustMetadata.liveFlags()`), so it changes when they do.
//
// It is published as an IYA-STS extension, NOT as a WS-* standard: the
// document at `GET /sts/metadata/capabilities`, in the namespace
// `urn:iya-sts:metadata:token-capabilities:1`, validated by the schema at
// `GET /sts/metadata/capabilities.xsd`. The WSDL names that document, and
// the WS-MetadataExchange answer at `POST /sts/mex` carries it as a section
// of its own dialect. A token type is always its standard URI; the ids are
// this document's own names for a row and nothing else.
//
// THE VERSIONING RULE, the one a client relies on. The version is in the
// namespace (`:1`) and repeated on the root. A change that adds an element,
// an attribute or a condition `kind` keeps version 1, and a client ignores
// what it does not know: every element has an extension point, and an
// unknown `kind` is a condition the client cannot check, so the pair is
// conditional for it. A change that alters a meaning gets a new namespace.
//
// WHY THE PAIRS ARE SO REGULAR. Every enabled credential authenticates the
// requester, and the token issued depends on the requester, the AppliesTo,
// the TokenType and the issuance policy, not on which credential proved who
// the requester is (`wstrust.ts`'s handleRst() and issueKerberos()). So
// SAML 2.0, SAML 1.1 and JWT are supported from every enabled credential,
// and Kerberos is conditional on the same three things from every one. The
// matrix is still written out pair by pair, because the ticket's point is
// that a client may not infer it, and the next credential may not be
// regular.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import Html = require('../common/html');
import Krb5Tokens = require('../kerberos/krb5_tokens');
import WsModel = require('./ws_model');

const { log } = helpers;

const NS = 'urn:iya-sts:metadata:token-capabilities:1';
const XSD_NS = 'http://www.w3.org/2001/XMLSchema';
// The two token type URIs no model of this service holds: the WSS
// UsernameToken Profile's and the X.509 Token Profile's.
const USERNAME_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-username-token-profile-1.0#UsernameToken';
const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-x509-token-profile-1.0#X509v3';

type Flags = {
  acceptKerberos: boolean;
  issueKerberos: boolean;
  acceptClientCertificate: boolean;
  verifiesCredentials: boolean;
};

type Condition = {
  kind: string;
  setting?: string;
  text: string;
};

type InputToken = {
  id: string;
  name: string;
  enabled: boolean;
  tokenTypes: string[];
  policyAssertion: string;
  conditions: Condition[];
};

type OutputToken = {
  id: string;
  name: string;
  enabled: boolean;
  isDefault: boolean;
  tokenTypes: string[];
  proofKey: string;
  operations: string[];
  conditions: Condition[];
};

type Combination = {
  input: string;
  output: string;
  support: 'supported' | 'conditional' | 'unsupported';
  conditions: Condition[];
};

type Model = {
  issuer: string;
  endpoint: string;
  inputs: InputToken[];
  outputs: OutputToken[];
  delegation: string[];
  combinations: Combination[];
};

/**
 * The capability model and the two documents written from it (#958).
 */
class WsTrustCapabilities {
  /** The extension's namespace, version 1. */
  static readonly NAMESPACE = NS;

  /**
   * The model, from the flags the endpoint runs with.
   *
   * @param base - the realm's base URL, no trailing slash
   * @param issuer - the issuer every token from this STS names
   * @param flags - the runtime flags (`WsTrustMetadata.liveFlags()`)
   * @returns the model
   */
  static model(base: string, issuer: string, flags: Flags): Model {
    log.debug("Entering WsTrustCapabilities.model().");
    const root = String(base || '').replace(/\/+$/, '');
    const inputs = this.inputs(issuer, flags);
    const outputs = this.outputs(flags);
    const combinations: Combination[] = [];
    inputs.forEach((input) => {
      outputs.forEach((output) => {
        combinations.push(this.combination(input, output));
      });
    });
    const delegation = ['saml2', 'saml11', 'jwt'];
    if (flags.acceptKerberos) {
      delegation.push('kerberos');
    }
    const out = { issuer: issuer, endpoint: root + '/sts', inputs: inputs,
                  outputs: outputs, delegation: delegation,
                  combinations: combinations };
    log.debug("Leaving WsTrustCapabilities.model().");
    return out;
  }

  /**
   * The credentials, in the order the endpoint looks for them.
   *
   * @param issuer - this STS's issuer
   * @param flags - the runtime flags
   * @returns the input rows
   */
  private static inputs(issuer: string, flags: Flags): InputToken[] {
    log.debug("Entering WsTrustCapabilities.inputs().");
    const value = Krb5Tokens.VALUE_TYPES;
    const own = (): Condition => {
      return { kind: 'issuer', text: 'In product mode, issued by ' + issuer +
               ' and inside its validity period.' };
    };
    const verified: Condition[] = flags.verifiesCredentials
      ? [] : [{ kind: 'mode', text: 'Credentials are not verified in ' +
                'this mode; product mode verifies every one.' }];
    const out: InputToken[] = [
      { id: 'x509-signature', name: 'WS-Security X.509 signature',
        enabled: true, tokenTypes: [X509V3],
        policyAssertion: 'sp:X509Token/sp:WssX509V3Token11',
        conditions: [{ kind: 'signature', text: 'Over the SOAP Body and ' +
          'the wsu:Timestamp, exclusive canonicalisation; or HMAC with a ' +
          'Kerberos token\'s session key.' }].concat(verified) },
      { id: 'username-token', name: 'WS-Security UsernameToken',
        enabled: true, tokenTypes: [USERNAME_TOKEN],
        policyAssertion: 'sp:UsernameToken/sp:WssUsernameToken11',
        conditions: [{ kind: 'subject', text: 'A person or service ' +
          'account with their password (an application password when ' +
          'they must hold a second factor), or an application\'s ' +
          'identifier with one of its client secrets.' }]
          .concat(verified) },
      { id: 'saml2', name: 'SAML 2.0 assertion', enabled: true,
        tokenTypes: [WsModel.term('wst.tokenType', 'saml2')],
        policyAssertion: 'sp:SamlToken/sp:WssSamlV20Token11',
        conditions: [own()].concat(verified) },
      { id: 'saml11', name: 'SAML 1.1 assertion', enabled: true,
        tokenTypes: [WsModel.term('wst.tokenType', 'saml11'),
                     WsModel.term('wst.tokenType', 'saml11Namespace')],
        policyAssertion: 'sp:SamlToken/sp:WssSamlV11Token11',
        conditions: [own()].concat(verified) },
      { id: 'jwt', name: 'JWT', enabled: true,
        tokenTypes: [WsModel.term('wst.tokenType', 'jwt')],
        policyAssertion: 'sp:IssuedToken',
        conditions: [{ kind: 'carrier', text: 'In a BinarySecurityToken ' +
          'whose ValueType is the JWT token type.' }, own()]
          .concat(verified) },
      { id: 'kerberos', name: 'Kerberos AP-REQ (WSS Kerberos Token ' +
          'Profile 1.1)', enabled: !!flags.acceptKerberos,
        tokenTypes: [value.AP_REQ, value.GSS_AP_REQ, value.AP_REQ_1510,
                     value.GSS_AP_REQ_1510, value.AP_REQ_4120,
                     value.GSS_AP_REQ_4120],
        policyAssertion: 'sp:KerberosToken/sp:WssKerberosV5ApReqToken11',
        conditions: [{ kind: 'setting', setting: 'wstrust.acceptKerberos',
                       text: 'Accepted only while this setting is on.' },
                     { kind: 'target', text: 'For this service\'s own ' +
                       'service principal.' }] },
      { id: 'tls-client-certificate', name: 'TLS client certificate',
        enabled: !!flags.acceptClientCertificate, tokenTypes: [],
        policyAssertion: 'sp:HttpsToken/sp:RequireClientCertificate',
        conditions: [{ kind: 'setting',
                       setting: 'wstrust.acceptClientCertificate',
                       text: 'Accepted only while this setting is on.' },
                     { kind: 'precedence', text: 'Read only when the ' +
                       'message carries none of the credentials above.' }] },
      { id: 'none', name: 'No credential',
        enabled: !flags.verifiesCredentials, tokenTypes: [],
        policyAssertion: 'wsp:All (empty)',
        conditions: [{ kind: 'mode', text: 'Development mode only; ' +
          'product mode refuses a request with no credential.' }] }
    ];
    log.debug("Leaving WsTrustCapabilities.inputs().");
    return out;
  }

  /**
   * The token types this STS issues.
   *
   * @param flags - the runtime flags
   * @returns the output rows
   */
  private static outputs(flags: Flags): OutputToken[] {
    log.debug("Entering WsTrustCapabilities.outputs().");
    const value = Krb5Tokens.VALUE_TYPES;
    const all = ['Issue', 'Renew', 'Validate', 'Cancel'];
    const out: OutputToken[] = [
      { id: 'saml2', name: 'SAML 2.0 assertion', enabled: true,
        isDefault: true, tokenTypes: [WsModel.term('wst.tokenType', 'saml2')],
        proofKey: 'Bearer', operations: all, conditions: [] },
      { id: 'saml11', name: 'SAML 1.1 assertion', enabled: true,
        isDefault: false,
        tokenTypes: [WsModel.term('wst.tokenType', 'saml11'),
                     WsModel.term('wst.tokenType', 'saml11Namespace')],
        proofKey: 'Bearer', operations: all, conditions: [] },
      { id: 'jwt', name: 'JWT', enabled: true, isDefault: false,
        tokenTypes: [WsModel.term('wst.tokenType', 'jwt')],
        proofKey: 'Bearer', operations: all, conditions: [] },
      { id: 'kerberos', name: 'Kerberos ticket (WSS Kerberos Token ' +
          'Profile 1.1)', enabled: !!flags.issueKerberos, isDefault: false,
        tokenTypes: [value.AP_REQ, value.GSS_AP_REQ, value.AP_REQ_1510,
                     value.GSS_AP_REQ_1510, value.AP_REQ_4120,
                     value.GSS_AP_REQ_4120],
        proofKey: 'SymmetricKey', operations: ['Issue', 'Validate'],
        conditions: [{ kind: 'setting', setting: 'wstrust.issueKerberos',
                       text: 'Issued only while this setting is on.' },
                     { kind: 'transport', text: 'Over TLS: the session ' +
                       'key is the proof token.' },
                     { kind: 'target', text: 'The AppliesTo is an ' +
                       'application with an SPN@REALM identifier or a ' +
                       'krb5ServicePrincipalName.' }] }
    ];
    log.debug("Leaving WsTrustCapabilities.outputs().");
    return out;
  }

  /**
   * One pair. Unsupported when either side is off; conditional when the
   * output carries conditions; supported otherwise. The issuance policy
   * decides every issuance and is not a condition of the pair.
   *
   * @param input - the credential
   * @param output - the token type
   * @returns the pair
   */
  private static combination(input: InputToken,
                             output: OutputToken): Combination {
    log.debug("Entering WsTrustCapabilities.combination().");
    const off = (row: { conditions: Condition[] }): Condition[] => {
      return row.conditions.filter((one) => one.kind === 'setting');
    };
    let out: Combination;
    if (!input.enabled || !output.enabled) {
      out = { input: input.id, output: output.id, support: 'unsupported',
              conditions: (input.enabled ? [] : off(input).concat(
                input.id === 'none' ? input.conditions : []))
                .concat(output.enabled ? [] : off(output)) };
    } else if (output.conditions.length) {
      out = { input: input.id, output: output.id, support: 'conditional',
              conditions: output.conditions.filter((one) => {
                return one.kind !== 'setting';
              }) };
    } else {
      out = { input: input.id, output: output.id, support: 'supported',
              conditions: [] };
    }
    log.debug("Leaving WsTrustCapabilities.combination(). " + out.support);
    return out;
  }

  /**
   * The capability document.
   *
   * @param base - the realm's base URL
   * @param issuer - this STS's issuer
   * @param flags - the runtime flags
   * @returns the XML
   */
  static document(base: string, issuer: string, flags: Flags): string {
    log.debug("Entering WsTrustCapabilities.document().");
    const out = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      this.element(this.model(base, issuer, flags), base) + '\n';
    log.debug("Leaving WsTrustCapabilities.document().");
    return out;
  }

  /**
   * The root element alone, for the WS-MetadataExchange section.
   *
   * @param model - the model
   * @param base - the realm's base URL
   * @returns the element
   */
  static element(model: Model, base: string): string {
    log.debug("Entering WsTrustCapabilities.element().");
    const e = Html.esc;
    const root = String(base || '').replace(/\/+$/, '');
    const conditions = (list: Condition[]): string => {
      return list.map((one) => {
        return '<iya:Condition kind="' + e(one.kind) + '"' +
          (one.setting ? ' setting="' + e(one.setting) + '"' : '') + '>' +
          e(one.text) + '</iya:Condition>';
      }).join('');
    };
    const types = (list: string[]): string => {
      return list.map((one) => {
        return '<iya:TokenType>' + e(one) + '</iya:TokenType>';
      }).join('');
    };
    const inputs = model.inputs.map((one) => {
      return '<iya:InputToken id="' + e(one.id) + '" enabled="' +
        one.enabled + '"><iya:Name>' + e(one.name) + '</iya:Name>' +
        types(one.tokenTypes) + '<iya:PolicyAssertion>' +
        e(one.policyAssertion) + '</iya:PolicyAssertion>' +
        conditions(one.conditions) + '</iya:InputToken>';
    }).join('');
    const outputs = model.outputs.map((one) => {
      return '<iya:OutputToken id="' + e(one.id) + '" enabled="' +
        one.enabled + '" default="' + one.isDefault + '"><iya:Name>' +
        e(one.name) + '</iya:Name>' + types(one.tokenTypes) +
        '<iya:ProofKey>' + e(one.proofKey) + '</iya:ProofKey>' +
        '<iya:Operations>' + e(one.operations.join(' ')) +
        '</iya:Operations>' + conditions(one.conditions) +
        '</iya:OutputToken>';
    }).join('');
    const pairs = model.combinations.map((one) => {
      return '<iya:Combination input="' + e(one.input) + '" output="' +
        e(one.output) + '" support="' + one.support + '"' +
        (one.conditions.length ? '>' + conditions(one.conditions) +
          '</iya:Combination>' : '/>');
    }).join('');
    const delegation = model.delegation.map((one) => {
      return '<iya:Token ref="' + e(one) + '"/>';
    }).join('');
    const out = '<iya:TokenCapabilities xmlns:iya="' + NS + '" ' +
      'version="1" endpoint="' + e(model.endpoint) + '" issuer="' +
      e(model.issuer) + '" schemaLocation="' +
      e(root + '/sts/metadata/capabilities.xsd') + '">' +
      '<iya:InputTokens>' + inputs + '</iya:InputTokens>' +
      '<iya:OutputTokens>' + outputs + '</iya:OutputTokens>' +
      '<iya:Combinations>' + pairs + '</iya:Combinations>' +
      '<iya:DelegationTokens>' + delegation + '</iya:DelegationTokens>' +
      '</iya:TokenCapabilities>';
    log.debug("Leaving WsTrustCapabilities.element().");
    return out;
  }

  /**
   * The extension's schema. Every complex type ends with an extension point
   * for another namespace and allows any attribute from one, so a version 1
   * client reads a later version 1 document.
   *
   * @returns the XSD
   */
  static schema(): string {
    log.debug("Entering WsTrustCapabilities.schema().");
    const ext = '<xsd:any namespace="##other" processContents="lax" ' +
      'minOccurs="0" maxOccurs="unbounded"/>';
    const anyAttr = '<xsd:anyAttribute namespace="##other" ' +
      'processContents="lax"/>';
    const out = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<xsd:schema xmlns:xsd="' + XSD_NS + '" xmlns:iya="' + NS + '" ' +
      'targetNamespace="' + NS + '" elementFormDefault="qualified" ' +
      'version="1">' +
      '<xsd:element name="TokenCapabilities" type="iya:TokenCapabilities"/>' +
      '<xsd:complexType name="TokenCapabilities"><xsd:sequence>' +
      '<xsd:element name="InputTokens"><xsd:complexType><xsd:sequence>' +
      '<xsd:element name="InputToken" type="iya:InputToken" minOccurs="0" ' +
      'maxOccurs="unbounded"/>' + ext + '</xsd:sequence>' + anyAttr +
      '</xsd:complexType></xsd:element>' +
      '<xsd:element name="OutputTokens"><xsd:complexType><xsd:sequence>' +
      '<xsd:element name="OutputToken" type="iya:OutputToken" ' +
      'minOccurs="0" maxOccurs="unbounded"/>' + ext + '</xsd:sequence>' +
      anyAttr + '</xsd:complexType></xsd:element>' +
      '<xsd:element name="Combinations"><xsd:complexType><xsd:sequence>' +
      '<xsd:element name="Combination" type="iya:Combination" ' +
      'minOccurs="0" maxOccurs="unbounded"/>' + ext + '</xsd:sequence>' +
      anyAttr + '</xsd:complexType></xsd:element>' +
      '<xsd:element name="DelegationTokens"><xsd:complexType>' +
      '<xsd:sequence><xsd:element name="Token" minOccurs="0" ' +
      'maxOccurs="unbounded"><xsd:complexType>' +
      '<xsd:attribute name="ref" type="xsd:NCName" use="required"/>' +
      anyAttr + '</xsd:complexType></xsd:element>' + ext +
      '</xsd:sequence>' + anyAttr + '</xsd:complexType></xsd:element>' +
      ext + '</xsd:sequence>' +
      '<xsd:attribute name="version" type="xsd:string" use="required"/>' +
      '<xsd:attribute name="endpoint" type="xsd:anyURI" use="required"/>' +
      '<xsd:attribute name="issuer" type="xsd:string" use="required"/>' +
      '<xsd:attribute name="schemaLocation" type="xsd:anyURI"/>' + anyAttr +
      '</xsd:complexType>' +
      '<xsd:complexType name="InputToken"><xsd:sequence>' +
      '<xsd:element name="Name" type="xsd:string"/>' +
      '<xsd:element name="TokenType" type="xsd:anyURI" minOccurs="0" ' +
      'maxOccurs="unbounded"/>' +
      '<xsd:element name="PolicyAssertion" type="xsd:string" ' +
      'minOccurs="0"/>' +
      '<xsd:element name="Condition" type="iya:Condition" minOccurs="0" ' +
      'maxOccurs="unbounded"/>' + ext + '</xsd:sequence>' +
      '<xsd:attribute name="id" type="xsd:NCName" use="required"/>' +
      '<xsd:attribute name="enabled" type="xsd:boolean" use="required"/>' +
      anyAttr + '</xsd:complexType>' +
      '<xsd:complexType name="OutputToken"><xsd:sequence>' +
      '<xsd:element name="Name" type="xsd:string"/>' +
      '<xsd:element name="TokenType" type="xsd:anyURI" ' +
      'maxOccurs="unbounded"/>' +
      '<xsd:element name="ProofKey" type="xsd:string"/>' +
      '<xsd:element name="Operations"><xsd:simpleType><xsd:list>' +
      '<xsd:simpleType><xsd:restriction base="xsd:token">' +
      '<xsd:enumeration value="Issue"/><xsd:enumeration value="Renew"/>' +
      '<xsd:enumeration value="Validate"/>' +
      '<xsd:enumeration value="Cancel"/></xsd:restriction>' +
      '</xsd:simpleType></xsd:list></xsd:simpleType></xsd:element>' +
      '<xsd:element name="Condition" type="iya:Condition" minOccurs="0" ' +
      'maxOccurs="unbounded"/>' + ext + '</xsd:sequence>' +
      '<xsd:attribute name="id" type="xsd:NCName" use="required"/>' +
      '<xsd:attribute name="enabled" type="xsd:boolean" use="required"/>' +
      '<xsd:attribute name="default" type="xsd:boolean" use="required"/>' +
      anyAttr + '</xsd:complexType>' +
      '<xsd:complexType name="Combination"><xsd:sequence>' +
      '<xsd:element name="Condition" type="iya:Condition" minOccurs="0" ' +
      'maxOccurs="unbounded"/>' + ext + '</xsd:sequence>' +
      '<xsd:attribute name="input" type="xsd:NCName" use="required"/>' +
      '<xsd:attribute name="output" type="xsd:NCName" use="required"/>' +
      '<xsd:attribute name="support" use="required"><xsd:simpleType>' +
      '<xsd:restriction base="xsd:token">' +
      '<xsd:enumeration value="supported"/>' +
      '<xsd:enumeration value="conditional"/>' +
      '<xsd:enumeration value="unsupported"/>' +
      '</xsd:restriction></xsd:simpleType></xsd:attribute>' + anyAttr +
      '</xsd:complexType>' +
      '<xsd:complexType name="Condition"><xsd:simpleContent>' +
      '<xsd:extension base="xsd:string">' +
      '<xsd:attribute name="kind" type="xsd:NCName" use="required"/>' +
      '<xsd:attribute name="setting" type="xsd:string"/>' + anyAttr +
      '</xsd:extension></xsd:simpleContent></xsd:complexType>' +
      '</xsd:schema>\n';
    log.debug("Leaving WsTrustCapabilities.schema().");
    return out;
  }
}

export = WsTrustCapabilities;
