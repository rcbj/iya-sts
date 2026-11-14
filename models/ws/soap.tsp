// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/ws/soap.tsp
//
// Written by hand (#1579). THE SOAP ENVELOPES AND WHAT RIDES IN THEIR
// HEADERS, AS THIS SERVICE SPEAKS THEM: SOAP 1.1 and SOAP 1.2, each its own
// Envelope, Header, Body and Fault (the two Faults have different shapes),
// the one WS-Addressing header this service writes (wsa:Action), the
// WS-Addressing endpoint reference, WS-Policy's AppliesTo, and the
// WS-Security elements and URIs this service writes or reads as facts — a
// BinarySecurityToken, a SecurityTokenReference and its KeyIdentifier, and
// the UsernameToken, Timestamp and Security header it reads. `/sts`
// (`ws-trust/wstrust.ts`) answers in the SOAP version it was asked in.
//
// The Body's content is WS-Trust's (`wstrust.tsp`), and the vocabularies
// here are what `ws-trust/ws_model.ts` asks for by name. Reading a SOAP
// document, canonicalising it and checking a WS-Security signature stay in
// code (`common/crypto.js`), and so does everything that needs state
// (ws-trust/CLAUDE.md, *THE MESSAGES ARE THE MODEL'S*).

import "../lib/saml_lib.tsp";
import "./wstrust.tsp";

using IyaSts.SamlLib;

namespace IyaSts.Soap;

// ---------------------------------------------------------------------------
// THE VOCABULARIES.
// ---------------------------------------------------------------------------

/** The two SOAP versions' envelope namespaces. */
@vocabulary(#{ id: "soap.namespace",
               cite: "SOAP 1.1 section 4.1.2; SOAP 1.2 Part 1 section 5" })
model Namespaces {
  @term(#{ cite: "SOAP 1.1 (W3C Note, 8 May 2000) section 4.1.2" })
  soap11: "http://schemas.xmlsoap.org/soap/envelope/";

  @term(#{ cite: "SOAP Version 1.2 Part 1 section 5" })
  soap12: "http://www.w3.org/2003/05/soap-envelope";
}

/**
 * SOAP 1.1's fault codes, written with the envelope's `soap:` prefix. A
 * WS-Trust refusal REPLACES `Client` with its section 11 code.
 */
@vocabulary(#{ id: "soap11.faultCode", cite: "SOAP 1.1 section 4.4.1" })
model FaultCodes11 {
  @term(#{ cite: "SOAP 1.1 section 4.4.1 (Client)" })
  client: "soap:Client";

  /** This service failing: no WS-Trust code describes it (#183). */
  @term(#{ cite: "SOAP 1.1 section 4.4.1 (Server)" })
  server: "soap:Server";
}

/**
 * SOAP 1.2's fault codes. A WS-Trust refusal is `Sender` with its section 11
 * code as the Subcode.
 */
@vocabulary(#{ id: "soap12.faultCode",
               cite: "SOAP Version 1.2 Part 1 section 5.4.6" })
model FaultCodes12 {
  @term(#{ cite: "SOAP 1.2 Part 1 section 5.4.6 (Sender)" })
  sender: "soap:Sender";

  /** This service failing (#183). */
  @term(#{ cite: "SOAP 1.2 Part 1 section 5.4.6 (Receiver)" })
  receiver: "soap:Receiver";
}

@vocabulary(#{ id: "wsa.namespace",
               cite: "Web Services Addressing 1.0 - Core section 1.3" })
model Addressing {
  @term(#{ cite: "WS-Addressing 1.0 Core section 1.3 (wsa:)" })
  addressing: "http://www.w3.org/2005/08/addressing";
}

/** WS-Policy 1.2's namespace, the one `wsp:AppliesTo` is written in. */
@vocabulary(#{ id: "wsp.namespace",
               cite: "WS-Policy 1.2 (W3C Member Submission, 2006) section 2.1" })
model Policy {
  @term(#{ cite: "WS-Policy 1.2 section 2.1 (wsp:); WS-Trust 1.3 section 1.3" })
  policy: "http://schemas.xmlsoap.org/ws/2004/09/policy";
}

/** WS-Security 1.0's two namespaces. */
@vocabulary(#{ id: "wsse.namespace",
               cite: "Web Services Security: SOAP Message Security 1.0 section 3.2" })
model Security {
  @term(#{ cite: "WSS SOAP Message Security 1.0 section 3.2 (wsse:)" })
  secext: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

  @term(#{ cite: "WSS SOAP Message Security 1.0 section 3.2 (wsu:)" })
  utility: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
}

/**
 * What a KeyIdentifier or a BinarySecurityToken says it is. The Kerberos
 * Token Profile's ValueTypes and EncodingType are `kerberos/krb5_tokens.ts`'s,
 * which owns that profile (kerberos/CLAUDE.md).
 */
@vocabulary(#{ id: "wsse.valueType",
               cite: "WSS SAML Token Profile 1.1 section 3.4; RFC 8693 section 3" })
model ValueTypes {
  /** A SAML 2.0 assertion by its ID. */
  @term(#{ cite: "WSS SAML Token Profile 1.1 section 3.4.3 (Table 3)" })
  samlId: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID";

  /** A SAML 1.1 assertion by its AssertionID. */
  @term(#{ cite: "WSS SAML Token Profile 1.0 section 3.4.3 (Table 2)" })
  samlAssertionId: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID";

  /**
   * A JWT in a BinarySecurityToken: the token type itself, as this STS's
   * own RSTR carries one and a requester presents one back (#477, #519).
   */
  @term(#{ cite: "RFC 8693 section 3 (token type identifiers)" })
  jwt: IyaSts.WsTrust.TokenTypes.jwt;
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE WRITES: the envelopes, one per SOAP version.
// ---------------------------------------------------------------------------

/** The SOAP 1.1 envelope `/sts` answers a SOAP 1.1 request in. */
@message(#{ id: "soap11.Envelope", element: "Envelope",
            xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
            direction: "write", cite: "SOAP 1.1 section 4.1" })
model Envelope11 {
  @element(#{ xml: "Header", occurs: "optional",
              cite: "SOAP 1.1 section 4.2" })
  header?: Header11;

  @element(#{ xml: "Body", occurs: "one", cite: "SOAP 1.1 section 4.3" })
  body: Body11;
}

@message(#{ id: "soap11.Header", element: "Header",
            xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
            direction: "write", cite: "SOAP 1.1 section 4.2" })
model Header11 {
  /** The answer's action, WS-Trust 1.3 section 3.3's `.../RSTR/...`. */
  @element(#{ xml: "Action", occurs: "optional",
              xmlns: "http://www.w3.org/2005/08/addressing",
              cite: "WS-Addressing 1.0 SOAP Binding section 2.2; WS-Trust 1.3 section 3.3" })
  action?: string;
}

/**
 * The Body: an RSTR collection, an RSTR (2004/04's Issue, a Renew, a
 * Validate, a Cancel), or a Fault — exactly one of them.
 */
@message(#{ id: "soap11.Body", element: "Body",
            xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
            direction: "write", cite: "SOAP 1.1 section 4.3" })
model Body11 {
  @element(#{ xml: "RequestSecurityTokenResponseCollection",
              occurs: "optional", cite: "WS-Trust 1.3 section 3.2" })
  collection?: IyaSts.WsTrust.ResponseCollection;

  @element(#{ xml: "RequestSecurityTokenResponse", occurs: "optional",
              cite: "WS-Trust 1.3 section 3.2" })
  response?: IyaSts.WsTrust.Response;

  @element(#{ xml: "Fault", occurs: "optional",
              cite: "SOAP 1.1 section 4.4" })
  fault?: Fault11;
}

/**
 * SOAP 1.1's Fault: the code (`soap:Client`, `soap:Server`, or WS-Trust 1.4
 * section 11's `wst:<code>` qualified with the request's trust namespace)
 * and the reason. `faultactor` and `detail` are never written.
 */
@message(#{ id: "soap11.Fault", element: "Fault",
            xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
            direction: "write",
            cite: "SOAP 1.1 section 4.4; WS-Trust 1.4 section 11" })
model Fault11 {
  @element(#{ xml: "faultcode", occurs: "one",
              cite: "SOAP 1.1 section 4.4 (unqualified)" })
  faultcode: string;

  @element(#{ xml: "faultstring", occurs: "one",
              cite: "SOAP 1.1 section 4.4 (unqualified)" })
  faultstring: string;

  @element(#{ xml: "faultactor", occurs: "optional", written: false,
              cite: "SOAP 1.1 section 4.4" })
  faultactor?: string;

  @element(#{ xml: "detail", occurs: "optional", written: false,
              cite: "SOAP 1.1 section 4.4" })
  detail?: string;
}

/** The SOAP 1.2 envelope, `/sts`'s answer to anything that is not 1.1. */
@message(#{ id: "soap12.Envelope", element: "Envelope",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.1" })
model Envelope12 {
  @element(#{ xml: "Header", occurs: "optional",
              cite: "SOAP 1.2 Part 1 section 5.2" })
  header?: Header12;

  @element(#{ xml: "Body", occurs: "one",
              cite: "SOAP 1.2 Part 1 section 5.3" })
  body: Body12;
}

@message(#{ id: "soap12.Header", element: "Header",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.2" })
model Header12 {
  @element(#{ xml: "Action", occurs: "optional",
              xmlns: "http://www.w3.org/2005/08/addressing",
              cite: "WS-Addressing 1.0 SOAP Binding section 2.2; WS-Trust 1.3 section 3.3" })
  action?: string;
}

@message(#{ id: "soap12.Body", element: "Body",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.3" })
model Body12 {
  @element(#{ xml: "RequestSecurityTokenResponseCollection",
              occurs: "optional", cite: "WS-Trust 1.3 section 3.2" })
  collection?: IyaSts.WsTrust.ResponseCollection;

  @element(#{ xml: "RequestSecurityTokenResponse", occurs: "optional",
              cite: "WS-Trust 1.3 section 3.2" })
  response?: IyaSts.WsTrust.Response;

  @element(#{ xml: "Fault", occurs: "optional",
              cite: "SOAP 1.2 Part 1 section 5.4" })
  fault?: Fault12;
}

/**
 * SOAP 1.2's Fault: a Code (`soap:Sender` with WS-Trust 1.4 section 11's
 * code as its Subcode, or `soap:Receiver`) and a Reason. `Node`, `Role` and
 * `Detail` are never written.
 */
@message(#{ id: "soap12.Fault", element: "Fault",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write",
            cite: "SOAP 1.2 Part 1 section 5.4; WS-Trust 1.4 section 11" })
model Fault12 {
  @element(#{ xml: "Code", occurs: "one",
              cite: "SOAP 1.2 Part 1 section 5.4.1" })
  code: Code12;

  @element(#{ xml: "Reason", occurs: "one",
              cite: "SOAP 1.2 Part 1 section 5.4.2" })
  reason: Reason12;

  @element(#{ xml: "Node", occurs: "optional", written: false,
              cite: "SOAP 1.2 Part 1 section 5.4.3" })
  node?: string;

  @element(#{ xml: "Role", occurs: "optional", written: false,
              cite: "SOAP 1.2 Part 1 section 5.4.4" })
  role?: string;

  @element(#{ xml: "Detail", occurs: "optional", written: false,
              cite: "SOAP 1.2 Part 1 section 5.4.5" })
  detail?: string;
}

@message(#{ id: "soap12.Code", element: "Code",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.4.1" })
model Code12 {
  @element(#{ xml: "Value", occurs: "one",
              cite: "SOAP 1.2 Part 1 section 5.4.1.1" })
  value: string;

  @element(#{ xml: "Subcode", occurs: "optional",
              cite: "SOAP 1.2 Part 1 section 5.4.1.2; WS-Trust 1.4 section 11" })
  subcode?: Subcode12;
}

@message(#{ id: "soap12.Subcode", element: "Subcode",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.4.1.2" })
model Subcode12 {
  @element(#{ xml: "Value", occurs: "one",
              cite: "SOAP 1.2 Part 1 section 5.4.1.2" })
  value: string;
}

@message(#{ id: "soap12.Reason", element: "Reason",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.4.2" })
model Reason12 {
  @element(#{ xml: "Text", occurs: "many",
              cite: "SOAP 1.2 Part 1 section 5.4.2.1" })
  text: Text12;
}

/** One reason, in English: this service's faults are not translated. */
@message(#{ id: "soap12.Text", element: "Text",
            xmlns: "http://www.w3.org/2003/05/soap-envelope",
            direction: "write", cite: "SOAP 1.2 Part 1 section 5.4.2.1" })
model Text12 {
  @attribute(#{ xml: "xml:lang", fixed: "en",
                cite: "SOAP 1.2 Part 1 section 5.4.2.1" })
  lang: string;
}

// ---------------------------------------------------------------------------
// WS-ADDRESSING, WS-POLICY AND WS-SECURITY ELEMENTS WRITTEN INSIDE AN RSTR.
// ---------------------------------------------------------------------------

/** The scope a token is for (WS-Trust 1.3 section 4.1), echoed. */
@message(#{ id: "wsp.AppliesTo", element: "AppliesTo",
            xmlns: "http://schemas.xmlsoap.org/ws/2004/09/policy",
            direction: "write",
            cite: "WS-Policy 1.2 section 4.1 (wsp:AppliesTo); WS-Trust 1.3 section 4.4" })
model AppliesTo {
  @element(#{ xml: "EndpointReference", occurs: "one",
              cite: "WS-Addressing 1.0 Core section 2.1" })
  endpointReference: EndpointReference;
}

@message(#{ id: "wsa.EndpointReference", element: "EndpointReference",
            xmlns: "http://www.w3.org/2005/08/addressing",
            direction: "write", cite: "WS-Addressing 1.0 Core section 2.2" })
model EndpointReference {
  @element(#{ xml: "Address", occurs: "one",
              cite: "WS-Addressing 1.0 Core section 2.2" })
  address: string;
}

/**
 * A token as a BinarySecurityToken: a JWT (ValueType only) or a Kerberos
 * AP-REQ (an Id, its ValueType and the Base64Binary EncodingType).
 */
@message(#{ id: "wsse.BinarySecurityToken", element: "BinarySecurityToken",
            xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            direction: "both", cite: "WSS SOAP Message Security 1.0 section 6.3" })
model BinarySecurityToken {
  @attribute(#{ xml: "wsu:Id", cite: "WSS SOAP Message Security 1.0 section 4" })
  id?: string;

  @attribute(#{ xml: "ValueType",
                cite: "WSS SOAP Message Security 1.0 section 6.3" })
  valueType: string;

  @attribute(#{ xml: "EncodingType",
                cite: "WSS SOAP Message Security 1.0 section 6.3" })
  encodingType?: string;
}

/** A reference to the issued token, from outside it. */
@message(#{ id: "wsse.SecurityTokenReference",
            element: "SecurityTokenReference",
            xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            direction: "write",
            cite: "WSS SOAP Message Security 1.0 section 7.1" })
model SecurityTokenReference {
  @element(#{ xml: "KeyIdentifier", occurs: "one",
              cite: "WSS SOAP Message Security 1.0 section 7.3" })
  keyIdentifier: KeyIdentifier;
}

@message(#{ id: "wsse.KeyIdentifier", element: "KeyIdentifier",
            xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            direction: "write",
            cite: "WSS SOAP Message Security 1.0 section 7.3" })
model KeyIdentifier {
  @attribute(#{ xml: "ValueType",
                cite: "WSS SOAP Message Security 1.0 section 7.3" })
  valueType: string;

  @attribute(#{ xml: "EncodingType",
                cite: "WSS SOAP Message Security 1.0 section 7.3" })
  encodingType?: string;
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE READS OF A REQUEST'S SECURITY HEADER, AS FACTS. Each is
// found by its LOCAL NAME, the namespace ignored, for the reason
// ws-trust/CLAUDE.md opens with; `wstrust.ts` holds who it is and what it
// proves (a password against `userPassword`, a signature against a mapped
// certificate, a Timestamp's window).
// ---------------------------------------------------------------------------

/** The requester's security header: the scope a credential is read in. */
@message(#{ id: "wsse.Security", element: "Security",
            xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            direction: "read",
            cite: "WSS SOAP Message Security 1.0 section 5" })
model SecurityHeader {
  @element(#{ xml: "UsernameToken", occurs: "optional", read: true,
              cite: "WSS UsernameToken Profile 1.0 section 3.1" })
  usernameToken?: UsernameToken;

  @element(#{ xml: "BinarySecurityToken", occurs: "many", read: true,
              cite: "WSS SOAP Message Security 1.0 section 6.3 (a JWT, a certificate, a Kerberos AP-REQ)" })
  binarySecurityToken?: string;

  @element(#{ xml: "Assertion", occurs: "optional", read: true,
              cite: "WSS SAML Token Profile 1.1 section 3 (either SAML version)" })
  assertion?: string;

  @element(#{ xml: "Timestamp", occurs: "optional", read: true,
              cite: "WSS SOAP Message Security 1.0 section 10 (a signed request's, #521)" })
  timestamp?: Timestamp;

  @element(#{ xml: "Signature", occurs: "optional", read: true,
              cite: "WSS SOAP Message Security 1.0 section 8 (#521)" })
  signature?: string;
}

@message(#{ id: "wsse.UsernameToken", element: "UsernameToken",
            xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            direction: "read", cite: "WSS UsernameToken Profile 1.0 section 3.1" })
model UsernameToken {
  @element(#{ xml: "Username", occurs: "one", read: true,
              cite: "WSS UsernameToken Profile 1.0 section 3.1" })
  username: string;

  /**
   * Read VERBATIM (#1466): a password is not trimmed. Only the text type
   * is read; a PasswordDigest is not verified.
   */
  @element(#{ xml: "Password", occurs: "optional", read: true,
              cite: "WSS UsernameToken Profile 1.0 section 3.1" })
  password?: string;

  @element(#{ xml: "Nonce", occurs: "optional", read: false,
              cite: "WSS UsernameToken Profile 1.0 section 3.1" })
  nonce?: string;

  @element(#{ xml: "Created", occurs: "optional", read: false,
              cite: "WSS UsernameToken Profile 1.0 section 3.1" })
  created?: string;
}

@message(#{ id: "wsu.Timestamp", element: "Timestamp",
            xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            direction: "read",
            cite: "WSS SOAP Message Security 1.0 section 10" })
model Timestamp {
  @attribute(#{ xml: "wsu:Id", read: true,
                cite: "WSS SOAP Message Security 1.0 section 4" })
  id?: string;

  @element(#{ xml: "Created", occurs: "optional", read: true,
              cite: "WSS SOAP Message Security 1.0 section 10" })
  created?: string;

  @element(#{ xml: "Expires", occurs: "optional", read: true,
              cite: "WSS SOAP Message Security 1.0 section 10" })
  expires?: string;
}
