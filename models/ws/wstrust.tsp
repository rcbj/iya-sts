// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/ws/wstrust.tsp
//
// Written by hand (#1579). WS-TRUST 1.0 THROUGH 1.4, AS `/sts` SPEAKS IT
// (`ws-trust/wstrust.ts`):
//
// * THE VOCABULARIES (`@vocabulary`): the four trust namespaces it answers
//   in (it echoes the request's), the request types, the actions, the key
//   types and the status a Validate answers — each APPENDED to the request's
//   trust namespace (`relative`) — the token types it issues and accepts, and
//   WS-Trust 1.4 section 11's fault codes. `ws-trust/ws_model.ts` is asked
//   for a term by name, so a URI is written here once. SAML's own
//   vocabularies (the assertions' namespaces, NameID formats, confirmation
//   methods, authentication contexts) are `models/saml/`'s and are not
//   copied: a term here that is one of them is written as that property.
// * THE MESSAGES (`@message`): the RequestSecurityToken as it is read — which
//   children the code acts on, which hold ANOTHER PARTY'S token, and which
//   are read off the whole document and so must be inside a signed Body —
//   and every RSTR, RSTR collection and part this service writes, with its
//   children in THE ORDER THIS SERVICE WRITES THEM. WS-Trust's schema makes
//   the RSTR a sequence of `xs:any`, so the order is not the schema's: it is
//   this endpoint's, stated so a builder out of step with it is seen.
//   `WsModel.hold()` checks every envelope `/sts` sends — the RSTR's SAML
//   assertion against SAML's own model — logs a gap under STS-WSTRUST-0071
//   and changes nothing.
//
// What `/sts` publishes, stated rather than left to be discovered:
// `GET /sts/metadata` is WSDL 1.1 with WS-SecurityPolicy embedded (#958).
// SOAP WS-MetadataExchange is still not served. `GET /sts` answers a
// description in plain text and `GET /sts/cert` the signing certificate.
// No KET, BatchIssue or other request type has an
// answer of its own: the code reads the request type's LAST SEGMENT, and one
// that is not Renew, Validate or Cancel is answered as an Issue
// (ws-trust/CLAUDE.md). The Kerberos Token Profile's token and value types
// are `kerberos/krb5_tokens.ts`'s.
//
// Parsing, canonicalisation, signing and encryption stay in code, and so
// does everything that needs state: a credential's verification, the
// delegation policy, a registered AppliesTo, the lifetime's clamp.

import "../lib/saml_lib.tsp";
import "../saml/saml2.tsp";
import "../saml/saml11.tsp";
import "./soap.tsp";

using IyaSts.SamlLib;

namespace IyaSts.WsTrust;

// ---------------------------------------------------------------------------
// THE VOCABULARIES.
// ---------------------------------------------------------------------------

/**
 * The trust namespaces. The answer is written in the request's own (1.3's
 * when there is none to read); `trust14` is the 1.4 namespace of `ActAs`
 * alone — WS-Trust 1.4 keeps 1.3's for everything 1.3 defines.
 */
@vocabulary(#{ id: "wst.namespace",
               cite: "WS-Trust 1.3 section 1.3; WS-Trust 1.4 section 1.3" })
model Namespaces {
  @term(#{ cite: "WS-Trust 1.3 section 1.3 (OASIS, 2007); WS-Trust 1.4 section 1.3" })
  trust13: "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

  @term(#{ cite: "WS-Trust 1.4 section 1.3 (wst14:, ActAs)" })
  trust14: "http://docs.oasis-open.org/ws-sx/ws-trust/200802";

  @term(#{ cite: "WS-Trust February 2005 section 1.4" })
  trust2005: "http://schemas.xmlsoap.org/ws/2005/02/trust";

  /**
   * The May 2004 member submission: an Issue is answered with the RSTR
   * itself (its collection holds at least two), the reference is
   * `RequestedTokenReference`, and there is no Cancel (#188).
   */
  @term(#{ cite: "WS-Trust May 2004 section 1.4" })
  trust2004: "http://schemas.xmlsoap.org/ws/2004/04/trust";
}

/**
 * The request types, read from the LAST SEGMENT of `wst:RequestType` so any
 * version's namespace is one; any other is answered as an Issue.
 */
@vocabulary(#{ id: "wst.request", relative: true,
               cite: "WS-Trust 1.3 section 3.1; WS-Trust 1.4 sections 6-10" })
model RequestTypes {
  @term(#{ cite: "WS-Trust 1.3 section 4", answered: true })
  issue: "/Issue";

  @term(#{ cite: "WS-Trust 1.3 section 7", answered: true })
  renew: "/Renew";

  /** A wst:Status in a 200, never a fault, whatever it says. */
  @term(#{ cite: "WS-Trust 1.3 section 9", answered: true })
  validate: "/Validate";

  /** Refused in the 2004/04 namespace, which has no Cancel (#188). */
  @term(#{ cite: "WS-Trust 1.3 section 8", answered: true })
  cancel: "/Cancel";
}

/** The actions of the answers, on the envelope's `wsa:Action`. */
@vocabulary(#{ id: "wst.action", relative: true,
               cite: "WS-Trust 1.3 section 3.3; WS-Trust 1.4 section 3.3" })
model Actions {
  /** 2004/04's Issue, answered with one RSTR (#188). */
  @term(#{ cite: "WS-Trust May 2004 section 3.3" })
  issue: "/RSTR/Issue";

  @term(#{ cite: "WS-Trust 1.3 section 3.3 (RSTRC/IssueFinal)" })
  issueFinal: "/RSTRC/IssueFinal";

  @term(#{ cite: "WS-Trust 1.3 section 3.3" })
  renewFinal: "/RSTR/RenewFinal";

  @term(#{ cite: "WS-Trust 1.3 section 3.3" })
  validateFinal: "/RSTR/ValidateFinal";

  @term(#{ cite: "WS-Trust 1.3 section 3.3" })
  cancelFinal: "/RSTR/CancelFinal";
}

/**
 * The key types. THE RSTR STATES WHAT WAS ISSUED (#747): every token here is
 * a bearer token, so a requested PublicKey or SymmetricKey is not echoed. A
 * Kerberos token's session key is a SymmetricKey BinarySecret (#658).
 */
@vocabulary(#{ id: "wst.keyType", relative: true,
               cite: "WS-Trust 1.3 section 9.2; WS-Trust 1.4 section 9.2" })
model KeyTypes {
  @term(#{ cite: "WS-Trust 1.3 section 9.2 (Bearer)" })
  bearer: "/Bearer";

  @term(#{ cite: "WS-Trust 1.3 section 9.2 (SymmetricKey); section 3.2 (BinarySecret Type)" })
  symmetricKey: "/SymmetricKey";

  @term(#{ cite: "WS-Trust 1.3 section 9.2 (PublicKey)", readOnly: true })
  publicKey: "/PublicKey";
}

/** What a Validate answers: its token type and its two codes. */
@vocabulary(#{ id: "wst.status", relative: true,
               cite: "WS-Trust 1.3 section 9.1" })
model StatusValues {
  @term(#{ cite: "WS-Trust 1.3 section 9.1 (RSTR/Status)" })
  tokenType: "/RSTR/Status";

  @term(#{ cite: "WS-Trust 1.3 section 9.1" })
  valid: "/status/valid";

  @term(#{ cite: "WS-Trust 1.3 section 9.1" })
  invalid: "/status/invalid";
}

/**
 * The token types issued (`wst:TokenType`) and named in an answer. The
 * Kerberos Token Profile's are `kerberos/krb5_tokens.ts`'s (#658).
 */
@vocabulary(#{ id: "wst.tokenType",
               cite: "WS-Trust 1.3 section 3.1 (TokenType); WSS SAML Token Profile 1.1 section 3.6" })
model TokenTypes {
  /** The default, and what an unnamed type is issued as. */
  @term(#{ cite: "WSS SAML Token Profile 1.1 section 3.6 (Table 6)" })
  saml2: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

  /** #487. */
  @term(#{ cite: "WSS SAML Token Profile 1.1 section 3.6 (Table 6)" })
  saml11: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";

  /**
   * An older client's name for a SAML 1.1 token: the assertion namespace.
   * It asks for the same token, and the answer names `saml11`.
   */
  @term(#{ cite: "saml-core-1.1 section 1.2; WS-Federation 1.2 section 13.6.3",
           aliasOf: "saml11" })
  saml11Namespace: IyaSts.Saml11.Namespaces.assertion;

  /** #476: an RFC 9068 access token. */
  @term(#{ cite: "RFC 8693 section 3" })
  jwt: "urn:ietf:params:oauth:token-type:jwt";
}

/**
 * WS-Trust 1.4 section 11's fault codes, each written `wst:<code>` and
 * qualified with the request's own trust namespace: SOAP 1.1's faultcode,
 * SOAP 1.2's Subcode under `soap:Sender`. The four `readOnly` describe no
 * refusal here better than another (ws-trust/CLAUDE.md, *Every refusal
 * names its section 11 fault code*).
 */
@vocabulary(#{ id: "wst.fault", cite: "WS-Trust 1.4 section 11" })
model Faults {
  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The request was invalid or malformed\")" })
  InvalidRequest: "InvalidRequest";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"Authentication failed\")" })
  FailedAuthentication: "FailedAuthentication";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The specified request failed\")" })
  RequestFailed: "RequestFailed";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"Security token has been revoked\")",
           readOnly: true })
  InvalidSecurityToken: "InvalidSecurityToken";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"Insufficient Digest Elements\")" })
  AuthenticationBadElements: "AuthenticationBadElements";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The specified RequestSecurityToken is not understood\")" })
  BadRequest: "BadRequest";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The request data is out-of-date\")" })
  ExpiredData: "ExpiredData";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The requested time range is invalid or unsupported\")",
           readOnly: true })
  InvalidTimeRange: "InvalidTimeRange";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The request scope is invalid or unsupported\")" })
  InvalidScope: "InvalidScope";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"A renewable security token has expired\")",
           readOnly: true })
  RenewNeeded: "RenewNeeded";

  @term(#{ cite: "WS-Trust 1.4 section 11 (\"The requested renewal failed\")",
           readOnly: true })
  UnableToRenew: "UnableToRenew";
}

/**
 * This service's own SAML 1.1 attribute naming the parties that acted, least
 * to most recent: SAML 1.1 has no Delegation Restriction (#522).
 */
@vocabulary(#{ id: "wst.delegates",
               cite: "this service (#522); ws-trust/CLAUDE.md" })
model Delegates {
  @term(#{ cite: "#522 (AttributeName)" })
  attributeName: "delegates";

  @term(#{ cite: "#522 (AttributeNamespace)" })
  attributeNamespace: "urn:iya:sts:delegation";
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE READS.
// ---------------------------------------------------------------------------

/**
 * The RST. Every child is found by its LOCAL NAME in the WHOLE document
 * (`helpers.firstByLocal()`), so one reader serves the four versions; `read`
 * says which the code acts on. `anotherPartys` marks the elements that hold
 * SOMEBODY ELSE'S token: a credential inside one is never the requester's.
 * `inSignedBody` (#521) marks the ones a signed request must carry inside the
 * Body its signature covers, because a copy in a header would be read first;
 * the order is the one that refusal names them in (the RST's schema is a
 * sequence of xs:any, so no other order is the schema's).
 */
@message(#{ id: "wst.RequestSecurityToken", element: "RequestSecurityToken",
            namespaces: "wst.namespace", direction: "read",
            cite: "WS-Trust 1.3 section 3.1; WS-Trust 1.4 section 3.1" })
model Request {
  @element(#{ xml: "RequestType", occurs: "one", read: true,
              inSignedBody: true, cite: "WS-Trust 1.3 section 3.1" })
  requestType: string;

  /** Not acted on: the RSTR states the Bearer key type issued (#747). */
  @element(#{ xml: "KeyType", occurs: "optional", read: false,
              inSignedBody: true, cite: "WS-Trust 1.3 section 9.2" })
  keyType?: string;

  @element(#{ xml: "TokenType", occurs: "optional", read: true,
              inSignedBody: true, cite: "WS-Trust 1.3 section 3.1" })
  tokenType?: string;

  @element(#{ xml: "AppliesTo", occurs: "optional", read: true,
              inSignedBody: true,
              cite: "WS-Trust 1.3 section 4.1 (wsp:AppliesTo: the scope)" })
  appliesTo?: string;

  /**
   * Read, and CLAMPED to `wstrust.maxTokenLifetimeMin`: WS-Trust 1.4
   * section 4.1 makes the requested lifetime a request the STS decides.
   */
  @element(#{ xml: "Lifetime", occurs: "optional", read: true,
              inSignedBody: true, cite: "WS-Trust 1.3 section 4.1" })
  lifetime?: string;

  @element(#{ xml: "Claims", occurs: "optional", read: false,
              cite: "WS-Trust 1.3 section 4.1" })
  claims?: string;

  @element(#{ xml: "Entropy", occurs: "optional", read: false,
              cite: "WS-Trust 1.3 section 4.1" })
  entropy?: string;

  @element(#{ xml: "KeySize", occurs: "optional", read: false,
              cite: "WS-Trust 1.3 section 9.2" })
  keySize?: string;

  /** IMPERSONATION: a token about somebody (#108, #186). */
  @element(#{ xml: "OnBehalfOf", occurs: "optional", read: true,
              anotherPartys: true, inSignedBody: true,
              cite: "WS-Trust 1.3 section 9.3" })
  onBehalfOf?: string;

  /** DELEGATION: composite by definition, in 1.4's namespace. */
  @element(#{ xml: "ActAs", occurs: "optional", read: true,
              anotherPartys: true, inSignedBody: true,
              xmlns: "http://docs.oasis-open.org/ws-sx/ws-trust/200802",
              cite: "WS-Trust 1.4 section 9.5" })
  actAs?: string;

  @element(#{ xml: "RenewTarget", occurs: "optional", read: true,
              anotherPartys: true, inSignedBody: true,
              cite: "WS-Trust 1.3 section 7.1" })
  renewTarget?: string;

  @element(#{ xml: "ValidateTarget", occurs: "optional", read: true,
              anotherPartys: true, inSignedBody: true,
              cite: "WS-Trust 1.3 section 9.1" })
  validateTarget?: string;

  @element(#{ xml: "CancelTarget", occurs: "optional", read: true,
              anotherPartys: true, inSignedBody: true,
              cite: "WS-Trust 1.3 section 8.1" })
  cancelTarget?: string;

  /**
   * A Kerberos token's (#658). Read off the whole document like every part,
   * so a signed request carries it inside its signed Body (rcbj, #1579):
   * a copy in a header would otherwise ask for a forwardable ticket, or a
   * forwarded TGT, that nobody signed for.
   */
  @element(#{ xml: "Forwardable", occurs: "optional", read: true,
              inSignedBody: true, cite: "WS-Trust 1.3 section 9.3" })
  forwardable?: string;

  /**
   * A Kerberos token's (#658). Read off the whole document like every part,
   * so a signed request carries it inside its signed Body (rcbj, #1579):
   * a copy in a header would otherwise ask for a forwardable ticket, or a
   * forwarded TGT, that nobody signed for.
   */
  @element(#{ xml: "Delegatable", occurs: "optional", read: true,
              inSignedBody: true, cite: "WS-Trust 1.3 section 9.3" })
  delegatable?: string;
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE WRITES, in the request's trust namespace.
// ---------------------------------------------------------------------------

@message(#{ id: "wst.RequestSecurityTokenResponseCollection",
            element: "RequestSecurityTokenResponseCollection",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 3.2" })
model ResponseCollection {
  @element(#{ xml: "RequestSecurityTokenResponse", occurs: "many",
              cite: "WS-Trust 1.3 section 3.2" })
  response: Response;
}

/**
 * One RSTR, its children in the order `/sts` writes them: an Issue's and a
 * Renew's token parts, a Validate's TokenType and Status, a Cancel's
 * RequestedTokenCancelled.
 */
@message(#{ id: "wst.RequestSecurityTokenResponse",
            element: "RequestSecurityTokenResponse",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 3.2 (a sequence of xs:any: the order is this service's)" })
model Response {
  @element(#{ xml: "TokenType", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  tokenType?: string;

  @element(#{ xml: "RequestedSecurityToken", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  requestedSecurityToken?: RequestedSecurityToken;

  /** A Kerberos token's session key, over TLS only (#658). */
  @element(#{ xml: "RequestedProofToken", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4; WS-Trust 1.4 section 4.4.2" })
  requestedProofToken?: RequestedProofToken;

  @element(#{ xml: "AppliesTo", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  appliesTo?: IyaSts.Soap.AppliesTo;

  @element(#{ xml: "Lifetime", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  lifetime?: Lifetime;

  @element(#{ xml: "KeyType", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  keyType?: string;

  /** 2004/04 spells it RequestedTokenReference (#188). */
  @element(#{ xml: "RequestedAttachedReference", occurs: "optional",
              or: #["RequestedTokenReference"],
              cite: "WS-Trust 1.3 section 4.4; WS-Trust May 2004 section 4.3" })
  requestedAttachedReference?: AttachedReference;

  @element(#{ xml: "RequestedUnattachedReference", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  requestedUnattachedReference?: UnattachedReference;

  @element(#{ xml: "Status", occurs: "optional",
              cite: "WS-Trust 1.3 section 9.1" })
  status?: Status;

  @element(#{ xml: "RequestedTokenCancelled", occurs: "optional",
              cite: "WS-Trust 1.3 section 8.1" })
  requestedTokenCancelled?: string;
}

/**
 * The issued token, exactly one of these: a SAML 2.0 assertion (held to
 * SAML's own model), a SAML 1.1 one, either encrypted (`?encrypt=1`), or a
 * BinarySecurityToken — a JWT or a Kerberos AP-REQ.
 */
@message(#{ id: "wst.RequestedSecurityToken", element: "RequestedSecurityToken",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 4.4" })
model RequestedSecurityToken {
  @element(#{ xml: "Assertion", occurs: "optional",
              xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
              cite: "WSS SAML Token Profile 1.1 section 3 (SAML 2.0)" })
  saml2Assertion?: IyaSts.Saml2.Assertion;

  @element(#{ xml: "Assertion", occurs: "optional",
              xmlns: "urn:oasis:names:tc:SAML:1.0:assertion",
              cite: "WSS SAML Token Profile 1.1 section 3 (SAML 1.1, #487)" })
  saml11Assertion?: IyaSts.Saml11.Assertion;

  @element(#{ xml: "EncryptedAssertion", occurs: "optional",
              cite: "saml-core-2.0-os section 2.3.4 (?encrypt=1)" })
  encryptedAssertion?: string;

  @element(#{ xml: "BinarySecurityToken", occurs: "optional",
              cite: "WSS SOAP Message Security 1.0 section 6.3 (a JWT, #476; a Kerberos AP-REQ, #658)" })
  binarySecurityToken?: IyaSts.Soap.BinarySecurityToken;
}

@message(#{ id: "wst.RequestedProofToken", element: "RequestedProofToken",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 4.4" })
model RequestedProofToken {
  @element(#{ xml: "BinarySecret", occurs: "one",
              cite: "WS-Trust 1.3 section 3.3" })
  binarySecret: BinarySecret;
}

@message(#{ id: "wst.BinarySecret", element: "BinarySecret",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 3.3" })
model BinarySecret {
  @attribute(#{ xml: "Type", cite: "WS-Trust 1.3 section 3.3" })
  type?: string;
}

/**
 * The issued token's lifetime: the requested one clamped, or the default;
 * a Kerberos token's Authenticator window.
 */
@message(#{ id: "wst.Lifetime", element: "Lifetime",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 4.4" })
model Lifetime {
  @element(#{ xml: "Created", occurs: "one",
              cite: "WSS SOAP Message Security 1.0 section 10 (wsu:Created)" })
  created: string;

  @element(#{ xml: "Expires", occurs: "one",
              cite: "WSS SOAP Message Security 1.0 section 10 (wsu:Expires)" })
  expires: string;
}

@message(#{ id: "wst.RequestedAttachedReference",
            element: "RequestedAttachedReference",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 4.4" })
model AttachedReference {
  @element(#{ xml: "SecurityTokenReference", occurs: "one",
              cite: "WSS SOAP Message Security 1.0 section 7.1" })
  securityTokenReference: IyaSts.Soap.SecurityTokenReference;
}

@message(#{ id: "wst.RequestedUnattachedReference",
            element: "RequestedUnattachedReference",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 4.4" })
model UnattachedReference {
  @element(#{ xml: "SecurityTokenReference", occurs: "one",
              cite: "WSS SOAP Message Security 1.0 section 7.1" })
  securityTokenReference: IyaSts.Soap.SecurityTokenReference;
}

@message(#{ id: "wst.Status", element: "Status",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Trust 1.3 section 9.1" })
model Status {
  @element(#{ xml: "Code", occurs: "one", cite: "WS-Trust 1.3 section 9.1" })
  code: string;

  @element(#{ xml: "Reason", occurs: "optional",
              cite: "WS-Trust 1.3 section 9.1" })
  reason?: string;
}
