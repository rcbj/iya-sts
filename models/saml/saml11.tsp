// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/saml/saml11.tsp
//
// Written by hand (#1579). SAML 1.1, AS THIS SERVICE SPEAKS IT: the
// Browser/POST and Browser/Artifact profiles and the SOAP responder behind
// them (`saml/saml11_sso.ts`), and the assertion `saml/saml11.ts` builds for
// them and for WS-Trust and WS-Federation.
//
// SAML 1.1 HAS NO REQUEST MESSAGE in its browser profiles (rule 4b), so what
// a relying party sends is a parameter set (`@params`), and SAML 1.1's
// status codes are QNames resolved against the document's `samlp` prefix,
// not URIs. Its namespaces carry `1.0` because the schemas were never
// renamed; the protocol's `protocolSupportEnumeration` value carries `1.1`.
// The facts are stated as `models/saml/saml2.tsp` states SAML 2.0's, and
// read through `saml/saml_model.ts`.

import "../lib/saml_lib.tsp";

using IyaSts.SamlLib;

namespace IyaSts.Saml11;

// ---------------------------------------------------------------------------
// THE VOCABULARIES.
// ---------------------------------------------------------------------------

@vocabulary(#{ id: "saml11.namespace", cite: "saml-core-1.1 section 1.2" })
model Namespaces {
  @term(#{ cite: "saml-core-1.1 section 1.2" })
  assertion: "urn:oasis:names:tc:SAML:1.0:assertion";

  @term(#{ cite: "saml-core-1.1 section 1.2" })
  protocol: "urn:oasis:names:tc:SAML:1.0:protocol";
}

/** What `protocolSupportEnumeration` names, beside SAML 2.0's protocol. */
@vocabulary(#{ id: "saml11.protocol",
               cite: "saml-metadata-2.0-os section 2.4.1; sstc-saml1x-metadata section 2" })
model Protocols {
  /** Spelled 1.1: the PROTOCOL's version, not a schema namespace. */
  @term(#{ cite: "sstc-saml1x-metadata section 2" })
  saml11: "urn:oasis:names:tc:SAML:1.1:protocol";

  /**
   * Shibboleth's: a Shibboleth SP looks for the AuthnRequest profile's
   * endpoint only in a role naming it (#189).
   */
  @term(#{ cite: "Shibboleth 1.3 Architecture and Protocols section 3.1.1" })
  shibboleth1: "urn:mace:shibboleth:1.0";
}

@vocabulary(#{ id: "saml11.profile",
               cite: "saml-bindings-1.1 section 4.1; sstc-saml1x-metadata section 2.1" })
model Profiles {
  @term(#{ cite: "saml-bindings-1.1 section 4.1.2" })
  post: "urn:oasis:names:tc:SAML:1.0:profiles:browser-post";

  /** `artifact-01` is the real spelling. */
  @term(#{ cite: "saml-bindings-1.1 section 4.1.1" })
  artifact: "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01";

  /** Shibboleth's request profile, advertised so an SP offers it. */
  @term(#{ cite: "Shibboleth 1.3 Architecture and Protocols section 3.1.1" })
  shibAuthnRequest: "urn:mace:shibboleth:1.0:profiles:AuthnRequest";
}

@vocabulary(#{ id: "saml11.binding", cite: "saml-bindings-1.1 section 3" })
model Bindings {
  /** The responder's. */
  @term(#{ cite: "saml-bindings-1.1 section 3.1" })
  soap: "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding";
}

/** QNames, resolved against the document's `samlp` prefix. */
@vocabulary(#{ id: "saml11.status", cite: "saml-core-1.1 section 3.4.3.1",
               prefix: "samlp:" })
model Status {
  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "top" })
  Success: "samlp:Success";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "top" })
  Requester: "samlp:Requester";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "top" })
  Responder: "samlp:Responder";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "top",
           readOnly: true })
  VersionMismatch: "samlp:VersionMismatch";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "second",
           readOnly: true })
  RequestVersionTooHigh: "samlp:RequestVersionTooHigh";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "second",
           readOnly: true })
  RequestVersionTooLow: "samlp:RequestVersionTooLow";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "second",
           readOnly: true })
  RequestVersionDeprecated: "samlp:RequestVersionDeprecated";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "second",
           readOnly: true })
  TooManyResponses: "samlp:TooManyResponses";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "second",
           readOnly: true })
  RequestDenied: "samlp:RequestDenied";

  @term(#{ cite: "saml-core-1.1 section 3.4.3.1", level: "second",
           readOnly: true })
  ResourceNotRecognized: "samlp:ResourceNotRecognized";
}

// The formats ADVERTISED: what SAML 1.1 defines plus the X.509 one every
// deployment used, and not 2.0's three, which a 1.1 assertion has no way
// to ask for. Not a list of what is chosen from: the relying party's
// saml11.nameIdFormat setting is what an assertion carries.
@vocabulary(#{ id: "saml11.nameIdFormat",
               cite: "saml-core-1.1 section 7.3",
               prefix: "urn:oasis:names:tc:SAML:1.1:nameid-format:" })
model NameIdFormats {
  @term(#{ cite: "saml-core-1.1 section 7.3.1", advertised: true })
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

  @term(#{ cite: "saml-core-1.1 section 7.3.2", advertised: true })
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

  @term(#{ cite: "saml-core-1.1 section 7.3.3", advertised: true })
  x509SubjectName:
    "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

  @term(#{ cite: "saml-core-1.1 section 7.3.4", advertised: true })
  windowsDomainQualifiedName:
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
}

// The confirmation method is the assertion's own statement of how it
// reached the relying party: `artifact` for Browser/Artifact (saml-profile-
// 1.1 section 4.1.1.4), `bearer` for Browser/POST (4.2.1.4).
@vocabulary(#{ id: "saml11.confirmation",
               cite: "saml-core-1.1 section 7.1",
               prefix: "urn:oasis:names:tc:SAML:1.0:cm:" })
model Confirmations {
  @term(#{ cite: "saml-bindings-1.1 section 4.1.2.4" })
  bearer: "urn:oasis:names:tc:SAML:1.0:cm:bearer";

  @term(#{ cite: "saml-bindings-1.1 section 4.1.1.4" })
  artifact: "urn:oasis:names:tc:SAML:1.0:cm:artifact";

  @term(#{ cite: "saml-core-1.1 section 7.1", readOnly: true })
  holderOfKey: "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

  @term(#{ cite: "saml-core-1.1 section 7.1", readOnly: true })
  senderVouches: "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";
}

// `equivalent` is the SAML 2.0 class that means the same thing, which a
// partner's SAML 1.1 method re-asserted over SAML 2.0 takes.
@vocabulary(#{ id: "saml11.authnMethod", cite: "saml-core-1.1 section 7.1",
               prefix: "urn:oasis:names:tc:SAML:1.0:am:" })
model AuthnMethods {
  @term(#{ cite: "saml-core-1.1 section 7.1",
           equivalent: "passwordProtectedTransport" })
  password: "urn:oasis:names:tc:SAML:1.0:am:password";

  /** RFC 1510 by number, as section 7.1 spells it. */
  @term(#{ cite: "saml-core-1.1 section 7.1", equivalent: "kerberos" })
  kerberos: "urn:ietf:rfc:1510";

  /** "SSL/TLS Certificate Based Client Authentication", RFC 2246. */
  @term(#{ cite: "saml-core-1.1 section 7.1", equivalent: "tlsClient" })
  tlsClient: "urn:ietf:rfc:2246";

  @term(#{ cite: "saml-core-1.1 section 7.1", equivalent: "x509" })
  x509: "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";

  @term(#{ cite: "saml-core-1.1 section 7.1" })
  hardwareToken: "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";

  @term(#{ cite: "saml-core-1.1 section 7.1" })
  unspecified: "urn:oasis:names:tc:SAML:1.0:am:unspecified";

  /** Microsoft's, said in both vocabularies alike. */
  @term(#{ cite: "MS-ADFSPIP; AD FS multiple authentication",
           equivalent: "multipleAuthn" })
  multipleAuthn: "http://schemas.microsoft.com/claims/multipleauthn";
}

/**
 * What a `<samlp:Request>` asks, by the local name of the element that
 * says it. `answered: false` is refused by name.
 */
@vocabulary(#{ id: "saml11.request", cite: "saml-core-1.1 section 3.2" })
model Requests {
  @term(#{ cite: "saml-core-1.1 section 3.2.3", answered: true })
  assertionArtifact: "AssertionArtifact";

  @term(#{ cite: "saml-core-1.1 section 3.2.3", answered: true })
  assertionIdReference: "AssertionIDReference";

  @term(#{ cite: "saml-core-1.1 section 3.3.4", answered: true })
  attributeQuery: "AttributeQuery";

  @term(#{ cite: "saml-core-1.1 section 3.3.3", answered: true })
  authenticationQuery: "AuthenticationQuery";

  /** This service makes no authorization decisions. */
  @term(#{ cite: "saml-core-1.1 section 3.3.5", answered: false })
  authorizationDecisionQuery: "AuthorizationDecisionQuery";
}

// ---------------------------------------------------------------------------
// WHAT A RELYING PARTY SENDS: PARAMETERS, NOT A MESSAGE.
// ---------------------------------------------------------------------------

/**
 * The inter-site transfer service's parameters (saml-bindings-1.1 section
 * 4.1, and Shibboleth's request profile). One is this service's own and no
 * specification's: `authnContextClassRef`. The browser profile is the
 * binding registered for the `shire` and the NameIdentifier format is the
 * relying party's setting, as the specifications have it: the non-spec
 * `profile` and `format` parameters that chose them were removed, because a
 * `profile` that disagreed with the shire's registered binding sent an
 * assertion over a profile that consumer does not answer.
 */
@params(#{ id: "saml11.browser",
           cite: "saml-bindings-1.1 section 4.1; Shibboleth 1.3 Architecture and Protocols section 3.1.1" })
model BrowserParams {
  @param(#{ wire: "TARGET", cite: "saml-bindings-1.1 section 4.1.1.3" })
  target: string;

  /** Shibboleth's request profile spells it in lower case (#189). */
  @param(#{ wire: "target", cite: "Shibboleth 1.3 section 3.1.1.1" })
  shibbolethTarget: string;

  /** The assertion consumer; its registered binding picks the profile. */
  @param(#{ wire: "shire", cite: "Shibboleth 1.3 section 3.1.1.1" })
  shire: string;

  @param(#{ wire: "providerId", cite: "Shibboleth 1.3 section 3.1.1.1" })
  providerId: string;

  @param(#{ wire: "time", cite: "Shibboleth 1.3 section 3.1.1.1" })
  time: string;

  /** The EAP class URIs SAML 1.1 has no spelling for (#736). */
  @param(#{ wire: "authnContextClassRef", nonSpec: true,
            cite: "this service's: OpenID Connect EAP ACR Values 1.0 section 5" })
  authnContextClassRef: string;
}

/**
 * SAML 2.0's identity-provider-initiated start (#189), on the Shibboleth
 * identity provider's parameter names.
 */
@params(#{ id: "saml2.unsolicited",
           cite: "saml-profiles-2.0-os section 4.1.5; Shibboleth IdP UnsolicitedSSOConfiguration" })
model UnsolicitedParams {
  @param(#{ wire: "providerId", cite: "Shibboleth IdP unsolicited SSO" })
  providerId: string;

  @param(#{ wire: "shire", cite: "Shibboleth IdP unsolicited SSO" })
  shire: string;

  @param(#{ wire: "target", cite: "Shibboleth IdP unsolicited SSO" })
  target: string;

  @param(#{ wire: "binding", cite: "Shibboleth IdP unsolicited SSO" })
  binding: string;

  /** The one trip to the sign-in screen, marked in the URL (#711). */
  @param(#{ wire: "reprompted", nonSpec: true,
            cite: "this service's: saml/CLAUDE.md, ONE TRIP PER LINK" })
  reprompted: string;
}

// ---------------------------------------------------------------------------
// WHAT THE RESPONDER READS.
// ---------------------------------------------------------------------------

@message(#{ id: "saml11.Request", element: "Request",
            xmlns: "urn:oasis:names:tc:SAML:1.0:protocol",
            direction: "read", cite: "saml-core-1.1 section 3.2.2" })
model Request {
  @attribute(#{ xml: "RequestID", read: true,
                cite: "saml-core-1.1 3.2.1" })
  requestId: string;

  @attribute(#{ xml: "MajorVersion", read: false,
                cite: "saml-core-1.1 3.2.1" })
  majorVersion: string;

  @attribute(#{ xml: "MinorVersion", read: false,
                cite: "saml-core-1.1 3.2.1" })
  minorVersion: string;

  @attribute(#{ xml: "IssueInstant", read: false,
                cite: "saml-core-1.1 3.2.1" })
  issueInstant: string;

  @element(#{ xml: "RespondWith", occurs: "many", read: false,
              cite: "saml-core-1.1 3.2.1" })
  respondWith?: string;

  @element(#{ xml: "Signature", occurs: "optional", read: true,
              cite: "saml-core-1.1 3.2.1" })
  signature?: string;

  /** The request types: `saml11.request`'s terms. */
  @element(#{ xml: "AssertionArtifact", occurs: "many", read: true,
              or: #["AssertionIDReference", "AttributeQuery",
                    "AuthenticationQuery", "AuthorizationDecisionQuery"],
              cite: "saml-core-1.1 3.2.2" })
  asked?: string;
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE WRITES.
// ---------------------------------------------------------------------------

@message(#{ id: "saml11.Subject", element: "Subject",
            xmlns: "urn:oasis:names:tc:SAML:1.0:assertion",
            direction: "write", cite: "saml-core-1.1 section 2.4.2.1" })
model Subject {
  @element(#{ xml: "NameIdentifier", occurs: "optional",
              cite: "saml-core-1.1 2.4.2.2" })
  nameIdentifier?: string;

  @element(#{ xml: "SubjectConfirmation", occurs: "optional",
              cite: "saml-core-1.1 2.4.2.3" })
  subjectConfirmation?: string;
}

/**
 * A choice repeated in the schema: the audience restriction, then
 * DoNotCacheCondition (off unless `saml11.doNotCacheCondition`, #189).
 */
@message(#{ id: "saml11.Conditions", element: "Conditions",
            xmlns: "urn:oasis:names:tc:SAML:1.0:assertion",
            direction: "write", cite: "saml-core-1.1 section 2.3.2.1" })
model Conditions {
  @attribute(#{ xml: "NotBefore", cite: "saml-core-1.1 2.3.2.1" })
  notBefore?: string;

  @attribute(#{ xml: "NotOnOrAfter", cite: "saml-core-1.1 2.3.2.1" })
  notOnOrAfter?: string;

  @element(#{ xml: "AudienceRestrictionCondition", occurs: "many",
              cite: "saml-core-1.1 2.3.2.1.1" })
  audienceRestrictionCondition?: string;

  @element(#{ xml: "DoNotCacheCondition", occurs: "many",
              cite: "saml-core-1.1 2.3.2.1.2" })
  doNotCacheCondition?: string;

  @element(#{ xml: "Condition", occurs: "many", written: false,
              cite: "saml-core-1.1 2.3.2.1" })
  condition?: string;
}

@message(#{ id: "saml11.AuthenticationStatement",
            element: "AuthenticationStatement",
            xmlns: "urn:oasis:names:tc:SAML:1.0:assertion",
            direction: "write", cite: "saml-core-1.1 section 2.4.3" })
model AuthenticationStatement {
  @attribute(#{ xml: "AuthenticationMethod",
                cite: "saml-core-1.1 2.4.3" })
  authenticationMethod: string;

  @attribute(#{ xml: "AuthenticationInstant",
                cite: "saml-core-1.1 2.4.3" })
  authenticationInstant: string;

  @element(#{ xml: "Subject", occurs: "one",
              cite: "saml-core-1.1 2.4.2" })
  subject: Subject;

  @element(#{ xml: "SubjectLocality", occurs: "optional",
              cite: "saml-core-1.1 2.4.3.1" })
  subjectLocality?: string;

  @element(#{ xml: "AuthorityBinding", occurs: "many", written: false,
              cite: "saml-core-1.1 2.4.3.2" })
  authorityBinding?: string;
}

@message(#{ id: "saml11.AttributeStatement", element: "AttributeStatement",
            xmlns: "urn:oasis:names:tc:SAML:1.0:assertion",
            direction: "write", cite: "saml-core-1.1 section 2.4.5" })
model AttributeStatement {
  /** Repeated in each statement: a statement is about a subject. */
  @element(#{ xml: "Subject", occurs: "one",
              cite: "saml-core-1.1 2.4.2" })
  subject: Subject;

  @element(#{ xml: "Attribute", occurs: "many",
              cite: "saml-core-1.1 2.4.5.1" })
  attribute: string;
}

/**
 * The assertion: Conditions, then the statements, then ds:Signature LAST,
 * where SAML 2.0 puts it after the Issuer.
 */
@message(#{ id: "saml11.Assertion", element: "Assertion",
            xmlns: "urn:oasis:names:tc:SAML:1.0:assertion",
            direction: "write", cite: "saml-core-1.1 section 2.3.2" })
model Assertion {
  @attribute(#{ xml: "MajorVersion", fixed: "1",
                cite: "saml-core-1.1 2.3.2" })
  majorVersion: string;

  @attribute(#{ xml: "MinorVersion", fixed: "1",
                cite: "saml-core-1.1 2.3.2" })
  minorVersion: string;

  /** Twelve base64url characters, stamped for the cells (#98 D10). */
  @attribute(#{ xml: "AssertionID", cite: "saml-core-1.1 2.3.2" })
  assertionId: string;

  /** An ATTRIBUTE in SAML 1.1, where SAML 2.0 has an element. */
  @attribute(#{ xml: "Issuer", cite: "saml-core-1.1 2.3.2" })
  issuer: string;

  @attribute(#{ xml: "IssueInstant", cite: "saml-core-1.1 2.3.2" })
  issueInstant: string;

  @element(#{ xml: "Conditions", occurs: "optional",
              cite: "saml-core-1.1 2.3.2" })
  conditions?: Conditions;

  @element(#{ xml: "Advice", occurs: "optional", written: false,
              cite: "saml-core-1.1 2.3.2.2" })
  advice?: string;

  @element(#{ xml: "AuthenticationStatement", occurs: "many",
              cite: "saml-core-1.1 2.4.3" })
  authenticationStatement?: AuthenticationStatement;

  @element(#{ xml: "AttributeStatement", occurs: "many",
              cite: "saml-core-1.1 2.4.5" })
  attributeStatement?: AttributeStatement;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-core-1.1 2.3.2, 5.4.1" })
  signature?: string;
}

@message(#{ id: "saml11.Status", element: "Status",
            xmlns: "urn:oasis:names:tc:SAML:1.0:protocol",
            direction: "write", cite: "saml-core-1.1 section 3.4.3" })
model Status11 {
  @element(#{ xml: "StatusCode", occurs: "one",
              cite: "saml-core-1.1 3.4.3.1" })
  statusCode: string;

  @element(#{ xml: "StatusMessage", occurs: "optional",
              cite: "saml-core-1.1 3.4.3.2" })
  statusMessage?: string;

  @element(#{ xml: "StatusDetail", occurs: "optional", written: false,
              cite: "saml-core-1.1 3.4.3.3" })
  statusDetail?: string;
}

/**
 * The Response: ds:Signature FIRST ('prepend'), before the Status. Recipient
 * on a Browser/POST answer, InResponseTo only on a SOAP one.
 */
@message(#{ id: "saml11.Response", element: "Response",
            xmlns: "urn:oasis:names:tc:SAML:1.0:protocol",
            direction: "write", cite: "saml-core-1.1 section 3.4.2" })
model Response {
  @attribute(#{ xml: "ResponseID", cite: "saml-core-1.1 3.4.1" })
  responseId: string;

  @attribute(#{ xml: "MajorVersion", fixed: "1",
                cite: "saml-core-1.1 3.4.1" })
  majorVersion: string;

  @attribute(#{ xml: "MinorVersion", fixed: "1",
                cite: "saml-core-1.1 3.4.1" })
  minorVersion: string;

  @attribute(#{ xml: "IssueInstant", cite: "saml-core-1.1 3.4.1" })
  issueInstant: string;

  @attribute(#{ xml: "Recipient", cite: "saml-core-1.1 3.4.1" })
  recipient?: string;

  @attribute(#{ xml: "InResponseTo", cite: "saml-core-1.1 3.4.1" })
  inResponseTo?: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-core-1.1 3.4.1, 5.4.1" })
  signature?: string;

  @element(#{ xml: "Status", occurs: "one", cite: "saml-core-1.1 3.4.2" })
  status: Status11;

  @element(#{ xml: "Assertion", occurs: "many",
              cite: "saml-core-1.1 3.4.2" })
  assertion?: Assertion;
}
