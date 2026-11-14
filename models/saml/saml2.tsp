// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/saml/saml2.tsp
//
// Written by hand (#1579). SAML 2.0, AS THIS SERVICE SPEAKS IT: the Web
// Browser SSO profile, Single Logout, artifact resolution and the attribute
// authority (`saml/saml2_sso.ts`), and the assertion `saml/saml2.ts` builds
// for them and for WS-Trust and WS-Federation.
//
// * THE VOCABULARIES (`@vocabulary`): the namespaces, the bindings (and what
//   each carries), the top- and second-level status codes of
//   saml-core-2.0-os section 3.2.2.2, the NameID formats (section 8.3), the
//   attribute name formats (8.2), the confirmation methods
//   (saml-profiles-2.0-os section 3) and the authentication context classes
//   (saml-authn-context-2.0-os section 3.4) — with the two classes that are
//   not OASIS's and are used anyway. The code asks `saml/saml_model.ts` for a
//   term by name, so a URI is written here once.
// * THE MESSAGES (`@message`): every element this service writes, with its
//   attributes and children IN THE SCHEMA'S SEQUENCE — the builders join
//   their parts in this order, and `SamlModel.hold()` checks what they
//   built against it, recording a gap under STS-SAML-0121 and changing
//   nothing — and every request it reads, with which attributes the reader
//   hands to the code. What a child the builder never writes (`written:
//   false`) is, and where the signer puts ds:Signature (`signer: true`), is
//   stated so that the order is the schema's and not only ours.
// * THE METADATA (`md:EntityDescriptor` and the two roles it carries), in
//   saml-metadata-2.0-os section 2's order.
//
// XML parsing, canonicalisation, signing and encryption stay in code
// (`common/crypto.js`), and so does everything that needs state: whose
// signature a request carries, whether an address is registered, whether a
// session satisfies a context, whether an artifact was spent (saml/CLAUDE.md,
// *THE MESSAGES ARE THE MODEL'S*).

import "../lib/saml_lib.tsp";

using IyaSts.SamlLib;

namespace IyaSts.Saml2;

// ---------------------------------------------------------------------------
// THE VOCABULARIES.
// ---------------------------------------------------------------------------

@vocabulary(#{ id: "saml2.namespace",
               cite: "saml-core-2.0-os section 1.2; saml-metadata-2.0-os section 1.2" })
model Namespaces {
  @term(#{ cite: "saml-core-2.0-os section 1.2" })
  protocol: "urn:oasis:names:tc:SAML:2.0:protocol";

  @term(#{ cite: "saml-core-2.0-os section 1.2" })
  assertion: "urn:oasis:names:tc:SAML:2.0:assertion";

  @term(#{ cite: "saml-metadata-2.0-os section 1.2" })
  metadata: "urn:oasis:names:tc:SAML:2.0:metadata";

  @term(#{ cite: "SAML V2.0 Metadata Profile for Algorithm Support Version 1.0 section 1.3" })
  algorithmSupport: "urn:oasis:names:tc:SAML:metadata:algsupport";

  @term(#{ cite: "saml-core-2.0-os section 1.2 (ds:)" })
  xmlSignature: "http://www.w3.org/2000/09/xmldsig#";

  @term(#{ cite: "saml-bindings-2.0-os section 3.2 (SOAP 1.1)" })
  soap: "http://schemas.xmlsoap.org/soap/envelope/";
}

@vocabulary(#{ id: "saml2.binding",
               cite: "saml-bindings-2.0-os section 3",
               prefix: "urn:oasis:names:tc:SAML:2.0:bindings:" })
model Bindings {
  /** The message deflated, base64 and URL-encoded in the query string. */
  @term(#{ cite: "saml-bindings-2.0-os section 3.4", request: true,
           response: true,
           carries: #["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg",
                      "Signature"] })
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

  /** The message base64 in a form the browser posts. */
  @term(#{ cite: "saml-bindings-2.0-os section 3.5", request: true,
           response: true,
           carries: #["SAMLRequest", "SAMLResponse", "RelayState"] })
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

  /**
   * The POST binding's form with a detached signature over the form values
   * in place of an enveloped one.
   */
  @term(#{ cite: "SAML V2.0 HTTP POST \"SimpleSign\" Binding section 2",
           request: true, response: true,
           carries: #["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg",
                      "Signature", "KeyInfo"] })
  simpleSign: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign";

  /**
   * A 44-byte reference the service provider resolves over SOAP. A
   * Response's binding only: no AuthnRequest arrives as an artifact here
   * (#191).
   */
  @term(#{ cite: "saml-bindings-2.0-os section 3.6", response: true,
           carries: #["SAMLart", "RelayState"] })
  artifact: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";

  /** The back channel: artifact resolution and the attribute query. */
  @term(#{ cite: "saml-bindings-2.0-os section 3.2" })
  soap: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

  /** ECP's binding: refused by name (saml/CLAUDE.md). */
  @term(#{ cite: "saml-bindings-2.0-os section 3.3", readOnly: true })
  paos: "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
}

@vocabulary(#{ id: "saml2.status",
               cite: "saml-core-2.0-os section 3.2.2.2",
               prefix: "urn:oasis:names:tc:SAML:2.0:status:" })
model Status {
  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "top" })
  Success: "urn:oasis:names:tc:SAML:2.0:status:Success";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "top" })
  Requester: "urn:oasis:names:tc:SAML:2.0:status:Requester";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "top" })
  Responder: "urn:oasis:names:tc:SAML:2.0:status:Responder";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "top",
           readOnly: true })
  VersionMismatch: "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  AuthnFailed: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  InvalidAttrNameOrValue:
    "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  InvalidNameIDPolicy:
    "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  NoAuthnContext: "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  NoAvailableIDP: "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  NoPassive: "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  NoSupportedIDP: "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  PartialLogout: "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  ProxyCountExceeded:
    "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  RequestDenied: "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  RequestUnsupported:
    "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  RequestVersionDeprecated:
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  RequestVersionTooHigh:
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  RequestVersionTooLow:
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  ResourceNotRecognized:
    "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  TooManyResponses: "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  UnknownAttrProfile:
    "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second" })
  UnknownPrincipal: "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

  @term(#{ cite: "saml-core-2.0-os section 3.2.2.2", level: "second",
           readOnly: true })
  UnsupportedBinding:
    "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
}

// THE FORMATS THIS IDENTITY PROVIDER ADVERTISES are the `advertised` ones,
// in this order, and they are what the metadata lists. It is not a list of
// what is accepted: a NameIDPolicy naming another format is answered in the
// format it asked for, unless the service provider's consumed metadata
// declares its formats and that one is not among them (InvalidNameIDPolicy,
// #37). `saml2.unspecified` is the SAML 2.0 spelling of a format this
// service writes in its 1.1 spelling, as every deployed provider reads it.
@vocabulary(#{ id: "saml2.nameIdFormat",
               cite: "saml-core-2.0-os section 8.3" })
model NameIdFormats {
  @term(#{ cite: "saml-core-2.0-os section 8.3.1", advertised: true })
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

  @term(#{ cite: "saml-core-2.0-os section 8.3.2", advertised: true })
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

  @term(#{ cite: "saml-core-2.0-os section 8.3.7", advertised: true })
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

  @term(#{ cite: "saml-core-2.0-os section 8.3.8", advertised: true })
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

  @term(#{ cite: "saml-core-2.0-os section 8.3.3", advertised: true })
  x509SubjectName:
    "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

  @term(#{ cite: "saml-core-2.0-os section 8.3.6", advertised: true })
  entity: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

  @term(#{ cite: "saml-core-2.0-os section 8.3.4", readOnly: true })
  windowsDomainQualifiedName:
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";

  @term(#{ cite: "saml-core-2.0-os section 8.3.5", readOnly: true })
  kerberos: "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";

  /** The SAML 2.0 spelling of unspecified, which this service never writes. */
  @term(#{ cite: "saml-core-2.0-os section 8.3.1 (errata E12)",
           readOnly: true })
  unspecified2: "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
}

@vocabulary(#{ id: "saml2.attrNameFormat",
               cite: "saml-core-2.0-os section 8.2",
               prefix: "urn:oasis:names:tc:SAML:2.0:attrname-format:" })
model AttrNameFormats {
  @term(#{ cite: "saml-core-2.0-os section 8.2.2" })
  uri: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

  @term(#{ cite: "saml-core-2.0-os section 8.2.3" })
  basic: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

  @term(#{ cite: "saml-core-2.0-os section 8.2.1", readOnly: true })
  unspecified: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
}

@vocabulary(#{ id: "saml2.confirmation",
               cite: "saml-profiles-2.0-os section 3",
               prefix: "urn:oasis:names:tc:SAML:2.0:cm:" })
model Confirmations {
  /** What the Web Browser SSO profile requires (section 4.1.4.2). */
  @term(#{ cite: "saml-profiles-2.0-os section 3.3" })
  bearer: "urn:oasis:names:tc:SAML:2.0:cm:bearer";

  @term(#{ cite: "saml-profiles-2.0-os section 3.1", readOnly: true })
  holderOfKey: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

  @term(#{ cite: "saml-profiles-2.0-os section 3.2", readOnly: true })
  senderVouches: "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
}

/** The delegation restriction condition's own namespace and type. */
@vocabulary(#{ id: "saml2.condition",
               cite: "SAML V2.0 Condition for Delegation Restriction Version 1.0 section 2" })
model Conditions {
  @term(#{ cite: "SAML V2.0 Condition for Delegation Restriction section 2" })
  delegationNamespace: "urn:oasis:names:tc:SAML:2.0:conditions:delegation";

  @term(#{ cite: "SAML V2.0 Condition for Delegation Restriction section 2" })
  delegationType: "del:DelegationRestrictionType";
}

// `mfaDemand`: a RequestedAuthnContext naming one of these is read as "a
// second factor is required", and the sign-in screen is asked for one. The
// EAP phishing-resistant URIs are `common/phishing_resistance.ts`'s (#736),
// not a list here. `equivalent` is the SAML 1.1 authentication method that
// means the same thing, which a federated session re-asserted over the
// other profile takes.
@vocabulary(#{ id: "saml2.authnContext",
               cite: "saml-authn-context-2.0-os section 3.4",
               prefix: "urn:oasis:names:tc:SAML:2.0:ac:classes:" })
model AuthnContexts {
  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.20",
           equivalent: "password" })
  passwordProtectedTransport:
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.19",
           equivalent: "password" })
  password: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.12",
           equivalent: "kerberos" })
  kerberos: "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

  /**
   * TLSClient and not X509: what the main port verified is the client
   * certificate of the TLS HANDSHAKE.
   */
  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.24",
           equivalent: "tlsClient" })
  tlsClient: "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.27",
           equivalent: "x509" })
  x509: "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.28" })
  unspecified: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

  /**
   * What a WS-Trust assertion issued on a presented assertion or JWT states:
   * the requester authenticated earlier, elsewhere (ws-trust/CLAUDE.md).
   */
  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.18" })
  previousSession: "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";

  /**
   * Microsoft's: more than one factor, what AD FS emits for it. Not an
   * OASIS class; SAML 2.0's own have no member that says this without
   * overstating a mechanism.
   */
  @term(#{ cite: "MS-ADFSPIP; AD FS multiple authentication",
           mfaDemand: true, equivalent: "multipleAuthn" })
  multipleAuthn: "http://schemas.microsoft.com/claims/multipleauthn";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.13",
           mfaDemand: true })
  mobileTwoFactorContract:
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.25",
           mfaDemand: true })
  timeSyncToken: "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.22",
           mfaDemand: true })
  smartcardPki: "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE READS.
// ---------------------------------------------------------------------------

/** An AuthnRequest's NameIDPolicy. */
@message(#{ id: "saml2.NameIDPolicy", element: "NameIDPolicy",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "read",
            cite: "saml-core-2.0-os section 3.4.1.1" })
model NameIDPolicy {
  @attribute(#{ xml: "Format", read: true,
                cite: "saml-core-2.0-os section 3.4.1.1" })
  nameIdFormat?: string;

  @attribute(#{ xml: "SPNameQualifier", read: false,
                cite: "saml-core-2.0-os section 3.4.1.1" })
  spNameQualifier?: string;

  @attribute(#{ xml: "AllowCreate", read: true,
                cite: "saml-core-2.0-os section 3.4.1.1" })
  allowCreate?: boolean;
}

/**
 * The AuthnRequest. EVERYTHING section 3.4.1 puts on one is here; `read`
 * says which the reader hands to the code. Nothing here refuses: the
 * envelope's checks (`Version`, `IssueInstant`, `Destination`) are
 * `saml2_sso.ts`'s `envelopeProblem()`, which asks this model what Version
 * it accepts.
 */
@message(#{ id: "saml2.AuthnRequest", element: "AuthnRequest",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "read", cite: "saml-core-2.0-os section 3.4.1" })
model AuthnRequest {
  @attribute(#{ xml: "ID", read: true, cite: "saml-core-2.0-os 3.2.1" })
  id: string;

  @attribute(#{ xml: "Version", read: true, accepts: #["2.0"],
                cite: "saml-core-2.0-os 3.2.1, 3.2.2.1" })
  version: string;

  @attribute(#{ xml: "IssueInstant", read: true,
                cite: "saml-core-2.0-os 3.2.1" })
  issueInstant: string;

  @attribute(#{ xml: "Destination", read: true,
                cite: "saml-core-2.0-os 3.2.1" })
  destination?: string;

  @attribute(#{ xml: "Consent", read: false,
                cite: "saml-core-2.0-os 3.2.1" })
  consent?: string;

  @attribute(#{ xml: "ForceAuthn", read: true,
                cite: "saml-core-2.0-os 3.4.1" })
  forceAuthn?: boolean;

  @attribute(#{ xml: "IsPassive", read: true,
                cite: "saml-core-2.0-os 3.4.1" })
  isPassive?: boolean;

  @attribute(#{ xml: "ProtocolBinding", read: true,
                cite: "saml-core-2.0-os 3.4.1" })
  protocolBinding?: string;

  @attribute(#{ xml: "AssertionConsumerServiceIndex", read: true,
                cite: "saml-core-2.0-os 3.4.1" })
  acsIndex?: string;

  @attribute(#{ xml: "AssertionConsumerServiceURL", read: true,
                cite: "saml-core-2.0-os 3.4.1" })
  acsUrl?: string;

  @attribute(#{ xml: "AttributeConsumingServiceIndex", read: false,
                cite: "saml-core-2.0-os 3.4.1" })
  attributeConsumingServiceIndex?: string;

  @attribute(#{ xml: "ProviderName", read: false,
                cite: "saml-core-2.0-os 3.4.1" })
  providerName?: string;

  @element(#{ xml: "Issuer", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.2.1" })
  issuer?: string;

  @element(#{ xml: "Signature", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.2.1; saml/request_signature.ts decides what it proves" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", read: false,
              cite: "saml-core-2.0-os 3.2.1" })
  extensions?: string;

  /** A hint to pre-fill the sign-in screen with, never an assertion. */
  @element(#{ xml: "Subject", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.4.1" })
  subject?: string;

  @element(#{ xml: "NameIDPolicy", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.4.1.1" })
  nameIdPolicy?: NameIDPolicy;

  @element(#{ xml: "Conditions", occurs: "optional", read: false,
              cite: "saml-core-2.0-os 3.4.1" })
  conditions?: string;

  @element(#{ xml: "RequestedAuthnContext", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.3.2.2.1" })
  requestedAuthnContext?: string;

  @element(#{ xml: "Scoping", occurs: "optional", read: false,
              cite: "saml-core-2.0-os 3.4.1.2" })
  scoping?: string;
}

/** A service provider's LogoutRequest, read at /saml2/slo. */
@message(#{ id: "saml2.LogoutRequest.read", element: "LogoutRequest",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "read", cite: "saml-core-2.0-os section 3.7.1" })
model LogoutRequestRead {
  @attribute(#{ xml: "ID", read: true, cite: "saml-core-2.0-os 3.2.1" })
  id: string;

  @attribute(#{ xml: "Version", read: true, accepts: #["2.0"],
                cite: "saml-core-2.0-os 3.2.1, 3.2.2.1" })
  version: string;

  @attribute(#{ xml: "IssueInstant", read: true,
                cite: "saml-core-2.0-os 3.2.1" })
  issueInstant: string;

  @attribute(#{ xml: "Destination", read: true,
                cite: "saml-core-2.0-os 3.2.1" })
  destination?: string;

  @attribute(#{ xml: "Consent", read: false,
                cite: "saml-core-2.0-os 3.2.1" })
  consent?: string;

  @attribute(#{ xml: "Reason", read: false,
                cite: "saml-core-2.0-os 3.7.1" })
  reason?: string;

  @attribute(#{ xml: "NotOnOrAfter", read: false,
                cite: "saml-core-2.0-os 3.7.1" })
  notOnOrAfter?: string;

  @element(#{ xml: "Issuer", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.2.1" })
  issuer?: string;

  @element(#{ xml: "Signature", occurs: "optional", read: true,
              cite: "saml-core-2.0-os 3.2.1" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", read: false,
              cite: "saml-core-2.0-os 3.2.1" })
  extensions?: string;

  /** Always decrypted when it is an EncryptedID (saml/CLAUDE.md). */
  @element(#{ xml: "NameID", occurs: "one", or: #["EncryptedID", "BaseID"],
              read: true, cite: "saml-core-2.0-os 3.7.1" })
  nameId: string;

  @element(#{ xml: "SessionIndex", occurs: "many", read: true,
              cite: "saml-core-2.0-os 3.7.1" })
  sessionIndex?: string;
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE WRITES.
// ---------------------------------------------------------------------------

@message(#{ id: "saml2.StatusCode", element: "StatusCode",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "write", cite: "saml-core-2.0-os section 3.2.2.2" })
model StatusCode {
  @attribute(#{ xml: "Value", cite: "saml-core-2.0-os 3.2.2.2" })
  value: string;

  /** The second-level code, nested in the first. */
  @element(#{ xml: "StatusCode", occurs: "optional",
              cite: "saml-core-2.0-os 3.2.2.2" })
  statusCode?: StatusCode;
}

@message(#{ id: "saml2.Status", element: "Status",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "write", cite: "saml-core-2.0-os section 3.2.2.1" })
model Status2 {
  @element(#{ xml: "StatusCode", occurs: "one",
              cite: "saml-core-2.0-os 3.2.2.2" })
  statusCode: StatusCode;

  @element(#{ xml: "StatusMessage", occurs: "optional",
              cite: "saml-core-2.0-os 3.2.2.3" })
  statusMessage?: string;

  @element(#{ xml: "StatusDetail", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 3.2.2.4" })
  statusDetail?: string;
}

@message(#{ id: "saml2.SubjectConfirmationData",
            element: "SubjectConfirmationData",
            xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
            direction: "write", cite: "saml-core-2.0-os section 2.4.1.2" })
model SubjectConfirmationData {
  @attribute(#{ xml: "NotBefore", written: false,
                cite: "saml-core-2.0-os 2.4.1.2" })
  notBefore?: string;

  /** Section 4.1.4.2 of the profiles makes it a MUST. */
  @attribute(#{ xml: "NotOnOrAfter", cite: "saml-core-2.0-os 2.4.1.2" })
  notOnOrAfter?: string;

  @attribute(#{ xml: "Recipient", cite: "saml-core-2.0-os 2.4.1.2" })
  recipient?: string;

  @attribute(#{ xml: "InResponseTo", cite: "saml-core-2.0-os 2.4.1.2" })
  inResponseTo?: string;

  @attribute(#{ xml: "Address", written: false,
                cite: "saml-core-2.0-os 2.4.1.2" })
  address?: string;
}

@message(#{ id: "saml2.Subject", element: "Subject",
            xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
            direction: "write", cite: "saml-core-2.0-os section 2.4.1" })
model Subject {
  @element(#{ xml: "NameID", occurs: "optional",
              or: #["EncryptedID", "BaseID"],
              cite: "saml-core-2.0-os 2.4.1" })
  nameId?: string;

  @element(#{ xml: "SubjectConfirmation", occurs: "many",
              cite: "saml-core-2.0-os 2.4.1.1" })
  subjectConfirmation?: string;
}

/**
 * The schema's Conditions is a choice repeated; this is the order this
 * service writes its two in: the delegation restriction, then the audience.
 */
@message(#{ id: "saml2.Conditions", element: "Conditions",
            xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
            direction: "write", cite: "saml-core-2.0-os section 2.5.1" })
model Conditions2 {
  @attribute(#{ xml: "NotBefore", cite: "saml-core-2.0-os 2.5.1" })
  notBefore?: string;

  @attribute(#{ xml: "NotOnOrAfter", cite: "saml-core-2.0-os 2.5.1" })
  notOnOrAfter?: string;

  @element(#{ xml: "Condition", occurs: "many",
              cite: "saml-core-2.0-os 2.5.1.1; the Delegation Restriction condition (#186)" })
  condition?: string;

  @element(#{ xml: "AudienceRestriction", occurs: "many",
              cite: "saml-core-2.0-os 2.5.1.4" })
  audienceRestriction?: string;

  @element(#{ xml: "OneTimeUse", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 2.5.1.5" })
  oneTimeUse?: string;

  @element(#{ xml: "ProxyRestriction", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 2.5.1.6" })
  proxyRestriction?: string;
}

@message(#{ id: "saml2.AuthnStatement", element: "AuthnStatement",
            xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
            direction: "write", cite: "saml-core-2.0-os section 2.7.2" })
model AuthnStatement {
  /** The session's authentication instant, never backdated by the skew. */
  @attribute(#{ xml: "AuthnInstant", cite: "saml-core-2.0-os 2.7.2" })
  authnInstant: string;

  @attribute(#{ xml: "SessionIndex", cite: "saml-core-2.0-os 2.7.2" })
  sessionIndex?: string;

  @attribute(#{ xml: "SessionNotOnOrAfter", written: false,
                cite: "saml-core-2.0-os 2.7.2" })
  sessionNotOnOrAfter?: string;

  @element(#{ xml: "SubjectLocality", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 2.7.2.1" })
  subjectLocality?: string;

  @element(#{ xml: "AuthnContext", occurs: "one",
              cite: "saml-core-2.0-os 2.7.2.2" })
  authnContext: string;
}

/**
 * The assertion. The statements are a repeated choice in the schema; this
 * service writes the AuthnStatement first and the AttributeStatement after
 * it, and the attribute query's assertion carries no AuthnStatement.
 */
@message(#{ id: "saml2.Assertion", element: "Assertion",
            xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
            direction: "write", cite: "saml-core-2.0-os section 2.3.3" })
model Assertion {
  @attribute(#{ xml: "ID", cite: "saml-core-2.0-os 2.3.3" })
  id: string;

  @attribute(#{ xml: "Version", fixed: "2.0",
                cite: "saml-core-2.0-os 2.3.3" })
  version: string;

  /** When it was issued, never backdated by `saml.clockSkewS`. */
  @attribute(#{ xml: "IssueInstant", cite: "saml-core-2.0-os 2.3.3" })
  issueInstant: string;

  @element(#{ xml: "Issuer", occurs: "one",
              cite: "saml-core-2.0-os 2.3.3" })
  issuer: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-core-2.0-os 2.3.3, 5.4.1" })
  signature?: string;

  @element(#{ xml: "Subject", occurs: "optional",
              cite: "saml-core-2.0-os 2.3.3" })
  subject?: Subject;

  @element(#{ xml: "Conditions", occurs: "optional",
              cite: "saml-core-2.0-os 2.3.3" })
  conditions?: Conditions2;

  @element(#{ xml: "Advice", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 2.6.1" })
  advice?: string;

  @element(#{ xml: "AuthnStatement", occurs: "many",
              cite: "saml-core-2.0-os 2.7.2" })
  authnStatement?: AuthnStatement;

  @element(#{ xml: "AttributeStatement", occurs: "many",
              cite: "saml-core-2.0-os 2.7.3" })
  attributeStatement?: string;
}

/**
 * The Response, success and failure alike. ds:Signature goes after the
 * Issuer (`'after-issuer'`), as section 5.4.1's schema position has it.
 */
@message(#{ id: "saml2.Response", element: "Response",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "write", cite: "saml-core-2.0-os section 3.3.3" })
model Response {
  @attribute(#{ xml: "ID", cite: "saml-core-2.0-os 3.2.2" })
  id: string;

  @attribute(#{ xml: "Version", fixed: "2.0",
                cite: "saml-core-2.0-os 3.2.2" })
  version: string;

  @attribute(#{ xml: "IssueInstant", cite: "saml-core-2.0-os 3.2.2" })
  issueInstant: string;

  @attribute(#{ xml: "Destination", cite: "saml-core-2.0-os 3.2.2" })
  destination?: string;

  /** Absent from an unsolicited Response (saml-profiles-2.0-os 4.1.5). */
  @attribute(#{ xml: "InResponseTo", cite: "saml-core-2.0-os 3.2.2" })
  inResponseTo?: string;

  @attribute(#{ xml: "Consent", written: false,
                cite: "saml-core-2.0-os 3.2.2" })
  consent?: string;

  @element(#{ xml: "Issuer", occurs: "optional",
              cite: "saml-core-2.0-os 3.2.2" })
  issuer?: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-core-2.0-os 3.2.2, 5.4.1" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 3.2.2" })
  extensions?: string;

  @element(#{ xml: "Status", occurs: "one",
              cite: "saml-core-2.0-os 3.2.2" })
  status: Status2;

  @element(#{ xml: "Assertion", occurs: "many", or: #["EncryptedAssertion"],
              cite: "saml-core-2.0-os 3.3.3" })
  assertion?: Assertion;
}

/** The SOAP binding's answer to an ArtifactResolve; deliberately unsigned. */
@message(#{ id: "saml2.ArtifactResponse", element: "ArtifactResponse",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "write", cite: "saml-core-2.0-os section 3.5.2" })
model ArtifactResponse {
  @attribute(#{ xml: "ID", cite: "saml-core-2.0-os 3.2.2" })
  id: string;

  @attribute(#{ xml: "Version", fixed: "2.0",
                cite: "saml-core-2.0-os 3.2.2" })
  version: string;

  @attribute(#{ xml: "IssueInstant", cite: "saml-core-2.0-os 3.2.2" })
  issueInstant: string;

  @attribute(#{ xml: "InResponseTo", cite: "saml-core-2.0-os 3.2.2" })
  inResponseTo?: string;

  @element(#{ xml: "Issuer", occurs: "optional",
              cite: "saml-core-2.0-os 3.2.2" })
  issuer?: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 3.2.2" })
  signature?: string;

  @element(#{ xml: "Status", occurs: "one",
              cite: "saml-core-2.0-os 3.2.2" })
  status: Status2;

  /** The message the artifact stood for; nothing when it did not resolve. */
  @element(#{ xml: "Response", occurs: "optional",
              or: #["LogoutRequest", "LogoutResponse"],
              cite: "saml-core-2.0-os 3.5.2" })
  message?: Response;
}

@message(#{ id: "saml2.LogoutRequest", element: "LogoutRequest",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "write", cite: "saml-core-2.0-os section 3.7.1" })
model LogoutRequest {
  @attribute(#{ xml: "ID", cite: "saml-core-2.0-os 3.2.1" })
  id: string;

  @attribute(#{ xml: "Version", fixed: "2.0",
                cite: "saml-core-2.0-os 3.2.1" })
  version: string;

  @attribute(#{ xml: "IssueInstant", cite: "saml-core-2.0-os 3.2.1" })
  issueInstant: string;

  @attribute(#{ xml: "Destination", cite: "saml-core-2.0-os 3.2.1" })
  destination?: string;

  @element(#{ xml: "Issuer", occurs: "optional",
              cite: "saml-core-2.0-os 3.2.1" })
  issuer?: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-core-2.0-os 3.2.1, 5.4.1" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 3.2.1" })
  extensions?: string;

  /** An EncryptedID where `saml2.encryptLogoutNameId` says (#168). */
  @element(#{ xml: "NameID", occurs: "one", or: #["EncryptedID"],
              cite: "saml-core-2.0-os 3.7.1" })
  nameId: string;

  @element(#{ xml: "SessionIndex", occurs: "many",
              cite: "saml-core-2.0-os 3.7.1" })
  sessionIndex?: string;
}

@message(#{ id: "saml2.LogoutResponse", element: "LogoutResponse",
            xmlns: "urn:oasis:names:tc:SAML:2.0:protocol",
            direction: "write", cite: "saml-core-2.0-os section 3.7.2" })
model LogoutResponse {
  @attribute(#{ xml: "ID", cite: "saml-core-2.0-os 3.2.2" })
  id: string;

  @attribute(#{ xml: "Version", fixed: "2.0",
                cite: "saml-core-2.0-os 3.2.2" })
  version: string;

  @attribute(#{ xml: "IssueInstant", cite: "saml-core-2.0-os 3.2.2" })
  issueInstant: string;

  @attribute(#{ xml: "Destination", cite: "saml-core-2.0-os 3.2.2" })
  destination?: string;

  @attribute(#{ xml: "InResponseTo", cite: "saml-core-2.0-os 3.2.2" })
  inResponseTo?: string;

  @element(#{ xml: "Issuer", occurs: "optional",
              cite: "saml-core-2.0-os 3.2.2" })
  issuer?: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-core-2.0-os 3.2.2, 5.4.1" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", written: false,
              cite: "saml-core-2.0-os 3.2.2" })
  extensions?: string;

  /** PartialLogout or UnknownPrincipal as its second level (#192). */
  @element(#{ xml: "Status", occurs: "one",
              cite: "saml-core-2.0-os 3.2.2" })
  status: Status2;
}

// ---------------------------------------------------------------------------
// THE METADATA: ONE ENTITY, ONE DOCUMENT (#523).
// ---------------------------------------------------------------------------

/**
 * The identity provider's role, saml-metadata-2.0-os sections 2.4.1, 2.4.2
 * and 2.4.3 in sequence: the KeyDescriptors (signing, encryption, then the
 * back channel's TLS keys, #248), the ArtifactResolutionServices (SAML
 * 2.0's index 0, SAML 1.1's index 1), the SingleLogoutServices, the NameID
 * formats, then the SingleSignOnServices — never an HTTP-Artifact one
 * (#191).
 */
@message(#{ id: "md.IDPSSODescriptor", element: "IDPSSODescriptor",
            xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
            direction: "write", cite: "saml-metadata-2.0-os section 2.4.3" })
model IdpSsoDescriptor {
  @attribute(#{ xml: "WantAuthnRequestsSigned",
                cite: "saml-metadata-2.0-os 2.4.3" })
  wantAuthnRequestsSigned?: boolean;

  @attribute(#{ xml: "protocolSupportEnumeration",
                cite: "saml-metadata-2.0-os 2.4.1" })
  protocolSupportEnumeration: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", written: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  extensions?: string;

  @element(#{ xml: "KeyDescriptor", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.1.1" })
  keyDescriptor?: string;

  @element(#{ xml: "Organization", occurs: "optional", written: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  organization?: string;

  @element(#{ xml: "ContactPerson", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  contactPerson?: string;

  @element(#{ xml: "ArtifactResolutionService", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.2" })
  artifactResolutionService?: string;

  @element(#{ xml: "SingleLogoutService", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.2" })
  singleLogoutService?: string;

  @element(#{ xml: "ManageNameIDService", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.2" })
  manageNameIdService?: string;

  @element(#{ xml: "NameIDFormat", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.2" })
  nameIdFormat?: string;

  @element(#{ xml: "SingleSignOnService", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.3" })
  singleSignOnService: string;

  @element(#{ xml: "NameIDMappingService", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.3" })
  nameIdMappingService?: string;

  @element(#{ xml: "AssertionIDRequestService", occurs: "many",
              written: false, cite: "saml-metadata-2.0-os 2.4.3" })
  assertionIdRequestService?: string;

  @element(#{ xml: "AttributeProfile", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.3" })
  attributeProfile?: string;

  @element(#{ xml: "Attribute", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.3" })
  attribute?: string;
}

/** The attribute authority's role (#189), saml-metadata-2.0-os 2.4.7. */
@message(#{ id: "md.AttributeAuthorityDescriptor",
            element: "AttributeAuthorityDescriptor",
            xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
            direction: "write", cite: "saml-metadata-2.0-os section 2.4.7" })
model AttributeAuthorityDescriptor {
  @attribute(#{ xml: "protocolSupportEnumeration",
                cite: "saml-metadata-2.0-os 2.4.1" })
  protocolSupportEnumeration: string;

  @element(#{ xml: "KeyDescriptor", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.1.1" })
  keyDescriptor?: string;

  @element(#{ xml: "AttributeService", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.7" })
  attributeService: string;

  @element(#{ xml: "AssertionIDRequestService", occurs: "many",
              written: false, cite: "saml-metadata-2.0-os 2.4.7" })
  assertionIdRequestService?: string;

  @element(#{ xml: "NameIDFormat", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.7" })
  nameIdFormat?: string;

  @element(#{ xml: "AttributeProfile", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.7" })
  attributeProfile?: string;

  @element(#{ xml: "Attribute", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.4.7" })
  attribute?: string;
}

/**
 * The one EntityDescriptor (saml-metadata-2.0-os 2.3.2): ds:Signature
 * prepended, the Extensions (the crypto metadata location, #42, and the
 * Algorithm Support profile's methods, #1368), the roles — WS-Federation's
 * first in its own view (#524), a choice the schema lets come in any order —
 * then the Organization.
 */
@message(#{ id: "md.EntityDescriptor", element: "EntityDescriptor",
            xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
            direction: "write", cite: "saml-metadata-2.0-os section 2.3.2" })
model EntityDescriptor {
  @attribute(#{ xml: "ID", cite: "saml-metadata-2.0-os 2.3.2" })
  id?: string;

  @attribute(#{ xml: "entityID", cite: "saml-metadata-2.0-os 2.3.2" })
  entityId: string;

  @attribute(#{ xml: "validUntil", written: false,
                cite: "saml-metadata-2.0-os 2.3.2" })
  validUntil?: string;

  @attribute(#{ xml: "cacheDuration", written: false,
                cite: "saml-metadata-2.0-os 2.3.2" })
  cacheDuration?: string;

  @element(#{ xml: "Signature", occurs: "optional", written: false,
              signer: true, cite: "saml-metadata-2.0-os 2.3.2" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional",
              cite: "saml-metadata-2.0-os 2.3.2" })
  extensions?: string;

  @element(#{ xml: "RoleDescriptor", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.1; WS-Federation 1.2 section 3.1 (its view only)" })
  roleDescriptor?: string;

  @element(#{ xml: "IDPSSODescriptor", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.3" })
  idpSsoDescriptor: IdpSsoDescriptor;

  @element(#{ xml: "AttributeAuthorityDescriptor", occurs: "many",
              cite: "saml-metadata-2.0-os 2.4.7" })
  attributeAuthorityDescriptor?: AttributeAuthorityDescriptor;

  /** Omitted when `saml.organizationName` is emptied. */
  @element(#{ xml: "Organization", occurs: "optional",
              cite: "saml-metadata-2.0-os 2.3.2.1" })
  organization?: string;

  @element(#{ xml: "ContactPerson", occurs: "many", written: false,
              cite: "saml-metadata-2.0-os 2.3.2.2" })
  contactPerson?: string;

  @element(#{ xml: "AdditionalMetadataLocation", occurs: "many",
              written: false, cite: "saml-metadata-2.0-os 2.3.2" })
  additionalMetadataLocation?: string;
}

// ---------------------------------------------------------------------------
// A SERVICE PROVIDER'S METADATA, AS `saml/sp_metadata.ts` CONSUMES IT (#37).
// ---------------------------------------------------------------------------

/**
 * An AssertionConsumerService or a SingleLogoutService: the endpoint types
 * of saml-metadata-2.0-os section 2.2.2 and 2.2.3. `isDefault` is read as
 * its text, because "absent" is a third answer the default selection needs.
 */
@message(#{ id: "md.Endpoint", element: "AssertionConsumerService",
            xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
            direction: "read", cite: "saml-metadata-2.0-os section 2.2.2" })
model Endpoint {
  @attribute(#{ xml: "Binding", read: true,
                cite: "saml-metadata-2.0-os 2.2.2" })
  binding: string;

  @attribute(#{ xml: "Location", read: true,
                cite: "saml-metadata-2.0-os 2.2.2" })
  location: string;

  @attribute(#{ xml: "ResponseLocation", read: true,
                cite: "saml-metadata-2.0-os 2.2.2" })
  responseLocation?: string;

  @attribute(#{ xml: "index", read: true,
                cite: "saml-metadata-2.0-os 2.2.3" })
  index?: string;

  @attribute(#{ xml: "isDefault", read: true,
                cite: "saml-metadata-2.0-os 2.2.3" })
  isDefault?: string;
}

/**
 * The role a service provider's metadata is consumed for: the two flags,
 * the validity, and the children `consume()` writes onto the application
 * entry.
 */
@message(#{ id: "md.SPSSODescriptor", element: "SPSSODescriptor",
            xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
            direction: "read", cite: "saml-metadata-2.0-os section 2.4.4" })
model SpSsoDescriptor {
  @attribute(#{ xml: "ID", read: false, cite: "saml-metadata-2.0-os 2.4.1" })
  id?: string;

  @attribute(#{ xml: "validUntil", read: true,
                cite: "saml-metadata-2.0-os 2.4.1" })
  validUntil?: string;

  @attribute(#{ xml: "cacheDuration", read: true,
                cite: "saml-metadata-2.0-os 2.4.1" })
  cacheDuration?: string;

  @attribute(#{ xml: "protocolSupportEnumeration", read: true,
                cite: "saml-metadata-2.0-os 2.4.1" })
  protocolSupportEnumeration: string;

  @attribute(#{ xml: "errorURL", read: false,
                cite: "saml-metadata-2.0-os 2.4.1" })
  errorUrl?: string;

  @attribute(#{ xml: "AuthnRequestsSigned", read: true,
                cite: "saml-metadata-2.0-os 2.4.4" })
  authnRequestsSigned?: boolean;

  @attribute(#{ xml: "WantAssertionsSigned", read: true,
                cite: "saml-metadata-2.0-os 2.4.4" })
  wantAssertionsSigned?: boolean;

  @element(#{ xml: "Signature", occurs: "optional", read: true,
              cite: "saml-metadata-2.0-os 2.4.1" })
  signature?: string;

  @element(#{ xml: "Extensions", occurs: "optional", read: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  extensions?: string;

  /** `use="signing"` or none: the registered set; `encryption`: the key. */
  @element(#{ xml: "KeyDescriptor", occurs: "many", read: true,
              cite: "saml-metadata-2.0-os 2.4.1.1" })
  keyDescriptor?: string;

  @element(#{ xml: "Organization", occurs: "optional", read: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  organization?: string;

  @element(#{ xml: "ContactPerson", occurs: "many", read: false,
              cite: "saml-metadata-2.0-os 2.4.1" })
  contactPerson?: string;

  @element(#{ xml: "ArtifactResolutionService", occurs: "many", read: false,
              cite: "saml-metadata-2.0-os 2.4.2" })
  artifactResolutionService?: string;

  @element(#{ xml: "SingleLogoutService", occurs: "many", read: true,
              cite: "saml-metadata-2.0-os 2.4.2" })
  singleLogoutService?: Endpoint;

  @element(#{ xml: "ManageNameIDService", occurs: "many", read: false,
              cite: "saml-metadata-2.0-os 2.4.2" })
  manageNameIdService?: string;

  @element(#{ xml: "NameIDFormat", occurs: "many", read: true,
              cite: "saml-metadata-2.0-os 2.4.2" })
  nameIdFormat?: string;

  @element(#{ xml: "AssertionConsumerService", occurs: "many", read: true,
              cite: "saml-metadata-2.0-os 2.4.4" })
  assertionConsumerService: Endpoint;

  @element(#{ xml: "AttributeConsumingService", occurs: "many", read: false,
              cite: "saml-metadata-2.0-os 2.4.4" })
  attributeConsumingService?: string;
}
