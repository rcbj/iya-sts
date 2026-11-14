// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/ws/wsfed.tsp
//
// Written by hand (#1579). WS-FEDERATION 1.2's PASSIVE REQUESTOR PROFILE, AS
// `/wsfed` SPEAKS IT (`ws-federation/wsfed.ts`):
//
// * THE PARAMETERS (`@params`): every parameter section 13.2 defines for a
//   sign-in and a sign-out, with what this service does with each — read,
//   recorded and not enforced, refused (`wreqptr`, under its code), echoed
//   (`wctx`), written (`wresult`), or ignored — and the two non-spec ones it
//   reads beside them (`tokenType`, `trust`).
// * THE VOCABULARIES: the `wa` actions (and which are answered), the token
//   types offered (SAML's own assertion namespaces, written as those
//   properties, with the short forms the non-spec `tokenType` takes), the
//   `wauth` values and the demand each is read as (SAML's authentication
//   methods and classes, again as those properties, and the two identity
//   namespaces' password methods), the claim types offered, and the
//   namespaces.
// * THE MESSAGES: the RSTR a sign-in response posts in `wresult` — in the
//   2005/02 or 1.3 trust namespace, AD FS's element order, which differs
//   from `/sts`'s — and the `fed:SecurityTokenServiceType` RoleDescriptor the
//   realm's one metadata document carries in its WS-Federation view (#524).
//   `WsModel.hold()` checks both as they are built, logs a gap under
//   STS-WSFED-0031 and changes nothing.
//
// The sign-in itself — the session, `wfresh`'s age, `wauth`'s step-up, a
// registered `wreply`, the issuance policy — needs state and stays in code
// (ws-federation/CLAUDE.md, *THE MESSAGES ARE THE MODEL'S*).

import "../lib/saml_lib.tsp";
import "../saml/saml2.tsp";
import "../saml/saml11.tsp";
import "./soap.tsp";
import "./wstrust.tsp";

using IyaSts.SamlLib;

namespace IyaSts.WsFederation;

// ---------------------------------------------------------------------------
// THE PARAMETERS.
// ---------------------------------------------------------------------------

/**
 * What `/wsfed` reads, by GET or by form POST (the body winning a
 * collision), and what it sends back.
 */
@params(#{ id: "wsfed.passive",
           cite: "WS-Federation 1.2 section 13.2" })
model PassiveParams {
  /** The action: `wsfed.request`'s terms. None draws the description. */
  @param(#{ wire: "wa", use: "read",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wa: string;

  /** Required on a sign-in: the assertion's audience (STS-WSFED-0002). */
  @param(#{ wire: "wtrealm", use: "read",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wtrealm: string;

  /**
   * Where the response is posted: a registered `wsfedReplyUrl` in product,
   * an absolute http(s) URL always (STS-WSFED-0003, 0004).
   */
  @param(#{ wire: "wreply", use: "read",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wreply: string;

  @param(#{ wire: "wctx", use: "echoed",
            cite: "WS-Federation 1.2 section 13.2.1 (returned unchanged)" })
  wctx: string;

  /** Logged with its skew from this clock; nothing is refused on it. */
  @param(#{ wire: "wct", use: "recorded",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wct: string;

  /** Minutes since the authentication; 0 asks for a fresh one. */
  @param(#{ wire: "wfresh", use: "read",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wfresh: string;

  /** One URI, a `wsfed.wauth` term or an EAP class (#36, #737). */
  @param(#{ wire: "wauth", use: "read", refusedAs: "STS-WSFED-0006",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wauth: string;

  /** Shown on the sign-in screen; no account is read off it (#561). */
  @param(#{ wire: "whr", use: "recorded",
            cite: "WS-Federation 1.2 section 13.2.1" })
  whr: string;

  /** An RST by value: its TokenType is read, its AppliesTo only logged. */
  @param(#{ wire: "wreq", use: "read",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wreq: string;

  /** NEVER DEREFERENCED: fetching it would be a server-side forgery. */
  @param(#{ wire: "wreqptr", use: "refused", refusedAs: "STS-WSFED-0001",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wreqptr: string;

  @param(#{ wire: "wres", use: "ignored",
            cite: "WS-Federation 1.2 section 13.2.1 (the resource)" })
  wres: string;

  /** Logged; no policy is enforced here. */
  @param(#{ wire: "wp", use: "recorded",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wp: string;

  /** Logged; the parameters are read as ordinary values whatever it says. */
  @param(#{ wire: "wencoding", use: "recorded",
            cite: "WS-Federation 1.2 section 13.2.1" })
  wencoding: string;

  /** The sign-in response: the RSTR, posted to `wreply`. */
  @param(#{ wire: "wresult", use: "written",
            cite: "WS-Federation 1.2 section 13.2.2" })
  wresult: string;

  /**
   * NON-SPEC, in the manner of `/sts`'s `?encrypt=1`: a token type, or one
   * of a type's `shortForms`, without typing an RST into a URL.
   */
  @param(#{ wire: "tokenType", use: "read", nonSpec: true,
            refusedAs: "STS-WSFED-0005",
            cite: "this service: ws-federation/wsfed.ts tokenTypeFor()" })
  tokenType: string;

  /** NON-SPEC: `1.3` writes the RSTR in 1.3's namespace, else 2005/02's. */
  @param(#{ wire: "trust", use: "read", nonSpec: true, accepts: #["1.3"],
            cite: "this service: ws-federation/wsfed.ts buildRstr()" })
  trust: string;
}

// ---------------------------------------------------------------------------
// THE VOCABULARIES.
// ---------------------------------------------------------------------------

/** The `wa` actions; `answered: false` is a 501 that names the service. */
@vocabulary(#{ id: "wsfed.request", cite: "WS-Federation 1.2 section 13.2" })
model Actions {
  @term(#{ cite: "WS-Federation 1.2 section 13.2.1", answered: true })
  signIn: "wsignin1.0";

  @term(#{ cite: "WS-Federation 1.2 section 13.2.4", answered: true })
  signOut: "wsignout1.0";

  /** Non-interactive: it arrives as an image (#561). */
  @term(#{ cite: "WS-Federation 1.2 section 13.2.4", answered: true })
  signOutCleanup: "wsignoutcleanup1.0";

  /** The attribute service: STS-WSFED-0012. */
  @term(#{ cite: "WS-Federation 1.2 sections 3.2, 13.3", answered: false })
  attribute: "wattr1.0";

  /** The pseudonym service: STS-WSFED-0012. */
  @term(#{ cite: "WS-Federation 1.2 sections 3.3, 13.4", answered: false })
  pseudonym: "wpseudo1.0";
}

/**
 * The token types a sign-in issues and the metadata offers, SAML's own
 * assertion namespaces. The first is the default.
 */
@vocabulary(#{ id: "wsfed.tokenType",
               cite: "WS-Federation 1.2 sections 3.1.6, 13.2.1" })
model TokenTypes {
  @term(#{ cite: "WS-Federation 1.2 section 3.1.6; saml-core-1.1 section 1.2",
           offered: true, shortForms: #["saml11", "saml1", "1.1"] })
  saml11: IyaSts.Saml11.Namespaces.assertion;

  @term(#{ cite: "WS-Federation 1.2 section 3.1.6; saml-core-2.0-os section 1.2",
           offered: true, shortForms: #["saml2", "saml20", "2.0"] })
  saml2: IyaSts.Saml2.Namespaces.assertion;
}

/**
 * What `wauth` may ask for, besides the two EAP class URIs
 * (`common/phishing_resistance.ts`), and the demand each is read as. A
 * demand the session does not meet is a step-up (#36); any other value is
 * refused (STS-WSFED-0006). SAML's terms are those properties.
 */
@vocabulary(#{ id: "wsfed.wauth",
               cite: "WS-Federation 1.2 section 13.2.1 (wauth)" })
model Wauth {
  @term(#{ cite: "saml-core-1.1 section 7.1", wauth: "password" })
  saml11Password: IyaSts.Saml11.AuthnMethods.password;

  @term(#{ cite: "saml-core-1.1 section 7.1", wauth: "password" })
  saml11Unspecified: IyaSts.Saml11.AuthnMethods.unspecified;

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.20",
           wauth: "password" })
  saml2PasswordProtectedTransport:
    IyaSts.Saml2.AuthnContexts.passwordProtectedTransport;

  @term(#{ cite: "saml-authn-context-2.0-os section 3.4.19",
           wauth: "password" })
  saml2Password: IyaSts.Saml2.AuthnContexts.password;

  @term(#{ cite: "Identity Selector Interoperability Profile 1.5 section 7.5",
           wauth: "password" })
  identityPassword: "http://schemas.xmlsoap.org/ws/2005/05/identity/authenticationmethod/password";

  @term(#{ cite: "MS-ADFSPIP; Windows Identity Foundation authentication methods",
           wauth: "password" })
  microsoftPassword: "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password";

  /** Two real factors; a passwordless key alone does not answer it. */
  @term(#{ cite: "MS-ADFSPIP; AD FS multiple authentication",
           wauth: "multiFactor" })
  multipleAuthn: IyaSts.Saml2.AuthnContexts.multipleAuthn;

  /** A key, in either role. */
  @term(#{ cite: "saml-core-1.1 section 7.1", wauth: "hardware" })
  hardwareToken: IyaSts.Saml11.AuthnMethods.hardwareToken;
}

/**
 * The 2005/02 sign-in response's key type: that vintage has no `/Bearer`,
 * and "no proof key" is the identity namespace's, what AD FS writes. 1.3's
 * is `wst.keyType`'s `bearer`.
 */
@vocabulary(#{ id: "wsfed.keyType",
               cite: "Identity Selector Interoperability Profile 1.5 section 3.3.3" })
model KeyTypes {
  @term(#{ cite: "ISIP 1.5 section 3.3.3 (NoProofKey)" })
  noProofKey: "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey";
}

@vocabulary(#{ id: "wsfed.namespace",
               cite: "WS-Federation 1.2 section 1.2" })
model Namespaces {
  @term(#{ cite: "WS-Federation 1.2 section 1.2 (fed:)" })
  federation: "http://docs.oasis-open.org/wsfed/federation/200706";

  @term(#{ cite: "WS-Federation 1.2 section 1.2 (auth:)" })
  authorization: "http://docs.oasis-open.org/wsfed/authorization/200706";

  /** The claim types' namespace: WS-Federation defines a dialect, no list. */
  @term(#{ cite: "ISIP 1.5 section 7.5 (claims)" })
  claims: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

  @term(#{ cite: "MS-ADFSPIP (Microsoft claims)" })
  microsoftClaims: "http://schemas.microsoft.com/ws/2008/06/identity/claims";

  /** The RoleDescriptor's `xsi:type`. */
  @term(#{ cite: "XML Schema Part 1 section 3.2.7 (xsi:)" })
  schemaInstance: "http://www.w3.org/2001/XMLSchema-instance";
}

/**
 * The claim types a sign-in carries and the metadata offers, in that order.
 * A description is what a realm that invents no value (product) emits;
 * `invented` is development's, where it differs (2026-09-12: a signed
 * document describing fake values a product deployment never issues is a
 * signed falsehood).
 */
@vocabulary(#{ id: "wsfed.claim",
               cite: "WS-Federation 1.2 section 9.3 (auth:ClaimType)" })
model Claims {
  @term(#{ cite: "ISIP 1.5 section 7.5", display: "Name ID",
           description: "The subject identifier this service minted." })
  nameidentifier: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

  @term(#{ cite: "ISIP 1.5 section 7.5", display: "Name",
           description: "The username typed at the sign-in screen." })
  name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";

  @term(#{ cite: "ISIP 1.5 section 7.5", display: "Given name",
           description: "The givenName on the person's directory entry; omitted when it has none.",
           invented: "Made up from the username." })
  givenname: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";

  @term(#{ cite: "ISIP 1.5 section 7.5", display: "Surname",
           description: "The sn on the person's directory entry; omitted when it has none.",
           invented: "Always \"Mock\"." })
  surname: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";

  @term(#{ cite: "ISIP 1.5 section 7.5", display: "E-mail address",
           description: "The mail on the person's directory entry; omitted when it has none.",
           invented: "username@sts.example." })
  emailaddress: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";

  /** The same string as the mail address: one address is minted. */
  @term(#{ cite: "ISIP 1.5 section 7.5", display: "UPN",
           description: "The same string as the mail address; omitted when there is none.",
           invented: "The same string as the mail address." })
  upn: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";

  @term(#{ cite: "MS-ADFSPIP (Microsoft claims)",
           display: "Authentication method",
           description: "What the browser session actually did: a password, a security key, multiple factors, a TLS client certificate, a Kerberos ticket, what a federation partner asserted, or unspecified when it was none of those." })
  authenticationmethod: "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod";

  @term(#{ cite: "MS-ADFSPIP (Microsoft claims)",
           display: "Authentication instant",
           description: "When that session authenticated." })
  authenticationinstant: "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant";
}

// ---------------------------------------------------------------------------
// THE SIGN-IN RESPONSE.
// ---------------------------------------------------------------------------

/** 1.3's wrapper; a 2005/02 response is the RSTR itself. */
@message(#{ id: "wsfed.RequestSecurityTokenResponseCollection",
            element: "RequestSecurityTokenResponseCollection",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Federation 1.2 section 13.2.2; WS-Trust 1.3 section 3.2" })
model ResponseCollection {
  @element(#{ xml: "RequestSecurityTokenResponse", occurs: "one",
              cite: "WS-Federation 1.2 section 13.2.2" })
  response: Response;
}

/**
 * The RSTR in `wresult`, unsigned (the assertion inside is signed), its
 * children in AD FS's order — a relying party built on a generated parser
 * was written against this one.
 */
@message(#{ id: "wsfed.RequestSecurityTokenResponse",
            element: "RequestSecurityTokenResponse",
            namespaces: "wst.namespace", direction: "write",
            cite: "WS-Federation 1.2 section 13.2.2 (the order is AD FS's)" })
model Response {
  @element(#{ xml: "Lifetime", occurs: "one",
              cite: "WS-Trust 1.3 section 4.4" })
  lifetime: IyaSts.WsTrust.Lifetime;

  @element(#{ xml: "AppliesTo", occurs: "optional",
              cite: "WS-Trust 1.3 section 4.4" })
  appliesTo?: IyaSts.Soap.AppliesTo;

  @element(#{ xml: "RequestedSecurityToken", occurs: "one",
              cite: "WS-Trust 1.3 section 4.4" })
  requestedSecurityToken: IyaSts.WsTrust.RequestedSecurityToken;

  @element(#{ xml: "TokenType", occurs: "one",
              cite: "WS-Trust 1.3 section 4.4" })
  tokenType: string;

  @element(#{ xml: "RequestType", occurs: "one",
              cite: "WS-Trust 1.3 section 3.1" })
  requestType: string;

  @element(#{ xml: "KeyType", occurs: "one",
              cite: "WS-Trust 1.3 section 4.4" })
  keyType: string;
}

// ---------------------------------------------------------------------------
// THE ROLE IN THE REALM'S METADATA (#524): ONE ENTITY, TWO VIEWS.
// ---------------------------------------------------------------------------

/**
 * The security token service's role, `md:`-prefixed with its own namespaces
 * on itself; `saml2_sso.metadataFor()` puts it first among the roles of the
 * WS-Federation view and signs the document.
 */
@message(#{ id: "wsfed.RoleDescriptor", element: "RoleDescriptor",
            xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
            direction: "write",
            cite: "WS-Federation 1.2 section 3.1.2 (SecurityTokenServiceType)" })
model RoleDescriptor {
  @attribute(#{ xml: "xsi:type", fixed: "fed:SecurityTokenServiceType",
                cite: "WS-Federation 1.2 section 3.1.2" })
  type: string;

  /** The federation namespace and 2005/02's trust namespace. */
  @attribute(#{ xml: "protocolSupportEnumeration",
                cite: "saml-metadata-2.0-os section 2.4.1" })
  protocolSupportEnumeration: string;

  /** One per live generation of the XML signing key (#42). */
  @element(#{ xml: "KeyDescriptor", occurs: "many",
              cite: "saml-metadata-2.0-os section 2.4.1.1" })
  keyDescriptor?: string;

  @element(#{ xml: "TokenTypesOffered", occurs: "optional",
              cite: "WS-Federation 1.2 section 3.1.6" })
  tokenTypesOffered?: TokenTypesOffered;

  @element(#{ xml: "ClaimTypesOffered", occurs: "optional",
              cite: "WS-Federation 1.2 section 3.1.8" })
  claimTypesOffered?: ClaimTypesOffered;

  @element(#{ xml: "SecurityTokenServiceEndpoint", occurs: "many",
              cite: "WS-Federation 1.2 section 3.1.2" })
  securityTokenServiceEndpoint: Endpoint;

  @element(#{ xml: "PassiveRequestorEndpoint", occurs: "many",
              cite: "WS-Federation 1.2 section 3.1.2" })
  passiveRequestorEndpoint?: PassiveEndpoint;
}

@message(#{ id: "wsfed.TokenTypesOffered", element: "TokenTypesOffered",
            xmlns: "http://docs.oasis-open.org/wsfed/federation/200706",
            direction: "write", cite: "WS-Federation 1.2 section 3.1.6" })
model TokenTypesOffered {
  @element(#{ xml: "TokenType", occurs: "many",
              cite: "WS-Federation 1.2 section 3.1.6" })
  tokenType: TokenTypeOffered;
}

@message(#{ id: "wsfed.TokenType", element: "TokenType",
            xmlns: "http://docs.oasis-open.org/wsfed/federation/200706",
            direction: "write", cite: "WS-Federation 1.2 section 3.1.6" })
model TokenTypeOffered {
  @attribute(#{ xml: "Uri", cite: "WS-Federation 1.2 section 3.1.6" })
  uri: string;
}

@message(#{ id: "wsfed.ClaimTypesOffered", element: "ClaimTypesOffered",
            xmlns: "http://docs.oasis-open.org/wsfed/federation/200706",
            direction: "write", cite: "WS-Federation 1.2 section 3.1.8" })
model ClaimTypesOffered {
  @element(#{ xml: "ClaimType", occurs: "many",
              cite: "WS-Federation 1.2 section 9.3" })
  claimType: ClaimType;
}

@message(#{ id: "wsfed.ClaimType", element: "ClaimType",
            xmlns: "http://docs.oasis-open.org/wsfed/authorization/200706",
            direction: "write", cite: "WS-Federation 1.2 section 9.3" })
model ClaimType {
  @attribute(#{ xml: "Uri", cite: "WS-Federation 1.2 section 9.3" })
  uri: string;

  /** Every claim here is optional: an absent fact is omitted. */
  @attribute(#{ xml: "Optional", fixed: "true",
                cite: "WS-Federation 1.2 section 9.3" })
  optional: string;

  @element(#{ xml: "DisplayName", occurs: "optional",
              cite: "WS-Federation 1.2 section 9.3" })
  displayName?: string;

  @element(#{ xml: "Description", occurs: "optional",
              cite: "WS-Federation 1.2 section 9.3" })
  description?: string;
}

/** The WS-Trust STS at `/sts`. */
@message(#{ id: "wsfed.SecurityTokenServiceEndpoint",
            element: "SecurityTokenServiceEndpoint",
            xmlns: "http://docs.oasis-open.org/wsfed/federation/200706",
            direction: "write", cite: "WS-Federation 1.2 section 3.1.2" })
model Endpoint {
  @element(#{ xml: "EndpointReference", occurs: "one",
              cite: "WS-Addressing 1.0 Core section 2.2" })
  endpointReference: IyaSts.Soap.EndpointReference;
}

/** This profile's endpoint at `/wsfed`. */
@message(#{ id: "wsfed.PassiveRequestorEndpoint",
            element: "PassiveRequestorEndpoint",
            xmlns: "http://docs.oasis-open.org/wsfed/federation/200706",
            direction: "write", cite: "WS-Federation 1.2 section 3.1.2" })
model PassiveEndpoint {
  @element(#{ xml: "EndpointReference", occurs: "one",
              cite: "WS-Addressing 1.0 Core section 2.2" })
  endpointReference: IyaSts.Soap.EndpointReference;
}
