// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the SAML namespace of the abstract model (#1579), and
// of every other XML protocol it states: WS-Trust 1.0-1.4, the SOAP 1.1 and
// 1.2 envelopes and WS-Federation 1.2 (`models/ws/*.tsp`) are written with
// the same decorators, because a SOAP envelope, an RSTR and a federation
// role are XML messages exactly as a Response is. `saml_lib.mjs` reads each
// family into its own generated file by the ids' prefixes.
//
// XML IS NOT JSON, so nothing here is rendered as a JSON Schema. The
// model states the protocol's messages as FACTS the code reads:
//
// * A VOCABULARY (`@vocabulary`) is a closed list of the values a SAML
//   attribute or element takes — the bindings, the status codes, the NameID
//   formats, the confirmation methods, the authentication context classes,
//   SAML 1.1's QName status codes and its request types. Each property is
//   one term: its name is what the code asks for, its TypeSpec type is the
//   string literal it is on the wire, and `@term` says where it is defined
//   and what this service does with it. A term whose type is ANOTHER
//   vocabulary's property (`password: IyaSts.Saml11.AuthnMethods.password`)
//   is that term, written once: WS-Federation's `wauth` list names SAML's
//   authentication methods this way rather than copying their URIs.
// * A MESSAGE (`@message`) is one XML element: its attributes and its child
//   elements, IN THE ORDER THE SCHEMA'S SEQUENCE HAS THEM, which is the
//   order this service writes them in. A property is an attribute
//   (`@attribute`) or a child element (`@element`). An attribute's TypeSpec
//   type says how it is read: `boolean` is the schema's xs:boolean, read as
//   true for "true" or "1"; anything else is read as its text. An element's
//   type is the message it is, when the model states it, or `string` for
//   one whose text is all that is read.
// * A PARAMETER SET (`@params`) is what a binding or a profile carries
//   beside a message: SAML 1.1's browser profiles, which have no request
//   message, are read entirely from one.
//
// A value a decorator takes is closed, so a new fact is added here on
// purpose.

import "./saml_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.SamlLib;

/** One closed list of values. */
model VocabularyOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining the list. */
  cite: string;

  /**
   * The text every term of the list begins with, where the specification
   * gives one (a reader that recognises the family by it asks for it).
   */
  prefix?: string;

  /**
   * Each term is APPENDED to the namespace of the request it answers: a
   * WS-Trust key type, request type, action or status is the request's
   * trust namespace followed by the term, which begins with '/'.
   */
  relative?: boolean;
}

/** What one term is, and what this service does with it. */
model TermOptions {
  /** The document and section defining the term. */
  cite: string;

  /** A status code's level (saml-core-2.0-os section 3.2.2.2). */
  level?: "top" | "second";

  /** A NameID format this identity provider publishes in its metadata. */
  advertised?: boolean;

  /** A binding a request may arrive on at a SingleSignOnService. */
  request?: boolean;

  /** A binding a Response is delivered on. */
  response?: boolean;

  /** What a binding's message carries beside it, by parameter name. */
  carries?: string[];

  /**
   * An authentication context class read as "a second factor is required"
   * when a RequestedAuthnContext names it.
   */
  mfaDemand?: boolean;

  /**
   * The term of the other SAML version's vocabulary that means the same
   * thing, by name: an authentication context class and a SAML 1.1
   * authentication method.
   */
  equivalent?: string;

  /** A SAML 1.1 request type the responder answers (false: refused). */
  answered?: boolean;

  /** A term this service names nowhere it writes, defined for a reader. */
  readOnly?: boolean;

  /**
   * A `wauth` value (WS-Federation 1.2 section 13.2.1): the demand it is
   * read as.
   */
  wauth?: "password" | "multiFactor" | "hardware";

  /**
   * A token type that asks for the token another term of the same
   * vocabulary names, by name: an older client's spelling of one.
   */
  aliasOf?: string;

  /** The short forms a non-spec parameter may name a token type by. */
  shortForms?: string[];

  /** A token type this identity provider offers in its metadata. */
  offered?: boolean;

  /** A claim type's display name, as the metadata offers it. */
  display?: string;

  /**
   * A claim type's description in a realm that invents no claim value
   * (product), as the metadata offers it.
   */
  description?: string;

  /**
   * A claim type's description in a realm that invents claim values
   * (development), where it differs.
   */
  invented?: string;
}

/** One XML element this service reads or writes. */
model MessageOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining it. */
  cite: string;

  /** The element's local name. */
  element: string;

  /** Its namespace's URI, when it has one. */
  xmlns?: string;

  /**
   * The vocabulary whose terms are the namespaces it may be in, when it is
   * written in the namespace of the request it answers (an RSTR echoes the
   * RST's trust namespace). A message has `xmlns` or `namespaces`.
   */
  namespaces?: string;

  /** Whether this service reads it, writes it, or both. */
  direction: "read" | "write" | "both";
}

/** What an attribute's TypeSpec type cannot say. */
model AttributeOptions {
  /** Its name on the wire. */
  xml: string;

  /** The document and section defining it. */
  cite: string;

  /** The one value this service writes, whatever the caller passes. */
  fixed?: string;

  /** The values a read accepts; another is refused by the code that asks. */
  accepts?: string[];

  /**
   * Read: the reader of this message hands it to the code (false: the
   * schema has it and this service does not act on it).
   */
  read?: boolean;

  /** Written: this service writes it (false: the schema has it, unused). */
  written?: boolean;
}

/** What an element's TypeSpec type cannot say. */
model ElementOptions {
  /** Its local name on the wire. */
  xml: string;

  /** The document and section defining it. */
  cite: string;

  /** How many times the schema allows it here. */
  occurs: "one" | "optional" | "many";

  /**
   * The other local names that may stand in its place (an xs:choice): an
   * EncryptedAssertion for an Assertion, an EncryptedID for a NameID.
   */
  or?: string[];

  /**
   * Written by this service's builder (false: the schema has it here and
   * the builder never writes it — a ds:Signature the signer inserts, an
   * Extensions nothing fills).
   */
  written?: boolean;

  /**
   * Inserted after the builder by the signer, at this place in the
   * sequence: a ds:Signature.
   */
  signer?: boolean;

  /** Read: the reader of this message acts on it. */
  read?: boolean;

  /**
   * Its namespace, where another child of the same local name stands in
   * the same place (a SAML 1.1 and a SAML 2.0 Assertion).
   */
  xmlns?: string;

  /**
   * It holds ANOTHER PARTY'S token, never the requester's credential
   * (WS-Trust's OnBehalfOf, ActAs and the three targets).
   */
  anotherPartys?: boolean;

  /**
   * Read off the WHOLE document, so a signed request is answered only when
   * it is inside the Body the signature covers (WS-Trust's RST, #521).
   */
  inSignedBody?: boolean;
}

/** One set of parameters a binding or a profile carries. */
model ParamsOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining them. */
  cite: string;
}

/** One parameter. */
model ParamOptions {
  /** Its name on the wire. */
  wire: string;

  /** The document and section defining it, or why this service reads it. */
  cite: string;

  /** A parameter no specification defines, read by this service only. */
  nonSpec?: boolean;

  /** The values it may take (compared in lower case); another is refused. */
  accepts?: string[];

  /**
   * What this service does with it: `read` (it acts on it), `recorded`
   * (logged, nothing enforced), `refused` (a request carrying it is
   * refused), `echoed` (handed back unchanged), `written` (this service
   * sends it), `ignored` (the specification defines it and nothing here
   * reads it).
   */
  use?: "read" | "recorded" | "refused" | "echoed" | "written" | "ignored";

  /** The error code a request is refused under for it, where one is. */
  refusedAs?: string;
}

extern dec vocabulary(target: Model, options: valueof VocabularyOptions);
extern dec term(target: ModelProperty, options: valueof TermOptions);
extern dec message(target: Model, options: valueof MessageOptions);
extern dec attribute(target: ModelProperty,
                     options: valueof AttributeOptions);
extern dec element(target: ModelProperty, options: valueof ElementOptions);
extern dec params(target: Model, options: valueof ParamsOptions);
extern dec param(target: ModelProperty, options: valueof ParamOptions);
