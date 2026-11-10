// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the SAML namespace of the abstract model (#1579).
//
// SAML IS XML, NOT JSON, so nothing here is rendered as a JSON Schema. The
// model states the protocol's messages as FACTS the code reads:
//
// * A VOCABULARY (`@vocabulary`) is a closed list of the values a SAML
//   attribute or element takes — the bindings, the status codes, the NameID
//   formats, the confirmation methods, the authentication context classes,
//   SAML 1.1's QName status codes and its request types. Each property is
//   one term: its name is what the code asks for, its TypeSpec type is the
//   string literal it is on the wire, and `@term` says where it is defined
//   and what this service does with it.
// * A MESSAGE (`@message`) is one XML element: its attributes and its child
//   elements, IN THE ORDER THE SCHEMA'S SEQUENCE HAS THEM, which is the
//   order this service writes them in. A property is an attribute
//   (`@attribute`) or a child element (`@element`). An attribute's TypeSpec
//   type says how it is read: `boolean` is the schema's xs:boolean, read as
//   true only for "true"; anything else is read as its text. An element's
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
}

/** One XML element this service reads or writes. */
model MessageOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining it. */
  cite: string;

  /** The element's local name. */
  element: string;

  /** Its namespace's URI. */
  xmlns: string;

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
}

extern dec vocabulary(target: Model, options: valueof VocabularyOptions);
extern dec term(target: ModelProperty, options: valueof TermOptions);
extern dec message(target: Model, options: valueof MessageOptions);
extern dec attribute(target: ModelProperty,
                     options: valueof AttributeOptions);
extern dec element(target: ModelProperty, options: valueof ElementOptions);
extern dec params(target: Model, options: valueof ParamsOptions);
extern dec param(target: ModelProperty, options: valueof ParamOptions);
