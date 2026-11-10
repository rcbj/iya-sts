// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the GNAP namespace of the abstract model (#1579): RFC
// 9635 and RFC 9767. A document a client instance or a resource server
// sends is a model whose properties are its members; `@shape` says what the
// TypeSpec type cannot — a string's bound and pattern, an array's item cap,
// an object's member cap and whether it is open — and the build renders the
// JSON Schema 2020-12 `gnap/gnap_schemas.ts` compiles. The types a document
// shares are the properties of the one `@definitions` model, in the order of
// its `$defs`. An answer is a model of members, as OAuth's are; a path's
// parameters, a `/gnap-api` act's body and the approval page's query are
// `@params`; the error codes are one model. A value a
// decorator takes is closed, so a new fact is added here on purpose.

import "./gnap_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.GnapLib;

/** `common/validation.js`'s length caps, by name. */
alias Cap = "IDENTIFIER" | "NAME" | "TOKEN" | "URI" | "DEFAULT" | "TEXT" |
  "LARGE";

/** A string's facts, where an array's items or a map's values are strings. */
model StringShape {
  /** The longest value, as a number. */
  maxLength?: int32;

  /** The longest value, as one of the shared caps. */
  cap?: Cap;

  /**
   * The pattern. Without one a string carries the model's: no C0 control
   * character and no DEL, which no member of a GNAP document may carry.
   */
  pattern?: string;

  /** A JSON Schema format: `uri` is RFC 9635's "absolute URI". */
  format?: "uri";
}

/** What a member's, a variant's, a scalar's or an object's type cannot say. */
model Shape {
  maxLength?: int32;
  cap?: Cap;
  pattern?: string;
  format?: "uri";

  /** An array's most items. */
  maxItems?: int32;

  /** An array's items, where they are strings. */
  items?: StringShape;

  /** An object's most members. */
  maxProperties?: int32;

  /**
   * Whether a member the object does not name is allowed: true where RFC
   * 9635 has an extension registry, false where the document is fixed.
   * Unsaid, the schema says nothing.
   */
  open?: boolean;

  /** A map's names. */
  propertyNames?: StringShape;

  /** A map's values. */
  values?: StringShape;

  /** The document and section defining it. */
  cite?: string;
}

/** One request document. */
model DocumentOptions {
  /** The name `gnap_schemas.ts` validates by. */
  name: string;

  /** The schema's `$id`, which a refusal names. */
  schemaId: string;

  /** The document and section defining it. */
  cite: string;
}

/**
 * Parameters checked by `common/validation.js`'s shared types: a path's, a
 * query's, or the body of a `/gnap-api` act.
 */
model ParamsOptions {
  /** The id the service asks the model for. */
  id: string;

  /** Where they arrive. */
  input: "params" | "query" | "body";

  /** A member the model does not name is refused (zod's `strict()`). */
  closed?: boolean;

  cite: string;
}

/**
 * What a parameter's TypeSpec type cannot say. Its type says the rest: a
 * union of string literals is one of those values, an array repeats.
 */
model ParamOptions {
  /**
   * The shared type of `common/validation.js` it is checked as; none where
   * its type is a union of string literals.
   */
  kind?: "identifier" | "base64url" | "token" | "text";

  /** An empty value is no value (`validation.types.opt()`). */
  empty?: boolean;

  cite: string;
}

/** An answer, a discovery document, or an object inside one. */
model MembersOptions {
  /** The id the service asks the model for. */
  id: string;

  cite: string;

  /**
   * `closed`: a member the model does not name is a wrong answer. `open`:
   * other members may appear — a person's claims at introspection, a
   * profile's own members — and the model holds the ones it names.
   */
  members: "closed" | "open";
}

/** What a member's TypeSpec type cannot say. */
model MemberOptions {
  cite: string;

  /** A member this service adds that no specification defines. */
  own?: boolean;
}

/** One error code. */
model ErrorOptions {
  cite: string;

  /** A code this service sends that RFC 9635 section 3.6 does not define. */
  own?: boolean;
}

/** A registry the request walk reads. */
model RegistryOptions {
  /** The id the service asks the model for. */
  id: string;

  cite: string;
}

extern dec shape(target: Model | ModelProperty | UnionVariant | Scalar,
  options: valueof Shape);
extern dec document(target: Model, options: valueof DocumentOptions);
extern dec definitions(target: Model);
extern dec params(target: Model, options: valueof ParamsOptions);
extern dec param(target: ModelProperty, options: valueof ParamOptions);
extern dec members(target: Model, options: valueof MembersOptions);
extern dec member(target: ModelProperty, options: valueof MemberOptions);
extern dec registry(target: Union | Model, options: valueof RegistryOptions);
extern dec errorCodes(target: Model);
extern dec errorCode(target: ModelProperty, options: valueof ErrorOptions);
