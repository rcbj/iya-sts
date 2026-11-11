// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the certificate-enrollment namespace of the abstract
// model (#1579): ACME (RFC 8555 and the extensions this service implements),
// EST (RFC 7030) and SCEP (RFC 8894).
//
// A request a protocol reads as JSON or as a query — an ACME JWS's members,
// its protected header and each resource's payload, EST's nonce request,
// SCEP's query — is a `@body` model whose properties are its members. The
// property's TypeSpec type says whether a member is required (not
// optional), is an array, a boolean, an integer, a literal, a union of
// literals or a nested object (a `@shape` model), and `@field` says the
// rest: the bounds, in the order the check makes them. An answer (ACME's
// resources and problem document, EST's nonce answer) is an `@answer` model
// whose properties are its members. A register the code branches on — the
// error types, the identifier and challenge types, the algorithms, the
// revocation reasons, the media types, the capabilities, the message types,
// pkiStatus and failInfo — is a `@register` model whose properties are its
// rows, in order, each `@term`. The operations of EST and SCEP are an
// `@operations` model whose properties are the operations, each
// `@operation`.
//
// A value a decorator takes is closed, so a new fact is added here on
// purpose.

import "./enrollment_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.EnrollmentLib;

/** The three enrollment protocols. */
alias Family = "acme" | "est" | "scep";

/** A request document: what it is, where it is read and what it allows. */
model BodyOptions {
  /** The id the service asks the model for, within its family. */
  id: string;

  family: Family;

  /**
   * How a member the model does not name is met: `strict` refuses it,
   * `loose` keeps it (RFC 7515 and RFC 8555 say an unknown member is
   * ignored), `strip` drops it.
   */
  others: "strict" | "loose" | "strip";

  /**
   * `json`: a parsed JSON document, whose integer is a JSON number.
   * `query`: a query string, whose integer arrives as text and whose
   * enumeration is `validation.types.oneOf()`.
   */
  input: "json" | "query";

  /** The document and section defining it. */
  cite: string;
}

/** A nested object a member holds. */
model ShapeOptions {
  others: "strict" | "loose" | "strip";

  cite: string;
}

/** What a member's TypeSpec type cannot say. */
model FieldOptions {
  /** A string's (or each string item's) shortest and longest value. */
  minLength?: int32;

  maxLength?: int32;

  /** A string's pattern, and the sentence a value that misses it gets. */
  pattern?: string;

  patternMessage?: string;

  /** An integer's bounds. */
  minimum?: int32;

  maximum?: int32;

  /** An array's fewest and most items. */
  minItems?: int32;

  maxItems?: int32;

  /**
   * The values a member may take are a register's row names, or with
   * `operations` the family's operation names: that is the one source, and
   * a union of literals here would be a second.
   */
  valuesFrom?: string;

  /**
   * An empty value is no value (`validation.types.opt()`): what a query
   * carries for a parameter given and left empty.
   */
  empty?: boolean;

  /** The document and section defining the member. */
  cite: string;
}

/** An answer: what it is and whether a member it does not name is wrong. */
model AnswerOptions {
  id: string;

  family: Family;

  /**
   * `closed`: a member the model does not name is a wrong answer.
   * `open`: other members may appear, and the model holds the named ones.
   */
  members: "closed" | "open";

  cite: string;
}

/** What an answer member's TypeSpec type cannot say. */
model MemberOptions {
  cite: string;

  /** A member this service adds that no specification defines. */
  own?: boolean;
}

/** A register: rows the code reads and branches on, in order. */
model RegisterOptions {
  id: string;

  family: Family;

  cite: string;
}

/** One row of a register. */
model TermOptions {
  cite: string;

  /** The row's value on the wire, where it is not its name. */
  value?: string;

  /** The row's number: a reason code, a messageType, an HTTP status. */
  code?: int32;

  /** The row's values, where it names several (EST's name types). */
  values?: string[];

  /**
   * EST: a refusal at this status counts against the caller's rate limit;
   * ACME: a problem of this type does.
   */
  counted?: boolean;
}

/** The operations of a protocol. */
model OperationsOptions {
  family: Family;

  cite: string;
}

/** One operation. */
model OpOptions {
  /** The HTTP methods it answers, the first its default. */
  methods: string[];

  cite: string;

  /**
   * Its path under the protocol's base, where the operation is a resource of
   * its own (ACME); `:id` stands for a segment this service minted.
   */
  path?: string;

  /** The media type of the request body it reads, where it reads one. */
  accepts?: string;

  /** The media type of its answer. */
  answers?: string;

  /** Whether a credential is required. */
  authenticated?: boolean;

  /** An operation this service answers only with a refusal, and why. */
  refused?: string;
}

extern dec body(target: Model, options: valueof BodyOptions);
extern dec shape(target: Model, options: valueof ShapeOptions);
extern dec field(target: ModelProperty, options: valueof FieldOptions);
extern dec answer(target: Model, options: valueof AnswerOptions);
extern dec member(target: ModelProperty, options: valueof MemberOptions);
extern dec register(target: Model, options: valueof RegisterOptions);
extern dec term(target: ModelProperty, options: valueof TermOptions);
extern dec operations(target: Model, options: valueof OperationsOptions);
extern dec operation(target: ModelProperty, options: valueof OpOptions);
