// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the AuthZEN namespace of the abstract model (#1579).
//
// A REQUEST is a model whose properties are the members of a JSON object
// body, checked in the order they are declared. A property's TypeSpec type
// says what JSON value it is — a model is an object (whose own properties
// are checked the same way), `string`, `string[]`, an integer, a union of
// string literals (the values it may take), `unknown` (anything, read by
// somebody else) or `never` (a member the request must not carry) — and
// whether it must be present (not optional). `@field` says the rest: the
// bounds, the error code and the sentence a refusal carries when the
// request's own sentences do not fit.
//
// AN ANSWER is a model whose properties are its members (`@members`,
// `@member`), as the OAuth namespace states one: `closed` sets name every
// member that may appear, `open` ones the members a specification names.
// The Obligations Profile's registered types are member sets too, marked
// `obligation`. The Access Request and Approval Profile's problem types are
// one model whose properties are the types (`@problemTypes`).
//
// A value a decorator takes is closed, so a new fact is added here on
// purpose.

import "./authzen_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.AuthZenLib;

/**
 * The sentences a request's fields are refused with, by what is wrong. Each
 * is a template: `{path}` is the field's dotted path, `{member}` a member it
 * does not take (cut to 64 characters), `{members}` the members it takes
 * joined by commas, `{membersAnd}` the same with the last joined by "and",
 * `{required}` the required string members' paths joined by "and",
 * `{maxLength}` a string's bound and `{values}` the values it may take.
 */
model Sentences {
  /** An object field carrying a member it does not take. */
  strayMember: string;

  /** A required object field that is absent. */
  absentObject: string;

  /** A required string field absent, null or empty. */
  absentString: string;

  /** A field that must be an object and is not. */
  notObject: string;

  /** A field that must be a bounded string and is not. */
  notString: string;

  /** A field that must be an array and is not. */
  notArray: string;

  /** A field that must be one of its values and is not. */
  notOneOf: string;
}

/** The error codes of each kind of refusal of one request. */
model Codes {
  notObject: string;
  stray: string;
  absent: string;
  type: string;
}

/** One request: its endpoints, and how it is refused. */
model RequestOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining it. */
  cite: string;

  /** The paths it is read at, under a realm's prefix. */
  paths: string[];

  /** The HTTP methods. */
  methods: string[];

  /** The sentence for a body that is not a JSON object. */
  notObject: string;

  /**
   * The sentence for a top-level member the request does not take. Without
   * one the request is OPEN at the top: what it does not name is read by
   * the next reader (a search's body is an evaluation's after its own
   * members are taken off).
   */
  stray?: string;

  codes: Codes;

  sentences: Sentences;
}

/** What a field's TypeSpec type cannot say. */
model FieldOptions {
  /** The document and section defining the field. */
  cite: string;

  /** The error code of every refusal of this field, in place of the kind's. */
  code?: string;

  /**
   * One sentence for every refusal of this field and of anything it holds,
   * in place of the kinds' (`{path}` is the field's own).
   */
  refusal?: string;

  /** The sentence for this required field absent, in place of the kind's. */
  absent?: string;

  /** A string's longest value. */
  maxLength?: int32;

  /** An empty string is refused (a required one: as absent). */
  nonEmpty?: boolean;

  /** An array's most items. */
  maxItems?: int32;

  /**
   * An array whose items are each read alone, as the request a batch item
   * is: an item that is not a JSON object is refused with this sentence,
   * by itself, and the array is not.
   */
  itemRefusal?: string;

  /** The longest string item of an array. */
  itemMaxLength?: int32;

  /** An integer's least value. */
  minimum?: int64;

  /**
   * An object field: refused unless at least one of these members is
   * present and not empty.
   */
  requireOne?: string[];

  /** A field of values: compared as `String(value)`. */
  coerce?: "string";

  /** A field of values: the one meant when the member is absent. */
  default?: string;

  /** An object field whose members it does not name are allowed. */
  open?: boolean;

  /**
   * Declared and not read by the shape pass: the service reads it at its
   * own place in the request's checks, between checks that need state, by
   * asking for this one field (`AuthzenModel.field()`).
   */
  deferred?: boolean;
}

/** An answer, a part of one, or an obligation type. */
model MembersOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining it. */
  cite: string;

  /** As in the OAuth namespace: `closed` names every member. */
  members: "closed" | "open";

  /** One of the Obligations Profile's registered types, named by `id`. */
  obligation?: boolean;
}

/** What a member's TypeSpec type cannot say. */
model MemberOptions {
  cite: string;

  /** A member this service adds that no specification defines. */
  own?: boolean;
}

/** The problem types' common prefix and where they are defined. */
model ProblemTypesOptions {
  prefix: string;
  cite: string;
}

/** One problem type: the title an answer carries for it. */
model ProblemTypeOptions {
  title: string;
  cite: string;
}

extern dec request(target: Model, options: valueof RequestOptions);
extern dec field(target: ModelProperty, options: valueof FieldOptions);
extern dec members(target: Model, options: valueof MembersOptions);
extern dec member(target: ModelProperty, options: valueof MemberOptions);
extern dec problemTypes(target: Model,
                        options: valueof ProblemTypesOptions);
extern dec problemType(target: ModelProperty,
                       options: valueof ProblemTypeOptions);
