// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the OAuth 2.0 and OpenID Connect namespace of the
// abstract model (#1579). An endpoint's request is a model whose properties
// are its parameters; a property's TypeSpec type says whether the parameter
// is required (not optional), may repeat (an array) and is a number (an
// integer type), and `@param` says the rest: the shared type it is checked
// as, its bounds, and the document and section that define it. A discovery
// document, an answer and a claim set are models whose properties are their
// members, each with `@member`'s citation. The error codes are one model
// whose properties are the codes. A value a decorator takes is closed, so a
// new fact is added here on purpose.

import "./oauth_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.OAuthLib;

/** One endpoint's request: where its parameters arrive and how. */
model EndpointOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The paths it answers at, a named authorization server's beside them. */
  paths: string[];

  /** The HTTP methods. */
  methods: string[];

  /** Which input group holds the parameters. */
  input: "query" | "body" | "params";

  /**
   * An undeclared parameter is passed through rather than dropped: the
   * handler forwards the request whole (the authorization request across
   * the consent round trip, the token request into the libraries that read
   * members this model does not name).
   */
  passThrough: boolean;

  /** The document and section defining the endpoint. */
  cite: string;
}

/**
 * The shared type a parameter is checked as, by `common/validation.js`'s
 * name. `string` is a plain bounded string.
 */
alias ParamKind = "string" | "identifier" | "name" | "redirectUri" |
  "scope" | "opaque" | "uri" | "base64url" | "integer";

/** The length caps of `common/validation.js`, by name. */
alias Cap = "IDENTIFIER" | "NAME" | "TOKEN" | "URI" | "SCOPE" | "TEXT";

/** What a parameter's TypeSpec type cannot say. */
model ParamOptions {
  /** `string` when not said. */
  kind?: ParamKind;

  /** A `string` parameter's shortest value. */
  minLength?: int32;

  /** A `string` parameter's longest value, as a number. */
  maxLength?: int32;

  /** A `string` parameter's longest value, as one of the shared caps. */
  cap?: Cap;

  /** A `string` parameter's pattern. */
  pattern?: string;

  /** An `integer` parameter's bounds. */
  minimum?: int32;

  maximum?: int32;

  /**
   * An empty value is no value (`validation.types.opt()`): what an HTML form
   * sends for a control left empty. Without it an empty value must still be
   * well formed.
   */
  empty?: boolean;

  /** The document and section defining the parameter. */
  cite: string;
}

/** A discovery document, an answer or a claim set. */
model MembersOptions {
  /** The id the service asks the model for. */
  id: string;

  /** The document and section defining it. */
  cite: string;

  /**
   * `closed`: a member the model does not name is a wrong answer.
   * `open`: other members may appear — a custom claim an administrator
   * configured, a client's own registration metadata — and the model holds
   * the ones it names.
   */
  members: "closed" | "open";
}

/** What a member's TypeSpec type cannot say. */
model MemberOptions {
  /** The document and section defining the member. */
  cite: string;

  /** A member this service adds that no specification defines. */
  own?: boolean;
}

/** One error code: where it is defined and the endpoints that send it. */
model ErrorOptions {
  cite: string;
}

extern dec endpoint(target: Model, options: valueof EndpointOptions);
extern dec param(target: ModelProperty, options: valueof ParamOptions);
extern dec members(target: Model, options: valueof MembersOptions);
extern dec member(target: ModelProperty, options: valueof MemberOptions);
extern dec errorCodes(target: Model);
extern dec errorCode(target: ModelProperty, options: valueof ErrorOptions);
