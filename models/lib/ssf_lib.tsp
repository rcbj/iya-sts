// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the Shared Signals namespace of the abstract model
// (#1579): SSF 1.0, CAEP 1.0, RISC 1.0, the RFC 8417 Security Event Token
// they travel in, the RFC 9493 subject identifiers they name somebody with,
// and RFC 8935 and RFC 8936 delivery.
//
// An EVENT TYPE is a model whose properties are its payload's members. A
// member's TypeSpec type says its JSON shape — `string`, a number, `boolean`,
// `string[]`, `Record<string>` (a map keyed by a language tag), a
// `Record<unknown>` object, a union of string literals (a closed list) or
// such a union with `string` beside it (a list two parties may extend) — and
// whether it is required (not optional). `@event` says the rest of the row.
//
// A SUBJECT IDENTIFIER FORMAT is a model whose properties are its CLOSED
// member set; `@subjectMember` names the check each value is held to.
//
// A DOCUMENT — the transmitter metadata, a stream configuration, a status,
// a poll, a refusal, the SET's own claims — is a model whose properties are
// its members, each with `@member`'s citation.
//
// A value a decorator takes is closed, so a new fact is added here on
// purpose.

import "./ssf_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.SsfLib;

/** Which specification an event type belongs to. */
alias Family = "ssf" | "caep" | "risc" | "sts";

/** One event type: the row `ssf/ssf_events.js` builds from the model. */
model EventOptions {
  /** The event type URI: the key in a SET's `events`. */
  uri: string;

  family: Family;

  /** Its name, for a page. */
  name: string;

  /**
   * Whether a SET of it names somebody: `none` (it is about the stream or
   * the issuer), `optional` or `required`.
   */
  subject: "none" | "optional" | "required";

  /** The subject formats its specification narrows the subject to. */
  subjectFormats?: string[];

  /** The event type that replaces it, where its specification says so. */
  deprecated?: string;

  /** What it says, for the console and `GET /ssf`. */
  what: string;

  /** The document and section defining it. */
  cite: string;
}

/** What a payload member's TypeSpec type cannot say. */
model EventMemberOptions {
  /** What it carries, for the console and `GET /ssf`. */
  what: string;

  /** The document and section defining it, where not the event's own. */
  cite?: string;
}

/** A set of members several event types share, written once. */
model CommonOptions {
  /** The id the service asks the model for: `caep` or `risc`. */
  id: string;

  cite: string;
}

/** The check a subject member's value is held to, by name. */
alias SubjectCheck = "string" | "acct" | "addrSpec" | "e164" | "did" |
  "absoluteUri" | "issuer" | "jwtIssuer" | "ipAddresses" | "identifiers";

/** One Subject Identifier format. */
model SubjectFormatOptions {
  /** The `format` value. */
  format: string;

  /**
   * A format a PERSON can be named in: a stream's `format`, and what a
   * default subject is composed in.
   */
  person: boolean;

  /** What it identifies, for the console and `GET /ssf`. */
  what: string;

  /** A real value of the format, as JSON, for the page and the tests. */
  example: string;

  cite: string;
}

model SubjectMemberOptions {
  /** `string` (a non-empty string) when not said. */
  check?: SubjectCheck;
}

/** SSF's complex subject: its `format` value and its member names. */
model ComplexOptions {
  format: string;

  /** The grammar an additional member's name must have. */
  memberName: string;

  cite: string;
}

model ComplexMemberOptions {
  what: string;
}

/** A closed list the service keeps by id: the statuses, the credential types. */
model ListOptions {
  id: string;

  cite: string;
}

/** One delivery method of SSF 1.0 section 7.1.1. */
model DeliveryOptions {
  /** Its URN. */
  method: string;

  name: string;

  what: string;

  cite: string;
}

/** A document: the metadata, a configuration, a poll, a refusal, a SET. */
model MembersOptions {
  id: string;

  cite: string;

  /**
   * `closed`: a member the model does not name is a wrong document.
   * `open`: others may appear, and the model holds the ones it names.
   */
  members: "closed" | "open";
}

/** Who supplies a stream configuration's member (SSF 1.0 section 8.1.1). */
alias Supplier = "transmitter" | "receiver";

model MemberOptions {
  cite: string;

  /** A member this service adds that no specification defines. */
  own?: boolean;

  supplier?: Supplier;
}

/** One `err` value: where it is defined. */
model ErrorOptions {
  cite: string;
}

extern dec event(target: Model, options: valueof EventOptions);
extern dec eventMember(target: ModelProperty,
                       options: valueof EventMemberOptions);
extern dec common(target: Model, options: valueof CommonOptions);
extern dec subjectFormat(target: Model, options: valueof SubjectFormatOptions);
extern dec subjectMember(target: ModelProperty,
                         options: valueof SubjectMemberOptions);
extern dec complexSubject(target: Model, options: valueof ComplexOptions);
extern dec complexMember(target: ModelProperty,
                         options: valueof ComplexMemberOptions);
extern dec valueList(target: Union, options: valueof ListOptions);
extern dec delivery(target: Model, options: valueof DeliveryOptions);
extern dec members(target: Model, options: valueof MembersOptions);
extern dec member(target: ModelProperty, options: valueof MemberOptions);
extern dec errorCodes(target: Model);
extern dec errorCode(target: ModelProperty, options: valueof ErrorOptions);
