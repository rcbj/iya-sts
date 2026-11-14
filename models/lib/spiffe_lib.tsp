// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the SPIFFE namespace of the abstract model (#1579): the
// SPIFFE ID, the trust bundle, the X509-SVID and JWT-SVID formats, the
// Workload API, the SPIRE Server API and the Broker API.
//
// A protobuf message is a model whose properties are its fields: `@message`
// names the message as the vendored `.proto` does, `@field` its number,
// `@oneof` the oneof it belongs to, and the TypeSpec type says the rest (a
// scalar, a message, an enum, `T[]` for `repeated`, `Record<T>` for a map).
// Every field is optional, because proto3 has no required field; what this
// service REFUSES a request for is `@refuse`, with the gRPC status, the error
// code and the sentence. A service is an interface (`@grpcService`, with the
// statuses every method of the surface may answer), a method an operation
// (`@rpc`, with how it streams, the statuses its own handler adds, and why
// it answers UNIMPLEMENTED where it does). The build holds every message,
// field, number, type, enum and method to the vendored protos.
//
// The facts no message carries — the SPIFFE ID grammar, an X509-SVID's leaf
// rules, a bundle's and a JWT-SVID's members and the registries they draw
// from — are `@idGrammar`, `@svidRules`, `@members` and `@registry`. A value
// a decorator takes is closed, so a new fact is added here on purpose.

import "./spiffe_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.SpiffeLib;

/** A gRPC status, by grpc-js's name (`google.rpc.Code`). */
alias Status = "OK" | "CANCELLED" | "UNKNOWN" | "INVALID_ARGUMENT" |
  "DEADLINE_EXCEEDED" | "NOT_FOUND" | "ALREADY_EXISTS" | "PERMISSION_DENIED" |
  "RESOURCE_EXHAUSTED" | "FAILED_PRECONDITION" | "ABORTED" | "OUT_OF_RANGE" |
  "UNIMPLEMENTED" | "INTERNAL" | "UNAVAILABLE" | "DATA_LOSS" |
  "UNAUTHENTICATED";

/** One service of the vendored protos. */
model ServiceOptions {
  /** Its full name in the `.proto`, without the leading dot. */
  name: string;

  /**
   * The surface `spiffe/spiffe_grpc.ts` registers its methods on: the
   * Workload API, the SPIRE Server API or the Broker API.
   */
  surface: "workload" | "server" | "broker";

  /**
   * The statuses every method of the surface may answer before or around
   * its handler: the wrapper's refusals (a missing security header, a
   * caller the authorization table or the access policy refuses, a surface
   * turned off) and a defect's UNKNOWN.
   */
  statuses: Status[];

  /** The document defining it. */
  cite: string;
}

/** One method. */
model RpcOptions {
  /** `unary`, a server stream, or a bidirectional stream. */
  stream: "unary" | "server" | "bidi";

  /** The statuses this method's own handler answers, beside the surface's. */
  statuses?: Status[];

  /**
   * Why this service answers the method UNIMPLEMENTED, published on
   * `GET /spiffe` and the console. Unsaid, the method is implemented.
   */
  unimplemented?: string;
}

/** A refusal of a request field. */
model RefuseOptions {
  /**
   * When: `empty` — absent, or empty once the handler has read it (each
   * method trims and drops blank values as it always did, and hands the
   * check what is left); `malformed` — not a SPIFFE ID by `@idGrammar`;
   * `unexpected` — present where the conversation does not expect it.
   */
  when: "empty" | "malformed" | "unexpected";

  status: Status;

  /** The STS error code the call is marked with. */
  code: string;

  /**
   * The status's details. `{reason}` is replaced by the grammar's sentence
   * for a `malformed` value.
   */
  message: string;

  /**
   * The method whose request this is, where one message is shared by
   * several methods and each refuses it in its own words.
   */
  method?: string;

  /**
   * The `google.rpc.ErrorInfo` reason carried in `grpc-status-details-bin`,
   * where the specification asks for one (SPIFFE Broker Endpoint section
   * 4.8).
   */
  errorInfo?: string;

  /** The document requiring it, or this service where none does. */
  cite: string;
}

/** The SPIFFE ID grammar (SPIFFE-ID section 2). */
model GrammarOptions {
  scheme: string;

  /** The longest SPIFFE ID, in bytes (section 2.3). */
  maxBytes: int32;

  /** The longest trust domain name, in bytes (section 2.1). */
  maxTrustDomainBytes: int32;

  /** A trust domain name's characters (section 2.1). */
  trustDomainPattern: string;

  /** A path segment's characters (section 2.2). */
  pathSegmentPattern: string;

  /**
   * The path prefix SPIRE keeps for its own identities: an agent's and the
   * server's. A registration entry may not name one.
   */
  reservedPrefix: string;

  cite: string;
}

/** One rule an X509-SVID leaf is held to. */
model SvidRule {
  /** The fact of the certificate it reads. */
  fact: "ca" | "keyUsage";

  /** `ca`: the value the leaf must have. */
  equals?: boolean;

  /** `keyUsage`: a usage the leaf must name. */
  includes?: string;

  /** `keyUsage`: usages the leaf must name none of. */
  excludes?: string[];

  /** The clause of the refusal, after "not a leaf X509-SVID: ". */
  problem: string;
}

/** An X509-SVID's leaf rules (X509-SVID section 4.3). */
model SvidRulesOptions {
  leaf: SvidRule[];
  cite: string;
}

/** A document of members: a bundle, a JWK, a JWT-SVID's claims. */
model MembersOptions {
  id: string;
  cite: string;

  /** `closed`: a member the model does not name is a wrong answer. */
  members: "closed" | "open";
}

model MemberOptions {
  cite: string;

  /** A member this service adds that no specification defines. */
  own?: boolean;
}

/** A list of values the service branches on. */
model RegistryOptions {
  id: string;
  cite: string;
}

extern dec grpcService(target: Interface, options: valueof ServiceOptions);
extern dec rpc(target: Operation, options: valueof RpcOptions);
extern dec message(target: Model, name: valueof string);
extern dec field(target: ModelProperty, num: valueof int32);
extern dec oneof(target: ModelProperty, name: valueof string);
extern dec protoEnum(target: Enum, name: valueof string);
extern dec refuse(target: ModelProperty, options: valueof RefuseOptions);
extern dec idGrammar(target: Model, options: valueof GrammarOptions);
extern dec svidRules(target: Model, options: valueof SvidRulesOptions);
extern dec members(target: Model, options: valueof MembersOptions);
extern dec member(target: ModelProperty, options: valueof MemberOptions);
extern dec registry(target: Union, options: valueof RegistryOptions);
