// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/authzen/authzen.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT THE AUTHZEN AUTHORIZATION API
// READS: the access evaluation request (AuthZEN Authorization API 1.0
// section 6), the evaluations request (section 7) with its options and
// semantics, the three search requests (section 8), and the Access Request
// and Approval Profile's submission (#1180). `models/tools/generate.mjs`
// compiles it into `models/generated/authzen.json` during the image build,
// and `authzen/authzen_model.ts` builds every reader from that file: the
// hand-written shape checks in `authzen_map.ts`, `authzen.ts`,
// `authzen_search.ts` and `authzen_access_request.ts` are gone.
//
// THE MODEL DESCRIBES AND VALIDATES THE WIRE; IT DOES NOT RESHAPE IT. Every
// field is checked in the order it is declared here, because the order
// decides which refusal a request with two wrong members gets, and every
// sentence below is the one the hand-written reader sent, word for word;
// `tests/authzen_model_wire.js` holds 326 answers to what that version
// said. A change here is a change to what a PEP sees, and owes that
// snapshot.
//
// What needs state stays in the code and reads the generated shape:
// the catalogue's rows (which properties and context members a realm
// declares, and the value rules they impose, `xacml_attribute_rows.ts`),
// the caller's application scope, the batch's two bounds (realm settings),
// a search's page token against the request it continues, a submission's
// binding token, expiry, idempotency and registered callbacks, and the
// token-exchange binding's fixed context. `authzen/CLAUDE.md`, *THE REQUEST
// SHAPES ARE THE MODEL'S*, says where each is.

import "../lib/authzen_lib.tsp";

using IyaSts.AuthZenLib;

namespace IyaSts.AuthZen;

/** The sentences every AuthZEN JSON request's fields are refused with. */
const SENTENCES = #{
  strayMember: "{path} has no member \"{member}\"; it takes {members}.",
  absentObject: "The request has no {path}, which AuthZEN requires ({required}).",
  absentString: "{path} is required, and a non-empty string.",
  notObject: "{path} must be a JSON object.",
  notString: "{path} must be a string of at most {maxLength} characters.",
  notArray: "{path} must be an array.",
  notOneOf: "{path} must be one of {values}."
};

/** The codes of the evaluation family's shape refusals. */
const EVALUATION_CODES = #{
  notObject: "STS-AUTHZEN-0001",
  stray: "STS-AUTHZEN-0009",
  absent: "STS-AUTHZEN-0002",
  type: "STS-AUTHZEN-0003"
};

// ---------------------------------------------------------------------------
// THE ENTITIES (section 5).
// ---------------------------------------------------------------------------

/** Section 5.1. */
model Subject {
  @field(#{ maxLength: 1024, nonEmpty: true,
            cite: "AuthZEN Authorization API 1.0 section 5.1" })
  type: string;

  @field(#{ maxLength: 1024, nonEmpty: true,
            cite: "AuthZEN Authorization API 1.0 section 5.1" })
  id: string;

  /** Read against the realm's catalogue, member by member. */
  @field(#{ open: true, cite: "AuthZEN Authorization API 1.0 section 5.1" })
  properties?: Record<unknown>;
}

/** Section 5.3. */
model Action {
  @field(#{ maxLength: 1024, nonEmpty: true,
            cite: "AuthZEN Authorization API 1.0 section 5.3" })
  name: string;

  @field(#{ open: true, cite: "AuthZEN Authorization API 1.0 section 5.3" })
  properties?: Record<unknown>;
}

/** Section 5.2. */
model Resource {
  @field(#{ maxLength: 1024, nonEmpty: true,
            cite: "AuthZEN Authorization API 1.0 section 5.2" })
  type: string;

  @field(#{ maxLength: 1024, nonEmpty: true,
            cite: "AuthZEN Authorization API 1.0 section 5.2" })
  id: string;

  @field(#{ open: true, cite: "AuthZEN Authorization API 1.0 section 5.2" })
  properties?: Record<unknown>;
}

/** The approval a completed access request returned (#1180). */
model Approval {
  @field(#{ maxLength: 1024, nonEmpty: true,
            cite: "AuthZEN Access Request and Approval Profile, the approval object" })
  id: string;
}

/**
 * Section 5.4. Every member but these three is a realm's, read against its
 * catalogue — so THESE ARE THE RESERVED CONTEXT MEMBERS a catalogue row may
 * never name (`authzen_catalogue.ts`'s `RESERVED_CONTEXT` is this list),
 * declared in the order they are checked.
 */
model Context {
  /** The Obligations Profile's declaration (#1177). */
  @field(#{ maxItems: 32, itemMaxLength: 64,
            refusal: "{path} must be an array of at most 32 obligation type names.",
            cite: "AuthZEN Obligations Profile section 3" })
  supported_obligations?: string[];

  /**
   * Its shape is checked here; whether it is an approval at all is
   * `verify()`'s, against the store.
   */
  @field(#{ open: true,
            refusal: "{path} must be the approval object a completed access request returned, with its id.",
            cite: "AuthZEN Access Request and Approval Profile, re-evaluation" })
  approval?: Approval;

  /** Which of the caller's applications the question is about. */
  @field(#{ maxLength: 1024, nonEmpty: true,
            refusal: "{path} must be a non-empty string naming one of the applications this caller is scoped to.",
            cite: "this service's own (#563, decision 1)" })
  application?: string;
}

// ---------------------------------------------------------------------------
// THE REQUESTS.
// ---------------------------------------------------------------------------

/** Section 6.1: one access evaluation. */
@request(#{
  id: "evaluation",
  cite: "AuthZEN Authorization API 1.0 section 6.1",
  paths: #["/access/v1/evaluation"],
  methods: #["POST"],
  notObject: "An access evaluation request is a JSON object with subject, action, resource and optionally context.",
  stray: "An access evaluation request has no member \"{member}\"; it takes {membersAnd}.",
  codes: EVALUATION_CODES,
  sentences: SENTENCES
})
model EvaluationRequest {
  @field(#{ cite: "AuthZEN Authorization API 1.0 section 6.1" })
  subject: Subject;

  @field(#{ cite: "AuthZEN Authorization API 1.0 section 6.1" })
  action: Action;

  @field(#{ cite: "AuthZEN Authorization API 1.0 section 6.1" })
  resource: Resource;

  @field(#{ open: true, cite: "AuthZEN Authorization API 1.0 section 6.1" })
  context?: Context;
}

/** Section 7.1.2: what an evaluations request does after each item. */
model EvaluationsOptions {
  @field(#{ coerce: "string", default: "execute_all",
            code: "STS-AUTHZEN-0036",
            cite: "AuthZEN Authorization API 1.0 section 7.1.2" })
  evaluations_semantic?: "execute_all" | "deny_on_first_deny" |
    "permit_on_first_permit";
}

/**
 * Section 7.1: several evaluations, the top-level members each item's
 * defaults (overridden per item WHOLE, section 7.1.1). The defaults are
 * read as an evaluation when they are merged into one, so they are not
 * read here.
 */
@request(#{
  id: "evaluations",
  cite: "AuthZEN Authorization API 1.0 section 7.1",
  paths: #["/access/v1/evaluations"],
  methods: #["POST"],
  notObject: "An access evaluations request is a JSON object.",
  stray: "An access evaluations request has no member \"{member}\"; it takes {members}.",
  codes: EVALUATION_CODES,
  sentences: SENTENCES
})
model EvaluationsRequest {
  @field(#{ cite: "AuthZEN Authorization API 1.0 section 7.1.1" })
  subject?: unknown;

  @field(#{ cite: "AuthZEN Authorization API 1.0 section 7.1.1" })
  action?: unknown;

  @field(#{ cite: "AuthZEN Authorization API 1.0 section 7.1.1" })
  resource?: unknown;

  @field(#{ cite: "AuthZEN Authorization API 1.0 section 7.1.1" })
  context?: unknown;

  /**
   * Each item is an evaluation's members; an item that is not an object
   * is refused alone (section 7.2), with `itemRefusal`.
   */
  @field(#{ itemRefusal: "An evaluation is a JSON object.",
            cite: "AuthZEN Authorization API 1.0 section 7.1" })
  evaluations?: unknown[];

  @field(#{ open: true, cite: "AuthZEN Authorization API 1.0 section 7.1.2" })
  options?: EvaluationsOptions;
}

/** Section 8.2: a search's paging. */
model Page {
  @field(#{ cite: "AuthZEN Authorization API 1.0 section 8.2" })
  token?: string;

  @field(#{ minimum: 0, cite: "AuthZEN Authorization API 1.0 section 8.2" })
  limit?: int64;

  @field(#{ open: true, cite: "AuthZEN Authorization API 1.0 section 8.2" })
  properties?: Record<unknown>;
}

/** The searched entity: its type, and no meaningful id (8.4, 8.5). */
model Searched {
  @field(#{ nonEmpty: true, cite: "AuthZEN Authorization API 1.0 section 8.4" })
  type: string;
}

/** What every search's `page` is refused with. */
const PAGE_REFUSAL = "page is an object with token (a string from a previous next_token), limit (a non-negative integer) and properties (an object), each optional.";

/**
 * Section 8.4: which subjects of a type may do this. OPEN: what it does not
 * name is read as an evaluation once `page` is taken off.
 */
@request(#{
  id: "search-subject",
  cite: "AuthZEN Authorization API 1.0 section 8.4",
  paths: #["/access/v1/search/subject"],
  methods: #["POST"],
  notObject: "A search request is a JSON object.",
  codes: EVALUATION_CODES,
  sentences: SENTENCES
})
model SubjectSearchRequest {
  @field(#{ code: "STS-AUTHZEN-0042", refusal: PAGE_REFUSAL,
            cite: "AuthZEN Authorization API 1.0 section 8.2" })
  page?: Page;

  @field(#{ open: true, code: "STS-AUTHZEN-0002",
            refusal: "A subject search names the {path}.type to search, a non-empty string.",
            cite: "AuthZEN Authorization API 1.0 section 8.4" })
  subject: Searched;
}

/** Section 8.5: which resources of a type this subject may act on. */
@request(#{
  id: "search-resource",
  cite: "AuthZEN Authorization API 1.0 section 8.5",
  paths: #["/access/v1/search/resource"],
  methods: #["POST"],
  notObject: "A search request is a JSON object.",
  codes: EVALUATION_CODES,
  sentences: SENTENCES
})
model ResourceSearchRequest {
  @field(#{ code: "STS-AUTHZEN-0042", refusal: PAGE_REFUSAL,
            cite: "AuthZEN Authorization API 1.0 section 8.2" })
  page?: Page;

  @field(#{ open: true, code: "STS-AUTHZEN-0002",
            refusal: "A resource search names the {path}.type to search, a non-empty string.",
            cite: "AuthZEN Authorization API 1.0 section 8.5" })
  resource: Searched;
}

/** Section 8.6: which actions this subject may do on this resource. */
@request(#{
  id: "search-action",
  cite: "AuthZEN Authorization API 1.0 section 8.6",
  paths: #["/access/v1/search/action"],
  methods: #["POST"],
  notObject: "A search request is a JSON object.",
  codes: EVALUATION_CODES,
  sentences: SENTENCES
})
model ActionSearchRequest {
  @field(#{ code: "STS-AUTHZEN-0042", refusal: PAGE_REFUSAL,
            cite: "AuthZEN Authorization API 1.0 section 8.2" })
  page?: Page;

  @field(#{ code: "STS-AUTHZEN-0009",
            refusal: "An Action Search request carries no action member (section 8.6).",
            cite: "AuthZEN Authorization API 1.0 section 8.6" })
  action?: never;
}

// ---------------------------------------------------------------------------
// THE ACCESS REQUEST AND APPROVAL PROFILE (#1180).
// ---------------------------------------------------------------------------

/**
 * The denial a submission is based on. Bound BY VALUE: the token is what is
 * verified, and its members are read as text, so their JSON types are not
 * the shape's.
 */
model Denial {
  @field(#{ cite: "AuthZEN Access Request and Approval Profile, the denial binding" })
  binding_token?: unknown;

  @field(#{ cite: "AuthZEN Access Request and Approval Profile, the denial binding" })
  evaluation_id?: unknown;

  @field(#{ cite: "AuthZEN Access Request and Approval Profile, the denial binding" })
  expires_at?: unknown;

  @field(#{ cite: "AuthZEN Access Request and Approval Profile, the denial binding" })
  reason?: unknown;
}

/** What the PEP asks for beyond the denied tuple. */
model RequestedAccess {
  /** An RFC 3339 instant in the future: read against the clock. */
  @field(#{ deferred: true,
            cite: "AuthZEN Access Request and Approval Profile, requested_access" })
  requested_until?: unknown;

  @field(#{ cite: "AuthZEN Access Request and Approval Profile, requested_access" })
  emergency?: unknown;
}

/** The CALLBACK companion's request member. */
model Callback {
  /** Held to the URLs an administrator registered: read in the code. */
  @field(#{ cite: "AuthZEN Access Request Callback companion profile" })
  endpoint: string;

  /**
   * Any array: a name that is not an event is dropped, never refused. Read
   * after the endpoint is held to the registration.
   */
  @field(#{ deferred: true,
            refusal: "{path} must be an array of event names.",
            cite: "AuthZEN Access Request Callback companion profile" })
  events?: unknown[];

  @field(#{ cite: "AuthZEN Access Request Callback companion profile" })
  state?: unknown;
}

/** The submission: the denied tuple, the denial and what is asked for. */
@request(#{
  id: "access-request",
  cite: "AuthZEN Access Request and Approval Profile, the submission",
  paths: #["/access/v1/access-requests"],
  methods: #["POST"],
  notObject: "An access request is a JSON object with subject, resource, action and denial.",
  stray: "An access request has no member \"{member}\"; it takes {members}.",
  codes: #{
    notObject: "STS-AUTHZEN-0071",
    stray: "STS-AUTHZEN-0071",
    absent: "STS-AUTHZEN-0071",
    type: "STS-AUTHZEN-0071"
  },
  sentences: SENTENCES
})
model AccessRequestSubmission {
  /** BULK's member, which this service does not implement. */
  @field(#{ refusal: "This service does not implement the bulk companion profile; submit one item at a time.",
            cite: "AuthZEN Access Request BULK companion profile" })
  items?: never;

  @field(#{ open: true,
            refusal: "{path} is required, the AuthZEN {path} of the denied evaluation, as a JSON object.",
            cite: "AuthZEN Access Request and Approval Profile, the submission" })
  subject: Record<unknown>;

  @field(#{ open: true,
            refusal: "{path} is required, the AuthZEN {path} of the denied evaluation, as a JSON object.",
            cite: "AuthZEN Access Request and Approval Profile, the submission" })
  resource: Record<unknown>;

  @field(#{ open: true,
            refusal: "{path} is required, the AuthZEN {path} of the denied evaluation, as a JSON object.",
            cite: "AuthZEN Access Request and Approval Profile, the submission" })
  action: Record<unknown>;

  @field(#{ cite: "AuthZEN Access Request and Approval Profile, the submission" })
  context?: unknown;

  @field(#{ deferred: true, open: true, code: "STS-AUTHZEN-0072",
            requireOne: #["binding_token", "evaluation_id"],
            refusal: "The request carries no denial with the binding_token of a requestable denial, so it is not based on one.",
            cite: "AuthZEN Access Request and Approval Profile, the denial binding" })
  denial: Denial;

  @field(#{ deferred: true, open: true, code: "STS-AUTHZEN-0096",
            cite: "AuthZEN Access Request and Approval Profile, requested_access" })
  requested_access?: RequestedAccess;

  @field(#{ cite: "AuthZEN Access Request and Approval Profile, client" })
  client?: unknown;

  @field(#{ deferred: true, open: true, code: "STS-AUTHZEN-0079",
            refusal: "{path} must be a JSON object with an endpoint.",
            cite: "AuthZEN Access Request Callback companion profile" })
  callback?: Callback;
}
