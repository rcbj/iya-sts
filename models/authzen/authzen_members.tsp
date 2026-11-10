// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/authzen/authzen_members.tsp
//
// Written by hand (#1579). THE MEMBERS OF WHAT THE AUTHZEN AUTHORIZATION
// API ANSWERS: the PDP metadata document (section 9), an evaluation's
// answer and its Decision Context, the evaluations answer (section 7.2),
// a search's answer and page (section 8.3), the error object this API's
// refusals take, the Obligations Profile's obligation and its registered
// types, and the Access Request and Approval Profile's task, its status
// answer, the callback it sends, and its problem types (RFC 9457).
//
// A `closed` set is every member that may appear: `authzen/authzen.ts` and
// `authzen_access_request.ts` hold every answer to it as it is sent, and a
// member the model does not name, a wrong type or a missing required member
// is recorded under STS-AUTHZEN-0116 — the answer is sent unchanged, because
// the model describes the wire and does not reshape it. An `open` set names
// the members a specification defines; the Decision Context is one, since a
// realm's policy advice reaches it.

import "../lib/authzen_lib.tsp";

using IyaSts.AuthZenLib;

namespace IyaSts.AuthZen;

// ---------------------------------------------------------------------------
// THE METADATA (section 9). Every member in any realm, with every switch
// on: each appears only while what it names answers.
// ---------------------------------------------------------------------------

/** Section 9.1, at /.well-known/authzen-configuration. */
@members(#{ id: "metadata", cite: "AuthZEN Authorization API 1.0 section 9.1", members: "closed" })
model PdpMetadata {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  policy_decision_point: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  access_evaluation_endpoint: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  access_evaluations_endpoint?: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  search_subject_endpoint?: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  search_resource_endpoint?: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  search_action_endpoint?: string;

  @member(#{ cite: "AuthZEN Obligations Profile section 6" })
  supported_obligations?: string[];

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, PDP metadata" })
  access_request_endpoint?: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, PDP metadata" })
  jwks_uri?: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  capabilities?: string[];

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 9.1" })
  signed_metadata?: string;
}

// ---------------------------------------------------------------------------
// AN EVALUATION'S ANSWER (sections 6.2, 7.2).
// ---------------------------------------------------------------------------

/** Section 6.2; each item of section 7.2's answer is one too. */
@members(#{ id: "evaluation-response", cite: "AuthZEN Authorization API 1.0 section 6.2", members: "closed" })
model EvaluationResponse {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 6.2" })
  decision: boolean;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 6.2.1" })
  context?: DecisionContext;
}

/**
 * Section 6.2.1's Decision Context: what this service puts there, each
 * only when what it names happened.
 */
@members(#{ id: "decision-context", cite: "AuthZEN Authorization API 1.0 section 6.2.1", members: "open" })
model DecisionContext {
  /** `authzen.returnReasons` (#1161). */
  @member(#{ cite: "this service's own (#1161)", own: true })
  xacml_decision?: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 6.2.1" })
  reason_admin?: Record<string>;

  @member(#{ cite: "this service's own (#1161)", own: true })
  undischargeable_obligations?: string[];

  @member(#{ cite: "this service's own (#1161)", own: true })
  advice?: Record<unknown>[];

  @member(#{ cite: "AuthZEN Obligations Profile section 2" })
  obligations?: Obligation[];

  /** A batch item that could not be evaluated (section 7.2's example). */
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 7.2" })
  error?: ErrorDetail;

  /** A search answer that is partial (#1175). */
  @member(#{ cite: "this service's own (#1175)", own: true })
  incomplete?: boolean;

  /** The Token Issuance Profile's envelope (#1181). */
  @member(#{ cite: "AuthZEN Token Issuance Profile, context.issuance" })
  issuance?: Record<unknown>;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, requestable denial" })
  evaluation_id?: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, requestable denial" })
  evaluated_at?: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, requestable denial" })
  reason?: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, requestable denial" })
  access_request?: Record<unknown>;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, re-evaluation" })
  next_action?: "request" | "none";

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, re-evaluation" })
  approval?: Record<unknown>;
}

/** Section 7.2. */
@members(#{ id: "evaluations-response", cite: "AuthZEN Authorization API 1.0 section 7.2", members: "closed" })
model EvaluationsResponse {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 7.2" })
  evaluations: EvaluationResponse[];
}

/** One obligation handed to the PEP (the Obligations Profile, section 2). */
@members(#{ id: "obligation", cite: "AuthZEN Obligations Profile section 2", members: "closed" })
model Obligation {
  @member(#{ cite: "AuthZEN Obligations Profile section 2" })
  id: string;

  @member(#{ cite: "AuthZEN Obligations Profile section 2" })
  type: string;

  @member(#{ cite: "AuthZEN Obligations Profile section 2" })
  properties: Record<unknown>;
}

// THE OBLIGATIONS PROFILE'S REGISTERED TYPES (its section 5), in the order
// the metadata lists them. A required member is what a registered
// obligation may not be handed without; an array member collects every
// assignment of its name. `custom` is every other obligation.

/** Section 5.1. */
@members(#{ id: "step-up", obligation: true, cite: "AuthZEN Obligations Profile section 5.1", members: "open" })
model StepUpObligation {
  @member(#{ cite: "AuthZEN Obligations Profile section 5.1" })
  acr_value: string;

  @member(#{ cite: "AuthZEN Obligations Profile section 5.1" })
  amr_values?: string[];
}

/** Section 5.2. */
@members(#{ id: "notification", obligation: true, cite: "AuthZEN Obligations Profile section 5.2", members: "open" })
model NotificationObligation {
  @member(#{ cite: "AuthZEN Obligations Profile section 5.2" })
  to: string[];

  @member(#{ cite: "AuthZEN Obligations Profile section 5.2" })
  body: string;
}

/** Section 5.3. */
@members(#{ id: "session_termination", obligation: true, cite: "AuthZEN Obligations Profile section 5.3", members: "open" })
model SessionTerminationObligation {
  @member(#{ cite: "AuthZEN Obligations Profile section 5.3" })
  subject: string;
}

// ---------------------------------------------------------------------------
// A SEARCH'S ANSWER (section 8.3).
// ---------------------------------------------------------------------------

/** Section 8.3: the page first, as it RECOMMENDS. */
@members(#{ id: "search-response", cite: "AuthZEN Authorization API 1.0 section 8.3", members: "closed" })
model SearchResponse {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 8.3" })
  page: SearchPage;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 8.3" })
  results: Record<unknown>[];

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 8.3" })
  context?: DecisionContext;
}

/** Section 8.2. */
@members(#{ id: "search-page", cite: "AuthZEN Authorization API 1.0 section 8.2", members: "closed" })
model SearchPage {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 8.2" })
  next_token: string;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 8.2" })
  count: int32;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 8.2" })
  total: int32;
}

// ---------------------------------------------------------------------------
// THE ERRORS. Section 10 leaves the body of an error to the PDP; this API's
// is section 7.2's per-item `context.error`, at the top level too.
// ---------------------------------------------------------------------------

/** Every refusal of the evaluation, batch and search endpoints. */
@members(#{ id: "error", cite: "AuthZEN Authorization API 1.0 section 7.2", members: "closed" })
model ErrorResponse {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 7.2" })
  error: ErrorDetail;
}

/** The error object, as a batch item's `context.error` carries it too. */
@members(#{ id: "error-detail", cite: "AuthZEN Authorization API 1.0 section 7.2", members: "closed" })
model ErrorDetail {
  @member(#{ cite: "AuthZEN Authorization API 1.0 section 7.2" })
  status: int32;

  @member(#{ cite: "AuthZEN Authorization API 1.0 section 7.2" })
  message: string;
}

// ---------------------------------------------------------------------------
// THE ACCESS REQUEST AND APPROVAL PROFILE (#1180).
// ---------------------------------------------------------------------------

/** RFC 9457, which every refusal of the profile's endpoints is. */
@members(#{ id: "problem", cite: "RFC 9457 section 3.1", members: "closed" })
model Problem {
  @member(#{ cite: "RFC 9457 section 3.1.1" })
  type: string;

  @member(#{ cite: "RFC 9457 section 3.1.3" })
  title: string;

  @member(#{ cite: "RFC 9457 section 3.1.2" })
  status: int32;

  @member(#{ cite: "RFC 9457 section 3.1.4" })
  detail: string;
}

/**
 * The profile's problem types. A refusal with none is `about:blank`,
 * titled by its status.
 */
@problemTypes(#{ prefix: "urn:openid:authzen:access-request:error:", cite: "AuthZEN Access Request and Approval Profile, error responses" })
model ProblemTypes {
  @problemType(#{ title: "Access is not requestable", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  not_requestable: string;

  @problemType(#{ title: "The requestable denial has expired", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  expired_denial: string;

  @problemType(#{ title: "The request cannot be bound to the denial", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  invalid_denial_binding: string;

  @problemType(#{ title: "The Idempotency-Key was used for another request", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  duplicate_request: string;

  @problemType(#{ title: "There is no such task", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  unknown_task: string;

  @problemType(#{ title: "The task has expired", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  task_expired: string;

  @problemType(#{ title: "The task is not in a state that allows this", cite: "AuthZEN Access Request and Approval Profile, error responses" })
  invalid_task_state: string;
}

/** The submission's, the status endpoint's and the cancellation's answer. */
@members(#{ id: "task-response", cite: "AuthZEN Access Request and Approval Profile, the task", members: "closed" })
model TaskResponse {
  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  task: TaskHandle;

  /** REQUIRED once the task is approved: `mode: reevaluate`. */
  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the result" })
  result?: Record<unknown>;
}

/**
 * The Task Handle: never the approver, the policy or the tuple. `status`'s
 * values are the lifecycle, the first the only one that is not terminal,
 * and the terminal ones are the CALLBACK companion's event names.
 */
@members(#{ id: "task-handle", cite: "AuthZEN Access Request and Approval Profile, the task", members: "closed" })
model TaskHandle {
  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  id: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  status: "pending" | "approved" | "denied" | "expired" | "cancelled" |
    "failed";

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  status_endpoint: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  expires_at: string;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  links?: Record<string>;

  @member(#{ cite: "AuthZEN Access Request and Approval Profile, the task" })
  progress?: Record<unknown>;
}

/** What a registered callback is sent, once. */
@members(#{ id: "callback-notification", cite: "AuthZEN Access Request Callback companion profile", members: "closed" })
model CallbackNotification {
  @member(#{ cite: "AuthZEN Access Request Callback companion profile" })
  task: TaskHandle;

  @member(#{ cite: "AuthZEN Access Request Callback companion profile" })
  state?: string;
}
