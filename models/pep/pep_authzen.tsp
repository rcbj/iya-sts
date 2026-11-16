// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/pep/pep_authzen.tsp
//
// Written by hand (#1830). THE SOURCE OF THE REMOTE PEP AUTHZEN OPENAPI
// DOCUMENT (`xacml-pep/openapi/pep-authzen.json`): the AuthZEN edge PDP
// (#1179) that `rust/bins/xacml-pep/src/authzen.rs` answers on the PEP's API
// listeners — the access evaluation, the batch, and the metadata. The
// service's own AuthZEN API is `models/authzen/`, a validation model of the
// requests it reads; this is the edge's WIRE, and it differs from the
// service's where the edge does (`xacml-pep/CLAUDE.md`, *THE AUTHZEN EDGE
// PDP*), each said where it is declared:
//
// * no search endpoints and no Access Request profile: those paths are the
//   PEP's generic 404;
// * the metadata names only the PDP and the two evaluation endpoints, and is
//   404 when the PEP cannot name its own origin;
// * Content-Type is not read, so there is no 415;
// * `context.application` is the only reserved context member: every other
//   one is a catalogue property or refused (STS-AUTHZEN-0004);
// * a forwarded evaluation (an application enforcing fine-grained
//   authorization, #564 P7) passes the service's `context` through whole, so
//   `DecisionContext` is open;
// * the batch with no items answers the single shape.
//
// UNKNOWN MEMBERS ARE IGNORED (AuthZEN 1.0 section 10.1.1), so every request
// object is open; `properties` and `context` are open by design, their
// members decided by the realm's pulled attribute catalogue.

import "../lib/api_lib.tsp";

using IyaSts.ApiLib;

@apiDocument(#{
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS remote PEP AuthZEN edge PDP",
    `version`:"1",
    `description`:"AuthZEN Authorization API 1.0's access evaluation, evaluations and metadata, answered by a remote PEP from the policy and attribute catalogue it pulled from its realm, so that a PEP nearby can ask a PDP nearby. A caller is admitted by a client certificate (mutual TLS) on the HTTPS listener, verified against PEP_AUTHZEN_CLIENT_CA and named on the caller list the PEP pulls from the service (GET /xacml/pep/authzen-callers), optionally narrowed by PEP_AUTHZEN_CALLERS. The metadata admits anybody. Every answer is application/json with Cache-Control: no-store; a POST's answer echoes a valid X-Request-ID. Error codes are recorded in the PEP's log and never sent. Paths not listed, the search and access-request endpoints among them, are 404 with the PEP's NotFound body."
  },
  `servers`:#[
    #{`url`:"https://localhost:9443",`description`:"The HTTPS listener, PEP_HTTPS_PORT, or an HTTPS listener of purpose api the service defines."}
  ],
  `components`:#{
    `securitySchemes`:#{
      `mutualTLS`:#{
        `type`:"mutualTLS",
        `description`:"A client certificate verified against PEP_AUTHZEN_CLIENT_CA whose SHA-256 is on a pulled caller's certificates, the caller's endpoints naming this endpoint. Refusals: 401 none configured (STS-XPEP-0039), none presented or plain HTTP (0035), did not verify (0036), the realm's caller door is not mtls (0052); 403 not on the pulled list (0051), endpoint not admitted (0053), not on PEP_AUTHZEN_CALLERS (0054, or 0037 before the first pull); 503 no list pulled and none configured (0050). No WWW-Authenticate."
      }
    }
  },
  `x-iya-doc`:"pepAuthzen"
})
namespace IyaSts.Pep.Authzen {

@component model `ErrorDetail` {
  @js(#{`description`:"The HTTP status again."}) `status`: int64;
  `message`: string;
}

@component model `Error` {
  `error`: `ErrorDetail`;
}

@component model `NotFound` {
  `error`: "not_found";
  `error_description`?: string;
}

@js(#{`$apTrue`:true,`description`:"Unknown members are ignored."})
@component model `Subject` {
  @js(#{`minLength`:1,`maxLength`:1024}) `type`: string;
  @js(#{`minLength`:1,`maxLength`:1024}) `id`: string;
  `properties`?: `Properties`;
}

@js(#{`$apTrue`:true,`description`:"Unknown members are ignored."})
@component model `Resource` {
  @js(#{`minLength`:1,`maxLength`:1024}) `type`: string;
  @js(#{`minLength`:1,`maxLength`:1024}) `id`: string;
  `properties`?: `Properties`;
}

@js(#{`$apTrue`:true,`description`:"Unknown members are ignored."})
@component model `Action` {
  @js(#{`minLength`:1,`maxLength`:1024}) `name`: string;
  `properties`?: `Properties`;
}

@js(#{`$apTrue`:true,`$noProps`:true,`description`:"Members the realm's attribute catalogue declares, a dotted path of at most six segments nested as objects; a value is a scalar of the row's datatype, or for a bag row an array of at most 256. An undeclared member is 400 STS-AUTHZEN-0004, a null 0005, a wrong type or form 0006, a wrong multiplicity 0007, a wrong nesting 0008."})
@component model `Properties` {}

@js(#{`$apTrue`:true,`description`:"application names the application asked about, one of the caller's; required when the caller is scoped to more than one (400 STS-AUTHZEN-0027), refused when not one of them (403 STS-AUTHZEN-0025). Every other member is a catalogue property, as in Properties."})
@component model `Context` {
  @js(#{`minLength`:1,`maxLength`:1024}) `application`?: string;
}

@js(#{`$apTrue`:true,`description`:"Members other than these four are ignored. Refusals are 400: not an object STS-AUTHZEN-0001, a missing entity or member 0002, a wrong type 0003, and the catalogue's 0004 to 0008."})
@component model `EvaluationRequest` {
  `subject`: `Subject`;
  `action`: `Action`;
  `resource`: `Resource`;
  `context`?: `Context`;
}

@js(#{`$apTrue`:true,`description`:"One evaluation: each entity it carries replaces the default whole."})
@component model `EvaluationItem` {
  `subject`?: `Subject`;
  `action`?: `Action`;
  `resource`?: `Resource`;
  `context`?: `Context`;
}

@js(#{`$apTrue`:true})
@component model `EvaluationsOptions` {
  @js(#{`default`:"execute_all"})
  `evaluations_semantic`?: "execute_all" | "deny_on_first_deny" | "permit_on_first_permit";
}

@js(#{`$apTrue`:true,`description`:"The defaults, merged into each item; with no items, the defaults are one evaluation answered as the single endpoint answers. More than the realm's authzen.maxEvaluations items is 400 STS-AUTHZEN-0038; a body over authzen.maxBodyBytes 400 STS-AUTHZEN-0037; an unknown semantic 0036."})
@component model `EvaluationsRequest` {
  `subject`?: `Subject`;
  `action`?: `Action`;
  `resource`?: `Resource`;
  `context`?: `Context`;
  `evaluations`?: `EvaluationItem`[];
  `options`?: `EvaluationsOptions`;
}

@component model `AdviceAttribute` {
  `id`: string;
  @js(#{`description`:"The value's lexical form."}) `value`: string;
}

@component model `Advice` {
  `id`: string;
  `attributes`: `AdviceAttribute`[];
}

@component model `ReasonAdmin` {
  `en`: string;
}

@js(#{`$apTrue`:true,`description`:"Decided here: present only when the realm's authzen.returnReasons is on, holding xacml_decision and reason_admin, and undischargeable_obligations and advice when not empty. Forwarded to the service (an application enforcing fine-grained authorization): the service's context, whole, whatever returnReasons says. On a batch item that failed: error alone."})
@component model `DecisionContext` {
  `xacml_decision`?: "Permit" | "Deny" | "NotApplicable" | "Indeterminate";
  `reason_admin`?: `ReasonAdmin`;
  @js(#{`description`:"Obligation ids that made a Permit false (STS-AUTHZEN-0029)."})
  `undischargeable_obligations`?: string[];
  `advice`?: `Advice`[];
  `error`?: `ErrorDetail`;
}

@component model `EvaluationResponse` {
  @js(#{`description`:"True only on a Permit with nothing undischargeable; decided deny-biased. A failed batch item is false with context.error."})
  `decision`: boolean;
  `context`?: `DecisionContext`;
}

@js(#{`description`:"In request order; under deny_on_first_deny or permit_on_first_permit it ends at the item that stopped it."})
@component model `EvaluationsResponse` {
  `evaluations`: `EvaluationResponse`[];
}

@component model `Metadata` {
  @js(#{`description`:"PEP_AUTHZEN_PDP_IDENTIFIER, else https://<Host> of an HTTPS request."})
  `policy_decision_point`: string;
  `access_evaluation_endpoint`: string;
  @js(#{`description`:"Only while the realm's authzen.batchEnabled is on."})
  `access_evaluations_endpoint`?: string;
}

@endpoint("/access/v1/evaluation", "post", #{
  `operationId`:"postEvaluation",
  `summary`:"Access evaluation (AuthZEN 1.0 section 6)",
  `description`:"Decided here against the pulled root policy, deny-biased, the PIP consulted when subject.type is one of the realm's resolveSubjectTypes; or, for an application that enforces fine-grained authorization, forwarded to the service's POST /access/v1/evaluation with context.application set, and its answer passed through. Content-Type is not read.",
  `security`:#[#{`mutualTLS`:#[]}],
  `parameters`:#[
    #{`name`:"X-Request-ID",`in`:"header",`required`:false,`description`:"Echoed on the answer when it matches the pattern; else neither echoed nor forwarded.",`schema`:#{`type`:"string",`pattern`:"^[\\x21-\\x7e]{1,128}$"}}
  ],
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"The decision.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"The request's shape or the catalogue refused it (STS-AUTHZEN-0001 to 0008), it names no application among several (0027), or the service answered 400 to a forward (STS-XPEP-0057).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"Admission: see the mutualTLS scheme.",`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"Admission, or an application the caller is not scoped to (STS-AUTHZEN-0025) or no application at all (0026).",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"On the CRL-only listener (STS-XPEP-0114).",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"Larger than PEP_MAX_BODY_BYTES (STS-XPEP-0046), or the service's 413 to a forward (0057).",`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"The engine could not evaluate it (STS-AUTHZEN-0028), or the service's 500 to a forward (STS-XPEP-0057).",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"Turned off here (PEP_AUTHZEN, STS-XPEP-0044) or in the realm (STS-AUTHZEN-0013, 0014), or the service's 501 to a forward (STS-XPEP-0057).",`content`:#{`application/json`:#{`schema`:null}}},
    `502`:#{`description`:"A forward failed: the service unreachable (STS-XPEP-0055), refused this PEP (0056), answered another status (0057) or no decision (0058).",`content`:#{`application/json`:#{`schema`:null}}},
    `503`:#{`description`:"Nothing pulled yet: the policies and catalogue (STS-XPEP-0043) or the callers (0050); or the service's 503 to a forward (0057).",`content`:#{`application/json`:#{`schema`:null}}},
    `504`:#{`description`:"A forward timed out (PEP_AUTHZEN_FORWARD_TIMEOUT_MS, STS-XPEP-0055).",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postEvaluation`(`requestBody/content/application~1json/schema`: `EvaluationRequest`,
  `responses/200/content/application~1json/schema`: `EvaluationResponse`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/404/content/application~1json/schema`: `NotFound`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`,
  `responses/502/content/application~1json/schema`: `Error`,
  `responses/503/content/application~1json/schema`: `Error`,
  `responses/504/content/application~1json/schema`: `Error`): void;

@endpoint("/access/v1/evaluations", "post", #{
  `operationId`:"postEvaluations",
  `summary`:"Access evaluations (AuthZEN 1.0 section 7)",
  `description`:"Each item merged over the defaults and decided as the single endpoint decides one, a failed item answered false with context.error rather than failing the batch. With no items the defaults are one evaluation, answered as EvaluationResponse with the single endpoint's statuses. Turned off by the realm's authzen.batchEnabled (501 STS-AUTHZEN-0039, before admission).",
  `security`:#[#{`mutualTLS`:#[]}],
  `parameters`:#[
    #{`name`:"X-Request-ID",`in`:"header",`required`:false,`description`:"Echoed when valid; item i is logged and forwarded as <id>#<i>.",`schema`:#{`type`:"string",`pattern`:"^[\\x21-\\x7e]{1,128}$"}}
  ],
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"The decisions; or, with no items, one decision.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"Not an object (STS-AUTHZEN-0001), evaluations or options of the wrong type (0003), an unknown semantic (0036), too large (0037), too many items (0038); with no items, the single endpoint's 400s.",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"Admission: see the mutualTLS scheme.",`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"Admission; with no items, the single endpoint's 403s.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"On the CRL-only listener (STS-XPEP-0114).",`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"With no items only: as the single endpoint.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"Turned off here (STS-XPEP-0044), in the realm (STS-AUTHZEN-0013, 0014), or the batch off (0039).",`content`:#{`application/json`:#{`schema`:null}}},
    `502`:#{`description`:"With no items only: as the single endpoint.",`content`:#{`application/json`:#{`schema`:null}}},
    `503`:#{`description`:"Nothing pulled yet (STS-XPEP-0043, 0050).",`content`:#{`application/json`:#{`schema`:null}}},
    `504`:#{`description`:"With no items only: as the single endpoint.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postEvaluations`(`requestBody/content/application~1json/schema`: `EvaluationsRequest`,
  `responses/200/content/application~1json/schema`: `EvaluationsResponse` | `EvaluationResponse`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/404/content/application~1json/schema`: `NotFound`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`,
  `responses/502/content/application~1json/schema`: `Error`,
  `responses/503/content/application~1json/schema`: `Error`,
  `responses/504/content/application~1json/schema`: `Error`): void;

@endpoint("/.well-known/authzen-configuration", "get", #{
  `operationId`:"getAuthzenConfiguration",
  `summary`:"PDP metadata (AuthZEN 1.0 section 9)",
  `description`:"No admission. Reads the Host header to name the identifier when PEP_AUTHZEN_PDP_IDENTIFIER is not set; no search, obligation, access-request, key or capability member is ever published.",
  `responses`:#{
    `200`:#{`description`:"The metadata.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"No identifier: PEP_AUTHZEN_PDP_IDENTIFIER is not set and the request was not HTTPS with a usable Host (STS-XPEP-0045); or the CRL-only listener (0114, NotFound body).",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"Turned off here (STS-XPEP-0044) or in the realm (STS-AUTHZEN-0013, 0014).",`content`:#{`application/json`:#{`schema`:null}}},
    `503`:#{`description`:"The policies and catalogue not yet pulled (STS-XPEP-0043).",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getAuthzenConfiguration`(`responses/200/content/application~1json/schema`: `Metadata`,
  `responses/404/content/application~1json/schema`: `Error` | `NotFound`,
  `responses/501/content/application~1json/schema`: `Error`,
  `responses/503/content/application~1json/schema`: `Error`): void;

}
