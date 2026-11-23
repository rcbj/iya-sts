// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/pep/pep_service.tsp
//
// Written by hand (#1830). THE SOURCE OF THE REMOTE PEP SERVICE OPENAPI
// DOCUMENT (`xacml-pep/openapi/pep-service.json`): what `Pep::handle`
// (`rust/bins/xacml-pep/src/service.rs`) answers on the PEP's API listeners
// — the plain `api-http` (PEP_PORT, only with PEP_HTTP=true), the HTTPS
// `api-https` (PEP_HTTPS_PORT) and the service-defined listeners of purpose
// `api`. The AuthZEN edge PDP shares those listeners and has a document of
// its own (`pep_authzen.tsp`); the reverse proxy's listeners never reach this
// handler (`pep_proxy.tsp`).
//
// WHAT THE CODE DOES, DESCRIBED AS IT IS, NOT AS IT MIGHT BE TIDIED:
//
// * There is no route table. Method and raw path are compared exactly, and
//   anything that matches nothing — a wrong method on a known path, OPTIONS,
//   a trailing slash — is the generic 404 (`NotFound`). Nothing answers 405.
//   So each operation's `404` is part of its contract.
// * HEAD is answered as GET without the body for every GET here but
//   `/protected`, whose GET is a decision (#1830): the same status and
//   headers, Content-Length the GET's. HEAD /protected is the generic 404.
// * Every JSON answer is `application/json` with `Cache-Control: no-store`,
//   pretty-printed. A CRL is the one answer without that header.
// * No STS-XPEP code is ever in a body: each refusal's code is in its
//   description, for an operator reading the PEP's log.
// * `/protected` and `/notify` read no credential. An HTTPS listener ASKS
//   for a client certificate when PEP_AUTHZEN_CLIENT_CA is set and its
//   tuning asks, for AuthZEN, and these two ignore it, so no security scheme
//   is declared.
//
// The `GET /` overview is closed at every depth the code fixes, and open
// only where it passes something through: `registration.notify` is the
// service's register answer's member (`pep_control_plane.tsp`'s
// `RegisterNotify`), and `proxy.answered.byStatus` is keyed by status code.

import "../lib/api_lib.tsp";

using IyaSts.ApiLib;

@apiDocument(#{
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS remote PEP",
    `version`:"1",
    `description`:"The remote XACML policy enforcement point's own API: its status overview, its liveness, the demonstration decision at /protected, the PDP's policy nudge and its own credential's CRLs. Served on the plain listener (PEP_PORT, 9090, only with PEP_HTTP=true), the HTTPS listener (PEP_HTTPS_PORT, 9443) and any listener of purpose api the service defines. With PEP_HTTP off and a CRL directory present, 9090 is a CRL-only listener that answers GET /crl/{name} and nothing else (404 STS-XPEP-0114). A method or path not listed here is 404 with the NotFound body (STS-XPEP-0009); nothing answers 405. HEAD is answered as GET without the body for every GET listed here but /protected, whose GET is a decision; HEAD /protected is that 404. Error codes are recorded in the PEP's log and never sent."
  },
  `servers`:#[
    #{`url`:"https://localhost:9443",`description`:"The HTTPS listener, PEP_HTTPS_PORT."},
    #{`url`:"http://localhost:9090",`description`:"The plain listener, PEP_PORT, with PEP_HTTP=true."}
  ],
  `x-iya-doc`:"pepService"
})
namespace IyaSts.Pep.Service {

@component model `NotFound` {
  `error`: "not_found";
  @js(#{`description`:"Absent on a CRL lookup that found nothing."})
  `error_description`?: string;
}

@component model `Health` {
  @js(#{`const`:"Success"}) `message`: string;
}

@js(#{`description`:"What the PIP did for the last evaluation. One of seven forms: used is false with why (PIP off; no subject; no designators, with subject; too many designators, with subject and designators; the query failed or its answer was unreadable, with subject, designators and failed), or used is true with subject, designators, resolved and unresolved."})
@component model `PipReport` {
  `used`: boolean;
  `why`?: string;
  `subject`?: string;
  `designators`?: int64;
  @js(#{`const`:true}) `failed`?: boolean;
  `resolved`?: int64;
  `unresolved`?: `Unresolved`[];
}

@component model `Unresolved` {
  `attributeId`: string;
  `why`: string;
}

@component model `Pip` {
  `enabled`: boolean;
  @js(#{`description`:"{pdp}/xacml/pip when enabled."})
  `endpoint`: string | null;
  `credentialed`: boolean;
  @js(#{`description`:"The last evaluation's report, the reverse proxy's included; null before any."})
  `lastQuery`: `PipReport` | null;
  `what`: string;
}

@component model `Build` {
  `number`: string | null;
  `release`: boolean;
  `commit`: string | null;
  `at`: string;
  `stamped`: boolean;
  `what`: string;
}

@component model `ServedCertificate` {
  `subject`: string;
  `issuer`: string;
  `serialHex`: string;
  `subjectAltName`: string;
  `validFrom`: string;
  `validTo`: string;
  `fingerprint256`: string;
}

@component model `Https` {
  `configured`: boolean;
  `listening`: boolean;
  `port`: int64 | null;
  `certificate`: `ServedCertificate` | null;
  `loadedAt`: string | null;
  `lastCheckedAt`: string | null;
  @js(#{`description`:"What the listener does: the acceptor it serves asks callers for a certificate (PEP_AUTHZEN_CLIENT_CA or trust anchors set, and its tuning's askClientCertificate or requireClientCertificate on); before it serves one, what its tuning will build."})
  `asksForClientCertificates`: boolean;
  `problem`: string | null;
  `what`: string;
}

@component model `PulledCallers` {
  `loaded`: boolean;
  `syncToken`: string;
  `door`: string;
  `callers`: int64;
  `certificates`: int64;
  `truncatedByThePdp`: boolean;
  `refused`: string[];
  `lastPullAt`: string;
  `lastPullOk`: boolean;
  `lastPullWhy`: string;
}

@component model `AuthzenSettings` {
  `enabled`: boolean;
  `resolveSubjectTypes`: string[];
  `batchEnabled`: boolean;
  @js(#{`minimum`:1,`maximum`:1000}) `maxEvaluations`: int64;
  @js(#{`minimum`:1024,`maximum`:5242880}) `maxBodyBytes`: int64;
  `returnReasons`: boolean;
  @js(#{`description`:"The realm's authzen.obligationsProfile, as pulled. The default, and an absent member, is on."})
  `obligationsProfile`: boolean;
}

@component model `Catalogue` {
  `loaded`: boolean;
  `syncToken`: string;
  `realm`: string;
  `apiObject`: boolean;
  `rows`: int64;
  `fgaApplications`: int64;
  `refused`: string[];
  `leftOutByThePdp`: int64;
  `settings`: `AuthzenSettings`;
  `lastPullAt`: string;
  `lastPullOk`: boolean;
  `lastPullWhy`: string;
}

@component model `AuthzenAnswered` {
  `decisions`: int64;
  `true`: int64;
  `false`: int64;
  `errors`: int64;
  `forwarded`: int64;
}

@component model `LocalCallers` {
  `configured`: boolean;
  `certificates`: int64;
  `role`: string;
}

@component model `AuthzenStatus` {
  `pulledCallers`: `PulledCallers`;
  `catalogue`: `Catalogue`;
  `answered`: `AuthzenAnswered`;
  @js(#{`description`:"Whether the edge PDP answers: the value in force, the service's managed authzen when it set one, else PEP_AUTHZEN (settings.values.authzen says which)."})
  `enabled`: boolean;
  `endpoints`: string[];
  `localCallers`: `LocalCallers`;
  @js(#{`description`:"https.asksForClientCertificates: whether the environment's HTTPS listener asks. Admission asks the listener each request arrived on."})
  `clientCertificatesAsked`: boolean;
  @js(#{`description`:"The identifier in force: the service's managed authzenPdpIdentifier when it set one, else PEP_AUTHZEN_PDP_IDENTIFIER; null when neither is, and the metadata names the origin each request arrived at."})
  `pdpIdentifier`: string | null;
  `what`: string;
}

@component model `ProxyPorts` {
  `http`: int64;
  `https`: int64;
}

@component model `RoutesByMechanism` {
  `session`: int64;
  `oauth2`: int64;
  `saml2`: int64;
  `basic`: int64;
}

@component model `LibrarySessions` {
  `held`: int64;
  `max`: int64;
  `ttlSec`: int64;
  `evicted`: int64;
  `expired`: int64;
}

@component model `ProxySignals` {
  `receivers`: int64;
  `healthy`: int64;
  `stale`: int64;
  `staleAfterMs`: int64;
  `pollIntervalMs`: int64;
  `oldestSuccessAgeMs`: int64 | null;
  `mostConsecutiveFailures`: int64;
  `setsAccepted`: int64;
  `setsRefused`: int64;
  `sessionsEnded`: int64;
  `librarySessions`: `LibrarySessions`;
}

@component model `ProxyAnswered` {
  `requests`: int64;
  `forwarded`: int64;
  @js(#{`description`:"Answers by HTTP status, the status as the key.",`propertyNames`:#{`pattern`:"^[1-5][0-9][0-9]$"}})
  `byStatus`: Record<int64>;
  `signIns`: int64;
  `sessionsEnded`: int64;
}

@component model `ProxySessions` {
  `live`: int64;
  `signInsInFlight`: int64;
  `max`: int64;
}

@component model `ProxyStatus` {
  `enabled`: boolean;
  `ports`: `ProxyPorts`;
  `loaded`: boolean;
  `configured`: boolean;
  `active`: boolean;
  `syncToken`: string;
  `routes`: int64;
  `publicRoutes`: int64;
  `unusableRoutes`: int64;
  `routesByMechanism`: `RoutesByMechanism`;
  `sessionClients`: int64;
  `relyingParties`: int64;
  `signalsReceivers`: int64;
  `signingCertificates`: int64;
  @js(#{`description`:"Null when the proxy is not running."})
  `signals`: `ProxySignals` | null;
  `lastPullAt`: string;
  `lastPullOk`: boolean;
  `lastPullWhy`: string;
  `answered`: `ProxyAnswered`;
  `sessions`: `ProxySessions`;
  `what`: string;
}

@component model `RefusedPolicy` {
  `name`: string;
  `why`: string;
}

@component model `Holding` {
  `loaded`: boolean;
  `syncToken`: string;
  @js(#{`description`:"The root policy's id, \"(unnamed)\" when it has none; null when none is held."})
  `root`: string | null;
  `policyCount`: int64;
  `lastPullAt`: string;
  `lastPullOk`: boolean;
  `lastPullWhy`: string;
  @js(#{`description`:"start, poll, nudge, heartbeat or unnamed; empty before any change."})
  `lastChangeCause`: "" | "start" | "poll" | "nudge" | "heartbeat" | "unnamed";
  `lastChangeAt`: string;
  `lastNudgeAt`: string;
  `lastNudgeResult`: "" | "failed" | "changed" | "unchanged";
  `refused`: `RefusedPolicy`[];
}

@js(#{`description`:"The service's register answer's notify member, passed through as it came (POST /xacml/pep/register). The PEP reads usable and why.",`$apTrue`:true})
@component model `RegistrationNotify` {
  `usable`?: boolean;
  `why`?: string;
}

@js(#{`description`:"registered false: name, attempts and why. registered true adds authenticated and notify."})
@component model `Registration` {
  `registered`: boolean;
  `name`: string;
  `attempts`: int64;
  `authenticated`?: boolean;
  `why`: string;
  `notify`?: `RegistrationNotify` | null;
}

@component model `Enforced` {
  `decisions`: int64;
  `allowed`: int64;
  `refused`: int64;
  `undischargeable`: int64;
}

@component model `Poll` {
  `intervalMs`: int64;
  `heartbeatMs`: int64;
}

@js(#{`description`:"One managed setting in force: its value (typed by its key), where it came from, and rejected: true on a notifyUrl that was set and refused, whose value is then the refused string."})
@component model `SettingValue` {
  `value`: boolean | int64 | string;
  `source`: "service" | "environment" | "derived" | "default";
  @js(#{`const`:true}) `rejected`?: boolean;
}

@component model `Settings` {
  `token`: string;
  @js(#{`description`:"Every managed setting, by key: description, resource, notifyUrl, bias, pip, pollIntervalMs, heartbeatIntervalMs, backoffMaxMs, timeoutMs, maxBodyBytes, httpsReloadIntervalMs, logLevel, authzen, authzenPdpIdentifier, authzenForwardTimeoutMs, the proxy's settings and the decision records' (auditEnabled, auditIntervalMs, auditBatch, auditBuffer)."})
  `values`: Record<`SettingValue`>;
  `lastPullAt`: string;
  `lastPullOk`: boolean;
  `lastPullWhy`: string;
  `offered`: boolean;
  `configured`: boolean;
}

@js(#{`description`:"The decision records this PEP sends to the service's audit log (#1827): POST /admin-api/pep-audit, with its DPoP-bound token for /admin-api. Delivery is at least once; dropped counts records lost to a full queue (PEP_AUDIT_BUFFER) or to a batch the service refused as malformed."})
@component model `AuditStatus` {
  `enabled`: boolean;
  `queued`: int64;
  `shipped`: int64;
  `dropped`: int64;
  `lastShipAt`: string | null;
  `lastShipOk`: boolean | null;
  `lastShipWhy`: string;
  `tokenHeld`: boolean;
  @js(#{`description`:"This process's id, which a batch carries so the service can tell two instances under one name apart."})
  `instance`: string;
  `what`: string;
}

@component model `CredentialToken` {
  @js(#{`description`:"The audience: this realm's /xacml/pep, /admin-api or /access/v1."})
  `resource`: string;
  `scope`: string;
  `held`: boolean;
  `expiresAt`: string | null;
  @js(#{`description`:"Why the last token request was refused; null when none was."})
  `lastRefusal`: string | null;
}

@js(#{`description`:"How this PEP authenticates to the service (#1827): a DPoP-bound access token per audience, from an RFC 7523 self-assertion signed with one key, which signs every DPoP proof too."})
@component model `CredentialStatus` {
  `keyFile`: string | null;
  @js(#{`description`:"The variable the key came from: PEP_ASSERTION_KEY, else PEP_TLS_KEY."})
  `keySource`: string | null;
  `fallback`: boolean;
  `keyType`: string | null;
  `alg`: string | null;
  `jwkThumbprint`: string | null;
  `keyProblem`: string | null;
  @js(#{`const`:"sts-remote-pep"}) `clientId`: string;
  @js(#{`description`:"PEP_NAME: the username of this PEP's entry."}) `subject`: string;
  @js(#{`description`:"Whether PEP_TLS_CERT is presented as well."}) `clientCertificate`: boolean;
  @js(#{`description`:"By audience: xacml-pep, admin-api and access-v1."})
  `tokens`: Record<`CredentialToken`>;
  `what`: string;
}

@component model `Overview` {
  `what`: string;
  `pip`: `Pip`;
  @js(#{`description`:"M.N.O.<build>."}) `version`: string;
  `build`: `Build`;
  @js(#{`description`:"The PDP's base URL, PEP_PDP_URL."}) `pdp`: string;
  `bias`: "deny-biased" | "permit-biased";
  @js(#{`const`:"/protected"}) `protectedAt`: string;
  `https`: `Https`;
  `authzen`: `AuthzenStatus`;
  `proxy`: `ProxyStatus`;
  `audit`: `AuditStatus`;
  `credential`: `CredentialStatus`;
  `holding`: `Holding`;
  @js(#{`description`:"lastPullAt is empty, unreadable, or older than staleAfterMs."})
  `stale`: boolean;
  `staleAfterMs`: int64;
  `registration`: `Registration`;
  `enforced`: `Enforced`;
  @js(#{`description`:"The https notify URL in force; null when none is, or the one set was refused."})
  `notify`: string | null;
  `poll`: `Poll`;
  `settings`: `Settings`;
  `contract`: string;
}

@component model `DecisionStatus` {
  `code`: "urn:oasis:names:tc:xacml:1.0:status:ok" | "urn:oasis:names:tc:xacml:1.0:status:missing-attribute" | "urn:oasis:names:tc:xacml:1.0:status:syntax-error" | "urn:oasis:names:tc:xacml:1.0:status:processing-error";
  @js(#{`description`:"Absent, not null, when the engine gave none."})
  `message`?: string;
}

@component model `Obligation` {
  `id`: string;
  `discharged`: boolean;
}

@component model `ApplicablePolicy` {
  `kind`: "PolicySet" | "Policy";
  `id`: string;
  `version`: string;
}

@component model `DecidedBy` {
  `pep`: string;
  @js(#{`description`:"The policy set's sync token; empty before any pull."})
  `syncToken`: string;
  `note`: string;
}

@component model `Decision` {
  `decision`: "Permit" | "Deny" | "NotApplicable" | "Indeterminate";
  `allowed`: boolean;
  `bias`: "deny-biased" | "permit-biased";
  `why`: string;
  `status`: `DecisionStatus`;
  `obligations`: `Obligation`[];
  @js(#{`description`:"Advice ids."}) `advice`: string[];
  `applicablePolicies`: `ApplicablePolicy`[];
  `decidedBy`: `DecidedBy`;
  `pip`: `PipReport`;
  @js(#{`description`:"Present only when no root policy is held (STS-XPEP-0005)."})
  `note`?: string;
}

@js(#{`description`:"What the service sends (POST, https only, the PEP's certificate verified against the realm's pep-tls chain, redirects not followed) after a commit to the policy repository, to every member of a cluster whose configuration changed, and on a Sync from the console. The PEP reads full alone and trusts nothing else in it."})
@component model `Nudge` {
  @js(#{`const`:"policy-repository-changed"}) `event`: string;
  @js(#{`description`:"When, ISO 8601."}) `at`: string;
  @js(#{`description`:"The realm's PDP: the base /xacml/pep/* is served under, realm prefix included — pinned, or that of the request that made the change; empty only with neither. Not read by the PEP."}) `pdp`: string;
  @js(#{`description`:"true on a Sync from the console: pull every document whole rather than answered 304. Honoured at most once a poll interval (STS-XPEP-0120 logs one asked for sooner, which pulls as usual); absent, false or any other value is an ordinary pull."})
  `full`?: boolean;
}

@endpoint("/", "get", #{
  `operationId`:"getOverview",
  `summary`:"What this PEP holds and how it is doing",
  `description`:"The whole state of the PEP: the policy it holds and whether it is stale, its registration, the PIP, the HTTPS listener, the AuthZEN edge PDP, the reverse proxy, and every managed setting in force with its source. Reads nothing in the request. HEAD is answered as GET without the body.",
  `responses`:#{
    `200`:#{`description`:"The overview. Cache-Control: no-store.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"On the CRL-only listener (STS-XPEP-0114).",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getOverview`(`responses/200/content/application~1json/schema`: `Overview`,
  `responses/404/content/application~1json/schema`: `NotFound`): void;

@endpoint("/healthcheck", "get", #{
  `operationId`:"getHealthcheck",
  `summary`:"Liveness",
  `description`:"Always 200 while the process answers; it says nothing about whether the policy is current (GET / says that). The image's HEALTHCHECK, xacml-pep --healthcheck, asks this over the plain listener with PEP_HTTP=true and over HTTPS, unverified, otherwise. HEAD is answered as GET without the body.",
  `responses`:#{
    `200`:#{`description`:"Alive.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"On the CRL-only listener (STS-XPEP-0114).",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getHealthcheck`(`responses/200/content/application~1json/schema`: `Health`,
  `responses/404/content/application~1json/schema`: `NotFound`): void;

@endpoint("/protected", "get", #{
  `operationId`:"getProtected",
  `summary`:"The demonstration decision",
  `description`:"Builds an XACML request from the query with the service's request builder, decides it against the held policy (fetching the attributes the policy designates from the PDP's PIP first), applies the bias and the obligation rule of XACML 3.0 section 7.2, and answers 200 when allowed and 403 when not, with the same body. A repeated parameter keeps its last value. Every parameter not named here is a subject attribute, asserted under its own name and as urn:sts:xacml:attribute:<name>. No credential is read: the subject is what the query says. HEAD is the generic 404 (STS-XPEP-0009): a decision is evaluated, counted and reported, which a HEAD from a monitor or a link checker does not mean to ask for.",
  `parameters`:#[
    #{`name`:"subject",`in`:"query",`required`:false,`description`:"The access-subject's subject-id. Absent or empty: no subject attribute.",`schema`:#{`type`:"string"}},
    #{`name`:"resource",`in`:"query",`required`:false,`description`:"The resource-id (anyURI). Absent or empty: the resource setting (PEP_RESOURCE), else urn:xacml-pep:protected.",`schema`:#{`type`:"string"}},
    #{`name`:"action",`in`:"query",`required`:false,`description`:"The action-id. Absent or empty: GET.",`schema`:#{`type`:"string"}},
    #{`name`:"subjectKind",`in`:"query",`required`:false,`description`:"application says the subject is an application; any other value says user. Asserted as urn:sts:xacml:subject-kind and forwarded to the PIP.",`schema`:#{`type`:"string"}},
    #{`name`:"attributes",`in`:"query",`required`:false,`style`:"form",`explode`:true,`description`:"Any other parameter: a subject attribute, under both spellings, unbounded and unchecked.",`schema`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}}}
  ],
  `responses`:#{
    `200`:#{`description`:"Allowed.",`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"Not allowed: Deny, NotApplicable or Indeterminate under the bias, or a Permit with an obligation this PEP cannot discharge (STS-XPEP-0004). No policy held is STS-XPEP-0005; Indeterminate STS-XPEP-0006.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"On the CRL-only listener (STS-XPEP-0114).",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getProtected`(`responses/200/content/application~1json/schema`: `Decision`,
  `responses/403/content/application~1json/schema`: `Decision`,
  `responses/404/content/application~1json/schema`: `NotFound`): void;

@endpoint("/notify", "post", #{
  `operationId`:"postNotify",
  `summary`:"The PDP's nudge: pull now",
  `description`:"Answered on an HTTPS listener only. Says that something may have changed: nothing in the request is checked, and of the body (at most 4096 bytes) only full is read, which asks for every document whole and carries nothing a pull does not fetch. The PEP answers at once and then pulls; the outcome shows on GET / as holding.lastNudgeAt and lastNudgeResult (a failed pull is STS-XPEP-0010).",
  `requestBody`:#{`required`:false,`description`:"What the service sends. A body that is not JSON, or has no full: true, is an ordinary nudge; any body is answered alike.",`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `204`:#{`description`:"Accepted; the pull follows. No body and no Content-Type; Cache-Control: no-store."},
    `404`:#{`description`:"On a plain listener (STS-XPEP-0112): the PDP nudges over https only. On the CRL-only listener, STS-XPEP-0114.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postNotify`(`requestBody/content/application~1json/schema`: `Nudge`,
  `responses/404/content/application~1json/schema`: `NotFound`): void;

@endpoint("/crl/{name}", "get", #{
  `operationId`:"getCrl",
  `summary`:"A CRL of this PEP's own credential",
  `description`:"The file {name} in PEP_CRL_DIR (default: the crl directory beside PEP_TLS_CERT), as stored, so that a client verifying this PEP's certificate can check it. Served on every API listener, the CRL-only one included. HEAD is answered as GET without the body.",
  `parameters`:#[
    #{`name`:"name",`in`:"path",`required`:true,`description`:"A file name; anything else is 404.",`schema`:#{`type`:"string",`pattern`:"^[A-Za-z0-9-]+\\.[cC][rR][lL]$"}}
  ],
  `responses`:#{
    `200`:#{`description`:"The CRL's bytes, as the file holds them (normally DER). No Cache-Control.",`content`:#{`application/pkix-crl`:#{`schema`:#{`type`:"string",`contentMediaType`:"application/pkix-crl"}}}},
    `404`:#{`description`:"No CRL directory, a name of another form, or no such readable file (STS-XPEP-0009); only error is sent.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getCrl`(`responses/404/content/application~1json/schema`: `NotFound`): void;

}
