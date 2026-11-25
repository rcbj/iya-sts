// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/pep/pep_control_plane.tsp
//
// Written by hand (#1830). THE SOURCE OF THE REMOTE PEP CONTROL PLANE
// OPENAPI DOCUMENT (`xacml-pep/openapi/pep-control-plane.json`): what the
// identity service serves for a remote PEP — `/xacml/pep/*` in
// `xacml/xacml.ts` and the modules it calls, and `POST /xacml/pip` — which
// the PEP calls (`sync.rs`, `pip.rs`, `listeners.rs`, `proxy_auth.rs`). The
// service's nudge to the PEP is the other direction, and is the request body
// of `POST /notify` in `pep_service.tsp`.
//
// THE MODEL IS THE SERVICE'S ANSWER, NOT ONLY WHAT THE PEP READS. Several
// members are written and never read by the PEP (a register answer's URLs,
// a policy row's kind and version, the callers' counts, the realm's three
// endpoints the PEP finds by discovery instead); each is declared, so the
// generated Rust type reads the whole answer, and its description says the
// PEP does not use it. A member that is present only in one case (a
// policies answer's `rootNote`, a catalogue row's `description`, a pull's
// `note` when not configured) is optional, not nullable, because the service
// leaves it out.
//
// WHAT MODELLING CORRECTED (#1830): every irregularity the first version of
// this file declared was fixed rather than kept — `If-None-Match` is read,
// a pull touches the certificate's row, register and heartbeat answer each
// registry refusal's own status, the PIP answers every refusal as XML, the
// listener certificate lost its stray `ok`, the nudge names its PDP, and
// every validation door answers one 429 shape. `xacml/CLAUDE.md`, *What
// modelling the control plane corrected*, argues each.
//
// THE REFUSALS AHEAD OF EVERY ROUTE (2026-11-16): a body over 5 MB, in a
// charset or encoding the service does not read, or cut short; a control
// character or a polluting name in the query; the per-address ceiling. The
// fuzzing of PR #1858 found the first two answered as Express's HTML page and
// in text; `common/surface_refusals.ts` answers them as `Error` (and
// `TooManyRequests`), and a `PIPError` at the PIP, and every operation here
// declares each at its status. `tests/surface_refusals.js` holds the two.
//
// The PEP reaches the five validation doors at the absolute URLs the proxy
// pull's `validation` names, which are these paths under the realm.

import "../lib/api_lib.tsp";

using IyaSts.ApiLib;

@apiDocument(#{
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS remote PEP control plane",
    `version`:"1",
    `description`:"What the identity service serves for a remote XACML PEP: registration and heartbeat, the pulls (policies, AuthZEN attribute catalogue and callers, reverse-proxy configuration, managed settings and listeners), a defined listener's certificate, the reverse proxy's five validation doors and the PIP. Paths are under PEP_PDP_URL, which carries the realm's prefix (/realm/<id>). Every operation needs a client certificate the service verifies whose entry holds REMOTE_PEPS (the access-control policy on xacml-pep-api: READ for the pulls, the doors and the PIP; WRITE for register, heartbeat and listener-certificate); a refusal is 403 access_denied (STS-XACML-0007, 0008, 0009, 0010, 0179, 0180, or the revocation's code). xacml.enabled off is 501 (STS-XACML-0001), xacml.remotePeps off 501 (0002), both before the gate. A pull's sync token is base64url SHA-256, sent as ETag in quotes; ?since=<token> equal to it answers 304, and so does an If-None-Match that matches the ETag (RFC 9110 section 13.1.2: *, or a list of entity tags compared weakly). Errors are the Error object, with Cache-Control: no-store, except at POST /xacml/pip, where every refusal (the gate's and the off switches' included) is a PIPError in XML; a request refused before any endpoint sees it (a body over 5 MB, 413; in a character set or content encoding the service does not read, 415; cut short of its Content-Length, or a control character or a parameter named __proto__, constructor or prototype in the query, 400; over the ceiling on one address's requests, 429 with Retry-After) is answered in the same shapes; no error code is ever in a body, except a route's resolved.code inside the proxy pull. The PEP sends Accept: application/xml on POST /xacml/pip and Accept: application/json everywhere else, and User-Agent: sts/<version> (xacml-pep), and follows no redirect."
  },
  `servers`:#[
    #{`url`:"https://localhost:8081",`description`:"PEP_PDP_URL: the service, with /realm/<id> for a realm."}
  ],
  `security`:#[#{`mutualTLS`:#[]},#{`dpop`:#["xacml:pep"]}],
  `components`:#{
    `securitySchemes`:#{
      `mutualTLS`:#{
        `type`:"mutualTLS",
        `description`:"The PEP's PEP_TLS_CERT, verified by the service, stored on an entry that holds REMOTE_PEPS. The PEP's register name is the certificate's CN (else its DN), folded to [A-Za-z0-9._-] and 128 characters; a name in the request is read only when no certificate was presented. Accepted when the realm's xacml.pepAuthentication is certificate or either."
      },
      `dpop`:#{
        `type`:"http",
        `scheme`:"DPoP",
        `description`:"RFC 9449 (#1827): Authorization: DPoP <token> with a DPoP proof for this method and URL. The token is the client sts-remote-pep's, from an RFC 7523 self-assertion, audienced to the realm's /xacml/pep, carrying xacml:pep, its subject the PEP's own entry. Accepted when xacml.pepAuthentication is token or either. A refusal is 401 with a DPoP challenge, error=... and algs=\"ES256 RS256\" (and a DPoP-Nonce header for use_dpop_nonce): no token where one is required (STS-XACML-0289), a token where a certificate is (0290), not this realm's or revoked (0291), not DPoP-bound (0292), another audience (0293), another client (0294), without xacml:pep (0295), a refused proof (0296), a subject naming no entry (0297)."
      }
    }
  },
  `x-iya-doc`:"pepControlPlane"
})
namespace IyaSts.Pep.ControlPlane {

@component model `Error` {
  `error`: "not_implemented" | "access_denied" | "invalid_client" | "invalid_request" | "invalid_token" | "insufficient_scope" | "use_dpop_nonce" | "server_error" | "too_many_requests";
  `error_description`: string;
}

// ---------------------------------------------------------------- register

@component model `RegisterRequest` {
  @js(#{`description`:"PEP_NAME. Read only when no certificate was presented."})
  `name`?: string;
  @js(#{`description`:"Where the service nudges this PEP: https, or empty. notify_url is accepted as an alias."})
  `notifyUrl`?: string;
  `bias`?: "deny-biased" | "permit-biased";
  `resource`?: string;
  `version`?: string;
  @js(#{`description`:"Empty keeps the description held."})
  `description`?: string;
  @js(#{`description`:"Sent only when the PEP knows it: a lower-case DNS name of at most 253 characters, not an IP address; anything else is 400 STS-XACML-0261.",`maxLength`:253})
  `hostname`?: string | null;
}

@component model `RegisterNotify` {
  `url`: string | null;
  `usable`: boolean;
  `why`: string;
}

@component model `Registered` {
  @js(#{`const`:true}) `registered`: boolean;
  `name`: string;
  `created`: boolean;
  @js(#{`description`:"A certificate was presented."}) `authenticated`: boolean;
  `verified`: boolean;
  `verifiedWhy`: string;
  @js(#{`description`:"The certificate's DN, or empty."}) `identity`: string;
  @js(#{`description`:"The policy repository's token. Not read by the PEP."}) `syncToken`: string;
  `policiesUrl`: string;
  `heartbeatUrl`: string;
  `notify`: `RegisterNotify`;
  `note`: string;
}

@endpoint("/xacml/pep/register", "post", #{
  `operationId`:"postRegister",
  `summary`:"Register, or register again",
  `description`:"The PEP registers on every poll until this answers 200 or 201. With xacml.pepRequireCertificate (the default) a certificate is required: a plain socket is 401 STS-XACML-0017, TLS with no certificate 0018.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"Registered again.",`content`:#{`application/json`:#{`schema`:null}}},
    `201`:#{`description`:"Registered for the first time.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"No usable name (STS-XACML-0019) or a bad hostname (0261): invalid_request. Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"No certificate (STS-XACML-0017, 0018): invalid_client; or the token door refused the credential (see the dpop scheme), with a DPoP challenge.",`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}},
    `503`:#{`description`:"No embedded directory in this process (STS-XACML-0026): server_error; a later attempt can succeed.",`content`:#{`application/json`:#{`schema`:null}}},
    `507`:#{`description`:"The directory refused the entry: ou=peps holds xacml.maxPeps, or the directory its entry cap (STS-XACML-0027): server_error, until an operator makes room.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postRegister`(`requestBody/content/application~1json/schema`: `RegisterRequest`,
  `responses/200/content/application~1json/schema`: `Registered`,
  `responses/201/content/application~1json/schema`: `Registered`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/501/content/application~1json/schema`: `Error`,
  `responses/503/content/application~1json/schema`: `Error`,
  `responses/507/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- heartbeat

@component model `LibrarySessions` {
  `held`: int64;
  `max`: int64;
  `ttlSec`: int64;
  `evicted`: int64;
  `expired`: int64;
}

@component model `SignalStream` {
  @js(#{`maxLength`:256,`pattern`:"^[A-Za-z0-9._:~@/+-]*$"}) `clientId`: string;
  @js(#{`maxLength`:128,`pattern`:"^[A-Za-z0-9._:~@/+-]*$"}) `streamId`: string;
  `running`: boolean;
  `healthy`: boolean;
  `startedAgeMs`: int64 | null;
  `lastPollAgeMs`: int64 | null;
  `lastSuccessAgeMs`: int64 | null;
  `consecutiveFailures`: int64;
  `polls`: int64;
  `failedPolls`: int64;
  `setsAccepted`: int64;
  `setsRefused`: int64;
  `sessionsEnded`: int64;
}

@js(#{`description`:"The reverse proxy's CAEP and RISC receivers: counts only; the service drops a member it does not name."})
@component model `PepSignals` {
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
  @js(#{`maxItems`:64}) `streams`?: `SignalStream`[];
}

@component model `SettingInUse` {
  `value`: boolean | int64 | string;
  `source`: "service" | "environment" | "derived" | "default";
  @js(#{`const`:true,`description`:"Only on notifyUrl, when the one set was not https."}) `rejected`?: boolean;
}

@component model `SettingsReport` {
  @js(#{`pattern`:"^[A-Za-z0-9_-]{0,128}$"}) `token`: string;
  @js(#{`description`:"Every managed setting in force, by key; values are checked against the row and unknown keys dropped."})
  `values`: Record<`SettingInUse`>;
}

@component model `ReportedCertificate` {
  `subject`: string;
  `issuer`: string;
  `serialHex`: string;
  `subjectAltName`: string;
  `validFrom`: string;
  `validTo`: string;
  `fingerprint256`: string;
}

@component model `ListenerPool` {
  `min`: int64;
  `max`: int64;
  `current`: int64;
  `busy`: int64;
  `idle`: int64;
  `queued`: int64;
  `completed`: int64;
}

@component model `ListenerStats` {
  `accepted`?: int64;
  `open`?: int64;
  `refused`?: int64;
  `http1`?: int64;
  `http2`?: int64;
  `handshakes`?: int64;
  `handshakeFailures`?: int64;
  @js(#{`description`:"Kept only with all seven members."}) `pool`?: `ListenerPool`;
}

@component model `ReportedListener` {
  @js(#{`pattern`:"^[A-Za-z0-9._-]{1,64}$"}) `id`: string;
  `source`: "environment" | "service";
  `protocol`: "http" | "https";
  `purpose`: "api" | "proxy" | "crl";
  `address`: string;
  @js(#{`minimum`:0,`maximum`:65535}) `port`: int64;
  `state`: "listening" | "waiting" | "failed" | "off";
  `reason`: "none" | "address-in-use" | "permission-denied" | "address-unavailable" | "no-certificate" | "certificate-refused" | "certificate-request-refused" | "proxy-off" | "http-off" | "not-configured" | "crl-only" | "other";
  `renew`: int64;
  `certificate`: `ReportedCertificate` | null;
  `stats`?: `ListenerStats`;
}

@component model `ProcessMemory` {
  `rssBytes`?: int64;
  `virtualBytes`?: int64;
  `dataBytes`?: int64;
  `threads`?: int64;
}

@component model `PathCount` {
  @js(#{`pattern`:"^[A-Z*]{1,16}$"}) `method`: string;
  @js(#{`maxLength`:200,`description`:"The path, its query cut."}) `path`: string;
  `count`: int64;
  `refused`: int64;
}

@component model `ListenersReport` {
  @js(#{`maxItems`:36}) `listeners`: `ReportedListener`[];
  `memory`?: `ProcessMemory`;
  @js(#{`maxItems`:256}) `paths`?: `PathCount`[];
}

@js(#{`description`:"Absent keeps what the service holds; null clears signals, settings and listeners; a value replaces it. The counters are set, not added. A member the PEP's entry stores that carries a value the service cannot hold refuses the whole heartbeat, 400 STS-XACML-0331 naming the member, and nothing of it is recorded: a counter that is not a non-negative integer of at most 2^53 - 1, a text member that is not a string (or null) or carries a control character, or signals, settings or listeners that are not an object or null. Within signals and listeners a value is held to its member instead: a count that is not a non-negative integer is 0, and an age that is not one, or is older than the epoch, is no time."})
@component model `HeartbeatRequest` {
  @js(#{`description`:"Read only when no certificate was presented."}) `name`?: string;
  @js(#{`pattern`:"^[^\\u0000-\\u001f\\u007f-\\u009f]*$",`description`:"The policy set held, empty if none."}) `syncToken`?: string;
  @js(#{`minimum`:0,`maximum`:9007199254740991}) `policyCount`?: int64;
  @js(#{`minimum`:0,`maximum`:9007199254740991}) `decisions`?: int64;
  @js(#{`minimum`:0,`maximum`:9007199254740991}) `allowed`?: int64;
  @js(#{`minimum`:0,`maximum`:9007199254740991}) `refused`?: int64;
  @js(#{`minimum`:0,`maximum`:9007199254740991}) `undischargeable`?: int64;
  @js(#{`pattern`:"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"}) `bias`?: string;
  @js(#{`pattern`:"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"}) `resource`?: string;
  @js(#{`pattern`:"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"}) `version`?: string;
  @js(#{`pattern`:"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"}) `notifyUrl`?: string;
  @js(#{`maxLength`:253}) `hostname`?: string | null;
  `settings`?: `SettingsReport` | null;
  `signals`?: `PepSignals` | null;
  `listeners`?: `ListenersReport` | null;
}

@component model `HeartbeatAnswer` {
  @js(#{`const`:true}) `acknowledged`: boolean;
  `name`: string;
  @js(#{`description`:"The repository's current token, not the PEP's."}) `syncToken`: string;
  @js(#{`description`:"Whether the PEP holds the current policy set: the one member the PEP reads; false makes it pull."})
  `current`: boolean;
  `action`: string;
}

@endpoint("/xacml/pep/heartbeat", "post", #{
  `operationId`:"postHeartbeat",
  `summary`:"Report what this PEP holds and does",
  `description`:"Every PEP_HEARTBEAT_INTERVAL_MS: the policy held, the decision counters, the settings in force, the reverse proxy's receivers and the listeners.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"Acknowledged.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"No name (STS-XACML-0020), a bad hostname (0261) or a value the service cannot hold (0303; see HeartbeatRequest). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"Not registered (STS-XACML-0021).",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}},
    `503`:#{`description`:"No embedded directory in this process (STS-XACML-0026): server_error.",`content`:#{`application/json`:#{`schema`:null}}},
    `507`:#{`description`:"The directory refused the write (STS-XACML-0027): server_error.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postHeartbeat`(`requestBody/content/application~1json/schema`: `HeartbeatRequest`,
  `responses/200/content/application~1json/schema`: `HeartbeatAnswer`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/404/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/501/content/application~1json/schema`: `Error`,
  `responses/503/content/application~1json/schema`: `Error`,
  `responses/507/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- policies

@component model `PolicyRow` {
  `name`: string;
  `policyId`: string;
  `kind`: "Policy" | "PolicySet";
  `version`: string;
  `combiningAlgId`: string;
  `isRoot`: boolean;
  `description`: string;
  @js(#{`description`:"The XACML 3.0 Policy or PolicySet, as XML."}) `document`: string;
}

@component model `PolicySet` {
  `syncToken`: string;
  @js(#{`description`:"The root policy's name. Not read by the PEP, which uses isRoot."}) `root`: string | null;
  @js(#{`description`:"Only when root is null."}) `rootNote`?: string;
  @js(#{`description`:"Every enabled policy but those withheld."}) `policies`: `PolicyRow`[];
  @js(#{`description`:"Names withheld from PEPs: the access and issuance policies and every policy an application owns."})
  `withheld`: string[];
  `note`: string;
}

@endpoint("/xacml/pep/policies", "get", #{
  `operationId`:"getPolicies",
  `summary`:"Pull the policy repository",
  `description`:"Every PEP_POLL_INTERVAL_MS, on a nudge, and when a heartbeat says the PEP is not current.",
  `parameters`:#[
    #{`name`:"since",`in`:"query",`required`:false,`description`:"The token held; equal to the current one answers 304.",`schema`:#{`type`:"string"}},
    #{`name`:"If-None-Match",`in`:"header",`required`:false,`description`:"The ETag held; a match (weak comparison, a list, or *) answers 304.",`schema`:#{`type`:"string"}},
    #{`name`:"pep",`in`:"query",`required`:false,`description`:"The register name, read only when no certificate was presented; with one, the certificate's name (as register's) is the row whose last-seen time a pull touches, whatever this says.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `200`:#{`description`:"The policies. ETag: \"<syncToken>\".",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `304`:#{`description`:"Unchanged. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}}},
    `400`:#{`description`:"A control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getPolicies`(`responses/200/content/application~1json/schema`: `PolicySet`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/501/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- AuthZEN

@component model `CatalogueRow` {
  `object`: "subject" | "resource" | "action" | "context";
  @js(#{`description`:"A dotted path of at most six segments of [A-Za-z0-9_$@:-]{1,64}."}) `property`: string;
  `attributeId`: string;
  `category`: string;
  `dataType`: string;
  `multiplicity`: "single" | "bag";
  @js(#{`maxLength`:500,`description`:"Only when not empty."}) `description`?: string;
}

@component model `AuthzenSettings` {
  `enabled`: boolean;
  `resolveSubjectTypes`: string[];
  `batchEnabled`: boolean;
  @js(#{`minimum`:1,`maximum`:1000}) `maxEvaluations`: int64;
  @js(#{`minimum`:1024,`maximum`:5242880}) `maxBodyBytes`: int64;
  `returnReasons`: boolean;
  @js(#{`description`:"The realm's authzen.obligationsProfile. Absent on an older catalogue is read as off: the edge hands no obligation."})
  `obligationsProfile`: boolean;
  @js(#{`description`:"The realm's authzen.tokenExchange: on, the edge answers 403 (STS-XPEP-0140, a PEP failure) to every tuple the service answers by the binding's fixed rules. Absent on an older catalogue is read as on."})
  `tokenExchange`: boolean;
  @js(#{`description`:"The authorization_details types the realm's applications declare, which make a tuple beside a token-exchange gate a detail tuple. null when the service could not read them (STS-AUTHZEN-0145); null or absent, every other resource type beside a gate is read as one."})
  `tokenExchangeDetailTypes`: string[] | null;
  @js(#{`description`:"The token types a token-exchange gate (issue:<token type>:token_exchange) may name. Absent, every well-formed one is read as registered."})
  `tokenExchangeTokenTypes`: string[];
}

@component model `AuthzenCatalogue` {
  `syncToken`: string;
  @js(#{`description`:"The realm's id; empty for the default realm."}) `realm`: string;
  @js(#{`description`:"sts-authzen-api when the realm has the API's resource object."}) `apiObject`: "sts-authzen-api" | null;
  `rows`: `CatalogueRow`[];
  @js(#{`description`:"Rows left out of the catalogue (STS-AUTHZEN-0060)."}) `leftOut`: int64;
  `settings`: `AuthzenSettings`;
  @js(#{`description`:"Applications enforcing fine-grained authorization, whose evaluations the PEP forwards; each non-empty, at most 256 characters, or the PEP refuses the whole catalogue."})
  `fgaApplications`?: string[];
  `note`: string;
}

@endpoint("/xacml/pep/authzen-catalogue", "get", #{
  `operationId`:"getAuthzenCatalogue",
  `summary`:"Pull the realm's AuthZEN attribute catalogue",
  `parameters`:#[
    #{`name`:"since",`in`:"query",`required`:false,`schema`:#{`type`:"string"}},
    #{`name`:"If-None-Match",`in`:"header",`required`:false,`description`:"The ETag held; a match (weak comparison, a list, or *) answers 304.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `200`:#{`description`:"The catalogue. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `304`:#{`description`:"Unchanged. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}}},
    `400`:#{`description`:"A control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"The fine-grained authorization applications could not be read (STS-FGA-0108); answered before since or If-None-Match is compared.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getAuthzenCatalogue`(`responses/200/content/application~1json/schema`: `AuthzenCatalogue`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

@component model `CallerCertificate` {
  @js(#{`description`:"64 hex digits; colons allowed."}) `sha256`: string;
  @js(#{`description`:"Not read by the PEP."}) `source`: "stored" | "issued";
}

@component model `EdgeCaller` {
  @js(#{`description`:"The caller's verified DN."}) `name`: string;
  @js(#{`minItems`:1,`maxItems`:64}) `certificates`: `CallerCertificate`[];
  @js(#{`maxItems`:64}) `applications`: string[];
  `endpoints`: ("evaluation" | "evaluations")[];
}

@component model `CallerCounts` {
  `members`: int64;
  `read`: int64;
  `unlocated`: int64;
  `unnamed`: int64;
  `notAdmitted`: int64;
  `unreadable`: int64;
}

@component model `AuthzenCallers` {
  `syncToken`: string;
  `realm`: string;
  @js(#{`description`:"The realm's authzen.callerAuthentication. The edge admits callers only when it is mtls."})
  `door`: "mtls" | "bearer" | "mtls+bearer";
  @js(#{`const`:"AUTHZEN_PEPS"}) `role`: string;
  `group`: string;
  @js(#{`description`:"Sorted by name; empty unless door is mtls."}) `callers`: `EdgeCaller`[];
  `truncated`: boolean;
  `counts`: `CallerCounts`;
  `note`: string;
}

@endpoint("/xacml/pep/authzen-callers", "get", #{
  `operationId`:"getAuthzenCallers",
  `summary`:"Pull who may ask the AuthZEN edge PDP",
  `parameters`:#[
    #{`name`:"since",`in`:"query",`required`:false,`schema`:#{`type`:"string"}},
    #{`name`:"If-None-Match",`in`:"header",`required`:false,`description`:"The ETag held; a match (weak comparison, a list, or *) answers 304.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `200`:#{`description`:"The callers. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `304`:#{`description`:"Unchanged. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}}},
    `400`:#{`description`:"A control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getAuthzenCallers`(`responses/200/content/application~1json/schema`: `AuthzenCallers`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/501/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- proxy

@component model `RouteAuthorization` {
  `kind`: "policy" | "simple" | "public";
  @js(#{`pattern`:"^[A-Za-z0-9._-]{1,128}$"}) `policy`: string;
  @js(#{`description`:"Empty: the normalised path."}) `resource`: string;
  `actionModel`: "method" | "crud" | "read-write";
  @js(#{`description`:"The roles each action of the model needs, at most 8 each: create, read, update, delete for crud; read, write for read-write."})
  `roles`: Record<string[]>;
}

@component model `IdentityHeader` {
  @js(#{`description`:"An HTTP token, not a reserved header."}) `name`: string;
  `claim`: "sub" | "username" | "email" | "name" | "given_name" | "family_name" | "groups" | "mechanism" | "acr" | "amr";
}

@component model `RouteIdentity` {
  `mode`: "headers" | "saml" | "jwt";
  @js(#{`maxItems`:16}) `headers`: `IdentityHeader`[];
  @js(#{`minLength`:1,`maxLength`:1,`default`:","}) `separator`: string;
}

@js(#{`description`:"What the service resolved for a route. When not usable, why and code (STS-XACML-0217 to 0223, 0228: the one error code this surface sends)."})
@component model `RouteResolution` {
  `usable`: boolean;
  `why`?: string;
  `code`?: string;
  @js(#{`description`:"An oauth2 route's accepted audiences."}) `audiences`?: string[];
  `samlAudience`?: string;
  @js(#{`description`:"A session route's client."}) `clientId`?: string;
}

@component model `ProxyRoute` {
  @js(#{`pattern`:"^[A-Za-z0-9._-]{1,64}$"}) `id`: string;
  @js(#{`pattern`:"^/",`description`:"Never /.iya-pep or under /.iya-pep/, which the proxy keeps (STS-XACML-0300 at the save; a stored one makes the pull configured: false)."}) `path`: string;
  `match`: "prefix" | "exact";
  @js(#{`description`:"Empty denies every method."}) `methods`: ("GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS")[];
  `mechanisms`: ("session" | "oauth2" | "saml2" | "basic")[];
  @js(#{`description`:"Empty on a public route."}) `application`: string;
  `authorization`: `RouteAuthorization`;
  `identity`: `RouteIdentity`;
  `forwardCredentials`: boolean;
  `signals`: boolean;
  @js(#{`description`:"Only with session."}) `multipleAccounts`: boolean;
  `resolved`: `RouteResolution`;
}

@component model `ProxyDocument` {
  `enabled`: boolean;
  @js(#{`description`:"An absolute http(s) URL with no userinfo, query or fragment."}) `upstream`: string;
  @js(#{`description`:"An origin or empty; https when any route uses session."}) `publicBaseUrl`: string;
  @js(#{`minimum`:1,`maximum`:120000,`default`:10000}) `upstreamTimeoutMs`: int64;
  @js(#{`minimum`:0,`maximum`:104857600,`default`:1048576}) `maxBodyBytes`: int64;
  @js(#{`maxItems`:64}) `routes`: `ProxyRoute`[];
}

@component model `SessionClient` {
  @js(#{`description`:"The application client's secret, in the clear: the PEP is its relying party."})
  `clientSecret`: string;
  `tokenEndpointAuthMethod`: "client_secret_basic" | "client_secret_post";
  `redirectUri`: string;
  `scopes`: string[];
}

@component model `RealmFacts` {
  `issuer`: string;
  `jwksUri`: string;
  @js(#{`description`:"Not read: the PEP discovers it from issuer."}) `authorizationEndpoint`: string;
  @js(#{`description`:"Not read: the PEP discovers it from issuer."}) `tokenEndpoint`: string;
  @js(#{`description`:"Not read: the PEP discovers it from issuer."}) `endSessionEndpoint`: string;
  `samlIssuer`: string;
  @js(#{`description`:"PEM certificates."}) `signingCertificates`: string[];
  @js(#{`description`:"PEM, leaf to Root."}) `tlsCaChain`: string;
  @js(#{`description`:"By client id: each session route's client."}) `clients`: Record<`SessionClient`>;
  @js(#{`description`:"Cookies of the service's the proxy strips upstream; absent or null is the built-in list."})
  `serviceCookiePrefixes`?: string[] | null;
}

@component model `ValidationUrls` {
  `introspect`: string;
  `basic`: string;
  `saml`: string;
  `session`: string;
  `identity`: string;
}

@js(#{`description`:"configured false: note alone. configured true: proxy, realm and validation. A cluster member gets its cluster's document."})
@component model `ProxyPull` {
  `syncToken`: string;
  `pep`: string;
  `configured`: boolean;
  `note`?: string;
  `proxy`?: `ProxyDocument`;
  `realm`?: `RealmFacts`;
  `validation`?: `ValidationUrls`;
}

@endpoint("/xacml/pep/proxy", "get", #{
  `operationId`:"getProxy",
  `summary`:"Pull the reverse proxy's configuration",
  `description`:"Pulled only while PEP_PROXY is on.",
  `parameters`:#[
    #{`name`:"since",`in`:"query",`required`:false,`schema`:#{`type`:"string"}},
    #{`name`:"name",`in`:"query",`required`:false,`description`:"Read only when no certificate was presented; the PEP does not send it.",`schema`:#{`type`:"string"}},
    #{`name`:"If-None-Match",`in`:"header",`required`:false,`description`:"The ETag held; a match (weak comparison, a list, or *) answers 304.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `200`:#{`description`:"The configuration. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `304`:#{`description`:"Unchanged. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}}},
    `400`:#{`description`:"A control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getProxy`(`responses/200/content/application~1json/schema`: `ProxyPull`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/501/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- settings

@js(#{`description`:"Only the keys an administrator set. A notifyUrl that is not https is held and refused by the PEP."})
@component model `ManagedSettings` {
  @js(#{`maxLength`:1024}) `description`?: string;
  @js(#{`maxLength`:2048}) `resource`?: string;
  @js(#{`maxLength`:2048}) `notifyUrl`?: string;
  `bias`?: "deny-biased" | "permit-biased";
  `pip`?: boolean;
  @js(#{`minimum`:1000,`maximum`:86400000}) `pollIntervalMs`?: int64;
  @js(#{`minimum`:1000,`maximum`:86400000}) `heartbeatIntervalMs`?: int64;
  @js(#{`minimum`:1000,`maximum`:86400000}) `backoffMaxMs`?: int64;
  @js(#{`minimum`:100,`maximum`:120000}) `timeoutMs`?: int64;
  @js(#{`minimum`:1024,`maximum`:104857600}) `maxBodyBytes`?: int64;
  @js(#{`minimum`:1000,`maximum`:3600000}) `httpsReloadIntervalMs`?: int64;
  `logLevel`?: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
  `authzen`?: boolean;
  @js(#{`description`:"An https origin."}) `authzenPdpIdentifier`?: string;
  @js(#{`minimum`:1,`maximum`:120000}) `authzenForwardTimeoutMs`?: int64;
  @js(#{`minimum`:0,`maximum`:3600000}) `proxySessionRecheckMs`?: int64;
  @js(#{`minimum`:1000,`maximum`:2592000000}) `proxySessionTtlMs`?: int64;
  @js(#{`minimum`:1,`maximum`:1000000}) `proxyMaxSessions`?: int64;
  @js(#{`minimum`:1,`maximum`:32}) `proxyMaxAccounts`?: int64;
  @js(#{`minimum`:0,`maximum`:86400000}) `proxyJwksTtlMs`?: int64;
  @js(#{`description`:"Refused true in product mode."}) `proxyUpstreamInsecure`?: boolean;
  @js(#{`description`:"Refused true in product mode."}) `proxyRpAllowInsecure`?: boolean;
  @js(#{`minimum`:100,`maximum`:3600000}) `proxySignalsPollMs`?: int64;
  @js(#{`minimum`:1,`maximum`:86400000}) `proxySignalsStaleMs`?: int64;
  @js(#{`maxLength`:1024}) `proxyStripCookies`?: string;
  @js(#{`description`:"PEP_AUDIT: whether this PEP sends its decision records to the service's audit log (#1827)."}) `auditEnabled`?: boolean;
  @js(#{`minimum`:1000,`maximum`:86400000}) `auditIntervalMs`?: int64;
  @js(#{`minimum`:1,`maximum`:500}) `auditBatch`?: int64;
  @js(#{`minimum`:1,`maximum`:1000000}) `auditBuffer`?: int64;
}

@component model `ListenerTuning` {
  `minVersion`: "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";
  `disableTls12`: boolean;
  `ciphers`: string;
  `tls13CipherSuites`: string;
  `pqcOnly`: boolean;
  `groups`: string;
  `signatureAlgorithms`: string;
  `trustAnchorsFile`: string;
  `trustIssuedClientCertificates`: boolean;
  `askClientCertificate`: boolean;
  `requireClientCertificate`: boolean;
  @js(#{`minimum`:1,`maximum`:86400}) `sessionTimeoutS`: int64;
  @js(#{`minimum`:0,`maximum`:1000000}) `sessionCacheSize`: int64;
  @js(#{`minimum`:1,`maximum`:3600}) `keepAliveTimeoutS`: int64;
  @js(#{`minimum`:0,`maximum`:3600}) `headersTimeoutS`: int64;
  @js(#{`minimum`:0,`maximum`:1000000}) `maxRequestsPerSocket`: int64;
  @js(#{`minimum`:0,`maximum`:1000000}) `maxConnections`: int64;
  `http2`: boolean;
  @js(#{`minimum`:1,`maximum`:1000}) `http2MaxConcurrentStreams`: int64;
  `threadPoolMin`: int64;
  `threadPoolMax`: int64;
}

@component model `ListenerDefinition` {
  @js(#{`pattern`:"^[A-Za-z0-9._-]{1,64}$",`description`:"Not one of the four environment listeners' ids."}) `id`: string;
  `protocol`: "http" | "https";
  `purpose`: "api" | "proxy";
  @js(#{`description`:"An IP literal."}) `address`: string;
  @js(#{`minimum`:1,`maximum`:65535}) `port`: int64;
  @js(#{`maxItems`:16}) `dnsNames`: string[];
  @js(#{`maxItems`:16}) `ipAddresses`: string[];
  @js(#{`description`:"https only."}) `keyAlg`?: "ec-p256" | "ec-p384" | "rsa-2048" | "rsa-3072";
  `renew`: int64;
  @js(#{`description`:"The tuning in force, complete."}) `tuning`: `ListenerTuning`;
}

@component model `EnvironmentTuning` {
  `api-http`: `ListenerTuning`;
  `api-https`: `ListenerTuning`;
  `proxy-http`: `ListenerTuning`;
  `proxy-https`: `ListenerTuning`;
}

@js(#{`description`:"configured false: note; configured true: settings. listeners only when at least one is defined; environmentTuning always, unless the stored listeners failed validation (STS-XACML-0252), when neither is sent."})
@component model `SettingsPull` {
  `syncToken`: string;
  @js(#{`description`:"Not read by the PEP."}) `pep`: string;
  `configured`: boolean;
  `settings`?: `ManagedSettings`;
  `note`?: string;
  `listeners`?: `ListenerDefinition`[] | null;
  `environmentTuning`?: `EnvironmentTuning`;
}

@endpoint("/xacml/pep/settings", "get", #{
  `operationId`:"getSettings",
  `summary`:"Pull the managed settings and listeners",
  `description`:"A 404 is a service older than #1760: the PEP puts its environment in force (STS-XPEP-0101).",
  `parameters`:#[
    #{`name`:"since",`in`:"query",`required`:false,`schema`:#{`type`:"string"}},
    #{`name`:"name",`in`:"query",`required`:false,`description`:"Read only when no certificate was presented; the PEP does not send it.",`schema`:#{`type`:"string"}},
    #{`name`:"If-None-Match",`in`:"header",`required`:false,`description`:"The ETag held; a match (weak comparison, a list, or *) answers 304.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `200`:#{`description`:"The settings. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `304`:#{`description`:"Unchanged. ETag.",`headers`:#{`ETag`:#{`schema`:#{`type`:"string"}}}},
    `400`:#{`description`:"A control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `getSettings`(`responses/200/content/application~1json/schema`: `SettingsPull`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/501/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- listener certificate

@component model `ListenerCertificateRequest` {
  @js(#{`description`:"A defined https listener of this PEP."}) `listener`: string;
  @js(#{`description`:"PKCS #10, PEM or base64 DER; its key one of the listener's keyAlg values."}) `csr`: string;
  @js(#{`description`:"Read only when no certificate was presented; the PEP does not send it."}) `name`?: string;
}

@component model `ListenerCertificate` {
  `pep`: string;
  `listener`: string;
  `renew`: int64;
  @js(#{`description`:"False when the certificate held was answered again."}) `issued`: boolean;
  `serialHex`: string;
  `notBefore`: string;
  `notAfter`: string;
  `replacedSerialHex`: string | null;
  `certificatePem`: string;
  @js(#{`description`:"Leaf to Root, each PEM ending in a newline: the one member the PEP reads."}) `fullChainPem`: string;
}

@endpoint("/xacml/pep/listener-certificate", "post", #{
  `operationId`:"postListenerCertificate",
  `summary`:"Have a defined HTTPS listener's certificate issued",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"Issued, or the one held.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"Not a defined https listener of this PEP (STS-XACML-0253), or a bad CSR or key (0254). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `404`:#{`description`:"Not registered (STS-XACML-0253).",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: too_many_requests, Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"Issuance failed (STS-XACML-0255).",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postListenerCertificate`(`requestBody/content/application~1json/schema`: `ListenerCertificateRequest`,
  `responses/200/content/application~1json/schema`: `ListenerCertificate`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/404/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- validation doors

@component model `IntrospectRequest` {
  @js(#{`minLength`:1,`maxLength`:16384}) `token`: string;
  `name`?: string;
}

@js(#{`description`:"active false alone, or active true with the RFC 7662 members that are not null."})
@component model `Introspection` {
  `active`: boolean;
  `sub`?: string;
  `username`?: string;
  `scope`?: string;
  `client_id`?: string;
  `aud`?: string | string[];
  `iss`?: string;
  `exp`?: numeric;
  `iat`?: numeric;
  `token_type`?: string;
  @js(#{`$apTrue`:true,`$noProps`:true}) `cnf`?: {};
}

@component model `BasicRequest` {
  @js(#{`minLength`:1,`maxLength`:256}) `username`: string;
  @js(#{`maxLength`:1024}) `password`: string;
  `name`?: string;
}

@js(#{`description`:"valid false alone, or valid true with username, sub and a ticket: opaque, bound to this PEP, good for 120 s, the evidence the identity door takes."})
@component model `BasicValidation` {
  `valid`: boolean;
  `username`?: string;
  `sub`?: string;
  `ticket`?: string;
}

@js(#{`description`:"A refusal for now, from every validation door: the doors' shared limiter (STS-XACML-0215), or basic's lockout of the account (0205). The wait is retryAfterS, and the Retry-After header."})
@component model `TooManyRequests` {
  `error`: "too_many_requests";
  `error_description`: string;
  @js(#{`minimum`:1}) `retryAfterS`: int64;
}

@component model `SamlRequest` {
  @js(#{`maxLength`:524288,`description`:"The assertion's XML, base64; at most 262144 bytes decoded."}) `assertion`: string;
  @js(#{`maxLength`:1024,`description`:"The route's resolved.samlAudience."}) `audience`: string;
  `name`?: string;
}

@js(#{`description`:"valid false alone (the reason audited: STS-XACML-0208 to 0213), or valid true with the assertion's subject and its facts."})
@component model `SamlValidation` {
  `valid`: boolean;
  @js(#{`description`:"The NameID."}) `subject`?: string;
  `username`?: string;
  `issuer`?: string;
  `notOnOrAfter`?: string;
  `sessionIndex`?: string;
}

@component model `SessionRequest` {
  @js(#{`minLength`:1,`maxLength`:512}) `sid`: string;
  `name`?: string;
}

@component model `SessionLiveness` {
  `live`: boolean;
  `sub`?: string;
  `username`?: string;
  @js(#{`description`:"Only when it differs from username."}) `name`?: string;
}

@component model `IdentityEvidence` {
  `kind`: "access_token" | "saml_assertion" | "ticket";
  @js(#{`minLength`:1,`maxLength`:524288}) `value`: string;
}

@js(#{`description`:"Closed: any other member is 400 STS-XACML-0229."})
@component model `IdentityRequest` {
  @js(#{`minLength`:1,`maxLength`:64,`description`:"A non-public route of this PEP's own proxy document."}) `route`: string;
  `evidence`: `IdentityEvidence`;
  @js(#{`maxItems`:16,`description`:"headers mode only: claims the route's headers name."})
  `claims`?: ("sub" | "username" | "email" | "name" | "given_name" | "family_name" | "groups" | "mechanism" | "acr" | "amr")[];
  `name`?: string;
}

@js(#{`description`:"By the route's identity.mode. headers: claims (groups and amr are lists; a claim with no value is left out). jwt: accessToken, tokenType and expiresIn. saml: samlResponse, acsUrl and notOnOrAfter."})
@component model `IdentityAnswer` {
  `claims`?: Record<string | string[]>;
  `accessToken`?: string;
  `tokenType`?: "Bearer";
  `expiresIn`?: int64;
  @js(#{`description`:"The SAML Response's XML, base64."}) `samlResponse`?: string;
  `acsUrl`?: string;
  `notOnOrAfter`?: string;
}

@endpoint("/xacml/pep/introspect", "post", #{
  `operationId`:"postIntrospect",
  `summary`:"Validation door: an access token (RFC 7662)",
  `description`:"The oauth2 mechanism, after the PEP's own JWS check. Rate-limited per address and DN by xacml.pipMaxPerWindow (429 STS-XACML-0215, Retry-After) before the gate; any throw is 500 STS-XACML-0216.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"The token's reading.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"No token, or too long (STS-XACML-0207). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"The limiter (STS-XACML-0215). Or over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"STS-XACML-0216.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postIntrospect`(`requestBody/content/application~1json/schema`: `IntrospectRequest`,
  `responses/200/content/application~1json/schema`: `Introspection`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

@endpoint("/xacml/pep/basic", "post", #{
  `operationId`:"postBasic",
  `summary`:"Validation door: a username and password",
  `description`:"The basic mechanism. The same limiter and failure as introspect; a password the service has locked out is 429 too (STS-XACML-0205), the same body as the limiter's.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"Valid or not; the reason is audited (STS-XACML-0206).",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"Malformed (STS-XACML-0204). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"Locked out (STS-XACML-0205), or the limiter (0215): one shape either way. Retry-After. Or over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"STS-XACML-0216.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postBasic`(`requestBody/content/application~1json/schema`: `BasicRequest`,
  `responses/200/content/application~1json/schema`: `BasicValidation`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

@endpoint("/xacml/pep/saml", "post", #{
  `operationId`:"postSaml",
  `summary`:"Validation door: a SAML 2.0 assertion",
  `description`:"The saml2 mechanism, after the PEP's own check. The same limiter and failure as introspect.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"Valid or not.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"Malformed (STS-XACML-0208). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"The limiter (STS-XACML-0215). Or over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"STS-XACML-0216.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postSaml`(`requestBody/content/application~1json/schema`: `SamlRequest`,
  `responses/200/content/application~1json/schema`: `SamlValidation`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

@endpoint("/xacml/pep/session", "post", #{
  `operationId`:"postSession",
  `summary`:"Validation door: is a sign-on session live",
  `description`:"The session mechanism, every PEP_PROXY_SESSION_RECHECK_MS when no signal says. The same limiter and failure as introspect.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"Live or ended.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"Malformed (STS-XACML-0214). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate.",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"The limiter (STS-XACML-0215). Or over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"STS-XACML-0216.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postSession`(`requestBody/content/application~1json/schema`: `SessionRequest`,
  `responses/200/content/application~1json/schema`: `SessionLiveness`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

@endpoint("/xacml/pep/identity", "post", #{
  `operationId`:"postIdentity",
  `summary`:"Validation door: the identity to deliver upstream",
  `description`:"For a route's identity.mode: the claims for its headers, a service-issued access token, or a SAML Response for the application's ACS. The same limiter and failure as introspect.",
  `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"The identity.",`content`:#{`application/json`:#{`schema`:null}}},
    `400`:#{`description`:"Malformed, or claims the route does not name (STS-XACML-0229). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/json`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `403`:#{`description`:"The gate; not one of this PEP's non-public routes (STS-XACML-0230); the evidence invalid or not for the application (0231); the ticket unknown, expired or another PEP's (0232); the issuance policy refused (0234).",`content`:#{`application/json`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/json`:#{`schema`:null}}},
    `422`:#{`description`:"The route not usable, no SAML entity ID or no directory entry (STS-XACML-0233); issuance failed (0235).",`content`:#{`application/json`:#{`schema`:null}}},
    `429`:#{`description`:"The limiter (STS-XACML-0215). Or over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `500`:#{`description`:"STS-XACML-0216.",`content`:#{`application/json`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off.",`content`:#{`application/json`:#{`schema`:null}}}
  }
})
op `postIdentity`(`requestBody/content/application~1json/schema`: `IdentityRequest`,
  `responses/200/content/application~1json/schema`: `IdentityAnswer`,
  `responses/400/content/application~1json/schema`: `Error`,
  `responses/401/content/application~1json/schema`: `Error`,
  `responses/403/content/application~1json/schema`: `Error`,
  `responses/413/content/application~1json/schema`: `Error`,
  `responses/415/content/application~1json/schema`: `Error`,
  `responses/422/content/application~1json/schema`: `Error`,
  `responses/429/content/application~1json/schema`: `TooManyRequests`,
  `responses/500/content/application~1json/schema`: `Error`,
  `responses/501/content/application~1json/schema`: `Error`): void;

// ---------------------------------------------------------------- PIP

@js(#{`$raw`:#{`type`:"string",`contentMediaType`:"application/xml",`description`:"A PIPRequest in urn:sts:xacml:pip:1.0: one XACML 3.0 core Request (urn:oasis:names:tc:xacml:3.0:core:schema:wd-17) whose access-subject category carries subject-id (IncludeInResult true) and, for an application, urn:sts:xacml:subject-kind; then 1 to xacml.pipMaxDesignators (50) AttributeDesignator elements in the core namespace, MustBePresent false. No DOCTYPE or ENTITY.",`x-iya-xml`:#{`namespace`:"urn:sts:xacml:pip:1.0",`root`:"PIPRequest"}}})
@component model `PipRequest` {}

@js(#{`$raw`:#{`type`:"string",`contentMediaType`:"application/xml",`description`:"A PIPResponse in urn:sts:xacml:pip:1.0: one XACML core Attributes per category asked (only access-subject is ever resolved), each Attribute (IncludeInResult false) with one or more AttributeValue; an empty bag is an absent Attribute. Then, if any, Unresolved holding a Designator (Category, AttributeId, DataType, MustBePresent) with a Reason for each designator not resolved.",`x-iya-xml`:#{`namespace`:"urn:sts:xacml:pip:1.0",`root`:"PIPResponse"}}})
@component model `PipResponse` {}

@js(#{`$raw`:#{`type`:"string",`contentMediaType`:"application/xml",`description`:"<PIPError xmlns=\"urn:sts:xacml:pip:1.0\" error=\"invalid_request|too_many_requests|access_denied|not_implemented\"><Description>…</Description></PIPError>",`x-iya-xml`:#{`namespace`:"urn:sts:xacml:pip:1.0",`root`:"PIPError"}}})
@component model `PipError` {}

@endpoint("/xacml/pip", "post", #{
  `operationId`:"postPip",
  `summary`:"The policy information point",
  `description`:"Before evaluation the PEP walks the policy for every designator it could be asked about and fetches them all in one request; the answer feeds a synchronous resolver. A subject homed in another cell is relayed there and answered by it. Rate-limited (xacml.pipMaxPerWindow) before the gate. The PEP reads no refusal: any status but 200 is an empty bag for every designator.",
  `requestBody`:#{`required`:true,`content`:#{`application/xml`:#{`schema`:null}}},
  `responses`:#{
    `200`:#{`description`:"The attributes. Cache-Control: no-store.",`content`:#{`application/xml`:#{`schema`:null}}},
    `400`:#{`description`:"Not a well-formed PIPRequest (STS-XACML-0023), too many designators (0024), a value too long (0025). Also a control character in a query value (STS-HTTP-0011) or a parameter named __proto__, constructor or prototype (0010), refused before any endpoint sees it, and a body cut short of its Content-Length (STS-HTTP-0013).",`content`:#{`application/xml`:#{`schema`:null}}},
    `401`:#{`description`:"The token door refused the credential (see the dpop scheme): a DPoP challenge in WWW-Authenticate, the body a PIPError.",`headers`:#{`WWW-Authenticate`:#{`schema`:#{`type`:"string"}},`DPoP-Nonce`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/xml`:#{`schema`:null}}},
    `403`:#{`description`:"The gate (the codes in the document's description), error=\"access_denied\".",`content`:#{`application/xml`:#{`schema`:null}}},
    `413`:#{`description`:"A body over the 5 MB the service reads (STS-HTTP-0004), refused before any endpoint sees it: invalid_request.",`content`:#{`application/xml`:#{`schema`:null}}},
    `415`:#{`description`:"A body in a character set or content encoding the service does not read (STS-HTTP-0012), refused before any endpoint sees it: invalid_request.",`content`:#{`application/xml`:#{`schema`:null}}},
    `429`:#{`description`:"The limiter (STS-XACML-0022). Retry-After. Or over the ceiling on one address's requests (security.requestsPerAddressPerMinute, STS-CORE-0172), refused before any endpoint sees it: Retry-After 60.",`headers`:#{`Retry-After`:#{`schema`:#{`type`:"integer"}}},`content`:#{`application/xml`:#{`schema`:null}}},
    `501`:#{`description`:"XACML or remote PEPs off (STS-XACML-0001, 0002), error=\"not_implemented\".",`content`:#{`application/xml`:#{`schema`:null}}}
  }
})
op `postPip`(`requestBody/content/application~1xml/schema`: `PipRequest`,
  `responses/200/content/application~1xml/schema`: `PipResponse`,
  `responses/400/content/application~1xml/schema`: `PipError`,
  `responses/401/content/application~1xml/schema`: `PipError`,
  `responses/403/content/application~1xml/schema`: `PipError`,
  `responses/413/content/application~1xml/schema`: `PipError`,
  `responses/415/content/application~1xml/schema`: `PipError`,
  `responses/429/content/application~1xml/schema`: `PipError`,
  `responses/501/content/application~1xml/schema`: `PipError`): void;

}
