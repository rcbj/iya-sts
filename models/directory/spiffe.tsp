// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/spiffe.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `spiffe/spiffe_registry.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "spiffe",
  source: "../spiffe/spiffe_registry",
  container: "ou=spiffe",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "top",
      where: "RFC 4512",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "applicationProcess",
      where: "RFC 4519 section 3.3",
      standard: true,
      what: "The one REGISTERED class that fits: it brings cn and description, so the NAME of a registration entry is a standard attribute even though nothing else about it can be. The same class ou=applications uses, for the same reason."
    },
    #{
      name: "spiffeRegistrationEntry",
      where: "this service",
      standard: false,
      what: "INVENTED. No registered LDAP schema has a SPIFFE ID, a parent ID or a selector — SPIRE keeps its entries in SQL and nothing else keeps them anywhere — so there was nothing to borrow."
    },
    #{
      name: "spiffeAgent",
      where: "this service",
      standard: false,
      what: "INVENTED, for the same reason, on the entries under ou=agents."
    }
  ]
})
model Spiffe {
  // --- identity ---------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "THE KEY: the entry id, which is what the SPIRE Server API calls `id` and what BatchUpdateEntry and BatchDeleteEntry name. Generated here as 32 hex characters and never reused. The entry's own cn is a shortened form of it, so this is the attribute to search on — the arrangement appIdentifier already has one container over."
  })
  spiffeEntryId?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    standard: true,
    editable: false,
    what: "The RDN value: the entry id."
  })
  cn?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "THE IDENTITY THIS ENTRY GRANTS — the SPIFFE ID a matching workload is issued. Refused if it is not a valid SPIFFE ID, if it belongs to another trust domain, or if it is under the reserved /spire path."
  })
  spiffeId?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "WHO MAY ISSUE IT: the SPIFFE ID of the agent (or of this server) that this entry hangs beneath. It decides which entries GetAuthorizedEntries and SyncAuthorizedEntries tell an agent about: those beneath its own SPIFFE ID or a node alias its selectors match, and BatchNewX509SVID and NewJWTSVID refuse an agent any other entry."
  })
  spiffeParentId?: string;
  @attr(#{
    kind: "multi",
    from: "the caller",
    editable: true,
    what: "One value per selector, written `type:value` — `unix:uid:1000`, `k8s:ns:default`, `docker:label:app:web`. The type is everything before the FIRST colon and the value is the whole rest, colons included, which is why they are stored as one string rather than as a pair: splitting on every colon is how `docker:label:app:web` becomes a selector nobody wrote."
  })
  spiffeSelector?: string[];
  // --- what gets issued -------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "The lifetime in seconds of the X509-SVIDs this entry produces. Absent or 0 means spiffe.svidTtl."
  })
  spiffeX509SvidTtl?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "The same for JWT-SVIDs. Absent or 0 means spiffe.jwtSvidTtl."
  })
  spiffeJwtSvidTtl?: string;
  @attr(#{
    kind: "multi",
    from: "the caller",
    editable: true,
    what: "DNS subjectAltNames added to the SVID beside the SPIFFE ID. What makes an SVID usable by TLS software that checks a hostname and cannot read a SPIFFE ID."
  })
  spiffeDnsName?: string[];
  @attr(#{
    kind: "multi",
    from: "the caller",
    editable: true,
    what: "Trust domain names whose bundles are handed to a workload holding this identity — X509SVIDResponse.federated_bundles. A name with no bundle here is recorded and simply contributes nothing, because a federation relationship configured before the bundle arrives is the ordinary order of events."
  })
  spiffeFederatesWith?: string[];
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "The operator's guidance when a workload gets more than one SVID — `internal`, `external`. Passed through to the Workload API verbatim; nothing here reads it."
  })
  spiffeHint?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "TRUE where the holder may call the SPIRE Server API's administrative methods — entries, agents, bundles, federation relationships, minting an SVID — over mutual TLS. ENFORCED in both modes: the server API makes a caller `admin` when an unexpired entry for its identity carries this flag or spiffe.adminIds names it, and refuses those methods to a remote caller that is neither (the private Unix socket's `local` caller is the other way in). Read on every call, so a change applies to the next one."
  })
  spiffeAdmin?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "TRUE where the holder is a downstream SPIRE server that may ask for an intermediate CA (NewDownstreamX509CA) and publish a JWT or WIT authority. ENFORCED in both modes: those methods are refused to a caller no unexpired entry marks downstream, and the flag grants nothing else."
  })
  spiffeDownstream?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "TRUE where the SVID is to be written to an SVID store plugin rather than handed to the workload. Recorded and not acted on — this service has no store plugins."
  })
  spiffeStoreSvid?: string;
  @attr(#{
    kind: "single",
    from: "the caller",
    editable: true,
    what: "When the ENTRY itself stops applying, as seconds since the epoch. Different from an SVID lifetime: this retires the registration. An expired entry is kept and reported as expired rather than deleted, because an entry that vanished is indistinguishable from one nobody created."
  })
  spiffeEntryExpiresAt?: string;
  // --- what has happened ------------------------------------------------
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "Incremented on every change. The SPIRE Server API publishes it and an agent uses it to tell \"the entry I hold is current\" from \"I hold an entry\"."
  })
  spiffeRevisionNumber?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "How this entry got here: `seed`, `console`, `api`, `grpc`, `auto` (invented for a workload that matched nothing) or `ldap`. What tells an invented entry from one somebody meant."
  })
  spiffeOrigin?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "How many SVIDs have been issued against this entry. ASSIGNED on every change — a counter that accumulated values would be nonsense — and a live number in a directory entry, which a real directory would not hold."
  })
  spiffeSvidsIssued?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "GeneralizedTime, the most recent issuance against it."
  })
  spiffeLastSvidAt?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "GeneralizedTime. Beside the entry's own createTimestamp because the SPIRE Server API publishes `created_at` as a number and a reader should be able to see both are the same moment."
  })
  spiffeCreatedAt?: string;
  @attr(#{
    kind: "multi",
    from: "this registry",
    standard: true,
    editable: false,
    what: "One line saying where this entry came from."
  })
  description?: string[];
  // --- agents (ou=agents) -----------------------------------------------
  @attr(#{
    kind: "single",
    from: "the agent",
    editable: false,
    what: "THE KEY of an agent entry: the agent's own SPIFFE ID, always under the reserved /spire/agent path."
  })
  spiffeAgentId?: string;
  @attr(#{
    kind: "single",
    from: "the agent",
    editable: false,
    what: "The node attestor that verified the agent — `join_token`, and the other types a realm names in spiffe.nodeAttestors. A type no attestor here verifies is refused at AttestAgent, never recorded."
  })
  spiffeAttestationType?: string;
  @attr(#{
    kind: "multi",
    from: "the agent",
    editable: false,
    what: "The selectors the attestation produced. Invented from what the agent sent, for the same reason."
  })
  spiffeAgentSelector?: string[];
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "TRUE where BanAgent was called. A banned agent is REFUSED at AttestAgent and RenewAgent — one of the few refusals in this service — because an unbannable agent makes the ban button a lie."
  })
  spiffeAgentBanned?: string;
  @attr(#{
    kind: "single",
    from: "the agent",
    editable: false,
    what: "Whether the attestor can be run again without an operator. Reported to the agent, which decides what to do about it."
  })
  spiffeAgentCanReattest?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "SHA-256 over the DER of the agent's current SVID, which is what spire.api.types.Agent carries and how an operator tells two agents with one identity apart."
  })
  spiffeAgentSvidHash?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "When that SVID expires, as seconds since the epoch."
  })
  spiffeAgentExpiresAt?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "GeneralizedTime, when this agent first attested."
  })
  spiffeFirstSeen?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "GeneralizedTime, the most recent time."
  })
  spiffeLastSeen?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    editable: false,
    what: "How many times it has attested or renewed. ASSIGNED, not accumulated."
  })
  spiffeAttestations?: string;
}
