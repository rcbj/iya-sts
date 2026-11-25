// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/xacml_pep.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `xacml/xacml_pep_registry.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "xacmlPep",
  source: "../xacml/xacml_pep_registry",
  container: "ou=peps",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "xacmlPep",
      what: "One remote Policy Enforcement Point that has registered with this Policy Decision Point. THE ROW IS A RECORD AND NOT A PERMISSION — a PEP that never registers can still pull the repository and enforce. What a row buys is a place on the console and an address for the change nudge."
    }
  ]
})
model XacmlPep {
  @attr(#{
    kind: "single",
    what: "The DN certificatePlan() names this certificate's identity with. NO ENTRY IS CREATED THERE by a registration — the naming rule is reused, not the entry creation, because a PEP is a component and ou=users counts people."
  })
  xacmlPepIdentity?: string;
  @attr(#{
    kind: "single",
    what: "The full subject of the client certificate the registration arrived on. Held whole beside the DN because the DN is the LEAF and this is what was actually presented."
  })
  xacmlPepCertificateSubject?: DirectoryDn;
  @attr(#{
    kind: "single",
    what: "RFC 8705 x5t#S256 of that certificate — the SHA-256 of its DER, base64url. The same computation the token endpoint binds a certificate-bound access token with, through the same function, so the two spellings cannot drift."
  })
  xacmlPepThumbprint?: string;
  @attr(#{
    kind: "single",
    what: "\"TRUE\" when the registration arrived on a connection carrying a client certificate, \"FALSE\" when xacml.pepRequireCertificate was off and it did not. NOT hidden and not conflated: an unauthenticated registration is a row that proved nothing, and the console says so on the row rather than in a footnote."
  })
  xacmlPepAuthenticated?: DirectoryBoolean;
  @attr(#{
    kind: "single",
    what: "Where to POST the change nudge, if the PEP gave one. THE NUDGE IS NEVER THE MECHANISM — a PEP pulls on its own interval and converges without this — so an absent, refused or unreachable URL costs latency and nothing else."
  })
  xacmlPepNotifyUrl?: string;
  @attr(#{
    kind: "single",
    what: "The bias the remote PEP reports it is running with. REPORTED BY IT, never set from here: it is the PEP's own configuration (PEP_BIAS), and a control that appeared to set it would silently do nothing."
  })
  xacmlPepBias?: string;
  @attr(#{
    kind: "single",
    what: "What the remote PEP says it is guarding. Free text from the PEP, shown as its own claim about itself."
  })
  xacmlPepResource?: string;
  @attr(#{
    kind: "single",
    what: "\"TRUE\" or \"FALSE\". A disabled PEP keeps its row and its counters and is not nudged. It does NOT stop enforcing, and the console says so — nothing here can reach into another process and turn it off."
  })
  xacmlPepEnabled?: DirectoryBoolean;
  @attr(#{
    kind: "single",
    what: "When this PEP first registered. Kept across a re-registration, because a component that restarts hourly is a fact worth seeing and an entry whose age reset on every restart could never show it."
  })
  xacmlPepRegisteredAt?: DirectoryTime;
  @attr(#{
    kind: "single",
    what: "The last heartbeat or pull when this entry was last written. A heartbeat that changes nothing durable is not written here (#1882): it, the counters, the signal health and the last nudge are kept beside the entry, and the console shows the later of the two. xacml.pepStaleAfterS is how long since the last one before the console says \"stale\" — which changes nothing this service does, deliberately."
  })
  xacmlPepLastSeen?: DirectoryTime;
  @attr(#{
    kind: "single",
    what: "The repository digest this PEP last reported holding. Compared against syncToken() to decide whether it is CURRENT, so that being up to date is something this service works out rather than something the PEP asserts."
  })
  xacmlPepSyncToken?: string;
  @attr(#{
    kind: "single",
    what: "How many policies the PEP says it loaded from that pull. A count that disagrees with this repository's is the signature of a PEP that pulled successfully and then refused a document."
  })
  xacmlPepPolicyCount?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "Decisions the remote PEP reports having MADE, cumulatively. Its own count, in its own process — this service did not see them, and that is the point of a remote PEP."
  })
  xacmlPepDecisions?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "How many of those it ALLOWED. Beside the decision count rather than derived from it, because the difference between them is what the bias and the obligation rule actually did."
  })
  xacmlPepAllowed?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "How many it REFUSED, including Permits refused for an obligation it could not discharge (section 7.2)."
  })
  xacmlPepRefused?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "How many of those refusals were an undischargeable obligation on a Permit. Counted separately because it is the one enforcement outcome that looks like a bug from the client side and is the specification working."
  })
  xacmlPepUndischargeable?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "What the remote PEP says it is. Free text."
  })
  xacmlPepVersion?: string;
  @attr(#{
    kind: "single",
    what: "The hostname the remote PEP reports on its registration and heartbeat (#1760): the HOSTNAME environment variable, else the kernel's, else /etc/hostname — the name the container is known by on its network, and the one it derives its notify URL from when its HTTPS listener certificate names it. Held to a DNS name of at most 253 characters, lower-cased, never an IP address; a registration or heartbeat carrying anything else is refused (STS-XACML-0261). The realm's default listener certificate names it beside the PEP's registered name and its notify host. A registration without it drops it, a heartbeat without it keeps it. Absent on a PEP older than this, whose certificate names are as before."
  })
  xacmlPepHostname?: string;
  @attr(#{
    kind: "single",
    what: "What happened to the last nudge — the status, or the refusal sentence — when this entry was last written. A nudge's outcome is not written here (#1882): the newest is kept in the PEP's liveness record beside the entry (xacml_pep_registry.liveness), and the console shows the later of the two. This service is the only one that records a failed nudge, for the reason ssf_streams.js gives about a refused push: it is invisible from the receiving end by definition."
  })
  xacmlPepLastNotify?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The reverse-proxy configuration the remote PEP pulls from GET /xacml/pep/proxy (#1760): one JSON document — enabled, the upstream application's base URL, the public base URL a browser reaches the proxy at, the timeouts and the ordered route table, each route with its path, methods, authentication mechanisms, the application in the realm's registry it fronts, and XACML resource and action. Written by the set-pep-proxy action of the console and the management API, validated whole there and again when the pull is built, so a value an ldapmodify wrote that does not validate is pulled as configured: false. Kept across a registration and a heartbeat; removed with the row."
  })
  xacmlPepProxy?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The reverse proxy's CAEP/RISC signal-stream health as the remote PEP last reported it on a heartbeat (#1760): one JSON document of counts and ages only — the receivers, how many are healthy and stale, the stale threshold and poll interval, the oldest last-success age, the most failures in a row, the SETs accepted and refused, the sessions ended, and the library session stores' held, max, TTL, evicted and expired — with when it arrived, and, from a PEP that reports them, one row per stream: the OIDC client it serves and its stream id, each held to a charset, whether it runs and is healthy, when it started, last polled and last succeeded (computed here from the ages the PEP sent and the arrival, never a clock of the PEP's), and its counters. Every other member is dropped and every value that is not a non-negative integer is 0, so no URL or error text is ever held. A heartbeat without it keeps it, one with null clears it, and a registration drops it, since a registration is a new process. Absent on a PEP that never reported it, which the console draws as not reported."
  })
  xacmlPepSignals?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The settings an administrator set for this remote PEP on its console page or with the set-pep-settings action of the management API (#1760): one JSON document holding only the settings that were set, each by its member name (description, resource, notifyUrl, bias, pip, the poll, heartbeat and back-off intervals, the timeout and body bound, the HTTPS reload interval, the log level, the AuthZEN switch, identifier and forward timeout, and the reverse proxy's session, JWKS, upstream, relying-party and signal-stream bounds), validated whole on write and again when the PEP pulls them from GET /xacml/pep/settings. A setting not in it is the PEP's environment variable, or its default. The minimum the PEP needs to connect the first time is never here. Kept across a registration and a heartbeat; removed with the row."
  })
  xacmlPepSettings?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "What the remote PEP last reported, on a heartbeat, having in force for each managed setting (#1760): one JSON document of { token, values: { setting: { value, source } } }, the source service, environment or default, with when it arrived. Every setting the table does not name, every value not of its setting's type and every other source is dropped. A heartbeat without it keeps it, one with null clears it, and a registration drops it. Absent on a PEP older than the settings, which the console draws as not reported."
  })
  xacmlPepSettingsInUse?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The listeners an administrator defined for this remote PEP on its console page or with the set-pep-listener action of the management API (#1760), beyond the four its environment binds: one JSON array, each listener its id, protocol (http or https), purpose (api or proxy), address and port, and for an HTTPS one the DNS names and IP addresses its certificate carries, its key algorithm and a renewal counter. Validated whole on write and again when the PEP pulls them from GET /xacml/pep/settings, which binds and unbinds them while it runs. The PEP generates each HTTPS listener's key and asks POST /xacml/pep/listener-certificate for its certificate, so no private key is ever here. Kept across a registration and a heartbeat; removed with the row."
  })
  xacmlPepListeners?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "What the remote PEP last reported, on a heartbeat, about every listener it has (#1760), its environment's four and the defined ones: one JSON document of { listeners: [ { id, source, protocol, purpose, address, port, state, reason, renew, certificate } ] }, with when it arrived. The state is one of listening, waiting, failed and off and the reason one of a closed set, never the operating system's text; the certificate is the subject, issuer, serial, subjectAltName, validity and fingerprint of the one it serves. Every other member is dropped. A heartbeat without it keeps it, one with null clears it, and a registration drops it. Absent on a PEP older than the listeners, which the console draws as not reported."
  })
  xacmlPepListenersInUse?: string;
  @attr(#{
    kind: "single",
    what: "What kind of remote PEP registered (#2026, part of #1206): container, the xacml-pep image, or embedded, a PEP inside an authentication library through an iya-pep package. A registration that names none is container, so an older PEP is read as it always was. An embedded PEP has no reverse proxy, no listeners and no AuthZEN edge."
  })
  xacmlPepKind?: string;
  @attr(#{
    kind: "single",
    what: "The application an embedded remote PEP said it is embedded in when it registered (#2026). Accepted only when it is the application its entry is bound to (stsPepApplication, set by an administrator), so it can differ from the binding only until the PEP's next heartbeat, which is refused once they disagree. Empty for a container."
  })
  xacmlPepApplication?: string;
  @attr(#{
    kind: "single",
    what: "An embedded remote PEP's mode (#2026): central, where every decision is asked of this service's AuthZEN evaluation endpoint, or local, where it pulls its application's policies and decides in process. Empty for a container, which may not send one."
  })
  xacmlPepMode?: string;
  @attr(#{
    kind: "single",
    what: "The PEP protocol version the remote PEP's package speaks, as it said on its registration or last heartbeat (#2026). This service supports version 1 and refuses any other, so a library that falls behind is visible rather than silently wrong. Empty for a PEP that sends none (the container)."
  })
  xacmlPepProtocolVersion?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "Whether the stream of the application an embedded remote PEP is embedded in can carry the pep-policies-changed event, as the PEP last reported on a heartbeat (#2026): none (the host has no signal stream, so the PEP polls), requested, excluded (the application's ssfEvents leaves it out) or down. Empty until reported."
  })
  xacmlPepPolicyEvents?: string;
  @attr(#{
    kind: "single",
    what: "What the remote PEP last pulled from GET /xacml/pep/policies (#2027): repository, every enabled policy but those withheld (the container's pull), or bound-application, a local embedded PEP's: its application's own policy, or the realm root, and the reference closure. Kept across a registration; a change is audited as xacml.pep.scope. Empty until it pulls."
  })
  xacmlPepPullScope?: string;
  @attr(#{
    what: "Whatever the PEP said about itself when it registered."
  })
  description?: (string)[];
}
