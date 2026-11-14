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
    what: "The last heartbeat or pull. xacml.pepStaleAfterS is how long since this before the console says \"stale\" — which changes nothing this service does, deliberately."
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
    what: "What happened to the last nudge — the status, or the refusal sentence. THE ONLY PLACE A FAILED NUDGE IS RECORDED, for the reason ssf_streams.js gives about a refused push: it is invisible from the receiving end by definition."
  })
  xacmlPepLastNotify?: string;
  @attr(#{
    what: "Whatever the PEP said about itself when it registered."
  })
  description?: (string)[];
}
