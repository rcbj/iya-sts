// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/trust_anchor.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "trustAnchor",
  source: "catalogue",
  container: "ou=trustAnchors",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md Trust anchors",
  note: "One entry per client truststore anchor, in the default realm.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsTrustAnchor",
      standard: false,
      what: "This service's class for this register."
    }
  ]
})
model TrustAnchor {
  @attr(#{
    kind: "single",
    what: "The anchor's certificate, PEM. A client certificate presented at a TLS handshake may chain to it."
  })
  stsTrustAnchorCertificate?: string;
  @attr(#{
    kind: "single",
    what: "The certificate's SHA-256 fingerprint, which also names the entry."
  })
  stsTrustAnchorFingerprint?: string;
  @attr(#{
    kind: "single",
    what: "Who added the anchor, from the console or the management API; empty where nobody is recorded."
  })
  stsTrustAnchorAddedBy?: string;
}
