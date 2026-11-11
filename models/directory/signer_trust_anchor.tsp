// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/signer_trust_anchor.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "signerTrustAnchor",
  source: "catalogue",
  container: "ou=signerTrustAnchors",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md Trust anchors",
  note: "One entry per signer truststore anchor.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsSignerTrustAnchor",
      standard: false,
      what: "This service's class for this register."
    }
  ]
})
model SignerTrustAnchor {
  @attr(#{})
  stsTrustAnchorCertificate?: string;
  @attr(#{})
  stsTrustAnchorFingerprint?: string;
  @attr(#{})
  stsTrustAnchorAddedBy?: string;
  @attr(#{})
  stsSignerTrustAnchorKind?: string;
  @attr(#{})
  stsSignerTrustAnchorPurpose?: (string)[];
}
