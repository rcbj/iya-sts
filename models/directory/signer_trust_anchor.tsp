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
  @attr(#{
    kind: "single",
    what: "The certificate, PEM. A third party's certificate relied on under a signature, as an encryption recipient or in an attestation may chain to it, in this realm only."
  })
  stsTrustAnchorCertificate?: string;
  @attr(#{
    kind: "single",
    what: "The certificate's SHA-256 fingerprint, which also names the entry."
  })
  stsTrustAnchorFingerprint?: string;
  @attr(#{
    kind: "single",
    what: "Who added the certificate, from the console or the management API; empty where nobody is recorded."
  })
  stsTrustAnchorAddedBy?: string;
  @attr(#{
    kind: "single",
    what: "anchor, intermediate or accepted: what the certificate is in a path this store builds. Absent is anchor."
  })
  stsSignerTrustAnchorKind?: string;
  @attr(#{
    kind: "multi",
    what: "A use the certificate is trusted for, one per value. An entry naming no purpose serves every one."
  })
  stsSignerTrustAnchorPurpose?: (string)[];
}
