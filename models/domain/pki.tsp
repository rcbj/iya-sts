// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The PKI area of the catalogue (#1390).

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "PKI",
  entry: "trustAnchor",
  what: "A certificate authority a realm trusts for client certificates."
})
model TrustAnchor {
  @fromAttr(#{attr: "stsTrustAnchorCertificate", transform: "first"})
  certificate: string;

  @fromAttr(#{attr: "stsTrustAnchorFingerprint", transform: "first"})
  fingerprint?: string;

  @fromAttr(#{attr: "stsTrustAnchorAddedBy", transform: "first"})
  addedBy?: string;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;
}

@domain(#{
  area: "PKI",
  entry: "signerTrustAnchor",
  what: "A certificate authority a realm trusts to sign what it is sent."
})
model SignerTrustAnchor {
  @fromAttr(#{attr: "stsTrustAnchorCertificate", transform: "first"})
  certificate: string;

  @fromAttr(#{attr: "stsTrustAnchorFingerprint", transform: "first"})
  fingerprint?: string;

  @fromAttr(#{attr: "stsTrustAnchorAddedBy", transform: "first"})
  addedBy?: string;

  @fromAttr(#{attr: "stsSignerTrustAnchorKind", transform: "first"})
  kind?: string;

  @fromAttr(#{attr: "stsSignerTrustAnchorPurpose", transform: "first"})
  purpose?: string;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;
}

@domain(#{
  area: "PKI",
  entry: "truststore",
  what: "A named truststore: certificate authorities a use case is assigned to trust (#2118), or a key set bound to one party (#2149)."
})
model Truststore {
  @fromAttr(#{attr: "stsTruststoreKind", transform: "first"})
  kind?: string;

  @fromAttr(#{attr: "stsTruststoreParty", transform: "first"})
  party?: string;

  @fromAttr(#{attr: "stsTruststoreJwks", transform: "first"})
  jwks?: string;

  @fromAttr(#{attr: "stsTruststoreJwksUri", transform: "first"})
  jwksUri?: string;

  @fromAttr(#{attr: "stsTruststoreSshKeys", transform: "first"})
  sshKeys?: string;

  @fromAttr(#{attr: "stsTruststoreDocument", transform: "first"})
  document?: string;

  @fromAttr(#{attr: "stsTrustAnchorAddedBy", transform: "first"})
  addedBy?: string;

  @derived(#{how: "The trust realm whose directory holds the entry; the default realm's are service-wide."})
  realm: string;
}

@domain(#{
  area: "PKI",
  entry: "truststoreAssignments",
  what: "Which truststores each use case of a realm trusts (#2118)."
})
model TruststoreAssignments {
  @fromAttr(#{attr: "stsTruststoreAssignment"})
  assignments?: string[];

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;
}
