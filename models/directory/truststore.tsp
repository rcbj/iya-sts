// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/truststore.tsp
//
// Written by hand (#2118). THIS IS THE SOURCE of these objects' tables.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "truststore",
  source: "catalogue",
  container: "ou=truststores",
  ownContainer: true,
  authored: true,
  section: "docs/v1.2.0/ldap-schema.md Trust anchors",
  note: "One entry per named truststore; its certificates are stsSignerTrustAnchor entries beneath it.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsTruststore",
      standard: false,
      what: "This service's class for a named truststore."
    }
  ]
})
model Truststore {
  @attr(#{
    kind: "single",
    what: "What the truststore holds: x509 (certificate authorities) or jwks (a key set bound to one party, #2149). Absent is x509."
  })
  stsTruststoreKind?: string;
  @attr(#{
    kind: "single",
    what: "A jwks truststore's party, the one whose JSON Web Tokens its keys may verify: client:<client_id>, federation:<relationship id>, claims-provider:<provider id> or oidfed-anchor:<entity id> (#2149, #2150)."
  })
  stsTruststoreParty?: string;
  @attr(#{
    kind: "single",
    what: "A jwks truststore's key set as pasted: a JSON Web Key Set of public keys only."
  })
  stsTruststoreJwks?: string;
  @attr(#{
    kind: "single",
    what: "A jwks truststore's jwks_uri, fetched under the outbound policy where no key set was pasted."
  })
  stsTruststoreJwksUri?: string;
  @attr(#{
    kind: "single",
    what: "Who created the truststore, from the console or the management API; empty where nobody is recorded."
  })
  stsTrustAnchorAddedBy?: string;
}

@entry(#{
  id: "truststoreAssignments",
  source: "catalogue",
  container: "ou=truststores",
  ownContainer: false,
  authored: true,
  section: "docs/v1.2.0/ldap-schema.md Trust anchors",
  note: "One entry, cn=assignments: the truststores each use case of this realm trusts.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsTruststoreAssignments",
      standard: false,
      what: "This service's class for a realm's truststore assignments."
    }
  ]
})
model TruststoreAssignments {
  @attr(#{
    kind: "multi",
    what: "One use case and the truststores it trusts, as '<use case> <name>,<name>', in order. A use case with no value trusts its default list."
  })
  stsTruststoreAssignment?: (string)[];
}
