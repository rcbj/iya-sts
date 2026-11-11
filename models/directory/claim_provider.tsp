// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/claim_provider.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "claimProvider",
  source: "catalogue",
  container: "ou=claimproviders",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md Claims providers",
  note: "The record is one JSON value, stsClaimProviderData.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsClaimProvider",
      standard: false,
      what: "This service's class for this register."
    }
  ]
})
model ClaimProvider {
  @attr(#{
    kind: "single",
    what: "The claims provider's whole record as one JSON value: its issuer, endpoints, client identifier, authentication method, scope, the claims it answers and how they are delivered. Written by the console and the management API."
  })
  stsClaimProviderData?: DirectoryJson;
  @attr(#{
    kind: "single",
    what: "The client secret this service presents to the claims provider, sealed where a key-encryption key is configured. Withheld from every directory read."
  })
  stsClaimProviderSecret?: string;
}
