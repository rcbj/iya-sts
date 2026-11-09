// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/kerberos_trust.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "kerberosTrust",
  source: "catalogue",
  container: "ou=kerberosTrusts",
  ownContainer: true,
  authored: true,
  section: "ldap/ldap_server.js OWN_NAMES",
  note: "One entry per trust with another Kerberos realm.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsKrb5Trust",
      standard: false,
      what: "This service's class for this register."
    }
  ]
})
model KerberosTrust {
  @attr(#{})
  stsKrb5TrustData?: unknown;
  @attr(#{})
  stsKrb5TrustKeys?: unknown;
  @attr(#{})
  trustPartner?: unknown;
  @attr(#{})
  flatName?: unknown;
  @attr(#{})
  securityIdentifier?: unknown;
  @attr(#{})
  trustDirection?: unknown;
  @attr(#{})
  trustAttributes?: unknown;
  @attr(#{})
  trustType?: unknown;
}
