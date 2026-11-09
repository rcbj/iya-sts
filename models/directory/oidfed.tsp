// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/oidfed.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "oidfed",
  source: "catalogue",
  container: "ou=oidfed",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md OpenID Federation",
  note: "One entry per federation key, subordinate, anchor or mark.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsOidfedEntry",
      standard: false,
      what: "This service's class for this register."
    }
  ]
})
model Oidfed {
  @attr(#{})
  stsOidfedKind?: string;
  @attr(#{})
  stsOidfedEntityId?: string;
  @attr(#{})
  stsOidfedData?: DirectoryJson;
  @attr(#{})
  stsOidfedKeys?: (DirectoryJson)[];
  @attr(#{})
  stsOidfedEvent?: (DirectoryJson)[];
}
