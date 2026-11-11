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
  @attr(#{
    kind: "single",
    what: "What the entry holds: keys, subordinate, anchor, mark-type, issued-mark, held-mark, mark-policy, events, suspension or collection. Written by this service."
  })
  stsOidfedKind?: string;
  @attr(#{
    kind: "single",
    what: "The Entity Identifier the entry concerns, where it concerns one. Written by this service."
  })
  stsOidfedEntityId?: string;
  @attr(#{
    kind: "single",
    what: "The entry's record as one JSON value, of the shape its kind says. Written by the console, the management API and the federation endpoints."
  })
  stsOidfedData?: DirectoryJson;
  @attr(#{
    kind: "multi",
    what: "The realm's Federation Entity Keys, one JSON row per value, on the keys entry. Withheld from every directory read."
  })
  stsOidfedKeys?: (DirectoryJson)[];
  @attr(#{
    kind: "multi",
    what: "A subordinate's event history, one JSON event per value, on its events entry. Appended by this service."
  })
  stsOidfedEvent?: (DirectoryJson)[];
}
