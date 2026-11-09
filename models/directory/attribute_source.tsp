// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/attribute_source.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "attributeSource",
  source: "catalogue",
  container: "ou=attributesources",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md Attribute sources",
  note: "The source is one JSON value, stsAttributeSourceData.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsAttributeSource",
      standard: false,
      what: "This service's class for one attribute source."
    }
  ]
})
model AttributeSource {
  @attr(#{what: "The source id, the RDN."})
  cn?: unknown;
  @attr(#{jsonBlob: true, what: "The whole definition as one JSON value. No password."})
  stsAttributeSourceData?: unknown;
  @attr(#{what: "On a person: <source>:<attribute> a source wrote."})
  stsAttributeSourced?: unknown;
  @attr(#{what: "On a person: <source>=<time> of the last read."})
  stsAttributeSourceSeen?: unknown;
}
