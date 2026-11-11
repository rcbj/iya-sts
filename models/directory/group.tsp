// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/group.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "group",
  source: "catalogue",
  container: "ou=groups",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md Groups",
  note: "No SCHEMA export. A group grants nothing by being a group.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "groupOfNames",
      standard: true,
      what: "The class the container's own groups carry."
    },
    #{
      name: "groupOfUniqueNames",
      standard: true,
      what: "Also treated as a group."
    },
    #{
      name: "posixGroup",
      standard: true,
      what: "RFC 2307. Also treated as a group."
    },
    #{
      name: "groupOfURLs",
      what: "Also treated as a group. The page states no RFC number."
    }
  ]
})
model Group {
  @attr(#{what: "Named on the Groups section."})
  cn?: (string)[];
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "person", cardinality: "multi", owns: false, what: "The members, by DN."})
  member?: (string)[];
  @attr(#{what: "Named on the Groups section."})
  description?: (string)[];
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "person", cardinality: "multi", owns: false, what: "The members, by DN."})
  uniqueMember?: (string)[];
  @attr(#{what: "Named on the Groups section."})
  memberUid?: (string)[];
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "policy.passkey", cardinality: "single", owns: false, what: "The named passkey policy of its members."})
  stsPasskeyPolicy?: string;
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "policy.locale", cardinality: "single", owns: false, what: "The named locale policy of its members."})
  stsLocalePolicy?: string;
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "policy.password", cardinality: "single", owns: false, what: "The named password policy of its members."})
  stsPasswordPolicy?: string;
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "policy.authn", cardinality: "single", owns: false, what: "The named authentication policy of its members."})
  stsAuthnPolicy?: string;
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "policy.postLogin", cardinality: "single", owns: false, what: "The named post-login policy of its members."})
  stsPostLoginPolicy?: string;
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "policy.attributes", cardinality: "single", owns: false, what: "The named attribute policy of its members."})
  stsAttributePolicy?: string;
  @attr(#{what: "Named on the Groups section."})
  @link(#{to: "federationRelationship", cardinality: "multi", owns: false, what: "The relationships this group is tied to."})
  federationRelationship?: (string)[];
}
