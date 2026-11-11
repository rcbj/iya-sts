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
  @attr(#{what: "The group's name, which names the entry (cn=<name>,ou=groups) and is what a roster or a role names the group by."})
  cn?: (string)[];
  @attr(#{what: "The group's members, one DN per value. Deleting a person leaves their DN here: the directory keeps no referential integrity."})
  @link(#{to: "person", cardinality: "multi", owns: false, what: "The members, by DN."})
  member?: (string)[];
  @attr(#{what: "What the group is for, as an administrator wrote it."})
  description?: (string)[];
  @attr(#{what: "The members of a groupOfUniqueNames group, one DN per value, read as member is."})
  @link(#{to: "person", cardinality: "multi", owns: false, what: "The members, by DN."})
  uniqueMember?: (string)[];
  @attr(#{what: "The members of a posixGroup (RFC 2307), one bare username per value, read beside member."})
  memberUid?: (string)[];
  @attr(#{kind: "single", what: "SCIM's externalId of a Group, which /scim/v2 stores verbatim (models/scim/scim.tsp). The People section names it on people and groups."})
  scimExternalId?: string;
  @attr(#{kind: "single", what: "The named passkey policy this group's members are held to, or `default`. Set on the group's page or with POST /admin-api/groups/set-policy, which accepts only a policy the realm holds."})
  @link(#{to: "policy.passkey", cardinality: "single", owns: false, what: "The named passkey policy of its members."})
  stsPasskeyPolicy?: string;
  @attr(#{kind: "single", what: "The named locale policy this group's members are held to, or `default`. Set on the group's page or with POST /admin-api/groups/set-policy, which accepts only a policy the realm holds."})
  @link(#{to: "policy.locale", cardinality: "single", owns: false, what: "The named locale policy of its members."})
  stsLocalePolicy?: string;
  @attr(#{kind: "single", what: "The named password policy this group's members are held to, or `default`. Set on the group's page or with POST /admin-api/groups/set-policy, which accepts only a policy the realm holds."})
  @link(#{to: "policy.password", cardinality: "single", owns: false, what: "The named password policy of its members."})
  stsPasswordPolicy?: string;
  @attr(#{kind: "single", what: "The named authentication policy this group's members are held to, or `default`. Set on the group's page or with POST /admin-api/groups/set-policy, which accepts only a policy the realm holds."})
  @link(#{to: "policy.authn", cardinality: "single", owns: false, what: "The named authentication policy of its members."})
  stsAuthnPolicy?: string;
  @attr(#{kind: "single", what: "The named post-login policy this group's members are held to, or `default`. Set on the group's page or with POST /admin-api/groups/set-policy, which accepts only a policy the realm holds."})
  @link(#{to: "policy.postLogin", cardinality: "single", owns: false, what: "The named post-login policy of its members."})
  stsPostLoginPolicy?: string;
  @attr(#{kind: "single", what: "The named attribute policy this group's members are held to, or `default`. Set on the group's page or with POST /admin-api/groups/set-policy, which accepts only a policy the realm holds."})
  @link(#{to: "policy.attributes", cardinality: "single", owns: false, what: "The named attribute policy of its members."})
  stsAttributePolicy?: string;
  @attr(#{kind: "multi", what: "On a group a federation relationship's group provisioning created: that relationship's id. A later sign-in through the relationship may add people only to groups carrying its mark."})
  @link(#{to: "federationRelationship", cardinality: "multi", owns: false, what: "The relationships this group is tied to."})
  federationRelationship?: (string)[];
  @attr(#{what: "The address a notice to the group is sent to (#989). The operator's to set; nothing verifies it."})
  mail?: (string)[];
  @attr(#{what: "The name OpenID Provider Commands metadata shows for the group, where it differs from cn."})
  displayName?: string;
}
