// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Authorization area of the catalogue (#1390).

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Authorization",
  entry: "role",
  what: "A set of permissions and who holds it."
})
model Role {
  @fromAttr(#{attr: "roleName", transform: "first"})
  name: string;

  @fromAttr(#{attr: "displayName", transform: "first"})
  displayName?: string;

  @fromAttr(#{attr: "description", transform: "first"})
  description?: string;

  @fromAttr(#{attr: "roleMemberUser"})
  memberUsers?: string[];

  @fromAttr(#{attr: "roleMemberGroup"})
  memberGroups?: string[];

  @fromAttr(#{attr: "roleMemberApplication"})
  memberApplications?: string[];

  @fromAttr(#{attr: "rolePermission"})
  permissions?: string[];

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;
}

@domain(#{
  area: "Authorization",
  entry: "xacmlPolicy",
  what: "An XACML 3.0 policy or policy set this realm evaluates."
})
model XacmlPolicy {
  @fromAttr(#{attr: "xacmlPolicyId", transform: "first"})
  identifier: string;

  @fromAttr(#{attr: "xacmlPolicyDocument", transform: "first"})
  document?: string;

  @fromAttr(#{attr: "xacmlVersion", transform: "first"})
  version?: string;

  @fromAttr(#{attr: "xacmlKind", transform: "first"})
  kind?: string;

  @fromAttr(#{attr: "xacmlCombiningAlgId", transform: "first"})
  combiningAlgorithm?: string;

  @fromAttr(#{attr: "xacmlEnabled", transform: "first"})
  enabled?: boolean;

  @fromAttr(#{attr: "xacmlIsRoot", transform: "first"})
  isRoot?: boolean;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;
}
