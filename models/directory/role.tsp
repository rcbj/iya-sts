// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/role.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/roles.js`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "role",
  source: "./roles",
  container: "ou=roles",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "stsRole",
      what: "One ROLE. The entry is named by the role name (`cn=staff`), and everything on it is MEMBERSHIP — who holds the role. What a role is REQUIRED for lives on the application entry that requires it, in `appRequiredRole`, because that is a fact about the application rather than about the role."
    }
  ]
})
model Role {
  @attr(#{
    what: "The role name, which is also the `cn`. Carried explicitly as well so that a reader who has only the attributes has the name."
  })
  roleName?: unknown;
  @attr(#{
    what: "A username that holds this role. Multi-valued. The person need not exist yet — this service creates a directory entry for any name on first sight, so a role may be granted before its holder has ever signed in."
  })
  roleMemberUser?: unknown;
  @attr(#{
    what: "A group whose every member holds this role. Multi-valued. Resolved at DECISION TIME rather than expanded on write, so an `ldapmodify` adding somebody to the group changes the very next token."
  })
  roleMemberGroup?: unknown;
  @attr(#{
    what: "An application that holds this role AS ITSELF — what a client_credentials grant is decided on, where there is no person. Multi-valued. NOT the same relation as `appRequiredRole` on the application entry, which is what that application DEMANDS of others."
  })
  roleMemberApplication?: unknown;
  @attr(#{
    what: "A permission a holder of this role may be ISSUED (#303). Multi-valued. Named as a client asks for it: a generic application permission by its full scope value — the resource application's `oauthPermissionBaseUri` followed by the name — and a native permission of this service by its own name (`admin:read`, `admin:write`). It matters only for a permission its resource application GATES (`oauthRoleGatedPermission`); a gated permission is issued only to a subject holding a role that names it, and an ungated one as it always was."
  })
  rolePermission?: unknown;
  @attr(#{
    what: "A client this role is CONFERRED BY (#454): every person who signs in through that client holds the role on the access token the client is issued, and on no other token. Multi-valued, client_ids of applications in this realm. A role held this way is a fact about the TOKEN rather than about the person, so it is mixed with the roles the person holds themselves on every call, and taking a client off it takes the role off that client's tokens at once. Never applied to a client's own client_credentials token, whose roles are its membership. ADMIN_CONSOLE is seeded conferred by `sts-admin-console`."
  })
  roleConferredBy?: unknown;
  @attr(#{
    what: "The ONE application this role belongs to (#310), by its identifier in ou=applications; absent, the role is realm-wide. An application's role is named `<role>@<application>` in the register, so two applications may each have a `reader`; a token or assertion for that application carries it as `<role>`, and no other application's token carries it at all. The application's `appRequiredRole` may name it by `<role>`."
  })
  roleApplication?: unknown;
  @attr(#{
    what: "WHO MAY HOLD this role (#93): `user` (people, directly or through a group) and `application` (an application as itself). Multi-valued; absent, both may — every role written before it. A member of a kind the role does not allow is refused when the role is written. The two console roles cannot be restricted: the roster grants their people and the seed their application."
  })
  roleAllowedMemberType?: unknown;
  @attr(#{
    what: "An optional name for people to read (#93). The role's NAME is still what a token carries, what a requirement names and what the register is keyed on; this is only its label on the console and the API. Its stable id is the entry's `entryUUID`, kept across every edit."
  })
  displayName?: unknown;
  @attr(#{
    what: "What the role is for, for the next person."
  })
  description?: unknown;
  @attr(#{
    what: "A person or a group of this realm who answers for the role (#604), by DN — RFC 4519 section 2.23's attribute, as a group's owners are (#603). Multi-valued, at most 25. Since #607 an owner may ADMINISTER the role through /admin-api with owner:read and owner:write (OWNER_READ, OWNER_WRITE), within what the access-control policy's owner rule allows; an owner holds the role itself only by being a member. The user portal lists what a person owns."
  })
  owner?: unknown;
  @attr(#{
    what: "TRUE: the role's owners may not administer it through /admin-api (#607), whatever they own — an administrator's mark, read by the access-control policy's owner rule as urn:sts:xacml:object-protected. Absent is FALSE."
  })
  stsOwnerProtected?: unknown;
}
