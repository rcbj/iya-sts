---
title: Dynamic selectable roles
---

# Dynamic selectable roles

A **dynamic selectable role** is a role that nobody holds outright. When a
person signs in, iya-sts offers them the dynamic roles they are eligible
for, and they tick the ones to use for that sign-in. A role they choose is
carried on the tokens for that sign-in, alongside the roles they hold
through membership. Choosing it changes nothing in the directory: no
membership, no group and no role entry is written.

It is still an ordinary role. Its name, display name, description,
permissions and application are the ones every role on
[`/admin/roles`](admin-console.md#roles--adminroles) has; what differs is
how somebody comes to hold it.

## Static and dynamic roles

Every role has a **membership mode**:

| Mode | Who holds it |
|---|---|
| `static` (the default) | The users, groups and applications listed on it, as always. |
| `dynamic-selectable` | Nobody, until they choose it at sign-in. It is offered only to people its eligibility policy permits. |

A dynamic role has **no members**. Making a role dynamic is refused while it
has members or conferring clients, and adding a member to a dynamic role is
refused. Switching the mode back and forth adds and removes nothing. The
console's roles and this service's own native roles cannot be dynamic.

A dynamic role also says how it is chosen:

- **Selection.** `optional` (the default) or `required`. A required role a
  person is eligible for must be chosen.
- **Exclusive group.** Roles that share an exclusive group name cannot be
  chosen together; a sign-in may choose at most one of them.

## Eligibility is an XACML decision

Who may be offered a dynamic role is decided by **the role's own XACML 3.0
policy**, evaluated by the [PDP](xacml.md) for one person at a time. There is
no separate expression language and no second decision engine.

- **Only Permit makes a person eligible.** Deny, NotApplicable, an
  Indeterminate result (including a missing attribute the policy requires),
  an obligation the service cannot discharge, a missing or disabled policy,
  and any evaluation error all mean *not eligible*.
- **The conditions are the policy's own rules.** AND and OR are written as
  XACML (or ALFA) target clauses, conditions and combining algorithms, which
  XACML 3.0 defines deterministically.
- **The person's attributes come from the directory** through the
  [Policy Information Point](xacml.md#the-policy-information-point), so a
  policy can test `employeeType`, `departmentNumber` or any other attribute
  of the person's entry. Group membership can be an input, but is never a
  requirement.
- **An application's role is offered only on sign-ins to that
  application**, whatever its policy says. A realm-wide role is offered on a
  sign-in to any application.

A role's eligibility policy is stored in `ou=policies` like any other policy,
marked as owned by the role (`xacmlRole`). It is decided **alone**: it is
never the repository's root, it is never reached from the root through a
`PolicyIdReference`, and it is never sent to a [remote PEP](remote-pep.md).
Deleting the role deletes its policy.

### The request the policy sees

| Category | Attribute | Value |
|---|---|---|
| access-subject | `subject-id` | the person's username |
| access-subject | `urn:sts:xacml:subject-kind` | `user` |
| action | `action-id` | `select-role` |
| resource | `resource-id` | the role's name |
| resource | `urn:sts:xacml:role-eligibility:role-application` | the application the role belongs to, absent for a realm-wide role |
| environment | `urn:sts:xacml:role-eligibility:stage` | `offer` (the sign-in), `issue` (each issuance that carries the role) or `test` (an administrator's dry run) |
| environment | `urn:sts:xacml:role-eligibility:application` | the application the sign-in is for |
| environment | `urn:sts:xacml:acr`, `urn:sts:xacml:amr` | the sign-in's authentication context class and methods (RFC 8176) |
| environment | `urn:sts:xacml:realm`, `urn:sts:xacml:protocol` | the trust realm, and the protocol |

### An example policy

This ALFA policy makes a person eligible when their entry's `employeeType` is
`operator`:

```
namespace oncall {
    attribute kind {
        category = subjectCat
        id = "employeeType"
        type = string
    }
    policy eligible {
        id = "urn:example:oncall-eligible"
        apply denyUnlessPermit
        rule operators {
            permit
            target clause kind == "operator"
        }
    }
}
```

## Administering dynamic roles

On the console, a role's page (`/admin/roles?role=<name>`) shows how the role
is held. Its **Edit** section sets the membership mode, the selection and the
exclusive group, and a dynamic role's **Eligibility** section sets its policy
(as ALFA or XACML 3.0 XML) and **tests** it against a person without a
sign-in. The test reports the decision, why a person is not eligible, and any
missing attribute.

The [management API](management-api.md) has the same operations:

| Operation | What it does |
|---|---|
| `POST /admin-api/roles/create-role` | Makes a role; `membershipMode`, `selection` and `exclusiveGroup` make it dynamic from the start. |
| `POST /admin-api/roles/set-membership-mode` | Makes a role `static` or `dynamic-selectable`. |
| `POST /admin-api/roles/set-selection` | Sets a dynamic role's selection and exclusive group. |
| `POST /admin-api/roles/set-eligibility-policy` | Writes the role's eligibility policy from `alfa` or `document` (XML). |
| `GET /admin-api/roles/eligibility` | Tests the policy for `role`, `user` and, optionally, `application`. |

Every eligibility decision is audited as `roles.eligibility`; a refusal
carries its error code, and the row never contains the policy or the
person's attributes.

## Turning it off

The realm setting `roles.dynamicSelection` (on by default) and an
application's `appDynamicRoleSelection` turn the feature off for the realm or
for one application. When it is off, nothing is offered and no token carries
a dynamically selected role.

## Related

- [XACML 3.0 and ALFA](xacml.md)
- [Authorization overview](authorization.md)
- [Error codes](error-codes.md) (`STS-XACML-0303` to `STS-XACML-0322`)
