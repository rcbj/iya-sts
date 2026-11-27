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

## At sign-in

1. **The box.** In a realm that defines at least one dynamic role, the
   sign-in screen shows **Choose roles for this sign-in**, unless the feature
   is turned off for the realm or the application. The box is shown to
   everybody, whether or not they are eligible for anything, so it reveals
   nothing about who may hold which role.
2. **The step.** After every factor (password, passkey, second factor), each
   dynamic role's policy is decided for the person. If the box was ticked,
   or a role marked `required` is among those offered, a page lists the
   roles they may choose, each with its display name and description, as
   checkboxes. Ticking none is allowed unless a required role is offered.
3. **The check.** What the person submits is held against the step's own
   record of what it offered, never against what the browser sends, and each
   chosen role's policy is decided again. A role that was not offered, two
   roles of one exclusive group, a missing required role, or a role no
   longer eligible is refused, and the page is shown again.
4. **The session.** The choice is recorded on the sign-on session, for the
   application the sign-in was for. Nothing is written to the directory, and
   the choice ends with the session.

If nothing is offered, the sign-in continues as it always did.

## In tokens

A chosen role appears in the tokens issued for that application on that
session, through the same processing as any other role:

- the `roles` claim (named by `roles.claimName`) of the OAuth 2.0 access
  token, the ID Token and the UserInfo response;
- the roles attribute of SAML 2.0, SAML 1.1 and WS-Federation assertions
  issued through the browser profiles;
- the issuance policy's role checks, and the permissions a role authorizes
  (scopes).

An application's own role (`<role>@<application>`) is carried only in tokens
for that application, as with every application role. Existing deny
decisions, scope restrictions and audience rules still apply.

**Each issuance asks the role's policy again.** A role the person is no
longer eligible for (their entry changed, the policy changed, or the role
was disabled, deleted or made static) is left off that token and audited as
`roles.selection.dropped`. Refreshing a token never adds a role the person
did not choose. Tokens already issued keep what they carry until they
expire.

An `offline_access` refresh token used after its session has ended carries
no chosen role, because there is no longer a session to read the choice
from.

## Other applications, and signing in again

Single sign-on into a second application carries no choice: what was chosen
applies to the application of that sign-in only. To choose roles for
another application, start from the [user portal](user-facing-pages.md#the-user-portal)'s
**Applications** page and tick **Sign in again**. Each Sign in link then
asks for a fresh sign-in, in that protocol's own way:

| Protocol | What the link adds |
|---|---|
| SAML 2.0, SAML 1.1 | `forceAuthn=true` on the identity-provider-initiated link |
| WS-Federation | `wfresh=0` |
| OpenID Connect | `prompt=login` on the request to the client's `initiate_login_uri`, for the client to forward. This is not part of OpenID Connect Core section 4, so a client that does not forward it signs in as usual. |

The new choice replaces the session's choice for that application only.

## Sign-ins without the screen

A dynamic role is never assumed. Sign-ins and grants that cannot show the
step never carry a dynamically selected role:

- the password grant, token exchange (Native SSO included), the JWT and SAML
  assertion grants, the device grant and CIBA, and a refresh token that
  descends from one of them;
- WS-Trust, Kerberos and LDAP;
- federated, wallet, SPNEGO and certificate sign-ins.

Where the application would **require** a role of the person (a `required`
role the person is eligible for, with the feature on for that application),
each of them is refused, because the person cannot choose there:

| Flow | Refusal |
|---|---|
| The password grant, token exchange, the JWT and SAML assertion grants, the device grant, CIBA | `access_denied` at the token endpoint (`STS-XACML-0332`) |
| WS-Trust | `wst:RequestFailed` (`STS-XACML-0332`) |
| Kerberos: a service ticket, or a ticket-granting ticket | `KDC_ERR_POLICY` (`STS-XACML-0332`) |
| An LDAP simple or SASL EXTERNAL bind | `unwillingToPerform` (`STS-XACML-0332`) |
| Federated, wallet, SPNEGO and certificate sign-ins | the session is not started (`STS-XACML-0329`), with a message sending the person to the sign-in screen |

A flow that names no application — an LDAP bind, a ticket-granting ticket, a
certificate sign-in at `/tls/sign-in` — is asked about the realm-wide
required roles only. A refresh token is not refused: the grant it descends
from was.

**Single sign-on is not a way round a required role.** When a browser asks
an application that would require a role of the person, and the session
chose nothing for that application (it was signed in for another one, or at
a door that names none, such as a certificate), the person is sent to sign
in again, and the role step is shown. A request that forbids asking
(`prompt=none`, `IsPassive`) is answered `interaction_required` or
`NoPassive` (`STS-XACML-0333`).

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
for one application. When it is off, nothing is offered, nothing is required,
and no token carries a dynamically selected role, including one a session
chose while it was on.

An application is named by its registry identifier wherever a choice is
recorded or read, so a client whose `client_id` (or a service provider whose
entityID) differs from its identifier is offered its own roles and carries
what was chosen for it. A choice applies to tokens issued to the
application the sign-in was for: an access token a client asks for another
resource carries the client's choice, never one made for that resource.

## Related

- [XACML 3.0 and ALFA](xacml.md)
- [Authorization overview](authorization.md)
- [Error codes](error-codes.md) (`STS-XACML-0303` to `STS-XACML-0330`, `STS-XACML-0332` and `STS-XACML-0333`)
