---
title: Fine-grained authorization
---

# Application-scoped fine-grained authorization

An application that declares its own `authorization_details` types (RFC 9396,
`oauthAuthorizationDetailsType` on the application) can also own an XACML
policy that decides each detail of those types. This page
describes every application's own policy, the switch that enforces it, what
happens when a token is issued for an application that enforces it, and what
happens to the policy when the application is deleted. How a detail's
members become policy attributes is described under
[Rich authorization requests](oauth-oidc.md#rich-authorization-requests-rfc-9396).
The same policy also decides each access a resource server asks about
through [AuthZEN](authzen.md); see
[What happens at access time](#what-happens-at-access-time).

## Features

* **One policy per application.** When an application is created on
  **Applications → New**, through the management API, or by importing an LDIF
  file, the service writes a default policy for it into the realm's
  `ou=policies`. The policy has one rule that permits every detail. It is a
  real Permit decision, not a fallback: delete the rule and the policy denies.
* **The application names its policy.** The application entry carries the
  policy's entry name in `appFgaPolicy`. The policy carries the application's
  identifier in `xacmlApplication`.
* **A switch, off by default.** `appFgaEnforced` is `TRUE` when the
  application's policy is enforced. It starts absent, which means off.
  Switching it on creates the policy first if the application has none. It is
  refused while the policy is disabled or does not parse, because an enforced
  application with such a policy would refuse every detail. It is also
  refused while a type the application declares is not *covered*: a member
  its schema allows is neither mapped (`xacml`) nor listed in `notForPolicy`,
  or its schema allows members it does not name. The refusal names those
  member paths, `*` for an open schema (`STS-FGA-0018`). While the switch is
  on, a type definition that would leave a member uncovered is refused when
  it is written (`STS-FGA-0019`).
* **Enforced when tokens are issued.** While the switch is on, every
  `authorization_details` entry of a type the application declares is granted
  only when the application's policy says Permit. See
  [What happens at issuance](#what-happens-at-issuance).
* **Enforced at access time, through AuthZEN.** While the switch is on, an
  AuthZEN evaluation about the application is decided by the application's
  policy instead of the realm's root policy. See
  [What happens at access time](#what-happens-at-access-time).
* **Deleting an application keeps its policy.** The policy is disabled and
  marked `xacmlOrphanedAt` with the time of the deletion. It stays in
  `ou=policies` for audit until an administrator removes it on
  **XACML → Policies** (see [The console and the API](#the-console-and-the-api)). If an application with the same identifier is created
  again, it gets a new policy; it never inherits the orphan.
* **Never the root.** An application's policy is never the repository's root,
  is never reached by a `PolicyIdReference` from the root, and is never
  counted when the service picks "the only enabled policy" as the root. A
  realm with one ordinary policy keeps it as its root however many
  applications it has.
* **Never sent to a remote PEP.** `GET /xacml/pep/policies` withholds every
  application's policy and lists its name in `withheld`, as it does for this
  service's own two policies. The sync token ignores them, so creating an
  application does not make the remote PEPs pull again. Fine-grained
  authorization is decided only by this service: a resource server asks it
  through the AuthZEN endpoint, directly or through a remote PEP.

## What happens at issuance

When an application has `appFgaEnforced` on, the service asks its policy
about each detail of its types, one detail at a time. The question is asked
after the realm's issuance policy and the type checks of RFC 9396, never
instead of them. A detail of any other type, and every detail of an
application with the switch off, is handled exactly as before.

| Where | When | A refusal by the policy | The policy cannot be used |
|---|---|---|---|
| `/oauth2/authorize` | after sign-in, before the consent screen | `access_denied`, sent to the client's `redirect_uri` (also with `prompt=none`) | `server_error`, sent to the `redirect_uri` |
| `/oauth2/par` | when the request is pushed | `400 invalid_authorization_details` | `500 server_error` |
| `/oauth2/token` | every grant that issues `authorization_details` | `400 invalid_authorization_details` | `500 server_error` |

* **Only Permit grants a detail.** Deny, NotApplicable, and Indeterminate
  because an attribute the policy needs is missing all refuse the detail
  (`STS-FGA-0014`). So does a Permit that carries an obligation this service
  cannot carry out. A detail with a member the type does not cover is refused
  the same way (`STS-FGA-0103`).
* **A policy that cannot be used refuses too, with `server_error`.** That is
  an application with no policy (`STS-FGA-0003`), a policy that is missing
  (`0004`), that is not the application's own (`0005`), that is disabled
  (`0006`) or that does not parse (`0007`), or a policy whose evaluation
  fails (`0015`). A detail is never issued without a decision.
* **The consent screen never shows a refused detail.** The authorization
  endpoint asks before consent, so a person is never asked to approve a
  detail that will not be issued.
* **At the PAR endpoint nobody has signed in yet**, so the policy sees the
  client but no subject: the request has no `subject-id` and no
  `urn:sts:xacml:subject-kind` at all, never an empty one. A rule that needs
  a person does not match, and a policy that must refuse when nobody is
  there tests for the attribute's absence. The authorization endpoint asks
  again once a person has signed in.
* **Limits a person lowers on the consent screen are asked about again**
  when the authorization endpoint itself issues an access token
  (`response_type` containing `token`). The question before the consent
  screen was about the limits the client asked for; the token carries the
  lowered ones, so the policy is asked about those before the token is
  issued, with the same `access_denied` or `server_error` if it refuses. For
  a code, the token endpoint asks about the lowered details when the code is
  redeemed.
* **Every refresh is decided again**, against the policy and the type
  definition as they are now. A policy change reaches a client at its next
  refresh: a refused refresh ends that grant, as a refused code does.
* **A token exchange is bounded.** For a type whose application enforces the
  policy, a token exchange may ask only for details the `subject_token`
  already carries (RFC 9396 section 6's rule: the same type, each common
  array a subset, every other member equal). A `subject_token` that this
  service did not issue, or that carries no `authorization_details`, covers
  none. Otherwise the request is refused `invalid_authorization_details`
  (`STS-FGA-0017`). Types of applications that do not enforce the policy are
  granted as asked, as before.
* **Who the subject is.** At the authorization endpoint and for a code,
  refresh, device, CIBA or exchange grant it is the person
  (`subject-id`, `urn:sts:xacml:subject-kind` = `user`), and the policy can
  read their directory attributes. For a client credentials grant it is the
  client (`application`). The client is always `urn:sts:xacml:client-id`.

Each decision is written to the audit log as `fga.decision`: the
application, the policy's entry name, `PolicyId` and version, the detail's
type and a SHA-256 of the type definition, the subject, the client, the
stage, the grant, the outcome with its XACML decision and error code, and a
SHA-256 of the detail. **The detail's values are never written to the audit
log.** **XACML → Monitor** counts each decision on the row *The fine-grained
authorization PEP*, with how many were allowed and refused.

### An example: no deletes

The resource application `https://docs.example/api` declares this type:

```json
{"type": "document_access",
 "locations": ["https://docs.example/"],
 "actions": ["read", "update", "delete"],
 "schema": {"type": "object", "additionalProperties": false,
            "properties": {"type": {}, "locations": {}, "actions": {},
                           "identifier": {"type": "string"},
                           "classification": {"type": "string"},
                           "note": {"type": "string"}}},
 "xacml": [{"path": "classification",
            "attributeId": "urn:example:classification"}],
 "notForPolicy": ["note"]}
```

Switch fine-grained authorization on for it, then replace the rules of its
policy (**XACML → Policies**, the policy named `fga-…` with the application
as its owner) with this ALFA:

```
namespace docs {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute detailAction { category = actionCat
        id = "urn:sts:xacml:fga:detail:action" type = string }
    policy documents {
        id = "urn:example:docs"
        apply firstApplicable
        target clause act == "grant-authorization-detail"
        rule noDelete {
            deny
            target clause detailAction == "delete"
        }
        rule everythingElse {
            permit
        }
    }
}
```

Now a client that asks for

```
authorization_details=[{"type":"document_access",
  "locations":["https://docs.example/"],"actions":["read","delete"],
  "identifier":"doc-1","classification":"internal"}]
```

at `/oauth2/authorize` is sent back to its `redirect_uri` with
`error=access_denied` as soon as the person has signed in, without a consent
screen. The same detail at `/oauth2/par` or `/oauth2/token` gets
`400 {"error":"invalid_authorization_details"}`. A detail with
`"actions":["read"]` is granted. The audit log shows one `fga.decision` row
for each request.

## What happens at access time

A token says what was granted when it was issued. Whether a particular
request may go ahead now — this person, this document, this action — is a
question the resource server asks at the time of the request, and for an
application that enforces fine-grained authorization the same policy answers
it:

```
resource server ──► remote PEP ──► POST /access/v1/evaluation ──► the application's policy
resource server ───────────────►  (AuthZEN)
```

The resource server, or a [remote PEP](remote-pep.md) in front of it, sends
an [AuthZEN](authzen.md) access evaluation naming the application in
`context.application`. When that application has `appFgaEnforced` on, the
evaluation is decided against the application's own policy alone, never the
realm's root policy and never a policy the root references. Every other
application is decided against the root, as before. The remote PEP's own
AuthZEN endpoint, which forwards a resource server's evaluation here, comes
in a later release; until then a resource server or PEP calls this service's
AuthZEN endpoint directly.

**What the caller needs** is what every AuthZEN caller needs:

* to authenticate at the realm's AuthZEN door (mutual TLS by default; see
  [Who may call it](authzen.md#who-may-call-it));
* membership of the realm's `authzen-peps` group, which carries the
  `AUTHZEN_PEPS` role;
* the application in its scope (`stsAuthzenApplication` on a person or
  service account, `appAuthzenApplication` on an application), and the
  application named in `context.application` when it has several. A caller
  cannot reach an application's policy by naming an application outside its
  scope (`403`).

**What the policy sees** is the AuthZEN request as it always is —
`subject-id`, `urn:sts:xacml:authzen:subject-type`, the caller's
`action-id`, `resource-id`, `urn:sts:xacml:authzen:resource-type`, the
catalogue's attributes, and `urn:sts:xacml:protocol` = `authzen` with the
other AuthZEN facts — and two more, which this service writes and a caller
cannot send:

| Attribute | Category | Value |
|---|---|---|
| `urn:sts:xacml:fga:application` | resource | the application whose policy decides |
| `urn:sts:xacml:fga:stage` | environment | `access` |

At issuance the stage is `authorize`, `par`, `token`, `refresh` or
`exchange` and the action is `grant-authorization-detail`; at access time
the action is the one the resource server asks about. One policy can answer
both by targeting on the stage, or on `urn:sts:xacml:protocol`
(`oauth2` at issuance, `authzen` at access time).

**The answer** follows AuthZEN's rules: only a Permit with no obligation
this service cannot carry out is `true`; Deny, NotApplicable and a missing
attribute are `false`. A policy that cannot be used — none, missing, not the
application's own, disabled, or one that does not parse — is an error,
`500`, and in a batch that item's `context.error`; it is never `false`, and
the root policy is never asked instead (`STS-AUTHZEN-0040`, with the
`STS-FGA-*` code that says why on the audit row).

Each evaluation is one `authzen.decision` row in the audit log, which names
the application's policy, its `PolicyId` and its version when that policy
decided. **XACML → Monitor** counts it once, on the AuthZEN row: the
resource server enforces the answer, not this service.

### An example: no deletes at access time

Extending the policy of the example above so that it also answers the
resource server:

```
namespace docs {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute stage { category = environmentCat
        id = "urn:sts:xacml:fga:stage" type = string }
    policy documents {
        id = "urn:example:docs"
        apply firstApplicable
        rule noDeleteNow {
            deny
            target clause stage == "access"
            target clause act == "delete"
        }
        rule everythingElse {
            permit
        }
    }
}
```

A PEP scoped to the application asks:

```
POST /access/v1/evaluation
{"subject":{"type":"user","id":"alice"},
 "action":{"name":"delete"},
 "resource":{"type":"document","id":"doc-1"},
 "context":{"application":"https://docs.example/api"}}
```

and gets `{"decision": false}`, even if the realm's root policy would permit
it. The same request with `"action":{"name":"read"}` gets
`{"decision": true}`.

## The console and the API

Everything below is a form in the admin console and an operation of the
[management API](management-api.md). A form posts to the operation named
beside it, so a script can do each step the way the console does. Every
write needs Admin Write, or `admin:write` on the API token.

1. **Declare the type.** On **Applications → (the resource application) →
   Access types**, declare the type with its JSON Schema
   (`POST /admin-api/applications/set-access-type`). Close the schema with
   `"additionalProperties": false`; an open schema can never be covered.
2. **Map its members.** Under **XACML mapping** on the same tab there is a
   sub-tab for each declared type. Map each member the policy needs (see
   [Mapping a type's members](#mapping-a-types-members)), and list the members
   it should never see under **Not for the policy**.
3. **Check the coverage.** The application's **Fine-grained authorization**
   tab lists each declared type with **covered**, or **not covered:**
   followed by the member paths still to map or list.
4. **Write the policy.** **Its policy** on the same tab names the policy,
   with a link into the **XACML → Editor**. Narrow its rule there. An
   application with no policy of its own gets one from **Create the default
   policy** (`POST /admin-api/applications/fga-create-policy`).
5. **Enforce it.** Press **Enforce**
   (`POST /admin-api/applications/fga-enable`). The refusal names what to
   fix: an uncovered type with its paths (`STS-FGA-0018`), or a policy that
   is disabled (`STS-FGA-0006`) or does not parse (`STS-FGA-0007`).
   **Stop enforcing** (`fga-disable`) switches it off and keeps the policy.

| Console | Operation | What it does |
|---|---|---|
| Access types → XACML mapping → **Save the row** | `POST /admin-api/applications/set-access-type-row` | Adds the row for a member path, or replaces the one already mapping it |
| Access types → XACML mapping → **Remove** | `POST /admin-api/applications/remove-access-type-row` | Takes one row off |
| Access types → XACML mapping → **Save the list** | `POST /admin-api/applications/set-not-for-policy` | Replaces the list of paths the policy never sees |
| Access types → **Save the type** | `POST /admin-api/applications/set-access-type` | Writes the whole definition, `xacml` and `notForPolicy` included |
| Fine-grained authorization → **Enforce** / **Stop enforcing** | `fga-enable` / `fga-disable` | Sets or clears `appFgaEnforced` |
| Fine-grained authorization → **Create the default policy** | `fga-create-policy` | Writes the `fga-default` policy for an application that has none |
| Fine-grained authorization → **Reset to the default policy** | `fga-reset-policy` | Rewrites the policy from `fga-default`; needs `confirm` |
| XACML → Policies → **Applications' own policies** → **Remove** | `POST /admin-api/xacml/delete` | Deletes a policy no application names |

`GET /admin-api/applications?application=<id>` returns what the two tabs
draw: `page.accessTypes` (each type with its `xacml` rows and `notForPolicy`)
and `page.fga`. `page.fga` holds `enforced`, `reference` (the
`appFgaPolicy` value), `policy` (its entry name, `policyId`, `version`,
`enabled`, whether it is the application's `own`, and the `editor` link),
`usable` with the `code` and `why` when it cannot be used, and `types`, each
with `covered`, `uncovered`, `rows` and `notForPolicy`.

**Reset to the default policy** replaces every rule in the policy with the
one rule of `fga-default`, which permits every detail. Tick **Replace every
rule in this policy** first; the API needs `"confirm": true`. Without it the
reset is refused (`STS-FGA-0020`) and nothing changes. The policy keeps its
entry name and whether it is enabled. An application with no policy of its
own is refused (`STS-FGA-0021`); create one instead.

**Removing an orphan.** **XACML → Policies** lists every application's
policy under **Applications' own policies**, grouped by application, each
linked into the editor. **Make root** is never offered for them. A policy
whose application was deleted is marked *orphaned since* the deletion, and
one no application names any more is marked *no application names it*; both
have **Remove**. The policy an application still names has no Remove, and
`POST /admin-api/xacml/delete` refuses it (`STS-FGA-0022`). Reset it from
the application's tab instead. `GET /admin-api/xacml/policies` returns the
same grouping as `applicationPolicies`, each policy with `referenced` and
`orphanedAt`.

### Mapping a type's members

A row maps one member of a detail of the type to an XACML attribute the
policy can test:

| Field | What it is |
|---|---|
| Member path | The member's name, or a dotted path to a nested member (`instructedAmount.amount`) |
| Attribute id | The attribute the policy tests, for example `urn:example:payment:amount` |
| Category | `resource` (the default), `action`, `environment`, `access-subject` or another of the listed names, or its URI |
| Data type | `string` (the default) or another of the listed XACML data types |
| Multiplicity | `single`, or `bag` for an array |

The type itself and the five common data fields (`locations`, `actions`,
`datatypes`, `identifier`, `privileges`) are always mapped and cannot be
rows. A row on the same path replaces the one already there.

A row is checked before it is saved, and a refusal is shown under the field
it is about (`STS-FGA-0023`). These are refused:

* an attribute id this service writes itself: anything under
  `urn:sts:xacml:`, `subject-id`, `resource-id`, `action-id` and the
  current-time attributes;
* a bare directory attribute name, such as `departmentNumber`, in a subject
  category, which would read as the person's own attribute;
* a category, data type or multiplicity that is not one of the listed ones;
* a path that names the type or a common data field.

While the application enforces fine-grained authorization, a change that
would leave a member uncovered is refused too (`STS-FGA-0019`), with the
paths named. Taking a row off, for example, is refused until the member is
listed in **Not for the policy**.

## Which applications get a policy when

| How the application appeared | Its policy |
|---|---|
| Created on **Applications → New**, through `/admin-api`, or by an LDIF import | Created with it |
| Registered by a client (`POST /oauth2/register`), seen in development mode, or one of this service's own seeded applications | Created the first time fine-grained authorization is switched on for it |

Registrations and sightings do not write a policy, because they can be made
by callers who are not administrators. A policy for each of them would let
such a caller fill `ou=policies` up to `xacml.maxPolicies` and stop
administrators writing policies at all.

## The default policy

The `fga-default` template on **XACML → Policies** builds the same document,
so you can see it before any application has one. Its `PolicyId` is
`urn:sts:xacml:fga:` followed by the application's identifier, with every
character outside letters, digits and `-._~` percent-encoded. For the
application `https://rs.example/api` it is
`urn:sts:xacml:fga:https%3A%2F%2Frs.example%2Fapi`. The entry name is
`fga-`, a readable form of the identifier and twelve hexadecimal digits that
keep two similar identifiers apart, for example
`fga-https-rs-example-api-1715052a2eea`.

Edit it in the **Editor** like any other policy; the application's
**Fine-grained authorization** tab links to it. Saving, enabling or
disabling it keeps its owner. **Make root** is not offered for it, and the
management API's `setXacmlRootPolicy` refuses it. **Reset to the default
policy** on that tab writes this document over it again.

## Development and product mode

Nothing here differs between the two modes.

## Configuration

There is no setting of its own yet. Every application's policy counts toward
`xacml.maxPolicies` (default 200), the most entries `ou=policies` may hold.
An application created when the container is full is still created, without
a policy, and gets one when fine-grained authorization is switched on after
there is room. Raise `xacml.maxPolicies` in a realm with many applications.

## In the running service

* `GET /admin-api/xacml/policies` and `GET /xacml/policies` list every policy
  with `application` (its owner, or `null`) and `orphanedAt`;
  `GET /admin-api/xacml/policies` also groups them by application in
  `applicationPolicies`.
* An application's **Fine-grained authorization** tab and
  `GET /admin-api/applications?application=<id>`'s `page.fga` show the
  switch, the policy and each declared type's coverage.
* `GET /admin-api/ldap/applications` and `/admin/ldap/directory` show
  `appFgaPolicy` and `appFgaEnforced` on an application entry.
* `GET /xacml/pep/policies` names withheld policies in `withheld`.
* **XACML → Monitor** and `GET /admin-api/xacml/monitor` count the
  decisions at issuance on the `fga` row, and those at access time on the
  `authzen` row.
* **Audit** shows each decision at issuance as `fga.decision`, and each at
  access time as `authzen.decision` naming the policy.
* Failures are recorded under `STS-FGA-*` codes; see
  [error codes](error-codes.md).

## Related

* [XACML 3.0 and ALFA](xacml.md) — the engine and the repository.
* [Configuring XACML and ALFA](configure-xacml.md) — the templates and the
  policy operations.
* [AuthZEN](authzen.md) — access evaluations, against the realm's root
  policy or an enforcing application's own.
* [Remote PEP](remote-pep.md) — what a remote PEP pulls.
