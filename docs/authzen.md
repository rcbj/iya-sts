---
title: AuthZEN
---

# AuthZEN Authorization API 1.0

[AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
is the OpenID Foundation's standard for asking a Policy Decision Point (PDP)
one question per access. A Policy Enforcement Point (PEP) sends a subject, an
action, a resource and a context, and gets back `decision: true` or `false`.

This service answers those questions. **It does not have a second policy
language for them.** Every authorization decision this service makes, for an
AuthZEN caller, for an internal application, or for its own console and
APIs, is written in [XACML 3.0](xacml.md) (or in ALFA, which is stored as
XACML). An AuthZEN request is **converted** into an XACML request by rules
this page defines, decided by the realm's root policy, and the XACML result is
converted back.

```
   a PEP                       iya-sts (one trust realm)

  POST /access/v1/evaluation
  { subject, action,     ──▶  1. who is asking, and may they ask?
    resource, context }       2. convert AuthZEN → XACML
                                 (fixed rules + the realm's catalogue)
                              3. the realm's ROOT XACML policy decides
  { "decision": true }  ◀──   4. convert XACML → AuthZEN, fail-closed
```

AuthZEN is an addition. The XACML endpoints (`/xacml`, `/xacml/pdp`,
`/xacml/policies`, `/xacml/pep/*`, `/xacml/pip`) and the
[remote PEP](remote-pep.md) container are unchanged. The difference between
the two is where the decision is made: a remote PEP pulls the policies and
decides locally, and an AuthZEN PEP asks this service per request.

## The conversion, AuthZEN to XACML

The conversion is the contract between a PEP and the policies a realm writes.
It has three parts, applied in this order.

### 1. Fixed rules

These five members always become the same XACML attributes, in every realm:

| AuthZEN member | XACML category | XACML attribute |
|---|---|---|
| `subject.id` | access-subject | `urn:oasis:names:tc:xacml:1.0:subject:subject-id` |
| `subject.type` | access-subject | `urn:sts:xacml:authzen:subject-type` |
| `action.name` | action | `urn:oasis:names:tc:xacml:1.0:action:action-id` |
| `resource.id` | resource | `urn:oasis:names:tc:xacml:1.0:resource:resource-id` |
| `resource.type` | resource | `urn:sts:xacml:authzen:resource-type` |

All values are strings.

### 2. Trusted facts

This service adds these attributes to every AuthZEN request. **They come from
the caller's authentication and this service's own records, never from the
request body**, so a policy can rely on them:

| Attribute (environment category) | Value |
|---|---|
| `urn:sts:xacml:protocol` | `authzen`, so a policy can tell an AuthZEN question apart from this service's own |
| `urn:sts:xacml:realm` | the trust realm |
| `urn:sts:xacml:authzen:caller` | the authenticated caller: the directory entry's DN, or the OAuth client's id |
| `urn:sts:xacml:authzen:application` | the application the question is scoped to (chosen with `context.application`, checked against the caller's scope) |
| `urn:sts:xacml:authzen:supplied` | a bag naming every member the caller sent, by path: `subject.properties.department`, `context.source_ip` |

**Subjects that are directory people.** For a `subject.type` listed in
`authzen.resolveSubjectTypes` (default `user`), `subject.id` names a person in
the realm's directory. The policy can then read that person's roles
(`urn:sts:xacml:role`) and directory attributes (by their LDAP names, such as
`employeeType` or `mail`) through the Policy Information Point. The caller
cannot supply or override them. For any other type the directory is not
consulted, so an id that happens to match a person's name is not that
person.

### 3. The realm's conversion rules: the attribute catalogue

Every other member — `subject.properties.*`, `action.properties.*`,
`resource.properties.*` and `context.*` — reaches the policy **only through a
conversion rule the realm declares**. A member with no rule is refused with
400, in every mode, so a property name never takes on a meaning by accident.

Each rule is one row of the realm's attribute catalogue:

| Member | Meaning | Default |
|---|---|---|
| `object` | `subject`, `resource`, `action` or `context` | required |
| `property` | the member's name, or a dotted path into a nested object (`owner.country`) | required |
| `attributeId` | the XACML attribute it is sent as | required |
| `category` | `access-subject`, `resource`, `action`, `environment` (or another XACML category, or its URI) | the object's own |
| `dataType` | `string`, `boolean`, `integer`, `double`, `date`, `dateTime`, `time`, `anyURI`, `dayTimeDuration`, `yearMonthDuration`, `hexBinary`, `base64Binary`, `rfc822Name`, `x500Name`, `dnsName`, `ipAddress`, or the type's URI | `string` |
| `multiplicity` | `single` (one value) or `bag` (a JSON array) | `single` |
| `description` | free text for administrators | — |

Rows are kept on the realm's `sts-authzen-api` application (one value of
`authzenAttribute` each) and edited on **Protocols → XACML → AuthZEN** or
through `/admin-api/xacml/authzen` (below). A row for the same `object` and
`property` replaces the previous one.

**Reserved identifiers.** A rule may not convert a caller's value into an
identifier this service fills in itself. A value the caller sends would hide
the one this service would have supplied, and the policy would believe it.
Refused:

* anything in `urn:sts:xacml:` (roles, the realm, the protocol, the caller,
  the application, and every other trusted fact);
* `subject-id`, `resource-id`, `action-id`, and the current date and time;
* `context.application` and `context.supported_obligations`;
* in a subject category, a bare directory attribute name such as
  `employeeType`. Use an identifier of your own, such as
  `urn:example:department`.

### Value conversion

The rule's datatype decides; the JSON value is never quietly converted into
something else:

| Sent | Result |
|---|---|
| a member no rule declares | 400, in every mode |
| `null` | 400; leave the member out, or send a value |
| a string | parsed at the rule's datatype; 400 if it does not parse |
| a number | accepted by an `integer` rule (whole numbers only) or a `double` rule |
| `true` / `false` | accepted by a `boolean` rule |
| an array | accepted by a `bag` rule only; each element follows the rules above |
| an object | accepted only through rules for its members (`owner.country`) |
| `""` or `[]` | sent as an empty value or an empty bag, and listed in `urn:sts:xacml:authzen:supplied` |

A member that AuthZEN 1.0 does not define, at the top level or inside
`subject`, `action` or `resource`, is also refused with 400.

## The conversion back, XACML to AuthZEN

Only an explicit Permit allows access. A failure to decide is never reported
as an ordinary denial:

| XACML result | `decision` |
|---|---|
| Permit | `true` |
| Permit with an obligation the PEP has not declared it can carry out (see *Obligations*) | `false` |
| Deny | `false` |
| NotApplicable | `false` |
| Indeterminate because an attribute was missing | `false` |
| Indeterminate because of a fault (a root policy that will not load, a processing error) | an error (500), never `false` |

`urn:sts:xacml:obligation:log` is the one obligation this service carries out;
it is recorded in the audit log.

### Obligations

This service implements the AuthZEN **Obligations Profile** (a draft). Any
other XACML obligation is converted into the profile's form and handed to the
PEP in `context.obligations`, but **only when the request declares, in
`context.supported_obligations`, every obligation type the answer carries.** A
PEP that does not know the profile would read `decision: true` and grant
access without carrying the obligation out, so without the declaration the
answer stays `false`.

| XACML obligation id | AuthZEN `type` |
|---|---|
| `urn:sts:xacml:authzen:obligation:step-up` | `step-up` (requires `acr_value`; `amr_values` is an array) |
| `urn:sts:xacml:authzen:obligation:notification` | `notification` (requires `to`, an array, and `body`) |
| `urn:sts:xacml:authzen:obligation:session_termination` | `session_termination` (requires `subject`) |
| `urn:sts:xacml:obligation:log` | not handed: this service carries it out |
| anything else | `custom`, with the XACML id as `xacml_obligation` |

Each attribute assignment becomes a property named by the last segment of its
attribute id (`…:acr_value` and `acr_value` both become `acr_value`). A
registered type missing a property it requires is not handed, and a Permit
carrying it answers `false`. In ALFA:

```
rule approve {
    permit
    target clause act == "approve"
    on permit {
        obligation "urn:sts:xacml:authzen:obligation:step-up" {
            "acr_value" = "phr"
        }
    }
}
```

A PEP that sends `"context": { "supported_obligations": ["step-up"] }` gets:

```json
{ "decision": true,
  "context": { "obligations": [
    { "id": "obligation-1", "type": "step-up",
      "properties": { "acr_value": "phr" } } ] } }
```

The metadata lists the types as `supported_obligations`.
`authzen.obligationsProfile` turns the profile off.

With `authzen.returnReasons` on, the response
carries a `context` with the XACML decision, the reason and any advice. It is
explanatory only: `decision` is the answer.

## A worked example

A realm declares one rule:

```json
{"object":"resource","property":"classification",
 "attributeId":"urn:example:classification"}
```

A PEP, authenticated as `cn=docs-pep,ou=users,dc=acme,dc=example` and scoped
to `engineering-portal`, sends:

```json
{
  "subject":  { "type": "user", "id": "alice" },
  "action":   { "name": "read" },
  "resource": { "type": "document", "id": "doc-1",
                "properties": { "classification": "internal" } },
  "context":  { "application": "engineering-portal" }
}
```

The XACML request the policy sees (shown in the XACML JSON Profile's shape):

| Category | Attribute | Value |
|---|---|---|
| access-subject | `…:subject:subject-id` | `alice` |
| access-subject | `urn:sts:xacml:authzen:subject-type` | `user` |
| action | `…:action:action-id` | `read` |
| resource | `…:resource:resource-id` | `doc-1` |
| resource | `urn:sts:xacml:authzen:resource-type` | `document` |
| resource | `urn:example:classification` | `internal` |
| environment | `urn:sts:xacml:protocol` | `authzen` |
| environment | `urn:sts:xacml:realm` | `acme` |
| environment | `urn:sts:xacml:authzen:caller` | `cn=docs-pep,ou=users,dc=acme,dc=example` |
| environment | `urn:sts:xacml:authzen:application` | `engineering-portal` |
| environment | `urn:sts:xacml:authzen:supplied` | `subject.type`, `subject.id`, `action.name`, `resource.type`, `resource.id`, `context.application`, `resource.properties.classification` |

Because `user` is a resolved subject type, the policy can also read alice's
`employeeType`, `mail` and roles from the directory. A root policy that decides
it, in ALFA:

```
namespace docs {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute protocol { category = environmentCat
        id = "urn:sts:xacml:protocol" type = string }
    attribute app { category = environmentCat
        id = "urn:sts:xacml:authzen:application" type = string }
    attribute classification { category = resourceCat
        id = "urn:example:classification" type = string }
    attribute staff { category = subjectCat id = "employeeType" type = string }

    policy engineeringDocuments {
        id = "urn:example:engineering-documents"
        apply firstApplicable
        target clause protocol == "authzen"
        target clause app == "engineering-portal"
        rule staffReadInternal {
            permit
            target clause act == "read"
            target clause classification == "internal"
            target clause staff == "staff"
        }
    }
}
```

The answer is `{ "decision": true }` if alice's entry says `staff`, and
`false` otherwise.

## Guidelines for conversion rules and policies

1. **Write the decision in XACML, and only there.** A PEP sends facts; the
   realm's policy decides. Do not encode a decision in a conversion rule or in
   the PEP.
2. **Target AuthZEN questions explicitly.** Start an AuthZEN policy, or a
   policy set's branch, with `urn:sts:xacml:protocol == "authzen"`, and narrow
   it by `urn:sts:xacml:authzen:application`. The root policy also decides this
   service's other questions, and an AuthZEN rule should not match them.
3. **Use your own namespace for converted attributes.** Name them
   `urn:<your organisation>:<application>:<property>`, for example
   `urn:example:todo:owner-id`. Never use `urn:sts:xacml:`; it is refused.
4. **Declare the datatype the policy compares with.** A rule's datatype
   should match the policy's attribute declaration. A mismatch is a property
   the policy never sees, which looks like a denial.
5. **Use `bag` only for genuinely multi-valued members**, and compare them
   with bag functions (`stringIsIn`, `stringAtLeastOneMemberOf`). Use
   `single` everywhere else, so an array is refused rather than decided on.
6. **Nested objects: one rule per leaf** (`owner.country`, `owner.city`).
   Objects are never flattened into strings.
7. **Let the directory speak for people.** For a resolved subject type, read
   roles and attributes from the directory through the PIP. Do not declare
   subject properties for facts the directory already holds; a caller's copy
   is not trusted.
8. **Trust only the trusted facts.** A policy that needs to know who asked, or
   for which application, reads `urn:sts:xacml:authzen:caller` and
   `urn:sts:xacml:authzen:application`, never a property the PEP could set.
9. **Tell "not sent" from "sent empty" with `supplied`.** An attribute sent
   with an empty value and one not sent both look empty to most functions;
   `urn:sts:xacml:authzen:supplied` says which.
10. **Make the policy total for its application.** Deny explicitly where a
    denial is the intent; NotApplicable also answers `false`, but is harder to
    read in the decision log.
11. **Internal applications follow the same rules.** This service's own
    applications, the reports application among them, ask their questions
    through the same conversion and the same XACML policies. A report runs
    with the permissions of the person signed in to it (#1176).

## Calling it

```
POST /access/v1/evaluation                      the default realm
POST /realm/<id>/access/v1/evaluation           a trust realm
Content-Type: application/json
X-Request-ID: 7c1f…                             optional; echoed back

{
  "subject":  { "type": "user", "id": "alice" },
  "action":   { "name": "read" },
  "resource": { "type": "document", "id": "doc-1",
                "properties": { "classification": "internal" } },
  "context":  { "application": "engineering-portal" }
}
```

```
200 OK
{ "decision": true }
```

A denial is `200` with `"decision": false`. A request that could not be
evaluated gets an error status and a body of the form
`{ "error": { "status": 400, "message": "…" } }`:

| Status | When |
|---|---|
| 400 | the request is not valid: a missing member, a value that breaks the rules below, an undeclared property, or several applications in scope and none named |
| 401 | the caller did not authenticate; `WWW-Authenticate: Bearer realm="<issuer>"` when tokens are accepted |
| 403 | the caller may not ask (no `AUTHZEN_PEPS`, or the access policy refuses it), its token lacks `authzen:evaluate`, or it is not scoped to the application named |
| 500 | the policy could not be evaluated (for example the root policy does not load) — never reported as `false` |
| 501 | AuthZEN, or XACML, is turned off in the realm, or the realm has no `sts-authzen-api` application |

### Several evaluations at once

`POST /access/v1/evaluations` (section 7) takes top-level `subject`, `action`,
`resource` and `context` as defaults and an `evaluations` array whose items
override them, member by member:

```json
{
  "subject":  { "type": "user", "id": "alice" },
  "resource": { "type": "document", "id": "doc-1" },
  "context":  { "application": "engineering-portal" },
  "evaluations": [
    { "action": { "name": "read" } },
    { "action": { "name": "delete" } }
  ],
  "options": { "evaluations_semantic": "execute_all" }
}
```

```json
{ "evaluations": [ { "decision": true }, { "decision": false } ] }
```

* `evaluations_semantic` is `execute_all` (the default), `deny_on_first_deny`
  (stop after the first `false`) or `permit_on_first_permit` (stop after the
  first `true`).
* A failed item is `"decision": false` with
  `"context": { "error": { "status": 400, "message": "…" } }`. The batch is
  still `200`, so read each item's `context.error`.
* Without `evaluations`, or with an empty one, the request is one evaluation
  and is answered as `/access/v1/evaluation` answers it.
* More items than `authzen.maxEvaluations`, or a body larger than
  `authzen.maxBodyBytes`, refuses the whole batch with 400 before anything is
  decided.
* Each item is its own audit row, carrying the batch's `X-Request-ID` (or an
  id this service makes up) and the item's position.

### Metadata

`GET /.well-known/authzen-configuration` is the PDP's metadata (AuthZEN 1.0
section 9). It needs no credential. A trust realm's PDP identifier carries
the realm's path, and section 9.2 inserts the well-known segment before it,
so a realm's document is at `/.well-known/authzen-configuration/realm/<id>`:

```json
{
  "policy_decision_point": "https://sts.example.com/realm/acme",
  "access_evaluation_endpoint": "https://sts.example.com/realm/acme/access/v1/evaluation",
  "access_evaluations_endpoint": "https://sts.example.com/realm/acme/access/v1/evaluations"
}
```

It lists only what answers in that realm: the batch endpoint only while
`authzen.batchEnabled` is on. There are no search endpoints, no
`capabilities`. It carries `signed_metadata`: a JWT of the same members, with
`iss` the PDP identifier, signed with the realm's key the way the OAuth
metadata is and verifiable with the realm's JWKS (`/oauth2/jwks`).
`authzen.signedMetadata` turns it off. While the API is off in the realm the
document answers 501.

### Who may call it

**The realm is the tenant.** A caller is looked up in the directory of the
realm whose path it called, so a caller from another realm is unknown there.

**Authentication** is chosen per realm by `authzen.callerAuthentication`:

| Value | The caller presents |
|---|---|
| `mtls` (default) | a client certificate this service verifies against its client truststore. It names the directory entry that stores it in `userCertificate`, or the person it was issued to by this service. |
| `bearer` | an OAuth 2.0 access token from `client_credentials`, requested with `resource=<realm base>/access/v1` and `scope=authzen:evaluate`. The caller is the client. |
| `mtls+bearer` | both, and the token must be bound to the certificate presented (RFC 8705), so the two name one party |

AuthZEN itself defines no scope; `authzen:evaluate` is this service's. A
client may ask for it only if it holds a delegated permission grant of
`urn:sts:authzen-api:authzen:evaluate` on the realm's `sts-authzen-api`
application.

**Authorization.** The caller must hold the built-in `AUTHZEN_PEPS` role: be a
member of the group named by `roles.authzenPepGroup` (default
`authzen-peps`). A person, a service account, or an application's entry can be
a member. The access-control policy decides it on resource `authzen-api`, so
`/admin/xacml/decide` reproduces the answer. `AUTHZEN_PEPS` is a separate role
from `XACML_USER` and `REMOTE_PEPS`: it lets a caller ask for decisions and
nothing else.

**Application scope.** An administrator names the applications a caller may ask
about:

* on a person's or service account's entry, `stsAuthzenApplication`;
* on an application, `appAuthzenApplication`. A client's own application is
  always in its scope.

`context.application` must be one of them. When the request names none and the
caller has exactly one, that one is used. The application a policy sees is
`urn:sts:xacml:authzen:application`, never the value as the caller sent it.
The remote PEP register (`ou=peps`) is not consulted.

## The console and the management API

**Protocols → XACML → AuthZEN** (`/admin/xacml`, the AuthZEN tab) shows whether
the API answers in the realm, how callers authenticate, the AuthZEN settings,
the attribute catalogue, and the members of the `AUTHZEN_PEPS` group with
their application scope. From there an administrator adds, replaces or
removes a catalogue row, and sets a caller's scope.

The same operations are on the management API:

| Operation | What it does |
|---|---|
| `GET /admin-api/xacml/authzen` | the tab, as JSON; `?caller=<name or DN>` looks one caller up |
| `POST /admin-api/xacml/authzen/set-attribute` | add a row, or replace the row for the same `object` and `property` |
| `POST /admin-api/xacml/authzen/remove-attribute` | remove the row for an `object` and `property` |
| `POST /admin-api/xacml/authzen/set-scope` | replace a caller's application scope: `caller` and `applications` |

```
POST /admin-api/xacml/authzen/set-attribute
{"object":"resource","property":"classification",
 "attributeId":"urn:example:classification"}

POST /admin-api/xacml/authzen/set-scope
{"caller":"todo-pep","applications":["todo-app"]}
```

`GET /admin-api/openapi.json` carries every member and refusal. The scope can
also be set on an application's own page, as `appAuthzenApplication`.

## Configuration

Each setting is per realm and can be changed at run time on `/admin/xacml`
or with `/admin-api/config`. That page and `GET /admin-api/config` are the
live source; this table is a copy.

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `authzen.enabled` | `STS_AUTHZEN_ENABLED` | `true` | The API answers; off, its routes answer 501 |
| `authzen.callerAuthentication` | `STS_AUTHZEN_CALLER_AUTHENTICATION` | `mtls` | `mtls`, `bearer` or `mtls+bearer` |
| `authzen.resolveSubjectTypes` | `STS_AUTHZEN_RESOLVE_SUBJECT_TYPES` | `user` | Subject types whose id is a directory person |
| `authzen.batchEnabled` | `STS_AUTHZEN_BATCH_ENABLED` | `true` | `POST /access/v1/evaluations` answers, and the metadata names it |
| `authzen.maxEvaluations` | `STS_AUTHZEN_MAX_EVALUATIONS` | `64` | The most items one batch may carry (1–1000) |
| `authzen.maxBodyBytes` | `STS_AUTHZEN_MAX_BODY_BYTES` | `262144` | The largest batch request body |
| `authzen.signedMetadata` | `STS_AUTHZEN_SIGNED_METADATA` | `true` | The metadata carries `signed_metadata` |
| `authzen.obligationsProfile` | `STS_AUTHZEN_OBLIGATIONS_PROFILE` | `true` | Hand obligations to a PEP that declares every type (see *Obligations*) |
| `authzen.returnReasons` | `STS_AUTHZEN_RETURN_REASONS` | `false` | Add the XACML decision, the reason and any advice to the response's `context` |
| `roles.authzenPepGroup` | `STS_ROLES_AUTHZEN_PEP_GROUP` | `authzen-peps` | The group whose members hold `AUTHZEN_PEPS` |

## In the running service

* Every evaluation is an `authzen.decision` row in the audit log, with the
  caller, the application, the subject and resource types, the action, the
  request id and the decision. Property values and credentials are not
  recorded.
* `/admin/xacml/monitor` counts AuthZEN decisions on its own row. It counts
  decisions, not enforcements: the PEP enforces the answer in its own process.
* `/admin/sts-metadata` lists the endpoint.

## What is not built yet

Each of these has a ticket. Until it is built, it is not advertised in the
metadata.

| | Ticket |
|---|---|
| The three Search APIs (subject, resource, action) | #1175 |
| Searches as `/report` sources, run with the permissions of the person signed in | #1176 |
| An AuthZEN endpoint on the remote PEP container | #1179 |
| The Access Request and Approval Profile (design) | #1180 |
| The OAuth token issuance and token exchange binding (design) | #1181 |

## Related

* [XACML 3.0 and ALFA](xacml.md) — the engine, the repository and writing a
  policy
* [Remote PEP](remote-pep.md) — the container that pulls the policies and
  decides locally
* [Error codes](error-codes.md) — the `STS-AUTHZEN-*` section
