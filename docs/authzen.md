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
converted back. An evaluation about an application that enforces
[fine-grained authorization](fga.md) is decided against that application's
own policy instead; see
[Applications with their own policy](#applications-with-their-own-policy).

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
[remote PEP](remote-pep.md) container's pull are unchanged. The difference between
the two is where the decision is made: a remote PEP pulls the policies and
decides locally, and an AuthZEN PEP asks this service per request.

The [remote PEP](remote-pep.md#an-authzen-edge-pdp) container answers the same
access evaluations itself, as an **edge PDP** over the policy and the attribute
catalogue it pulls from the realm — so a PEP in its network can ask a PDP
nearby, and gets the answer the service would give. An evaluation about an
application that enforces fine-grained authorization, whose policy the edge
PDP is never sent, it forwards to this service (see
[Applications with their own policy](#applications-with-their-own-policy)).
**It admits the callers
this realm admits**, pulled from the service: who holds `AUTHZEN_PEPS` as the
access-control policy decides it, by their certificates, with their
application scopes. Anybody holding `REMOTE_PEPS` can read that list. What it
cannot do that the service can is listed there.

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
| `urn:sts:xacml:authzen:approval-id`, `:approved-until` (a dateTime), `:approver` | only when the request carried a `context.approval` this service verified (see [Access requests and approvals](#access-requests-and-approvals)) |

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

### Applications with their own policy

An application whose `appFgaEnforced` is on owns the policy that decides
access to it (see [Fine-grained authorization](fga.md)). An evaluation whose
application — `context.application`, or the caller's only one — is such an
application is decided against **that policy alone**: not the root, and not
a policy the root references. Every other application is decided against the
root, as above. Nothing about the request changes for the caller, and the
metadata document is the same. A [search](#searching) about such an
application decides each candidate against the same policy.

The request the policy sees is the one the three parts above build, with two
more facts:

| Attribute | Category | Value |
|---|---|---|
| `urn:sts:xacml:fga:application` | resource | the application whose policy decides |
| `urn:sts:xacml:fga:stage` | environment | `access` |

For example, a caller scoped to `https://docs.example/api` sends

```json
{"subject":  {"type": "user", "id": "alice"},
 "action":   {"name": "delete"},
 "resource": {"type": "document", "id": "doc-1"},
 "context":  {"application": "https://docs.example/api"}}
```

If that application enforces fine-grained authorization and its policy denies
`delete` at stage `access`, the answer is `{"decision": false}`, whatever the
root policy says. If its policy is disabled or does not parse, the answer is
`500` (`STS-AUTHZEN-0046`), and in a batch that item's `context.error`; a
search is `500` as a whole. A caller still reaches only applications in its
scope: naming one outside it is `403`. Obligations are handed back by the
rules under *Obligations* below, whichever policy decided.

The audit row of such an evaluation names the application's policy, its
`PolicyId` and version. The decision is counted on the AuthZEN row of
**XACML → Monitor**, like every AuthZEN decision.

**The remote PEP's edge PDP forwards these evaluations here.** Application
policies are withheld from `GET /xacml/pep/policies`, so the edge PDP never
holds one. Instead the AuthZEN catalogue it pulls names the applications that
enforce fine-grained authorization (`fgaApplications`), and an evaluation
the edge PDP is asked about one of them is sent, as one single evaluation
naming the application in `context.application`, to this realm's
`POST /access/v1/evaluation` over mutual TLS with the PEP's own certificate.
This service decides it against the application's policy, as above, and the
edge passes the answer back. An error here — the `500` for a policy that
cannot be used, a refusal of the PEP, no answer — is an error there, never
`false`. So the PEP's directory entry must hold `AUTHZEN_PEPS` and have the
application in its scope, and a policy here sees the **PEP** as the caller.
[The remote PEP](remote-pep.md#applications-that-enforce-fine-grained-authorization-forwarded)
has the details.

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
| No usable policy for an application that enforces fine-grained authorization | an error (`500`), never `false`, and never the root policy instead |

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
    with the permissions of the person who owns it, as the caller.

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
| 500 | the policy could not be evaluated (for example the root policy does not load, or the application enforces fine-grained authorization and its policy is disabled or missing) — never reported as `false` |
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

### Searching

The three AuthZEN Search APIs (section 8) answer which subjects, resources or
actions the realm's policy permits. XACML has no reverse query, so a search
takes the **candidates this service can name**, asks the realm's root policy
(or, for an application that enforces fine-grained authorization, that
application's own policy) about each one exactly as an evaluation would, and answers the permitted
ones. Every result is therefore a real Permit.

| Endpoint | Request | Candidates |
|---|---|---|
| `POST /access/v1/search/subject` | `subject.type` (no id), `action`, `resource` | the realm's directory people, for a type in `authzen.resolveSubjectTypes`; none for any other type |
| `POST /access/v1/search/resource` | `subject`, `action`, `resource.type` (no id) | `application`: every application; `api`: the APIs (resource-server applications); `delegation`: every delegation relationship an application declares, as `<source>\|<target>`; none for any other type |
| `POST /access/v1/search/action` | `subject`, `resource` (no `action`) | every action name the realm's policies compare `action-id` with, and, for an `application` or `api` resource, the permissions it defines |

An id sent where the search names only a type is ignored, as the
specification says. The answer is:

```json
{ "page": { "next_token": "1.4f0c2b9d8e7a6c51", "count": 1, "total": 3 },
  "results": [ { "type": "user", "id": "alice" } ] }
```

* `page.limit` (default `authzen.searchPageSize`) sets the page size;
  `page.token`, set to the previous `next_token`, continues. An empty
  `next_token` ends the result set. A continued request must repeat every
  entity and the limit unchanged, or it is refused with 400.
* At most `authzen.searchMaxCandidates` candidates are decided per search.
  Past that, or when a candidate could not be decided, the answer says so
  in `context.incomplete`.
* Searches are not transitive: a candidate is decided as named.
* Each search is one `authzen.search` audit row.

#### From the reports application

The same three searches are report sources in `/report`: `authzenSubjects`,
`authzenResources` and `authzenActions` ([Reports](reporting.md#the-authzen-search-sources)).
A report runs **with the permissions of the person who owns it**. The owner
is the search's caller, `urn:sts:xacml:authzen:caller`, and `sts-report` is
the application, `urn:sts:xacml:authzen:application`. A policy can tell a
report's question from a PEP's, and one person's report from another's:

```
rule reportOwnersAudit {
    permit
    target clause act == "audit"
    target clause app == "sts-report"
    target clause caller == "alice"
}
```

Every report rule still applies first: the report rights, the access-control
policy on the definition, and the anchor and time caps. An owner who is a
person of another realm is refused, because the caller is a name and in this
realm that name is somebody else, or nobody.

### Metadata

`GET /.well-known/authzen-configuration` is the PDP's metadata (AuthZEN 1.0
section 9). It needs no credential. A trust realm's PDP identifier carries
the realm's path, and section 9.2 inserts the well-known segment before it,
so a realm's document is at `/.well-known/authzen-configuration/realm/<id>`:

```json
{
  "policy_decision_point": "https://sts.example.com/realm/acme",
  "access_evaluation_endpoint": "https://sts.example.com/realm/acme/access/v1/evaluation",
  "access_evaluations_endpoint": "https://sts.example.com/realm/acme/access/v1/evaluations",
  "search_subject_endpoint": "https://sts.example.com/realm/acme/access/v1/search/subject",
  "search_resource_endpoint": "https://sts.example.com/realm/acme/access/v1/search/resource",
  "search_action_endpoint": "https://sts.example.com/realm/acme/access/v1/search/action",
  "supported_obligations": ["step-up", "notification", "session_termination", "custom"],
  "access_request_endpoint": "https://sts.example.com/realm/acme/access/v1/access-requests",
  "jwks_uri": "https://sts.example.com/realm/acme/oauth2/jwks",
  "capabilities": ["urn:openid:authzen:capability:access-request"]
}
```

It lists only what answers in that realm: the batch endpoint while
`authzen.batchEnabled` is on and the three searches while
`authzen.searchEnabled` is on, and the access request endpoint and
`jwks_uri` while `authzen.accessRequests` is on. It carries `capabilities`
only while one is on: `urn:openid:authzen:capability:access-request` with
`authzen.accessRequests`, and the token issuance capability with
`authzen.tokenExchange` (see *OAuth token exchange*). It carries
`signed_metadata`: a JWT of the same members, with
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

A remote PEP's [edge PDP](remote-pep.md#an-authzen-edge-pdp) admits by the
same answers: it pulls the callers admitted now, each with the name above,
its certificates' SHA-256 digests and its scope, from
`GET /xacml/pep/authzen-callers`, and converges on its poll.

## OAuth token exchange: deciding for another authorization server

The [AuthZEN Binding for OAuth 2.0 Token Exchange](https://github.com/openid/authzen/blob/main/profiles/authzen-oauth/authzen-oauth-token-exchange-1_0.md)
(a draft) and the Token Issuance Profile it builds on let an authorization
server that is about to perform an RFC 8693 token exchange ask a PDP whether
it may. This service can be that PDP. It is off by default; turn on
`authzen.tokenExchange` in the realm.

The authorization server sends one batch to `/access/v1/evaluations` with
`execute_all`:

* the **subject gate**: the exchange subject, the action
  `issue:<type>:token_exchange`, and a resource of type `audience` naming
  the target;
* the **requesting party gate**: the same action and resource, with the
  party that is asking (the `actor_token`'s party, or else the
  authenticated client) as the subject. When the two are the same, the
  authorization server can send one gate;
* one **scope tuple** per requested scope: the exchange subject, the scope as
  the action, and a resource of type `protected_resource`.

The token types are `access_token`, `refresh_token`, `id_token`, `jwt`,
`saml1`, `saml2`, `id_jag` (an Identity Assertion JWT Authorization Grant)
and `txn_token` (a Transaction Token).

### The same decision as this service's own exchanges

This service already decides who may act for whom when it performs a token
exchange itself, from the delegation settings on `/admin/delegation`
(`appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf`, the delegation
semantics, the protected groups, `may_act`) and the issuance policy's
exchange rules. The binding uses the same facts and the same rules. There
is no second list of who may act for whom, and nothing about a local RFC
8693, WS-Trust or Kerberos delegation changes. An exchange asked over AuthZEN
gets the answer the same exchange would get at this service's token
endpoint:

* both gates are `true` when this service would issue the token;
* when the issuance policy refuses, the gate the refusal is about is
  `false`: the subject gate for a fact about the subject or the target, the
  requesting party gate for a fact about the party, and both for a protected
  subject or a refusal of the realm's own policy. The authorization server
  fails the exchange on either. The audit row says which;
* in development mode, a refusal the policy does not enforce answers `true`,
  because the local token endpoint would issue the token too. The audit row
  carries `STS-AUTHZEN-0110` and says what product mode would answer. A
  `may_act` naming somebody else is refused in every mode.

A scope tuple is `true` when the scope survives the same three checks a
local exchange's scope meets: the issuance policy's exchange stage (a scope
the subject token does not carry is refused in product mode), the client's
declared scopes (`oauthAllowedScope`, from `context.client_id`), and the
subject's roles for a gated permission.

The parties are looked up in this realm: the subject by name or `urn:uuid:`
subject, the requesting party and the source application by identifier or
`client_id`. An external authorization server whose clients and users are
not registered here gets the answer an unregistered party gets here.

### The fixed rules

These conversion rules are built in and cannot be edited. A realm's
attribute catalogue can add rows (a `context.tenant`, say, whose attribute
reaches the exchange question beside these facts), but it cannot override
them: a row naming any of the context members below, or a path under one,
is refused.

| Member | Fixed rule |
|---|---|
| `resource.type = audience, action.name = issue:<type>:token_exchange` | a GATE tuple. The first one for a target is the subject gate; one naming another subject for the same target and type is the requesting party gate; a third subject is refused |
| `resource.type = audience, action.name = issue:<type>:<grant>` | any other grant, or a token type not registered: decided false (this PDP decides the token-exchange gate only) |
| `resource.type = protected_resource` | a SCOPE tuple: action.name is the scope, verbatim; decided only beside a token-exchange gate in the same batch, and only for the exchange subject (or, for txn_token, the requesting party) |
| `<type> of the gate action` | the token type short name: access_token, refresh_token, id_token, jwt, saml1, saml2, id_jag, txn_token; sent as urn:sts:xacml:authzen:token-type |
| `subject (subject gate)` | the exchange subject: the access-subject of the exchange question, a person by name or urn:uuid subject, an application by identifier or client_id (urn:sts:client:<id> is <id>) |
| `subject (requesting party gate)` | the actor: the intermediary-subject of the exchange question; with no requesting party gate, the subject itself (the gates coincide) |
| `subject.type` | user, client or workload, else 400; sent as urn:sts:xacml:authzen:subject-type on each party |
| `resource.id (gate)` | the one target R, resolved as a local exchange's audience is |
| `context.subject_token.aud, .client_id, .azp` | S, the application the subject token was issued for, in that order, as a local exchange reads its subject_token |
| `context.may_act` | may-act-present, and may-act-names-actor compared with the requesting party (sub, and iss where the claim has one); never a permit by itself |
| `context.act` | its depth, as urn:sts:xacml:authzen:act-depth |
| `context.subject_token_type, context.actor_token_type` | verbatim, as urn:sts:xacml:authzen:subject-token-type and ...:actor-token-type |
| `context.subject_token.scope` | what a scope tuple may not widen (exchange stage), and the set granted_scope narrows when the request names no scope |
| `context.subject_token.exp` | the ceiling on token_lifetime; none left is a false subject gate |
| `context.client_id` | the client whose declared scopes a scope tuple is held to, and whose access-token lifetime bounds token_lifetime |
| `context.cnf, .acr, .amr, .auth_time, .jti` | read for their type only; no rule decides on them |
| `exchange_semantics` | not sent: the policy chooses by its precedence, as for a local exchange that named none |
| `urn:sts:xacml:protocol` | OAuth 2.0, the act's protocol, so one policy decides both; the trusted urn:sts:xacml:authzen:caller tells this one apart |

A policy can tell an exchange asked over AuthZEN from one this service
performs: only the AuthZEN one carries `urn:sts:xacml:authzen:caller`,
`urn:sts:xacml:authzen:token-type` and the other `urn:sts:xacml:authzen:*`
facts above.

### What the answer carries

The subject gate may carry the Token Issuance Profile's `context.issuance`.
It only ever narrows what the authorization server would otherwise issue:

* `token_lifetime`: the lesser of the subject token's remaining lifetime
  (`context.subject_token.exp`) and, for an access token, this realm's
  access-token lifetime for the client. A subject token with no lifetime left
  makes the subject gate `false`;
* `granted_scope`: only when the request names no scope. It is the subject
  token's scope (`context.subject_token.scope`), narrowed by the same three
  checks as a scope tuple. Without a subject token scope it is left out, and
  the authorization server uses its own defaults.

The answer never sets `sub`, `aud`, `act`, `may_act` or any other claim. The
binding reserves them: a PDP that could write `act` could invent a
delegation history. `context.issuance` is sent whatever
`authzen.returnReasons` says; with that setting on, each item also carries
`xacml_decision`, `reason_admin` and, for a gate, `exchange_semantics` (the
delegation or impersonation the policy chose).

While the binding is on, the metadata advertises
`"capabilities": ["urn:openid:authzen:capability:token-issuance"]`. A gate
for any other grant (`issue:access_token:authorization_code`, say) or an
unregistered token type is answered `false`: this PDP decides the token
exchange gate only.

### ID-JAG and Transaction Tokens

* **ID-JAG.** The gates name the resource authorization server that will
  redeem the grant (level 1), and are decided by whether the identity
  provider's client may delegate to it. Scope tuples may name the resources
  behind it (level 2); they are decided as any scope tuple.
* **Txn-Token.** The requesting party is a workload. The authorization server
  sends scope tuples for the workload as well as for the subject, and the
  workload's are decided as the workload's own (its declared scopes and
  roles). Outside a Txn-Token, a scope tuple for the requesting party is
  `false`: scope is the subject's authority.

### A worked example

A gateway client `gw` exchanges Alice's access token for one addressed to
`https://api.example`, which is registered here as the application `api`.
`gw` has `appAllowedToDelegateTo: api` and declares `read:docs`.

```http
POST /access/v1/evaluations HTTP/1.1
Content-Type: application/json

{
  "resource": { "type": "audience", "id": "https://api.example" },
  "context": {
    "client_id": "gw",
    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "subject_token": { "aud": "gw", "scope": "read:docs write:docs",
                       "exp": 1767225900 }
  },
  "evaluations": [
    { "subject": { "type": "user", "id": "alice" },
      "action": { "name": "issue:access_token:token_exchange" } },
    { "subject": { "type": "client", "id": "gw" },
      "action": { "name": "issue:access_token:token_exchange" } },
    { "subject": { "type": "user", "id": "alice" },
      "action": { "name": "read:docs" },
      "resource": { "type": "protected_resource",
                    "id": "https://api.example" } },
    { "subject": { "type": "user", "id": "alice" },
      "action": { "name": "write:docs" },
      "resource": { "type": "protected_resource",
                    "id": "https://api.example" } }
  ],
  "options": { "evaluations_semantic": "execute_all" }
}
```

In product mode the answer is:

```json
{
  "evaluations": [
    { "decision": true,
      "context": { "issuance": { "token_lifetime": 300 } } },
    { "decision": true },
    { "decision": true },
    { "decision": false }
  ]
}
```

The two gates are `true` because `gw` is the application Alice's token was
issued for and it may delegate to `api`, which is what the same exchange at
this service's token endpoint would need. `read:docs` is in Alice's token and
`gw` declares it. `write:docs` is in Alice's token, but `gw` does not declare
it. `token_lifetime` is what is left of Alice's token, or this realm's
access-token lifetime for `gw` if that is shorter.

### A guideline on delegation

Write who may act for whom once, as delegation settings and, where those are
not enough, as exchange rules in the realm's issuance policy. Do not write it
again in the root policy for AuthZEN. The binding never reaches the root
policy, and one rule set means a local exchange and one decided for another
authorization server cannot disagree. If a rule must apply only to exchanges
asked over AuthZEN, test `urn:sts:xacml:authzen:caller` in the issuance
policy's exchange rules.

The binding is decided by the issuance policy even when the caller's
application enforces [fine-grained authorization](fga.md). A local token
exchange asks that application's policy only about RFC 9396 authorization
details, and the binding carries none.

## Access requests and approvals

This service implements the draft **AuthZEN Access Request and Approval
Profile** and its **Callback** companion. It is both the profile's PDP and its
Access Request Service. An approval never permits anything by itself: the
PEP asks again, carrying the approval, and the realm's root policy decides
(or, for an application that enforces
[fine-grained authorization](fga.md), that application's own policy, which
then also decides whether the denial can be requested and reads the
approval's facts).

### Which denials can be requested

**The policy decides.** A Deny is requestable only when the XACML answer
carries the advice `urn:sts:xacml:advice:access-request`. Its attribute
assignments, each named `urn:sts:xacml:advice:access-request:<name>`, say:

| Assignment | Meaning |
|---|---|
| `approver-role` | a role whose holders may approve (repeatable) |
| `approver-group` | a group, by name or DN, whose members may approve (repeatable) |
| `approver-owners` | `true`: the owners of the application the question is scoped to may approve |
| `max-approval-seconds` | the longest an approval holds (never longer than `authzen.accessRequestMaxApprovalS`) |
| `emergency` | `true`: emergency access is allowed (below) |
| `context-member` | a `context` member that binds the request and the approval (repeatable); none means only subject, resource and action bind |
| `template`, `reason` | echoed as `context.access_request.template` and `context.reason` |

An example in ALFA:

```
rule requestableRead {
    deny
    target clause act == "read"
    on deny {
        advice "urn:sts:xacml:advice:access-request" {
            "urn:sts:xacml:advice:access-request:approver-group" = "doc-approvers"
            "urn:sts:xacml:advice:access-request:max-approval-seconds" = "3600"
        }
    }
}
```

A requestable denial answers `false` with:

```json
{
  "decision": false,
  "context": {
    "evaluation_id": "eval_…",
    "evaluated_at": "2026-10-30T09:00:00Z",
    "reason": "approval_required",
    "access_request": {
      "expires_at": "2026-10-30T09:10:00Z",
      "endpoint": "https://sts.example.com/realm/acme/access/v1/access-requests",
      "binding_token": "eyJ…"
    }
  }
}
```

The `binding_token` is a JWS the realm signs over the denied subject,
resource, action, the bound context members, the caller and the application.
It expires with the denial (`authzen.accessRequestDenialLifetimeS`).

### Submitting, polling and cancelling

The same caller door and the `AUTHZEN_PEPS` role as an evaluation apply.

| Request | Answer |
|---|---|
| `POST /access/v1/access-requests` | the denied `subject`, `resource`, `action` and `context`, and `denial` with the `binding_token` and `expires_at` echoed unchanged. `202` with a `task`, or `201` with the result when it was decided at once. `Idempotency-Key` is honoured per caller. |
| `GET /access/v1/access-requests/<id>` | the task. `Retry-After` while it is `pending`; once `approved`, `result` with `mode: "reevaluate"` and the `approval` |
| `POST` or `DELETE /access/v1/access-requests/<id>/cancel` | cancels a pending task; `409` once it has finished |

A task is `pending`, then exactly one of `approved`, `denied`, `expired` or
`cancelled` (`failed` is defined and not used). Only the caller that
submitted a task can read or cancel it; to anybody else it is `unknown_task`.
Every refusal is `application/problem+json` with the profile's type, such as
`urn:openid:authzen:access-request:error:invalid_denial_binding`. A
submission must come from the caller the denial was answered to, about the
same tuple, while that caller is still scoped to the application.

`requested_access.requested_until` can shorten an approval. Bulk submissions
(`items`) are refused.

### Who approves, and where

The people the advice names are the request's approvers. **Whether a person
may decide a request is asked of the access-control policy**: resource
`authzen-access-request`, action `approve-access-request`. The built-in
document permits:

* a person the advice named, or
* a person holding `ADMIN_WRITE` acting through the management API (the
  console),

and refuses either of them when one of their names (username, DN, mail,
`urn:uuid:` subject) is the request's subject or the PEP that asked. These
are template parameters (`permitAccessRequestApproval`,
`permitAdministratorApproval`, `forbidSelfApproval`); a separation-of-duties
rule of your own is a further Deny rule over the same facts. An approval
needs a Permit: with `xacml.enforceAccess` off nobody can approve.

Approvers decide in the user portal, under **Access requests**
(`/portal/access-requests`), and administrators also on the console's AuthZEN
tab. Approvers are mailed through the mail channel when a request arrives.

### Re-evaluating with an approval

The PEP sends the approval back unchanged as `context.approval`:

```json
{
  "subject": { "type": "user", "id": "alice" },
  "action": { "name": "read" },
  "resource": { "type": "document", "id": "q4-plan" },
  "context": { "approval": { "id": "apr_…", "approved_until": "2026-10-30T10:00:00Z" } }
}
```

The service looks the `id` up. It is used only when it names an approved,
unrevoked approval within its `approved_until`, presented by the same caller,
for the same application and the same subject, resource, action and bound
context members. Then, and only then, the request carries the trusted facts
`urn:sts:xacml:authzen:approval-id`, `:approved-until` and `:approver`. The
other members of `context.approval` are never believed. Your policy reads the
facts, as `approvedRead` does here:

```
attribute approval { category = environmentCat
    id = "urn:sts:xacml:authzen:approval-id" type = string }
rule approvedRead {
    permit
    target clause act == "read"
    condition integerGreaterThan(stringBagSize(approval), 0)
}
```

A re-evaluation that presented an approval says what to do next:

| `reason` | `next_action` | When |
|---|---|---|
| (a permit) | — | `context.approval` carries the id and `approved_until` |
| `approval_unverifiable` | `none` | unknown id, or another caller |
| `approval_expired` | `request` | revoked or past `approved_until` |
| `out_of_scope` | `request` | another tuple or application |
| `policy_denied` | `none` | verified, and the policy denied anyway |

`request` comes with a fresh `context.access_request`.

### Emergency access

Where the advice allows it, a submission with `requested_access.emergency:
true` and a `context.business_justification` is approved at once (`201`),
for at most `authzen.accessRequestEmergencyS`, and every approver is mailed a
security notice to review it. Without the advice's permission, or without a
justification, it is refused.

### Callbacks

A submission may carry `callback` (`endpoint`, `state`, `events`). The
endpoint must be one of the URLs an administrator registered for the
caller: `appAuthzenCallbackUri` on an application, `stsAuthzenCallbackUri` on
a person's or service account's entry (set on the AuthZEN tab, or with
`set-callbacks`). When the task finishes with a requested event the service
POSTs `{ "state", "task" }` to it, with `Authorization: Bearer <JWT>` signed
by the realm (verify it with the realm's JWKS). The notification has no
`result`: fetch the task before enforcing. It goes out under the outbound
policy (https verified, no redirect, internal addresses refused in product
mode). A failed delivery is recorded and not retried.

## The console and the management API

**Protocols → XACML → AuthZEN** (`/admin/xacml`, the AuthZEN tab) shows whether
the API answers in the realm, how callers authenticate, the AuthZEN settings,
the attribute catalogue, and the members of the `AUTHZEN_PEPS` group with
their application scope and registered callback URLs, and the realm's
access requests. From there an administrator adds, replaces or removes a
catalogue row, sets a caller's scope or callback URLs, and approves, denies,
revokes or cancels an access request.

The same operations are on the management API:

| Operation | What it does |
|---|---|
| `GET /admin-api/xacml/authzen` | the tab, as JSON; `?caller=<name or DN>` looks one caller up |
| `POST /admin-api/xacml/authzen/set-attribute` | add a row, or replace the row for the same `object` and `property` |
| `POST /admin-api/xacml/authzen/remove-attribute` | remove the row for an `object` and `property` |
| `POST /admin-api/xacml/authzen/set-scope` | replace a caller's application scope: `caller` and `applications` |
| `POST /admin-api/xacml/authzen/set-callbacks` | replace a caller's access request callback URLs: `caller` and `callbacks` |
| `POST /admin-api/xacml/authzen/approve-access-request` | approve one: `request` |
| `POST /admin-api/xacml/authzen/deny-access-request` | deny one: `request` |
| `POST /admin-api/xacml/authzen/revoke-access-request` | revoke an approval: `request` |
| `POST /admin-api/xacml/authzen/cancel-access-request` | cancel a pending one: `request` |

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
| `authzen.tokenExchange` | `STS_AUTHZEN_TOKEN_EXCHANGE` | `false` | Decide OAuth token exchanges for another authorization server (see *OAuth token exchange*), and advertise the token issuance capability |
| `authzen.searchEnabled` | `STS_AUTHZEN_SEARCH_ENABLED` | `true` | The three searches answer, and the metadata names them |
| `authzen.searchMaxCandidates` | `STS_AUTHZEN_SEARCH_MAX_CANDIDATES` | `1000` | The most candidates one search decides |
| `authzen.searchPageSize` | `STS_AUTHZEN_SEARCH_PAGE_SIZE` | `50` | Results per page when the request names no `page.limit` |
| `authzen.returnReasons` | `STS_AUTHZEN_RETURN_REASONS` | `false` | Add the XACML decision, the reason and any advice to the response's `context` |
| `authzen.accessRequests` | `STS_AUTHZEN_ACCESS_REQUESTS` | `true` | The Access Request and Approval Profile: requestable denials, the three endpoints and the metadata members |
| `authzen.accessRequestDenialLifetimeS` | `STS_AUTHZEN_ACCESS_REQUEST_DENIAL_LIFETIME_S` | `600` | How long a requestable denial may be submitted |
| `authzen.accessRequestLifetimeS` | `STS_AUTHZEN_ACCESS_REQUEST_LIFETIME_S` | `604800` | How long a request waits for an approver |
| `authzen.accessRequestMaxApprovalS` | `STS_AUTHZEN_ACCESS_REQUEST_MAX_APPROVAL_S` | `86400` | The longest an approval holds |
| `authzen.accessRequestEmergencyS` | `STS_AUTHZEN_ACCESS_REQUEST_EMERGENCY_S` | `3600` | The longest emergency access holds |
| `authzen.accessRequestRetryAfterS` | `STS_AUTHZEN_ACCESS_REQUEST_RETRY_AFTER_S` | `30` | `Retry-After` on a pending task |
| `authzen.accessRequestMaxPending` | `STS_AUTHZEN_ACCESS_REQUEST_MAX_PENDING` | `10000` | Pending requests a realm holds before a submission is refused 503 |
| `roles.authzenPepGroup` | `STS_ROLES_AUTHZEN_PEP_GROUP` | `authzen-peps` | The group whose members hold `AUTHZEN_PEPS` |

## In the running service

* Every evaluation is an `authzen.decision` row in the audit log, with the
  caller, the application, the subject and resource types, the action, the
  request id and the decision. Property values and credentials are not
  recorded.
* `/admin/xacml/monitor` counts AuthZEN decisions on its own row. It counts
  decisions, not enforcements: the PEP enforces the answer in its own process.
* Every access request transition is an `authzen.access-request.*` audit
  row (`submitted`, `approved`, `denied`, `expired`, `cancelled`, `revoked`,
  `approver-refused`, `callback`).
* The scheduler job `authzen.access-requests` expires pending requests and
  removes finished ones a day after they finished (or once their approval
  ran out, if later).
* `/admin/sts-metadata` lists the endpoints.

## What is not built yet

None of these is advertised in the metadata:

* Of the Access Request and Approval Profile: binding a denial by
  `evaluation_id` alone, `approval.state`, machine-readable forms, and the
  BULK, ACTOR and CATALOG companions.
* Of the OAuth token exchange binding: this service's own authorization
  server asking an external AuthZEN PDP (direction B), authorization-detail
  tuples, and the `claims` and `audience` shaping keys.
* The [edge PDP](remote-pep.md#an-authzen-edge-pdp) answers evaluations and
  batches only: no searches, access requests, Obligations Profile, token
  exchange binding or `signed_metadata`.

## Related

* [Authorization overview](authorization.md) — every authorization decision
  this service makes, and where each is documented
* [XACML 3.0 and ALFA](xacml.md) — the engine, the repository and writing a
  policy
* [Remote PEP](remote-pep.md) — the container that pulls the policies and
  decides locally, and answers AuthZEN as an edge PDP
* [Error codes](error-codes.md) — the `STS-AUTHZEN-*` section
