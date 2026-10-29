---
title: AuthZEN
---

# AuthZEN Authorization API 1.0

This service answers [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
access evaluations. A Policy Enforcement Point (PEP) sends one question — a
subject, an action, a resource and a context — and gets back `decision: true`
or `false`. The answer comes from the same XACML 3.0 engine and the same
policy repository as everything on the [XACML](xacml.md) page: an AuthZEN
request is turned into an XACML request, decided against the realm's root
policy, and turned back.

AuthZEN is an addition. The XACML endpoints (`/xacml`, `/xacml/pdp`,
`/xacml/policies`, `/xacml/pep/*`, `/xacml/pip`) and the
[remote PEP](remote-pep.md) container are unchanged.

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

### Subjects that are directory people

For a `subject.type` listed in `authzen.resolveSubjectTypes` (default `user`),
`subject.id` names a person in the realm's directory. The policy then reads
that person's roles and directory attributes through the Policy Information
Point, and the caller cannot supply them. For any other type the directory is
not consulted.

## How a request becomes an XACML request

| AuthZEN member | XACML category | XACML attribute |
|---|---|---|
| `subject.id` | access-subject | `urn:oasis:names:tc:xacml:1.0:subject:subject-id` |
| `subject.type` | access-subject | `urn:sts:xacml:authzen:subject-type` |
| `action.name` | action | `urn:oasis:names:tc:xacml:1.0:action:action-id` |
| `resource.id` | resource | `urn:oasis:names:tc:xacml:1.0:resource:resource-id` |
| `resource.type` | resource | `urn:sts:xacml:authzen:resource-type` |
| `subject.properties.*`, `action.properties.*`, `resource.properties.*`, `context.*` | the catalogue row's | the catalogue row's |
| `context.application` | — | chooses the caller's application (see below) |

This service adds these facts to every AuthZEN request. They come from the
caller's authentication, never from the request body:

| Attribute (environment category) | Value |
|---|---|
| `urn:sts:xacml:protocol` | `authzen`, so a policy can tell an AuthZEN question apart |
| `urn:sts:xacml:realm` | the trust realm |
| `urn:sts:xacml:authzen:caller` | the authenticated PEP |
| `urn:sts:xacml:authzen:application` | the application the question is scoped to |
| `urn:sts:xacml:authzen:supplied` | every member the caller sent, by path, such as `subject.properties.department` or `context.source_ip` |

### The attribute catalogue

A property reaches the policy only if the realm's **attribute catalogue**
declares it. Each row names:

| Member | Meaning | Default |
|---|---|---|
| `object` | `subject`, `resource`, `action` or `context` | required |
| `property` | the member's name, or a dotted path into a nested object (`owner.country`) | required |
| `attributeId` | the XACML attribute it is sent as | required |
| `category` | `access-subject`, `resource`, `action`, `environment` (or another XACML category, or its URI) | the object's own |
| `dataType` | `string`, `boolean`, `integer`, `double`, `date`, `dateTime`, `time`, `anyURI`, `dayTimeDuration`, `yearMonthDuration`, `hexBinary`, `base64Binary`, `rfc822Name`, `x500Name`, `dnsName`, `ipAddress`, or the type's URI | `string` |
| `multiplicity` | `single` (one value) or `bag` (a JSON array) | `single` |
| `description` | free text for administrators | — |

Each row is one value of `authzenAttribute` on the realm's `sts-authzen-api`
application, for example:

```json
{"object":"resource","property":"classification","attributeId":"urn:example:classification"}
```

A row is refused when it would map onto an identifier this service fills in
itself, because a value the caller sends hides the one this service would have
looked up:

* anything in `urn:sts:xacml:` — roles, the realm, the protocol, the caller,
  the application, and every other fact this service supplies;
* `subject-id`, `resource-id`, `action-id`, and the current date and time;
* `context.application`;
* in a subject category, a bare directory attribute name such as
  `employeeType`. Use an identifier of your own, such as
  `urn:example:department`.

### Value rules

| Sent | Result |
|---|---|
| a property no catalogue row declares | 400, in every mode |
| `null` | 400; leave the member out, or send a value |
| a string | parsed at the row's datatype; 400 if it does not parse |
| a number | accepted by an `integer` row (whole numbers only) or a `double` row |
| `true` / `false` | accepted by a `boolean` row |
| an array | accepted by a `bag` row only; each element follows the rules above |
| an object | accepted only through rows for its members (`owner.country`) |
| `""` or `[]` | sent as an empty value or an empty bag, and listed in `urn:sts:xacml:authzen:supplied` |

A member that AuthZEN 1.0 does not define, at the top level or inside
`subject`, `action` or `resource`, is also refused with 400.

## How a decision comes back

| XACML result | `decision` |
|---|---|
| Permit | `true` |
| Permit with an obligation this service cannot carry out | `false` |
| Deny | `false` |
| NotApplicable | `false` |
| Indeterminate because an attribute was missing | `false` |
| Indeterminate because of a fault (a root policy that will not load, a processing error) | an error, never `false` |

`urn:sts:xacml:obligation:log` is the one obligation this service carries out;
it is recorded in the audit log.

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

## Related

* [XACML 3.0 and ALFA](xacml.md) — the engine, the repository and writing a
  policy
* [Remote PEP](remote-pep.md) — the container that pulls the policies and
  decides locally
* [Error codes](error-codes.md) — the `STS-AUTHZEN-*` section
