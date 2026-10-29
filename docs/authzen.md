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

## Related

* [XACML 3.0 and ALFA](xacml.md) — the engine, the repository and writing a
  policy
* [Remote PEP](remote-pep.md) — the container that pulls the policies and
  decides locally
* [Error codes](error-codes.md) — the `STS-AUTHZEN-*` section
