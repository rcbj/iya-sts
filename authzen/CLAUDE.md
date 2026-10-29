# authzen/ — AuthZEN Authorization API 1.0 over the XACML engine

**An adapter, and nothing else** (#563). AuthZEN Authorization API 1.0 (Final,
2026-01-11) lets a Policy Enforcement Point ask a Policy Decision Point one
question per access — subject, action, resource, context in; `decision` out.
This directory reads that question, maps it onto an XACML request through THE
builder (`xacml/xacml_request.js`, rule 3br), decides it with the XACML
surface's own `decide()` against the realm's ROOT policy, and maps the answer
back. **No decision logic lives here**: what is permitted is the policy's, and
policies tell an AuthZEN question apart by the trusted `urn:sts:xacml:protocol
= authzen`.

**IT IS THE OTHER MODEL FROM THE REMOTE PEP, AND IT CHANGES NOTHING THERE.**
`xacml-pep/` PULLS the repository and decides locally (`xacml/CLAUDE.md`,
phase five); an AuthZEN PEP asks per request. So AuthZEN is additive: `GET
/xacml`, `POST /xacml/pdp`, `GET /xacml/policies`, `/xacml/pep/*` and `POST
/xacml/pip` keep their paths, bodies, statuses, authentication, roles,
settings and codes (rcbj on #563, 2026-10-29). The two interfaces share the
engine and the repository and nothing else.

rcbj's design is the comment of 2026-10-29 on #563; the phases are #1160
(this contract), #1161 (single evaluation), #1162 (console and API), #1163
(metadata), #1164 (batch), #1165 (protocol tests). Search, the Obligations
Profile, Access Request and Approval, the token-exchange binding and an
AuthZEN endpoint on the remote PEP container are NOT filed: each is a ticket
of its own when its semantics are settled, and none is advertised until then.

| File | What it is |
|---|---|
| `authzen_catalogue.ts` | The per-realm ATTRIBUTE CATALOGUE's grammar: a row (object, property or dotted path → attribute id, category, datatype, `single` or `bag`), its defaults, its reserved identifiers, and the reading of an entry's rows. **Pure.** |
| `authzen_map.ts` | One access evaluation read against the catalogue and refused where it cannot be represented, the XACML request built, and the decision mapped back fail-closed. **Pure.** |

`tests/authzen_map.js` holds both, in process.

## The mapping, in one table

| AuthZEN | XACML category | Attribute |
|---|---|---|
| `subject.id` | access-subject | `urn:oasis:names:tc:xacml:1.0:subject:subject-id` |
| `subject.type` | access-subject | `urn:sts:xacml:authzen:subject-type` |
| `action.name` | action | `urn:oasis:names:tc:xacml:1.0:action:action-id` |
| `resource.id` | resource | `urn:oasis:names:tc:xacml:1.0:resource:resource-id` |
| `resource.type` | resource | `urn:sts:xacml:authzen:resource-type` |
| `*.properties.*`, `context.*` | the catalogue row's | the catalogue row's, and nothing else |
| `context.application` | — | read by the adapter to choose the caller's application |
| *(trusted)* | environment | `urn:sts:xacml:protocol` = `authzen`, `urn:sts:xacml:realm`, `urn:sts:xacml:authzen:caller`, `urn:sts:xacml:authzen:application`, `urn:sts:xacml:authzen:supplied` |

The two type identifiers and the three trusted AuthZEN facts are in
`VOCABULARY`, and the Rust builder spells them the same
(`tests/xacml_request.js` E2).

## The catalogue lives on the API's own object

**One value of `authzenAttribute` per row, on the realm's `sts-authzen-api`
resource object** (`common/applications.js`). That object IS the API as an
OAuth 2.0 resource (#1139's model), and what properties the API accepts is
part of what the API is — the way GNAP's access-type catalogue is
`oauthAuthorizationDetailsType` on its resource server's object. It buys
per-realm storage, persistence in every mode and the registry's write doors
with no store of its own. **Every write goes through `authzen_catalogue.ts`'s
`parse()`** — `applications.js`'s `authzenAttributeProblem()` requires it
LAZILY at the write, so a reserved row is refused where it is written
(`STS-AUTHZEN-0010`–`0012`), and the request reads rows through the same
function. A value that is somehow not a row (written by hand) is left out of
the reading and named, never thrown: a catalogue is read on every request.

**That lazy require is not owed to the parent project's Kerberos COPY
closure**: `applications.js` is in it, but the require runs only when an
`authzenAttribute` is written, which none of the four Kerberos jobs does
(`kerberos/CLAUDE.md`, #236's precedent).

## The reserved identifiers, and why a row may never name one

**A request-supplied attribute suppresses the PIP.** `xacml_pdp.js` asks the
resolver only when a designator found no value in the request. So a row
mapping a caller's property onto `urn:sts:xacml:role` would let any caller name
the roles of the subject it asks about, and the policy would believe it.
Refused, at the write:

* **all of `urn:sts:xacml:`**, matched as a prefix and case-insensitively —
  `VOCABULARY`, the settings and passkey-policy prefixes, the PIP's directory
  prefix and the trusted AuthZEN facts all live there, and a prefix cannot
  fall behind a list (`0011`);
* **subject-id, resource-id, action-id** and the three current-time
  attributes (`0011`);
* **`context.application`** (`0011`);
* **a bare LDAP-shaped name in any SUBJECT category** (`0012`): the PIP reads
  one off the subject's directory entry (`directoryAttributeFor()`), and for a
  subject the realm resolves the directory is authoritative (decision 5). The
  check is by the row's CATEGORY, not its object, so a context row cannot
  reach the subject category under a bare name either.

**An empty bag does NOT suppress the PIP** — the engine's check is
`values.length === 0` — and the ticket asked for that to be confirmed:
`tests/authzen_map.js` P1 and P2. It is why `supplied` exists: a policy that
must tell "sent empty" from "not sent" reads that bag, never the attribute.

## The value rules (decision 6)

The row's datatype wins; `null` is refused; an array only for a `bag` row; a
nested object only through declared dotted rows; an undeclared property is a
400 in every mode; `supplied` keeps absent and empty apart. `authzen_map.ts`'s
header argues each, and a JSON number is never quietly a string (nor a
boolean a string): the only conversion is a STRING parsed at the row's type
by `xacml_datatypes.js`, which owns every lexical space.

**Unknown members of the request itself are refused too** (`0009`): a member
AuthZEN 1.0 does not define is either a newer version's or a mistake, and
silently dropping either would decide a question the caller did not ask.

## The result (decision 8)

Fail-closed: `true` only on a Permit carrying nothing this PDP cannot
discharge, which is `xacml.ts`'s `enforce()` deny-biased — the console's
what-if and the remote PEP apply the same rule. Deny, NotApplicable and an
Indeterminate over a missing attribute are an ordinary `false`. **An
Indeterminate over a FAULT** (`STS-XACML-0012`, a root policy that will not
load; `STS-XACML-0013`, a processing or syntax error) **is an error, never a
denial**: a PEP told `false` about a broken policy enforces its bias over
somebody else's outage. A Permit with an undischargeable obligation is `false`
until the Obligations Profile is implemented end to end — there is no way yet
to hand one to the PEP and know it was done. `urn:sts:xacml:obligation:log`
is the one discharged.

Reasons and advice go in the response's `context` only when
`authzen.returnReasons` is on (#1161), and never decide anything: section 5.5
keeps `decision` alone as the answer.

## Error codes

`STS-AUTHZEN-*` is its own subsystem (`common/error_codes.js`). 0001–0009 are
the request's shape and values, 0010–0012 the catalogue's writes.
