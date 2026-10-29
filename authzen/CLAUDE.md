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
| `authzen_caller.ts` | Who is asking (the realm's door), whether they may (AUTHZEN_PEPS on resource `authzen-api`), and about which application. |
| `authzen.ts` | The routes, registered at 23c-ii (`common/protocol_stack.ts`): `POST /access/v1/evaluation`, `POST /access/v1/evaluations`, and the metadata. Thin, as `xacml/xacml.ts` is. |
| `authzen_admin.ts` | What the AuthZEN tab of `/admin/xacml` shows and does: `view()` and `act()` (`set-attribute`, `remove-attribute`, `set-scope`), shared by the console and `mgmt-api/authzen_api.ts`'s `/admin-api/xacml/authzen` operations (rule 7). A library, built by the root beside the other API modules. |

`tests/authzen_map.js` holds the two pure modules in process;
`tests/authzen_evaluation.js` drives the route over real handshakes in a child
process, in a throwaway realm whose root policy it wrote;
`tests/authzen_admin.js` holds the tab's view and acts.
`tests/protocol/sts_authzen.js` (`local: true`, #1165) asks a running service
the same questions over HTTP in a throwaway realm, and carries the **AuthZEN
interop "Todo" scenario** — its five people, five actions and owner rule
written in ALFA as the realm's root policy — through mutual TLS, the default
door. The bearer door is held in process only: issuing a client a delegated
permission grant and a token over the network is a second stack's worth of
setup for checks the report API's jobs already drive.

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

## Who is asking (#1161)

**Three doors, chosen per realm by `authzen.callerAuthentication`, mutual TLS
by default** (rcbj, 2026-10-29: "for remote PDPs, use Mutual Auth TLS by
default"). The design comment on #563 asked for mutual TLS AND a token;
`mtls+bearer` is that, and it binds the two — the token must carry the
presented certificate's RFC 8705 `x5t#S256` — so they name one party rather
than two that would each need a role. `bearer` alone is for a PEP that cannot
present a certificate. Every door is checked in every mode: AuthZEN section
11.2 leaves the PEP's authentication to the deployment, and a decision
endpoint anybody can drive is an oracle that maps the policy.

* **The certificate is read by `xacml/xacml.ts`'s `callerIdentity()`** —
  public for this since #563 — so one certificate names one entry on every
  surface (the four links' first two, `xacml/CLAUDE.md`).
* **The token is read as `report/report_api.ts` reads its own**, less the
  person: a token whose `sub` is not its client (`client_id`, or
  `urn:sts:client:<id>` in RFC 9700 mode) is refused 403 — a person is not an
  enforcement point.
* **A 401 carries `WWW-Authenticate: Bearer realm="<issuer>"`** wherever a
  token is a door (section 11.3's SHOULD). On the certificate door alone there
  is no HTTP scheme to name, so there is none.

**AUTHZEN_PEPS, NOT XACML_USER OR REMOTE_PEPS** (decision 2), through
`roles.authzenPepGroup` (default `authzen-peps`, seeded empty in every
realm), decided by the access-control policy on resource `authzen-api` with
the role in `requiredRoles` — so `/admin/xacml/decide` reproduces it. An
APPLICATION caller's groups are the ones whose `member` names its entry's
DN; `roles.rolesOf()` resolves groups only for a person by itself, so
`authzen_caller.ts` passes them in.

**The application scope** (decision 1): the realm is the tenant; within it,
`stsAuthzenApplication` on a person's or service account's entry,
`appAuthzenApplication` (plus its own identifiers) on an application's.
Administrator-set: `sts*` is refused by every self-service and provisioning
door, and the attribute is not in the portal's list. `context.application`
must be in the set (403 `0025`), none named and one in the set picks it,
none in the set is `0026`, several and none named `0027`. **`ou=peps` is not
consulted**: registration is not a permission.

## The metadata (#1163)

**Section 9.2 INSERTS the well-known segment**, RFC 8414's shape: a realm's
PDP identifier is `https://host/realm/<id>`, so its document is
`/.well-known/authzen-configuration/realm/<id>`, arriving at the host root
with the realm after it. `authzen.ts` reads that path the way `oauth2.ts`'s
`issuerPathTarget()` reads an issuer's — `realm/<id>` of a realm that exists,
asked from the default realm — and answers inside that realm; anything else
is Express's 404 (`0035`). The appended form (`/realm/<id>/.well-known/…`)
reaches the bare route already in its realm and answers the same document.

**`policy_decision_point` is `baseUrlOf(req, 'authzen')`**, the base the API
is advertised under (#472), so it matches the URL a PEP built — section
9.2.3 has the PEP refuse a document whose identifier does not. **It names
only what answers**: the single endpoint, and the batch one while it is on;
no search endpoint and no `capabilities` until one is implemented end to
end, and no `signed_metadata` (a follow-up may sign it with the realm's key).
While the API is off the document answers 501 rather than advertising an
endpoint that does not.

## The batch (#1164)

`POST /access/v1/evaluations` is the single evaluation run per item, through
the same `evaluateOne()` — the same caller, admitted ONCE for the batch, the
same audit row and monitor count per item — with section 7's additions:

* **Defaults, overridden per item WHOLE**, member by member (`subject`,
  `action`, `resource`, `context`): an item naming `resource` replaces the
  top-level resource rather than merging into it, which is section 7.1.1's
  reading and the only one in which an item says exactly what it is about.
* **No items is one evaluation, answered in the single shape**, section 7.1's
  "backwards-compatible".
* **Bounds before anything is decided**: the body against
  `authzen.maxBodyBytes`, then the count against `authzen.maxEvaluations`,
  each refusing the whole batch 400 (`0037`, `0038`). Every item is a full
  decision on this service's thread.
* **An item's failure is its own**: `decision: false` with `context.error
  { status, message }` (section 7.2's example; the shape this API's top-level
  errors take too), and never hidden by the batch's 200. For
  `deny_on_first_deny` an error counts as a deny.
* **The batch id** is `X-Request-ID` or one made here, and each item's audit
  row carries it with the item's position (`<id>#<n>`), decision 9.
* `authzen.batchEnabled` off answers 501 (`0039`) and takes the endpoint out
  of the metadata; the single endpoint is unaffected.

## The console and the API (#1162)

**One tab, AuthZEN, on `/admin/xacml`**, after the XACML tabs it is decided
by — the sibling structure: its settings block (the `AuthZEN` group, homed on
`/admin/xacml` and drawn on this tab alone; the Settings tab now asks
`configSettingsJson()` for `XACML` only), the catalogue with its add form and
a Remove per row, and the members of `roles.authzenPepGroup` with their
scopes and the form that sets one. Its forms post to
`/admin/xacml#xacml-tab-authzen`, which `/admin-api/xacml/authzen/:action`
mirrors, and the settings block's to the configuration resource, whose
mirrors name the tab too.

* **`set-attribute` replaces the row for the same object and property** rather
  than adding a second: the registry stores values, and two rows for one
  property is what `rowsOf()` reads as a problem. It goes through
  `applications.updateApplication()`, so the reserved-identifier refusal is
  the write door's and cannot be skipped here.
* **`set-scope` replaces the scope whole.** A person's is written through
  the slot `ldap/ldap_server.js` fills (`setDirectory()`: `locate`,
  `members`, `write`, validated whole) — `ldap/person_editor.ts`'s
  arrangement, because nothing else writes an `sts*` attribute of a person,
  and that is the point: the scope is an administrator's. An application's
  goes through the registry.
* **The tab lists the GROUP, not every holder of a scope.** Listing holders
  would be a new `eachHolderOfAny()` name, which is a new index expression
  and a schema version (`persistence/directory_queries.js`); the group is
  who may ask, and `?caller=` looks anybody else up.

## What is decided, and what is recorded

* **The realm's ROOT policy** (decision 7), through the XACML surface's own
  `decide()`; `protocol = authzen` tells the question apart. `decide()`
  gained an optional `{ resolve: false }` for this: a subject whose type is
  not in `authzen.resolveSubjectTypes` is decided with NO PIP, so an id that
  happens to match a person's name is not that person.
* **One audit row per evaluation** (`authzen.decision`): the caller, the
  application, the two types, the action, the request id, the decision, and
  the obligation that made a Permit false (`0029`) or the fault (`0028`).
  Never a property value, an id the caller sent, or a credential (decision 9).
* **`/admin/xacml/monitor`'s `authzen` row** counts decisions and leaves the
  enforcement cells empty, the PDP endpoint's reason.
* **`sts-authzen-api` is the API** (#1139's model): its `oauthAudience` is the
  realm's `/access/v1`, it defines `authzen:evaluate`
  (`urn:sts:authzen-api:`), and deleting it turns the API off (`0014`) and
  every token for it (`common/registered_targets.ts`).

## Error codes

`STS-AUTHZEN-*` is its own subsystem (`common/error_codes.js`). 0001–0009 are
the request's shape and values, 0010–0012 the catalogue's writes, 0013–0014
the API being off, 0015–0023 the caller's authentication, 0024–0027 its
admission and scope, 0028–0029 the result, 0030–0034 the tab's acts, 0035
the metadata path, 0036–0039 the batch.
