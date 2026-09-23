# xacml/ — the XACML 3.0 engine

**All five phases are here: the ENGINE, the STORE, the PIP, a service surface,
the PAP, ALFA and the REMOTE PEP.** `common/protocol_stack.ts` requires
`xacml.ts` at 23c, eight routes answer under `/xacml` (see *The surface*), five
configuration pages under `/admin/xacml` and a sixth, `/admin/xacml/monitor`,
filed under Monitoring, seventeen operations under `/admin-api/xacml`,
policies live in `ou=policies`
in the embedded directory and registered remote enforcement points in
`ou=peps`.

**THE ONLY FAMILY HERE THAT ANSWERS A QUESTION ABOUT SOMEBODY ELSE'S
BOUNDARY** — every other protocol authenticates or provisions somebody, and this
one is handed a subject authenticated elsewhere and asked whether they may.

**The remote PEP is a SECOND CONTAINER and it is not in this directory** — it
is `xacml-pep/`, which has a `CLAUDE.md` of its own and is the only directory
in this repository that is not part of the mock. What is here is the PDP's side
of it: the register, the three endpoints under `/xacml/pep`, the console page
and the nudge.

## What is here

| File | What it is |
|---|---|
| `xacml_model.js` | The vocabulary: the identifiers the specification fixes, the shape of a policy tree, and the seven decision values. **No I/O.** |
| `xacml_datatypes.js` | The seventeen datatypes — parse, write, equality, ordering. The table every function is generated over. **No I/O.** |
| `xacml_functions.js` | The standard function library: 275 identifiers, about thirty implementations. **No I/O.** |
| `xacml_validate.js` | Static type checking. What a policy is REFUSED for at load, before any request. **No I/O.** |
| `xacml_xml.js` | XACML 3.0 core XML → the model, and a response back. The first of three readers. |
| `xacml_pdp.js` | Evaluation: targets, rules, conditions, the twelve combining algorithms, obligations. **No I/O.** |
| `xacml_json.js` | The JSON Profile 1.1 request and response — what anybody actually sends. The second reader. **No I/O.** |
| `xacml_store.ts` | The repository. Owns the policy schema; `ou=policies` IS the store. |
| `xacml_pip.ts` | Attribute resolution off the subject's own directory entry. |
| `xacml.ts` | The protocol routes: the four under `/xacml` proper, the three under `/xacml/pep` and `POST /xacml/pip`, plus the embedded PEP. |
| `xacml_templates.ts` | Five starting points: RBAC, ABAC, this service's own two, and **`blank`** — an empty Policy or PolicySet, which is the only way to create a PolicySet from the console without ALFA. **Adding one is a row in `TEMPLATES` and nothing else.** No DOM. |
| `xacml_editor.ts` | The editor's GRAMMAR: what may be added where, and how one edit is applied. **No DOM** — which is what lets the menus be asserted in node. |
| `xacml_alfa.ts` | ALFA read and written — the third rendering, and the one people want to look at. **No DOM.** |
| `xacml_pep_registry.ts` | The register of REMOTE enforcement points. `ou=peps` IS the store, and the sync token is computed here. |
| `xacml_pep_http.ts` | **The THIRD outbound request in this repository** — the nudge. Argued rather than cited. |
| `xacml_pep_tls.ts` | **A remote PEP's HTTPS listener certificate (2026-09-13).** Issues a REGISTERED PEP a `serverAuth` key pair from its realm's `pep-tls` Issuing CA through `common/pki.js`, naming the PEP and its notify host, and hands the private key back once. A LIBRARY — `xacml_admin.ts` draws the control and answers the action. See *The remote PEP's HTTPS listener* below. |
| `xacml_admin.ts` | The five `/admin/xacml` console pages and their actions, and `/admin/xacml/monitor`'s body. |
| `xacml_monitor.ts` | The decision and enforcement counters behind `/admin/xacml/monitor`. A LEAF. See *`/admin/xacml/monitor`* below. |
| `xacml_access_pep.ts`, `xacml_role_pep.ts` | The two embedded PEPs that decide THIS service's own access and issuance. See *AND SINCE 2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE* below. |
| `conformance/` | The vendored OASIS suite. `PROVENANCE.md` is the argument, `MANIFEST.js` the drift check. **Not edited here, ever.** |

Five tests, all in-process, no port, no container:
`tests/xacml_conformance.js` (the engine, against 455 cases somebody else
wrote), `tests/xacml_service.js` (the store, the PIP, the JSON Profile and the
PEP), `tests/xacml_pap.js` (the templates, the editor grammar and the XML
writer), `tests/xacml_alfa.js` (ALFA, both directions) and — since phase five —
`tests/xacml_pep.js`, which is the odd one out: it spawns a CHILD PROCESS in
`xacml-pep/` and asks the container questions this process cannot answer about
itself. Three more have joined them since, each argued in its own header:
`tests/xacml_service_own.js` (the two built-in policies, below),
`tests/xacml_monitor.js` (the monitor's counters) and
`tests/xacml_pep_realms.js` (a remote PEP registered in another realm).

**AND THREE OVER HTTP, WHICH IS WHAT THOSE FIVE COULD NEVER
COVER.** Between them the five hold the ENGINE to 455 cases, the store, the PIP,
the JSON Profile, the editor's grammar and the container's shim — and they make
NOT ONE HTTP REQUEST, so until these existed every route in `xacml.ts` and
every form on the five console pages was uncovered. Since 2026-09-05,
`tests/vendored/`
`sts_xacml_endpoints.js` drives the seven `/xacml` endpoints and
`sts_xacml_editor.js` drives `/admin/xacml/editor` in a real browser; **since
2026-09-06 `sts_xacml_remote_pep.js` DRIVES THE `xacml-pep/` IMAGE AS A SECOND
CONTAINER ON THIS SERVICE'S OWN DOCKER NETWORK — in both launchers' stacks** and asserts that a policy
deployed through `/admin-api/xacml` changes what that container allows — the
seam neither `tests/xacml_pep.js` (which loads the container's modules and makes
no request) nor `sts_xacml_endpoints.js` (where the TEST impersonates a PEP and
nothing evaluates what it pulled) can reach, and the only thing anywhere that
loads `xacml-pep/sync.js`. **It is also the only test of the NUDGE against a
listener that answers**: `xacml_pep_http.ts` is this family's outbound half and
until that file existed nothing had ever delivered one. All three are
this repository's own (`local: true`), and they live there rather than in the
parent project's suite for one reason worth stating here, because it is a fact
about THIS family: **a PDP with an empty repository answers NotApplicable to
everything**, so there is no question worth asking `/xacml/pdp` until a policy
exists, and over HTTP the only way to put one there is `/admin-api/xacml`. Every
assertion in either file therefore spans an authoring door and a deciding door.

All three work in a THROWAWAY TRUST REALM, which is not tidiness: `ou=policies` is
per realm and a new realm's is EMPTY — the seeded policy is written once, in the
default realm, at require time — so a realm gives them a repository whose whole
contents they wrote, makes every count exact rather than "at least", makes the
no-root state reachable at all, and keeps `xacml.enabled`, `xacml.remotePeps`,
`xacml.pepBias` and `xacml.pepRequireCertificate` off the process while they are
turned off and on. **The remote-PEP job needs it for two reasons of its own**:
it disables every policy in the repository to reach the state where a PEP holds
nothing, and doing that anywhere but a realm of its own would stop every other
job in the run being decided about — and it then turns `xacml.remotePeps` OFF
in that realm while its container is still running (it REMOVED the realm until
2026-09-06, when the suite stopped removing realms), which is how it makes a
PDP outage without stopping the service the rest of the suite is using. **The
editor job needs the realm most**: the draft IS the stored policy, so a job
editing in the default realm would be rewriting the seeded one, live, while
every other job in the run decided against it.

`sts_xacml_editor.js` found the thirteenth defect on its first run and it is
listed below with the twelve.

## Where this family sits in the require order (23c)

**After `admin-ui/admin`**, whose `setXacmlPages()` and `setRolePreviewer()`
slots `xacml_admin.ts` and `xacml_role_pep.ts` fill and whose page shell,
settings block and action responder it requires — so a require the other way
would close a cycle, and one from `mgmt-api/admin_api.ts` would have moved
every `/xacml` route and all six `/admin/xacml*` pages ahead of the management
API's own (since #50's R1 the routes are placed only by
`common/protocol_stack.ts`'s `register()` calls, but that require would still
arm the issuance gate and fill the console's slots at 19 rather than 23c). It
requires `xacml_admin.ts` ITSELF rather than `common/protocol_stack.ts` doing
it, so this family has ONE require in the require order — and two `register()`
calls, `xacml_admin` then `xacml`, because requiring `xacml.ts` used to
register `xacml_admin.ts`'s pages first; that module requires this one back
LAZILY, inside the one function that needs it.

**And after `ldap/ldap_server` (21) in effect** — not as an ordering
constraint, since both registers take their directory across a slot that module
fills, but because a process that loaded this one and not that has an empty
repository and answers NotApplicable to everything. Since 2026-09-05 it also
requires `oauth-oidc/mtls` for the remote PEP's client certificate, which is a
LIBRARY (rule 3) and registers nothing, so it cannot move a route or join a
cycle.

**AND IT REQUIRES `xacml_role_pep.ts`, WHICH IS WHAT ARMS EVERY ISSUANCE SITE IN
THE SERVICE**: that module fills `common/issuance_gate.js`'s decider at require
time, so from this line onward every `gate.check()` call reaches the engine
and before it — in `npm test`, in the parent project's in-process Kerberos
jobs, in the remote PEP container — they answer "allowed". See *AND SINCE
2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE* below.

## The three `/xacml/pep` endpoints are GATED, and the chain has four links

**SINCE 2026-09-06 A REMOTE PEP IS AN IDENTITY RATHER THAN A CONNECTION.** It
was `xacml.pepRequireCertificate` and nothing else: any certificate at all —
self-signed, minted a second ago, naming anything — registered, pulled the
repository and reported counters. That was right while a PEP was a
demonstration and stopped being right when the repository it pulls became the
one this service enforces its own access with.

Four links, and each is checked by the module that owns it:

| # | The question | Answered by |
|---|---|---|
| 1 | Did the certificate build a path to an anchor in this service's truststore? | `oauth-oidc/mtls.js`'s `peerVerified()`, over `POST /tls/trust` — and the MAIN listener joined that truststore the same day, which is what made the question answerable at all |
| 2 | Which directory entry is that? | `xacml_pep_registry.ts`'s `certificateIdentity()`, across the slot `ldap_server.js` fills — the same lookup `GET /tls/sign-in` gets (it was a certificate arriving on 8443 or 9443 until both listeners were deleted on 2026-09-16), so one certificate is one person however it turns up |
| 3 | What roles does that entry hold? | `common/roles.js`, with the groups LEFT UNRESOLVED so it reads them from the directory. `REMOTE_PEPS` was the first built-in role held through a GROUP rather than computed from what the party is; `XACML_USER` is the second, and the two are deliberately separate |
| 4 | Does the policy allow it? | `common/access_gate.ts` → `xacml_access_pep.ts`, on resource `xacml-pep-api` or `xacml-api` — the same embedded PEP and the same `access-control` document that decide the console and the management API |

**THE CERTIFICATE SAYS WHO AND THE GROUP SAYS WHETHER**, and keeping them apart
is the whole design. A certificate this service verified, naming
`cn=rogue-pep,ou=users,…`, holding `EVERYBODY, ALL_AUTHENTICATED_USERS` and not
`REMOTE_PEPS`, is refused — and the refusal says the certificate was fine,
because somebody debugging it otherwise regenerates a certificate that was
never wrong. `tests/vendored/sts_xacml_endpoints.js` drives exactly that case.

**IT IS A POLICY DECISION AND NOT A HARD-CODED ROLE TEST.** The requirement
travels in the REQUEST — `xacml-pep-api` was the first resource that is
restricted by DEFAULT rather than narrowed by an operator and `xacml-api` is
the second, which
`xacml_access_pep.ts` argues where it reads it — so an operator who edits the
access-control document, or points `roles.remotePepGroup` at a group of their
own, changes this answer with everything else. `xacml.enforceAccess` turns the
layer off and the old `xacml.pepRequireCertificate` refusal is what answers
underneath.

### This service's own policies are never pushed

`GET /xacml/pep/policies` withholds the documents named by `xacml.accessPolicy`
and `xacml.issuancePolicy`, and names them in a `withheld` field rather than
dropping them silently.

**THE REASON IS NOT SECRECY, IT IS THAT THEY WOULD BREAK THE PEP THAT PULLED
THEM.** Those two decide THIS service's questions against attributes only this
process can supply — a required role off an application entry, a resource owner
off a portal session. Evaluated in a remote PEP against its own requests they
answer NotApplicable to everything, and a deny-biased PEP turns NotApplicable
into a refusal: shipping them would silently make every remote decision a Deny,
which is the exact shape of the defect `xacml-pep/CLAUDE.md` records having cost
a run already. They stay readable at `GET /xacml/policies`, where a PERSON reads
the repository.

Filtered BY NAME and not by a flag on the entry, because those two names are
settings: an operator who points `xacml.accessPolicy` at a document of their own
has made THAT one internal, and a stored flag would still be on the old one.

## ALFA

The third rendering of the model, and the one worth reading — forty lines of
XML are eight of ALFA:

```
policy staffAccess {
    apply denyUnlessPermit
    rule allowStaff {
        permit
        target clause employeeType == "staff" and actionId == "GET"
    }
}
```

**It is an OASIS Committee Specification Draft, not a ratified standard.** No
conformance suite, no schema, no second implementation to disagree with — a
completely different footing from the engine. So the contract stated and
asserted is the one that can actually be kept:

> **Anything the emitter writes, the parser reads, and the policy decides
> identically either way.**

`tests/xacml_alfa.js` checks all three halves of that over every policy the
templates build and the seeded one — stable bytes, still type-checks, **and
the same decisions on seven probes**. The third is the one a round-trip test
usually omits, and the only one that would catch a swapped comparison: `age >
18` becoming `18 > age` round-trips perfectly and decides the opposite. That is
what `mirrorOperator()` is for.

**ALFA is a VIEW, never a second stored copy.** An imported policy is parsed,
converted and stored as XACML XML; the editor renders the ALFA back from the
model. A stored ALFA text beside a stored XML one would be two documents that
could disagree.

Three places the dialect is explicit where ALFA is vague, all argued in the
file's header: **typed literals** (`date("2026-01-01")`, because ALFA has
native syntax for four datatypes and nothing agreed for the other thirteen),
**the three target levels** mapping onto `clause` / `or` / `and`, and
**attributes declared before use** — which is ALFA's own rule and the most
useful refusal in the parser, because a typo in an attribute name is otherwise
a policy that quietly matches nothing and looks exactly like one that is
working and denying you.

## The console

```
/admin/xacml            settings, and what the PDP decides with
/admin/xacml/policies   the repository; enable, disable, root, delete,
                        import ALFA, create from a template — and this is the
                        ONLY page that creates a policy: the editor edits one
                        that exists, and says so on itself
/admin/xacml/editor     the guided editor
/admin/xacml/peps       the REMOTE enforcement points, and whether they are
                        deciding with the same policy this service holds
/admin/xacml/decide     ask the PDP and see what the PEP would do
```

**The editor has no JavaScript, and that is argued rather than assumed.** This
console is `script-src 'none'` and `admin-ui/CLAUDE.md` refuses a script nine
times over under a rule that the argument must be *made* each time — the test
being whether the page CANNOT work without one. An editor can. So every
"pick the next valid element" dropdown is a `<select>` whose options were
computed on the server by `xacml_editor.ts`, and choosing one is a form POST.

**Every page of this console but one is `script-src 'none'`** (the exception is
`/admin/api-explorer`, which arrived on 2026-09-09 and argues itself); the
editor's version of the claim is unaffected, because that page genuinely has no
script.

*What it costs*: a round trip per element — a five-rule policy built by hand is
perhaps forty POSTs. The page says so; the templates are the answer.

**THE EDITOR CREATES NOTHING, AND SINCE 2026-09-06 IT SAYS SO ON BOTH OF ITS
BRANCHES.** Every control on that page posts a policy NAME and a PATH into a
stored document, so there is nowhere for a policy that has not been written yet
to live and there is no New button. That was defensible and it was invisible: a
reader who opened the editor to write a policy found a chooser of other
people's policies and no door. There are now two notes rather than one, because
the two readers are different people — the empty-repository branch is somebody
with nothing at all, and the note beside the chooser is somebody who has a
policy open and is looking for the button that makes another. Both send them to
`/admin/xacml/policies` and both name the three doors there.

**The third door is the `blank` template**, added the same day and the reason
the second note could be written at all: before it, "create a policy and come
back" meant starting from somebody else's RBAC document or learning ALFA first.
It builds an empty `Policy` or an empty `PolicySet` — no rules, no children, no
Target — and **an empty deny-unless-permit document DENIES**, which the page
says on the template, on the created policy's own description and in the
editor's note, because the one thing that must not happen is somebody making a
blank policy the root and reading its silence as inert. That is the same choice
`xacml_editor.ts` makes for a child policy added in the editor, and it is the
direction a half-built policy should fail in.

*What it buys*: the menu is computed by the same process that will validate the
policy, against the real function library, so **the editor cannot offer
something the validator will then refuse**. A browser-side editor would have
needed a second copy of the grammar shipped to the page, and a second copy of a
grammar is what this whole directory is arranged to avoid.

**The editor holds no session state.** The draft IS the stored policy: every
edit loads the document, applies one change, serializes and writes back. There
is nothing to lose when a browser closes and no second copy that could disagree
with the stored one. The cost is that editing is LIVE, so the page says so and
puts the disable control one click away.

## What the editor can build, and the three things it cannot

**Since 2026-09-05 the guided editor reaches the whole of the XACML 3.0 policy
syntax this engine models.** Before that it built a `Policy` — rules, targets,
matches, conditions, obligations, advice — and nothing else, while
`xacml_xml.js` read and wrote considerably more. That gap was not a missing
feature so much as **four defects, because the editor SERIALIZES THE WHOLE
DOCUMENT ON EVERY EDIT**: a part of the syntax the reader skipped was not
merely unread, it was deleted by the next rename.

| Was | Is |
|---|---|
| A `PolicySet` drew as a policy with no rules, offered `add-rule`, accepted it, said "Rule added." and wrote a document without it — the writer serializes `children` and never looks at `rules` | `policySet` is a kind of its own with its own menu: an inline `Policy`, a nested set, a `PolicyIdReference` or a `PolicySetIdReference`, and the POLICY-combining algorithm list, which is a different set of URIs from the rule-combining one it is almost spelt the same as |
| `set-expression-variable` was in the menu and there was no way to DEFINE a variable, so choosing it built `$v1`, the validator refused the document and the store declined the write | `VariableDefinition` is addable, renamable (**every reference is rewritten with it**) and removable, and the reference option is WITHDRAWN where the enclosing policy defines none |
| Choosing `any-of`, `all-of`, `map` or the other four higher-order functions built an `<AttributeValue>` where a `<Function>` belongs — an expression the validator refuses, offered by the editor's own menu | a function-parameter argument arrives as a `<Function>` reference, and `map` gets a one-argument default because its function takes one value where the other six take a predicate of two |
| An `AttributeSelector` could not be built, and a policy that HELD one lost its namespace bindings on the first edit — an unresolvable prefix is an empty bag, which is NotApplicable, which looks exactly like a policy that decided you may not | selectors are addable and editable (path, category, `ContextSelectorId`, `MustBePresent`, one namespace binding at a time), a `Match` may test one instead of a designator, and **the bindings are written back onto the element** |
| `add-assignment` had been in the menu since the editor shipped and an assignment could not be SEEN, so the only way to correct a mistyped one was to delete the whole obligation | assignments are drawn, editable (`AttributeId`, `Category`, `Issuer`) and removable, and their value is an expression node of its own |
| `Version`, `Issuer`, `ContextSelectorId`, `XPathCategory` and `MaxDelegationDepth` had no control anywhere; `MaxDelegationDepth` was read and never written | all of them are settable, and a `Version` that is not dot-separated numbers is refused HERE, because nothing else in this service would refuse it and somebody else's schema validator will |

**`MustBePresent` is a `<select>` and not a checkbox, and that is the one piece
of markup here worth arguing about.** An unchecked checkbox sends nothing, so
the handler cannot tell "unchecked" from "this form does not edit that field" —
and it has to keep the value for the second case, or the form that edits a
Match's function would clear `MustBePresent` on every save. That is the
difference between an absent attribute being an empty bag and being
Indeterminate: between a policy that quietly does not apply and one that fails
closed.

**`XPathVersion` is REPORTED and never enforced.** Section 5.14 says the
element MUST be present when a policy holds an `AttributeSelector` or an
`xpathExpression`, and `xacml_validate.js` says nothing about it and never
will — that file refuses what is CERTAINLY WRONG for every request, and this
changes no decision this PDP makes, because this engine evaluates no XPath at
all (see *What is not here yet*), so nothing here chooses a dialect by URI. So
the editor page names the policies that need one, beside the field that sets it.
Refusing the write would be the editor inventing a rule the evaluator has not
got; saying nothing would let somebody build a document here that this service
is happy with and a schema validator elsewhere rejects.

**THE THREE THINGS IT DOES NOT DO, and each is a decision rather than a gap:**

* **The four combiner-parameter elements are carried, drawn and removable —
  and no menu offers to add one.** Section C of the specification says none of
  the twelve standard combining algorithms takes a parameter, so an Add button
  would be the first control on this console that provably changes no decision.
  Drawing them is a different question and comes out the other way: a document
  may arrive carrying them through ALFA, an import or an `ldapmodify` straight
  into `ou=policies`, and an element the editor did not draw would be one the
  person could neither see nor delete while the writer faithfully kept it.
* **`<PolicyIssuer>` is not implemented at all**, so a document carrying one
  loses it here. It belongs to the administrative delegation profile, which
  this PDP does not implement — and `MaxDelegationDepth` beside it is carried
  and read by nothing, which the console says out loud rather than letting the
  attribute imply otherwise.
* **A variable may not be named with a dot in it.** XACML allows one; this
  editor addresses a node by a dotted path, so `a.b` would produce a row that
  cannot be edited or removed while the document itself stayed valid. Refused
  at the point of naming, where it can still be explained.

`tests/xacml_pap.js` carries all of it — 62 assertions added with the change,
including the one that would have caught the policy-set defect: three children
added, serialized, read back, and counted.

**Every element arrives complete and valid** — a new rule has a Target and an
Effect, a new Match has a function, a value and an attribute — because an
editor that produced half-built elements would hold a document that cannot be
saved, and a document that cannot be saved cannot be evaluated, which is when
you most want to look at it.

## The surface

```
GET  /xacml                 what this is; ?format=json for the same as data
POST /xacml/pdp             a decision. JSON Profile in, JSON Profile out
GET  /xacml/policies        the repository as the PDP sees it, documents included
GET  /xacml/protected       the embedded PEP — 200 or 403
POST /xacml/pep/register    a REMOTE PEP registers, over mutual TLS
GET  /xacml/pep/policies    the enabled policies, for a remote PEP to LOAD
POST /xacml/pep/heartbeat   what a remote PEP has enforced
POST /xacml/pip             the PIP over HTTP — XACML XML in, XACML XML out
```

**ALL EIGHT REQUIRE A CLIENT CERTIFICATE NOW, AND THIS SECTION SAID THE
OPPOSITE.** What stood here was an argument for `POST /xacml/pdp`
authenticating nobody, and half of it is still true and still load-bearing: **a
PDP is not an authorization boundary.** It answers a question about somebody
ELSE'S, the identity that matters is IN the request, and nothing the connection
carries reaches `decide()` — a PDP that decided about whoever holds the client
certificate would be a different and much worse component.

**What changed is that "not a boundary" was being read as "not worth
guarding".** Those are different sentences, and three of the four endpoints
proper do something an anonymous caller should not get for free: `GET
/xacml/policies` publishes the documents this service now decides its own
admissions with, `GET /xacml/protected` names its own subject from a query
parameter and is otherwise an oracle anybody can drive to map the policy one
subject at a time, and `POST /xacml/pdp` evaluates an arbitrary document on
this service's thread. `GET /xacml` is guarded because it describes the other
three, and its refusal names the group and the setting so that the page's job
survives being refused.

### Two roles, two groups, and they must not become one

| Endpoints | Role | Group |
|---|---|---|
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies`, `GET /xacml/protected` | `XACML_USER` | `roles.xacmlUserGroup` (default `xacml-users`) |
| `POST /xacml/pep/register`, `GET /xacml/pep/policies`, `POST /xacml/pep/heartbeat`, **`POST /xacml/pip`** | `REMOTE_PEPS` | `roles.remotePepGroup` (default `remote-peps`) |

**ONE GROUP GRANTING BOTH WOULD BE THE MISTAKE.** The `/xacml/pep/*` endpoints
hand out the documents this service enforces its own access with, and
`/xacml/pip` hands out a named person's directory attributes; the four above
them serve a demonstration policy. Admitting a caller to the second set must
not silently admit it to the first, which is why there are two built-in roles
and two settings rather than one of each. `common/roles.js` argues it at the
role and `common/access_gate.ts` at the resource — `xacml-api` and
`xacml-pep-api` are two ids precisely so an operator narrowing one surface and
not the other has two names to target.

**`POST /xacml/pip` IS THE ONE ENDPOINT WHOSE ROLE DOES NOT FOLLOW ITS PATH**,
and that is deliberate rather than an oversight: what comes back is somebody's
personal data rather than a rule anybody may check, so it takes the narrower
role even though it sits outside `/xacml/pep/`. The `Requires` column on `GET
/xacml` exists so that a role never has to be inferred from a path.

**THE MECHANISM IS ONE CHAIN, DESCRIBED ONCE**, in *Four links* above: a
verified certificate, a DN resolved to an entry, the roles that entry holds,
and a policy decision. `xacmlAccess()` and `pepAccess()` in `xacml/xacml.ts`
are the two call sites and differ only in the role and the resource they name.

## Where a policy lives

`ou=policies` in the embedded directory **is** the repository, the way
`ou=federations` is the federation register. That buys three things and none of
them is tidiness: persistence in all three modes with no driver change,
per-realm isolation for free, and `ldapsearch` and `/admin/ldap/directory` as
inspection tools that already exist.

The entry holds the **document as authored** and everything else on it is
derived at write time — so where the two disagree, the document wins. A write
goes through static validation, so a policy that does not typecheck is refused
while somebody is still looking at it rather than going Indeterminate on every
request for ever.

**One policy is seeded**, role-based, and the seeded directory was given
`employeeType` to match it — alice and bob are staff, carol is admin. The two
seeds have to agree or neither demonstrates anything: a policy granting on an
attribute nobody has answers Deny for everybody, which looks exactly like a
broken PDP.

## The one rule this directory is built on

**One model; XML, JSON and ALFA are three renderings of it.**

`xacml_model.js` is what all three readers produce and what `xacml_pdp.js`
evaluates. **If a function in `xacml_pdp.js` ever asks which syntax a policy
arrived in, this separation has failed** and the fix belongs in the model
rather than in the evaluator.

The argument is `common/vendored/xmldsig.js`'s, one layer up: a grammar is a
READING, and three readings are three chances to disagree with the PDP at the
far end — which for authorization means a decision nobody can reproduce. It is
also what makes ALFA cheap when it lands: a parser and an emitter, not a second
policy system.

## Where it stands against the conformance suite

**454 of 455 mandatory cases**, with the one exception recorded in
`conformance/MANIFEST.js`'s `EXPECTED_FAILURES` and argued there. The
VENDORED OASIS conformance suite is **Apache-2.0 rather than this repository's
MIT** and says so in `conformance/LICENSE`.

```
IIA   attribute references     18 of 18
IIB   target matching          55 of 55
IIC   the function library    261 of 261
IID   combining algorithms     57 of 57
IIE   policy references         2 of 3    (IIE003 — see EXPECTED_FAILURES)
IIF   other mandatory           3 of 3
IIIA  obligations              58 of 58
```

**The first run scored 6 of 455 and the second 434**, and what the difference
between those two numbers records is worth more than the final one: every
defect below was found by the suite and none of them would have been found by a
test written here.

## Four more defects, from phase two, and all four were silent

The engine's seven are below; these are from wiring it up. Every one of them
left a service that started, answered every request, logged nothing unusual,
and decided incorrectly. `tests/xacml_service.js` asserts each.

1. **LDAP ATTRIBUTE NAMES COME BACK LOWER-CASED.** RFC 4512 makes them
   case-insensitive and this directory normalises them, so a store that asks
   for the `xacmlPolicyDocument` it wrote gets `undefined`. Every field of
   every policy read back empty, `root()` found nothing, and the PDP answered
   NotApplicable to everything with a policy plainly sitting in `ou=policies`.
   `federation.js` reads `stored.attributes.fedid` in lower case for exactly
   this reason.
2. **THE SAME BUG IN THE PIP IS QUIETER AND WORSE.** A missing attribute is a
   *legitimate* answer, so there was nothing to report: the PDP simply decided
   as though the person held no roles.
3. **THE SEED RAN BEFORE THE STORE HAD ITS DIRECTORY.** `ldap_server.js` seeds
   at require time and fills the store's slot further down the same file. It is
   seeded at the slot-fill site now, guarded on the repository being EMPTY
   rather than on the container being new — those are different facts once
   persistence is in play, and the second would re-seed a policy an operator
   deleted on purpose.
4. **JSON HAS ONE NUMBER TYPE.** `5` and `5.0` both parse to `5`, so the
   integer/double distinction survives only in the source text.
   `xacml_json.js` re-scans the raw body for it.

## The seven defects the conformance suite caught, because each will be made again

Each of these produced an engine that looked correct, ran without error, and
was wrong. They are written up beside the code that fixes them; this is the
index.

1. **`errorHandler` is not a deprecated option in @xmldom/xmldom 0.9, it
   THROWS.** Passing both spellings defensively made every parse fail before a
   document was read — 449 cases reporting "could not be loaded" and naming an
   option rather than a policy. `xacml_xml.js`, `parseDocument()`.

2. **A combining algorithm CONTROLS EVALUATION; it is not handed results.** The
   specification's pseudocode returns from inside the loop, so a
   `deny-overrides` set whose fourth policy denies never evaluates the fifth.
   Evaluate all five and combine afterwards and the DECISION is identical every
   time — but the fifth policy's OBLIGATION is now in the response. Eight IID
   cases. `xacml_pdp.js`, above `COMBINERS`.

3. **NaN equals NaN.** XML Schema defines xs:double equality over a value space
   holding exactly one NaN and XACML defers to it, so `double-equal(NaN, NaN)`
   is True — the opposite of IEEE 754 and of `a === b`. IIC350, IIC358.
   `xacml_datatypes.js`, the double row.

4. **Date arithmetic is on the LOCAL components; the timezone is a label.**
   Normalising to UTC, adding, and re-labelling with the original offset shifts
   twice and lands five hours out — while still producing a well-formed
   dateTime. IIC102, IIC104. `xacml_functions.js`, `addSeconds()`.

5. **`only-one-applicable` must go through the same obligation collection as
   every other algorithm.** Returning the selected policy's result directly
   dropped the POLICY SET's own obligations and kept the policy's, which is a
   response that is right about the decision and short by half on what the PEP
   must do. IIIA025, IIIA026. `xacml_pdp.js`, `evaluatePolicySet()`.

6. **XACML is statically typed and a policy that does not typecheck must be
   REFUSED at load.** Five cases exist for this and for nothing else — a
   designator passed where a primitive is required (the commonest mistake in
   hand-written XACML), a Condition returning an integer, a string literal in
   an integer argument, a literal substring index out of range. Without the
   check all five load happily and produce a decision. `xacml_validate.js`.

7. **A rule's obligations must be resolved AT the rule.** XACML 3.0 put
   obligations on rules as well as policies, and the rule is the only place its
   variables are still in scope. `xacml_pdp.js`, `firedRule()`.

## Three things about the specification that catch everybody once

**The version segment in a function URI is not predictable.** Most standard
functions are `1.0`; every function of the two DURATION types is `3.0`, because
those types moved namespaces; and the six higher-order functions split across
both — `any-of`, `all-of` and `any-of-any` are 3.0 while `all-of-all`,
`all-of-any` and `any-of-all` are 1.0. This is the specification's own
inconsistency. It is why `xacml_model.js` spells every identifier out instead
of building one by concatenation: a wrong URI matches nothing and fails as
`NotApplicable`, which is not an error anywhere.

**There are seven decisions, not four.** `Indeterminate{P}`, `{D}` and `{DP}`
exist for the combining algorithms and for nothing else, and collapsing them
makes `deny-overrides` return Permit where the specification says Deny — a
policy that permits because an attribute lookup failed. `externalDecision()`
folds them down ONCE, at the bottom of `evaluate()`; a second call site
anywhere is a bug.

**Every value is a bag.** An `AttributeDesignator` returns a bag even when it
finds one value, which is why `string-one-and-only` exists and why IIC003 is an
invalid policy. Nothing here ever holds a bare value, so there is no code path
where somebody has to remember to wrap one.

## What is not here yet

One gap in the engine, and it is the only one left.

* **`AttributeSelector` and the XPath functions.** A policy using one is
  Indeterminate rather than silently empty, which is the deliberate choice: an
  empty bag is a perfectly ordinary result a policy may be written to expect,
  so returning one would make an unimplemented feature look like a decision.

**Phase five was this list's other entry and it landed as described**, which is
worth recording because two of the three things this section predicted about it
turned out to be exactly right and one was left open: it IS `xacml-pep/`, its
own container; it DOES register over mutual TLS on the main port, which already
asks for a client certificate (`server.js`'s `requestCert: true`), so no new
listener was needed; and the certificate DOES map to a directory entry through
`ldap_server.js`'s `certificatePlan()` rather than a second mapping — though
only the NAMING is reused and no `ou=users` entry is created, because a PEP is
a component and that container counts people.

What this section did not settle was the DIRECTION, and it reads as though a
push were assumed ("policy push"). **It is a pull.** See below.

## What phase three actually cost outside this directory

For the next person adding a console surface, following the shape
`ssf/CLAUDE.md` records:

* `common/config.js` — the `xacml.pepBias` row needed **`enumValues`**, not
  `values`. The wrong key name is not a startup error: the setting loads, the
  service runs, and the settings form throws a 500 on the one page that draws
  it.
* `admin-ui/admin.ts` — the **tenth slot** `setXacmlPages()`, a `SETTING_HOMES`
  row (its absence is what the boot warning was about), an `XACML` group of
  four in `SECTIONS` with a `blurb` each, and three helpers exported that had
  been private: `configFormsFor`, `configSettingsJson` and `respondToAction`.
* `mgmt-api/admin_api.ts` — three GETs and a POST with ten documented actions
  (`import-alfa` arrived in phase four);
  `mgmt-api/admin_api_spec.ts` — `Xacml`, `XacmlPolicies` and `XacmlEditor`.
* `sts_metadata.ts` — **eight** `ENDPOINTS` rows, four of them console pages
  and four management API, which are again the ones a checklist forgets.

**The one thing that is not a file**: `protocolSettingsJsonFor()` is NOT the
JSON counterpart of `configFormsFor()`. It is keyed by admin.js's own
`PROTOCOL_SETTINGS_PAGES` table and **throws** for a path that table does not
carry — correct for the pages that file generates, and a 500 for one drawn
anywhere else. `configSettingsJson()` is the right function and is now
exported beside the renderer it belongs to.

## And what phase four cost, which was almost nothing outside this directory

ALFA is a SYNTAX, not a second policy system — the model, the validator and the
XML writer were already there — so it landed as one new module, one console
`<details>`, one `import-alfa` action and its `/admin-api` operation. No new
setting, no new route, no metadata row beyond the action's own.

**One defect, and it is the same one twice.** The emitter first wrote a policy's
`<Description>` as a `//` comment — and the tokenizer discards comments, so
every explanation survived being read by a person and was DELETED by the next
round trip. The XML reader had had exactly this defect a phase earlier. It is a
`description = "..."` property now, which reads back.

**The one thing a round trip through ALFA can still change**: a policy naming a
LEGACY 1.0 or 1.1 combining algorithm comes back naming the 3.0 one. They share
an ALFA name and they are genuinely different functions (see `xacml_pdp.js`), so
this is a normalisation rather than a no-op. It is called out where
`ALGORITHM_NAMES` is declared.

---

# Phase five: the remote PEP

**THE REMOTE PEP LANDED 2026-09-05 and its container is `xacml-pep/`.**

**THE PEP PULLS. THIS SERVICE DOES NOT PUSH.** Everything below follows from
that sentence, and this section's predecessor assumed the opposite — the *What
is not here yet* entry above said "policy push" and the direction was settled
the other way when the phase was built.

A remote PEP holds its own copy of the engine and evaluates locally, because a
PEP that asked this service per request would be `POST /xacml/pdp` with a
network hop in front of every access decision, and pushing *policies* to
something that could not evaluate them would make no sense at all — you would
push decisions. So something has to move policy from here to there, and it
could have gone either way. It goes by pull for three reasons:

1. **A push would be an outbound request CARRYING CONTENT.** Outbound requests
   are deliberately rare in this repository — `federation/federation_http.ts`
   and `ssf/ssf_http.ts` each argue their own — and a push would make policy
   DISTRIBUTION depend on this service being able to dial every PEP.
2. **A PEP knows when it is behind and this service does not.** Under push, a
   PEP that was down for a minute has a stale copy and no way to discover it;
   under pull, being current is checked on every poll. That inverts the
   failure: a partition leaves a pulling PEP KNOWINGLY stale rather than
   unknowingly wrong.
3. **It works where a PEP cannot be dialled** — behind NAT, in another cluster,
   on a laptop. A PDP that could only serve PEPs it could reach would be a PDP
   for one deployment topology.

## The nudge is the third outbound request here, and it is the weakest case

When the repository changes, this service POSTs a few bytes to each registered
PEP that gave a notify URL, saying only "something changed, pull now".

`xacml_pep_http.ts`'s header makes the argument from scratch, as
`ssf_http.ts`'s does rather than citing federation's — and it opens by saying
it can make NEITHER of the other two arguments. Federation's rule is *those
URLs are supplied by the caller, these by the administrator*, enforced by
refusing to take a URL at all; a notify URL is supplied by the PEP that
registers, which is a caller. SSF can say that RFC 8935 push IS the receiver
telling the transmitter where to post; there is no specification here at all,
because XACML 3.0 says nothing about how a policy reaches a PEP.

**What makes it affordable is the one thing the other two cannot say: the nudge
is never the mechanism.** It carries no policy, no decision, no event, no
credential and not even the new sync token. Every PEP converges without it. So:

* `xacml.pepNotify` can be turned off in a deployment with no egress and nothing
  breaks — not the feature, not a test, not a PEP;
* there is no retry and nothing to redeliver, because there is nothing to lose
  (where `ssf_http.ts` records a failed push on the stream and offers a
  redeliver, because a lost push IS a lost event);
* a refusal is worth RECORDING and never worth escalating.

**If a future change puts something in that body a PEP cannot get any other
way, the whole argument goes with it.** The body is three members; keep it that
way or move the argument.

Its four bounds are `ssf.push*`'s four, deliberately — an off switch, a host
allowlist empty by default meaning any, an https-only rule with an escape in
development only, and a timeout — because two families making one outbound
request each should be
configured the same way or the second is a surprise to anybody who read the
first. The timeout is SHORTER (2s against SSF's 10s) and that is the difference
that follows from the argument: a lost push is a lost event, so SSF waits; a
lost nudge costs one polling interval, so waiting is the expensive mistake.

**The https rule is `common/outbound_tls.ts`'s since #171 (2026-09-23)**, shared
with GNAP, SSF and federation. `xacml.pepNotifyAllowInsecure` allowed plain
http AND turned the PEP's certificate check off, and product mode honoured it.
Three settings now: `xacml.pepNotifyAllowHttp` (development only; product
refuses a plain-http nudge, `STS-XACML-0073`), `xacml.pepNotifySkipTlsVerification`
(development only; ignored in product, `STS-XACML-0074`, and refused on write,
`STS-CORE-0103`) and `xacml.pepNotifyCaFile` (a PEP certified by a private CA,
beside node's store; unreadable refuses the nudge, `STS-CORE-0104`).
`GET /admin-api/xacml/peps`' `notify.transport` reports the three as they are
IN FORCE, so a skip stored in a product realm reads false there.

**On an active-active node the nudge waits for the COMMIT, and only there
(2026-09-15, #46).** It is fired from inside `xacml_store.write()`, and the PEP
answers 204 and pulls at once — through the load balancer, on whichever node
its connection lands. A node that is not the writer serves what has COMMITTED,
so it answered the old sync token with 304 and the PEP converged on its next
heartbeat: the suite's `cluster` mode measured 2018ms and 916ms against a
nudge worth tens of milliseconds (`sts_xacml_remote_pep` section 6). So
`afterCommit()` in `xacml.ts` dispatches it after `setImmediate` (the saving
request has usually answered, so its barrier's commit is the flush in flight)
and `persistence.commitThrough(writeGeneration())`. A failed commit still
nudges. One node, the cluster off and a dispatched pool dispatch at once as
before; this is not "waiting on somebody else's web server" — nothing awaits
the nudge, it only leaves later. `tests/cluster_observation_counters.js`
section 4.

## What is authenticated, and what deliberately is not

**EVERY ENDPOINT IN THIS FAMILY ASKS NOW.** This section said otherwise —
that `POST /xacml/pdp` and `GET /xacml/pep/policies` needed no credential — and
the second of those two sentences had already stopped being true when phase
five put `pepAccess()` in front of that endpoint. The full argument is under
*Two roles, two groups* above; what belongs here is the part that did NOT
change and is easy to lose:

* **A PDP is still not an authorization boundary.** The identity on the
  connection decides who may ASK; the identity the decision is ABOUT is in the
  request, and nothing `xacmlAccess()` learns reaches `decide()`.
* **A policy is still a rule, and a rule nobody can read is a rule nobody can
  check.** That argument did not stop being sound — it stopped being the whole
  question. Once the access and issuance PEPs were embedded, these documents
  became the ones this service decides its own admissions with, and *who may
  read it* is a different question from *is it redacted*. The documents are
  still shown in full to anybody the policy admits, which is the half of the
  old sentence worth keeping.
* **`/xacml/protected` still has TWO gates about two different people**: the
  caller needs `XACML_USER` to drive the embedded PEP at all, and the subject
  in `?subject=` is what it then enforces about. An admitted caller can still
  ask about somebody the policy refuses and watch it refuse — which is the
  whole demonstration, and it is why the two are not folded into one.

**REGISTERING ASKS A SECOND QUESTION ON TOP**, and it is a different one: not
who the decision is about but WHICH PEP THIS IS — because a registration writes
an entry, puts a row on the console, and supplies an address this service will
later dial. `xacml.pepRequireCertificate` is on by default.

It is a TURNSTILE like every other gate here: the certificate need not chain to
anything, on RFC 8705 section 3's argument that what is proved is that the same
key completed the handshake. And **a registration is not a permission** — an
unregistered PEP pulls and enforces exactly as well. `xacml_pep_registry.ts`
says so where the register is defined, because the shape looks like an
access-control list and is not one.

**The refusal distinguishes the two ways of arriving at it**, because they need
opposite fixes: a plain-HTTP listener cannot carry a certificate at all (turn on
`global.https`, or turn the requirement off), and an https one can (the client
sent none). A single sentence covering both would send half its readers the
wrong way.

## `POST /xacml/pip`: THE POLICY INFORMATION POINT, OVER HTTP

A remote PEP holds its own copy of the engine and evaluates locally — that is
the whole point of having one. What it does NOT hold is the PIP: **this
service's PIP *is* the embedded directory**, and a process in another container
has no access to it. So a policy with an attribute designator the request did
not carry resolves to an EMPTY BAG out there and to a real value in here, and
**the same policy decides two different ways in two enforcement points** —
which is the drift a shared repository exists to prevent, reappearing one layer
down.

The remote PEP could not have fixed this for itself. The attributes are on
directory entries this service owns, and handing a PEP an LDAP connection would
be a far larger grant than handing it an answer to one question.

### XACML defines no PIP protocol, so this invents as little as possible

The specification describes the PIP as an architectural component and says
nothing about how a PDP reaches one: no request document, no response document,
no binding. So the obvious move is to design an envelope of this service's own,
and **the first draft did exactly that — a JSON body with a `Designator` array
— and it was wrong.** The reason is worth keeping: an invented vocabulary means
the remote PEP has to TRANSLATE, and every translation is somewhere the two
engines can come to disagree about a datatype, a category, or what an absent
value means. That is the drift this endpoint exists to remove, moved into the
transport.

Both directions are **XACML's own XML**, and the envelope is two elements
thick:

```
REQUEST   <PIPRequest xmlns="urn:sts:xacml:pip:1.0">
            <Request …/>                  the request being decided — it names the subject
            <AttributeDesignator …/>      one per attribute wanted
          </PIPRequest>

RESPONSE  <PIPResponse xmlns="urn:sts:xacml:pip:1.0">
            <Attributes xmlns="…core:schema:wd-17" Category="…">   ← XACML's namespace
              <Attribute AttributeId="mail" IncludeInResult="false">
                <AttributeValue DataType="…#string">alice@…</AttributeValue>
            <Unresolved>                                          ← this service's own
              <Designator …><Reason>…</Reason></Designator>
```

Nothing in either direction is read or written by code invented for it. The
`<Request>` goes through `xacml_xml.js`'s `readRequest()` and each designator
through its `readExpression()` — **the same function that reads an
`<AttributeDesignator>` out of a POLICY**, so a designator means the same thing
on this wire as it does in the document the PEP is evaluating, including the
reading of `MustBePresent` where absent and false are recorded as different
things.

`readRequest()` is a SPLIT of `parseRequest()` and not a second reader: that
one takes a whole document, this takes the node, and the alternative was to
serialize the nested subtree back to a string — putting an XML serializer in
the path of every PIP query, which is exactly where namespace declarations
inherited from an ancestor go missing.

### The response shape is the whole design

A PIP's answer is a bag of attribute values for a designator, and the XACML XML
rendering of exactly that already exists: it is the `<Attributes>` /
`<Attribute>` / `<AttributeValue>` tree a `<Request>` is made of. **So what
comes back is a REQUEST FRAGMENT**, and a remote PEP has two ways to use it,
neither of which needs a translator:

* splice the `<Attributes>` into its own request and evaluate — after which its
  engine finds the values where a designator looks for them, which is precisely
  what happens in this process when the embedded PDP asks the embedded PIP; or
* read them with its own copy of `xacml_xml.js`'s request reader, which is the
  same code that read them out here.

**AN EMPTY BAG IS AN ABSENT `<Attribute>` AND NOT AN EMPTY ONE.** Two reasons
pointing the same way. The schema requires at least one `<AttributeValue>`
inside an `<Attribute>`, so an empty one is not a legal request fragment and a
PEP splicing it would build a request its own parser refuses. And *the request
did not carry it* is what an unresolved designator ALREADY looks like to every
engine — so a PEP that receives nothing behaves exactly as the embedded PDP
behaves when the PIP answers nothing, **with no branch of its own**. That is
the sentence the whole endpoint is arranged around.

**`MustBePresent` IS READ AND DELIBERATELY NOT APPLIED.** Whether an empty bag
ends a decision is settled by the designator and by the function the bag is
handed to, and both of those are in the CALLER's engine. Applying it here would
move a decision across a network boundary and answer a question nobody asked —
and it would make an absent attribute an ERROR on the wire, which is the
classic PIP defect in its most damaging form: `xacml_pip.ts`'s header opens
with why an absence must never become a presence or a failure.

### `<Unresolved>` is the one invented thing, and it is out of the way

A bag can be empty for five reasons that need five different fixes — a
designator in the wrong category, an AttributeId that is not a directory name,
a request naming no subject, a subject that resolves to no entry, and an entry
whose values will not parse at the declared datatype. **To a PDP they are one
empty bag and must be**; `xacml_pip.ts` logs the difference at debug level, in
a log that is in another container as far as the caller is concerned.

So the reasons come back in `<Unresolved>`, in **this service's own
namespace**, a sibling of the `<Attributes>` rather than inside them. A PEP
reading only the XACML core namespace — which is every PEP — never sees it, so
the payload stays a clean request fragment; a person or a PEP that wants to
know why finds it named. Putting a diagnostic INSIDE the core namespace would
have been the mistake: an element the OASIS schema does not define, in a
document a caller is invited to splice.

### What guards it, which is a shorter list than it looks

Every mechanism this service puts on an endpoint that takes a body from a
stranger, and the one that had to be given its own number.

| | |
|---|---|
| **Authentication** | a client certificate this service VERIFIED, whose subject DN resolves to a directory entry holding `REMOTE_PEPS`. Four links, none permissive — see *The three `/xacml/pep` endpoints are GATED* above |
| **Authorization** | `accessGate.check()` on resource **`xacml-pep-api`** and NOT `xacml-api`, which is the role not following the path said at the resource as well |
| **Rate limiting** | `websecurity.attemptShared('xacml-pip', …)`, **BEFORE the access check** |
| **Body ceiling** | `validation.parseXml()` at `CAP.LARGE` — a megabyte, where `app.js`'s parser stops at five |
| **Scalar bounds** | AttributeId, Category and DataType at `CAP.IDENTIFIER`; the subject at `CAP.NAME`; C0 refused in all four |
| **Designator cap** | fifty per query |
| **Cache-Control** | `no-store`, like every other answer here |
| **Audit** | `xacml.pip.query`, one row per call, naming the PEP and the subject |

**THE RATE LIMIT IS BEFORE THE ACCESS CHECK AND THAT IS THE ONE ORDERING
DECISION.** Put after it, an unadmitted caller could ask this service to build
a certificate chain, resolve a DN and evaluate an access policy as fast as it
could send — refused every time and never counted. Put where it is, the ADDRESS
bucket bounds that and the IDENTITY bucket bounds the case that actually costs
something: a caller this service ADMITTED reading directory attributes in a
loop.

**AND IT NAMES ITS OWN CEILING**, `xacml.pipMaxPerWindow`, default 600 over
`security.rateLimitWindowS`. `security.rateLimitPerIdentity` is FIVE because it
guards a SIGN-IN, where a sixth attempt a minute is somebody guessing; a PIP
query is one per access decision, so a busy enforcement point makes several a
second and every one is legitimate. **Sharing the sign-in number would have
switched this endpoint off for its only caller, and it would have done it
SILENTLY** — `xacml-pep/pip.js` treats a refused query as an empty bag and goes
on deciding on less information. `websecurity.js` argues the optional fourth
argument that carries it and `tests/portal_access.js` asserts it in process,
where the bucket can be cleared afterwards; the buckets are per PROCESS, so a
job that drove one over HTTP would leave the next job in the run meeting 429s
that were nothing to do with it.

**ENTITY EXPANSION IS NOT A HAZARD AND THAT IS MEASURED RATHER THAN ASSUMED.**
`@xmldom/xmldom` resolves no entity declared in a DTD, internal or external: a
billion-laughs document and an `<!ENTITY xxe SYSTEM "file:///etc/passwd">` both
come back as *entity not found* and are refused as not well-formed. So there is
no expansion limit to set and no external resolver to disable — and
`sts_xacml_endpoints.js` asserts it anyway, which is what stops it becoming an
assumption the day the parser is swapped.

**THE XML READERS ARE NOT RE-CHECKED AND MUST NOT BE.** What a `<Request>` and
an `<AttributeDesignator>` ARE is settled by `xacml_xml.js`, held to 454 of 455
OASIS conformance cases; a schema over either would be a second, worse reading
of a specification this directory implements. What those readers have no
opinion about is the LENGTH of a string, and three of the scalars come back out
again — echoed into `<Unresolved>`, named in the audit row, handed to
`locateEntry()`. That is the whole of what is added, and the line is worth
keeping: bound what a caller chooses the size of, and re-read nothing the
conformance suite already covers.

### Three smaller decisions

* **The entry is resolved ONCE per call**, for `resolverFor()`'s own reason: a
  caller asking about six attributes of one person must not be able to see six
  different people because somebody wrote to the directory in between. The
  lookup exists a second time only so `<Unresolved>` can say which reason
  applied, and it goes through the PIP's own `locateSubject()` rather than a
  new one, so "resolves" means one thing.
* **`IncludeInResult="false"` is written explicitly** rather than left to the
  default. A PEP that splices this into a request it then echoes must not start
  reporting this service's directory contents back to its own callers.
* **A malformed query is a 400 and never an empty answer.** This is
  `/xacml/pdp`'s 400-not-Indeterminate rule and it matters more here: an
  unresolved designator is a legitimate ANSWER, so a reader that answered one
  for a typo would be indistinguishable from the attribute being absent, and
  the caller's PDP would go on to decide on it.
* **`xacml.remotePeps` turns it off, not `xacml.enabled` alone**, and the first
  draft had that the other way. The endpoint is NAMED for the component it is,
  so putting it behind the registration feature's switch looks inconsistent —
  but **the switch follows the CALLER rather than the name**. An operator who
  turns remote enforcement points off has said they want none outside this
  process, and leaving an endpoint that hands a named person's directory
  attributes to anything holding `REMOTE_PEPS` still answering would be that
  switch not doing what its own description says. The role does not follow the
  path here and neither does the switch, and both point the same way — which
  makes it one decision rather than two exceptions.

### The remote PEP uses it, and the shape of how is the interesting part

**`xacml-pep/pip.js` is the client** and `xacml-pep/CLAUDE.md` argues it. The
one thing worth knowing from this side is why the endpoint is BATCHED: the
engine's resolver is synchronous — it is handed a designator and must return an
array — so the remote PEP cannot make an HTTP request from inside evaluation.
It walks the policy for every access-subject designator first, asks for all of
them in ONE query, and evaluates with a resolver over what came back.

**So the list is not an optimisation.** A one-designator-per-call endpoint
would have been unusable by the only caller it was built for, and that is the
constraint that decided the request shape rather than anything about
efficiency.

`tests/vendored/sts_xacml_remote_pep.js` section 3 drives the whole path: a
policy over `employeeType`, a container asked about `carol` with the request
asserting NOTHING, and a Permit that can only have come from her entry under
`ou=users` in this service's embedded directory — beside a name the directory
has never heard of, refused at both ends. **That section used to assert the
opposite**, in both directions, and the inversion is recorded where it happens.

### What it does not do yet

**Nothing caches.** A PIP query is made per decision, so a busy PEP asks the
same question about the same person repeatedly. That is correct and slow, and
correct is the right half to have first: a cache needs an invalidation story,
and the honest one here is that a directory entry can change at any moment with
nothing to tell a PEP about it. The nudge is the obvious mechanism and it
currently carries nothing by design.

## `ou=peps` is the register, and one certificate is one entry

The same arrangement `ou=policies` has, for the same three reasons — persistence
in all three modes, per-realm isolation, and `ldapsearch` for free.

The entry is NAMED from the client certificate through `certificatePlan()`'s
naming rule, which arrives across the slot rather than being reimplemented, so a
PEP is filed under exactly the name this service gives any certificate-borne
identity. A PEP that restarts UPDATES its row. Two instances sharing a
certificate collapse into one row, which is correct: the question the register
answers is *which PEPs am I distributing policy to, and are they current*, and a
nudge to either instance is a nudge to that deployment.

**No `ou=users` entry is created.** The NAMING is reused, the entry creation is
not — a PEP is a component and that container counts people, which is exactly
the distinction `spiffe_registry.js` had to draw between an ISSUANCE and an
AUTHENTICATION.

Three decisions on the row that each prevent a specific wrong reading:

* **A re-registration keeps the counters, the date and the DISABLED flag.** The
  last is the one that would have been a security-shaped mistake the other way
  round: a PEP an administrator stopped nudging must not re-enable itself by
  reconnecting.
* **A heartbeat SETS the counters rather than adding to them**, because a PEP
  reports its own cumulative totals — adding would count every decision once
  per heartbeat and produce a number that only goes up, looks plausible, and is
  wrong by a factor of the heartbeat interval. A PEP that restarts therefore
  makes the row go DOWN, which is honest.
* **A failed nudge does not move `lastSeen`.** A nudge that failed is evidence
  the PEP is NOT reachable, and letting it stamp liveness would make an
  unreachable PEP look freshly seen.

## The sync token is a digest of what would be SENT

`syncToken()` hashes the documents of every ENABLED policy plus which one is the
root — exactly the bytes `GET /xacml/pep/policies` answers with. Three
consequences, and the third is why it is not a modification stamp:

* a policy edited and edited BACK does not invalidate anybody's copy, because
  the repository genuinely did not change;
* DISABLING a policy moves it, because a disabled policy is not sent;
* a change through ANY door moves it — console, `/admin-api`, `ldapmodify`,
  LDIF restore — because it is computed from the store on the ask. A counter
  incremented by the write path would have been correct for the two doors that
  remembered to increment it.

`current` is therefore a COMPARISON this service performs rather than a claim
the PEP makes about itself.

## What the console page is NOT

`/admin/xacml/peps` reaches into no other process. "Stop nudging" stops this
service dialling a PEP; it does not stop it enforcing, because it already holds
the engine and the policy. "Forget" removes a row. **A control labelled
"disable" that leaves the thing running is the single most misleading thing a
console can do**, so every disabled row says so.

## The remote PEP's HTTPS listener (2026-09-13)

The fourth control on `/admin/xacml/peps`, and the only one that does something
FOR the other process rather than about it: **Issue certificate** mints the key
pair a PEP serves its own clients over HTTPS with. `xacml_pep_tls.ts` is the
module; `common/pki.js`'s `issueTlsServerKeyPair()` does the issuing, from the
realm's `pep-tls` Issuing CA.

* **THE REALM IS THE REGISTRATION'S.** The row is looked up in the ambient
  realm's `ou=peps` and a PEP not registered there is refused
  (`STS-XACML-0071`). That is not a permission on the PEP — registering is
  still not what lets it pull — it is the only record that says which realm
  this PEP belongs to, and it carries the notify URL the default name comes
  from.
* **THE NAMES** are the PEP's registered name (where it is a DNS name), the
  host of its notify URL (an IP host becomes an IP subjectAltName), and what
  the caller adds. Added, never replacing: the notify host is where this
  service would dial the PEP.
* **THE KEY IS IN ONE REPLY.** Nothing writes it onto the PEP's entry — this
  service is never party to a handshake between the PEP and its clients, so a
  copy would be a server key held by something with no use for it. The console
  answers the POST as a `no-store` PAGE rather than a 303, for
  `/admin/pki/person`'s reason: a private key on a query string is a private
  key in the history, the log and the next `Referer`. JSON in, JSON out.
* **THE ROW SHOWS WHAT WAS ISSUED, FROM THE CERTIFICATE REGISTER** (`pki.js`'s
  slot for the PEP's name), not a copy on `ou=peps` that would go stale at the
  first reissue. Whether the PEP is SERVING it is the PEP's own `GET /`.
* **IT IS THE ONE ASYNCHRONOUS XACML ACTION.** `pepAction()` answers a PROMISE
  for it and a plain result for the other three, and both callers
  (`admin-core/admin_actions.ts`'s `xacmlAction()` and the console handler)
  settle it with `Promise.resolve()`. The other actions stay synchronous
  because `tests/xacml_pap.js` and `tests/xacml_alfa.js` call
  `combinedAction()` without awaiting.

`xacml-pep/CLAUDE.md` argues the container's half — why the pair is re-read
from disk rather than read once — and `tests/pep_listener_certificate.js` and
section 1b of `tests/vendored/sts_xacml_remote_pep.js` pin both.

## What phase five cost outside this directory

* `common/config.js` — **eight** rows and the regenerated `env/defaults.js`.
* `ldap/ldap_server.js` — `ou=peps`, its three store functions, and a slot
  carrying FOUR things: the three plus `certificateIdentity`, which is the whole
  reason the register does not invent a naming rule of its own.
* `admin-ui/admin.ts` — the tenth slot grew from four views to SIX, a
  `SECTIONS` row, and `xacmlPepsView` / `xacmlDecideView`.
* `mgmt-api/` — two GETs, three actions and two schemas for phase five itself,
  plus the nineteen undocumented editor actions and thirty-two request bodies
  that defect 5 below turned out to owe.
* `sts_metadata.ts` — **six** `ENDPOINTS` rows.
* `admin-ui/crypto_metadata.ts` — the XACML row's missing halves (see below).
* `docker-compose.yml` — a `xacml-pep` service under `profiles: [xacml]`.
* And the container itself, `xacml-pep/`, which has its own `CLAUDE.md`.

## SIX DEFECTS PHASE FIVE FOUND THAT WERE NOT PHASE FIVE'S

All six predated it, all six were in the PDP-side work of phases one to three,
and **every one of them was found by running three jobs this branch had never
run** — `sts_metadata.js`, `admin_api.js` and `sts_admin_api_operations.js`,
all three of which are THIS REPOSITORY'S OWN (`local: true` in the vendored
manifest) and all three of which would have failed the day the defect was made.

1. **`/admin-api/crypto` answered 500.** The XACML row added to
   `crypto_metadata.js`'s `FAMILIES` in phase one carried no `envelopes` and no
   `algorithms()`, and `cryptoJson()` calls both on every row without checking —
   deliberately, because a row is the whole shape or it is not a row. Three rows
   of that table say "nothing" and this one must still carry the fields.
2. **`/admin/xacml/decide` had no `/admin-api` operation**, which rule 7 requires
   in the same commit as the page. It shipped in phase three without one.
3. **`tests/vendored/sts_metadata.js`'s protocol list did not name XACML**, so
   the card added in phase one was never checked against the page.
4. **The action endpoint answered `{ ok, why }` where every other action
   resource on `/admin-api` answers `{ ok, errors: [...] }`.** That is not a
   cosmetic difference: `sts_admin_api_operations.js` reads that array on every
   resource to check that the refusal SENTENCE names the actions, and
   `admin_api.js`'s parity check reads that same sentence to find out what a
   resource can do. A resource answering `why` is invisible to both. The
   conversion is in `xacmlAction()` (in `admin-core/admin_actions.ts`; it was
   `admin.js`'s until 2026-09-12), which is the one function the management
   API calls and the console does not.
5. **NINETEEN of the editor's twenty-three actions were undocumented, and not
   one of the thirty-two carried a request-body example.** Both halves matter
   and they fail differently: an undocumented action is a console control that
   could lose its operation with nothing failing, and an operation with no
   example is one `sts_admin_api_operations.js`'s ledger drives with nothing —
   its walk is driven off the document, so an operation arriving with no
   example and no section of its own is covered by nothing and reported by
   nothing. All thirty-two carry a documented body and an example now, and the
   ledger replays every one of them against the running service.
6. **`sts_admin_console.js` read only the FIRST console control an operation
   said it mirrored.** `/admin-api/xacml/{action}` mirrors three, so
   `/admin/xacml/editor`'s forms were never checked against the route list at
   all — and when phase five's sentence grew a comma, the greedy `\S*` swallowed
   it and even the first path stopped matching. `consolePostPathsIn()` is the
   one reader of that prose field now, it finds all of them, and it strips
   trailing punctuation. **Phase five did not cause that defect; it made the
   pre-existing one visible**, which is the ordinary way a silent guard is
   found.

## AND TWO THAT WERE

1. **`certificatePlan()` takes DN fields as STRINGS and node hands back
   OBJECTS.** `getPeerCertificate()` returns `subject` and `issuer` as
   null-prototype objects of RDN types, so `String()` on one throws `Cannot
   convert object to primitive value` rather than producing a DN. Every existing
   caller had always put both through `helpers.dnRfc4514()` first, so the
   precondition was real and written down nowhere — it is written at the
   function now. It was met TWICE, once per field: fixing the subject alone just
   moved the throw eighty lines down.
2. **The remote PEP asserted attributes under only ONE spelling.** The mock's
   PIP answers both `employeeType` and
   `urn:sts:xacml:attribute:employeeType` from one directory attribute, so
   a policy author may legitimately write either; the container asserted only the
   prefixed form and the seeded RBAC policy names it bare. **Every request was
   denied by a policy that was working perfectly**, which is the worst shape an
   authorization bug can take. It asserts both now.

Neither would have been found by anything but running the container against the
service.

## THE MOST VALUABLE THING IN PHASE FIVE IS NOT THE FEATURE

`xacml-pep/common/helpers.js` is thirty lines exporting `log` and `xmlEscape`,
and it is what `../common/helpers` resolves to inside that container. Every
engine module here claims **no I/O, no DOM, no store** in its header — and every
one of them requires `../common/helpers`, which in this service pulls in the
config table, the crypto module, the realm registry, node-forge and
jsonwebtoken. The claim had a loophole wide enough to drive anything through.

An engine module that grows a dependency on this service does not degrade in
that container — **it throws at load**, and `tests/xacml_pep.js` fails naming
it. That test also asserts that not one of this service's modules is in the
child's `require.cache` once the engine has loaded, and that the engine reaches
the same decision there as here on the same policy.

So "the engine is a library with no I/O" stopped being a comment at the top of
seven files and became something that is checked. That is worth more than the
remote PEP it arrived with.

## THE THIRTEENTH DEFECT, AND THE ONLY DOOR THAT COULD HAVE SHOWN IT

`tests/vendored/sts_xacml_editor.js` found it on its first run, and it had been
there since phase three: **every refusal on the three `/admin/xacml` pages
redirected back to the page with `error=` and nothing in it.**

The three action functions here — `policyAction()`, `editorAction()` and
`pepAction()` — refuse with a single `why`, which is the shape `xacml_store.ts`
and `xacml_editor.ts` hand up to them. `admin.respondToAction()` built the
browser's message out of `errors`, which none of them sets. So the person got
the page they had just posted from, unchanged, with no explanation — which reads
exactly like a control that does nothing.

**It was invisible from both of the places that look.** `/admin-api` had already
been given the translation (`admin_actions.js`'s `xacmlAction()` puts `why`
into `errors`), so
every refusal was fully explained there and
`tests/vendored/sts_admin_api_operations.js` was right to be satisfied. And
`tests/xacml_pap.js` asserts the refusal the FUNCTION returns, which was correct
the whole time. The defect lived in the two lines between them, and the only way
to see it was to press a button in a browser and read the page that came back.

It matters most exactly where this console leans on it hardest: the editor is
LIVE, and the thing that makes that tolerable is that an edit which would leave
a policy invalid is refused and the stored document is untouched. The sentence
saying so — which names the type error the author has to fix — was the part
being dropped.

Fixed in `admin-ui/admin.ts` rather than in the three handlers, so that a fourth
handler written in that shape cannot reintroduce it and so that the console and
`/admin-api` cannot disagree about what a refusal said.

## AND SINCE 2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE

`xacml_role_pep.ts` is the exception to the sentence at the top of this file.
Everything else here answers a question about SOMEBODY ELSE'S boundary — that is
what a PDP is. This one turns THIS service's issuances into XACML requests and
refuses the ones the PDP will not permit.

It fills `common/issuance_gate.js`'s decider at require time, which is what arms
every issuance site in the service: the nine kinds of issuance in
`issuance_gate.js`'s `ISSUANCE`, and every `gate.check()` call in the modules
that issue them. The decider is read at CALL time, so a module required after
23c (GNAP, at 23d) is armed exactly as one required before it. So
`xacml/xacml.ts`
requiring this module is the line that turns a service which answers "allowed"
to everything into one that asks a policy.

**There is no second implementation of the rule.** No `if (roles.includes(...))`
in `oauth2.js`, no membership test in the SAML builder. The reason somebody was
refused is a document an administrator can read, edit, test on
`/admin/xacml/decide` and see in the audit log — which is the whole point of
routing an internal decision through a policy engine that is already here.

### The request it builds is the contract

| Category | Attribute | What it is |
|---|---|---|
| access-subject | `subject-id` | who is being authenticated |
| | `urn:sts:xacml:role` | the roles they hold |
| | `urn:sts:xacml:role-from-token` | roles read out of a token they PRESENTED |
| resource | `resource-id` | the application |
| | `urn:sts:xacml:required-role` | what it demands |
| action | `action-id` | `issue-access-token`, `start-session`, and the rest of `issuance_gate`'s `ISSUANCE` |

**The subject is the party being authenticated and not always a person.** In a
browser flow it is whoever signed in; in a `client_credentials` grant there is
nobody there and it is the CLIENT. That is the case `common/roles.js` exists to
be able to answer, and it is why an application is a first-class member of a
role.

**The application is the resource and also, often, the subject's employer.** A
client asking for a token for itself appears in both categories, which is not a
confusion: as a resource it is the thing being reached, as a subject it is the
party whose roles are read. A policy may name either.

### The policy is BUILT IN, called rather than seeded

The `role-issuance` template answers by being CALLED. It is not written into
`ou=policies` at startup, and that is a correction rather than a preference:
`ou=policies` is per realm, so a seed written once in the default realm left
every later realm unable to use roles at all. A repository entry named by
`xacml.issuancePolicy` overrides it, so an administrator who wants to see and
edit the document still can.

**ONE COPY EVERYWHERE, OVERRIDDEN PER REALM — rcbj's decision (2026-09-19).**
Asked whether the two service policies (`role-issuance`, and `access-control`
over the console, `/admin-api` and the portal) should instead be SEEDED as a
stored copy into every realm's `ou=policies`, the answer was no: one built-in
document, identical in every realm, and a realm that wants something else
writes an override into its OWN `ou=policies`, which reaches that realm and no
other. `tests/xacml_service_own.js` section 5 holds both directions — a
realm's override does not reach the default realm, the default realm's does
not reach the realm, and deleting either brings the same built-in back.

### The two ways it can fail get OPPOSITE answers

This is the part to read before changing anything in that file.

**A missing or broken issuance policy fails OPEN for an application that
requires only `EVERYBODY`, and CLOSED for one that requires anything else.**

An application that names no required role is the default state of every
application here. It requires `EVERYBODY`, everybody holds `EVERYBODY`, and the
only answer the policy could give is Permit — so a missing policy costs it
nothing, and refusing it would mean a service whose issuance policy was deleted
stops issuing ANYTHING to ANYBODY, including the session an administrator needs
to put the policy back. That is not a security posture, it is a locked room with
the key inside.

An application whose entry names `staff` is a different sentence entirely:
somebody deliberately asked for a restriction, and answering Permit because the
document implementing it is missing would be the one failure this feature must
not have — a configured refusal silently not happening. So that one is refused,
and the refusal NAMES the policy and the template that rebuilds it.

**An error is not a decision.** A throw out of the engine is a defect, and
`issuance_gate.js` answers a throw by allowing, for the locked-room reason. A
Deny, a NotApplicable and an Indeterminate are not throws — they are answers,
and every one of them refuses here, because the policy is `deny-unless-permit`
and an issuance decision must not rest on a PEP's bias. **`xacml.pepBias` is
deliberately not read here**: that setting belongs to the demo PEP at
`/xacml/protected`, which exists to SHOW what bias does, and this one is
enforcing.

### It fills `admin.js`'s `setRolePreviewer()` slot

`setRolePreviewer()`, carrying TWO functions — the preview, and the thing that
says WHICH POLICY answered. Validated together for `setLogoutReader()`'s reason:
a preview installed without the explanation would be a page able to ask a
question and unable to explain the answer.

Rule 3e's test answers yes both ways round. A require from `admin.js` (18) to
this module would load the engine there and — much worse — fill the issuance
decider FROM THE CONSOLE, so a process that loaded the console and not
`xacml/xacml.ts` would gate every issuance in the service with half this family
present. A require the other way closes a cycle, because `xacml_admin.ts`
requires `admin.js` for the page shell.

## THE FOURTEENTH DEFECT: TWO CONTAINERS CLAIMING A PAGE THAT WAS NEVER WRITTEN

`xacml_store.ts` and `xacml_pep_registry.ts` each carry a `SCHEMA` whose comment
says it is "Published on `/admin/ldap/*` the way every other container's is".
Neither was. The export was dead in the first since phase two and in the second
since phase five, and `common/roles.js` copied the same comment on 2026-09-05
and made three.

The pages exist now — `/admin/ldap/policies` and `/admin/ldap/peps`, drawn by
`ldap/ldap_server.js` beside the other six, because that module already requires
both of these to fill their `setDirectory()` slots and therefore already holds
both schemas. No new require, no cycle, no route moved.

**What writing them exposed is the reason a dead export is worth chasing.** The
store lower-cases every attribute name (`@ldapjs/attribute` does), and
`ldap_server.js` un-lower-cases it through `learnName()` from a table each
owning module contributes to — a merge `applications.js` has had for months and
neither of these had. So the first draft of the policies page showed every
policy's kind as `(unstated)` and, worse, **drew a DISABLED policy as enabled**,
because a missing `xacmlEnabled` is not the string `FALSE`. Both are fixed by
merging the schemas rather than by reading case-insensitively at each site: a
lookup that silently misses answers something plausible, and these three pages
are not the only readers of these entries.

The booleans are `TRUE` and `FALSE` — RFC 4517's Boolean syntax, which is upper
case, and what both of these modules write. A page comparing against `'false'`
is a page that overstates what is switched on.

## THE FIFTEENTH AND SIXTEENTH DEFECTS: THE TWO POLICIES THAT DECIDE HERE WERE INVISIBLE, AND ONE OF THEM COULD NOT BE OVERRIDDEN AT ALL (2026-09-06)

rcbj asked a question rather than reporting a bug: *are the XACML policies
created for the various resources this service advertises visible in the editor
page as existing policies?* The answer was **no**, and finding out why turned up
a second defect underneath the first.

### The fifteenth: the console described the repository and called it the policies

`/admin/xacml/editor`'s chooser is `editorJson()` → `store.all()` →
`directory.allPolicies()`, so it lists `ou=policies` and nothing else. On an
ordinary service that is exactly one row — `seeded-rbac`, drawn **(root)** — and
it is *the one document on that page that decides nothing this service
enforces*. The two that do are `role-issuance` (all nine issuance sites) and
`access-control` (the console, the management API, the User Portal, SCIM and the
SPIRE Server API), and both are BUILT IN: the template is called at decision
time rather than seeded, for the reason `xacml_role_pep.ts` argues at length —
`ou=policies` is per realm, so a policy seeded once into the default realm
leaves every realm created afterwards unable to decide anything, and falling
back to the default realm's copy would couple two realms.

**THE FIX IS TO SAY SO AND NOT TO SEED THEM**, because seeding is the thing that
argument rules out. `serviceOwnPolicies()` in `xacml_admin.ts` reports both:

* a section under the repository table on `/admin/xacml/policies` — under it
  because the order is the argument, a reader sees the stored policies and is
  then told which two are deciding and are not among them. Above it, it reads as
  a preamble to scroll past; folded, it is the fact that was already invisible,
  hidden once more;
* a line under the editor's chooser, and in the **empty-repository branch**
  especially — that branch used to say "there is nothing to edit" on a service
  whose issuance and access decisions were both being made every request;
* `serviceOwn` on `GET /admin-api/xacml/policies` and `/admin-api/xacml/editor`,
  so a caller is not left believing `policies` is the whole answer either;
* a **Create an override** button, prefilled with the name the setting already
  names — so what it makes is an entry the PEP will pick up rather than one
  named after the template and silently ignored. It posts `create-from-template`
  like the template forms below it: **moving a form is not moving an action**, so
  no second operation on `/admin-api`.

**THE STATE COMES FROM THE FUNCTIONS THE PEPs THEMSELVES CALL.**
`issuancePolicyState()` and `accessPolicyState()` are thin wrappers over
`issuancePolicy()` / `accessPolicy()`. A page that worked out for itself which
document was in force would be a second answer to that question, and it would be
the one that is wrong the moment somebody disables an override.

**`entry` AND `builtIn` ARE TWO FACTS AND MUST COME FROM TWO PLACES.** *Nobody
has written an override* and *somebody wrote one and disabled it* are opposite
situations that `builtIn` alone cannot tell apart. `entry`/`enabled` are facts
about the DIRECTORY and come from `store.read()`; `builtIn` is a fact about the
DECISION. The first draft of `accessPolicyState()` read the entry through
`store.repository()` — the resolver facade, which holds only ENABLED policies —
and so reported `entry: false` for a disabled override, which is the very
confusion the function was added to remove, restated one level down.

### The sixteenth: `xacml.accessPolicy` had never once been honoured

Found by the test written for the fifteenth. `accessPolicy()` read:

```js
const repository = store.repository();
const found = repository && typeof repository.get === 'function'
  ? repository.get(name) : null;
```

`store.repository()` returns a **plain object keyed by PolicyId**. It has no
`get` method, so `typeof repository.get === 'function'` was false on every call:
what looked like a defensive guard *was the whole condition*, `found` was always
null, and the built-in document always answered. **A documented setting, offered
on the console, that did nothing.** Two more mistakes were hiding under it and
would each have been enough on their own — the name is an ENTRY name and that
map is keyed by PolicyId, and a value in it is a parsed policy rather than a row
with an `enabled` flag.

It reads the entry the way `issuancePolicy()` does now, which is the function
this one's own header had always claimed to follow.

**AND THE DISABLED CASE CHANGED WITH IT, which is a change rather than a fix.**
It used to fall back to the built-in document — so the console's Disable button
meant *evaluate something else instead*, which is exactly what
`issuancePolicy()` refuses to do and calls a lie. The divergence was invisible
because the branch was unreachable. Disabling the access policy now means what
the button says: this layer stops deciding.

**WHAT STILL DIFFERS IS THE CONSEQUENCE, AND THAT IS DELIBERATE.** A disabled
issuance policy REFUSES a narrowed application; a disabled access policy ALLOWS
every gated surface, because `decide()` here allows when no policy is loaded —
refusing would close the console that is the only place to fix it. Two different
answers to *what does not deciding mean here*, from one answer to *is it
deciding*.

### What the lookup bug generalises to

**A GUARD THAT IS ALWAYS FALSE IS INDISTINGUISHABLE FROM A FEATURE THAT IS
SWITCHED OFF**, and neither shows up in a log. `typeof x.get === 'function'` on
a plain object reads as caution and behaves as `return null`. The thing that
found it was not a review: it was a test that created the override and asserted
the state FLIPPED — an assertion about a transition rather than about a value,
which is the only shape that catches a condition nothing ever satisfies.

`tests/xacml_service_own.js` pins all four states and was mutation-tested
against both spellings of the bug.

---

## `/admin/xacml/monitor`: THE ONLY PAGE HERE ABOUT TRAFFIC (2026-09-06)

Every other page in this directory is about CONFIGURATION — what policies
exist, what one of them says, what the PDP would decide about a subject you
type in. None of them answered the question somebody has when authorization is
misbehaving: *how many decisions are being made, by whom, and how many are
refusals*.

Two sections. **Global** — policies, enforcement points, decisions, allows,
declines. **Per enforcement point** — every PEP, embedded and remote, in one
table.

**IT IS FILED UNDER `Monitoring` IN THE CONSOLE AND NOT UNDER Protocols >
XACML, and that is the paragraph above read as a placement.** The five pages
this directory registers under `/admin/xacml` are configuration and sit in the
XACML group; this one answers *what has this service done*, which is the
Monitoring section's own heading, and it is labelled `XACML decisions` there
because `Monitor` alone would name the section rather than the subject. **The
PATH did not move**: it is `/admin/xacml/monitor` still, drawn by
`xacml_admin.ts` still, because a console page is a `path` and a `label` in
`admin-ui/admin.ts`'s `SECTIONS` whoever builds the body — the arrangement the
eight `/admin/ldap/*` pages have with the Directory section and
`/admin/sts-metadata` has had since 2026-08-24. Two consequences for this
route: its `active` is its own path, so the crumb's label comes from `NAV`; and
it passes NO `up`, because it is a page of a section rather than a drill-down
of `/admin/xacml`. **The rule to take from it is that where a page is FILED is
decided by the question it answers**, never by the module that draws it or the
path space it sits in.

`xacml_monitor.ts` is the counters and `xacml_admin.ts` draws them. Four things
about it are decisions rather than details, and the first two are the reason
the page is not one number.

### Nothing counts in `xacml_pdp.js`, and nothing ever may

That file is a DOM-free library with no I/O — the claim `xacml-pep/`'s
thirty-line `helpers.js` shim exists to CHECK — and a counter in the evaluator
would also count in the wrong process the moment the remote PEP loaded its
build-time copy of it. So the counting is at the PEPs, in each one's existing
`allowed()`/`refused()` funnel: two lines per module, and a return path added
later is counted BY CONSTRUCTION rather than by whoever adds it remembering.

`xacml_monitor.ts` is a LEAF (rule 3) and **may not require `admin.js`**, which
is the constraint that decides where the page lives. `xacml_access_pep.ts` fills
`common/access_gate.ts`'s decider and is reached from `common/`, far above
`admin-ui/admin.ts` at 18 — so a console require here would have dragged every
console route into the router at that position (rule 1). Since #50's R1 the
console registers nothing when required, but it still loads the JavaScript
`tls/tls_server` on the way (through `admin-core/admin_views.ts`), whose routes
WOULD move, and it would run the console's load-time code far too early. The
symptom would not be an error: it would be `/admin/sts-metadata` reporting a
different route order.

### A DECISION IS NOT AN ENFORCEMENT, and both are counted

XACML has four decisions and a PEP has two outcomes. What maps between them is
the PEP's BIAS — so a deny-biased PEP refuses a NotApplicable that a
permit-biased one allows, from one identical decision — and **an obligation the
PEP cannot discharge turns a Permit into a refusal** (section 7.2), which is the
one enforcement outcome that looks like a bug from the client side and is the
specification working.

So `allowed` is not `permit`, and a page showing either alone would be wrong for
whichever question the reader had. Both are drawn, with the four decisions
broken out on every row that has them.

### THE FOUR FIGURES HAVE TO RECONCILE, AND THE FIRST DRAFT DID NOT

`allowed + refused` is less than `decisions` on any service that has answered
`POST /xacml/pdp`: those decisions were enforced by somebody else's PEP in
somebody else's process, so counting them either way would report an
enforcement this service was not present for. On that row `allowed` and
`refused` are **null rather than 0** — a zero reads as "it refused nothing".

The gap was real and unexplained until the page was driven with traffic on it,
where it read as an arithmetic error. **A total that does not add up is what
makes somebody distrust every other number beside it**, so the gap is now
COUNTED, as `unenforced`, and drawn as its own column:
`allowed + refused + unenforced == decisions`, on every row.

**The error path then broke the same rule and a test caught it.** `record()`
incremented `decisions` and THEN read the outcome, so a caller whose object
threw on a property access — a getter, a Proxy, a half-built object — left the
row with a decision counted, no bucket and no enforcement, permanently one
short with nothing to say why. Everything is read before anything is written
now: a throw records NOTHING, because half a count is worse than none — it is
indistinguishable from a real decision.

### What is on the page is every PEP this service KNOWS ABOUT

Which is a smaller claim than every one that exists, and the page says so.

* **An embedded PEP is not "registered" and cannot be.** It is compiled into
  this process, so its existence is a fact about the build. There are exactly
  three — the demonstration PEP at `/xacml/protected`, the issuance PEP and the
  access PEP — and they are the catalogue in `xacml_monitor.ts`. A fifth asker
  added without a row there would be decisions nobody could see.
* **A remote PEP registers because it has no other way to be known about**, and
  even that is not a permission: an unregistered PEP pulls
  `/xacml/pep/policies` and enforces perfectly and appears here nowhere.
* **`POST /xacml/pdp` is on the table and is NOT a PEP.** It earns its place
  because a reader counting decisions has to see all of them; it is marked as an
  endpoint with an empty enforcement cell.

**ONE TABLE FOR BOTH KINDS rather than two.** Embedded and remote PEPs differ in
where they run and in how this service learns their figures; they do not differ
in what a reader wants from the row. Two tables would have been two renderers
that could drift, and a reader comparing one against the other would have had to
do it across a page break.

It keeps two things apart that a single number would lose: **a decision is not
an enforcement** (four decisions, two outcomes, and the PEP's bias in between),
and **what this service SAW is not what it was TOLD** (a remote PEP's counts are
reported by it and go down when it restarts).

### The two counting sites that were nearly wrong

**`enforce()` looks like the obvious funnel for the demonstration PEP and is
not.** `/admin/xacml/decide` calls it too, to show what the embedded PEP WOULD
do with a decision somebody just asked about — a what-if, not a request anybody
guarded. Counting there would put the console's own experiments into the figure
an operator reads to find out how much traffic authorization is seeing, and the
number would grow every time somebody looked at the page. The count is at
`/xacml/protected`, the one place a real request is enforced.

**Drawing the monitor page itself DOES add one to the access PEP's count, and
that is right.** `/admin` is one of the five gated surfaces, so reading it is a
real request the access policy really decided; the number would be wrong if it
did not move. The two cases are worth telling apart and the page does it: one is
an access that happened, the other is a question somebody typed.

### A DRY RUN IS A QUESTION ABOUT A DECISION AND NOT ONE (2026-09-06)

`preview: true` on an issuance request means NOTHING IS BEING ISSUED — somebody
is looking at a page that says what would happen. `xacml_role_pep.ts` then
writes no `xacml.issuance.refused` audit row and moves no counter here. **The
decision itself is identical**: same policy, same PIP, same request, same
answer, which is what keeps a preview worth having at all.

Two callers set it. `/admin/roles`'s "would alice be issued a token" button,
which had been writing those rows and moving these counters since it was
written — **so this is a fix rather than a new feature**, and the shape of the
old defect is the shape this page exists to prevent: a number an operator reads
to find out how much traffic authorization is seeing, growing every time
somebody looks at a console page. It is the same argument `enforce()` makes two
sections up, arriving from the other direction.

The second is the User Portal's `/portal/applications`, which asks this
question once per application every time somebody opens it: a person with two
permitted applications out of forty would have written thirty-eight refusal
rows into a 5,000-event ring per page load.

The flag is held in a module variable rather than threaded through the eleven
return sites, and it is SAVED AND RESTORED rather than merely set. `decide()`
is synchronous end to end — `issuance_gate.js`'s header says why it must stay
so — and the save/restore makes that a property of this code rather than of an
assumption about its callers. `issuance_gate.js` needed no change: it passes
the request through untouched.

### There is no reset, and its absence is a decision

A console that could zero its own monitoring would make every number on the page
a number somebody might have zeroed — and the durable record of a refusal is the
AUDIT LOG, which cannot be reset either. The counters are in memory, per trust
realm (like `ou=policies` itself), and start with the process; the page prints
the timestamp, because a count with no epoch is a count somebody will misread.

### Several processes or nodes: every decision is journalled (2026-09-15, #46)

Where minted state is persisted, `counters` is a `merge: 'own'` store — each
process writes its own row and `merge()` adds the other processes' rows in. **It
was journalled only when a process's row was CREATED**: `record()` changed the
object `rowFor()` handed back, in place, and a `realms.map()` hears only
`set()` and `delete()`. So `sts_minted` held each process's first decision and
nothing after, and each node's page added its own live tally to the OTHER
node's frozen row. The suite's `cluster` mode caught it in
`sts_portal_sessions`: the issuance PEP read 126 on node A and 142 on node B
around one page load that decided nothing — and 21 then 17 in a run of that job
alone, a number going DOWN that no late-arriving decision can explain. One
process never reads its own row, so `postgres` mode could not see it.
`record()` now sets the row back; `oauth2_monitor.js` always had.

**The store is declared `observation: true`**, because the access PEP decides on
every console, portal and `/admin-api` request, and a journalled row would
otherwise make each of those reads a writing request the cluster barrier holds
for a commit — which rcbj's decision 6 refuses (`cluster/CLAUDE.md`, *What the
barrier cost*). A request that wrote anything else is held and its tally rides
that commit; one whose only row is a tally is answered at once, and its row
reaches the other node within one flush. `tests/cluster_observation_counters.js`
sections 1-3.

### THE SEVENTEENTH DEFECT: the access PEP refused things and audited nothing

Found while writing the page's "where a refusal is explained" note, which named
`xacml.access.refused` — an audit action that did not exist. `xacml_role_pep.ts`
has audited its refusals since it was written; `xacml_access_pep.ts` logged at
`info` level and recorded nothing, so a refusal at a gated surface was findable
in a log file and nowhere in `/admin/audit`.

It became worth fixing rather than worth noting the moment this page began
COUNTING those refusals: **a page that says how many and points at a log for the
reason has to be pointing at a log that has them.** The refusal is audited now,
in the one `return refused(...)` at the end of `decide()`, and only the refusals
— a permit there is every request to every gated surface in the service, which
would push everything else out of a 5,000-event ring within minutes.

Beside it, `xacml.issuance.refused` had never been in `audit.js`'s `ACTIONS`
table, so every one of them landed in the `protocol` category — findable by name
and invisible to anybody filtering the audit log for AUTHORIZATION, which is the
one filter somebody investigating a refusal reaches for. Both are registered now.
