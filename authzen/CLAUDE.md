# authzen/ — AuthZEN Authorization API 1.0 over the XACML engine

**An adapter, and nothing else** (#563). AuthZEN Authorization API 1.0 (Final,
2026-01-11) lets a Policy Enforcement Point ask a Policy Decision Point one
question per access — subject, action, resource, context in; `decision` out.
This directory reads that question, maps it onto an XACML request through THE
builder (`xacml/xacml_request.js`, rule 3br), decides it with the XACML
surface's own `decide()` against the realm's ROOT policy — or, since #564,
against the application's own fine-grained policy when it enforces one (*What
is decided*, below) — and maps the answer back. **No decision logic lives
here**: what is permitted is the policy's, and policies tell an AuthZEN
question apart by the trusted `urn:sts:xacml:protocol = authzen`.

**IT IS THE OTHER MODEL FROM THE REMOTE PEP, AND IT CHANGES NOTHING THERE.**
`xacml-pep/` PULLS the repository and decides locally (`xacml/CLAUDE.md`,
phase five); an AuthZEN PEP asks per request. So AuthZEN is additive: `GET
/xacml`, `POST /xacml/pdp`, `GET /xacml/policies`, `/xacml/pep/*` and `POST
/xacml/pip` keep their paths, bodies, statuses, authentication, roles,
settings and codes (rcbj on #563, 2026-10-29). The two interfaces share the
engine and the repository and nothing else.

rcbj's design is the comment of 2026-10-29 on #563; the phases are #1160
(this contract), #1161 (single evaluation), #1162 (console and API), #1163
(metadata), #1164 (batch), #1165 (protocol tests). **The remote PEP
container answers AuthZEN too since #1179**, as an edge PDP — *The edge PDP*
below. Search (#1175), the Obligations Profile (#1177), Access Request and
Approval (#1180, *Access requests* below) and the token-exchange binding
(#1181, direction A — *The token-exchange binding* below; #1200, direction B
— *Asking an external PDP* below) are tickets of their own, and each is
advertised only while it is on.

| File | What it is |
|---|---|
| `authzen_catalogue.ts` | The per-realm ATTRIBUTE CATALOGUE's grammar: a row (object, property or dotted path → attribute id, category, datatype, `single` or `bag`), its defaults, its reserved identifiers, and the reading of an entry's rows. **Pure.** |
| `authzen_map.ts` | One access evaluation read against the catalogue and refused where it cannot be represented, the XACML request built, and the decision mapped back fail-closed. **Pure.** |
| `authzen_caller.ts` | Who is asking (the realm's door), whether they may (AUTHZEN_PEPS on resource `authzen-api`), and about which application — and, asked ahead of any request, the callers a remote PEP's edge PDP admits (`edgeCallers()`, #1189). |
| `authzen.ts` | The routes, registered at 23c-ii (`common/protocol_stack.ts`): `POST /access/v1/evaluation`, `POST /access/v1/evaluations`, and the metadata. Thin, as `xacml/xacml.ts` is. |
| `authzen_exchange.ts` | The OAuth 2.0 Token Exchange Binding, direction A (#1181): which tuples are its gates and scopes, the FIXED conversion rules, and each tuple's answer from the questions a local RFC 8693 exchange asks. Built by `authzen.ts`'s `defaultDeps()` beside the caller and the search. |
| `authzen_external_pdp.ts` | Direction B (#1200): this authorization server asks an external PDP before it issues an OAuth access token for an RFC 8693 exchange. A library, no route. `oauth2.ts`'s token grant requires it only while `authzen.externalPdp` is on, and only on the branch that mints an access token. |
| `authzen_access_request.ts` | The Access Request and Approval Profile and its CALLBACK companion (#1180): the requestable denial, its `binding_token` and `binding_hash`, the denial record an `evaluation_id` resolves, `approval.state`, the submission, the per-realm task store and its index, the status and cancellation, `decide()` (the one door the portal and the console reach), the approval's verification at re-evaluation, the mail, the callback and the `authzen.access-requests` job. A library; `authzen.ts` registers its four routes, the submission schema among them. |
| `authzen_model.ts` | **The AuthZEN model, as the endpoints read it (#1579).** Builds every request's shape pass from `models/generated/authzen.json`, answers the lists the code branches on, and holds every answer to its member set. A leaf. See *THE REQUEST SHAPES ARE THE MODEL'S*, below. |
| `authzen_admin.ts` | What the AuthZEN tab of `/admin/xacml` shows and does: `view()` and `act()` (`set-attribute`, `remove-attribute`, `set-scope`), shared by the console and `mgmt-api/authzen_api.ts`'s `/admin-api/xacml/authzen` operations (rule 7). A library, built by the root beside the other API modules. |

`tests/authzen_map.js` holds the two pure modules in process;
`tests/authzen_evaluation.js` drives the route over real handshakes in a child
process, in a throwaway realm whose root policy it wrote;
`tests/authzen_admin.js` holds the tab's view and acts.
`tests/authzen_evaluation.js` K and P hold the two pulls the edge PDP
makes, the catalogue and the callers. `tests/fga_authzen.js` holds an
evaluation decided by an application's own fine-grained policy (#564).
`tests/protocol/sts_authzen.js` (`local: true`, #1165) asks a running service
the same questions over HTTP in a throwaway realm, and carries the **AuthZEN
interop "Todo" scenario** — its five people, five actions and owner rule
written in ALFA as the realm's root policy — through mutual TLS, the default
door. The bearer door is held in process by `tests/authzen_evaluation.js`,
and over HTTP only by the conformance job below, which registers its own
`client_credentials` client in a realm of its own.

**THE OPENID FOUNDATION'S AUTHZEN PDP PLANS RUN AT `api_key` (#936, rcbj's
decision of 2026-11-13).** `tests/protocol/sts_authzen_conformance.js`
(`conformance: true`, lane `conformance-b`) runs the six plans with the suite
as the PEP, in a throwaway realm with `authzen.callerAuthentication`
`bearer`; the suite's API key (`pdp.api_key`, sent as `Authorization:
Bearer`) is a `client_credentials` token carrying `authzen:evaluate`,
audienced to the realm's `/access/v1`, its client in `authzen-peps` and
holding a delegated permission grant of the scope on `sts-authzen-api`
(`POST /admin-api/permissions/grant-permission`; listing it in
`oauthAllowedScope` is refused `STS-OAUTH-0577`, which was the job's first
run). **The
service's default door stays `mtls`**; nothing here changed it. Two things
about suite release-v5.3.1 decide the variants, both read in its source:

* **`mtls` never reaches the PDP**: `SupportMTLSEndpointAliases` requires an
  environment object `server` that `configure()` maps only afterwards. The
  job keeps those plans as `mtls-*`, run only when `CONFORMANCE_PLANS` names
  them.
* **`api_key` needs `pdp_server_metadata=static`**: discovery replaces the
  `pdp` object, and the key with it, by the fetched document. The job copies
  the realm's metadata endpoints into the static configuration;
  `sts_authzen.js` holds the metadata and `signed_metadata`.

**What the plans found, fixed rather than ledgered**: the
`*-unknown-*-fields-ignored` modules, and the Action Search's
`extra-action-ignored`, expect 200 under section 10.1.1 ("receivers MUST
ignore unknown fields"), and this API refused such a member with `0009`.
rcbj decided to follow the specification (2026-11-13): *Unknown members are
IGNORED*, below. **And two more (2026-11-14)**: every plan's
`*-reject-non-json-content-type` expects 400 or 415 for `text/plain`, and
this API read any body as JSON (`app.js`'s text parser takes every type):
section 10.1's "Requests MUST include a `Content-Type` header with the
value `application/json`" is now held, 415 `0117` (`notJson()`, after the
caller is admitted, before the body is read; a parameter is allowed, an
absent header is refused). **The same rule holds in the two places it was
missing (2026-11-20, #936)**:
- the Access Request profile's submission (`POST /access/v1/access-requests`)
  answers 415 `0122` as problem+json, titled *Unsupported media type*. The
  status and the cancellation read no JSON body and are not held to it;
- the remote PEP's edge PDP (`rust/bins/xacml-pep/src/authzen.rs`,
  `is_json_type()`) answers 415 `0117` at its evaluation and batch, at the
  same point.

And the Resource Search of type `record` found
nothing, since this service has no records: a type with no objects here
now takes the policy's `resource-id` literals as its candidates (*The
searches*). **One module is LEDGERED, not fixed**: the batch's
`default-value-merging` expects an item's `resource: { id, properties }`
to take `type` from the top-level `resource`, a member-by-member merge;
section 7.1.1 says "Any of these keys specified within an individual
evaluation object overrides the corresponding top-level default", the key
being `resource` whole, which is this API's reading (*The batch*), so the
item has no `type` and is its own 400. The job's own fixture
(`CERT_POLICY`) is the suite's: rule 2 (alice reads record-2), and rule 6's
admin and archived record known to the PDP as bob and record-2, because the
searches send neither property.

## The mapping, in one table

**The public statement of the conversion, and the guidelines for a realm's
conversion rules and the policies that read them, is `docs/v1.2.0/authzen.md`**
(#1182). This file is why the code is the way it is; that page is what a
policy author relies on, and `tests/authzen_map.js` X holds its worked
example (the ALFA policy and the request) to the code.

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
| *(trusted, FGA only)* | resource, environment | `urn:sts:xacml:fga:application`, `urn:sts:xacml:fga:stage` = `access` — only when the application's own policy decides (#564), written by the builder's `fgaAccess()` |

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

**THE RULES, AND THE RESERVED IDENTIFIERS ABOVE, ARE SHARED SINCE #564**:
both live in `xacml/xacml_attribute_rows.ts`, because an access type's `xacml`
rows (fine-grained authorization, `xacml/fga_map.ts`, `xacml/CLAUDE.md` rule
3cy) map a detail's members onto XACML the same way and must be refused for
the same reasons. `authzen_catalogue.ts`'s `reservedProblem()` calls that
one; `authzen_map.ts`'s walk is the shared walk, which answers a problem by
KIND, and this directory maps each kind to the code it always had
(`0004`–`0008`). What stays here is AuthZEN's: the object, its default
category, `context.application`, the request's shape and the codes.
`tests/fga_map.js` S holds the two refusing by one function.

**Unknown members are IGNORED, at every depth (#936, rcbj's decision of
2026-11-13).** AuthZEN 1.0 section 10.1.1: "receivers MUST ignore unknown
fields present in request or response bodies". So a member no field of the
model names, at the top, in `subject`, `action`, `resource`, `page` or
`options`, on every `/access/v1` request (the evaluation, the batch, the
three searches and the access request submission), is accepted and never
read, and the Action Search's `action`, which section 8.6.1 does not list,
is declared `ignored`. **What it does not loosen**: a member that IS
defined keeps every check (its type, its presence, its values); a property
under `properties` or a member of `context` is still read against the
catalogue and refused when no row declares it (`0004`), because there the
caller is naming an attribute for the policy, which section 10.1.1 does not
speak to; and BULK's `items` on a submission is still refused (`0071`), a
member a profile defines and this service does not implement. **It is this
API's rule alone**: every other API this service serves still refuses a
member it does not declare. Until #936 this API refused one with `0009`, on
the argument that dropping it might decide a question the caller did not
ask; the specification decides otherwise, and `0009` is retired. The edge
PDP (`rust/bins/xacml-pep`) ignores them too, held by
`xacml-pep/authzen_cases.json` R9, R10 and R12.

## The result (decision 8)

Fail-closed: `true` only on a Permit carrying nothing this PDP cannot
discharge, which is `xacml.ts`'s `enforce()` deny-biased — the console's
what-if and the remote PEP apply the same rule. Deny, NotApplicable and an
Indeterminate over a missing attribute are an ordinary `false`. **An
Indeterminate over a FAULT** (`STS-XACML-0012`, a root policy that will not
load; `STS-XACML-0013`, a processing or syntax error) **is an error, never a
denial**: a PEP told `false` about a broken policy enforces its bias over
somebody else's outage. A Permit with an obligation is `false` unless
the PEP declared it carries the obligation out (the Obligations Profile,
below). `urn:sts:xacml:obligation:log` is the one discharged here.

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
`appAuthzenApplication` (plus its own identifiers) on an application's. An
mTLS caller is `kind: 'entry'` with the directory DN for both a person and
an application (`byCertificate`); `scopeOf()` reads `appAuthzenApplication`
when that entry has `appIdentifier` (#1202).
Administrator-set: `sts*` is refused by every self-service and provisioning
door, and the attribute is not in the portal's list. `context.application`
must be in the set (403 `0025`), none named and one in the set picks it,
none in the set is `0026`, several and none named `0027`. **`ou=peps` is not
consulted**: registration is not a permission.

**ENABLING FGA ON AN APPLICATION WRITES BOTH FOR THE REALM'S REMOTE PEPS
(#1210, rcbj's decision of 2026-10-30), WHICH DELIBERATELY MAKES THE
REMOTE_PEPS GROUP A SOURCE OF AUTHZEN PERMISSION.** An edge PDP forwards an
enforcing application's evaluations here as an AuthZEN caller (#564 P7), so
`fga_policies.enable()` calls `authzen_admin.ts`'s `grantRemotePeps()`:
each member of `roles.remotePepGroup`, located as `edgeCandidates()` locates
the AuthZEN group's (`locateMembers()`: a person, a service account or an
application by its entry's DN), is added to `roles.authzenPepGroup` if it is
not a member and has the application added to its scope if absent. The rule
above still holds — `ou=peps` is never read, and a registration grants
nothing; what grants is an administrator's act over a group an
administrator filled, written as ordinary state this tab shows and can take
back.

* **Through the ordinary doors**: the membership through `addGroupMember()`
  (the AuthZEN slot gained `addMember`, validated whole with the other
  three; audited `group.add-member`), a person's scope through the same
  `write` `set-scope` uses, an application's through `updateApplication()`.
  One `admin.authzen.pep.granted` row per holder changed; a holder that is
  not is a row carrying STS-FGA-0025.
* **One failing fails nothing else**, and never the enable: a member naming
  no entry, an empty or missing AuthZEN group, a scope at `MAX_SCOPE`, a
  refused write. A holder given the membership whose scope write then failed
  keeps the membership, and its `why` says so.
* **Nothing is ever removed.** Disable leaves both: a value set by hand is
  indistinguishable from one an enable added.
* **Not retroactive, and not periodic.** A holder added later is granted by
  the next enable (the tab's *Grant the remote PEPs again* on an enforcing
  application) or by hand here. Granting on a group change would be a
  directory observer reaching into AuthZEN state on every membership write,
  which nobody asked for.
* **Bounded at `MAX_PEP_GRANT` (200) holders**, the answer's and the tab's
  list; `truncated` says when the group is larger.

`tests/fga_pep_grant.js` holds it in process; `tests/protocol/sts_fga.js`
section 3 asserts it over HTTP.

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
no `capabilities` but the token issuance one, and that only while the
token-exchange binding is on (#1181). **`signed_metadata` since #1178**: the same members, `iss` the PDP
identifier, signed by `oauth2.ts`'s `signPublishedDocument()` under the
`oauth-signed-metadata` use case (the one signer of a published document; so
`oauth2.signedMetadata*` choose its algorithm and certificate header), signed
per fetch from the very object it is served beside, and switched by
`authzen.signedMetadata`. A failure to sign leaves it out (`0040`) rather
than failing the document: the plain members are the metadata.
While the API is off the document answers 501 rather than advertising an
endpoint that does not.

## The Obligations Profile (#1177)

**Handed only to a PEP that declares every type** (rcbj, 2026-10-30). The
profile sends a Permit with obligations as `decision: true` and trusts the PEP
to treat what it cannot carry out as a deny; a PEP that never heard of the
profile would grant instead. So `context.supported_obligations` — reserved
in the catalogue as `context.application` is — is the declaration, and
`outcome()` hands the converted obligations only when it names every type the
answer carries. Otherwise the old rule stands: a Permit carrying anything but
the log obligation is `false` (`0029`).

* **The conversion is one rule** (`obligationsOf()`):
  `urn:sts:xacml:authzen:obligation:<type>` is the registered type
  (`step-up`, `notification`, `session_termination`), anything else but
  `urn:sts:xacml:obligation:log` is `custom` with its XACML id kept, and an
  assignment is a property named by its attribute id's last segment, an
  array where the type says so. A registered type without a property it
  requires hands nothing and the Permit is `false` (`0041`).
* **A denial's obligations are handed too**, beside `false` (the profile's
  section 2), under the same declaration.
* `authzen.obligationsProfile` off is the pre-#1177 behaviour, and the
  metadata then leaves out `supported_obligations`.
* **Not implemented:** the profile's per-result obligations in search
  responses (its section 4.3), until search exists (#1175).

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

## The searches (#1175)

**XACML has no reverse query, so a search is a loop of evaluations**
(`authzen_search.ts`): the candidates this service can NAME for the
searched kind, each decided by `decideEvaluation()` — the one place a
question meets the policy, shared with the evaluation and the batch — and
the permitted ones answered. A result is therefore a real Permit, section
8.1's SHOULD kept as a MUST; search is not transitive.

**Candidates are this service's own objects** (rcbj, 2026-10-30: start with
the application directory — applications, APIs, the delegation relationships
between them): directory people for a resolved subject type; `application`,
`api` (resource-server kinds) and `delegation`
(`appAllowedToDelegateTo`, as `<source>|<target>`) resources; and as
actions, every literal the repository's policies compare action-id with
(a static walk of the model) plus an application's own `oauthPermission`
names. **A resource type that is none of the three takes the same walk over
`resource-id`** (#936, `policyLiterals()`): until then it answered nothing
whatever the policy permitted, which section 8.5's "all of the resources
of that type" does not allow when the PDP can name them, and the
conformance suite's `record` search was that case. A literal is still a
result only where the policy permits it as the searched type. A subject
type with no source answers empty results, never a 400.

* **Bounded, and said so**: `authzen.searchMaxCandidates` caps the decisions;
  past it, or with a candidate the PDP could not decide, `context.incomplete`
  says the answer is partial (`0045`, `0028` on the one audit row per
  search).
* **Paging is offset-based** over the whole permitted list, decided per call
  (bounded above). `next_token` is `<offset>.<fingerprint>`, the fingerprint a
  digest of the request without its token, so a continued request that
  changed an entity or the limit is refused (`0043`) — section 8.2's SHOULD
  kept. Not snapshot-consistent, which section 8.2 allows.
* **`runSearch()` takes its caller and application from its own caller**, so
  the reports application (#1176) searches as the report's owner, with
  application `sts-report` and no scope check (`report/CLAUDE.md`).
* **A search about an application that enforces fine-grained authorization
  (#564) decides every candidate against THAT application's policy**, for
  free: the routing is in `decideEvaluation()`, which every candidate goes
  through. A policy that cannot be used makes the WHOLE search an error
  (`0046`, 500, the `authzen.search` row carrying the STS-FGA code), never
  an empty or `incomplete` answer: every candidate would meet the same
  policy, and an empty result would be the restriction answering "nobody"
  by accident.
* Not implemented: per-result obligations (the Obligations Profile's 4.3).

## The token-exchange binding, direction A (#1181)

**This service is the PDP an external authorization server asks** whether
it may perform an RFC 8693 exchange (rcbj, 2026-10-30, decision 1).
Direction B — this authorization server consulting an external PDP — is
*Asking an external PDP* below (#1200). The
binding's draft and the Token Issuance Profile it builds on are on the
ticket; `docs/v1.2.0/authzen.md` is the public statement, with the fixed-rule
table (`authzen_exchange.ts`'s `FIXED_RULES`, which
`tests/authzen_token_exchange.js` F3 holds to that page).

* **A CONVERSION, AND NOTHING ELSE.** A gate group (one per target and
  token type: the first gate's subject is the exchange subject, a second
  subject the requesting party) becomes the question the token endpoint
  puts to `delegation_policy.decide()` for the same exchange — protocol
  `OAuth 2.0`, no requested semantics, S from `subject_token.aud`, then
  `client_id`, then `azp`, the one target, may_act — so the same entries and
  the same issuance-policy rules decide it (rcbj's hard constraint: one
  delegation configuration; nothing a local RFC 8693, WS-Trust or Kerberos
  delegation decides changes). **The one addition there is the question's
  optional `authzen` member**, which no other door sends and
  `delegation_policy.ts` only carries: `xacml_request.js`'s `exchange()`
  writes the trusted caller and application, the tuples' types, the token
  type, the token types and the act depth — and the catalogue's own rows —
  only when it is present (`tests/authzen_token_exchange.js` L). It is
  decided against the ISSUANCE policy, never the root policy: the exchange
  rules live there.
* **Which gate a refusal falls on** is by its kind (`SUBJECT_REFUSALS`,
  `PARTY_REFUSALS`; anything else, `subject` and `policy` included, both).
  The binding has the AS fail on either and tell the client neither, so the
  split is the audit row's.
* **DEVELOPMENT ANSWERS WHAT THE LOCAL TOKEN ENDPOINT WOULD ISSUE**: a refusal
  the policy does not enforce is `true` with `STS-AUTHZEN-0110` on the row.
  It is the judgment call of the ticket: "the same decision" is read as the
  same outcome at the token endpoint, mode included.
* **Scope tuples** meet the three questions a local exchange's scopes meet
  — the issuance policy's `exchange` stage, `scope_policy.ts`'s `judge()`
  for `context.client_id` (the mint stage, no row), and
  `role_permissions.ts`'s `narrowScope()` with `record: false` (added for
  this: nothing is issued here, so nothing is "taken off a token"). A
  Txn-Token's requesting party's own scope tuples are decided as its.
* **FIXED** (decision 2): the catalogue refuses a row naming any of
  `authzen_catalogue.ts`'s `BINDING_CONTEXT`, or a path under one
  (`STS-AUTHZEN-0011`), in every realm whether or not the binding is on,
  and the edge PDP's port refuses the same (`authzen_cases.json` C15b,
  C15c, V30). A request that is not a binding tuple, or arrives while the
  binding is off, carrying one of them is 400 (`0101`).
* **`context.issuance` only narrows**, on the subject gate only:
  `token_lifetime` (the subject token's remaining life, and the realm's
  access-token lifetime for the client), `granted_scope` for a request
  naming no scope, and nothing else is BUILT: #1201 asks for `audience`
  and `claims` that only narrow and defines no rule that produces one, so
  the review of #1201 (2026-11-23) corrected the documents rather than
  invent one. `shape()` still holds both keys, were one ever built:
  `audience` never leaves on one target: every element equal to this
  gate's resource id
  does not narrow it and is omitted, anything else is logged
  (`STS-AUTHZEN-0132`) and dropped, and an empty array withdraws the
  target (`0134`, the gate false). `claims` keeps a proper subset of a
  string array the subject token already carries, and a smaller
  non-negative integer ceiling; a reserved name (`sub`, `aud`, `act` and
  `may_act` among them), a claim the token does not carry, or a wider
  value is logged (`0133`) and dropped. An equal value is omitted
  without a log. `shape()` is that check; `narrowOnly()` returns only
  the envelope. The answer never writes `sub`, `aud`, `act` or
  `may_act`, and never returns a rewritten `authorization_details`.
* **`authzen.tokenExchange`, off by default**: it takes over two resource
  types (`audience`, `protected_resource`) that a realm may already use for
  its own AuthZEN questions, and it advertises a draft's capability
  (`urn:openid:authzen:capability:token-issuance`). A gate for another
  grant is a decision, `false` (`0103`), which is what that capability
  commits to.
* **The parties are this realm's**: an external AS whose users and clients
  are not registered here gets an unregistered party's answer.
* **NOT ROUTED BY #564, DELIBERATELY, EXCEPT A DETAIL TUPLE.** A gate or
  a scope never reaches `decideEvaluation()`, so an application that
  enforces fine-grained authorization does not move those to that
  application's policy. The rule they hold to is the local exchange's:
  there, an enforcing application's policy is asked only about RFC 9396
  details, and the subject token's details bound the requested ones
  (#564 decision 6, `oauth-oidc/CLAUDE.md`); the gate and the scopes stay
  the issuance policy's. Routing those would make the binding disagree
  with the token endpoint, which is the one thing #1181 must not do.
  **An authorization-detail tuple (#1201) is that per-detail question.**
  `classify()` stays a gate or a scope only; `plan()` marks a tuple
  whose `resource.type` is a declared type, and only while the binding
  is on, and never `audience` or `protected_resource`. With no exchange
  subject in the batch it is an ordinary evaluation again (a binding
  member on it is still `0101`). The exchange subject's cell is decided
  by `detailVerdict()`: a cell naming anybody else, a Txn-Token's
  requesting party included, is false (`0128`) in every mode. The cell
  is the type, one location when the tuple names an id, and an action
  or `action:datatype` split on the last colon; `authorization_detail`
  names neither. An enforcing type is held to `exchangeBoundProblem()`
  against `subject_token.authorization_details` and "issued here"
  (`subject_token.iss` equal to this realm's issuer, not a
  re-verification) before `fineGrainedRefusal()` at stage `exchange`;
  not covered is false (`0129`) and the decider is not asked. A permit
  is true. A deny is false (`0130`). A fault is `STS-AUTHZEN-0046`
  (HTTP 500) with the STS-FGA code on the audit row, and is not counted.
  A type that does not enforce skips the bound and is granted as asked,
  in every mode. `declaredTypes()` throwing while planning is logged
  (`0131`) and no detail is recognized; throwing while answering a cell
  already recognized is the same log and false (`0129`). The answer
  does not carry the cell back.
* **Not built:** the edge PDP answering the binding (its port only
  refuses the catalogue rows). Direction B is *Asking an external PDP*
  below.

## Asking an external PDP (#1200)

**This authorization server asks a PDP an administrator configured**, before
it issues an OAuth access token for an RFC 8693 exchange. It is the other
direction of the same binding. `authzen_external_pdp.ts` builds the batch
and reads the answer. `oauth-oidc/oauth2.ts`'s token grant calls it, lazily,
only while `authzen.externalPdp` is on and only in the branch that mints an
access token. A Kerberos `requested_token_type` is outside the binding and
is not sent.

* **IT SITS BESIDE THE ISSUANCE GATE.** `delegation_policy.decide()` and the
  local scope narrowing have already run. A refusal that policy enforces is
  not sent on. The PDP may only narrow: a false scope drops that scope,
  `granted_scope` is intersected with the scopes the local endpoint would
  already issue, and `token_lifetime` is a ceiling on the access token
  (`lifetimeCapS`, which only shortens). Nothing here writes `sub`, `aud`,
  `act`, `may_act` or a claim. The refresh token, when one is also issued,
  keeps its own lifetime.
* **FAIL CLOSED, IN EVERY MODE.** Development softens the local issuance
  policy. It does not soften this. An unusable URL (`0123`), no answer
  (`0124`: outbound off, unreachable, timeout, non-2xx, a throw), a body
  that is not the batch's decision (`0126`, including an item whose
  `context.error` says the PDP did not decide it), or a client certificate,
  key or named CA file that cannot be read (`0127`) means no token. A
  `decision: false` on a subject or requesting-party gate is `0125`, HTTP
  400, and the client is told neither which gate nor the code. The other
  four are HTTP 503.
* **THE URL IS AN ADMINISTRATOR'S**, the twenty-seventh row of
  `federation/CLAUDE.md`. Absolute https only, no userinfo, query or
  fragment, through `federation_http.requestConfigured`. Mutual TLS is the
  only mode. The PEM paths are settings, read at the dial and held to
  `security.fileRoots` in product. The key's bytes are not a configuration
  value. An empty audience is asked with a resource id of `''`; a PDP that
  requires a non-empty id refuses the token, which is the same fail-closed
  rule (`0126`, because this service's own model answers that shape as an
  item error rather than a policy `false`).
* **Off by default**, so a deployment that never turns it on dials nothing
  and does not load the module on a token exchange. The settings are the
  `AuthZEN` group's, on `/admin/xacml` and `GET /admin-api/config` (rule 7).
  No new route.
* `tests/authzen_external_pdp.js` holds the injected dial and a second realm
  over mutual TLS.

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
  `decide()`; `protocol = authzen` tells the question apart.
* **A REGISTERED UMA 2.0 RESOURCE is decided by UMA (#1196, rcbj
  2026-10-30).** `decideEvaluation()` hands an evaluation whose resource
  type is `uma_resource` to `decideUma()` before anything else: the UMA PEP's
  own `decide()` as a dry run at stage `assess`, the client's grant taken as
  declared (nobody is asking for a token), the subject a person by username
  or subject, the action's name the scope. The application must be the
  resource server the resource is registered with, and the scope one it was
  registered with, or the answer is false. #1168's design point 11 sends a
  resource server here for the CURRENT answer, and until this the root
  decided it, knowing nothing of the owner's document — so an owner's
  revocation changed an RPT and not this answer. The monitor counts it on
  the `authzen` row; the UMA PEP's dry run records nothing of its own.
* **AMENDED 2026-10-30 BY #564's P4 (rcbj's decision 4 on #564): an
  application that ENFORCES fine-grained authorization is decided against
  ITS OWN policy instead.** Once `applicationOf()` has chosen the
  application, `decideEvaluation()` — since #1175 the one place a question
  meets a policy, for an evaluation, a batch item and every search
  candidate — reads `applications.fgaStateOf()` — the
  registry's switch, no XACML needed to ask — and, when it is on, hands the
  request to `xacml/fga_pep.ts`'s `decideAccess()`: the same resolve and the
  same `decidePolicy()` (no PolicyIdReference map) an issuance question
  uses, so the two cannot disagree about which policy is the application's.
  Resource servers reach FGA only here, because FGA is decided only in this
  service (decision 4); the policies are withheld from the pull. **The
  remote PEP's edge PDP (#1179) FORWARDS such an evaluation here** (P7,
  rcbj's decision of 2026-10-30): it arrives as an ordinary evaluation from
  the PEP, and nothing in this branch knows it was forwarded (*The edge
  PDP*, below). An embedded FGA PDP there is still future work this design
  does not rule out. What stays AuthZEN's, and why:
  * **The request** is AuthZEN's mapping unchanged, plus the two facts the
    policy needs to know what it is asked — `urn:sts:xacml:fga:application`
    and `urn:sts:xacml:fga:stage = access` — written by the builder's
    `fgaAccess()` (rule 3br), never by a row (both are in `urn:sts:xacml:`,
    so the catalogue cannot name them). The action is the caller's, not
    `grant-authorization-detail`.
  * **The result rules** are decision 8's: a Permit with nothing
    undischargeable is true; an Indeterminate through a fault is 500
    (`0028`). **A policy that cannot be used is an ERROR, never false and
    never the root instead** (`0046`, 500, a batch item's `context.error`):
    the application enforces, and answering from the root would be the
    restriction silently not applying. The response is marked `0046`; the
    audit row carries the STS-FGA code that says why (0003–0007, 0009, or
    0015 for a throw), and nothing is counted, since no engine decided. A
    registry that cannot be read is the same error rather than "not
    enforced", for the same reason.
  * **The audit row** is the same `authzen.decision`, naming the policy's
    entry, PolicyId and version when it decided — never a value.
  * **The monitor** counts it on `authzen`, once: the rows are per asker,
    and the `fga` row counts what THIS process enforces at issuance;
    counting an AuthZEN answer there would invent an enforcement, and
    counting it on both would count one decision twice.
  * **The scope rule is unchanged**: a caller reaches an application's
    policy only by an application in its scope (`0025`).
  * **The metadata is unchanged**: nothing new is advertised.
  Every application without FGA enforced is decided exactly as before.
  `tests/fga_authzen.js` holds it. `decide()`
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

## The edge PDP in the `xacml-pep` container (#1179)

**The same contract in a second place, which is why the contract is now a
table.** `rust/bins/xacml-pep` ports `authzen_catalogue.ts`
(`authzen_catalogue.rs`), `authzen_map.ts` (`authzen_map.rs`) and the batch
and metadata of `authzen.ts` (`authzen.rs`), and `sts-xacml`'s builder ports
`xacml_request.js`'s `authzen()`. **`xacml-pep/authzen_cases.json` is the one
table both are held to** — catalogue values and requests, the code each is
refused with, and what an accepted one supplies and maps to:
`tests/authzen_map.js` S runs this directory's modules over it and `cargo
test -p xacml-pep` the port. **A change to a rule here owes a case there**,
or the two drift with both suites green.

* **The catalogue reaches it by the pull**: `GET /xacml/pep/authzen-catalogue`
  (`xacml/CLAUDE.md`), beside the policies, with the settings that change the
  mapping or the answer. The container re-reads each row through its port of
  `parse()`, so a reserved row cannot reach a request there either.
* **The codes are shared where the condition is the contract's**: a request
  refused there carries the `STS-AUTHZEN-*` code it carries here, and the
  `501`s for a realm with the API off are `0013` and `0014`. Its own
  conditions — the client CA, the catalogue and caller pulls, admission by
  the pulled list and the local narrowing — are `STS-XPEP-*`.
* **Who may ask is this service's answer, pulled** (#1189, below):
  `GET /xacml/pep/authzen-callers`. What still differs there is mutual TLS
  only, no revocation check of an outside authority, and a log line instead
  of an audit row; `xacml-pep/CLAUDE.md` states each.
* **It FORWARDS an evaluation about an application that enforces
  fine-grained authorization to this service (#564, P7; rcbj's decision of
  2026-10-30, extending decision 4).** An application's policy is withheld
  from `GET /xacml/pep/policies`, so the edge cannot decide it; the
  catalogue pull names the enforcing applications instead
  (`fgaApplications`, inside the catalogue's token so a switch flip is
  pulled — `xacml/CLAUDE.md`), and the edge sends such an evaluation, as one
  single evaluation with `context.application` set, to the realm's `POST
  /access/v1/evaluation` with its own client certificate. **Here it is an
  ordinary evaluation from an ordinary caller — the PEP** — admitted by the
  door and the scope like any other, which is the prerequisite operators
  owe: the PEP's entry holds AUTHZEN_PEPS with the application in its
  `stsAuthzenApplication`. Two consequences of that, accepted rather than
  engineered away: a policy sees the PEP as `urn:sts:xacml:authzen:caller`
  (the caller the edge admitted is the edge's to know; a name it asserted
  would be a fact a policy could not trust), and `supplied` names
  `context.application` though the original caller may not have sent it.
  **Every failure here is an error there, never false** — this branch's
  `0046` included (`xacml-pep/CLAUDE.md` has the status mapping). Until the
  edge's next poll an application just switched on is still decided there
  from the root: the same convergence as the caller list, stated in
  `docs/v1.2.0/remote-pep.md`. An embedded FGA PDP in the edge remains future work;
  forwarding rules it out no more than it did.

### The forward on the PEP's token (#1827's follow-up)

**rcbj's decision 3 on the PEP token plan (2026-11-16): the edge PDP's
forward is accepted on the PEP's DPoP-bound token under EVERY
`authzen.callerAuthentication`, `mtls` included.** It is the same caller on a
different credential, so it is scoped exactly as the certificate-holding
PEP: `authenticate()` asks `xacml/pep_token.ts`'s `isPepToken()` first (a
token this realm issued to `sts-remote-pep`), and `byPepToken()` reads it
for this realm's `/access/v1` and `authzen:evaluate` and answers the caller
as `kind: 'entry'`, the PEP's DN — what its certificate named — so
`mayAsk()`'s AUTHZEN_PEPS and `scopeOf()`'s `stsAuthzenApplication` decide
as before. **It must name a REMOTE_PEPS holder as well** (`0120`): every PEP
shares the client, and the token is not a way for anybody else in
AUTHZEN_PEPS to arrive. `authzen:evaluate` is not role-gated at issuance
(AUTHZEN_PEPS authorizes no permission), so a non-PEP person can be issued
one through `sts-remote-pep` and is refused here; AUTHZEN_PEPS is widened
for nobody. A token of any other client goes through the realm's door as
it always did. A refusal carries a `DPoP` challenge, not the Bearer one.
`tests/remote_pep_token_door.js` Z.

### The callers the edge PDP admits (#1189)

**rcbj's decision on #1189: the edge admits by pulling who this service
admits**, with the cost accepted that anybody holding `REMOTE_PEPS` can read
who may ask the PDP. `authzen_caller.ts`'s `edgeCallers()` is the list, and it
is the three questions of *Who is asking* asked ahead of any request, by the
same functions:

* **WHO**: each certificate through the certificate door's own reading,
  `xacml.ts`'s `certificateCaller()` (`xacml/CLAUDE.md`), so the name sent is
  the DN the door resolves it to — the value `urn:sts:xacml:authzen:caller`
  carries — and the certificate is sent by the SHA-256 of its DER.
* **MAY THEY**: `admission()`, the writeless half of `mayAsk()`, for the path
  of each endpoint the edge serves (the realm's prefix included). The OUTCOME
  is sent, not the membership: a member the policy refuses is counted
  (`notAdmitted`) and left out.
* **WHICH APPLICATION**: `scopeOf()`, as is.

**THE CANDIDATES ARE THE GROUP'S MEMBERS** (`roles.authzenPepGroup`, read
through `authzen_admin.ts`'s `edgeCandidates()` over the tab's directory
slot), and their certificates are what the door accepts: the values of
`userCertificate` on the entry (read with the directory codec's
`certificateDerOf()`, the reading the stored-certificate index keys) and the
TLS client certificates this realm issued them that are valid
(`tls_client_certificates.js`'s `activeFor()`). Two things the service admits
are therefore NOT listed, and the edge is narrower there, never wider: an
entry a policy admits without the role, and a certificate enrolled over ACME,
EST or SCEP that is not stored on the entry. Bounded at 500 members and 64
certificates each; past either the list says `truncated` and the log carries
`STS-AUTHZEN-0061`. A certificate that cannot be read is `STS-AUTHZEN-0062`.

**A REALM WHOSE DOOR IS A TOKEN LISTS NOBODY.** The edge has mutual TLS only,
and `bearer` and `mtls+bearer` admit no certificate alone, so with either the
list is empty and says why.

**REVOCATION IS THE REGISTER'S ONLY.** A certificate the register records as
revoked is left out, so revoking one this realm issued reaches the edge on its
poll; an outside authority's CRL or OCSP answer is never consulted for the
list, and the edge consults none either.

## The Access Request and Approval Profile (#1180)

rcbj's decisions of 2026-10-30 on #1180 are the design; `authzen_access_request.ts`'s
header argues each. What a maintainer needs quickly:

* **A denial is requestable only by the POLICY**: the advice
  `urn:sts:xacml:advice:access-request` on a Deny (assignments under
  `ADVICE_PREFIX`: `approver-role`, `approver-group`, `approver-owners`,
  `max-approval-seconds`, `emergency`, `context-member`, `template`,
  `reason`). No per-application switch; `authzen.accessRequests` turns the
  whole profile off. A NotApplicable carries no advice in XACML, so in
  practice only a Deny is requestable.
* **The denial is bound BY VALUE AND BY REFERENCE.** The
  `binding_token` is signed with `oauth2.ts`'s `signPublishedDocument()`
  (use case `oauth-signed-metadata`, the metadata's signer) over the tuple
  whole less `subject.properties.act`, the advice's context members, the
  caller, the application and the advice's terms, and it always carries
  `binding_hash` (base64url SHA-256 of the RFC 8785 form of that tuple).
  The same denial is a row of `authzen.accessRequestDenials`, keyed by
  `evaluation_id`, so a submission may name it by that id and the echoed
  `expires_at` (`0073` when this realm has no such denial, `0074` when the
  echo or the tuple does not match, `0075` when the recorded window has
  passed). When the token is present it is authoritative. The approval is
  a store row, looked up by a digest of `approval.id`, and `approve()`
  also signs `approval.state`. A presented state is verified, and a bad
  signature is not an approval (`0084`) even when the row would be; a
  state with no row is not an approval either, so revocation stays a
  write.
* **The submission schema is published, and no form is** (#1204). A
  requestable denial's `request_schema_url` is
  `GET /access/v1/access-requests/schema` on the same origin as
  `endpoint`, so a PEP's same-origin check (the profile's section
  11.2) passes. The document is JSON Schema draft 2020-12 of the
  augmentations `requestedAccess()` accepts:
  `context.business_justification`, and
  `requested_access.requested_until` and `emergency`. None is
  required on an ordinary submission, and emergency requires the
  justification. It is public, names no secret, and is not read when
  a submission arrives — the reader stays the enforcer. While the
  API or the profile is off it answers 501. `form_url` is omitted:
  this service hosts no requester-facing form, and a URL that is not
  one would be a lie.
* **AN APPROVAL NEVER PERMITS BY ITSELF.** `verify()` (same caller, same
  application, exact tuple, not revoked, inside `approved_until`) adds
  `urn:sts:xacml:authzen:approval-id`, `:approved-until`, `:approver` to the
  request through `xacml_request.js`'s `authzen()`; the root policy decides.
  **For an application that enforces fine-grained authorization (#564) it
  is that application's policy**: a re-evaluation carrying an approval goes
  through `decideEvaluation()` like any other, so the facts reach the
  policy that decides, and the advice that makes a denial requestable is
  that policy's too. An unusable policy is `0046` before anything is
  requestable — no denial was decided, so there is nothing to request.
  `approval` is reserved in the catalogue's `RESERVED_CONTEXT` so no row can
  forge those facts. The Rust edge PDP does not reserve it (nor
  `supported_obligations`, a drift predating this); its catalogue arrives
  through this `parse()`, so no such row can reach it either.
* **Who may decide is the access-control policy's**: resource
  `authzen-access-request`, action `approve-access-request`, the facts in
  `access_gate.ts`'s `accessRequestObject`. The built-in document's FOURTH
  rule (`xacml_templates.ts`, `permitAccessRequestApproval`,
  `permitAdministratorApproval`, `forbidSelfApproval`) permits the advice's
  approvers and an ADMIN_WRITE caller of `/admin-api`, never one of whose
  names is the subject or the requester; the FIRST rule now excludes that
  resource, or a role it required would bypass the self-approval rule.
  `mayDecide()` needs a real Permit: the gate's allow-when-nothing-decides is
  right for a console and wrong for an approval. **A revocation is asked
  as `revoke-access-request`** (the review of #1203, `mayRevoke()`), which
  the fourth rule's target lists beside `approve-access-request`, so the
  built-in document answers the two alike. A repository policy whose text
  never names the new action predates it and is asked
  `approve-access-request` instead — rcbj's backwards-compatibility rule:
  an existing deployment's own policy decides a revocation as it did.
* **Eligibility is computed, the decision is not**: `eligible()` (role,
  group, application owners) is routing — who is mailed, whose
  `/portal/access-requests` lists it — and a fact the rule reads.
* **The callback** goes only to a URL registered for the caller (the tab's
  `set-callbacks`): an application's `appAuthzenCallbackUri`, or a
  person's or service account's `stsAuthzenCallbackUri`. #1202 had stopped
  honouring the second and refused to write it (`0136`, now retired); no
  decision of rcbj's said so — decision 4 on #1180 is "a callback URL
  registered for the requester" — and a 1.1.0 deployment with person
  callbacks would have broken on upgrade, so the review restored it. A
  per-URL override is an application's only (`0137` for a person). Delivery is
  `federation_http.deliverJson()` under the SENDABLE attribute
  `authzenCallbackEndpoint`, with a 300-second JWT as the Bearer. A network
  error, a timeout or an HTTP 5xx is tried again by this file's
  `authzen.access-requests` job, up to `authzen.callbackAttempts` (the
  first included), the first wait `authzen.callbackBackoffS` and each
  later one doubled, up to a day (`waitAfter()`). One URL may set
  either in `appAuthzenCallbackConfig` (`url attempts=N backoff=S`, stored
  only when at least one override is set). A 4xx or an outbound-policy
  refusal is not tried again (`0137` is the set-callbacks refusal for a
  bad override). Each failed try is `0091`. When the delivery will not
  succeed, `callbackDelivery.state` is `failed` and the give-up is `0135`.
  A delivery's outcome never writes the task's status. The status
  endpoint stays the record (`federation/CLAUDE.md`, the twentieth row).
  Each attempt (time, status, reason, `code`) is on
  `viewOf().callbackDelivery.attempts`, drawn per attempt on the console
  row, and on the portal; not on the public Task Handle. **A write after
  the POST re-reads the row** (`currentOf()`) and writes only the delivery
  record onto it, so a revocation made while the POST was in flight is
  not lost (rcbj's rule, no lost revocations), and a row the sweep removed
  is not brought back.
* **`failed` is a workflow step that cannot complete** (#1202, the
  review): `approve()` writes the approval's index row and then the task;
  either refused moves the task to `failed` (`0142`) instead of an
  `approved` no re-evaluation could find. The job fails a pending task
  whose advice named approvers that resolve, CERTAINLY, to nobody but the
  subject (`0143`): `approverWalk()` is certain only when the directory was
  readable and every role named is a configured static one, since a
  computed or dynamic role's holders cannot be listed. Advice that named no
  approver is never "nobody": an administrator decides it.
* **The store is cell-tier** (`authzen.accessRequests`,
  `authzen.accessRequestIndex`, `authzen.accessRequestDenials`), and
  `/access/v1` is placed `local`: under cells a PEP must poll the cell it
  submitted to.
* **Expiry**: read-time (a pending task past `expiresAt` is finished as
  expired by `task()`) and the `authzen.access-requests` cluster job, realm
  scope, every minute, which also removes rows past `keepUntil` (a day after
  finishing, or the approval's end) — EXCEPT a row whose callback is still
  being tried, kept up to `horizonS()` past `keepUntil` (every wait and
  flight the bound allows); one that must go with its delivery open gets
  the final `0135` row first (`giveUp()`).
* **The denial store is capped at the insert**
  (`authzen.accessRequestMaxDenials`, default 100000, per realm): full,
  `recordDenial()` records nothing and the token form still works; the full
  store is logged and audited once as `0144` (state changes, never per
  denial).
* **A DELETED SUBJECT'S TASKS END WITH THEM (2026-11-16, #1612's rule: a
  person deleted and made again under the same name inherits nothing).** A
  task names its subject as the PEP sent it — a username, often — and
  `verify()` matches that exactly, so a namesake was the subject of the
  deleted person's approvals. `ldap_server.js`'s `forgetPersonHoldings()`
  calls `forgetSubject()` with the username, the `urn:uuid:` subject and the
  mail addresses: a pending task is cancelled and an approval revoked, each
  with its audit row (actor `the directory`). They are found through a
  SUBJECT INDEX, not a walk: `subject:<SHA-256 of the lower-cased id>` in
  `authzen.accessRequestIndex` — the module's existing per-realm,
  cell-tier store, so no new store and no new tier — holding that subject's
  task ids and kept as long as the latest of them. `save()` writes it (one
  get, a set only when it changes) and the sweep takes a removed task out.
  **A task from before the index** is noted by the sweep job, which walks
  every task already: the backfill, within a minute of the upgrade and never
  on the delete path; a delete inside that minute misses such a task.
* **The portal lists and revokes the approvals that person gave** (#1203),
  through the same `decide()` door, and ONLY those: a revocation on the
  portal door of an approval somebody else gave is refused (`0141`), since
  the policy question alone would let any permitted approver revoke
  another's. `grantedBy()` is the list: status `approved`, a live approval
  whose `approver` is that username, and `mayRevoke()` on the portal door.
  **Neither portal list reads the store** (no full scans): `grantedBy()`
  reads the APPROVER INDEX (`approver:<SHA-256 of the lower-cased
  username>` in `authzen.accessRequestIndex`), and `awaiting()` the
  PENDING INDEX (`pending:tasks`), whose length
  `authzen.accessRequestMaxPending` bounds — eligibility is computed at
  the read, so a per-approver list could not be exact. `save()` writes
  both; two processes can lose each other's id, and the sweep, which walks
  every task already, puts it back within a minute.
  The requester is mailed (`authzen-access-revoked`) when the channel can
  address their own entry; a failure to mail is `0138` and the revocation
  stands. An emergency approval, whose approver is the door rather than a
  person, stays on the console.
* Not built: `form_url`, `display`, BULK, ACTOR, CATALOG.
  `tests/authzen_access_request.js` holds it in process and
  `tests/protocol/sts_authzen.js` section 9 over HTTP.

## THE REQUEST SHAPES ARE THE MODEL'S (#1579, 2026-11-10)

**`models/authzen/authzen.tsp` is the source of every request this API
reads**: the access evaluation (section 6), the evaluations request with its
`options` and `evaluations_semantic` (section 7), the three searches with
`page` (section 8), and the access request submission (#1180). Each property
is a member, checked IN THE ORDER IT IS DECLARED, because the order decides
which refusal a request with two wrong members gets. Its TypeSpec type says
what it is — a model (an object, its own properties checked the same way), a
bounded `string`, `string[]`, an integer, a union of string literals (its
values), `unknown` (read by somebody else) or `never` (a member the request
must not carry) — and whether it must be present; `@field` says the bounds,
the error code and the sentence a refusal carries. `@request` gives the
request's own sentences (a body that is not an object, a member it does not
take) and the codes of each kind, and since #936 `unknownMembers:
"ignored"`, which every request here carries: a member no field names is
accepted and not read, at every depth, and the request has no `stray`
sentence (`checkAuthzen()` refuses one). **Every sentence is the one the
hand-written reader sent, word for word**, and `tests/authzen_model_wire.js`
holds 326 recorded answers to it, in a development and a product realm with
each switch turned.

* **The pass, in `authzen_model.ts`'s `read()`**: the body an object, the
  leading members it must not carry (BULK's `items`), then (only on a
  request whose `unknownMembers` is `refused`, which none here is since
  #936) the first member it does not take, then every field. A field with a
  `refusal` answers it for everything it holds, at the request's type code
  unless it names its own (`context.approval`, `page`, a search's entity).
* **Deferred fields are read where the code reads them**, with `field(id,
  path, value)`: a submission's `denial`, `requested_access` and `callback`
  (and `callback.events`) sit between checks that need state — the binding
  token, the clock, the registered callbacks — and moving them would change
  which refusal comes first. `item(id, path, value)` is a batch item, refused
  alone.
* **The lists the code branches on are the model's**: the reserved context
  members (`authzen_catalogue.ts`'s `RESERVED_CONTEXT` is the evaluation's
  `Context`, in its check order, which since #1579 is the order the console's
  catalogue tab lists them too), the obligation types and their required and
  array properties (`authzen_members.tsp`'s `obligation` sets), the batch
  semantics and the default one, the task statuses and the callback events
  (the terminal statuses), and the problem types' URIs and titles.
* **Every answer is HELD, never reshaped**: the metadata, an evaluation's and
  a batch's answers (each item, its Decision Context and its `context.error`
  through the nested sets), a search's answer and page, the error object,
  every problem, every task response and the callback's payload. A member a
  closed set does not name, a wrong type or value, or a missing required
  member is logged under STS-AUTHZEN-0116 and the answer is sent as it was
  built.

**What stays in the code, because it needs state**: the catalogue's rows and
their value rules (`xacml/xacml_attribute_rows.ts`), the token-exchange
binding's fixed context (`authzen_exchange.ts`'s `strayContext()`, which
depends on `authzen.tokenExchange`), the caller's application scope, the
batch's `maxBodyBytes` and `maxEvaluations`, a search's page token against the
request it continues, a submission's binding token, `expires_at`, freshness,
idempotency, scope and registered callbacks, and `requested_until` (the
clock). The access request's cancellation body is read leniently and never
refused, so it is not a request in the model. `tests/model_authzen.js` holds
the build's refusals, that `authzen/` writes no shape check or sentence of its
own, and every recorded answer to its member set.

## Error codes

`STS-AUTHZEN-*` is its own subsystem (`common/error_codes.js`). 0001–0008 are
the request's shape and values (0009, a member AuthZEN 1.0 does not define,
is retired by #936), 0010–0012 the catalogue's writes, 0013–0014
the API being off, 0015–0023 the caller's authentication, 0024–0027 its
admission and scope, 0028–0029 the result, 0030–0034 the tab's acts, 0035
the metadata path, 0036–0039 the batch, 0046 an application's fine-grained
policy that cannot be used (#564), 0060 a value left out of the
catalogue a remote PEP pulled (#1179), 0061–0062 a caller list a remote PEP
pulled that was cut or held a certificate that could not be read (#1189),
0070–0096 the Access Request and Approval Profile (#1180): 0070–0083 and 0096
the endpoints, 0084–0086 a presented approval not used, 0087 an unsigned
binding, 0088–0090 and 0094–0095 the approvers' and the tab's acts, 0091–0093
the callback, the job and the mail; 0100–0115 the token-exchange binding
(#1181): 0100–0102 a tuple's shape, 0103–0107 a fixed-rule `false`, 0108–0110
the exchange question's answer, 0111–0113 a scope's, 0114 an expired subject
token, 0115 the no-broadening check; 0116 an answer that is not its model's
(#1579); 0117 a request whose `Content-Type` is not `application/json`
(#936); 0118–0121 a remote PEP's DPoP-bound token from `sts-remote-pep`
(#1827's follow-up): 0118 refused as a token, 0119 without
`authzen:evaluate`, 0120 naming no entry or one outside REMOTE_PEPS, 0121
`xacml.pepAuthentication` set to `certificate`; 0122 an access request
submission whose `Content-Type` is not `application/json` (#936); 0123–0127
direction B (#1200): 0123 an unusable PDP address, 0124 no answer, 0125 a
subject or requesting-party gate refused, 0126 an answer that is not the
batch's decision, 0127 a client certificate, key or named CA file that
cannot be read; 0128–0134 the binding's authorization-detail tuples and
the issuance envelope's audience and claims (#1201): 0128 a cell naming
somebody other than the exchange subject, 0129 a cell not covered, not
issued here, or whose type can no longer be read, 0130 the application's
policy denying the cell, 0131 the type list unreadable (logged), 0132 an
audience that would broaden (logged and dropped), 0133 a claim that
would broaden, is reserved, or is not on the subject token (logged and
dropped), 0134 an empty audience withdrawing the target; 0135–0137 the
callback retry (#1202): 0135 the delivery will not be tried again (the
task status is unchanged), 0136 retired (a callback for somebody who is
not an application, refused until the review of #1202), 0137 a per-URL
`attempts` or `backoff` that is not an integer in range or is set for a
person; 0138 the requester of a revoked approval could not be
mailed, and the revocation stands (#1203); 0139 a requestable denial
could not be recorded, and the binding_token is still issued; 0140 an
approval's state could not be signed, and the approval stands by id
(#1204); 0141 a portal revocation of an approval somebody else gave
(#1203), 0142 an approval that could not be stored and 0143 approvers who
resolve to nobody, each a task moved to `failed` (#1202), 0144 the denial
store full (#1204).
