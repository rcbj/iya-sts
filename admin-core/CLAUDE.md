# admin-core/

**What the admin console and the management API both do, in a directory
neither of them owns.** Two files arrived on 2026-09-12 out of
`admin-ui/admin.ts`, and two more were written here on 2026-09-13:

| File | | |
|---|---|---|
| `admin_actions.ts` | **what CHANGES state** | 31 actions, the tables they dispatch on, the helpers they share |
| `admin_views.ts` | **what ANSWERS a question** | 38 functions that compute a JSON answer and build no markup |
| `certificate_views.ts` | **which certificates a details view may open, and the view** | the catalogue and `detailsView()` / `listView()`, read by `/admin/pki`, `/admin/crypto-metadata` and `GET /admin-api/certificates` — see the section at the foot |
| `protocol_endpoints.ts` | **which endpoints each Protocols page lists** | the page-to-route table and `forPage()`, read by `admin.respond()` and `admin_api.js`'s `sendJson()` — see the section at the foot |

**Read each file's own header first.** They carry the argument at length: what
may be in them, what may not, why they are not in `common/`, and why the
collaborators they need are still the console's. This file is the part that
does not belong inside either one.

**The require between them goes ONE WAY.** `admin_views.ts` requires
`admin_actions.ts` for the tables they share — a page draws the buttons its
action dispatches on, and one table with two readers is what stops a page
offering a control its action does not have. Nothing in `admin_actions.ts`
reaches back, and nothing may: an action consulting a view would depend on how
its own result is going to be displayed.

## Why the directory exists at all

Rule 7 says every control on `/admin` owes an operation on `/admin-api`, and
until this directory existed the way the two were kept from disagreeing was
that **`mgmt-api/admin_api.ts` required `admin-ui/admin.ts` and called its
action functions**. That enforced the rule in the strongest possible way — a
page and its operation could not disagree, because they were the same call —
and it cost something real: the surface a machine drives was downstream of the
surface a person reads, and the console was the declared home of logic that was
never the console's.

**The functions themselves were never the problem, and that is the only reason
this was a cheap change.** Not one of the thirty-one had ever touched `req`,
`res` or markup. Each took a parsed body and an actor, called the domain module
that owns the change, wrote its audit row and returned `{ ok, errors, … }`.
They were a shared logic layer already; what was wrong was where they lived.

So this was a MOVE and not a rewrite. Every function in `admin_actions.ts` is
the one that was in `admin-ui/admin.ts`, carrying the comment that argued it.

## What actually moved, and what deliberately did not

| | |
|---|---|
| **Moved** | 31 actions, the tables they dispatch on, and the pure helpers they share with the pages that draw their buttons — 61 symbols, about 3,100 lines with their comments |
| **Stayed: `respondToAction()`** | It turns a result into a 303 back to the page or into JSON. That is TRANSPORT, and it belongs to the surface that has a page |
| **Stayed: `respondToApplicationAction()`** | Same, plus it reaches for the console's paging (`listViewFromBack()`, `queryWith()`) |
| **Stayed: `listField()`** | It reads `req` — the repeated-checkbox parse that `helpers.parseBody()` cannot answer. It sits at the transport edge and stays there |
| **Stayed: every view** | A `*View()` returns `{ json, inner }`, and `inner` is HTML. Splitting those into a model and two renderings is the next increment and has not been done |

**`listField()` staying is the fact that made the whole move possible, and it
is worth understanding rather than noting.** `applicationsAction(body,
protocols)` takes the repeated values as a PARAMETER; the route parses them and
hands them down. Somebody drew that boundary long before this directory
existed, and every action was on the right side of it.

## The seven collaborators

Seven actions need something filled by a module further down the require order:
the logout reader, the directory and group writers, the three Shared Signals
reporters, and the XACML pages. Those are inverted hooks on `admin-ui/admin.ts`
(rule 3e), filled by `ldap/ldap_server.js`, `ssf/ssf.ts`, `logout/logout.ts`
and `xacml/xacml_admin.ts`.

**AN EIGHTH ARRIVED ON 2026-09-12: THE CLIENT-CERTIFICATE TRUSTSTORE**, which
`truststoreAction()` here and `truststoreJson()` in the views layer both reach
through `admin.setTruststore()`. It is the one collaborator whose slot is
filled by `common/protocol_stack.ts` rather than by the module that owns the
array (`tls/tls_server.js`), because that module is first loaded from inside the
console's own require and could not fill it without a cycle —
`admin-ui/CLAUDE.md` argues it. It changes nothing about the rule below: one
setter, two destinations, one writer in each half.

**The slots did not move, and that was a choice about prose as much as code.**
Every filler in the tree names `admin.js`, and so does every sentence of
CLAUDE.md explaining why each hook has to exist. Moving them would have meant
editing four fillers and rewriting that argument to say something no less true
and no more useful. So the console FORWARDS what it was handed, from inside the
setter it already had.

That is **one decider with two caches, which is not the same as two answers** —
and the difference has to be stated, because this repository refuses the
second. Nothing in the layer is ever assigned from anywhere but the console's
own setter, so the two cannot drift; what would make them two answers is a
second writer. `tests/admin_actions_layer.js` asserts there is exactly one.

## Where it may be required

**At 18 or later, and nowhere earlier.** `admin_actions.ts` requires `oauth2`,
`saml2`, `saml11` and `federation`, every one of which registered routes when it
was required (rule 1) until #50's R1 — so anything that loads this file loads
them. That is free from the console (18) and the management API (19), where all
four are already loaded and every require is a cache hit. From position 4 it
would have pulled the authorization server and both SAML profiles into the
router ahead of themselves, and the symptom would have been a handler winning
somewhere else entirely. **Since R1 all four are TypeScript and register
nothing when required** — `common/protocol_stack.ts` calls their
`registerRoutes(app)` in its own order — so an early require no longer moves a
route; it still runs their load-time code (stores, slot fills, and whatever
JavaScript route module THEY require) out of order, which is reason enough to
keep the rule.

**That is why this is not in `common/`.** That directory reads as *anything may
require this, at any point in the order*. This one may not.
`tests/admin_actions_layer.js` walks the tree and fails if any module outside
its named `allowed` list requires `admin_actions.ts` or `admin_views.ts` — the
console, the management API and a handful of view/action layers that all load
at 18 or later.

## What the move cost, which is the honest part

The in-process suite passed unchanged — it does not drive either surface over
HTTP, so it could not have caught what was wrong. The first run of
`tests/vendored/sts_admin_api_operations.js` failed with

```
POST /applications/__no_such_action__ should be refused 400; it answered 500
  "ReferenceError: numberWord is not defined"
```

on one refusal path, because `numberWord` and `signJwt` come from a destructure
in `admin-ui/admin.ts` spread over thirty comment-interleaved lines and the
first pass of the move did not carry them across. A second run found
`SPIFFE_ACTIONS is not defined` the same way.

**FIVE OF THESE SHIPPED IN TOTAL ACROSS THE TWO MOVES, AND THEY ARE ALL ONE
DEFECT.** `numberWord`, `signJwt`, `baseUrlOf`, `stsKeysFor` and `sessions` —
the first two in the actions, the last three in the views. `admin-ui/admin.ts`
pulls fourteen names into scope through destructured requires, from
`common/helpers` and from `authn/authn`, and both of those are spread over
comment-interleaved lines. A function that used one read perfectly well in the
file it came from and threw a `ReferenceError` in the file it moved to, on
whichever branch happened to reach it. Each was found by a different HTTP job,
one at a time, and `npm test` was green for all five.

`tests/admin_actions_layer.js` now asks the question statically — *is this name
in scope here* rather than *did a test reach it* — which is the check the move
needed and did not have. A sixth would fail there.

**A SIXTH DEFECT WAS OF A DIFFERENT KIND AND IS WORTH KEEPING SEPARATE.**
`admin-ui/api_explorer.ts` called `admin.gateStateFor()`, which stopped
existing the moment the console stopped re-exporting what moved. It loaded
fine and threw a `TypeError` when somebody opened the page. The management API
had been repointed deliberately; a console page calling a moved function had
not been looked for. That is pinned too.

**All of them were found by a job driving the running surface, and none could
have been found by reading.** That is the argument for running the owned jobs after
a change of this shape — see `tests/CLAUDE.md`, and
[the rule about `npm test` missing `/admin`](../tests/CLAUDE.md).

## The views: what came across, and the measurement that decided it

The second move, the same day, and it could not be made on a hunch. Of the
**eighty-nine** view-shaped functions in `admin-ui/admin.ts`, forty-six return
a json half — and **only three of those separate at a clean boundary.** The
other forty-three build row markup part-way through the computation, inside the
`.map()` that walks the rows.

So the line was drawn somewhere else: **thirty-eight functions that were
already pure** — they compute an answer and reach no markup at all, directly or
through anything they call. Those needed no surgery and moved exactly as the
actions did.

**Two kinds of thing stayed behind, and only one of them is about markup.**

* **Anything that builds HTML**, which is the forty-three above and the views
  that wrap them. `{ json, inner }` computed in one pass is the strongest form
  of rule 7 there is — the page and the operation cannot disagree because one
  function computes both — and splitting it has to preserve that rather than
  degrade it to *tested not to*. That is the next increment and it is bespoke.
* **THE CONSOLE'S OWN STRUCTURE, even though it is perfectly pure.**
  `consoleJson()` (which pages exist, from `NAV`), `configJson()` and
  `settingsGroupsFor()` (where a settings group is edited, from
  `SETTING_HOMES`), `protocolSettingsJsonFor()` and `configSettingsJson()`. A
  caller asking *what pages does this console have* is asking the console about
  itself. **Purity was not the test; ownership was.**

`scimJson()` is the one function that reaches back for that knowledge — it
embeds the SCIM settings block — and does so through `configSettingsJson`,
which the console hands over like any other collaborator. The alternative was
for the page and `/admin-api/scim` to assemble that block separately, which is
the drift rule 7 exists to prevent.

**THE REQUEST RULE IS NOT THE SAME FOR THE TWO HALVES.** An action is handed a
parsed body and an actor and never sees the request. A view is parameterised by
the QUERY STRING — which page, which filter, which user — and reads
`req.query`, exactly as it did on the console. Nothing else off the request:
a header, a cookie or a body would not mean the same thing arriving at the API.
Neither half touches `res`.

## And then the interleaved ones, which had to be SPLIT

The thirty-eight above needed no surgery. The rest did, and they were done one
family at a time: new-application, new-person, RBAC, SAML 2.0, SAML 1.1,
authorization servers, groups, applications, federation, users, the
second-factor roster and sign-out.

**THE TRANSFORMATION IS THE SAME EVERY TIME AND IT IS WORTH KNOWING, because it
is the one that keeps rule 7 rather than weakening it.** A page computed a
dozen facts, built markup from them, and assembled a json from the same facts
at the bottom. So: the computation and the json move here; the page takes the
model back in one call and its markup is untouched.

```js
// admin-core/admin_views.ts
function xListJson(req) { …compute…; return { …the facts…, json: {…} }; }

// admin-ui/admin.ts
function xListPage(req) {
  const view = adminViews.xListJson(req);
  const rows = view.rows;            // the same names the markup already used
  …markup unchanged…
  return { inner: inner, json: view.json };
}
```

**The page and the resource are now ONE computation with two renderings, which
is stronger than what was there before** — before, they were one function that
happened to build both, and nothing stopped a later edit computing the json
from something else.

**WHAT STAYED, AND THE LINE IS OWNERSHIP RATHER THAN PURITY.** Four things, and
`/admin-api` still calls exactly these four on the console module:

| | |
|---|---|
| `consoleJson()` | which pages this console has, from `NAV` |
| `configJson()` | every setting, and which page edits each group |
| `protocolSettingsJsonFor()` | the settings one protocol page owns |
| `listField()` | the repeated-checkbox parse, which reads `req` |

The first three are the console describing ITSELF; a layer beneath it could not
know the answer. The fourth is transport. Everything else the API needs it now
gets from `admin-core/`.

**ONE FUNCTION LEFT THE CONSOLE ENTIRELY.** `mfaView()` built the second-factor
roster and returned somebody else's markup with it; the page it belonged to had
split into `/admin/totp` and `/admin/webauthn` and its columns had moved onto
`/admin/users`, so nothing on the console drew from it any more. It is
`mfaRosterJson()` here — the resource, and only the resource.

## What the splitting cost, which is the honest part

**Every family but one shipped a defect that the two HTTP jobs caught**, and
they are worth listing because they are all the same KIND of mistake — a name
that meant one thing in the page's scope and another in the layer's:

* `prefill` — a page PARAMETER dropped when the signature was rewritten, so a
  refused create came back with empty boxes.
* `an` and `bn` — locals of a sort COMPARATOR, lifted as though they were the
  page's.
* `pagedGroup` — declared after the markup that needed it, so the layer
  returned a name it never bound.
* `looksGuessed` — the same, one regex the json published and the page drew.
* `?id=` where the page reads `?relationship=` — the resource answered the
  LIST for every drill-down, and nothing errored.
* the no-directory branch of `groupsJson()`, missing until a build without
  `ldap_server.js` would have thrown where the page answers a sentence.
* a blanket `json: info` replacement that hit four other functions.
* `spiffeJson()` returning the answer where its two siblings return
  `{ json, paging }` — so `.json` on all three sent one resource `undefined`,
  which reaches a caller as a string.

**None of these was found by reading and none by `npm test`.**
`tests/vendored/sts_admin_api_operations.js` and `sts_admin_console.js` found
every one. That is the whole argument for running the owned jobs against a
change of this shape — see `tests/CLAUDE.md`.

## THE USERS LIST PAGES BEFORE IT DECORATES (#352, 2026-09-29)

**On testidp (29,267 people) `GET /admin-api/users` took ten seconds a
request, whatever the page and whatever `?q=`**, and the request worker that
served it missed its read barriers while it did (STS-WORKER-0027). The list
was built WHOLE and then sliced: `peopleRows()` asked
`credentials.secondFactorHolders()`, which asked `mechanismsFor()` of every
name — about nine directory reads, a copy of the entry for the mail factor
and an unseal of the TOTP secret per person — for five thousand directory
people (the scan cap) plus everybody the register had seen, and then
`usersListJson()` showed fifty. `/admin-api/mfa` answers out of the same view
and paid the same.

**The order is now list, filter, page, decorate, and each step reads only
what it needs:**

* **List.** `peopleRows()` folds the register's rows with
  `credentials.secondFactorPopulation()` — the same union, deduplication,
  sort and cap as before, and nothing read per name. A row comes back with
  `factors: null`; beside the rows, `spellings` records which population
  names folded into which row, in the order the old fold applied
  `mergeFactors()`. `isApplicationRow()`'s third test uses the directory's
  `applicationMatcher()`, one listing of `ou=applications`, where it used to
  ask `applications.get()` per register row.
* **Filter.** `?q=` and `?protocol=` read the row. `?factor=` needs every
  row's factors, and so do the seven tiles, so both read `peopleCensus()`:
  `credentials.factorCensus()` over every spelling, from ONE call into the
  directory (`credentialCensus()`), united per row by the same
  `mergeFactors()`. The census carries seven facts and never the recovery
  codes or the authenticator's detail, which no count reads.
* **Page, then decorate.** `pagedRows()` takes `options.decorate(row)` and
  applies it to the shown slice only. `decoratePerson()` builds each shown
  row's full factors from `credentials.factorHolderRow()` — which is
  `mechanismsFor()` — per spelling, exactly as the old fold did for
  everybody.

**The census interprets nothing in the directory.** `ldap_server.js` hands
back raw attribute values; which values are keys, what a sealed TOTP record
is, and when an emailed factor is held are still decided in
`common/credentials.ts` and `common/mail_factor.ts`, through the same
functions the one-name path uses — that file's header argues why the console
must not learn what an enrolment is, and a directory that did would be a
second answer to it.

**The one unseal left is remembered.** Whether a sealed TOTP secret opens is
a pure function of the sealed text and this process's keys, so
`credentials.ts` keeps the verdict (`credentials.totp-verdicts` on
`/admin/caches`), stamped with `keystore.kekEpoch()`, which moves when the
keys do. Each secret is opened at most once per process and key set and not
at all on a repeat request. `verifyTotp()` never reads the memo; it opens the
secret every time.

**`?user=` no longer builds the list to find one row**: `stats.userDetail()`
asks `stats.userRow(key)`, which runs the same builder for that key only, and
`knownUserKeys()` — nine pages' "can this member's name be a link" — asks
`stats.userKeys()` instead of building every row to read their keys.
`/admin/sessions` asks `stats.issuedArtifactsOfKind('Kerberos TGT')` for the
tickets rather than building `issuedList()`.

**What was measured, and what holds it.** `tests/users_page_before_decoration.js`
seeds three thousand people and asserts that page one, a far page, `?q=` and
each `?factor=` call `mechanismsFor()` at most once per row shown, that a
first request opens each sealed secret at most once and a repeat opens none,
and that every answer — tiles, counts, scan cap, the rows with their factors
— equals the old algorithm's, computed there independently. In that test the
old algorithm took about 600 ms for the population and the new page about
90 ms on a first request and 70 on a repeat. The remaining cost is building
the register's rows and listing the directory's names, both in memory, and
the name list is `persons()`, whose own cost is `ldap/`'s to make small.

**Not done, and why.** The census is not memoized across requests. It would
have to be keyed on every input a fact depends on — the people subtree's
version, the realm's authentication policy and mail settings for the emailed
factor, and the key epoch — and a request that already reads no secret and
makes one call into the directory does not need it. Under #349's windowed
directory, `credentialCensus()` is one batched `byKeys()` query.

## `certificate_views.ts`: THE CERTIFICATE DETAILS DIALOG'S CATALOGUE (2026-09-13)

`/admin/pki` and `/admin/crypto-metadata` open a certificate's every X.509 field
and its trust chain in a dialog over the page, and `GET /admin-api/certificates`
answers the same thing for a machine. **This file is the one place that decides
which certificates any of the three may open**, which is the half of the feature
that is not a rendering. The model is `common/certificate_details.ts` and the
dialog is `admin-ui/certificate_dialog.ts`; the file headers argue each.

Four decisions, and each is a refusal:

* **A CERTIFICATE IS NAMED BY ITS SHA-256 AND LOOKED UP, NEVER SENT.** A view
  that described a PEM from the query string would render an attacker's
  certificate — subject, extension values, chain status — under this console's
  header from a link somebody was sent. The only certificates that resolve are
  the ones in the CATALOGUE: what this service holds.
* **THE CATALOGUE IS PER REALM.** The service Root, the process branch, and THIS
  realm's Intermediate, Issuing CAs and what they certified, plus this realm's
  signing keys, the workbench store, the TLS listeners, the SPIFFE authorities
  and the key pairs issued to applications and people. Another realm's branch is
  not in it, so its certificates are refused here and open under that realm's
  prefix — `verifyLeaf()`'s boundary, drawn on a page.
* **THE CHAIN IS BUILT OVER THE AUTHORITIES AND NEVER OVER THE HOLDERS.** The
  authorities are a few dozen certificates in memory; the holders walk the
  directory, which a bulk-loaded realm holds fifty thousand people in. A lookup
  asks the authorities first, and a leaf signs nothing, so it is never a
  candidate issuer.
* **`tls/tls_server.js` AND `spiffe/spiffe_ca.ts` ARE REQUIRED INSIDE THE
  FUNCTIONS**, for rule 1: `admin-ui/pki_admin.ts` requires this file at 18a and
  the TLS module registers routes at 20. A request runs after every module has
  loaded, so inside a function the require is a cache hit. `admin_views.ts` is
  required lazily too, for the same reason read the other way.

**THE LIST PAGES BEFORE IT PARSES (#352, 2026-09-29).** `listView()` parsed
every certificate in the catalogue with pkijs — subject, issuer, notAfter —
before it filtered and sliced; the holders are the part of the catalogue that
grows with the realm. The catalogue is in the order its sources were read and
nothing sorts it, so without `q` the page is a slice and only the slice is
parsed; with `q` a certificate is asked the cheap question first (the labels of
where it appears, text already in hand) and parsed only when that does not
match, against the same haystack the old filter searched. What a parse finds
is kept in `certificates.parsed-facts` — CONTENT-KEYED (the fingerprint, or
the SHA-256 of the PEM text for `pqcOf()`), so it can never be wrong in this
process or any other and needs no version or invalidation; bounded at 4,096,
the oldest dropped, and on `/admin/caches` (rule 3ap). `pqcOf()` is the same
memo put in front of `pqc_support.of()` for `/admin/pki`. **The details
lookup's miss path parses nothing it does not open**: it fingerprints the
holders' certificates (a SHA-256 of the DER, not an X.509 parse), and the
holders themselves come from `person_assertions.holders()`, which reads
presence in one walk. `tests/certificate_listing_bounds.js` counts it.

It is here rather than in `common/` because both surfaces read it and it reads
the two route-registering modules above — lazily, but it reads them — which is
what this directory's position rule is about. `tests/admin_actions_layer.js`
still passes with it here, and `tests/certificate_details.js` pins the
catalogue and its boundary.

## `protocol_endpoints.ts`: WHAT EACH PROTOCOLS PAGE LISTS (2026-09-13)

A fourth file, and a library: one table from console page to the routes and
sockets that page lists, and `forPage(req, page)` turning a row into concrete
`{ name, methods, url }` rows for the realm the request is in. Both surfaces
read it at their TRANSPORT EDGE rather than in a view: `admin.respond()` adds
`protocolEndpoints` to the page (`admin-ui/CLAUDE.md`, the foot), and
`mgmt-api/admin_api.ts` adds the same member to the GET whose `mirrors` names
exactly that page. So no view function learnt an argument and the two doors
cannot disagree.

**IT NEVER LOADS A ROUTE-REGISTERING MODULE, NOT EVEN LAZILY.**
`sts_metadata.ts` (names, the router walk), `ldap/ldap_server.js` (the realm's
base DN), `kerberos/krb5_kdc.js` (the realm name) and `spiffe/spiffe_server.ts`
(the bindings) are read out of `require.cache` by `loaded()` only if something
already loaded them. `certificate_views.ts` requires inside a function, which
is a cache hit once the stack is up; this goes one step further because the
first of those four must be LAST and requires the console. An in-process caller
without the stack gets rows named by their paths and no methods — and no
`registered` verdict, since nothing was checked. No slot was added: rule 3e's
test is about a require, and there is none.

It is here rather than in `common/` for this directory's reason: both admin
surfaces read it, and what it reads is route-registering, lazily or not.
`tests/protocol_endpoints.js` holds it.
