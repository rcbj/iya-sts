# uma/ — User-Managed Access 2.0

**A grant, not a decision engine** (#1168). UMA 2.0 is two Kantara
Recommendations (2018-01-07): *UMA 2.0 Grant for OAuth 2.0 Authorization*
(the permission ticket, the `uma-ticket` grant, the RPT, claims gathering,
discovery) and *Federated Authorization for UMA 2.0* (the protection API: the
PAT, resource registration, the permission endpoint, RPT introspection). What
UMA adds that nothing here had is a POLICY A PERSON WRITES: the resource
owner's own document, authored by a form. Everything it DECIDES is already a
question this service puts to the XACML PDP, so this family is built as #432
and #564 were: a protocol module that gathers facts and enforces verdicts,
with no decision in code. `docs/uma.md` is the user-facing half; this file is
why the code is the way it is.

rcbj's design is the *Design* comment of 2026-10-30 on #1168, and his eight
decisions are at its foot. The phases: #1190 (this contract), #1191 (the
protection API), #1192 (the owner's policy and `/portal/shared`), #1193 (the
grant), #1194 (claims interaction and approval), #1195 (the console), #1196
(protocol tests with Keycloak). A phase's section below is written when it
lands.

## The four layers, and the one sentence that holds them together

An RPT permission — one registered resource, one scope — is issued only when
ALL of these answer Permit, in this order, each a separate PDP question with
its own audit row:

| # | Policy | Action-id forced to | Asked through |
|---|---|---|---|
| 1 | the realm's **`uma-authorization`** — the `xacml_templates.ts` row, built in and CALLED like `role-issuance`, overridden by the `ou=policies` entry `uma.authorizationPolicy` names (a DISABLED entry does not fall back) | `issue-uma-permission` | `decidePolicy()` with the repository and the PIP |
| 2 | the **resource owner's own document** — `uma.ownerPolicies`, the `uma-owner-default` shape, written by the portal's form | the SCOPE itself | `decidePolicy()` with NO repository, as an application's fine-grained policy is |
| 3 | the resource server's **fine-grained policy**, only while `appFgaEnforced` (#564) | `grant-uma-permission` | `common/fga_gate.ts`'s decider, stage `uma` |
| 4 | the **issuance gate**'s `issue-access-token`, for the RPT as a token | — | `common/issuance_gate.js`, as every access token |

Deny, NotApplicable and an Indeterminate over a missing attribute ABOUT THE
RESOURCE refuse the permission. **An Indeterminate over a missing attribute
ABOUT THE REQUESTING PARTY is `need_info`** (decision 6): the engine's own
missing-attribute status (`xacml_pdp.js` throws `model.missingAttribute()`
with the designator's `attributeId` and `category` in its detail) is what
the PEP builds `required_claims` from. A fault (`STS-XACML-0012`/`0013`), a
throw, or an owner document that will not parse is `server_error`, never
`request_denied`: nobody decided. **No owner document is NotApplicable,
which refuses: absence is never consent** — the default-permit FGA policy
manufactures nothing here, because it is layer 3 and layers 1 and 2 must
have said yes first (the ticket's rule 3).

## Phase 1 (#1190): the contract

| Where | What |
|---|---|
| `xacml/xacml_request.js` | `uma(facts)` (rule 3br), the `UMA_*` identifiers in `VOCABULARY` under `urn:sts:xacml:uma:*`, `ACR` (`urn:sts:xacml:acr`, the same identifier `xacml_templates.ts`'s `AUTHN_ATTRIBUTE.ACR` always was), and the constants `UMA_LAYERS`, `UMA_STAGES`, `UMA_PERMISSION_ACTION`, `UMA_FGA_ACTION`, `UMA_GRANT_TYPE`, `UMA_CLAIM_SOURCES`. The Rust builder (`rust/crates/sts-xacml/src/builder.rs`) spells every one the same; `tests/xacml_request.js` E2 holds them equal by NAME, so a constant added to one side without the other fails there. |
| `xacml/xacml_templates.ts` | `UMA_ATTRIBUTE` (the two action-ids, the approval obligation and its one assignment, the template ids, the owner-self rule id and the share-rule prefix), `PolicyBuilders.umaOwnerPolicyId()`, `requiredDesignator()` and `holdsTrue()`, and the two template rows. |
| `uma/uma_store.ts` | The six stores and the one writer of each; `spend()` for a ticket or PCT, GNAP's cluster claim. |
| `persistence/tiers.js` | All six CELL-tier. |
| `common/config.js` | The `UMA` group, fifteen settings, `uma.enabled` off. |
| `common/error_codes.js` | The `UMA` subsystem; `0001`–`0003` here, the rest numbered by phase (the subsystem's comment says the blocks). |
| `tests/uma_request.js`, `tests/uma_templates.js` | The facts and both templates through the real engine. |

### Three things in the contract that are not what the design comment says, and why

* **The built-in realm policy has TWO Permits, not one.** The design named
  `uma-owner-self` as "the only built-in Permit". Read literally, a known
  stranger would be NotApplicable at layer 1 — refused before the owner's
  document was ever asked — which is the opposite of what a share is for. So
  `uma-participants-permitted` permits any known requesting party once no
  gate has denied, and the design's sentence that holds is "a realm tightens
  by adding a rule": under deny-overrides a Deny the realm adds wins over
  both Permits. The comment above the template row argues it.
* **The action-id on the OWNER's layer is the scope itself.** The design
  says both "the action-id is forced to `issue-uma-permission` on the realm
  and owner layers" and "a Target on `resource-id` and the scopes as
  `action-id`" for the owner's rule. They cannot both hold. An owner's
  document is only ever asked about UMA permissions over that owner's own
  resources, so there is nothing a forced action would tell apart there, and
  a rule reading `action-id == "read"` is what a person's form writes. The
  scope travels as `urn:sts:xacml:uma:scope` on EVERY layer as well, so a
  realm's or an application's rule can read it beside its forced action.
* **The owner's document is a Policy, not a PolicySet.** The form writes
  RULES; a PolicySet would hold them one Policy deeper for no reader's
  benefit, and the editor opens either.

### Why `uma-requesting-party-required` is a Deny rule that never denies

It exists for its DESIGNATOR: `subject-id` with `MustBePresent="true"`. With
nobody known `uma()` writes NO subject-id (never `''` — `fga()`'s rule), the
PIP is asked and answers nothing, and the engine throws the missing-attribute
Indeterminate, which deny-overrides propagates as `Indeterminate{D}`. With
somebody known its condition (`string-bag-size == 0`) is false. The algorithm
is `deny-overrides` and not `deny-unless-permit` for exactly this: the latter
turns every Indeterminate into a Deny, and the PEP could no longer tell "ask
for claims" from "no".

### `uma_store.ts` holds no bearer value as a key

A ticket and a PCT are stored under their SHA-256, as GNAP's interaction
handles are since #614, and an RPT under its `jti`. The two owner-document
bounds (`uma.maxOwnerPolicyBytes`, `uma.maxOwnerRules`) are held in
`saveOwnerPolicy()`, the one writer, so no door can exceed them; expiry is
checked at every read (`live()`), pruned opportunistically at writes, and
swept by the scheduler job phase 2 registers — never by a timer of this
family's own.

## Phase 2 (#1191): the protection API

| File | What it is |
|---|---|
| `uma_pat.ts` | The protection API token's door: AuthZEN's token door read again (signature or opaque handle, expiry, `at+jwt`, issuer, audience `/uma`, revocation, certificate binding, DPoP, sender constraints, `uma_protection` and the client's delegated permission grant of it, asked on every call), then the two facts a PAT adds: the client's application is DECLARED for `uma` (0104), and a token issued to the client as itself needs `umaOwnsResources` (0105). The caller it answers names the OWNER — a person's `urn:uuid:` subject or the application's identifier. |
| `uma.ts` | The routes, registered at 23d-ii: `/uma/rreg` (and `/:id`), `/uma/perm`, `/.well-known/uma2-configuration` at both forms, and `/uma` (a description page on #584's shell, `web_uma_description.ts` with the `describeUma` catalogs). Its wire step registers the `uma.sweep` job. |

The registry gained the `uma` protocol family (no identifier attribute: a
resource server is an OAuth client, and declaring the family is what makes
it one), the `umaOwnsResources` attribute, and the `sts-uma-protection-api`
resource object with its one permission, `uma_protection` — the word
Federated Authorization section 2 names. `scope_policy.ts` protects it,
`registered_targets.ts` names `/uma` as this service's own resource server,
and `hosted_applications.js` gives the family its two prefixes.

### Decisions made here, and why

* **An unknown member of a resource description is NOT STORED, not
  refused.** Federated Authorization section 3.1 lets an authorization
  server define extensions; this one defines none, and a peer such as
  Keycloak sends members of its own (`owner`, `ownerManagedAccess`). The
  one that matters is refused by construction: the owner is the PAT's,
  never a member (`tests/uma_protection.js` R2).
* **A resource another owner or another resource server registered is
  `not_found`**, and at the permission endpoint `invalid_resource_id`: a
  resource server cannot learn whether somebody else's `_id` exists.
* **Nothing unimplemented is advertised.** `capabilities()` answers what
  later phases have filled — the `uma-ticket` grant (phase 4) and the
  claims interaction endpoint (phase 5) — and the discovery document adds
  each only then. The document starts from `oauth2.ts`'s `asMetadata()` for
  the request, so its RFC 8414 members are the realm's own; its
  `signed_metadata` is dropped, because it signs the OAuth document and
  not this one.
* **The routes answer 501 while off, discovery included** (0108; 0109
  without the API object), XACML's and AuthZEN's rule.
* **Withdrawing a registration reaches the tokens that carried it**
  (decision 11): `revokeFor()` walks `uma.rpts`' resource index and
  revokes through `admin_stats.revoke()`, on a delete and on an update that
  drops scopes. It finds nothing until phase 4 issues RPTs; the hook is
  already the one phase 4 relies on.
* **The settings were homed on `/admin/xacml` until phase 6** gave the
  family its own page (`SETTING_HOMES` now names `/admin/uma`).

## Phase 3 (#1192): the owner's document and the portal's Sharing section

| File | What it is |
|---|---|
| `uma_owner_policy.ts` | The owner's document: `ruleFor()` (one share, one rule of a fixed shape), `specOf()` (a rule back to a share, or null), `view()`, `share()`, `unshare()`, `setAlfa()`, `documentXml()` (what phase 4 decides with). |
| `../portal/portal_shared.ts`, `../portal/web_shared.ts` | `/portal/shared` and `/portal/shared-with-me`, three `/account-api` operations, the `portalShared` catalogs. `portal/CLAUDE.md`'s rules hold: the person is the token's. |

### Decisions made here, and why

* **A rule is a share only if rebuilding it from the fields read off it
  gives the SAME XML.** Reading fields alone would draw a card for a rule a
  hand edit had widened; the comparison makes the card unable to say what
  the rule does not (`tests/uma_owner_policy.js` C2).
* **A group share tests a FACT, not `memberOf`.** The directory does not
  maintain `memberOf` (`ldap_server.js` says so), so phase 4 sends the
  requesting party's direct groups as
  `urn:sts:xacml:uma:requesting-party-group`, normalised DNs, and the rule
  tests the group's normalised DN in it. A person share tests their
  `urn:uuid:` subject, which survives a rename.
* **An expiry is `current-dateTime` < the date, inside the rule**, so an
  expired share simply stops permitting; nothing sweeps it.
* **Removing a share revokes the RPTs over its resource AND scopes, whoever
  holds them** — conservative where two shares overlap, and the next
  request re-decides. An ALFA edit revokes every RPT over the owner's
  resources, because nothing can tell which rule a hand edit narrowed.
* **A person deleted takes their UMA data with them**: `uma.ts` is one of
  the directory's account observers (`addAccountObserver()`, #151's
  arrangement), and `forgetOwner()` revokes their RPTs and removes their
  resources and document. Phase 4 adds the disabled account.
* **The Sharing section is always in the portal's column**; the page says
  when UMA is off in the realm. A column that changed with a setting would
  be a second thing the static NAV table cannot say.

## Phase 4 (#1193): the grant

| File | What it is |
|---|---|
| `../common/uma_gate.ts` | The leaf slot `oauth2.ts` hands the grant, a PAT introspection and a PCT revocation through. Empty, the grant is NOT OFFERED — neither the issuance gate's "allow" nor FGA's "refuse": nobody asked for UMA in that process. |
| `uma_pep.ts` | One permission through the three policy layers, each answer read deny-biased, one `uma.decision` audit row per question, counted on the monitor's `uma` row (FGA's layer on `fga`). |
| `uma_grant.ts` | The grant (protocol first, then the PEP, then the RPT through the endpoint's own `issue()`), introspection with a PAT, the PCT's revocation. Its wire step fills the slot. |

`oauth2.ts` carries four small hooks: the grant in `grant_types_supported`
while `umaGate.offered()`, the token endpoint's branch (beside CIBA's and the
device grant's), a `lifetimeCapS` that only shortens an access token, and the
two doors at introspection and revocation. `common/applications.js`'s
`FLOW_GRANT_TYPES` takes the grant so a client can declare it, which the
realm policy's `uma-client-grant-type` gate requires.

### Decisions made here, and why

* **The fourth layer is the funnel, not a fourth PEP question.** The RPT is
  minted through `issue()`, so `checkIssuance()` (`issue-access-token`), the
  client's role, the device, risk and transfer rules and the sender
  constraint all apply unchanged; its `IssuanceRefused` is caught and
  answered `request_denied` (0217) rather than RFC 6749's `access_denied`,
  because the Grant specification's client is waiting for UMA's errors.
* **The permissions ride as `assertionClaims`**, the layer of claims a
  grant adds under the protocol's own, so `tokenSet()` gains no UMA branch;
  and `authorization_details` rides the same way rather than through
  `opts.authorization_details`, which would put the details to the
  resource server's FGA policy a second time at stage `token`.
* **The owner's layer reads a BOUNDED PIP**: only the directory attributes
  in `uma.requestingPartyAttributes`, never a role — what a person's own
  rule may read about a stranger is the realm's to say. It is decided with
  `xacml_pdp.js`'s `evaluate()` and that resolver, rather than
  `decidePolicy()`, which would hand it the unbounded one.
* **A permission whose owner asks each time is not issued here**; phase 5
  queues it. Until a claims module is installed it is logged (0216) and
  left out, never issued undecided.
* **The disabled owner**: the account observer revokes every RPT over an
  owner's resources when `pwdAccountLockedTime` appears; the resources and
  the document stay for the day the account is enabled.
* **A PCT ends with a sign-out of everything** — `logout/`'s `uma` family,
  GNAP grants' rule — and at `/oauth2/revoke` whatever the hint says.

## Phase 5 (#1194): claims interaction, claim tokens, the owner's approval

`uma_claims.ts` registers `GET /uma/claims` (after `uma`'s routes) and its
wire step hands the grant this instance (`uma_grant.ts`'s `setClaims()`),
which is what makes the grant read the interaction's person, a pushed
`claim_token` and the approval queue. `oauthClaimsRedirectUri` is a client
attribute of its own (`common/applications.js`), and the `uma-approval` mail
template a notification, in every catalog.

### Decisions made here, and why

* **The interaction endpoint draws no page of its own.** It redirects to the
  one sign-in (`authn.beginAuthentication()`, as `/launch` does) and back;
  the only text it answers is the refusal told to the person, as text, so a
  return address nobody registered is never followed. A static surface for
  one sentence would be a bundle, a shell and seven catalogs for nothing.
* **The ticket carries the person** (`requestingParty`, `acr`) through the
  rotation, so the grant reads them from the ticket the client was handed,
  and a ticket another client presented first is `not_authorized`.
* **A claim_token that names nobody is not an error.** It is logged (0406)
  and the request goes on with nobody known, so the realm policy's own
  missing attribute answers `need_info` — a client cannot tell a bad token
  from no token, and nothing a client asserted reaches the policy.
* **An approval is a rule, placed before every share.** This engine's
  deny-unless-permit answers with the FIRST permitting rule and its
  obligations, so a rule appended after the "ask me" share would be
  shadowed and the request asked about again for ever
  (`uma_owner_policy.ts`'s `approve()` argues it). It holds a day.
* **The pending request's answer is read before anything else at a poll**:
  a refusal or an unanswered request is `request_denied` whatever the
  policy now says, and an approval is forgotten once read, so the next poll
  is decided by the rule alone.
* **Not built:** a step-up at the interaction to an `acr` a share requires
  (the session's own `acr` is recorded, and the share refuses below it); SAML
  as a `claim_token_format`; `claims_redirect_uris` in RFC 7591 dynamic
  registration (set on the application instead); and requiring a claims
  redirect URI of every public client.

## Phase 6 (#1195): the console, `/admin-api/uma`, the person's tab

| File | What it is |
|---|---|
| `uma_console.ts` | The view and the nine acts both doors call (rule 7): `view()`, `monitorView()`, `personView()`, `ownerView()`, `whatIf()`, `act()`. Built at 23d-ii after `uma_claims`, reached lazily by the API and `admin_views.ts`. |
| `web_uma.ts` | Protocols -> UMA 2.0 in the static console, a `web_` module drawn from `GET /admin-api/uma` alone. |
| `../mgmt-api/uma_api.ts` | The three operations, spread into `admin_api.ts`'s table as AuthZEN's are; built beside them at 19. |

### Decisions made here, and why

* **A person's document is read on the console and never edited there.**
  An administrator writing a share for a person would be the authorization
  server deciding for the owner, which is what UMA exists to stop. The owner
  tab edits only an APPLICATION's document (decision 5), which has nobody
  else to edit it — the console's administrators, and the application's own
  owners under `access-control`'s owner rule (`OWNER_OPERATIONS` rows for
  `GET /uma?owner=` and `POST /uma/owner-*`, projected to the owner tab
  alone; the four actions are in the template's `ownerApplicationActions`
  default, so a realm whose policy predates it refuses them until edited).
* **The what-if is on `/admin/uma`, not `/admin/xacml/decide`** (the ticket
  asked for either). The owner's layer needs the resource and the owner's
  document chosen together, and the decide page asks one policy of one
  request; here the PEP's own `decide()` is asked with `dryRun: true`, so
  every layer is the token endpoint's own question, reported layer by layer
  (`Verdict.layers`), and nothing is audited or counted.
* **A ticket is listed by twelve characters of its key**, which is a digest
  of the value (phase 1's rule): the value is a bearer artifact.
* **Disabling a resource server revokes its RPTs and keeps its
  resources.** The tokens have nobody to honour them; the registrations are
  the owners' data, and enabling it again brings them back. **Clearing
  `umaOwnsResources` keeps the application's document** for the same
  reason; the PAT the application obtains as itself is refused
  (`STS-UMA-0105`) until it is set again.
* **The person's UMA tab on `/admin/users` is read-only**, unlike the GNAP
  grants tab's Revoke: every act it could offer is on `/admin/uma`, which it
  links to by `?owner=`.

## Phase 7 (#1196): the protocol job, and Keycloak's library as the peer

`tests/protocol/sts_uma.js` drives everything over HTTP, the job as resource
server and client; section 12 drives **keycloak-authz-client 26.0.12**
(rcbj's decision 8, re-made on 2026-10-30 once it was clear Keycloak's
SERVER cannot be a UMA client of another authorization server): a thin
command line, `tests/tools/keycloak-uma-driver`, built into the tests image
as jscep's is, pointed at a loopback proxy in the job, because the library
builds its discovery address as `/realms/<name>/.well-known/
uma2-configuration` and this service answers `/realm/<id>/`.

### What the library found, and what was decided (rcbj, 2026-10-30)

| Finding | Decision |
|---|---|
| It obtains its PAT by `client_credentials` with no `scope` and no `resource`, so the token carries no `uma_protection` and is refused 401 | **Stay strict.** A PAT asks for `uma_protection` (Federated Authorization 1.3.1); the job hands the library one (`protection(String)`), and 12b asserts the bare one is refused |
| It registers a resource as `"scopes": [{"name": …}]`, Keycloak's representation, not section 3.1's `resource_scopes` | **Stay strict.** The job registers in the specification's form; 12c asserts Keycloak's is refused 400 |
| It introspects an RPT with its CLIENT CREDENTIALS and `token_type_hint=requesting_party_token`, and this service refused any hint but two (400) | **A bug, fixed**: RFC 7662 section 2.1 says an unknown hint is searched past, not refused; introspection now takes any short hint, as revocation has since #102 |
| …and, authenticated that way, it was answered no `permissions` | **Answered as the PAT door answers** (`uma_gate.permissionsFor()`), for the resource server the RPT was issued for and nobody else; in a realm whose introspection is open (development), the one client the request names is taken as said |
| It reads introspected permissions as `rsid`/`rsname`/`scopes`, so the specification's `resource_id`/`resource_scopes` reach it as nulls | **Recorded, nothing changed**; 12g asserts the count |

### AuthZEN at access time

The ticket's AuthZEN check found that `/access/v1/evaluation` never read
UMA: design point 11's "a resource server that needs the current answer asks
AuthZEN" got the root's answer. rcbj chose (2026-10-30) to make it read UMA:
the `uma_resource` type, `authzen/CLAUDE.md` (*What is decided*).

### Across nodes

A job cannot choose a node; the balancer does. So section 14 asks each
question several times per node (`STS_TEST_CLUSTER_NODES`): one ticket
presented at once from every try issues exactly one RPT (the cluster claim),
and a PCT is honoured for its client on every try and for another client on
none.

## What is deliberately not here

* `uma_profiles_supported` is empty until a profile is implemented end to
  end; SAML as a `claim_token_format` is not built; a scope description
  document is never dialled (a scope is a string); an RPT is never decided by
  the remote PEP container (nothing here rules it out either — the facts are
  engine data, as FGA's are).
* Nothing differs by mode except what already differs for every OAuth client
  (client authentication, unregistered addresses).
