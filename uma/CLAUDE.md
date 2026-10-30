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
* **The settings are homed on `/admin/xacml` until phase 6** gives the
  family its own page, as AuthZEN's are; the description page is the
  family's public face until then.

## What is deliberately not here

* `uma_profiles_supported` is empty until a profile is implemented end to
  end; SAML as a `claim_token_format` is not built; a scope description
  document is never dialled (a scope is a string); an RPT is never decided by
  the remote PEP container (nothing here rules it out either — the facts are
  engine data, as FGA's are).
* Nothing differs by mode except what already differs for every OAuth client
  (client authentication, unregistered addresses).
