# oidfed/ — OpenID Federation 1.1

**Every trust realm is an OpenID Federation entity** (#132 and #133, built
2026-09-23 against the 1.1 texts). A realm publishes an Entity Configuration, a
Federation Entity Key of its own, the subordinates it vouches for, the Trust
Anchors it trusts, and the Trust Marks it issues and carries, with the endpoints
of sections 8 and 9. `federation/` is a DIFFERENT family: bilateral
relationships, each with one pinned key. This one is trust through a chain of
signed statements.

**And three extensions (#135–#137, 2026-09-24)**, each against the editors'
draft rcbj named: the Extended Subordinate Listing (draft 03), the Entity
Collection Endpoint (draft 01) and the Subordinate Events Endpoint (draft
01).

rcbj's eight answers are on #132–#137 and in the memory file
`openid-federation-decisions.md`, with branch 3's three more on #135–#137.
Four of the eight shaped this directory:

- **Every role, per realm.** By default the default realm is a Trust Anchor and
  every other realm is its Subordinate (`oidfed.realmsAreSubordinates`).
- **Trust marks in full.**
- **A Federation Entity Key of its own.**
- **Resolution walks only toward a configured Trust Anchor.**

## The files

| File | What it is |
|---|---|
| `metadata_policy.ts` | **Pure.** Section 6. The seven operators; validating one statement's policy; the top-down merge; application in operator order; the three constraints. Tested against 6.1.5 and table 1 (`tests/oidfed_metadata_policy.js`). |
| `entity_statement.ts` | **Pure.** The six typed JWTs, made with `EntityStatement.sign()` and read with `EntityStatement.verify()`. The `typ` must match exactly, the algorithm must be asymmetric, and the `kid` must name EXACTLY one key. Section 3.2's per-statement checks are `validateClaims()`. |
| `trust_chain.ts` | Section 10 and 7.3. `validate()` a presented chain; `resolve()` by walking `authority_hints`; `validateTrustMark()` and `validateDelegation()`. Its deps are injected: a fetcher, and `local()` for entities this process answers for itself. |
| `oidfed_store.ts` | The register. Entries under `ou=oidfed` in the realm's own directory tree (`ldap/CLAUDE.md`), of seven kinds: keys, subordinate, anchor, mark-type, issued-mark, held-mark and mark-policy. |
| `federation_keys.ts` | The Federation Entity Key table, and its two scheduler jobs (`oidfed.key-rotate`, `oidfed.key-rotate-now`). |
| `oidfed.ts` | The entity: its identity, topology, Entity Configuration, Subordinate Statements, resolution and cache, Trust Marks, the routes, and the acts behind the console and the API. |
| `oidfed_admin.ts` | Protocols → OpenID Federation (`/admin/oidfed`). |
| `oidfed_api.ts` | `GET /admin-api/oidfed` and `POST /admin-api/oidfed/:action`. |
| `oidfed_registration.ts` | #134, the OP side of Connect 1.1 section 12: AUTOMATIC registration, called from `oauth2.ts`'s authorization and PAR endpoints before anything reads the client, and EXPLICIT registration at `POST /oidfed/register`. Both verify the RP's chain to one of the realm's anchors and hold its resolved metadata to `oauth2.registerFederatedClient()`, the same checks as RFC 7591. A registration expires with its chain (12.3): `clientConfigOf()` answers "unknown" past it, and the `oidfed.registrations-expire` job removes it. **It is not a mode exception** (rcbj's answer 5): product mode refuses a client NOBODY registered, and this one was registered, through a Trust Anchor the administrator configured, by a request proving the RP's key. The header argues it. |
| `page_pointer.ts` | #135, #136. The opaque `from` / `next` pointer both paged endpoints share: the Entity Identifier of the next page's first entity, MACed under the `oidfed-page` cluster secret over the realm and the endpoint, so "unknown" (`page_not_found`) means exactly "not one this service made here". The MAC is `crypto.js`'s. |
| `subordinate_events.ts` | #137. A subordinate's history, KEPT FOR GOOD: an `events` entry per subordinate, one JSON event per `stsOidfedEvent` value, merged by value across a cluster. The draft's six event types and four of this service's own (`reinstatement`, `constraints_update`, `trust_mark_issuance`, `trust_mark_revocation`). A realm of this service is keyed `realm:<id>` — see below. |
| `extended_listing.ts` | #135. `/oidfed/extended-list`: every list filter, paging, `updated_after` / `updated_before` / `audit_timestamps` from the history, and `claims`. **An entry is its `id` alone unless `claims` asks for more**, because `subordinate_statement` is a signature on an anonymous endpoint. |
| `entity_collection.ts` | #136. `/oidfed/collection`, the crawl behind it, the `oidfed.collection-crawl` job and the `oidfed.collections` cache. Its header argues the fetches. |
| `oidfed_rp.ts` | #134, this service as a federated RP. An `oidc` relationship with `fedTrustAnchor` set has its OP resolved through its chain. It registers automatically under the realm's Entity Identifier, with a request object and `private_key_jwt` signed by the realm's ES256 protocol key, which the Entity Configuration's `openid_relying_party` metadata publishes by value. |

**Where it loads** (`common/protocol_stack.ts`):

- `federation_keys` and `oidfed` at **14b**, after `vc_signin`. `oauth2` and
  `vc_verifier` are reached lazily, when a document is built.
- `extended_listing` and `entity_collection` (#135, #136) at **14b** too,
  built after `oidfed`, which serves their routes and reaches both lazily;
  the collection's wire step registers `oidfed.collection-crawl`.
  `subordinate_events` and `page_pointer` are plain libraries.
- `oidfed_admin` at **23g-ii**, after the console, whose shell it draws with.
- `oidfed_api` beside the other `_api` modules, before `mgmt-api/admin_api`.

## The Entity Identifier is the realm's issuer

OpenID Federation for OpenID Connect 1.1 section 5.1.2 says the
`openid_provider` metadata's `issuer` MUST be the Entity Identifier. So a
realm's Entity Identifier is `oauth2.issuerOf(baseUrlOf(req))`, which honours a
pinned `oauth2.issuer`. The Entity Configuration is served per realm at
`/.well-known/openid-federation` under the realm prefix. The `/oidfed/*`
endpoints are under the realm's base URL.

**`localRealmOf()` finds a realm by its Entity Identifier.** It computes each
realm's identifier from the CURRENT request (`requestIn()`, run inside that
realm), because an identifier depends on the host the request arrived on. A
background job with no request resolves no local entity. That is why no job
resolves anything.

## The key is not a unit of the key generations, and that is argued

`federation_keys.ts`'s header carries the argument. In short:

- **Protocol key readers publish everything they hold.** Almost every reader
  of `helpers.js`'s generations publishes its keys (the JWKS, the metadata,
  the "is this ours" check). A federation key placed among them would need
  filtering out of every one of those readers. 3.1.1 says it SHOULD NOT be used
  in other protocols.
- **Historical Keys needs retired keys kept.** Section 8.7 wants retired keys
  kept for good, and the generations drop them at their grace.
- **So it follows #168's arrangement.** A table on the realm's `ou=oidfed`
  `keys` entry, private halves sealed with `keystore.seal()` (label
  `oidfed-key`) wherever a KEK exists, rotated by a job of its own.
- **One key maker, one signer.** The key is made by
  `helpers.makeFederationKey()`, which uses the curve and post-quantum recipes
  a signing unit's next key uses. Signing is `crypto.js`'s.
- **Not a PKI leaf**, by nature. A federation trusts a key through the
  statements above it (`docs/pki.md`'s "every key pair is a leaf" has this
  exception, with the BBS key and SPIFFE's JWT authority).

**Row states:** `next` → `current` → `retired`.

- **A retired row drops its private key at once.** Its public half is still
  published until `publishedUntil`, which is the overlap after it stopped
  signing.
- **Revoking a row** takes it out of the published JWKS at once. The current
  or next key is revoked only by an emergency rotation (STS-OIDFED-0042).
- **`historical()`** is every retired or revoked row, with `iat`, `exp` and
  `revoked`.

**The first key is minted on first use**, under a cluster claim
(`oidfed.key-mint`). A node that loses the claim answers
`temporarily_unavailable` (STS-OIDFED-0043) until the directory's change log
brings it the winner's row.

**A rotation and a revocation are announced over Shared Signals (#245).**
`rotate()` and `revoke()` send `federation-key-rotated` through
`ssf/service_signals.ts` (the `signals` dep, reached lazily), in the realm. The
reason is `scheduled` from the job and `requested` by hand. An emergency sends
`emergency`, naming the next key it revoked. A retired key revoked as
`compromised` sends `emergency` too. A next key that is only PUBLISHED is not
announced: it signs nothing yet, and the rotation that promotes it says so. The
subordinate history (#137) is recorded as before. `ssf/CLAUDE.md` argues the
sibling URN.

## Resolution, and the fetches it makes

`trust_chain.ts`'s header is the argument for dialling URLs a caller named. It
is also a row in the root `CLAUDE.md`'s non-goal index. The bounds:

- `oidfed.maxAuthorityHints` per entity;
- `oidfed.maxChainDepth`;
- `oidfed.maxFetchesPerResolution` in total;
- loop detection;
- `fetchPublished()`'s outbound policy: https, a verified certificate, no
  redirect, a size cap and a timeout, with internal addresses refused in
  product mode.

**This service's own realms are resolved IN PROCESS** (`localEntity()`). They
are never dialled over HTTP.

**THE RESOLVE ENDPOINT NEVER STARTS A WALK** (18.1). It uses a resolver whose
fetcher refuses everything, so it answers only for:

- this service's own realms;
- what the `oidfed.resolutions` cache holds.

The cache is per process and per realm, bounded, ejected by
`caches.eject-expired`, and cleared whenever the register changes. **Cleared
in EVERY process**, which a per-process clear is not: each entry carries the
realm's register generation (`oidfed.registerGeneration`, a persisted and
replicated store), every act that changes the register replaces it, and an
entry made under an older one is not answered. Before that, a Trust Mark
issued on one request worker was missing from the resolve response another
worker answered from its cache (`sts_oidfed`, single-node, 2026-09-24). What fills
it is an administrator's `resolve` act. #134's automatic registration will be
the second thing.

## Trust Marks

- **Issuing.** A type is registered (`mark-type`) before marks of it are
  issued. Every mark has an `exp`: 7.1 allows none, and none would outlive any
  decision to withdraw the mark.
- **Delegation.** A type owned elsewhere carries the owner's delegation JWT,
  which is checked to be for this realm and this type when the type is
  registered.
- **The issued register** is keyed by the JWT's digest. That is how the status
  endpoint tells "ours" (active, expired or revoked) from "not ours" (404,
  8.4.2).
- **A mark issued to one of this service's realms is HANDED to that realm**
  (`held-mark`), so its Entity Configuration carries the mark at once.
- **As a Trust Anchor**, a realm publishes `trust_mark_issuers`: its
  `mark-policy` entries, plus its own types naming itself.
- **Verifying a mark in a resolution** follows 7.3. The issuer's keys come from
  the issuer's own chain to the same anchor, or from the anchor's configured
  keys when the issuer is the anchor. A mark this realm issued is also checked
  against the issued register, so a revoked one is dropped.

## The three extensions (#135–#137)

**SUSPENSION IS A STATE, REVOCATION IS REMOVAL** (rcbj, 2026-09-24). A
`suspension` entry beside a subordinate makes `subordinateStatementClaims()`
answer `not_found` (STS-OIDFED-0057), so no chain passes through it, and
`activeSubordinates()` — what both listings and the collection read — leaves
it out. `subordinates()` still returns it, marked, for the console and the
events endpoint. Removing a subordinate records its `revocation` and deletes
its suspension.

**THE HISTORY OUTLIVES THE SUBORDINATE** and nothing deletes it. A
registration is recorded ALONE (the draft forbids update events beside it);
a later `add-subordinate` records one update event per part of the statement
that changed (`updatesBetween()`). The endpoint prepends a `registration` at
the register's own creation time for a subordinate registered before #137.

**A REALM OF THIS SERVICE IS KEYED `realm:<id>`.** Its creation, its own key
rotation and its deletion happen with no request, and a realm's identifier
depends on the host a request arrived on. So `oidfed.ts`'s `watchRealms()`
records creation and deletion (from `realms.onChange()`; `realms.remove()`
passes the realm's `createdAt` since #137 so every node derives the same
event id), and `federation_keys.ts` records a published or revoked key — all
in the DEFAULT realm's register. `eventKeyOf()` maps an identifier back: a
live realm by asking each which identifier it has, a deleted one by its
prefix on this request's base (assuming it pinned no `oauth2.issuer`).

**THE COLLECTION CRAWL NEEDS A STABLE IDENTIFIER.** A crawl is kept in the
realm's register (the `collection` entry) so every node and every request
worker answers from the same one, and it is used only while the identifier
it was crawled for is the realm's. The scheduled job therefore runs only
where `global.publicBaseUrl` pins the base; Crawl now uses the
administrator's request. **A kept crawl is never the whole answer**: the
endpoint collects in process (no fetch) every time — cached per process under
a fingerprint of the realms and the active subordinates — and adds from the
crawl only what it reached through a subordinate that is still active. The
first version answered from the crawl alone, and a realm made a minute after
a Crawl now went unlisted for `oidfed.collectionMaxAgeS`.
**`trust_anchor` may be only the realm itself** (rcbj's answer): the
collection is of the realm's own subtree.

**THE THREE ENDPOINTS ARE PUBLISHED BY A SUPERIOR**: the listing and the
collection wherever the fetch and list endpoints are, and the events endpoint
also while any history is kept — a superior whose last subordinate was
revoked still answers for it.

## What is not here

- **Client authentication at federation endpoints** (8.8). "none" is the
  default and the only method.
- **`signed_jwks_uri`** is not published.
- **The RP side registers only automatically**, and sends no `trust_chain`
  header (a URL carrying a chain is longer than many servers accept, and PAR
  would be a fourth address `federation_http.ts` dials). An OP offering only
  explicit registration is refused by name (STS-FED-0149).
- **OID4VP trusting a credential issuer through the federation** (#134's
  optional follow-on) is not built.
- **An Entity Collection anchored elsewhere**: `trust_anchor` other than the
  realm is `invalid_trust_anchor` by decision, not by omission.
- **The Subordinate Events endpoint's POST form**, which exists for client
  authentication (8.8).

## Tests

- `tests/oidfed_metadata_policy.js`: section 6, against the specification's
  own examples.
- `tests/oidfed_trust_chain.js`: validation, walks, bounds, constraints and
  Trust Marks, over a federation built with real keys.
- `tests/oidfed_entity.js`: the default realm as Trust Anchor with a realm
  beneath it, in process.
- `tests/vendored/sts_oidfed.js` (local): the same over HTTP, with Trust Marks
  and key rotation through `/admin-api`.
- `tests/siop.js` 7f: the verifier's `openid_federation:` client identifier.
- `tests/oidfed_extensions.js`: the page pointer; a subordinate's history
  through registration, updates, suspension, reinstatement and revocation;
  a realm's creation, rotation and deletion; the Extended Listing's paging,
  claims and filters; the Entity Collection in process and by a CRAWL through
  a foreign Intermediate over a stub requester, with the fetch budget.
- `tests/vendored/sts_oidfed_extensions.js` (local): the three endpoints over
  HTTP, and the acts through `/admin-api`.

**Still untested:**

- a resolution through a real foreign entity over HTTP. The fetcher is covered
  by a stub, and `fetchPublished()` by the federation tests;
- a post-quantum Federation Entity Key end to end.
