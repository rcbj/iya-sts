# oidfed/ — OpenID Federation 1.1

**Every trust realm is an OpenID Federation entity** (#132 and #133, built
2026-09-23 against the 1.1 texts). A realm publishes an Entity Configuration, a
Federation Entity Key of its own, the subordinates it vouches for, the Trust
Anchors it trusts, and the Trust Marks it issues and carries, with the endpoints
of sections 8 and 9. `federation/` is a DIFFERENT family: bilateral
relationships, each with one pinned key. This one is trust through a chain of
signed statements.

rcbj's eight answers are on #132–#137 and in the memory file
`openid-federation-decisions.md`. Four of them shaped this directory:

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

**Where it loads** (`common/protocol_stack.ts`):

- `federation_keys` and `oidfed` at **14b**, after `vc_signin`. `oauth2` and
  `vc_verifier` are reached lazily, when a document is built.
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
`caches.eject-expired`, and cleared whenever the register changes. What fills
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

## What is not here

- **Client authentication at federation endpoints** (8.8). "none" is the
  default and the only method.
- **`signed_jwks_uri`** is not published.
- **OpenID Connect registration through the federation, and the RP side**:
  #134.
- **Extended listing, entity collection and subordinate events**: #135–#137.
  `oidfed_store.ts` keeps created and updated times on every subordinate,
  which #135's `updated_after` needs.

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

**Still untested:**

- a resolution through a real foreign entity over HTTP. The fetcher is covered
  by a stub, and `fetchPublished()` by the federation tests;
- a post-quantum Federation Entity Key end to end.
