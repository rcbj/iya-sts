---
title: OpenID Federation
nav_order: 14
---

# OpenID Federation

Every trust realm of iya-sts is an **OpenID Federation 1.1** entity
([OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html),
[for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)).
OpenID Federation lets two entities trust each other without being configured
with each other. Each entity publishes signed statements, and a superior signs
statements about its subordinates. That chain of signatures ends at a **Trust
Anchor**, whose key you configured.

```
  Trust Anchor  (the default realm)      its keys are configured out of band
       │  Subordinate Statement: "realm acme's keys are these"
       ▼
  Leaf          (realm acme)             /realm/acme/.well-known/openid-federation
```

## The default topology: one service, one federation

By default (`oidfed.realmsAreSubordinates`, on):

- **The default realm is a Trust Anchor.** It names no superior, and it
  publishes fetch and list endpoints for every other realm.
- **Every other realm is a Leaf** under it. It names the default realm in
  `authority_hints` and trusts it as its Trust Anchor.

A realm's role follows from its register:

| Role | When |
|---|---|
| **Trust Anchor** | It names no superior. |
| **Intermediate** | It names a superior and vouches for somebody. |
| **Leaf** | It names a superior and vouches for nobody. |

To place a realm under a different superior, add that superior to
`oidfed.authorityHints`. A realm that should be its own Trust Anchor needs
`oidfed.realmsAreSubordinates` off.

## The Entity Identifier

**A realm's Entity Identifier is its issuer**: the `issuer` of its OpenID
Connect discovery document. Section 5.1.2 of the OpenID Connect companion
specification requires the two to be equal. Its Entity Configuration is at that
identifier plus `/.well-known/openid-federation`.

| Realm | Entity Identifier | Entity Configuration |
|---|---|---|
| default | `https://sts.example` | `https://sts.example/.well-known/openid-federation` |
| `acme` | `https://sts.example/realm/acme` | `https://sts.example/realm/acme/.well-known/openid-federation` |

The Entity Configuration carries these entity types:

- `federation_entity`, with the realm's endpoints and `oidfed.organizationName`,
  `contacts`, `logoUri`, `policyUri` and `organizationUri`;
- `openid_provider` and `oauth_authorization_server`, which are the realm's
  discovery documents;
- `openid_credential_verifier`, the OpenID4VP verifier.

## Endpoints

Every endpoint is per realm, under the realm's prefix, and answers with
`Cache-Control: no-store`.

| Endpoint | Section | What it does |
|---|---|---|
| `GET /.well-known/openid-federation` | 9 | The Entity Configuration (`application/entity-statement+jwt`). |
| `GET /oidfed/fetch?sub=` | 8.1 | The Subordinate Statement about one subordinate. Published only by a realm that vouches for somebody. |
| `GET /oidfed/list` | 8.2 | The Immediate Subordinates. Filters: `entity_type`, `trust_marked`, `trust_mark_type`, `intermediate`. |
| `GET /oidfed/resolve?sub=&trust_anchor=` | 8.3 | A signed `resolve-response+jwt`: the subject's resolved metadata, its Trust Chain and its verified Trust Marks. |
| `GET /oidfed/trust-mark?trust_mark_type=&sub=` | 8.6 | A still-valid Trust Mark this realm issued. |
| `POST /oidfed/trust-mark-status` | 8.4 | Whether a mark this realm issued is `active`, `expired` or `revoked`. |
| `GET /oidfed/trust-mark-list?trust_mark_type=` | 8.5 | The entities holding a valid mark of the type. |
| `GET /oidfed/historical-keys` | 8.7 | Every Federation Entity Key the realm has retired or revoked, signed. |
| `GET /oidfed/extended-list` | Extended Listing, draft 03 | The Immediate Subordinates, paged, with what you ask for about each. Published by a realm that vouches for somebody. See [below](#the-extended-subordinate-listing). |
| `GET` or `POST /oidfed/collection` | Entity Collection, draft 01 | Every entity beneath the realm, with display information and Trust Marks. See [below](#the-entity-collection). |
| `GET /oidfed/subordinate-events?sub=` | Subordinate Events, draft 01 | A subordinate's history, signed. See [below](#subordinate-history-suspension-and-revocation). |

Errors are section 8.9's JSON: `invalid_request`, `not_found`,
`invalid_trust_anchor`, `invalid_trust_chain`, `invalid_metadata`,
`temporarily_unavailable` and `server_error` — and, from the extensions,
`page_not_found` and `unsupported_claim`.

**The resolve endpoint never walks the federation for an anonymous caller**
(section 18.1). It answers only in two cases:

- **One of this service's own realms**, which it resolves in process.
- **An entity an administrator has already resolved.** That can be done on
  the console, or with `POST /admin-api/oidfed/resolve`. The result is cached
  until the chain expires, for at most `oidfed.resolveCacheS`.

**Client authentication at federation endpoints** (section 8.8) is not
offered. Every endpoint takes unauthenticated requests, which is the
specification's default.

## Federation Entity Keys

Each realm signs its federation statements with a **Federation Entity Key**,
separate from its protocol signing keys (section 3.1.1: those keys SHOULD NOT
be used in other protocols).

**Algorithm.** Set by `oidfed.signingAlg`:

- **ES256** is the default, because every federation implementation verifies
  it.
- ES384, ES512 and EdDSA are also offered.
- ML-DSA-44, ML-DSA-65 and ML-DSA-87 are post-quantum. Use them in a
  federation whose members can verify them.

**Key id.** A key's `kid` is its RFC 7638 thumbprint.

**How a key changes over time.** The published set is always one rotation
ahead:

1. **Next.** A new key is published before it signs anything.
2. **Current.** It signs every statement.
3. **Retired.** It is still published for `oidfed.keyOverlapDays`, then is
   listed at the Historical Keys endpoint for good. Its private half is
   dropped the moment it is retired.

**When keys rotate.**

- In product mode the `oidfed.key-rotate` job rotates a key once it is older
  than `oidfed.keyRotationDays`, and only after its successor has been
  published for the whole overlap.
- You can rotate by hand on the console or with
  `POST /admin-api/oidfed/rotate-key`.
- An **emergency rotation** needs `confirm: "compromised"`. It revokes the
  current and next keys as compromised and replaces them at once.
- A retired key can be revoked later with a reason: `unspecified`,
  `compromised` or `superseded`.

**Storage.** Private keys are sealed under the key-encryption key wherever keys
persist. These keys are not X.509 leaves of the service's certificate
authority: a federation trusts a key through the statements above it, not
through a certificate path.

## Subordinates and Trust Anchors

**Registering a subordinate vouches for it.** Register one on `/admin/oidfed`
or with `POST /admin-api/oidfed/add-subordinate`. The fetch endpoint then
issues a statement about it carrying:

- **its keys**, given as a JWK Set or read from its own Entity Configuration
  (`fetchJwks`);
- **`metadata`** that overrides its own;
- **a `metadata_policy`**: the seven operators of section 6.1, merged with its
  superiors' and applied in order. `scope` is treated as a list;
- **`metadata_policy_crit`**;
- **`constraints`**: `max_path_length`, `naming_constraints` and
  `allowed_entity_types`.

A policy that combines operators the specification forbids is refused when you
save it.

**Suspending a subordinate** (**Suspend** on the console, or
`POST /admin-api/oidfed/suspend-subordinate`) stops the realm vouching for it
without forgetting it. The fetch endpoint answers `not_found` about it, and
neither listing includes it, so no Trust Chain passes through it until it is
reinstated (`reinstate-subordinate`). A realm beneath the default realm can be
suspended too.

**Revoking a subordinate** (**Revoke**, or `remove-subordinate`) removes it.
Both acts take an optional `reason` and `informationUri`, which go into the
subordinate's history.

**A Trust Anchor** is registered with its entity identifier and its keys.
A Trust Chain may end only at a configured anchor, and the chain is checked
against the keys configured for that anchor.

## Resolving another entity

`POST /admin-api/oidfed/resolve` (or **Resolve** on the console) resolves an
entity to one of the realm's Trust Anchors:

1. It walks the entity's `authority_hints` upward, fetching each Entity
   Configuration and each superior's Subordinate Statement.
2. It verifies every signature, the linkage between statements and the
   constraints.
3. It applies the chain's metadata policy.
4. It verifies each Trust Mark against its issuer, whose own chain is
   established first.

Where several chains are valid, the shortest wins.

The walk is bounded:

- `oidfed.maxAuthorityHints` hints per entity;
- `oidfed.maxChainDepth` statements;
- `oidfed.maxFetchesPerResolution` fetches in all;
- each fetch within `oidfed.fetchTimeoutMs` and `oidfed.fetchMaxBytes`, https
  only, with no redirects.

Every fetch follows the outbound policy (`federation.outbound`). In product
mode, internal addresses are refused.

## Trust Marks

**Issuing.** Register a type the realm issues, then issue marks of it:

- **Issue** on the console, or `issue-trust-mark` through the API.
- A mark for one of this service's own realms is handed to that realm at
  once, and its Entity Configuration carries it.
- A foreign subject collects its mark from the Trust Mark endpoint.

Every mark expires. A type's lifetime defaults to `oidfed.trustMarkLifetimeS`.

**A type owned by another entity** is registered with the
`trust-mark-delegation+jwt` its owner issued to this realm. Every mark of that
type then carries the delegation (7.2).

**Revoking** a mark makes its status `revoked`: the status endpoint reports
it, the listing drops it, and resolution drops it too.

**Carrying a foreign mark.** A realm carries a mark issued to it by somebody
else once you paste it on the console or send it with `add-held-mark`.

**As a Trust Anchor**, a realm publishes `trust_mark_issuers` and
`trust_mark_owners`:

- A **mark policy** sets them for a type: who may issue it, and who owns it.
- Every type the realm issues itself names the realm as its issuer, unless a
  policy says otherwise.

## Subordinate history, suspension and revocation

A superior keeps the history of each of its subordinates **for good**, and
serves it at `/oidfed/subordinate-events?sub=` as a signed
`application/entity-events-statement+jwt`
([Subordinate Events Endpoint 1.0, draft 01](https://openid.net/specs/openid-federation-subordinate-events-1_0.html)).
The history outlives the subordinate: revoking one records the revocation and
deletes nothing, so the endpoint still answers for it.

| Event | Recorded when |
|---|---|
| `registration` | the subordinate is registered — alone, as the draft requires; the update events below follow only later changes |
| `jwks_update` | its keys change; for a realm beneath the default realm, whenever that realm's own Federation Entity Key rotates or is revoked |
| `metadata_update`, `metadata_policy_update` | the `metadata` or `metadata_policy` its statement carries changes |
| `suspension`, `revocation` | it is suspended, or revoked (a deleted realm is revoked) |
| `reinstatement` * | a suspended subordinate is reinstated |
| `constraints_update` * | the `constraints` its statement carries change |
| `trust_mark_issuance`, `trust_mark_revocation` * | this realm issues it a Trust Mark, or revokes one |

\* This service's own event types. The draft lets a federation operator
define more, and these four cover what its six do not.

Each event carries `iat`, and `event_description` and `information_uri` where
the administrator gave a reason or a page. A realm of this service beneath the
default realm is registered when it is created and revoked when it is
deleted, and after deletion it is answered under the identifier it had.

The console lists each subordinate's history under **History**, and the
revoked ones under **Former subordinates**. `GET /admin-api/oidfed` returns
both.

## The Extended Subordinate Listing

`/oidfed/extended-list`
([Extended Subordinate Listing 1.0, draft 03](https://openid.net/specs/openid-federation-extended-listing-1_0.html))
lists the same subordinates as `/oidfed/list`, but paged and with more about
each:

- **Every list filter**: `entity_type`, `trust_marked`, `trust_mark_type`
  (repeat it to match any of several types) and `intermediate`.
- **`limit` and `from`.** A page is at most `oidfed.listPageMax` entities. A
  response with more to come carries `next`; pass it back as `from`. A `from`
  this realm did not hand out is `404 page_not_found`.
- **`updated_after` and `updated_before`** (seconds since the epoch), and
  **`audit_timestamps=true`** to return each entry's `registered` and
  `updated` times. Both come from the subordinate's history.
- **`claims`**, comma-separated or repeated: `subordinate_statement` (the
  signed statement), `trust_marks`, or any claim of the Subordinate Statement
  (`jwks`, `metadata`, `metadata_policy`, `constraints`, …).

**With no `claims`, each entry is its `id` alone.** The endpoint is anonymous
and a statement is a signature, so statements are returned only when asked
for, one page at a time.

## The Entity Collection

`/oidfed/collection`
([Entity Collection Endpoint 1.0, draft 01](https://openid.github.io/federation-entity-collection/main.html))
lists **every entity beneath the realm** — its subordinates, theirs, and so on
— for a login picker or a catalogue. Each entry has:

- `entity_id` and `entity_types`;
- `ui_infos`: per entity type, the informational metadata of section 5.2.2
  (`display_name`, `description`, `keywords`, `logo_uri`, `policy_uri`,
  `information_uri`), with language-tagged forms such as `display_name#de`.
  Where a relying party has no `display_name`, its `client_name` is used;
- `trust_marks`, verified.

**Only entities whose Trust Chain to the realm validates are listed**, with
their metadata as resolved through every policy above them. The response
itself is not signed and is informational: anyone relying on an entity it
names must still validate that entity's Trust Chain.

Parameters: `entity_type` (repeat for any of several), `trust_mark_type`
(repeat to require all), `query` (matched against the identifier, names,
descriptions and keywords), `entity_claims`, `ui_claims`, `limit` and `from`.
`trust_anchor` may only be the realm itself; any other value is
`404 invalid_trust_anchor`. A claim this service does not return is
`400 unsupported_claim`. The response carries `last_updated`.

**Where the collection comes from.** Collecting below an Intermediate outside
this service means fetching its list, and then each listed entity's
configuration. That is a **crawl**, and nothing an anonymous request asks for
starts one:

- **Crawl now** on `/admin/oidfed`, or
  `POST /admin-api/oidfed/crawl-collection`, crawls with your request's
  address as the realm's Entity Identifier.
- **The `oidfed.collection-crawl` job** crawls every
  `oidfed.collectionCrawlS`, but only where `global.publicBaseUrl` pins the
  Entity Identifier. A job has no request of its own to take it from, and
  `/admin/scheduler` says so.

A crawl fetches a list only from an entity whose chain has already validated,
through the outbound policy (https, a verified certificate, no redirect, a
size cap and, in product mode, no internal address). It collects at most
`oidfed.collectionMaxEntities` entities and fetches at most
`oidfed.collectionMaxFetches` lists. The realm keeps the crawl in its
directory, so every node answers from the same one, for up to
`oidfed.collectionMaxAgeS`.

**The crawl is added to, never answered alone.** What the service can
collect without fetching — its own realms, and subordinates an earlier
resolution already holds — is always collected fresh. The crawl adds the
entities it reached through a subordinate that is still active. So a realm
created after a crawl appears at once, and suspending or revoking a
subordinate removes everything beneath it at once. Only a new foreign
subordinate's own subtree waits for the next crawl. Each process keeps its
fresh part for `oidfed.collectionCacheS`, and makes it again whenever the
realms or the active subordinates change.

## Settings

All are per realm and changeable while running. They are listed in
[Configuration](configuration.md) and drawn on `/admin/oidfed`.

| Setting | Default | What it does |
|---|---|---|
| `oidfed.signingAlg` | `ES256` | The algorithm new Federation Entity Keys are made for. |
| `oidfed.keyRotationDays` | 180 | How long a key signs before the schedule rotates it (product mode). |
| `oidfed.keyOverlapDays` | 14 | How long a next key is published before it signs, and a retired key after it stops. |
| `oidfed.statementLifetimeS` | 86400 | The `exp` of the Entity Configuration and every Subordinate Statement. |
| `oidfed.realmsAreSubordinates` | on | The default realm vouches for every other realm, and they trust it. |
| `oidfed.authorityHints` | *(empty)* | Superiors named besides the default realm. |
| `oidfed.organizationName`, `contacts`, `logoUri`, `policyUri`, `organizationUri` | *(empty)* | Informational `federation_entity` metadata (5.2.2). |
| `oidfed.trustMarkLifetimeS` | 31536000 | A mark type's lifetime when none is given. |
| `oidfed.maxAuthorityHints`, `maxChainDepth`, `maxFetchesPerResolution` | 5, 6, 24 | The bounds on a resolution (18.1). |
| `oidfed.fetchTimeoutMs`, `fetchMaxBytes` | 5000, 262144 | The bounds on one fetch. |
| `oidfed.resolveCacheS`, `resolveCacheMax` | 3600, 1000 | How long and how many resolutions are kept for the resolve endpoint. |
| `oidfed.clockSkewS` | 60 | The leeway on `iat` and `exp`. |
| `oidfed.listPageMax` | 50 | The longest page of the Extended Subordinate Listing and the Entity Collection. |
| `oidfed.collectionCrawlS` | 3600 | How often the collection crawl runs; 0 is off. Needs `global.publicBaseUrl`. |
| `oidfed.collectionMaxEntities`, `collectionMaxFetches` | 500, 100 | The bounds on one crawl. |
| `oidfed.collectionMaxAgeS` | 86400 | How long the entities a crawl found beyond this service are served. |
| `oidfed.collectionCacheS` | 300 | How long a process keeps what it collects without fetching; changed realms or subordinates make it again at once. |

`oid4vp.federationAuthorityHints` was replaced by `oidfed.authorityHints`.

## Client registration through the federation

A realm's OpenID Provider registers relying parties it was never configured
with, when a Trust Anchor it trusts vouches for them
(`oidfed.clientRegistrationTypes`, default `automatic,explicit`). This is the
same in development and product mode.

- **Automatic.** The RP's first authorization or PAR request uses its Entity
  Identifier as `client_id`. It proves it holds its key with a signed request
  object, or with a `private_key_jwt` at PAR. The request's `aud` must be this
  OP alone.
- **Explicit.** The RP POSTs its Entity Configuration, with `aud` naming this
  OP, to `/oidfed/register`. It can also send a Trust Chain beginning with
  that configuration, as `application/trust-chain+json`. The answer is a
  signed `explicit-registration-response+jwt`.

Either way, the RP's chain must reach one of the realm's Trust Anchors. Its
resolved `openid_relying_party` metadata is then checked like any RFC 7591
registration. The registration lasts until the chain expires, or for at most
`oidfed.registrationLifetimeS`.

**This service as a federated RP.** Set `fedTrustAnchor` on an OpenID Connect
federation relationship, with `fedPeer` as the OP's Entity Identifier. The OP
is then discovered through its Trust Chain and registered with automatically.
The realm's Entity Configuration publishes `openid_relying_party` metadata
carrying its signing key.

## Not yet

- As an RP, this service registers only automatically.
- Trusting a credential issuer through the federation (OpenID4VP).
- An Entity Collection anchored at a Trust Anchor other than the realm itself.
- Client authentication at any federation endpoint (section 8.8), including
  the POST form of the Subordinate Events endpoint.
