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

Errors are section 8.9's JSON: `invalid_request`, `not_found`,
`invalid_trust_anchor`, `invalid_trust_chain`, `invalid_metadata`,
`temporarily_unavailable` and `server_error`.

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

`oid4vp.federationAuthorityHints` was replaced by `oidfed.authorityHints`.

## Not yet

- **OpenID Connect client registration through the federation** (automatic
  and explicit), and this service as a federated relying party (#134).
- **Extended Subordinate Listing, Entity Collection and Subordinate Events**
  (#135–#137).
