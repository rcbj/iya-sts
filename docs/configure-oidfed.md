---
title: "Configuring OpenID Federation"
---

# Configuring OpenID Federation

This page shows how to set up a trust realm of iya-sts as an OpenID
Federation 1.1 entity: as a Trust Anchor, an Intermediate or a Leaf, with
its subordinates, the Trust Anchors it trusts, the Trust Marks it issues and
carries, client registration through the federation, and this service as a
federated relying party. Each recipe is given twice: once as steps in the
**admin console** and once as **Management API** calls.

The values come from this repository's test jobs, and each recipe names the
job it is taken from. The jobs add a run stamp to every realm and entity
identifier; it is left out here. Change the identifiers and keys to your own.

What each part *is*, every endpoint, and every setting with its default, are
on [OpenID Federation](oidfed.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token and the `api` shell helper used
below. A bilateral relationship with one pinned key is a different thing, on
[Configuring federation](configure-federation.md).

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/oidfed` | **Protocols → OpenID Federation** | **Metadata**: the realm's Entity Identifier, role, authority hints, endpoints and the claims of its Entity Configuration. Then one tab per register, below. |
| the **Federation Entity Keys** tab | | **Rotate now**, **Emergency rotation**, and **Revoke** on a retired key. |
| the **Subordinates** tab | | **Register the subordinate**; **Suspend**, **Reinstate** and **Revoke** on each. **History** and **Former subordinates**. |
| the **Entity Collection** tab | | **Crawl now**. |
| the **Trust Anchors** tab | | **Trust it**; **Remove** on each. |
| the **Trust Marks** tab | | **Issue this type**; **Issue** a mark of a type; **Revoke** an issued mark; **Carry it**; and, as a Trust Anchor, **Set the policy**. |
| the **Resolve an entity** tab | | **Resolve**. |
| the **Settings** tab | | The `oidfed.*` settings, saved with **Save OpenID Federation**. |

Every act on the page is `POST /admin-api/oidfed/<action>` with a JSON body,
and `GET /admin-api/oidfed` answers everything the page draws. The settings
are written with `POST /admin-api/config/set` or `/config/set-many`.

Each [trust realm](trust-realms.md) is its own entity. Work in a realm under
`/realm/<id>/admin/oidfed`, or with `BASE` set to `https://<host>/realm/<id>`
for the API calls. A realm's Entity Identifier is its OAuth 2.0 issuer, and
its Entity Configuration is that identifier plus
`/.well-known/openid-federation`.

## What development and product mode change

* **The Federation Entity Keys.** Product mode rotates them on a schedule:
  the `oidfed.key-rotate` job replaces a key older than
  `oidfed.keyRotationDays`. Development does not rotate on a schedule, and a
  development process whose directory is not persisted makes new keys at
  every start. **A peer that pinned a development realm's key must pin it
  again after a restart.** A rotation by hand works in both modes.
* **Fetching.** Every fetch a resolution or a crawl makes goes through the
  federation outbound policy (`federation.outbound`, `https`, no redirect, a
  size cap and a timeout). Product mode also refuses an internal address.
  Name a privately certified peer's CA in `federation.outboundCaFile`.
* **Client registration through the federation is the same in both modes.**
  A relying party registered through a Trust Anchor you configured is a
  registered client in product mode too.

## The default topology

Nothing has to be configured for this. With `oidfed.realmsAreSubordinates`
on (the default), the default realm is a Trust Anchor and every other realm
is a Leaf beneath it. Creating a realm is enough. Taken from `sts_oidfed.js`:

```bash
api realms/create '{"id":"fed","domain":"fed.example.net","name":"OpenID Federation"}'

curl -sk https://<host>/.well-known/openid-federation            # the Trust Anchor
curl -sk https://<host>/realm/fed/.well-known/openid-federation  # the Leaf, naming it in authority_hints
curl -sk "https://<host>/oidfed/fetch?sub=https://<host>/realm/fed"
curl -sk "https://<host>/oidfed/resolve?sub=https://<host>/realm/fed&trust_anchor=https://<host>"
```

Each answer is a signed `application/entity-statement+jwt` (the resolve
endpoint's, a `resolve-response+jwt`). The **Metadata** tab of
`/admin/oidfed` shows the realm's role.

**To give a realm another superior**, add the superior's Entity Identifier to
`oidfed.authorityHints` (a comma-separated list) in that realm. **To make a
realm its own Trust Anchor**, turn `oidfed.realmsAreSubordinates` off. No test
job sets either; the values below are placeholders:

```bash
api config/set '{"key":"oidfed.authorityHints","value":"https://intermediate.example.org"}'
api config/set '{"key":"oidfed.realmsAreSubordinates","value":"false"}'
```

**Informational metadata** for the `federation_entity` entity type is
`oidfed.organizationName`, `oidfed.contacts`, `oidfed.logoUri`,
`oidfed.policyUri` and `oidfed.organizationUri`, all empty by default, on the
**Settings** tab.

## Register a subordinate

A realm that vouches for an entity becomes an Intermediate (the default realm
stays the Trust Anchor). Its fetch endpoint then issues a Subordinate
Statement about the entity, carrying its keys and the metadata policy you
give. Taken from `sts_oidfed.js` (section 5) and `sts_oidfed_extensions.js`.

**Console** (tab **Subordinates**):
1. Enter the **Entity Identifier** (`https://rp.example.test`).
2. Either tick **read its keys from its Entity Configuration**, or paste its
   JWK Set into **its JWK Set, if not read**.
3. Tick **an Intermediate** if it vouches for others.
4. Paste a `metadata_policy` and `constraints`, as JSON, if you have them.
5. Optionally fill in **what the history records about it** and an
   information URL.
6. Click **Register the subordinate**.

**API** (in realm `fed`):
```bash
api oidfed/add-subordinate '{
  "entityId": "https://rp.example.test",
  "jwks": {"keys": [<the entity'"'"'s Federation Entity Key, a public JWK>]},
  "entityTypes": "openid_relying_party",
  "metadataPolicy": {"openid_relying_party": {
    "token_endpoint_auth_method": {"one_of": ["private_key_jwt"], "essential": true}}}}'
```

| Member | What it is |
|---|---|
| `entityId` | required: an `https` URL with no query or fragment |
| `jwks` or `fetchJwks: true` | its keys, given, or read from its Entity Configuration through the outbound policy |
| `metadata` | metadata that overrides its own |
| `metadataPolicy`, `metadataPolicyCrit` | a `metadata_policy` (the operators of section 6.1); critical operators, comma-separated |
| `constraints` | `max_path_length`, `naming_constraints`, `allowed_entity_types` |
| `entityTypes` | its entity types, comma-separated, for the list endpoint's `entity_type` filter; read from its configuration when fetched |
| `intermediate` | whether it is an Intermediate |
| `eventDescription`, `informationUri` | recorded on its history |

`metadata`, `metadataPolicyCrit` and `entityTypes` have no box on the
console form; send them through the API. A policy that combines operators the
specification forbids is refused when you save it.

```bash
curl -sk "https://<host>/realm/fed/oidfed/fetch?sub=https://rp.example.test"
curl -sk "https://<host>/realm/fed/oidfed/list?entity_type=openid_relying_party"
```

### Suspend, reinstate or revoke it

Taken from `sts_oidfed_extensions.js`. A suspended subordinate is issued no
statement and listed nowhere until it is reinstated. A revoked one is
removed, and its history is kept and still served at
`/oidfed/subordinate-events?sub=`.

**Console:** on the subordinate's row, fill in the **reason** and the
information URL if you like, then **Suspend**, **Reinstate** or **Revoke**. A
realm of this service beneath the default realm can be suspended, not
revoked; deleting the realm revokes it.

**API:**
```bash
api oidfed/suspend-subordinate '{"entityId":"https://b.example.test","reason":"under review"}'
api oidfed/reinstate-subordinate '{"entityId":"https://b.example.test"}'
api oidfed/remove-subordinate '{"entityId":"https://b.example.test","reason":"no longer operated",
  "informationUri":"https://example.test/revoked"}'
```

## Trust a Trust Anchor

A Trust Chain may end only at a Trust Anchor the realm trusts, verified with
the keys configured for it here. Under the default topology every realm
already trusts the default realm. Add an anchor outside this service like
this. Taken from `sts_oidfed_conformance.js`, which trusts the OpenID
Foundation conformance suite's anchor.

**Console** (tab **Trust Anchors**): enter its **Entity Identifier**, tick
**read its keys from its Entity Configuration** or paste its JWK Set, and
click **Trust it**. **Remove** stops trusting it.

**API:**
```bash
api oidfed/add-trust-anchor '{"entityId":"https://anchor.example.org",
  "jwks":"{\"keys\":[<its public Federation Entity Keys>]}"}'
api oidfed/remove-trust-anchor '{"entityId":"https://anchor.example.org"}'
```

**Pin the keys you got out of band.** `fetchJwks: true` reads them from the
anchor's own Entity Configuration, which is only as good as the connection
it was fetched over. The conformance job also sets
`federation.outboundCaFile` in its realm, so this service trusts the suite's
certificate.

## Resolve another entity

The resolve endpoint never walks the federation for an anonymous caller. It
answers for this service's own realms, and for an entity an administrator
has already resolved. Resolve one first. Taken from `sts_oidfed.js`.

**Console** (tab **Resolve an entity**): enter the entity's identifier and,
optionally, the Trust Anchor to resolve to, then click **Resolve**.

**API:**
```bash
api oidfed/resolve '{"sub":"https://rp.example.test","trustAnchor":"https://anchor.example.org"}'
```

With no `trustAnchor`, any of the realm's anchors will do. The walk is
bounded by `oidfed.maxAuthorityHints`, `oidfed.maxChainDepth` and
`oidfed.maxFetchesPerResolution`, and the result is kept for
`oidfed.resolveCacheS` or until the chain expires.

## Trust Marks

Taken from `sts_oidfed.js` (section 4). The default realm issues a mark to
realm `fed`, which carries it at once.

**Console** (tab **Trust Marks**):
1. Under **Types this realm issues**, enter the type
   (`https://federation.example.test/marks/job`) and the lifetime in seconds
   (`3600`), then **Issue this type**. For a type another entity owns, paste
   the `trust-mark-delegation+jwt` it issued to this realm.
2. On the type's row, enter the subject's Entity Identifier and click
   **Issue**.
3. Under **Issued**, **Revoke** withdraws a mark.

**API:**
```bash
TYPE=https://federation.example.test/marks/job
api oidfed/add-mark-type '{"type":"'"$TYPE"'","lifetimeS":3600}'
api oidfed/issue-trust-mark '{"type":"'"$TYPE"'","sub":"https://<host>/realm/fed"}'   # answers id and trustMark
api oidfed/revoke-trust-mark '{"id":"<the id issue-trust-mark answered>","reason":"job"}'
api oidfed/remove-mark-type '{"type":"'"$TYPE"'"}'
```

A mark is then handed out at `/oidfed/trust-mark?trust_mark_type=&sub=`,
listed at `/oidfed/trust-mark-list?trust_mark_type=`, and its status is at
`POST /oidfed/trust-mark-status` (`trust_mark=<the JWT>`): `active`, and
`revoked` after the revocation. A type with no `lifetimeS` gets
`oidfed.trustMarkLifetimeS` (one year).

**Carry a mark somebody else issued to this realm:** paste it into **a
trust-mark+jwt issued to this realm** and click **Carry it**, or:

```bash
api oidfed/add-held-mark '{"trustMark":"eyJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9..."}'
```

**As a Trust Anchor, say who may issue a type** (published as
`trust_mark_issuers` and `trust_mark_owners`). Under **As a Trust Anchor: who
may issue a type**, fill in the type, the issuers (comma-separated; none
means anybody) and optionally the owner and its JWK Set, then **Set the
policy**. Through the API, `oidfed/set-mark-policy` with `{type, issuers,
ownerSub, ownerJwks}`. The examples in the API's operation table are
`https://federation.example.org/marks/audited` issued by
`https://tmi.example.org`; no test job sets a mark policy or carries a foreign
mark.

## Rotate or revoke the Federation Entity Key

Taken from `sts_oidfed.js` (section 6).

**Console** (tab **Federation Entity Keys**): **Rotate now** queues a
rotation. **Emergency rotation** needs `compromised` typed into its box; it
revokes the current and next keys and replaces them at once. On a retired
key, pick a reason and click **Revoke**.

**API:**
```bash
api oidfed/rotate-key '{}'
api oidfed/rotate-key '{"emergency":true,"confirm":"compromised"}'
api oidfed/revoke-key '{"kid":"<a retired key'"'"'s kid>","reason":"compromised"}'
```

An emergency rotation without `confirm` is refused. A retired or revoked key
is listed at `/oidfed/historical-keys`. The algorithm of new keys is
`oidfed.signingAlg` (`ES256`); it takes effect at the next key made, so
rotate by hand to change it at once.

## Client registration through the federation

A realm's OpenID Provider registers a relying party it was never configured
with, when one of the realm's Trust Anchors vouches for it. Both ways are on
by default (`oidfed.clientRegistrationTypes` `automatic,explicit`). Taken
from `sts_oidfed.js` (section 7), where realm `fed` is the OP and the
default realm, its Trust Anchor, vouches for the relying parties.

**1. The Trust Anchor vouches for the relying party.** At the anchor:

```bash
# BASE=https://<host>   (the default realm, the Trust Anchor)
api oidfed/add-subordinate '{"entityId":"https://auto.example.test",
  "jwks":{"keys":[<the RP'"'"'s Federation Entity Key>]},"entityTypes":"openid_relying_party"}'
```

An anchor outside this service does the same in its own way; the OP realm
then needs that anchor ([above](#trust-a-trust-anchor)).

**2. The relying party arrives.**

* **Automatically.** Its first authorization request, or its PAR request,
  uses its Entity Identifier as `client_id` and proves its key with a signed
  request object (or a `private_key_jwt` at PAR). The job POSTs the request
  object to `/realm/fed/oauth2/authorize`, because a request object carrying
  a whole Trust Chain is too long for a query string.
* **Explicitly.** It POSTs its Entity Configuration, with `aud` naming the
  OP, to `/realm/fed/oidfed/register`, or a Trust Chain that begins with it
  as `application/trust-chain+json`. The answer is a signed
  `explicit-registration-response+jwt`.

A request that proves nothing is answered 400 and never redirected. The
registration lasts until the chain expires, or for at most
`oidfed.registrationLifetimeS` (86400 s). To allow only one way:

```bash
api config/set '{"key":"oidfed.clientRegistrationTypes","value":"automatic"}'
```

## This service as a federated relying party

An OpenID Connect federation relationship can find its OpenID Provider
through a Trust Chain instead of being configured with its endpoints and a
client. Set `fedTrustAnchor` to one of the realm's Trust Anchors and
`fedPeer` to the OP's Entity Identifier. The OP's endpoints and keys are then
the metadata the chain vouches for, and this service registers with it
automatically under its own Entity Identifier, signing its requests and its
token-endpoint authentication with its Federation Entity Key. `fedSsoUrl`,
`fedTokenUrl`, `fedJwks`, `fedJwksUri`, `fedClientId` and `fedClientSecret`
are not read. Only the authorization code flow is used.

Taken from `sts_oidfed.js` (section 8), where the relationship `oidfed-rp` is
in realm `fed` and the OP is the default realm, which is also the Trust
Anchor.

**Console** (in realm `fed`): on **Protocols → Federation**, tab **Add a
relationship**, enter **Id** `oidfed-rp`, *Service provider*, *OpenID
Connect*, **Partner** the OP's Entity Identifier, and click **Add**. On its
page, **Set** `fedTrustAnchor` to the anchor's Entity Identifier, then **Turn
on** `fedEnabled`.

**API:**
```bash
# BASE=https://<host>/realm/fed
api federation/create '{"id":"oidfed-rp","role":"service-provider","protocol":"oidc",
  "peer":"https://<host>"}'
api federation/set '{"id":"oidfed-rp","field":"fedTrustAnchor","value":"https://<host>"}'
api federation/enable '{"id":"oidfed-rp"}'
```

The realm's Entity Configuration then publishes `openid_relying_party`
metadata: the relationship's assertion consumer service as a redirect URI,
`private_key_jwt`, and its key. Who the OP's people become here is the
relationship's subject policy, as for any federation relationship
([Configuring federation → Who a partner may sign in](configure-federation.md#who-a-partner-may-sign-in)).

## The Entity Collection

Taken from `sts_oidfed_extensions.js`. `/oidfed/collection` lists every
entity beneath the realm. What lies beyond this service is collected only by
a crawl.

**Console** (tab **Entity Collection**): **Crawl now**.

**API:**
```bash
api oidfed/crawl-collection '{}'
```

A crawl takes the realm's Entity Identifier from the request that asks for
it. The scheduled crawl (`oidfed.collection-crawl`, every
`oidfed.collectionCrawlS`) runs only where `global.publicBaseUrl` pins that
identifier. A crawl is bounded by `oidfed.collectionMaxEntities` and
`oidfed.collectionMaxFetches`.

## Related

* [OpenID Federation](oidfed.md): every endpoint, the keys, the extensions and every setting.
* [Configuring federation](configure-federation.md): bilateral relationships, including the federated relying party's relationship.
* [Configuring OpenID Connect flows](configure-oidc-flows.md): the OpenID Provider a registered relying party then uses.
* [Trust realms](trust-realms.md): each realm is an entity of its own.
