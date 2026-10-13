---
title: SCIM
---

# SCIM

iya-sts is a **SCIM 2.0 service provider** at `/scim/v2`
([RFC 7642](https://www.rfc-editor.org/rfc/rfc7642),
[RFC 7643](https://www.rfc-editor.org/rfc/rfc7643),
[RFC 7644](https://www.rfc-editor.org/rfc/rfc7644)). It is the one protocol
family here whose purpose is to **write**. What it writes is the embedded
[LDAP directory](ldap.md), entry for entry, and SCIM keeps no store of its own.
Every [trust realm](trust-realms.md) has its own endpoint
(`/realm/{id}/scim/v2`), and it provisions into that realm's directory.

```
POST /scim/v2/Users {"userName": "dave"}
    -> uid=dave,ou=users,dc=example,dc=com     the directory entry itself
    -> ldapsearch -b ou=users '(uid=dave)'     finds it
    -> /admin/users?user=dave                  shows it
    -> /admin/vc's selection sweeps it         so a credential has something to assert
    -> an access token for dave                carries its attributes
```

That is the whole design: the interesting property of a SCIM endpoint is that
what it writes is what everything else then reads.

It is also a **SCIM 2.0 client** (#552): each realm can push its people and
groups to any number of remote SCIM service providers. See
[The outbound SCIM client](#the-outbound-scim-client) below.

## Features

### Resources and operations

* **Users** and **Groups**: create, read, list, replace (PUT), modify (PATCH)
  and delete. PATCH is RFC 7644 section 3.5.2 in full, including value-filter
  paths such as `emails[type eq "work"].value`.
* **Query**: `filter` (section 3.4.2.2), `sortBy`, `sortOrder`, `startIndex`,
  `count`, `attributes` and `excludedAttributes`. A filter this server cannot
  evaluate is refused `400 invalidFilter`, never answered with an empty list.
* **Search by POST**: `/Users/.search`, `/Groups/.search`, and `/.search` at the
  root, which answers one filter from Users and Groups together. The body must
  carry the SearchRequest schema URN.
* **Bulk**: `POST /scim/v2/Bulk` (section 3.7). Each operation carries its own
  status, so a bulk request in which one operation failed is still a 200.
* **`/Me`**: an alias for the authenticated subject (section 3.11), with GET,
  PUT, PATCH and DELETE. An anonymous caller, or any POST, gets `501`. A
  credential that names somebody with no entry, such as a `client_credentials`
  token, gets `404`.
* **Discovery**: `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`. The
  User resource type declares the enterprise extension as a `schemaExtension`.
  **`/Schemas` lists only what the directory stores** (since #206): `nickName`,
  `locale`, `timezone`, `ims`, `photos`, `entitlements`, `roles`,
  `x509Certificates`, `name.middleName`, `name.honorificSuffix`, `costCenter`,
  `manager.displayName`, and the `display` and `primary` of `emails`,
  `phoneNumbers` and `addresses` are not offered, because nothing here could
  keep them. `emails.type` is `work` only, `phoneNumbers.type` `work` or
  `mobile`, `addresses.type` `work`; another type is refused `400
  invalidValue`.
* **References**: a Group member, a group a user is in, and a user's manager
  each carry a `$ref`, the absolute URL of that resource. A member has no
  `display`.
* **Filters** compare a `caseExact: false` attribute (`userName`, every email
  `value`, most of the schema) without regard to case, and refuse `gt`, `ge`,
  `lt` and `le` on a boolean or binary attribute with `400 invalidFilter`.
* **An unknown path** under `/scim/v2` is answered `404` in the SCIM Error
  schema, not as an HTML page.

Filtering, sorting, PATCH and bulk are advertised as supported. **ETag and
`changePassword` are advertised as unsupported.** The ServiceProviderConfig is
built from the same values the endpoints enforce, so its `maxResults`,
`bulk.maxOperations` and `bulk.maxPayloadSize` are the limits actually applied.

### The `id` is the entry's `entryUUID`

A resource's `id` is its directory entry's `entryUUID`
([RFC 4530](https://www.rfc-editor.org/rfc/rfc4530)). It is kept through a
rename, and a person deleted and created again gets a new one. It is the value a
person's tokens carry in `sub`, as `urn:uuid:<entryUUID>`.

```
GET /scim/v2/Users/5503c620-f13d-42e9-a841-fbfbe4cf8899
```

Group `members[].value`, a User's `groups[].value` and the enterprise
`manager.value` are ids on the wire. The directory stores the DNs they name. A
DN presented as an id still resolves, for a client that stored one earlier.

### Provisioning is the directory

A User create goes through the same function as the console's **New user** form
and `POST /admin-api/users/create`. The name rules, the one-entry-per-person
check and the refusals are the same at every door:

* `userName` is unique. A second user with a taken name gets `409 uniqueness`,
  including a name that another entry answers to under a different naming
  attribute.
* The `userName` `invalid` is refused `400 invalidValue`, the same reserved
  value every other protocol here refuses.
* A full directory (`ldap.maxEntries`) is a `500`.
* A name carrying RFC 4514's reserved characters is refused. One rule decides
  that for SCIM, the console and `/admin-api`, users and groups alike, so the
  doors cannot drift apart on which names are usable in a DN.

Because a create goes through the directory's own door, it also gets the
directory's *fold*: a new name lands on the entry that is already this person's
under a different naming attribute (a client certificate's `cn=rcbj,ou=users`,
say) rather than creating a second object for one person. The create writes one
`user.create` audit row naming SCIM as the protocol; SCIM itself records only
updates and deletes, so one act is never counted twice.

A created group gets an entry under `ou=groups` with a `groupOfNames` object
class. A group list includes everything the directory counts as a group: entries
under `ou=groups` and entries carrying a group object class anywhere. On a read,
`member`, `uniqueMember` and `memberUid` are all resolved as members. A write
puts values in `member` and clears the other two. **A member that names nothing
is accepted** and logged, because this directory does no referential integrity.

**Being provisioned is not authenticating.** A person created over SCIM has an
entry with `origin: scim` and no row on `/admin/users` until they sign in
somewhere.

### A service deployed in several regions

When this service runs as several regional cells, each person is homed in one
of them and their data stays there. SCIM follows the person:

* a request about one person (`/Users/{id}`) is answered by the region they
  are homed in, whichever region your client reached;
* a new person is homed in the region named by
  `urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User:homeCell` (a region
  id; write-only and never returned), or in the realm's default region. A
  region the realm may not home people in is refused. A later write cannot
  move a person: that is an administrator's act;
* a list or a search returns the people of the region that answered;
* a Group write whose members are homed in more than one region, and a
  BulkRequest whose operations are, are refused whole (400 `invalidValue`).
  Send one request per region's people.

A service deployed as one region ignores `homeCell`.

### Attribute mapping

Each SCIM member is stored in one LDAP attribute. For example, `userName` is
`uid`, `name.familyName` is `sn`, `emails` is `mail`, `phoneNumbers` is
`telephoneNumber` (type `work`) and `mobile` (type `mobile`), `userType` is
`employeeType`, the address members are `street`, `l`, `st`, `postalCode`, `c`
and `postalAddress`, and the enterprise extension maps to `employeeNumber`,
`departmentNumber`, `o`, `ou` and `manager`. The full table, with type, parent
and extension for each row, is published live at `GET /scim` and on
`/admin/scim`.

**A PUT replaces only what the mapping covers.** Every attribute outside the
mapping is left alone: `schacDateOfBirth`, `authnMethod`, `mfaAuthenticated` and
the `x509*` attributes, for example. A client removes a mapped value by omitting
it. `entryDN`, `createTimestamp` and `modifyTimestamp` are never written back.
`meta.created` and `meta.lastModified` come from the timestamps. (The DN is
synthesised from where the entry is stored, RFC 5020, and the timestamps belong
to the entry rather than to whoever wrote it, so writing them back would store a
copy of what is meant to be computed.)

### `active: false` disables the account

`active` maps to `pwdAccountLockedTime`, the administrative lock from the LDAP
password policy draft. **`active: false` is the same act as Disable on
`/admin/users`.** Every door then refuses the person: a password anywhere, any
sign-in, a session they already hold, a Kerberos AS-REQ, every token grant and
refresh, and the management API. Everything they hold is ended. Sessions end
with CAEP `session-revoked` and back-channel Logout Tokens, and RISC reports
`account-disabled`. `active: true` enables them again, and nothing they held
comes back.

A resource that does not mention `active` **leaves the lock as it was**, so a
client that never sends the member cannot re-enable an account an administrator
disabled. On the way out `active` is always present.

### Authentication: all six schemes of RFC 7644 section 2

RFC 7644 section 2 defines no SCIM credential of its own: "The SCIM protocol is
based upon HTTP and does not itself define a SCIM-specific scheme for
authentication and authorization." It *names* six ways — TLS client
authentication, HOBA, bearer tokens, proof-of-possession tokens, cookies, and
HTTP Basic, which it discourages — and states two normative sentences, both
honoured here: a provider **SHALL** indicate its supported schemes in
`WWW-Authenticate`, and **MUST** be able to map the authenticated client to an
access control policy (the policy is below).

Every endpoint needs a credential, except the three discovery documents while
`scim.authDiscovery` is off. A request with no credential gets `401` with one
`WWW-Authenticate` header per offered scheme. The ServiceProviderConfig's
`authenticationSchemes` is built from the same table, so a scheme turned off
disappears from both.

| Scheme | `type` published | What it takes |
|---|---|---|
| OAuth 2.0 Bearer ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)) | `oauthbearertoken` | An access token from this service with `scim:read` or `scim:write`, verified for signature, revocation and audience |
| DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) | `oauth2` | The same token, key-bound, with a proof. An [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) certificate-bound token is honoured too |
| HTTP Basic ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)) | `httpbasic` | A username and password |
| HTTP Digest ([RFC 7616](https://www.rfc-editor.org/rfc/rfc7616)) | `httpdigest` | SHA-256 or SHA-512-256, with the `-sess` variants; MD5 only where `scim.digestMd5` turns it on, in development mode |
| HOBA ([RFC 7486](https://www.rfc-editor.org/rfc/rfc7486)) | `hoba` | An RSA/SHA-256 signature over the server's challenge, by a key registered at `POST /.well-known/hoba/register` |
| Session cookie | `httpcookie` | The browser sign-on session from `/authn/login`, consulted only when there is no `Authorization` header |
| TLS client certificate | `tlsclientauth` | A certificate that verified against the client truststore on the main port (needs `global.https`) |

The ServiceProviderConfig publishes all seven rows, and three of them have no
canonical `type`: RFC 7643 section 5 gives `authenticationSchemes.type` five
values (`oauth`, `oauth2`, `oauthbearertoken`, `httpbasic`, `httpdigest`), and
there is none for a client certificate, a cookie or HOBA. Those three are
published with a type of their own (`tlsclientauth`, `httpcookie`, `hoba`)
rather than left out — a ServiceProviderConfig listing four of the seven ways
in would be the most misleading document this service publishes, and it is the
first thing a SCIM client reads.

**The access policy.** Only the OAuth schemes carry scopes. `scim:read` reads
and `scim:write` writes, and **neither implies the other**. A wrong scope is
`403` with `error="insufficient_scope"`. Every other scheme may both read and
write. To exercise a client's scope handling, turn the other five off. After the
scope check, the [XACML](xacml.md) access gate decides. It permits by default,
and its refusal says that the credential was accepted.

**A credential that was presented and failed is always a refusal**, even on the
discovery endpoints.

**Digest and HOBA really verify the exchange** in both modes. A Digest nonce
expires after `scim.digestNonceSeconds` and is then refused with `stale=true`,
which a conforming client retries silently. A replayed nonce count is refused
**without** `stale`, because the credential was valid and has been seen before.
A HOBA challenge may be reused until it expires, so a replay is a repeated
(key id, challenge, nonce) triple. On a cluster a nonce count or a HOBA triple
is spent once across every node.

HOBA's signature is RSA with SHA-256 over RFC 7486 section 5's length-prefixed
blob. The key is registered at `POST /.well-known/hoba/register` — in
development unauthenticated: it is how a caller **gets** a credential — and it lands on the person's own directory entry
as `hobaPublicKey`, so an `ldapsearch` and `/admin/users` show it. A HOBA
credential names its key by id alone, which is why a key id already registered
to another account is refused in every mode. In development the shared Digest
password defaults to `password!`, the same value as `krb5.userPassword`, so
there is one fact to remember rather than two.

An accepted SCIM credential starts a [session](sessions.md) keyed on the scheme
and the principal, never on the credential. Basic, Digest and HOBA present a
credential on every request and are recorded as authentications, so their
caller appears on `/admin/users` under protocol SCIM. A token, a cookie or a
certificate continues an authentication already recorded elsewhere.

### Things you can make fail

| Do this | Get this |
|---|---|
| create a user named `invalid` | `400 invalidValue` |
| create a duplicate `userName` | `409 uniqueness` |
| ask for an id that names nothing | `404` |
| send a filter the server cannot evaluate | `400 invalidFilter` — "no results" and "I could not read your filter" are different answers, and a client can only act on the second |
| send nothing | `401` with every offered challenge |
| use a token with the wrong scope | `403 insufficient_scope` |
| use a token this service did not issue, or a revoked one | `401` — a scope on a token nobody verified is a permission its holder wrote for themselves |
| use Basic with the password `invalid` | `401` |
| use Digest with a wrong password, a stale nonce or a repeated `nc` | `401`, three ways |
| use a HOBA signature that does not verify, or a repeated triple | `401` |
| `GET /Me` with no credential, or any `POST /Me` | `501` — the alias is unavailable (an anonymous caller has no subject, and a POST would create one that already exists); a credential naming nobody here gets `404` |
| POST to `.search` without the SearchRequest URN | `400 invalidSyntax` |
| send a Bulk request over `scim.bulkMaxOperations` | `413 payloadTooLarge` |
| send `If-Match` (other than `*`) on a PUT, PATCH or DELETE | `412` — there are no entity-tags, so no version can match; nothing is changed |
| order a boolean in a filter (`active gt true`) | `400 invalidFilter` |
| send an email of type `home` | `400 invalidValue` |
| ask for a path under `/scim/v2` that is no endpoint | `404`, as a SCIM Error |

### Not implemented

* **ETag** versioning. A version built over a one-second timestamp would be a
  concurrency control a client trusts and that is wrong. Responses carry no
  ETag header at all — not even the weak one a web framework would add by
  default — so they do not contradict the ServiceProviderConfig, and an
  `If-Match` on a write is refused `412` rather than ignored.
* The RFC 7643 members listed under *Discovery* above that the directory has
  no place for, and `primary` on a multi-valued member.
* **`changePassword`**. SCIM carries no password here.
* A scheme that RFC 7644 section 2 does not name, such as an API key header.

## Development and product mode

A credential is **required in both modes**. What differs is how much of it is
checked.

| | Product | Development |
|---|---|---|
| OAuth tokens | Verified; the scope decides | Verified; the scope decides |
| Basic | The password is verified against the person's hashed `userPassword` (off the request thread). A person who holds or must hold a second factor is refused their own password with the same `401` a wrong one gets, and uses an [app password](authentication.md#the-password-only-doors-and-app-passwords) scoped to `scim` | Any username, any password except `invalid` |
| Digest | **Not offered**, and refused (`STS-SCIM-0056`). A salted scrypt hash cannot answer an RFC 7616 exchange | Any username with the one shared password, `scim.digestPassword` |
| HOBA registration | Only the signed-in owner of an **existing** account may register a key for it (`STS-SCIM-0069`). A registration never creates an account | Anybody may register any key for any name |
| The shared Digest password in a `401` | Never printed | Printed, as a test aid |

**In every mode** a HOBA key id already registered to another account is
refused (409), and the SCIM scopes are tied to the client: they are issued only
to a client whose `oauthAllowedScope` declares them, and a token is honoured only
while its client still does — withdrawing the declaration cuts off tokens
already issued (`STS-SCIM-0079`). Declare them on the application's page, or
with `POST /admin-api/applications/add`
(`{"application": "<id>", "attribute": "oauthAllowedScope", "value": "scim:write"}`).
Verifying a Basic password costs about 70 ms of
CPU per request in product mode, so a bulk provisioning client should use a
`scim:write` access token. See [what is not checked](what-is-not-checked.md).

**In development mode the credential is a turnstile, not a lock.** Any password
but `invalid` passes Basic, any username passes Digest with the shared
password, and anybody can register a HOBA key for any name. Nothing decides that
a caller *should* be allowed to delete an account — only that they said who
they were first. Do not put a development-mode SCIM endpoint on a public
address on the strength of it.

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `scim.enabled` | `SCIM_ENABLED` | `true` | yes | Turns the family on; off leaves the routes registered and answering `501`. |
| `scim.maxResults` | `SCIM_MAX_RESULTS` | `200` | yes | The largest page a list or search returns, published as `filter.maxResults`; a larger `count` is clamped. |
| `scim.bulkMaxOperations` | `SCIM_BULK_MAX_OPERATIONS` | `100` | yes | How many operations one Bulk request may carry, published as `bulk.maxOperations`. |
| `scim.bulkMaxPayloadSize` | `SCIM_BULK_MAX_PAYLOAD_SIZE` | `1048576` | yes | The largest Bulk body in bytes, published as `bulk.maxPayloadSize` and checked against that number. |
| `scim.authDiscovery` | `SCIM_AUTH_DISCOVERY` | `false` | yes | Whether the three discovery documents also need a credential. Off is what RFC 7643 section 5 asks (authenticationSchemes SHOULD be readable without prior authentication); **on departs from it**. |
| `scim.inventOnCreate` | `SCIM_INVENT_ON_CREATE` | `true` | yes | Development mode only: fill a provisioned person in with the invented persona and the /admin/vc attributes the client did not send. Off, a create writes exactly what was sent. |
| `scim.authRealm` | `SCIM_AUTH_REALM` | `SCIM` | yes | The protection space in every challenge; Digest and HOBA credentials are computed over it. |
| `scim.scopeRead` | `SCIM_SCOPE_READ` | `scim:read` | yes | The OAuth scope needed to read, published in `scopes_supported`. |
| `scim.scopeWrite` | `SCIM_SCOPE_WRITE` | `scim:write` | yes | The OAuth scope needed to create, replace, patch, delete or bulk; it does not imply the read scope. |
| `scim.authBearer` | `SCIM_AUTH_BEARER` | `true` | yes | Offer OAuth 2.0 access tokens, as Bearer or DPoP. |
| `scim.authBasic` | `SCIM_AUTH_BASIC` | `true` | yes | Offer HTTP Basic. |
| `scim.authDigest` | `SCIM_AUTH_DIGEST` | `true` | yes | Offer HTTP Digest (never offered in product mode). |
| `scim.digestPassword` | `SCIM_DIGEST_PASSWORD` | `password!` | yes | The password every username shares for Digest in development. |
| `scim.digestNonceSeconds` | `SCIM_DIGEST_NONCE_SECONDS` | `300` | yes | How long a Digest nonce is usable before it is refused with `stale=true`. |
| `scim.digestMd5` | `SCIM_DIGEST_MD5` | `false` | yes | Whether Digest offers and accepts MD5 beside SHA-256 and SHA-512-256. **Warning:** MD5 is collision-broken and RFC 7616 keeps it for backward compatibility only; turn it on only to exercise a client that speaks nothing else. **Development mode only** — refused on write in product (`STS-CORE-0103`) and ignored if stored (`STS-CORE-0106`); product offers no Digest at all. |
| `scim.maxDigestNonces` | `SCIM_MAX_DIGEST_NONCES` | `2000` | yes | How many issued Digest nonces are remembered; a forgotten one is refused `stale=true`. |
| `scim.authHoba` | `SCIM_AUTH_HOBA` | `true` | yes | Offer HOBA, and turn `/.well-known/hoba/register` on or off. |
| `scim.hobaMaxAgeSeconds` | `SCIM_HOBA_MAX_AGE_SECONDS` | `600` | yes | The max-age of a HOBA challenge, published and enforced. |
| `scim.maxHobaChallenges` | `SCIM_MAX_HOBA_CHALLENGES` | `2000` | yes | How many issued HOBA challenges are remembered. |
| `scim.maxHobaSeen` | `SCIM_MAX_HOBA_SEEN` | `5000` | yes | How many accepted HOBA triples are remembered for replay detection; evicting one also forgets its challenge. |
| `scim.authCookie` | `SCIM_AUTH_COOKIE` | `true` | yes | Accept the browser sign-on session cookie. |
| `scim.authClientCert` | `SCIM_AUTH_CLIENT_CERT` | `true` | yes | Accept a TLS client certificate that verified against the client truststore. |

`ldap.maxEntries` is the cap a SCIM create runs out of, because SCIM has no
store of its own.

This table is a copy of the rows in the service's settings table. The live
source is **Protocols → SCIM** (`/admin/scim`), where every setting is drawn,
and `GET /admin-api/config`. `POST /admin-api/config/set` changes one, and every
setting can be set per trust realm. See [Configuration](configuration.md) for
how a value is resolved.

## Design decisions

* **No second store.** A SCIM server with its own map beside the directory would
  teach a provisioning client nothing. The useful property of a SCIM endpoint is
  that what it writes is what everything else then reads.
* **One create function for every door.** SCIM, the console and `/admin-api`
  share the directory's own create, so "creating a user" has one meaning and
  cannot fold a person into two entries.
* **A credential is required, and in development it is a turnstile rather than
  a lock.** These endpoints create and delete accounts. Requiring a credential
  makes a client's 401, 403, challenge and scope handling testable, which an
  open endpoint cannot do. No setting turns the requirement off.
* **All six schemes of RFC 7644 section 2 and no others.** An API key header is
  what many real integrations use, but it is in no specification and would
  interoperate with nothing.
* **The read and write scopes do not imply each other**, so that a read-only
  provisioning credential exists for a client to handle.
* **Digest and HOBA really verify.** A server that accepted any Digest response
  or any signature would not be performing the exchange, and the client code
  that computes it would never run.
* **Digest is not offered in product mode.** It needs the password or an
  unsalted hash of it on the server, and storing that per person would be a
  password equivalent with no work factor.
* **The discovery endpoints are open by default.** The ServiceProviderConfig is
  where a client learns which schemes exist, so demanding a credential to fetch
  it makes the client know the answer before it asks.
* **A PUT replaces only the mapping's window.** Read strictly, a PUT would
  delete attributes SCIM never knew about and cannot restore.
* **`active` omitted leaves the lock alone.** RFC 7643 gives `active` no
  default, and a client that never sends it must not undo an administrator's
  Disable by omission.
* **A dangling group member is accepted.** Refusing it would make a state the
  directory can reach impossible to reproduce through SCIM.
* **The `id` is `entryUUID`, not the DN.** RFC 7643 section 3.1's id must never
  be reassigned, and a rename reassigns a DN.
* **ETag and `changePassword` are advertised as unsupported** rather than
  half-implemented.
* **The published limits are read per request.** The ServiceProviderConfig is
  rebuilt from the current settings each time it is fetched, so a runtime change
  to `scim.maxResults` is both enforced and advertised at once, never enforced
  while the document still shows the old number.

## The SCIM library, and two defects routed around

The schema, filter and PATCH-path handling come from `scimmy` (MIT, no runtime
dependencies). It brings the three things that are hard about SCIM and boring
to get right: the RFC 7643 schema definitions with their attribute
characteristics and coercion, the section 3.4.2.2 filter grammar, and the
section 3.5.2 PATCH path grammar — where hand-rolled servers are usually subtly
wrong: `emails[type eq "work"].value` is a *path*, and treating it as a property
name makes a provisioning client's updates land somewhere else.

Two things it does *not* do look as though they are handled:

* **Reading a resource does not apply the filter it parsed.** A handler that
  ignored the filter would return everybody for every query, which looks like a
  working server until somebody filters. This service applies it; sorting and
  pagination are the library's.
* **Its filter matcher throws on a nested attribute the resource lacks.** A
  filter naming any sub-attribute (`emails.value co "@example.com"`,
  `name.familyName sw "Sm"`) would blow up on the first person with no email —
  in a directory the ordinary case — surfacing as
  `400 invalidValue: Cannot convert undefined or null to object`. This service
  pads every multi-valued and complex member to at least an empty array or
  object before matching, and takes the padding off again before the resource
  goes on the wire.

## In the running service

* **Protocols → SCIM** (`/admin/scim`): the six schemes and which are on, the
  endpoints, what SCIM here will not do, the negatives you can provoke, the
  attribute mapping, counters of what has been done, and every `scim.*` setting.
* **Monitoring → SCIM metrics** (`/admin/scim/monitor`): calls, successes and
  failures, latency and bytes per operation, counts per resource type and per
  scheme (including schemes at zero), one row per authenticated principal, and
  the last fifty requests. A caller the gate refused is counted as refused, not
  as a client. There is no reset. One Bulk request carrying five creates counts
  as one `bulk` and five `create`s, because each of the five really is
  performed — the column is not meant to add up. `/admin/scim` draws every
  operation and resource type including those at zero, because "does this
  server do PATCH" is the question somebody arrives with.
* The `scim.*` settings are drawn on `/admin/scim` and saved through
  `POST /admin-api/config/set`; there is no SCIM-specific write operation beside
  `GET /admin-api/scim`.
* `GET /scim`: a description of the surface, the mapping table and the schemes,
  with `?format=json`. It is not a SCIM endpoint.
* The management API: `GET /admin-api/scim` and `GET /admin-api/scim/monitor`.
* The provisioned people and groups: **Users** (`/admin/users`), **Groups**
  (`/admin/groups`) and `/admin/ldap/directory`.

`GET /admin/sts-metadata` lists every SCIM endpoint. Every SCIM failure is
recorded under an `STS-SCIM-NNNN` code on the audit row and never sent to a
client. See [error codes](error-codes.md).

## The outbound SCIM client

The other direction: this service as a SCIM **client**, pushing a realm's
people and groups to a remote SCIM 2.0 service provider — another identity
provider, a SaaS application, or another realm of this service. A realm may
have any number of clients, and each pushes to one service provider.

```
a person's entry changes in the realm's directory
    -> one delivery queued per client, per resource
    -> the scim-client.deliver job sends it:  POST / PUT / PATCH / DELETE
    -> the service provider holds the person, keyed by externalId = entryUUID
```

### Creating a client

On **Protocols → SCIM**, the **Clients** tab lists every client of the realm
with its queue counts and its pause, and has a form to add one. Each client has
a page of its own (`/admin/scim?client=<identifier>`) with its configuration,
what its service provider's discovery said, its retry queue, its dead letters
and the actions below.

Every action is also an operation of the management API, under
`POST /admin-api/scim/clients/{action}`, and the list and one client's page are
`GET /admin-api/scim/clients` (with `?client=<identifier>`):

```
POST /admin-api/scim/clients/add-client
{ "identifier": "partner-idp", "name": "Partner IdP",
  "baseUrl": "https://idp.example.com/scim/v2",
  "authMethod": "oauth2",
  "tokenEndpoint": "https://idp.example.com/oauth2/token",
  "oauthClientId": "iya-sts", "oauthClientSecret": "<a secret>",
  "scopeMode": "groups", "scopeGroups": "staff",
  "groupMode": "member-groups", "deprovision": "deactivate",
  "reconcileMinutes": "1440", "enabled": "true" }
```

A client is an **application entry** declared for the
`scim-client` protocol family, so it also appears on **Applications**. Its
credentials — a Basic password, an OAuth client secret, a TLS private key —
are **sealed on the entry** and never shown again: a page and an API answer
say only `passwordSet`, `oauthClientSecretSet` and `tlsPrivateKeySet`. They are
write-only; on a change, a credential left out keeps the one set. A new client
is **off** until `enabled` is `true`.

An add or a change is refused (`STS-SCIMC-0017`) when:

* the base URI is not `https`, carries a user name or password, or carries a
  query or fragment (RFC 7644 sections 7.2, 7.1 and 1.3). Plain `http` is
  accepted only in development mode with `scimClient.allowHttp` on;
* a value is outside its closed set, or the authentication method lacks what it
  needs (a user name and password; a token endpoint, client_id and secret);
* the client would not authenticate at all: `authMethod` `none` needs a TLS
  client certificate;
* the LDAP scope filter does not parse (RFC 4515), or a certificate, private
  key or CA certificate does not.

A client that is saved but cannot be used yet — waiting for its issued
certificate, say — is listed with the reason, and nothing is sent for it.

### Authenticating to the service provider

| `authMethod` | What is sent |
|---|---|
| `basic` | HTTP Basic with `username` and `password` |
| `oauth2` | A Bearer token from `tokenEndpoint` by the `client_credentials` grant, with `oauthScope` and `oauthResource` (RFC 8707) when set, the client authenticating with `client_secret_basic` (the default) or `client_secret_post` (`oauthClientAuth`). The token is cached until a minute before it expires; a `401` on a cached token gets **one** fresh token and one more try |
| `none` | Nothing but the TLS client certificate |

**A TLS client certificate** (`tlsSource`) is presented with any of the three,
so it can stand alone or sit beside Basic or OAuth:

* `issued` — **Issue certificate** on the client's page
  (`issue-certificate`) issues one from the realm's own certificate authority
  (the `tls-client` Issuing CA). The service provider must trust this
  service's Root; the answer carries it (`rootPem`).
* `uploaded` — paste `tlsCertificate` (PEM, a chain allowed) and
  `tlsPrivateKey` (PEM).
* `none` — no certificate.

**The service provider's certificate is always verified, host name
included** (RFC 7644 section 7.2), against the public roots plus the client's
own `caCertificates` and the file named by `scimClient.caFile`. Give a private
service provider's CA there. `scimClient.skipTlsVerification` turns the check
off in development mode only, with a warning in the log; product mode ignores
it.

### Who is pushed, and which groups

**Scope** (`scopeMode`) says which people:

| | |
|---|---|
| `all` | every person in the realm |
| `groups` | the members of the groups named in `scopeGroups` (by `cn` or DN) |
| `filter` | the people an RFC 4515 LDAP filter (`scopeFilter`) matches, such as `(departmentNumber=42)`. Credential attributes cannot be matched on. A filter that cannot be evaluated puts nobody in scope (`STS-SCIMC-0022`) |

**Groups** (`groupMode`) says which groups go:

| | |
|---|---|
| `none` | no group (the default) |
| `selected` | the groups named in `groups` |
| `member-groups` | every group that has at least one person in scope |
| `all` | every group of the realm |

A pushed group's members are **only the people in scope** who are already at
the service provider and active there. A member that is a group, not a person,
is not sent. A member not there yet is pushed first, and the group again once
they are (RFC 7643 section 4.2: a member's `value` is the service provider's
id).

**Deprovisioning** (`deprovision`) says what happens at the service provider to
a person who leaves the scope or is deleted:

* `deactivate` (the default) — `active: false`;
* `delete` — a `DELETE`.

**A disabled account is always `active: false`**, whatever `deprovision` says:
a disabled person is still in scope, and is replaced with `active` false. A
group that leaves the scope is deleted there.

### What the client sends (RFC 7643 and RFC 7644)

* **Discovery first.** Before it writes anything the client reads
  `/ServiceProviderConfig` (PATCH, filtering and its `maxResults`, ETags) and
  `/ResourceTypes` (the User and Group endpoints, and their **required** schema
  extensions). What it learns is kept for ten minutes. **Test connection**
  (`test-connection`) and a reconciliation read it again. A service provider
  that cannot be reached holds the delivery as a failure. One that answers but
  not with SCIM is assumed to support `/Users` and `/Groups` and nothing
  optional (`STS-SCIMC-0019`). `authenticationSchemes` and `bulk` are shown on
  the client's page and used for nothing: the client authenticates as it is
  configured, and it never sends a Bulk request.
* **`application/scim+json`** both ways.
* **A User** is this service's own SCIM mapping of the entry — the same
  resource `/scim/v2` would answer — without `id`, `meta`, `groups` or a
  password, with no extension but the enterprise one, and with **`externalId`
  set to the entry's `entryUUID`**. A `manager` is sent as the service
  provider's id for that person, or not at all. When `/ResourceTypes` marks the
  enterprise extension required, it is sent, empty if need be. Any other
  required extension is one the client has no values for: the resource is
  not sent and the delivery is a dead letter naming it (`STS-SCIMC-0029`). A
  User without `userName`, or a Group without `displayName`, is not sent
  (`STS-SCIMC-0030`).
* **Create** is a `POST`. The returned `id` (and ETag) are kept as the
  resource's link. A **`409` with `scimType` `uniqueness` adopts** the resource
  already there: the client looks for it by `externalId`, then by `userName` or
  `displayName`, and replaces it rather than trying again (RFC 7644 section
  3.3). This needs the service provider to support filtering. A `409` with any
  other `scimType`, or none, is a dead letter; nothing is adopted on a guess.
* **Replace** is a `PUT` of everything this client owns to the linked id. An
  attribute the client sent before and the entry no longer has is sent as
  `null`, or `[]` for a multi-valued one, so the service provider clears it
  (RFC 7644 section 3.5.1). A `404` there creates the resource again.
* **Groups** are changed by `PATCH` where the service provider supports it:
  `replace` of `displayName`, `add` of the new members, and one `remove` per
  departed member by `members[value eq "<id>"]`. Otherwise they are replaced by
  `PUT`. Deactivation is a `PATCH` of `active`, or a `GET` then a `PUT`.
* **Delete** is a `DELETE`. A `404` means it is already done.
* **ETags**, where the service provider supports them: `If-Match` on every
  `PUT`, `PATCH` and `DELETE`. A `412`, or a `400` with `scimType`
  `invalidVers`, re-reads the version and tries again, up to
  `scimClient.etagRetries` times (`STS-SCIMC-0021`).
* **Lookups and lists.** A filter is `attribute eq "value"` with the value
  JSON-escaped, so a quote in a name cannot end it. A reconciliation lists the
  service provider's resources page by page from `startIndex` 1. When a list
  answer has no `totalResults`, it keeps paging until a page is empty or
  brings nothing new. A resource seen twice counts once.
* **`tooMany`** (a `400` with that `scimType`, RFC 7644 section 3.4.2)
  narrows the query rather than failing. An `externalId` lookup is asked again
  for a page of two. A listing halves its page until it is answered, down to
  one, and then, where filtering is supported, asks only for resources with an
  `externalId` (`externalId pr`). Past that it fails (`STS-SCIMC-0028`).
* **Errors** are read as RFC 7644 section 3.12's Error body, whether its
  `status` is a string or a number. Its `scimType` is recorded on the dead
  letter; its `detail` is not, because it often quotes the refused value.
  Three `scimType`s change what the client does: `tooMany`, `uniqueness` and
  `invalidVers`, as above. `mutability` is a dead letter: the service provider
  holds that attribute as immutable, and a re-read cannot change what the
  client would send.
* **No credential, token or filter value is ever logged** (RFC 7644 section
  7.5.2), and none reaches a page, an API answer or an audit row.

### Delivery, retries and dead letters

Every change the directory makes to a person — created, changed, disabled or
deleted — and every change to who is in a group queues **one delivery per
enabled client and per resource**: the person, and the groups they are in.
A group no person's change touches — an empty one created, say — goes at the
next reconciliation. The row carries no data. The resource
is read as it is when the row is sent, so several changes to one person become
one request, and changes to one resource are sent in order, one at a time.
Different resources go in parallel, up to `scimClient.concurrency`.

The cluster scheduler job **`scim-client.deliver`** (every
`scimClient.sweepS`, on one node) sends what is due, so a directory change is
sent within one sweep. A reconciliation, a retry and `deliver-now` also send
at once. There is no timer of the client's own.

**Each client has its own retry queue and dead-letter queue**, shown on its
page:

* **queued** — never attempted yet;
* **retrying** — failed with something worth repeating, due again later;
* **dead** — a final failure, with its error code and reason, kept until an
  operator acts.

Only a **network failure, a timeout, `429`, `500`, `502`, `503` and `504`** are
retried, up to `scimClient.attempts`, with an exponential backoff
(`scimClient.backoffMs`, doubled each attempt, full jitter, capped at
`scimClient.maxBackoffMs`) that waits at least as long as a `Retry-After`
asks. Everything else — a `400`, `401`, `403`, a `409` that is not
`uniqueness`, a `404` other than on a delete, a `501` — is a dead letter at
once. **`408` is not retried.**

**A struggling service provider pauses its client.** A network failure, a
timeout, `429` or a `5xx` stops every delivery of that client until the pause
ends. The pause doubles with each such failure in a row (the same backoff,
capped). When it ends, **one** delivery goes first as a probe, and the rest
follow only after a success. The pause is shared by every node (and, in a
service deployed as cells, by every cell: below).

A dead letter **stays dead**. A later change to that resource marks it as
waiting, and is sent when the dead letter is retried, because the retry sends
the resource as it is then. A change still unsent after `scimClient.retentionS`
becomes a dead letter (`STS-SCIMC-0012`).

| Action | What it does |
|---|---|
| `retry-delivery` (`{"id": "<delivery id>"}`) | sends one dead letter again |
| `retry-dead` | sends every dead letter of the client again |
| `purge-dead` | deletes every dead letter of the client |
| `deliver-now` | lifts the client's pause and sends everything pending now |

### Reconciliation

**Reconcile** (`reconcile`) queues every person and group in the client's
scope. It then lists what the service provider holds and queues a
deprovisioning for every resource whose `externalId` this client linked, or
is an entry of this realm, that is no longer in scope. Resources with any
other `externalId` belong to somebody else and are left alone. A person
already deactivated there is left alone unless deprovisioning is `delete`.

Only an enabled client that is usable is reconciled; a disabled one is
refused (`STS-SCIMC-0017`).

A client can also be reconciled **on a schedule**: `reconcileMinutes`
(`0`, the default, is off) on the client. The cluster scheduler job
**`scim-client.reconcile`** runs every `scimClient.reconcileCheckS` and
reconciles each client whose interval has come round. Only an enabled, usable
client is reconciled on a schedule. Its last result is on the client's page.

### Removing a client

`remove-client` deletes the application entry with its credentials, queues,
links and pause. **Nothing at the service provider changes**: what was pushed
stays there.

### In a service deployed as cells

In a service deployed as [cells](cells.md) (#553), a person's entry exists
only in their home cell, and every cell has every client: a client is an
application entry, which is in the global tier. The client behaves as below.
**In a service that is one cell, none of this applies** and the two
attributes are ignored.

**A person is pushed only from their home cell.** Each cell pushes the people
homed there, from its own deliveries, links and queues, and the connection to
the service provider leaves from that cell. No person's data passes between
cells to reach the provider. A person whose session another cell holds (a
projection) is pushed by their home cell, never by the cell holding the
session.

**Each client says where its service provider is.** Two attributes of the
client's application entry, both on its form and in `add-client` and
`update-client`:

| Member | Attribute | |
|---|---|---|
| `jurisdiction` | `scimClientJurisdiction` | The provider's jurisdiction, as the cell map spells one (`us`, `eu`, `ca`) |
| `cells` | `scimClientCells` | The cells that push to it, by id. Empty (the default) is every cell. A cell not listed sends nothing for this client, so the people homed there are not pushed |

**The issuance policy decides each push.** Before a cell pushes a person, it
asks the issuance policy whether that person's data may go to the client's
jurisdiction: the `release-attributes` question, with the purpose
`scim-provision`, the person's home jurisdiction and the client's
jurisdiction (see [Cells](cells.md) and [XACML](xacml.md)). The built-in rule
is the strict default: the data goes only within one jurisdiction, or where
the realm lists the transfer in `cells.permittedTransfers` (`ca>eu`, say). A
realm's own policy may decide otherwise, even per person.

**A refusal means the person is out of scope.** They are not pushed. Nothing is
asked of the service provider about them, not even a lookup. If they were
pushed before, they are deprovisioned as `deprovision` says. No delivery is
created, so a refusal never appears as a dead letter (`STS-SCIMC-0031`, at
debug level). A client with no jurisdiction is an unknown one, and the strict
default lets nobody's data go there.

**Moving a person to another cell is a handover, not a deprovision.** When a
person leaves a cell's directory, that cell asks the routing index where they
are before acting:

* **homed in another cell now**: this cell drops its link, takes their
  provider id out of its share of every group, and sends nothing. The new home
  cell pushes them, finds the resource by `externalId` (the `entryUUID`, which
  a move keeps) and replaces it. They are never deactivated in between;
* **gone from every cell**: they are deprovisioned, as in one cell.

**Groups are shared by every cell.** A group's definition is the same in every
cell, but each cell holds only its own residents as members (its share). So:

* **membership changes by `PATCH` only.** Each cell adds its own members and
  removes only members it pushed itself. A cell never touches another cell's
  members, and never sends a whole member list where `PATCH` is supported;
* **any cell may create the group.** A second cell's `POST` is answered `409`,
  and that cell adopts the group by `externalId` (the group's `entryUUID`, the
  same in every cell) and patches its members in. It does not replace it;
* **one owner cell renames and deletes it.** The owner is the realm's
  `cells.homeCell` when that cell pushes to the client, else a cell chosen by a
  hash of the group's `entryUUID`; every cell computes the same one. Before
  deleting the group the owner asks every other cell whether it still has
  members in it. It deletes only when every cell answers "none". If a cell
  cannot be reached, the group is not deleted and the owner tries again later
  (`STS-SCIMC-0032`). In `member-groups` mode, a group whose members are all
  in other cells is kept;
* **a service provider without `PATCH`** is written by the owner alone. It
  gathers every cell's share (only the provider's own ids for the members),
  merges them and replaces the group with a `PUT`. If any cell cannot be
  reached, nothing is sent and the owner tries again, so a partial membership
  is never written. The other cells tell the owner when their share changes.

**The pause is shared by every cell.** A network failure, a timeout, `429` or a
`5xx` seen by any cell pauses the client in **every** cell, so a struggling
service provider is not sent several cells' worth of load. When the pause
ends, **one** probe goes for the whole service, from the cell that saw the
failure; the other cells wait for its result. A cell that does not send its
probe within two minutes after the pause ends is assumed to be gone, and
another cell's delivery becomes the probe. The pause is kept in the global
tier; it holds no person's data and is written only on a failure and on the
recovery. `deliver-now` lifts it for every cell.

**The concurrency budget is shared too.** Each cell sends at most
`scimClient.concurrency` divided by the number of cells that push to the
client, rounded up and never less than one, at a time for that client.

**Reconciliation is per cell.** Each cell reconciles the people homed there,
on its own schedule. It deprovisions only what it linked or holds: a remote
resource whose `externalId` is a projection, or a person of another cell, is
left to that cell. Each cell reconciles its share of every group in scope,
and only the owner cell considers deleting a group it did not push itself.

**Every cell on one page.** The **Clients** tab and each client's page show
every cell's queues, gathered from the other cells when the page is drawn:
each cell's counts (queued, retrying, dead, sent) and the pause, and on the
client's page each other cell's retry queue and dead letters. A cell that
cannot be reached is shown as **unreachable**, never left off
(`STS-SCIMC-0034`). Another cell's queued deliveries name the people homed
there, so they are shown only where the issuance policy releases that cell's
residents to the cell you are signed in through (`release-attributes`,
purpose `directory-list`, as for another cell's people on Directory); the
counts are always shown. `GET /admin-api/scim/clients` and
`GET /admin-api/scim` carry the same, as `byCell` on each client and on the
client's page.

**An act may name a cell.** `retry-delivery`, `retry-dead`, `purge-dead`,
`reconcile` and `deliver-now` take a `cell` member and are done in that cell
only. Without one they are done in every cell, and the answer lists each
cell's result in `cells`, a cell that cannot be reached as such:

```
POST /admin-api/scim/clients/purge-dead
{ "id": "partner-idp", "cell": "euc1" }
```

A `cell` the service does not have, a `cell` on an act about the client
itself (`add-client`, `update-client`, `remove-client`,
`issue-certificate`, `test-connection`), or any `cell` in a service that is
one cell, is refused (`STS-SCIMC-0033`). An act sent to a cell that cannot be
reached is refused too (`STS-SCIMC-0034`).

**No cell is ever named to a service provider or a person.** No URL, header,
body or error the service provider sees, and nothing an end user sees, names a
cell. Only the console and `/admin-api` do.

### What it does not do

* **Bulk** (RFC 7644 section 3.7). Every change is its own request.
* **Choose a scheme from `authenticationSchemes`.** It authenticates as
  configured.
* **Send a password**, or this service's own User extension.
* **Push a group nested in a group** as a member.
* **Delete what it pushed when a client is removed.**

### Settings

`scimClient.attempts`, `timeoutMs`, `backoffMs`, `maxBackoffMs`, `leaseMs`,
`sweepS`, `retentionS`, `maxRows`, `concurrency`, `summaryS`,
`reconcileCheckS`, `pageSize`, `etagRetries`, `allowHttp`,
`skipTlsVerification` and `caFile` apply to every client in a realm.
[Configuration → SCIM client](configuration.md#scim-client) has the table. A
client's own configuration is its application entry's `scimClient*`
attributes.

### Error codes

Every failure of the client is recorded under an `STS-SCIMC-NNNN` code: on the
dead letter, on the `scim-client.delivery`, `scim-client.reconcile`,
`scim-client.change` and `scim-client.queue` audit rows, and at the front of
a log line. The most common:

| Code | Meaning |
|---|---|
| `STS-SCIMC-0001` | the client is gone or disabled; its queued change is dead |
| `STS-SCIMC-0002`, `0003`, `0004` | an unusable URL, plain `http`, or unusable TLS material — nothing is sent |
| `STS-SCIMC-0005`, `0006` | a timeout, a network or TLS failure — retried |
| `STS-SCIMC-0007` | a refusal no second try changes (`400`, `408`, a `409` that is not `uniqueness`, …) |
| `STS-SCIMC-0008` | another error status; `429` and `5xx` are retried and pause the client |
| `STS-SCIMC-0009`, `0010` | the credential, token or certificate was refused; the token request failed |
| `STS-SCIMC-0017` | a client definition was refused |
| `STS-SCIMC-0019` | discovery could not be read |
| `STS-SCIMC-0020` | a `409 uniqueness` with nothing to adopt |
| `STS-SCIMC-0021` | stale too often (`412` / `invalidVers`) |
| `STS-SCIMC-0026` | more than one resource there with this entry's `externalId` |
| `STS-SCIMC-0028` | `tooMany`, even narrowed |
| `STS-SCIMC-0029` | a required schema extension the client cannot send |
| `STS-SCIMC-0030` | a required attribute missing |
| `STS-SCIMC-0031` | in a service deployed as cells, the issuance policy kept a person's data out of the provider's jurisdiction; the person is out of scope |
| `STS-SCIMC-0032` | in a service deployed as cells, another cell could not be asked for its share of a group; the group is not deleted or replaced, and the delivery is retried |
| `STS-SCIMC-0033`, `0034` | an act named a cell it cannot go to; another cell did not answer the console's question or an act |

[Error codes](error-codes.md) lists all of them.

## Related

* [LDAP](ldap.md): the directory SCIM writes into
* [Applications](applications.md): an outbound SCIM client is an application
  entry
* [Configuration → Scheduler](configuration.md#scheduler): the cluster
  scheduler `scim-client.deliver` and `scim-client.reconcile` run on
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md): where a `scim:*` token
  comes from
* [OAuth security](oauth-security.md): DPoP and certificate-bound tokens
* [TLS and mutual TLS](tls.md): the client truststore
* [Authentication](authentication.md): the sign-on session the cookie scheme
  uses
* [Shared Signals](shared-signals.md) and [CAEP events](caep-events.md): what a
  disable sends
* [XACML](xacml.md): the access gate after the scope check
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md)
