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
    -> an access token for dave                carries its attributes
```

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

A created group gets an entry under `ou=groups` with a `groupOfNames` object
class. A group list includes everything the directory counts as a group: entries
under `ou=groups` and entries carrying a group object class anywhere. On a read,
`member`, `uniqueMember` and `memberUid` are all resolved as members. A write
puts values in `member` and clears the other two. **A member that names nothing
is accepted** and logged, because this directory does no referential integrity.

**Being provisioned is not authenticating.** A person created over SCIM has an
entry with `origin: scim` and no row on `/admin/users` until they sign in
somewhere.

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
`meta.created` and `meta.lastModified` come from the timestamps.

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
| send a filter the server cannot evaluate | `400 invalidFilter` |
| send nothing | `401` with every offered challenge |
| use a token with the wrong scope | `403 insufficient_scope` |
| use a token this service did not issue, or a revoked one | `401` |
| use Basic with the password `invalid` | `401` |
| use Digest with a wrong password, a stale nonce or a repeated `nc` | `401`, three ways |
| use a HOBA signature that does not verify, or a repeated triple | `401` |
| `GET /Me` with no credential, or any `POST /Me` | `501` |
| POST to `.search` without the SearchRequest URN | `400 invalidSyntax` |
| send a Bulk request over `scim.bulkMaxOperations` | `413 payloadTooLarge` |

### Not implemented

* **ETag** versioning. A version built over a one-second timestamp would be a
  concurrency control a client trusts and that is wrong.
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

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `scim.enabled` | `SCIM_ENABLED` | `true` | yes | Turns the family on; off leaves the routes registered and answering `501`. |
| `scim.maxResults` | `SCIM_MAX_RESULTS` | `200` | yes | The largest page a list or search returns, published as `filter.maxResults`; a larger `count` is clamped. |
| `scim.bulkMaxOperations` | `SCIM_BULK_MAX_OPERATIONS` | `100` | yes | How many operations one Bulk request may carry, published as `bulk.maxOperations`. |
| `scim.bulkMaxPayloadSize` | `SCIM_BULK_MAX_PAYLOAD_SIZE` | `1048576` | yes | The largest Bulk body in bytes, published as `bulk.maxPayloadSize` and checked against that number. |
| `scim.authDiscovery` | `SCIM_AUTH_DISCOVERY` | `false` | yes | Whether the three discovery documents also need a credential. |
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

## In the running service

* **Protocols → SCIM** (`/admin/scim`): the six schemes and which are on, the
  endpoints, what SCIM here will not do, the negatives you can provoke, the
  attribute mapping, counters of what has been done, and every `scim.*` setting.
* **Monitoring → SCIM metrics** (`/admin/scim/monitor`): calls, successes and
  failures, latency and bytes per operation, counts per resource type and per
  scheme (including schemes at zero), one row per authenticated principal, and
  the last fifty requests. A caller the gate refused is counted as refused, not
  as a client. There is no reset. One Bulk request carrying five creates counts
  as one `bulk` and five `create`s.
* `GET /scim`: a description of the surface, the mapping table and the schemes,
  with `?format=json`. It is not a SCIM endpoint.
* The management API: `GET /admin-api/scim` and `GET /admin-api/scim/monitor`.
* The provisioned people and groups: **Users** (`/admin/users`), **Groups**
  (`/admin/groups`) and `/admin/ldap/directory`.

`GET /admin/sts-metadata` lists every SCIM endpoint. Every SCIM failure is
recorded under an `STS-SCIM-NNNN` code on the audit row and never sent to a
client. See [error codes](error-codes.md).

## Related

* [LDAP](ldap.md): the directory SCIM writes into
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
