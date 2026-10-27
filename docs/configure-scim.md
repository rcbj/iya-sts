---
title: "Configuring SCIM 2.0"
---

# Configuring SCIM 2.0

This page shows how to set up iya-sts for SCIM 2.0 in both directions: as a
**service provider** at `/scim/v2`, which a provisioning client writes people
and groups into, and as a **client**, which pushes a realm's people and
groups to somebody else's SCIM service provider. Each recipe covers what to
register, the settings to change, and the requests that are then sent. It is
given twice: once as steps in the **admin console** and once as
**Management API** calls.

The values come from this repository's test jobs, and each recipe names the
job it is taken from. Most are `tests/protocol/` jobs, which run over HTTP
against a service in both development and product mode. A few are
in-process tests in `tests/`, and the recipe says so. Change the names,
URLs and secrets to your own.

How SCIM *behaves* here, the attribute mapping, and every setting with its
default, is on [SCIM](scim.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/scim` | **Protocols → SCIM** | The **Server** tab: which authentication schemes are offered, the limits, and every `scim.*` setting, saved with **Save SCIM**. The **Clients** tab: the outbound clients, **Add a SCIM client**, and the `scimClient.*` settings, saved with **Save SCIM client**. |
| `/admin/scim?client=<identifier>` | click a client's row on the **Clients** tab | Change the client, test it, reconcile it, and work its retry and dead-letter queues. |
| `/admin/scim/monitor` | **Monitoring → SCIM metrics** | Calls, failures and latency per operation and per scheme, and the last fifty requests. |
| `/admin/applications` | **Directory → Applications** | Register the OAuth client a provisioning client gets its token with. |
| `/admin/policies` | **Directory → Policies** | The attribute policy, which decides what a provisioned person must carry in product mode. |
| `/admin/users`, `/admin/groups` | **Directory → Users**, **Directory → Groups** | The people and groups SCIM wrote. They are directory entries, so `ldapsearch` sees them too. |

Every trust realm has its own endpoint, `/realm/<id>/scim/v2`, and writes into
that realm's directory. The live description of the surface, with the
mapping table, is `GET /scim` (`?format=json`) and `GET /admin-api/scim`.

**What development and product mode change.** A credential is required in
both modes. What differs is how much of it is checked:
* **OAuth tokens** are verified in both modes. `scim:read` reads and `scim:write` writes, and neither implies the other.
* **HTTP Basic** accepts any username and any password but `invalid` in development. Product mode verifies the password against the person's `userPassword`, and refuses a person who holds or must hold a second factor unless they use an app password.
* **HTTP Digest** uses one shared password, `scim.digestPassword` (`password!`), in development. Product mode does not offer Digest at all.
* **HOBA** lets anybody register a key for any name in development. In product mode only the signed-in owner of an existing account may.
* **What a new person must carry.** Product mode refuses a person without what the realm's attribute policy requires: `userName`, `name.familyName`, and by default `name.givenName` and `emails`. Development mode requires none of it, and by default fills in an invented persona (`scim.inventOnCreate`).
* **The SCIM scopes are tied to the client in both modes.** They are issued only to a client whose `oauthAllowedScope` lists them.

---

# The service provider

## Read the discovery documents

The three discovery documents answer without a credential, because the
ServiceProviderConfig is where a client learns which credentials are
accepted. `scim.authDiscovery` turns that off. Held by the in-process test
`tests/scim_auth_discovery.js`.

```bash
curl -sk "$BASE/scim/v2/ServiceProviderConfig"
curl -sk "$BASE/scim/v2/ResourceTypes"
curl -sk "$BASE/scim/v2/Schemas"
```

The ServiceProviderConfig is rebuilt from the settings on every request. Its
`authenticationSchemes`, `filter.maxResults`, `bulk.maxOperations` and
`bulk.maxPayloadSize` are the values the endpoints actually apply. A request
to any other endpoint without a credential is refused `401`, with one
`WWW-Authenticate` challenge per scheme offered.

## A provisioning client with an OAuth token

The recommended credential. A confidential client gets a `scim:read
scim:write` token by the `client_credentials` grant, and sends it as
`Bearer`. Taken from `sts_scim_conformance.js`, which runs two independent
SCIM conformance harnesses with this token in a throwaway realm.

**Console:**
1. Register a confidential client as in [Configuring OAuth 2.0 grants → Client credentials](configure-oauth2-grants.md#client-credentials), with `client_secret_basic` as its auth method.
2. On the application's page, use **Add to** on `oauthAllowedScope` twice: `scim:read`, then `scim:write`.

**API:** the job creates a realm, opens dynamic registration in it (product
mode closes it), registers the client, and declares the two scopes:

```bash
api realms/create '{"id":"scimc1","domain":"scimc1.example.net","name":"SCIM conformance scimc1"}'
RB=$BASE/realm/scimc1
api() { curl -sk -X POST "$RB/admin-api/$1" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$2"; }
api config/set '{"key":"oauth2.openRegistration","value":true}'

curl -sk -X POST "$RB/oauth2/register" -H 'content-type: application/json' \
  -d '{"grant_types":["client_credentials"],
       "token_endpoint_auth_method":"client_secret_basic",
       "client_name":"SCIM conformance harnesses"}'
# -> 201 with client_id and client_secret

api applications/add '{"application":"<client_id>","attribute":"oauthAllowedScope","value":"scim:read"}'
api applications/add '{"application":"<client_id>","attribute":"oauthAllowedScope","value":"scim:write"}'
```

**The token request:**
```bash
curl -sk -u "<client_id>:<client_secret>" "$RB/oauth2/token" \
  -d grant_type=client_credentials -d 'scope=scim:read scim:write' \
  -d "resource=$RB/resource"
```

`resource` is the realm's own resource server, which the jobs name. Send the
`access_token` as `Authorization: Bearer …` on every SCIM request. A DPoP-
or certificate-bound token works too, with its proof or its certificate.

A token without the right scope is `403` with `insufficient_scope`. A token
this service did not issue, or one that was revoked, is `401`. Taking a scope
off `oauthAllowedScope` stops tokens already issued under it
(`STS-SCIM-0079`).

## Create a person and a group, and add a member

Taken from `sts_directory_bulk_load_scim.js`, which creates people and groups
this way and adds each membership with one PATCH, and from
`sts_scim_client.js` for the person's values. Both send
`application/scim+json`.

```bash
scim() {   # scim <METHOD> <path under /scim/v2> ['<json body>']
  curl -sk -X "$1" "$RB/scim/v2$2" -H "Authorization: Bearer $SCIM_TOKEN" \
    -H 'content-type: application/scim+json' -H 'accept: application/scim+json' \
    ${3:+-d "$3"}
}

scim POST /Users '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName":"scimc-pat",
  "name":{"givenName":"Pat","familyName":"scimc-pat"},
  "displayName":"Pat scimc-pat",
  "emails":[{"value":"scimc-pat@scim-client.test","type":"work"}]}'
# -> 201; "id" is the entry's entryUUID

scim POST /Groups '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName":"scimc-group","members":[]}'

scim PATCH /Groups/<group id> '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations":[{"op":"add","path":"members","value":[{"value":"<user id>"}]}]}'
```

The person is the directory entry `uid=scimc-pat,ou=users,<base>`, and the
group `cn=scimc-group,ou=groups,<base>`. A member's `value` is the member's
SCIM `id`. A DN is accepted too, for a client that stored one.

Things the person may and may not carry:
* `emails[].type` is `work` only, `phoneNumbers[].type` is `work` or `mobile`, and `addresses[].type` is `work`. Another type is `400 invalidValue`.
* A member this service does not store, such as `nickName` or `photos`, is not in `/Schemas`, and a PATCH to it is `400 invalidPath`.
* `userName` is unique. A taken name is `409 uniqueness`, and the name `invalid` is `400 invalidValue`.
* A resource that uses the enterprise extension lists its URN, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`, in `schemas`.

**In development mode** a created person is filled in with an invented
persona unless `scim.inventOnCreate` is off. The two conformance jobs turn it
off, so that what they read back is what they wrote:

```bash
api config/set '{"key":"scim.inventOnCreate","value":false}'
```

## Filter, sort and page

Taken from the in-process test `tests/scim_conformance_fixes.js`, which
creates four users `sc-page-a` to `sc-page-d` and pages through them.

```bash
scim GET '/Users?filter=userName%20sw%20%22sc-page-%22&count=2&startIndex=1&sortBy=userName'
scim GET '/Users?filter=userName%20eq%20%22SC-PAGE-A%22'          # userName ignores case
scim GET '/Users?attributes=userName,emails'
scim POST /Users/.search '{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  "filter":"userName sw \"sc-page-\"","startIndex":1,"count":2}'
```

* `count` is clamped to `scim.maxResults` (200).
* A `startIndex` past `totalResults` is an empty `Resources` with `itemsPerPage` 0.
* A filter the server cannot evaluate is `400 invalidFilter`, never an empty list. So is ordering a boolean (`active gt true`).
* `POST /.search` at the root answers one filter from Users and Groups together. A `.search` body without the SearchRequest URN is `400 invalidSyntax`.

## Disable and enable a person

`active` is the account's administrative lock. `active: false` is the same act
as **Disable** on the person's console page: every door then refuses them,
and their sessions end. Taken from the in-process test
`tests/account_disable.js`, which does this with a PATCH and with a PUT.

```bash
scim PATCH /Users/<id> '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations":[{"op":"replace","path":"active","value":false}]}'
```

`true` enables them again. A PUT or PATCH that does not mention `active`
leaves the lock as it was, so a client that never sends it cannot re-enable an
account an administrator disabled. A PUT replaces only the attributes the
mapping covers; everything else on the entry is left alone.

## Bulk

`POST /scim/v2/Bulk` runs the operations in order and answers each with its
own status, so a request in which one operation failed is still `200`.
Taken from the in-process test `tests/directory_bulk_delete.js`, whose
`bulkId` reference makes a group whose member is a user created earlier in
the same request.

```bash
scim POST /Bulk '{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
  "Operations":[
    {"method":"POST","path":"/Users","bulkId":"again",
     "data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"dbd-carol"}},
    {"method":"POST","path":"/Groups","bulkId":"grp",
     "data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName":"dbd-carols","members":[{"value":"bulkId:again"}]}}]}'
```

More than `scim.bulkMaxOperations` (100) operations, or a body over
`scim.bulkMaxPayloadSize` (1 MiB), is refused `413`. In product mode the
user above would also need the attribute policy's required members (below).

## HTTP Basic, and people who hold a second factor

Basic needs no client registration. In development any username and any
password but `invalid` are accepted. In product mode the password is
verified, and a person who holds or must hold a second factor is refused
their own password with the same `401` a wrong one gets. They use an **app
password** scoped to `scim`. Taken from `sts_second_factor_doors.js`.

**Console:** on the person's page, open the **Second factors** tab. Under
**App passwords**, give it a name, tick **SCIM**, and click **Make an app
password**. It is shown once.

**API:**
```bash
api users/create-app-password '{"user":"bob","name":"scim job","doors":["scim"]}'
curl -sk -u "bob:<appPassword>" "$RB/scim/v2/Users?count=1" -H 'accept: application/scim+json'
```

A password reset leaves the app password working. It is refused at the
sign-in screen and at every door it does not name.

**Prefer a token for bulk work.** Product mode checks a Basic password with
scrypt on every request, about 70 ms of CPU each. A token is a signature
check. That is why `sts_directory_bulk_load_scim.js` moved from Basic to a
token.

## Choose which schemes are offered

All six of RFC 7644 section 2's schemes are on by default: OAuth tokens
(Bearer and DPoP), Basic, Digest, HOBA, the session cookie and a TLS client
certificate. A scheme turned off disappears from the challenges and from the
ServiceProviderConfig together. To exercise a client's scope handling, turn
off everything but tokens, because only tokens carry scopes. A TLS client
certificate this realm issued to an **application** is held to the SCIM
scopes that application's `oauthAllowedScope` declares (see below). Every
other accepted credential may both read and write. A certificate from an
outside certificate authority is accepted only as the one entry storing it in
`userCertificate` ([TLS](tls.md#a-certificate-from-an-outside-certificate-authority)).

### An application's certificate, held to what it declares

A provisioning client can authenticate with a TLS client certificate issued
to its application, with no token. The certificate carries no scopes, so the
application's `oauthAllowedScope` stands in for them, on every request:
`scim:read` to read and `scim:write` to write. An application that declares
neither is refused `403` (`STS-SCIM-0083`), one that declares only
`scim:read` may only read, and removing a value cuts the certificate off at
once. A person's certificate is not affected.

1. On the application's page, use **Add to** on `oauthAllowedScope`:
   `scim:read`, and `scim:write` if it writes.
2. Issue the certificate on the same page (**Issue a TLS client
   certificate**), and install it in the client.
3. Call `/scim/v2` over HTTPS on the main port with it.

**API:**
```bash
api applications/add '{"application":"<id>","attribute":"oauthAllowedScope","value":"scim:read"}'
api applications/add '{"application":"<id>","attribute":"oauthAllowedScope","value":"scim:write"}'
api applications/issue-tls-client-certificate '{"application":"<id>","password":"<file password>"}'
```

A SCIM client of this service's own (`/admin/scim/clients`) whose
certificate was issued here and that provisions into this same realm is such
an application, and needs the declaration too.

**Console:** on **Protocols → SCIM**, **Server** tab, turn off the rows you do
not want (**Offer HTTP Basic**, **Offer HTTP Digest**, **Offer HOBA**, **Offer
the session cookie**, **Offer TLS client certificates**), and click **Save
SCIM**.

**API:**
```bash
api config/set-many '{"scim.authBasic":false,"scim.authDigest":false,"scim.authHoba":false,
  "scim.authCookie":false,"scim.authClientCert":false}'
```

Digest, HOBA and the certificate scheme each have more to set up. [SCIM →
Authentication](scim.md#authentication-all-six-schemes-of-rfc-7644-section-2)
describes them. No test job above uses them over HTTP.

## The attribute policy, in product mode

A product-mode realm refuses a SCIM create that lacks an attribute its
attribute policy requires, and a PUT or PATCH that would take one away, with
`400 invalidValue`. `uid`, `cn` and `sn` are always required (`userName`,
`displayName` or the two names, and `name.familyName`). By default
`givenName` and `mail` are too (`name.givenName` and `emails`).
`sts_scim_conformance.js` narrows the policy to the three that cannot be
lifted, because the conformance harnesses create users with only `userName`
and a name.

**Console:** on **Directory → Policies**, open the **Attribute policy** tab,
untick `givenName` and `mail` under **Required**, and click **Save the
profile**.

**API:**
```bash
api policies/save-attributes-policy '{"profile":"default","requiredAttributes":[]}'
```

Development mode stores and shows the policy but does not enforce it.

---

# The outbound client

A realm can push its people and groups to any number of remote SCIM service
providers. Each client is an application entry, sends what it owes on the
`scim-client.deliver` scheduler job, and keeps its own retry and dead-letter
queues. [SCIM → The outbound SCIM client](scim.md#the-outbound-scim-client)
describes what it sends and when.

## Push one realm into another realm's /scim/v2

Taken from `sts_scim_client.js`. Two throwaway realms on one service: the
**target** realm is the service provider, and the **source** realm holds a
person, a group with that person in it, and the client.

**1. The target.** Its `/scim/v2` needs a token, so register a confidential
client there with `scim:read` and `scim:write`, as in
[A provisioning client with an OAuth token](#a-provisioning-client-with-an-oauth-token)
above. The job also turns off `scim.inventOnCreate` in the target.

**2. The source realm, a person and a group:**
```bash
api realms/create '{"id":"scimcs1","domain":"scimcs1.example.net","name":"SCIM client source"}'
SRC=$BASE/realm/scimcs1
src() { curl -sk -X POST "$SRC/admin-api/$1" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$2"; }
src users/create '{"username":"scimc-pat","invent":false,
  "attributes":{"cn":"Pat scimc-pat","givenName":"Pat","sn":"scimc-pat",
                "mail":"scimc-pat@scim-client.test"}}'
src groups/create '{"group":"scimc-group","members":["scimc-pat"]}'
```

**3. The client.**

**Console:** on **Protocols → SCIM**, open the **Clients** tab. Under **Add a
SCIM client**:
1. **Identifier** `scimc-push`, **Name** `Into scimct1`, **Enabled** `true`.
2. **SCIM base URI** `https://<host>/realm/scimct1/scim/v2`.
3. Under **Authentication**: **Method** `oauth2`, **Token endpoint** `https://<host>/realm/scimct1/oauth2/token`, **client_id** and **Client secret** from the target's registration, **Token endpoint authentication** `client_secret_basic`, **Scope** `scim:read scim:write`, **Resource** `https://<host>/realm/scimct1/resource`.
4. In **CA certificates to trust (PEM)**, paste the CA that signed the target's certificate. Here that is this service's own Root, from `GET /tls/server-certificate`.
5. Under **Who and what is pushed**: **People pushed** `groups`, **Groups whose members are pushed** `scimc-group`, **Groups pushed** `selected`, **Selected groups** `scimc-group`, **When someone leaves the scope** `deactivate`.
6. Click **Add**.

**API:**
```bash
TGT=$BASE/realm/scimct1
src scim/clients/add-client '{"identifier":"scimc-push","name":"Into scimct1",
  "baseUrl":"'"$TGT"'/scim/v2","authMethod":"oauth2",
  "tokenEndpoint":"'"$TGT"'/oauth2/token",
  "oauthClientId":"<client_id>","oauthClientSecret":"<client_secret>",
  "oauthClientAuth":"client_secret_basic","oauthScope":"scim:read scim:write",
  "oauthResource":"'"$TGT"'/resource",
  "scopeMode":"groups","scopeGroups":"scimc-group",
  "groupMode":"selected","groups":"scimc-group",
  "deprovision":"deactivate","enabled":"true",
  "caCertificates":"'"$(cat sts.pem)"'"}'
```

The answer shows the client with `usable` true and `oauthClientSecretSet`
true. The secret is sealed on the entry and never returned. A new client is
off until `enabled` is `true`.

**4. Test, reconcile, and watch it go.** On the client's page these are
**Test the connection**, **Reconcile now** and **Send now**.

```bash
src scim/clients/test-connection '{"id":"scimc-push"}'   # reads the target's discovery
src scim/clients/reconcile '{"id":"scimc-push"}'         # queues the person and the group
curl -sk "$SRC/admin-api/scim/clients?client=scimc-push" -H "Authorization: Bearer $TOKEN"
```

What the job then finds at the target:
* a User `scimc-pat` whose `externalId` is the source entry's `entryUUID`;
* a Group `scimc-group` whose member is the target's own `id` for that User;
* after `users/set-attribute` of `title` and `deliver-now`, the same User with the new title;
* after `users/disable` and `deliver-now`, the same User with `active: false`. A disabled person is always sent as `active: false`, whatever `deprovision` says;
* the client's queue empty: nothing queued or retrying, no dead letter, no pause.

```bash
src users/set-attribute '{"user":"scimc-pat","attribute":"title","value":"Provisioned"}'
src scim/clients/deliver-now '{"id":"scimc-push"}'
src users/disable '{"user":"scimc-pat"}'
src scim/clients/remove-client '{"id":"scimc-push"}'
```

Removing a client changes nothing at the service provider. What was pushed
stays there.

**The service provider's certificate is always verified, host name
included.** The client trusts the public roots, its own `caCertificates`, and
the file `scimClient.caFile` names. `scimClient.skipTlsVerification` turns the
check off in development only. A service provider on plain `http` is refused
unless the realm is in development mode with `scimClient.allowHttp` on; the
job turns that on only when the service itself answers `http`.

## Other ways to authenticate

Taken from the in-process test `tests/scim_client.js`, which drives the client
against a SCIM service provider written in the test.

| `authMethod` | What to fill in | Example from the test |
|---|---|---|
| `basic` | **User name** and **Password** | `"authMethod":"basic","username":"pusher","password":"<secret>"` |
| `oauth2` | **Token endpoint**, **client_id**, **Client secret**, and optionally **Scope**, **Resource** and **Token endpoint authentication** (`client_secret_basic` or `client_secret_post`) | the recipe above |
| `none` | nothing but a TLS client certificate | `"authMethod":"none","tlsSource":"issued"` |

**A TLS client certificate** goes with any of the three. **TLS client
certificate** (`tlsSource`) is `none`, `uploaded` (paste **Uploaded
certificate and chain (PEM)** and **Uploaded private key (PEM)**), or
`issued`. For `issued`, add the client, then click **Issue a TLS client
certificate** on its page:

```bash
src scim/clients/add-client '{"identifier":"mtls-1","baseUrl":"https://sp.example.com/scim/v2",
  "authMethod":"none","tlsSource":"issued","caCertificates":"<the SP CA, PEM>"}'
src scim/clients/issue-certificate '{"id":"mtls-1"}'
```

Until the certificate is issued the client is listed as not usable, and
nothing is sent for it. The answer carries this service's Root (`rootPem`),
which the service provider must trust.

## Who is pushed, and what leaving means

Taken from the in-process test `tests/scim_client.js`. Change these on the
client's page with **Change this client** and **Save**, or with
`update-client`, which keeps every member it is not given:

```bash
src scim/clients/update-client '{"id":"basic-1","scopeMode":"filter",
  "scopeFilter":"(givenName=Alice)","deprovision":"delete"}'
src scim/clients/reconcile '{"id":"basic-1"}'
```

| Member | Values |
|---|---|
| `scopeMode` (**People pushed**) | `all`; `groups`, with `scopeGroups`; `filter`, with an RFC 4515 `scopeFilter` such as `(givenName=Alice)` |
| `groupMode` (**Groups pushed**) | `none` (the default); `selected`, with `groups`; `member-groups`, every group with somebody in scope; `all` |
| `deprovision` (**When someone leaves the scope**) | `deactivate` (the default) sends `active: false`; `delete` sends a `DELETE` |
| `reconcileMinutes` | `0` (the default) reconciles only on demand; `1440` once a day, on the `scim-client.reconcile` job |
| `maxRequestsPerSecond` | empty or `0` is no limit |

In the test, the filter keeps Alice and drops Bob, and a reconciliation then
`DELETE`s Bob at the service provider. A filter that does not parse is refused
when the client is saved.

## Retries and dead letters

A network failure, a timeout, `429`, `500`, `502`, `503` and `504` are retried
with a backoff, and pause the client. Anything else is a dead letter at once.
On the client's page:

| Button | API action | What it does |
|---|---|---|
| **Retry** (on a row) | `retry-delivery` with `{"id":"<client>\|User\|<uuid>"}` | sends one dead letter again |
| **Retry every dead letter** | `retry-dead` | sends every dead letter again |
| **Purge dead letters** | `purge-dead` | deletes them |
| **Send now** | `deliver-now` | lifts the pause and sends everything pending |

Each dead letter carries an `STS-SCIMC-NNNN` code. [SCIM → Error
codes](scim.md#error-codes) lists the common ones. The `scimClient.*`
settings (attempts, backoff, concurrency, sweep interval) are on the
**Clients** tab, saved with **Save SCIM client**, and listed in
[Configuration → SCIM client](configuration.md#scim-client).

## Related

* [SCIM](scim.md): the behaviour, the mapping, every setting, and the outbound client in a service deployed as cells.
* [Configuring LDAP](configure-ldap.md) and [LDAP](ldap.md): the directory SCIM writes into.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md): the client a SCIM token comes from.
* [Applications](applications.md): an outbound client is an application entry.
* [Management API](management-api.md): the token, and the OpenAPI document at `/admin-api/openapi.json`.
* [Trust realms](trust-realms.md) and [TLS and mutual TLS](tls.md).
