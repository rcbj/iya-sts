---
title: Management API
---

# Management API

`/admin-api` is the administrative console at `/admin` over JSON, for a
script, a CI job or a test rather than a person. Whatever the console shows
can be read here, and whatever it can change can be changed here. It is not a
protocol, but it is protected like one: every call carries an
[OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) access token that this
service issued, in the [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)
format and audienced to the API by an
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicator. The API
works per [trust realm](trust-realms.md), and each realm's administrators have
a token of their own that is confined to their realm.

The OpenAPI 3.1 document is generated from the same table that registers the
routes, so an operation cannot exist without being documented. Read the
document rather than any list on this page: `GET /admin-api/openapi.json`, or
the explorer on the console at `/admin/api-explorer`.

## Getting a token

The service seeds an application called **`sts-management-api`** in every
realm. It is a confidential OAuth client that can only use the
client-credentials grant. It has no redirect URI, it authenticates with
`client_secret_basic`, and its registered scope is `admin:read admin:write`.

| Scope | Lets the token |
|---|---|
| `admin:read` | make any `GET` request |
| `admin:write` | make anything else, meaning every `POST` that changes state |

To get a token, call the token endpoint with the client-credentials grant, the
scopes you need, and `resource=<base>/admin-api`. The `resource` value sets
the token's audience, and the API refuses a token audienced to anything else.

```bash
BASE=https://localhost:8081          # the main port is HTTPS by default

TOKEN=$(curl -sk -u "sts-management-api:$ADMIN_API_CLIENT_SECRET" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode 'scope=admin:read admin:write' \
  --data-urlencode "resource=$BASE/admin-api" \
  "$BASE/oauth2/token" | jq -r .access_token)

curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/admin-api/status" | jq

curl -sk -X POST "$BASE/admin-api/config/set" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"key":"groups.claimName","value":"roles"}'
```

(`-k` is there because development mode signs the listener's certificate with
an authority it generates at each start. See [TLS](tls.md).)

### The client secret

**`adminApi.clientSecret` sets the secret.** If it is empty, a new secret is
generated at every start. That secret can only be read through the API it
unlocks, so after a restart nobody can get a token wherever secrets are
checked. Any deployment, and any launcher that starts the service for a test
run, should set `adminApi.clientSecret` (`ADMIN_API_CLIENT_SECRET`) **before
the service starts**, because the seeded client reads the setting when it is
created. After that, the setting is the only way to change the secret: the
default realm's `regenerate-secret` action on this client is refused while the
secret is pinned.

In development mode, outside [RFC 9700 and OAuth 2.1 mode](oauth-security.md),
the token endpoint does not check client credentials. In product mode it
does. See [what is not checked](what-is-not-checked.md).

### What the API checks on the token

It checks these in order, in both modes, and each failure gets its own
refusal:

* **Present at all.** If there is no token, the answer is 401 with
  `WWW-Authenticate: Bearer`, naming both scopes and the `resource` to ask for.
* **Signed by this service**, meaning the default realm's key, or the realm's
  own key under a realm prefix (see below). Then **not expired**, and **not
  revoked**: a token this service has since revoked is refused, and so is one
  issued to a person whose account is now disabled.
* **An access token.** The `typ` header must be `at+jwt` (RFC 9068
  section 4), so an ID Token or refresh token signed with the same key is not
  accepted.
* **An issuer this service publishes, at the address you are calling.** An
  issuer is an address, so a token minted under one host name is refused
  under another. Mint the token at the address you will call the API at, or
  set `global.publicBaseUrl`.
* **The audience.** A token for a different audience gets 403. Bearer tokens
  minted for other resource servers must not be replayable here.
* **Its sender constraint, if it has one.** A certificate-bound token
  (`cnf["x5t#S256"]`) must arrive on a connection that presents that
  certificate. A DPoP-bound token (`cnf.jkt`) must be sent as
  `Authorization: DPoP <token>` with a valid proof, not as a Bearer token.
  `oauth2.accessTokenRequireDpop` and `oauth2.accessTokenRequireMtls` apply
  here as they do at every other resource server in the service
  ([OAuth security](oauth-security.md)).
* **The scope the method needs.** The scopes become the built-in `ADMIN_READ`
  and `ADMIN_WRITE` roles, and the XACML `access-control` policy decides
  whether that role is enough. A read-only token that tries a `POST` gets a
  403 from the policy, and the message names the scopes the token has.

The refusals are in the `STS-API-*` rows of [error codes](error-codes.md).
The code is recorded in the audit log and the service log, and is never sent
to the caller.

## What it covers

### Every console control, for a machine

**Every control added to `/admin` gets an operation on `/admin-api` in the
same change.** An API that covers eight of nine controls is worse than one
that covers none, because the missing one is found by a caller who has
already written code that assumed it was there. Parity is kept structurally:

* **The API decides nothing on its own.** Each `POST` calls the same action
  function the console's form posts to, with the action taken from the URL
  (`POST /admin-api/tokens/revoke`) rather than from a hidden form field.
  Each `GET` returns the same view the console page's `?format=json` returns.
  The two doors cannot disagree about what is allowed.
* **A page with no form has only a `GET`.** The audit log is an example.
  There is nothing to change, so there is no operation to mirror.
* **Each operation's description ends by naming the console control it
  mirrors**, so you can look up the page that shows the same thing.
* **An unknown action is not a 404.** It gets the console's own "Unknown
  action" refusal, which lists the actions that exist.

### The areas, broadly

The operations are grouped in the OpenAPI document by tag. Broadly, they
cover:

* **The service itself.** Status and totals, metrics, configuration (read,
  `set`, `set-many`, `reset`, `reset-all`), trust realms, token lifetimes,
  persistence, the database, encryption at rest, secrets, caches, the
  scheduler, the cluster, the error-code table and the audit log.
* **Identities.** People and groups in the directory, second factors (TOTP,
  WebAuthn, recovery codes), password policies, sessions and sign-out.
* **Applications and what they are issued.** The application register,
  consent, permissions, roles, delegation and who may delegate (`GET
  /admin-api/delegation/policy`), issued tokens, the claim and SAML
  attribute sets, and signing keys.
* **Each protocol family's settings and state.** OAuth 2.0 / OIDC and
  authorization servers, SAML 2.0 and 1.1, WS-Trust, WS-Federation, federation
  relationships, Kerberos principals, LDAP, SCIM, SPIFFE, Shared Signals
  (CAEP, RISC), OpenID4VCI, OpenID4VP and credential status, XACML, GNAP, and
  certificate enrollment (ACME, EST, SCEP).
* **The PKI.** Certificate authorities, key pairs, certificates and the
  TLS truststore.
* **Administration.** The two console roles (`/admin-api/rbac`) and the API
  explorer's own report.

For the full list, with request and response schemas and examples, see
`GET /admin-api/openapi.json`. The index at `GET /admin-api` returns the
version and build, whether the API is protected, and a one-line summary of
every operation.

### Request bodies

A `POST` takes a JSON body. Before the operation runs, the body is checked
against the schema the OpenAPI document publishes for it. An unknown member or
a value of the wrong type gets `400 { "ok": false, "errors": [...] }`
(`STS-API-0009`) and nothing changes. Every `POST` replies with the console
action's own result: `ok` is always present, and the other members depend on
the action.

### The explorer

`/admin/api-explorer` is a console page, behind the console's session and
roles. It shows the document, a form for each operation, the response, and
the equivalent `curl` command. Its **Try it** button calls `/admin-api` with a
token the page mints for you. That token carries only the scopes your console
roles grant (`admin:read` for Admin Read, `admin:write` for Admin Write). The
API still checks it on every call, so a reader with only Admin Read who tries
a `POST` gets the same 403 as from a terminal.

The explorer mints a default-realm token, which is a service credential, so a
realm's own administrators cannot see it. It also stops working while
`oauth2.accessTokenRequireDpop` is on, because its script sends a plain Bearer
header and has no DPoP key to prove. With that setting on, use `curl` and a
proof.

## Trust realms and per-realm administrators

The API is scoped to a realm by the same path prefix as every other endpoint.
`/admin-api/config` is the default realm's configuration and
`/realm/acme/admin-api/config` is `acme`'s. A `set` posted to the second
changes `acme` alone. Every operation works per realm.

**The five operations under `/admin-api/realms` manage the realm registry**,
and there is one registry per process. `GET /admin-api/realms` returns the
same list under any prefix, with `current` naming the realm the call arrived
in. `remove` refuses to remove that realm, because the caller would be left
calling a prefix that no longer exists.

**Two kinds of token are accepted:**

| Token | Minted at | Accepted at | May do |
|---|---|---|---|
| The service token | the default realm's `/oauth2/token`, with `resource=<base>/admin-api` | `/admin-api` and every `/realm/<id>/admin-api` | everything its scopes allow |
| A realm's own token | `/realm/<id>/oauth2/token` as that realm's `sts-management-api`, with `resource=<base>/realm/<id>/admin-api` | `/realm/<id>/admin-api` only | that realm's operations only |

**Either token must have been issued to a client that declares the scope it
uses** (#110, 2026-09-22). `admin:read` and `admin:write` are issued only to a
client whose `oauthAllowedScope` lists them, in both modes — any other client is
refused `invalid_scope` at the token endpoint — and the API asks again on every
call, in the realm that issued the token: a token whose client no longer
declares the scope an operation needs is refused 403 (`STS-API-0123`), so
withdrawing the declaration cuts off tokens already issued. The seeded
`sts-management-api` and `sts-admin-console` declare both in every realm; an
administrator may declare them on another client with
`POST /admin-api/applications/add`. A dynamic registration may not.

A realm's token is tried only under that realm's prefix. It must carry the
realm's issuer and audience. The token is then
refused whatever the console refuses the realm's administrators
(`STS-API-0112`), and the same rule decides both doors:

* service pages: persistence, database, encryption, secrets, the debugger,
  TLS and its truststore, the LDAP service page, and the API explorer;
* creating or removing a realm, or naming another realm;
* `build-root` or a `*` scope on the PKI, and exporting the `tls-server` key;
* any setting that belongs to the process: every `admin.*`, `adminApi.*`,
  `realms.*`, `workers.*`, `persistence.*`, `debugger.*`, `tls.*` and `keys.*`
  row, `global.mode`, `global.publicBaseUrl` and the listener settings, among
  others.

**A realm's client secret is generated at each start** and is not pinned by
`adminApi.clientSecret`, which applies only to the default realm's client. A
realm administrator reads or regenerates it on their realm's console at
`/realm/<id>/admin/applications?application=sts-management-api`.

[Trust realms](trust-realms.md) covers realm administrators on the console
side.

## Development and product mode

With `adminApi.authRequired` on (the default), **both modes require the token
and check it the same way**. What `global.mode` changes around the API:

| | Development | Product |
|---|---|---|
| The token, when `adminApi.authRequired` is on | required and verified | required and verified |
| The client secret at `/oauth2/token` | not checked, outside RFC 9700 / OAuth 2.1 mode | checked (product mode implies RFC 9700 mode) |
| `adminApi.authRequired` **off** | **the API is open** to anybody who can reach the port | the API falls back to the **console's gate**: a sign-in session, the role the method needs (Admin Read for `GET`, Admin Write otherwise), and the XACML policy above the roles |

The off switch exists because it is the recovery path. If nobody can mint a
token, it restores the open API so that `POST /admin-api/rbac/grant` can give
somebody a console role again. In development mode that also means **anybody
who can reach the port can grant themselves both roles**, which is as
dangerous as it sounds. In product mode, with the switch off, a browser that
navigates to the API gets a 403 page telling it to sign in at `/admin`, and a
realm administrator's session is confined to their realm as described above.

The policy layer runs only where the API is gated. In development with the
switch off there is no credential and so no subject, and a policy that
refused an unauthenticated subject would close the recovery path. On an
unedited product deployment, the policy permits anybody who has already
passed the role check.

## Configuration

`adminApi.*` and `admin.*` apply to the whole process: a trust realm cannot
override them, because they decide who administers the service.

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `adminApi.authRequired` | `ADMIN_API_AUTH_REQUIRED` | `true` | yes | Require an access token on every `/admin-api` call; off restores the open API (development) or the console's gate (product). |
| `adminApi.clientSecret` | `ADMIN_API_CLIENT_SECRET` | empty (generated per start) | no | The `client_secret` of the default realm's seeded `sts-management-api` client; set it so the secret survives a restart. Secret. |
| `adminApi.audience` | `ADMIN_API_AUDIENCE` | derived: `global.publicBaseUrl` + `/admin-api`, or this process's scheme, host and port + `/admin-api` | yes | The `aud` a token must carry. At its default, `/admin-api` under the host the request arrived on is accepted as well; any other value pins that one value. |
| `admin.readGroup` | `ADMIN_READ_GROUP` | `admin-read` | yes | The directory group whose members hold Admin Read, which lets them read the console and, with the token gate off in product mode, `GET` the API. |
| `admin.writeGroup` | `ADMIN_WRITE_GROUP` | `admin-write` | yes | The directory group whose members hold Admin Write; write implies read. |
| `admin.openWhenEmpty` | `ADMIN_OPEN_WHEN_EMPTY` | `true` | yes | Keep the console open to every signed-in person until the bootstrap administrator first signs in. Development mode only: product never opens it. |
| `admin.bootstrapUsername` | `STS_ADMIN_BOOTSTRAP_USERNAME` | `admin` | no | The administrator seeded at startup in every realm, a member of both roles, with a forced password change. |
| `admin.bootstrapPassword` | `STS_ADMIN_BOOTSTRAP_PASSWORD` | empty | no | In product mode, the bootstrap administrator's password instead of a generated one that is logged once. Secret; held to the password policy. |
| `xacml.enforceAccess` | `STS_XACML_ENFORCE_ACCESS` | `true` | yes | Ask the XACML policy before letting a caller through; on the token path this is what checks the scope. |
| `oauth2.accessTokenRequireDpop` | `STS_OAUTH2_ACCESS_TOKEN_REQUIRE_DPOP` | `false` | yes | Refuse any access token that is not DPoP-bound and proved, here and at every other resource server; the explorer stops working. |
| `oauth2.accessTokenRequireMtls` | `STS_OAUTH2_ACCESS_TOKEN_REQUIRE_MTLS` | `false` | yes | Refuse any access token that is not bound to the certificate the connection presents (RFC 8705). |
| `global.publicBaseUrl` | `STS_PUBLIC_BASE_URL` | empty (read from each request) | yes | The base of every issuer and address the service builds, including this API's default audience. |
| `global.mode` | `STS_MODE` | `development` | yes | `development` or `product`; decides what `adminApi.authRequired=false` falls back to. Per trust realm. |

The `adminApi.*` and `admin.*` groups are edited on `/admin/rbac`. See
[Configuration](configuration.md) for how values resolve, and for changing
them on the console or with `POST /admin-api/config/set`.

## Design decisions

* **The API mirrors the console and decides nothing.** Both doors call one
  action function and one read view, so they cannot differ on what is
  allowed. The console page is drawn from the same model the API returns.
* **The OpenAPI document is generated, not written.** It is built from the
  route table, so it cannot describe an operation that does not exist or
  omit one that does. The explorer's copy is built by the same function.
* **A token, not a console session.** `/admin-api` is a machine surface with
  no browser and no sign-in screen, so it is reached the way a machine
  reaches any resource server. A console session is not an API credential,
  and a token is not a console session.
* **One gate on the base path.** It covers all of the several hundred
  operations. A check in each handler would give the next operation a chance
  to be added without one.
* **Scopes become roles, and the policy decides.** `admin:read` and
  `admin:write` become the built-in `ADMIN_READ` and `ADMIN_WRITE` roles, and
  the XACML `access-control` document asks for the role each method needs.
  The requirement is stated where every other access decision in the service
  is stated, and a policy can name the roles without knowing about OAuth.
  With `xacml.enforceAccess` off, that question is not asked, so any valid
  token audienced to the API gets through whatever its scope.
* **The audience is checked, and so is the token type.** A Bearer token for
  another resource server must not be replayable here. Because every token
  the service signs uses the same key, without the `at+jwt` check an ID Token
  whose audience happened to name the API would be an administrative
  credential.
* **The service token is verified with the default realm's key, wherever it
  is presented.** If a token minted in a realm counted as the service
  credential, anybody who could create a realm could mint a token for
  everything. A realm's own token is therefore believed only in that realm.
* **`admin:*` is tied to the client, in both realms and both modes (#110).**
  Until 2026-09-22 the default realm's gate accepted the scopes from any
  client — the token endpoint did not restrict who could ask for them, so any
  client that could use `client_credentials` minted Admin Write — and only a
  realm's gate required `sts-management-api`. Now the token endpoint issues
  them only to a client whose `oauthAllowedScope` declares them, a registration
  cannot declare them, and the gate asks the same question of every token
  (`STS-API-0123`).
* **The secret is a configuration setting, not an action.** A secret
  generated per start is readable only through the API it unlocks. That is a
  bootstrap hole, so `adminApi.clientSecret` pins it, and regenerating a
  pinned secret is refused rather than letting the entry and the setting
  disagree.
* **An off switch that restores the open API.** It is the way back in when
  nobody can mint a token and nobody holds a console role. It is a separate
  setting from anything on the console, so turning the API's gate off never
  opens the console.
* **The policy layer cannot remove the recovery path.** With the token gate
  off, the policy is asked only in product mode, where a session supplies the
  subject.
* **Where an API write records who acted, it records `via: api` and no
  person.** The API authenticates a client, not a person, and has no session
  to name one.
* **`POST /admin-api/logout/end` with an empty selection is refused.** Global
  logout is its own named operation, `global`, because an empty list arriving
  at `end` usually means a caller built a list and got nothing.
* **The explorer is the service's own, not Swagger UI.** It is about 450
  lines with no dependency, where Swagger UI would add about 11.7 MB. It is
  one of the few pages allowed a script, and it loads the script as a file
  (`script-src 'self'`), never inline.

## In the running service

| Where | What |
|---|---|
| `GET /admin-api` | The index: name, version and build, whether the API is `protected`, where the document and the explorer are, and a summary of every operation |
| `GET /admin-api/openapi.json` | The OpenAPI 3.1 document, with `servers[0].url` set to the address the request reached. Behind the gate like everything else |
| `GET /admin-api/status` | The cheapest call, and the one to poll: the issuer, the start time and the running totals |
| `/admin/api-explorer` | The explorer, on the console; `GET /admin-api/api-explorer` reports where the document is, how many operations it describes and what your roles would grant |
| `/admin/rbac` | The two console roles, and the `adminApi.*` and `admin.*` settings; `GET /admin-api/rbac` and `POST /admin-api/rbac/{grant,revoke}` |
| `/admin/applications?application=sts-management-api` | The seeded client in this realm, including its secret |
| `/admin/xacml` | The `access-control` policy the scope check runs through |
| `/admin/error-codes` | The `STS-API-*` codes behind each refusal, also at `GET /admin-api/error-codes` |
| `/admin/audit` | The audit log, also at `GET /admin-api/audit` |

At startup the service logs how many operations the API has and whether a
token is currently required.

## Related

* [Configuration](configuration.md): how settings resolve, and the runtime
  `config` operations
* [Trust realms](trust-realms.md): realm prefixes and per-realm
  administrators
* [Accepted tokens](accepted-tokens.md): what each resource server here
  accepts
* [What is not checked](what-is-not-checked.md): the gated surfaces, by mode
* [OAuth 2.0 & OpenID Connect](oauth-oidc.md): the token endpoint and the
  client-credentials grant
* [OAuth security](oauth-security.md): DPoP, mutual TLS, RFC 9700 mode
* [XACML](xacml.md): the access-control policy
* [Error codes](error-codes.md)
* [Endpoints](endpoints.md)
