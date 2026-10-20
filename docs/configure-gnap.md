---
title: "Configuring GNAP"
---

# Configuring GNAP

This page shows how to set up iya-sts as a GNAP authorization server
([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)), with the resource
server connections of [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767). For
each recipe it covers the client instance or resource server to register, the
access types to declare, the settings to change, and what the client then
sends. Each recipe is given twice: once as steps in the **admin console** and
once as **Management API** calls.

The values come from this repository's test jobs in `tests/vendored/`, and
each recipe names the job it is taken from. How GNAP *behaves* here, and every
`gnap.*` setting with its default, is on [GNAP](gnap.md). This page covers
only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the console's **Set** / **Add to** / **Remove from** forms.

Every GNAP request a client or resource server sends is **signed with its
key** (an HTTP message signature, a JWS or mutual TLS). This page shows the
bodies of those requests, not the signatures. The test jobs build theirs with
`tests/vendored/gnap_client.js`, an independent client written from the RFCs,
which is a working reference for the signature base, `Content-Digest` and the
interaction hash.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/gnap` | **Protocols → GNAP** | See the endpoints and what each authorization server advertises. Revoke grants on the **Grants** tab, delete resource sets on **Registered resource sets**, and change every `gnap.*` setting on **Settings** (**Save GNAP**). |
| `/admin/gnap/monitor` | **Monitoring → GNAP grants** | See what each GNAP application has done: grants, approvals, tokens by format, rotations, revocations, failed proofs. |
| `/admin/applications/new` | **Applications → New application ›** | Register a client instance or a resource server: tick **GNAP**. |
| `/admin/applications?application=<id>` | **Directory → Applications** | Set `gnap*` attributes with **Set** / **Add to** / **Remove from**, and declare access types on the **Access types** tab. |
| `/admin/users?user=<name>` | **Directory → Users**, a person's **GNAP grants** tab | See and revoke the grants that person approved. |

The API equivalents are `GET /admin-api/gnap`, `GET /admin-api/gnap/monitor`,
`POST /admin-api/gnap/revoke-grant` and `/gnap/delete-resource-set`, and for
settings `POST /admin-api/config/set` and `/config/set-many`. Every setting is
per [trust realm](trust-realms.md): each realm is its own GNAP authorization
server at `/realm/<id>/gnap`.

The jobs below all work in a throwaway realm with `gnap.continueWaitS` set to
`0`, so a client may continue at once instead of waiting five seconds. Do that
only in a test realm:

```bash
api realms/create '{"id":"gnapcore","domain":"gnapcore.example.net","name":"GNAP core"}'
BASE=$BASE/realm/gnapcore
api config/set '{"key":"gnap.continueWaitS","value":"0"}'
```

## What development and product mode change

A key proof is verified in **every** mode: an unsigned or wrongly signed
request is refused `invalid_client`. Also in every mode, an access token must
be for a resource server. The rights in a request must name a registered
resource server, a type one declares, or this service's own Shared Signals
transmitter; otherwise the request is refused `invalid_request`
(`STS-GNAP-0904`). So **register a resource server before anything else**.

What differs:

* **An unknown client key.** Development mode gives it an application entry on
  first sight. Product mode refuses it `invalid_client` until it is
  registered, and an entry made on first sight does not count as a
  registration (`STS-GNAP-0902`).
* **Finish URIs.** Development mode records a new finish URI as observed.
  Product mode uses only one listed in `gnapFinishUri`, and refuses any other
  with `invalid_interaction` (`STS-GNAP-0101`).
* **Locations.** In product mode each location in a right must be at or under
  a registered resource server's `gnapResourceServerUri`, or name a
  registered application (`STS-GNAP-0903`). Development mode leaves such a
  right out of the token's audience instead.
* **Access types.** A type no resource server declares is granted as asked in
  development mode and refused `request_denied` in product mode
  (`STS-GNAP-0810`). Declare every type you use.
* **Mutual TLS.** `gnap.mtlsTrust` is `auto`: certificates are pinned in
  development and held to a PKI in product. See
  [mutual TLS](#a-client-that-proves-its-key-with-mutual-tls).
* **Push finish.** `gnap.pushSkipTlsVerification` is ignored in product mode,
  and `gnap.pushAllowHttp` allows only a loopback address there. Use
  `gnap.pushCaFile` to trust a privately certified listener.
* **Acting for somebody else.** A refused delegation or impersonation is
  `request_denied` (403) in product mode. Development mode issues the token
  and records that it would have been refused.

Registering every party, as every recipe here does, works in both modes.

---

# Registration

## A resource server

Register the resource server first. Its key is how it proves itself at
introspection, resource set registration and derivation, and its
`gnapResourceServerUri` is how a right's location is matched to it.

Taken from `sts_gnap_rs.js` and `sts_gnap_catalogue.js`.

**Console:**
1. **Applications → New application ›**.
2. Under **What it is called**, set **Identifier** to `gnap-rs-1`.
3. Under **Protocol families it is declared for**, tick **GNAP**.
4. Click **Show every field (advanced view)**. In the **GNAP** group, fill in:
   - `gnapKey`: the server's public key, as the JSON key object of RFC 9635
     section 7.1, for example
     `{"proof":"httpsig","jwk":{"kty":"EC","crv":"P-256","x":"…","y":"…","alg":"ES256","kid":"rs-1"}}`.
   - `gnapResourceServerUri`: `https://rs.gnap.test/api`, one per line.
5. Click **Create the application**.

The console's form does not ask for a kind. Through the API, pass
`"kind": "gnap-resource-server"` as the jobs do. Otherwise the entry is
recorded as a resource server when its key first calls introspection,
resource set registration or derivation.

**API:**
```bash
api applications/create '{
  "identifier": "gnap-rs-1", "kind": "gnap-resource-server",
  "protocols": ["gnap"],
  "fields": {
    "gnapKey": "{\"proof\":\"httpsig\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"…\",\"y\":\"…\",\"alg\":\"ES256\",\"kid\":\"rs-1\"}}",
    "gnapResourceServerUri": ["https://rs.gnap.test/api"]
  }}'
```

`gnapKey` is one string holding the JSON key object: a proof method and
exactly one of `jwk`, `cert` or `cert#S256`. A JWK must carry no private
member.

**Optional attributes for a resource server:**

| Attribute | When to set it |
|---|---|
| `gnapAccessTokenFormat` | It wants a format other than `gnap.accessTokenFormat` (`jwt-signed`): `jwt-encrypted`, `macaroon`, `biscuit` or `zcap`. |
| `gnapJweKey` | It wants `jwt-encrypted` tokens it can open itself: its public encryption JWK, for example with `"alg":"RSA-OAEP-256","use":"enc"` (`sts_gnap_rs.js`). |
| `gnapOwnerLookupUri` | It answers who owns a resource: an https template with `{identifier}` as one path segment. See [GNAP → Who owns a resource](gnap.md#who-owns-a-resource). |
| `appAllowedToDelegateTo` | It derives tokens for a downstream resource server. See [token derivation](#token-derivation-rfc-9767-section-4). |

`gnapMacaroonKey` is not one you set. The service writes it when the resource
server first registers a resource set.

## A client instance with its own key

A client presents its key in each request. In product mode, register the key
first, with the finish URIs the client will use.

Taken from `gnap_flow.js` (the registrar every GNAP job uses) and
`sts_gnap_core.js`.

**Console:**
1. **Applications → New application ›**. Set **Identifier** to
   `gnap-client-1` and tick **GNAP**.
2. Click **Show every field (advanced view)** and fill in, in the **GNAP**
   group:
   - `gnapKey`: the client's public key object, as for the resource server.
   - `gnapFinishUri`: `https://client.gnap.test/callback`, one per line.
3. Click **Create the application**.

**API:**
```bash
api applications/create '{
  "identifier": "gnap-client-1", "kind": "gnap-client",
  "protocols": ["gnap"],
  "fields": {
    "gnapKey": "{\"proof\":\"httpsig\",\"jwk\":{…}}",
    "gnapFinishUri": ["https://client.gnap.test/callback"]
  }}'
```

The client then sends its key by value in `client.key`. With
`gnap.instanceIds` on (the default), the first response carries an
`instance_id`, and the client may send that string as `client` in later
requests, signed with the same key (section 2.3.1). Signed with any other key,
it is refused `invalid_client`.

**Optional attributes for a client:**

| Attribute | What it does |
|---|---|
| `gnapInteractionStartModes` | Narrows the start modes this client may use (`redirect`, `app`, `user_code`, `user_code_uri`). Empty means all the server offers. |
| `gnapAllowedAccess` | The access types and references it may request. Empty means any. |
| `gnapBearerTokens` | `FALSE` refuses the `bearer` flag for it (`invalid_flag`). |
| `gnapAccessTokenFormat`, `gnapAccessTokenLifetimeS` | Its own token format and lifetime. |
| `gnapInstanceId` | A static instance identifier it may send instead of its key. |
| `gnapClassId`, `gnapDisplayUri`, `gnapLogoUri` | What the approval page shows. A registered value wins over what the request says. |

## A client with a shared secret

A key reference may resolve to a shared secret, for an HMAC proof (section
7.1.1). The secret never crosses the wire. It is at least 32 bytes,
base64url, and sealed at rest when keys persist.

Taken from `sts_gnap_core.js` (section 11).

**Console:** create the application as above, and fill in, in the **GNAP**
group:
- `gnapKeyReference`: `gnap-ref-1`
- `gnapSymmetricKey`: the secret, base64url
- `gnapKeyProof`: `httpsig`
- `gnapSymmetricAlg`: `hmac-sha256`
- `gnapFinishUri`: `https://client.gnap.test/callback`

**API:**
```bash
SECRET=$(openssl rand 32 | basenc --base64url | tr -d '=')
api applications/create '{
  "identifier": "gnap-ref-1-app", "kind": "gnap-client", "protocols": ["gnap"],
  "fields": {
    "gnapKeyReference": "gnap-ref-1",
    "gnapSymmetricKey": "'"$SECRET"'",
    "gnapKeyProof": "httpsig", "gnapSymmetricAlg": "hmac-sha256",
    "gnapFinishUri": ["https://client.gnap.test/callback"]
  }}'
```

The client then sends `"key": "gnap-ref-1"` in `client`, and signs with the
secret. For `jwsd` or `jws`, set `gnapKeyProof` to that and
`gnapSymmetricAlg` to `HS256`, `HS384` or `HS512`. A wrong secret is refused
`invalid_client`.

## A trusted client that needs no interaction

`gnapSkipInteraction` set to `TRUE` lets a registered client be issued tokens
with nobody asked, where every requested right's type allows it (section
2.3.3). It does not let the client act for a person on its own: see
[acting for a person](#impersonation-a-trusted-client-acting-for-a-person).
It is never honoured for an entry made on first sight.

Taken from `sts_gnap_core.js` (section 11) and `sts_gnap_interaction.js`.

**Console:** on the application's page, in **Change what it is allowed to
do**, **Set** `gnapSkipInteraction` to `TRUE`.

**API:**
```bash
api applications/create '{
  "identifier": "gnap-trusted-1", "kind": "gnap-client", "protocols": ["gnap"],
  "fields": {"gnapKey": "{\"proof\":\"httpsig\",\"jwk\":{…}}",
             "gnapSkipInteraction": "TRUE"}}'
```

**Request** (no `interact`):
```json
POST /gnap
{"client": {"key": {"proof": "httpsig", "jwk": {…}}},
 "access_token": {"access": [{"type": "int-default", "actions": ["read"]}]}}
```
The answer carries `access_token` and no `interact`. A right whose type
declares `interaction: always`, or names a `consentActions` action, still needs
the person, and is refused `invalid_interaction` when no interaction is offered.

---

# Access rights

## Declare an access type

An access right's `type` (RFC 9635 section 8) is declared by the resource
server that owns it, in the **access-type catalogue**. GNAP and OAuth's rich
authorization requests (RFC 9396) read the same catalogue: the resource
server's `oauthAuthorizationDetailsType`. A right of a declared type that
names no location is for its owning resource server. What each member does
is listed in [GNAP → Access types](gnap.md#one-catalogue-for-gnap-and-rfc-9396).

Taken from `sts_gnap_catalogue.js`.

**Console:**
1. Open the resource server's page (**Directory → Applications**, then its
   row) and its **Access types** tab.
2. Under **Declare or replace a type**, fill in:
   - **Type**: `cat-payment`
   - **Description**: `Initiate and track a payment`
   - **Actions**: `initiate`, `status` and `refund`, one per line
   - **Required members**: `actions`
   - **Bearer token**: `false`
   - **Maximum token lifetime (s)**: `120`
   - **Introspection claims**: `email`
   - **Limits schema**:
     `{"type":"object","properties":{"amount":{"type":"number","minimum":0},"currency":{"type":"string"}},"required":["amount"],"additionalProperties":false}`
3. Click **Save the type**.

A type of the same name is replaced. **Remove** beside a type takes it off.

**API:**
```bash
api applications/set-access-type '{
  "application": "gnap-rs-1", "type": "cat-payment",
  "description": "Initiate and track a payment",
  "actions": ["initiate", "status", "refund"],
  "requiredMembers": ["actions"],
  "bearer": false, "maxLifetimeS": 120, "introspectionClaims": ["email"],
  "limits": {"type": "object",
             "properties": {"amount": {"type": "number", "minimum": 0},
                            "currency": {"type": "string"}},
             "required": ["amount"], "additionalProperties": false}}'

api applications/remove-access-type '{"application":"gnap-rs-1","type":"cat-payment"}'
```

A list may be an array or text with one value per line. `requiredMembers` is
stored as the definition's `required`. A definition that does not read is
refused with the reason (`STS-REG-0294`), and the type already declared stays.
`GET /admin-api/applications?application=gnap-rs-1` shows the definitions,
under `oauthAuthorizationDetailsType`.

With that type declared, a right such as
`{"type":"cat-payment","actions":["status","initiate"],"limits":{"amount":25,"currency":"EUR"}}`
is granted, its token lives at most 120 seconds and is audienced to
`gnap-rs-1`. These are refused:

| Request | Refusal |
|---|---|
| the `bearer` flag on a token carrying the type | `request_denied` |
| an action the type does not list, such as `delete` | `invalid_request` |
| `limits` the schema refuses, such as `{"amount":-5}` | `invalid_request` |
| `limits` on a type that declares no limits schema | `invalid_request` |

## Who must be asked, per type

Three more members decide whether the resource owner sees the approval page
and how strongly they must be signed in. Taken from
`sts_gnap_interaction.js`, which declares one type of each kind:

```bash
api applications/set-access-type '{"application":"int-rs","type":"int-never","interaction":"never"}'
api applications/set-access-type '{"application":"int-rs","type":"int-always","interaction":"always"}'
api applications/set-access-type '{"application":"int-rs","type":"int-default",
  "actions":["read","delete"],"consentActions":["delete"]}'
api applications/set-access-type '{"application":"int-rs","type":"int-mfa","acr":"mfa"}'
```

In the console these are the **Interaction (phase 6)**, **Actions forcing
consent (phase 6)** and **Authentication level (phase 6)** boxes of the same
form.

| Type | What happens |
|---|---|
| `int-never` | Issued to any client, acting as itself, with nobody asked. |
| `int-default` with `read` | A trusted client (`gnapSkipInteraction`) skips the page. A remembered approval skips it too. |
| `int-default` with `delete` | `delete` is a consent action, so the person sees the page every time. |
| `int-always` | The person sees the page every time, whatever the client and whatever they approved before. |
| `int-mfa` | The person's sign-in must meet `mfa`. A password-only session is sent to sign in again, and refused `request_denied` if it comes back short. |

## Access references and resource sets

A right may also be a plain string, an **access reference**. A resource
server can register a resource set and get a reference for it (RFC 9767
section 3.4), which also fixes the token formats it accepts. Taken from
`sts_gnap_rs.js`.

**Request**, signed with the resource server's key:
```json
POST /gnap/resource
{"access": [{"type": "https://rs.gnap.test/photos", "actions": ["read"],
             "locations": ["https://rs.gnap.test/api"]}],
 "resource_server": {"key": {"proof": "httpsig", "jwk": {…}}},
 "token_formats_supported": ["macaroon"]}
→ 200 {"resource_reference": "…", "introspection_endpoint": "…/gnap/introspect"}
```

The same set registered again returns the same reference. A set whose only
format this server does not issue is refused `invalid_request`, and so is an
empty `access`. The job declares the photos type on the resource server first
(`oauthAuthorizationDetailsType`), because product mode refuses an undeclared
type.

A client then asks for the reference: `"access": ["<resource_reference>"]`.
A reference nobody registered is carried onto the token while
`gnap.unknownAccessReferences` is `accept` (the default). Set it to `refuse`
to answer `request_denied` instead.

Registered sets are listed on **Protocols → GNAP → Registered resource sets**
with a **Delete** on each. Through the API:
```bash
api gnap/delete-resource-set '{"reference":"<resource_reference>"}'
```
Tokens already issued keep the rights they carry.

---

# The grant

## Redirect interaction, redirect finish

The usual grant. A person approves in a browser and comes back to the
client's finish URI. Taken from `gnap_flow.js` (`redirectGrant`), which every
GNAP job uses.

**1. The grant request**, signed with the client's key:
```json
POST /gnap
{"access_token": {"access": [{"type": "cat-payment", "actions": ["status"]}]},
 "client": {"key": {"proof": "httpsig", "jwk": {…}},
            "display": {"name": "GNAP job", "uri": "https://client.gnap.test/"}},
 "interact": {"start": ["redirect"],
              "finish": {"method": "redirect",
                         "uri": "https://client.gnap.test/callback",
                         "nonce": "n-<random>"}}}
```

The answer carries `interact.redirect` (a `/gnap/interact/{id}` URI),
`interact.finish` (the server's nonce), `interact.expires_in`, a `continue`
object with `uri`, `access_token.value` and `wait`, and, with
`gnap.instanceIds` on, an `instance_id`.

**2. The person.** The client sends the person to `interact.redirect`. It
forwards to the approval page, `/gnap/approve/{id}`, which asks them to sign
in first. The page needs scripts. If `gnap.consentRequired` is off, the page
is skipped once they have signed in.

**3. The finish.** The person's browser returns to the finish URI with `hash`
and `interact_ref`. The client checks the hash (section 4.2.3): base64url of
SHA-256 over its own nonce, the server's nonce, `interact_ref` and the grant
endpoint URI, joined by newlines.

**4. The continuation**, signed with the same key:
```
POST <continue.uri>
  Authorization: GNAP <continue.access_token.value>
  {"interact_ref": "<interact_ref>"}
```
The answer carries `access_token` (its `value`, `expires_in`, `access` and,
with `gnap.tokenManagement` on, a `manage` object) and a new `continue`.

The client presents the token at the resource server as
`Authorization: GNAP <token>`, signed with its key. Another key, or no
signature, is refused there. An `interact_ref` presented twice is
`too_many_attempts`.

If the person clicks deny, the finish still happens, and the continuation
answers with no `access_token`.

**Settings** (console: **Protocols → GNAP → Settings**):

| Setting | Default | Why you would change it |
|---|---|---|
| `gnap.interactionLifetimeS` | `600` | How long the interaction URIs and user codes stay usable. |
| `gnap.continueWaitS` | `5` | The `wait` the client is told; continuing sooner is `too_fast`. |
| `gnap.consentRequired` | `true` | Off approves as soon as the person signs in. |
| `gnap.rememberApprovals` | `true` | Off asks the person again every time. |
| `gnap.interactionStartModes` | `redirect,app,user_code,user_code_uri` | Removes a start mode for the whole realm. |

## User code and app interaction

For a device with no browser. Taken from `sts_gnap_core.js` (section 5).

**Request:**
```json
POST /gnap
{"access_token": {"access": […]},
 "client": {"key": {…}},
 "interact": {"start": ["user_code", "user_code_uri", "app"]}}
```

The answer carries `interact.user_code` (`gnap.userCodeLength` characters,
8 by default), `interact.user_code_uri` with the same `code` and a `uri`, and
`interact.app`, a `/gnap/app/{id}` URI. There is no finish, so the client
polls its `continue.uri` until the person has approved; before that the
answer carries a new `continue` and no token. The person enters the code at
`/gnap/code`. It is not case-sensitive, and spaces and hyphens are ignored.

Polling sooner than `wait` is refused `too_fast` (`sts_gnap_core.js` section 13
sets `gnap.continueWaitS` to `30` to show it). After `gnap.maxPolls` polls
(60) the grant is finalized with `too_many_attempts`.

## Push finish

The server POSTs `{hash, interact_ref}` as JSON to the client's push URI
instead of redirecting the browser. Taken from `sts_gnap_core.js` (section 6).

```json
"interact": {"start": ["redirect"],
             "finish": {"method": "push", "uri": "https://client.gnap.test:8443/push",
                        "nonce": "n-<random>"}}
```

* Register the push URI in `gnapFinishUri`; product mode uses no other.
* The push URI must be `https`. To trust a listener certified by your own CA,
  put the CA in a PEM file the service can read and set `gnap.pushCaFile` to
  its path. The job does this rather than skipping verification, so that it
  passes in product mode.
* `gnap.pushAllowedHosts` limits the hosts a push may go to.
  `gnap.pushTimeoutMs` (5000) bounds it. `gnap.pushFinish` off stops every push.

The push URI and port above are illustrations; the job picks its own port.

## Several tokens, bearer tokens and subject information

Taken from `sts_gnap_core.js` (section 7).

```json
"access_token": [{"label": "bound", "access": […]},
                 {"label": "carry", "access": […], "flags": ["bearer"]}],
"subject": {"sub_id_formats": ["opaque", "iss_sub", "email"],
            "assertion_formats": ["id_token", "saml2"]}
```

* With several tokens, each needs a `label`, and labels must differ. The
  answer is an array, one token per label.
* A `bearer` token is presented without a signature. `gnap.bearerTokens` off,
  or `gnapBearerTokens` `FALSE` on the client, refuses the flag with
  `invalid_flag`.
* Subject information is released only if the person leaves **Who you are**
  ticked on the approval page. The formats offered are `gnap.subIdFormats` and
  `gnap.assertionFormats`.

## A grant that waits for an absent person

A request may name a person who is not at the browser, or offer no
interaction at all. With `gnap.ownerApproval` on (off by default), the grant
waits for that person on their portal, under **Sign-in requests**
(`/portal/ciba`), while the client polls. Taken from
`sts_gnap_interaction.js` (section 5).

```bash
api config/set '{"key":"gnap.ownerApproval","value":"true"}'
api config/set '{"key":"gnap.ownerApprovalLifetimeS","value":"300"}'
```

```json
POST /gnap
{"access_token": {"access": [{"type": "int-default", "actions": ["read"]}]},
 "client": {"key": {…}},
 "user": {"sub_ids": [{"format": "email", "email": "owner@gnap.test"}]}}
```

The answer carries `continue` and no token. The `wait` is long enough that
`gnap.maxPolls` polls cover the lifetime. Approved, the next poll collects
the tokens; denied, it is `user_denied`. One person may have at most
`gnap.ownerApprovalMaxPending` (5) waiting.

---

# After the grant

## Modify or revoke a grant

Taken from `sts_gnap_core.js` (section 8). Both requests are signed and carry
`Authorization: GNAP <continue.access_token.value>`.

```
PATCH <continue.uri>
  {"access_token": {"access": [{"type": "…", "actions": ["read"]}]}}

DELETE <continue.uri>
  → 204
```

* Narrowing the access issues a new token with no interaction. Widening it
  needs the person again: with no interaction offered it is `request_denied`.
* A modification may not carry `client` (`invalid_request`).
* While `gnap.revokeOnModify` is on (the default), a modification revokes the
  grant's earlier tokens, unless they were issued `durable`
  (`gnap.durableTokens`, off by default).
* `DELETE` revokes the grant and every token issued under it.

An administrator revokes a grant on **Protocols → GNAP → Grants**, with
**Revoke**, or on the person's **GNAP grants** tab. The person can revoke it
themselves on `/portal/gnap`. Through the API:
```bash
api gnap/revoke-grant '{"grant":"<grant id>"}'
api gnap/revoke-grant '{"grant":"<grant id>","user":"<username>"}'   # only if that person approved it
```
`GET /admin-api/gnap` lists the grant ids. `GET /admin-api/users?user=<name>`
lists a person's as `gnapGrants`.

## Rotate, rekey and revoke a token

Each token issued with `gnap.tokenManagement` on carries `manage.uri` and
`manage.access_token`. Taken from `sts_gnap_core.js` (section 9). Each
request carries `Authorization: GNAP <manage.access_token.value>`.

| Request | What it does |
|---|---|
| `POST <manage.uri>` with no body | Rotates the token: a new value with the same access, and a new `manage`. The old value and the old management token stop working (`invalid_rotation`). |
| `POST <manage.uri>` with `{"key": <new key object>}`, signed by the old key **and** the new one | Rotates the client's key (section 6.1.1). Signed by the old key alone, it is `invalid_rotation`. |
| `DELETE <manage.uri>` | Revokes the token: `204`. |

With an HTTP signature, the new key signs over the old signature
(`tag="gnap-rotate"`, covering `"signature";key="sig1"` and
`"signature-input";key="sig1"`). With `jwsd` and `jws`, the proof is nested
(sections 7.3.3.1 and 7.3.4.1). A bearer token's key cannot be rotated.
`gnap.keyRotation` off answers `key_rotation_not_supported`.

## Introspection (RFC 9767 section 3.3)

A resource server asks about a token it was given, signed with its own key.
Taken from `sts_gnap_catalogue.js` (section 2).

```json
POST /gnap/introspect
{"access_token": "<token>", "resource_server": {"key": {…}}}
→ {"active": true, "access": […], …}
```

Each resource server sees only the rights of its own types, and the person's
claims its type lists in `introspectionClaims`. `gnap.introspection` off turns
the endpoint off. The RS-facing discovery document is
`/.well-known/gnap-as-rs`.

## Token derivation (RFC 9767 section 4)

A resource server exchanges a token it was given for one to a downstream
resource server, with no more access. Taken from `sts_gnap_rs.js` (section 4)
and `sts_gnap_delegation.js` (section II).

**Register the relationship.** The deriving resource server's
`appAllowedToDelegateTo` names the downstream one (or the downstream one's
`appAllowedToActOnBehalfOf` names the deriving one). In the console:
**Add to** `appAllowedToDelegateTo` on the deriving server's page. Through
the API:
```bash
api applications/add '{"application":"gd-rs-a","attribute":"appAllowedToDelegateTo","value":"gd-rs-b"}'
```

**Request**, signed with the deriving resource server's key:
```json
POST /gnap
{"client": {"key": {…}},
 "existing_access_token": "<the token it was handed>",
 "access_token": {"access": [ … no more than that token carries … ]}}
```

More access than the original is `request_denied`, unless the catalogue
declares the new type `derivableFrom` a type the original carries. A
resource server the token was not issued for cannot derive from it. At most
`gnap.maxDerivationDepth` (2) derivations are allowed, and
`gnap.tokenDerivation` off refuses them all. Without the relationship,
product mode refuses `request_denied` and development mode issues the token
and records the refusal it would have been. The derived token names the
chain in `act`.

## Impersonation: a trusted client acting for a person

A trusted client may present an ID Token or SAML assertion about a person in
`user` and get tokens for that person with nobody asked. This is decided by
the same [delegation and impersonation](delegation.md) policy as OAuth token
exchange. Taken from `sts_gnap_delegation.js` (section I).

**Register the client:**
```bash
api applications/create '{
  "identifier": "gd-imp", "kind": "gnap-client", "protocols": ["gnap"],
  "fields": {"gnapKey": "{\"proof\":\"httpsig\",\"jwk\":{…}}",
             "gnapSkipInteraction": "TRUE",
             "gnapFinishUri": ["https://client.gnap.test/callback"],
             "appDelegationSemantics": ["impersonation"],
             "appAllowedToDelegateTo": ["gd-rs-a", "gd-rs-b", "gd-rs-c"]}}'
```
In the console: create it as a client, then **Set** `gnapSkipInteraction` to
`TRUE` and **Add to** `appDelegationSemantics` and `appAllowedToDelegateTo`.

**Request:**
```json
POST /gnap
{"client": {"key": {…}},
 "access_token": {"access": [{"type": "https://rs.gnap.test/photos",
                              "actions": ["read"],
                              "locations": ["https://rs-a.deleg.test/api"]}]},
 "user": {"assertions": [{"format": "id_token", "value": "<ID Token>"}]}}
```

The ID Token must have been issued **to this client**. The job gets one from
an ordinary grant that asked for `"subject": {"assertion_formats":
["id_token"]}`. An assertion issued to another client is refused
`unknown_user`. A client without `impersonation` in its semantics is refused
in product mode. Every act is listed on **Monitoring → Delegation** under
protocol `GNAP`.

## A client that proves its key with mutual TLS

The key is the TLS client certificate: `{"proof": "mtls", "cert":
"<base64 DER>"}`. `gnap.keyProofs` includes `mtls` by default, and it needs
the main port on HTTPS. Taken from `sts_gnap_mtls.js`.

* **Pinned** (`gnap.mtlsTrust` `pinned`, development's `auto`): register the
  certificate itself as `gnapKey`. A self-signed one is fine.
* **PKI** (`pki`, product's `auto`): the certificate must chain to the client
  truststore and be bound to the entry. The simplest way is to issue it from
  this realm's CA to the application:

```bash
api pki/build '{"organisation":"Gnapmtls","country":"US"}'       # once per realm
api applications/issue-tls-client-certificate '{"application":"pki-issued",
  "password":"<file password>","keyAlg":"ec-p256","label":"first"}'
```

In the console the issue button is on the application's **Credentials** tab
(**Issue a TLS client certificate from this realm's CA**). It is drawn for an
application declared for OAuth 2.0 or **TLS / mutual TLS**, so tick that
family as well as GNAP. Under PKI a certificate can be replaced at the
authority with no change to the registration, and a revoked one is refused in
both models. `gnapMtlsTrust` `pki` on one entry makes it stricter than a
pinned realm; `pinned` in a PKI realm is refused (`STS-REG-0196`).

---

# The server

## Named authorization servers

Each named authorization server profile is also a GNAP authorization server,
at `/<profile>/gnap`, and may override the discovery members. What it
publishes is what its grant endpoint enforces. Taken from `sts_gnap_core.js`
(section 12):

```bash
api authorization-servers/set '{"profile":"gnapas1",
  "member":"interaction_start_modes_supported","value":"[\"user_code\"]"}'
```
After this, `OPTIONS /gnapas1/gnap` lists only `user_code`, and a
`redirect` request there is refused `invalid_interaction`. The profiles are
on `/admin/authorization-servers`.

## Shared Signals

A grant or token revoked sends CAEP `session-revoked`, and a modified grant
sends `token-claims-change`, while `gnap.caepEvents` is on. A GNAP application
can own a Shared Signals stream with its GNAP token: declare `ssf.read` and
`ssf.manage` in its `oauthAllowedScope`, ask for them as access rights, and
present the token to `/ssf/stream` with the `GNAP` scheme and a signature.
Taken from `sts_gnap_signals.js`. See
[Configuring Shared Signals](configure-shared-signals.md) for the stream
itself, and [GNAP → Shared Signals](gnap.md#shared-signals) for which events
such a stream hears.

## Related

* [GNAP](gnap.md): what each feature does, and every setting.
* [Delegation and impersonation](delegation.md): the policy derivation and impersonation are decided by.
* [Applications](applications.md): the registry these recipes write to.
* [Management API](management-api.md): the token, and the OpenAPI document at `/admin-api/openapi.json`.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md) and [Configuring Shared Signals](configure-shared-signals.md).
