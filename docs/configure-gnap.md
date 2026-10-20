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
