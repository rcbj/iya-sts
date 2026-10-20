---
title: "Configuring federation"
---

# Configuring federation

This page shows how to set up a federation relationship in iya-sts: a
bilateral trust with one foreign identity service, in either direction. It
covers each of the five sign-in protocols with iya-sts as the service
provider (SAML 2.0, SAML 1.1, WS-Federation, OpenID Connect and OAuth 2.0),
iya-sts as the identity provider, who a partner may sign in, encrypted
assertions, sign-out, a partner's Shared Signals, and the consumer and social
providers. Each recipe is given twice: once as steps in the **admin console**
and once as **Management API** calls.

The values come from this repository's test jobs, and each recipe names the
job it is taken from. Most of those jobs make one trust realm of the service
the identity provider and a second realm the service provider, so both ends
of every recipe are iya-sts and the partner's half is shown too. The jobs add
a run stamp to every realm, person and client id; it is left out here. Change
the identifiers, URLs and certificates to your own.

How federation *behaves*, and every setting and relationship field, is on
[Federation](federation.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor. Trust through a chain of signed
statements, rather than one pinned key, is on
[Configuring OpenID Federation](configure-oidfed.md).

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/federation` | **Protocols → Federation** | Tabs: **The relationships** (the list, with a filter), **Consumer and social providers**, **Add a relationship**, and **Settings** (the `federation.*` settings). |
| `/admin/federation?relationship=<id>` | click a relationship's row | The relationship's page: **What to configure at the partner**, then **Settings** (one **Set** form per field), **Switches** (**Turn on** / **Turn off**), **Lists** (**Add** / **Remove**), **People linked to this partner**, **Encryption**, **Shared Signals from this partner** and **Delete**. |
| `/admin/users?user=<username>` | **Directory → Users**, then the person | The **Federation links** tab: link a partner's subject to the person, or remove a link. |
| `/admin/applications?application=<id>` | **Directory → Applications** | `appFederationRelationship`: which partners an application's people sign in through. |
| `/admin/federation/map` | **The picture** link on the federation page | The register drawn as a diagram. |

**The operations.** Every relationship field is written the same way:

| What | Console | API |
|---|---|---|
| Create a relationship | **Add a relationship**: **Id**, **This service is**, **Protocol**, **Name** (optional), **Partner**, then **Add** | `POST /admin-api/federation/create` with `{id, role, protocol, name?, peer?, application?}` |
| Set one field | the relationship's **Settings** table: the field's box, then **Set** (an empty value clears it) | `POST /admin-api/federation/set` with `{id, field, value}` |
| Turn a switch on or off | the **Switches** table: **Turn on** / **Turn off** | `federation/set` with the value `TRUE` or `FALSE` |
| Add or remove one value of a list field | the **Lists** section: the field's box, then **Add**; **Remove** on a value | `POST /admin-api/federation/add-value` and `/remove-value` with `{id, field, value}` |
| Enable or disable | the **Switches** row `fedEnabled` | `POST /admin-api/federation/enable` and `/disable` with `{id}` |
| Read it back | the relationship's page | `GET /admin-api/federation?relationship=<id>` |

The read answers the relationship's `fields`, the list of fields you may
`set` (`editable`), the URLs to give the partner (`endpoints`) and what is
still missing. The create and set replies carry `readiness.missing` too.

**Federation refuses by default.** Nothing federated happens until you
configure a relationship, and then not until you enable it. A relationship
is always created **disabled**, whatever the create says. An enabled
relationship that is still missing a field refuses every sign-in and names
the missing fields. It never half-works.

Relationships are per [trust realm](trust-realms.md). Work in a realm under
`/realm/<id>/admin/federation`, or set `BASE` to `https://<host>/realm/<id>`
for the API calls. The jobs create their two realms like this:

```bash
api realms/create '{"id":"fi","domain":"fi.example.net","name":"fi"}'   # the identity provider
api realms/create '{"id":"fs","domain":"fs.example.net","name":"fs"}'   # the service provider
```

**Settings** (console: the **Settings** tab, then **Save Federation**; API
`config/set` or `config/set-many`) are listed on
[Federation → Configuration](federation.md#configuration). The ones you are
most likely to change are `federation.outbound` (on, so this service may call
a partner's token, UserInfo and JWKS endpoints), `federation.outboundCaFile`
(the CA a privately certified partner chains to) and
`federation.consumerProviders` (off).

## What development and product mode change

The checks on what a partner sends are the same in both modes: federation is
not permissive in development. What changes is what you must fill in.

* **Creating people.** A new relationship is written with
  `fedAutocreateUsers` **TRUE in development and FALSE in product**. In
  product, a person with no directory entry is refused (`STS-FED-0090`)
  until you turn the switch on or provision them first.
* **The attributes a new person must hold.** In product, a person a sign-in
  creates must meet the realm's attribute policy: by default a given name, a
  surname and an address. Map them from the partner's names with
  `fedAttributeMap` (below), or the sign-in is refused (`STS-FED-0158`).
* **Plaintext assertions.** Product refuses a plaintext SAML 2.0 or
  WS-Federation assertion, and a signed-only ID Token by `form_post`
  (`STS-FED-0140`). Have the partner encrypt
  ([below](#encrypted-assertions)), or set `fedAllowUnencrypted` to `TRUE`.
  **That is a warning:** the person's identifier and attributes then cross
  their browser in clear. Most jobs set it because their partner does not
  encrypt. An ID Token redeemed at the partner's token endpoint crosses no
  browser and is not affected.
* **Signed sign-out.** Product refuses `fedRequireSignedLogout` off.
* **`any-existing`.** Product refuses to set this subject policy.
* **The linking sign-in.** Under `link-at-first-sign-in` the person signs in
  here before they are linked. Development does not check the password;
  product does, and asks for a second factor where the person holds one.
* **Outbound calls.** `federation.outboundAllowHttp` and
  `federation.outboundSkipTlsVerification` work in development only. In
  product, reach a privately certified partner by naming its CA in
  `federation.outboundCaFile`.
* **The partner's certificate's revocation**, under `pki.revocationCheck`
  `auto`: a status that cannot be fetched is accepted in development and
  refused in product.

---

# This service as the service provider

The partner is the identity provider. It signs the person in, and this
service consumes what it sends to the relationship's assertion consumer
service, `/federation/acs/<id>`. Every protocol arrives at that one path.

What each protocol needs before the relationship is ready:

| Protocol | Required fields |
|---|---|
| `saml2` | `fedPeer`, `fedSsoUrl`, `fedSigningCertificate` |
| `saml11` | `fedPeer`, `fedSsoUrl`, `fedSigningCertificate` |
| `wsfed` | `fedPeer`, `fedSsoUrl`, `fedSigningCertificate` |
| `oidc` | `fedPeer`, `fedSsoUrl`, `fedClientId`, and `fedTokenUrl` for the code flow or `fedJwks` / `fedJwksUri` for `fedResponseType` `id_token` |
| `oauth2` | `fedPeer`, `fedSsoUrl`, `fedTokenUrl`, `fedClientId`, and `fedUserinfoUrl` (or `fedJwks` / `fedJwksUri` when the access token is a JWT) |

`fedPeer` is the **Partner** box on the create form. It is the partner's
entityID, issuer or `wtrealm`, and every assertion's issuer is checked
against it. In product, an enterprise SAML 2.0, WS-Federation or OpenID
Connect relationship also needs its encryption key, which is issued when the
relationship is created ([below](#encrypted-assertions)).

**The URLs to give the partner** are on the relationship's page under **What
to configure at the partner**, and in `endpoints` on the API read:

| `endpoints` member | What the partner configures it as |
|---|---|
| `assertionConsumerService` | the SAML ACS, the WS-Federation `wreply`, the OAuth 2.0 / OpenID Connect `redirect_uri` |
| `metadata` | this service's SAML or WS-Federation metadata for this partner (SAML 2.0, SAML 1.1, WS-Federation) |
| `jwks` | the key to encrypt an ID Token to (OpenID Connect) |
| `singleLogout`, `signOutCleanup`, `backchannelLogout`, `frontchannelLogout`, `postLogoutRedirect` | the sign-out addresses ([below](#sign-out)) |
| `login` | `/federation/login/<id>`: where a browser starts a sign-in through this partner |

This service's entityID or `wtrealm` with this partner is the ACS URL, unless
`fedLocalEntityId` says otherwise. The metadata carries it.

## SAML 2.0

Taken from `sts_federation_realms.js`. The identity provider is realm `fi`,
the service provider realm `fs`.

**Console** (in realm `fs`):
1. **Protocols → Federation**, tab **Add a relationship**: **Id** `saml`,
   **This service is** *Service provider*, **Protocol** *SAML 2.0*, then
   **Add**. Leave **Partner** empty for now: with an iya-sts partner, its
   entityID is known only once its application exists.
2. Open `saml` on **The relationships** tab. Under **What to configure at the
   partner**, copy the assertion consumer service and the metadata URL. The
   metadata carries this service's entityID and its signing certificate.
3. Register this service at the partner (next step), then read the partner's
   metadata: its entityID, its HTTP-POST `SingleSignOnService` and its
   `use="signing"` certificate.
4. In **Settings**, **Set**:
   - `fedPeer` to the partner's entityID;
   - `fedSsoUrl` to its HTTP-POST `SingleSignOnService`;
   - `fedSigningCertificate` to its signing certificate (PEM or base64 DER);
   - `fedBinding` to `HTTP-POST`.
5. In **Switches**, **Turn on** `fedSignRequest`, then `fedEnabled`.

**At the partner.** When the partner is an iya-sts realm, register this
service there as a SAML 2.0 service provider, keyed by this service's
entityID. See [Configuring SAML profiles](configure-saml.md#register-the-sp-by-hand).

**API:**
```bash
# in realm fs
api federation/create '{"id":"saml","role":"service-provider","protocol":"saml2"}'
curl -sk "$BASE/admin-api/federation?relationship=saml" -H "Authorization: Bearer $TOKEN" |
  jq .endpoints        # assertionConsumerService and metadata

# in realm fi: this service, as the partner's service provider
api applications/create '{"identifier":"<our entityID>","name":"federation fs",
  "protocols":["saml2"],
  "fields":{"samlEntityId":["<our entityID>"],
            "samlAssertionConsumerService":["<assertionConsumerService>"],
            "samlSigningCertificate":["<our signing certificate, PEM>"]}}'
curl -sk "https://<host>/realm/fi/saml2/metadata/<our entityID, percent-encoded>"

# in realm fs again
api federation/set '{"id":"saml","field":"fedPeer","value":"<the partner'"'"'s entityID>"}'
api federation/set '{"id":"saml","field":"fedSsoUrl","value":"<its HTTP-POST SingleSignOnService>"}'
api federation/set '{"id":"saml","field":"fedSigningCertificate","value":"<its signing certificate>"}'
api federation/set '{"id":"saml","field":"fedBinding","value":"HTTP-POST"}'
api federation/set '{"id":"saml","field":"fedSignRequest","value":"TRUE"}'
api federation/enable '{"id":"saml"}'
```

**Why HTTP-POST and a signed request.** A product-mode identity provider,
iya-sts among them, refuses an unsigned AuthnRequest. This service signs the
AuthnRequest only on the HTTP-POST binding: on HTTP-Redirect (the default
`fedBinding`) it goes unsigned, and the log says so. The request always asks
for the Response on HTTP-POST.

The job also registers the same partner under two more ids: `saml-other`
(enabled) and `saml-off` (never enabled). A Response addressed to `saml` is
refused at both, because its audience names a different service provider at
one and the other is disabled.

## OpenID Connect

Taken from `sts_federation_realms.js`. There are two shapes. Both send PKCE,
`state` and a `nonce`.

### The front channel: an ID Token by form_post, no back channel

`fedResponseType` `id_token` with the partner's keys pasted into `fedJwks`.
This service makes no outbound call at all, so it works from a deployment
with no egress. It is the shape the job's positive path uses.

**Console** (in realm `fs`):
1. **Add a relationship**: **Id** `oidc-front`, *Service provider*, *OpenID
   Connect*, **Partner** the partner's issuer, then **Add**.
2. In **Settings**, **Set**:
   - `fedSsoUrl` to its `authorization_endpoint`;
   - `fedClientId` to `fs-front`, the client id the partner gave this service;
   - `fedResponseType` to `id_token`;
   - `fedScope` to `openid profile email`;
   - `fedJwks` to the partner's JWKS document, pasted whole;
   - `fedUsernameSource` to `preferred_username`.
3. In **Switches**, **Turn on** `fedEnabled`.

**API:**
```bash
ISSUER=https://<host>/realm/fi          # the partner's discovery document's issuer
api federation/create '{"id":"oidc-front","role":"service-provider","protocol":"oidc",
  "peer":"'"$ISSUER"'"}'
api federation/set '{"id":"oidc-front","field":"fedSsoUrl","value":"'"$ISSUER"'/oauth2/authorize"}'
api federation/set '{"id":"oidc-front","field":"fedClientId","value":"fs-front"}'
api federation/set '{"id":"oidc-front","field":"fedResponseType","value":"id_token"}'
api federation/set '{"id":"oidc-front","field":"fedScope","value":"openid profile email"}'
jq -n --arg j "$(curl -sk "$ISSUER/oauth2/jwks")" '{id:"oidc-front",field:"fedJwks",value:$j}' |
  curl -sk -X POST "$BASE/admin-api/federation/set" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' --data-binary @-
api federation/set '{"id":"oidc-front","field":"fedUsernameSource","value":"preferred_username"}'
api federation/enable '{"id":"oidc-front"}'
```

The job reads `authorization_endpoint` and `jwks_uri` from the partner's
`/.well-known/openid-configuration` rather than writing them; read yours the
same way. Pasted keys are never refreshed, so paste them again when the
partner rotates.

**At the partner** (realm `fi`), a public client that receives an ID Token
by `form_post`:
```bash
api applications/create '{"identifier":"fs-front","name":"federation fs-front",
  "protocols":["oidc"],
  "fields":{"oauthClientId":["fs-front"],
            "oauthRedirectUri":["<assertionConsumerService>"],
            "oauthTokenEndpointAuthMethod":"none",
            "oauthGrantType":["implicit"],"oauthResponseType":["id_token"]}}'
```

In product mode a signed-only ID Token by `form_post` is refused unless the
partner encrypts it ([below](#encrypted-assertions)) or the relationship sets
`fedAllowUnencrypted`. The job sets `fedAllowUnencrypted` `TRUE`.

### The authorization code flow

The default (`fedResponseType` `code`). This service redeems the code at the
partner's token endpoint and reads UserInfo. **Set `fedUserinfoUrl`**: a
provider that follows OpenID Connect Core section 5.4, iya-sts among them,
puts `preferred_username` and `email` in UserInfo, not in a code-flow ID
Token.

**Console:** as above with **Id** `oidc-code`, and in **Settings**, **Set**
`fedClientId` `fs-code`, `fedResponseType` `code`, `fedTokenUrl`,
`fedJwksUri` and `fedUserinfoUrl` from the partner's discovery document, and
`fedClientSecret` to the secret the partner issued. `fedClientSecret` is never
shown again on the page or in the API.

**API:**
```bash
api federation/create '{"id":"oidc-code","role":"service-provider","protocol":"oidc",
  "peer":"'"$ISSUER"'"}'
# one federation/set per field:
for kv in "fedSsoUrl=$ISSUER/oauth2/authorize" "fedClientId=fs-code" \
          "fedResponseType=code" "fedScope=openid profile email" \
          "fedTokenUrl=$ISSUER/oauth2/token" "fedJwksUri=$ISSUER/oauth2/jwks" \
          "fedUserinfoUrl=$ISSUER/oauth2/userinfo" "fedClientSecret=$SECRET" \
          "fedUsernameSource=preferred_username"; do
  api federation/set "$(jq -n --arg f "${kv%%=*}" --arg v "${kv#*=}" \
    '{id:"oidc-code",field:$f,value:$v}')"
done
api federation/enable '{"id":"oidc-code"}'
```

**At the partner**, a confidential client:
```bash
api applications/create '{"identifier":"fs-code","name":"federation fs-code",
  "protocols":["oidc"],
  "fields":{"oauthClientId":["fs-code"],
            "oauthRedirectUri":["<assertionConsumerService>"],
            "oauthClientSecret":"'"$SECRET"'",
            "oauthTokenEndpointAuthMethod":"client_secret_basic",
            "oauthGrantType":["authorization_code"],"oauthResponseType":["code"]}}'
```

This flow needs the outbound calls: `federation.outbound` on, an `https`
partner, and its certificate trusted (`federation.outboundCaFile` for a
private CA). `fedTokenAuth` chooses `client_secret_basic` (the default) or
`client_secret_post`.

The `/oauth2/...` paths above are this service's own, for an iya-sts
partner. For any other partner, take them from its discovery document.

### An OpenID Provider found through OpenID Federation

Set `fedTrustAnchor` instead of the endpoints and client credentials. The
provider is then discovered through its Trust Chain and this service
registers with it automatically. See
[Configuring OpenID Federation → This service as a federated relying party](configure-oidfed.md#this-service-as-a-federated-relying-party).

## WS-Federation

Taken from `sts_federation_signout.js` and `sts_federation_encryption.js`,
whose partner is the job itself, with a certificate of its own.

**Console:**
1. **Add a relationship**: **Id** `wsfed-t`, *Service provider*,
   **Protocol** *WS-Federation 1.2*, **Partner** the partner's issuer (the
   job uses `urn:test:signout-wsfed`), then **Add**.
2. In **Settings**, **Set** `fedSsoUrl` to the partner's passive requestor
   endpoint and `fedSigningCertificate` to its token-signing certificate.
3. **Turn on** `fedEnabled`.

**API:**
```bash
api federation/create '{"id":"wsfed-t","role":"service-provider","protocol":"wsfed",
  "peer":"urn:test:signout-wsfed"}'
api federation/set '{"id":"wsfed-t","field":"fedSsoUrl","value":"https://wsfed-partner.invalid/"}'
api federation/set '{"id":"wsfed-t","field":"fedSigningCertificate","value":"<base64 DER>"}'
api federation/enable '{"id":"wsfed-t"}'
```

This service sends `wa=wsignin1.0` with its `wtrealm`. The partner answers
with a `wresult` holding a SAML 1.1 or SAML 2.0 assertion. **At the
partner**, register the `wtrealm` (this service's entityID, in the
`metadata` document) and the `assertionConsumerService` as the `wreply`.

The jobs also set `fedAllowUnsolicited` `TRUE`, because their partner posts a
token without first being sent a request. Leave it off for a partner that
answers the `wsignin1.0` this service sends.

## SAML 1.1

Taken from `sts_federation_signout.js` and `sts_xml_schema_validation.js`.

**Console:** **Add a relationship** with **Id** `saml11-t`, *Service
provider*, *SAML 1.1*, **Partner** `urn:test:signout-saml11`. Then **Set**
`fedSsoUrl` to the partner's inter-site transfer service and
`fedSigningCertificate` to its signing certificate, and **Turn on**
`fedEnabled`.

**API:**
```bash
api federation/create '{"id":"saml11-t","role":"service-provider","protocol":"saml11",
  "peer":"urn:test:signout-saml11"}'
api federation/set '{"id":"saml11-t","field":"fedSsoUrl","value":"https://saml11-partner.invalid/"}'
api federation/set '{"id":"saml11-t","field":"fedSigningCertificate","value":"<base64 DER>"}'
api federation/enable '{"id":"saml11-t"}'
```

SAML 1.1 has no request message. The browser is sent to `fedSsoUrl` with a
`TARGET`, and unsolicited responses are accepted for the relationship
whatever `fedAllowUnsolicited` says. The SAML 1.1 `providerId` is
`fedLocalEntityId` (or the derived name) unless `fedSsoUrl` already names one.
`/federation/metadata/saml11-t` publishes this service's metadata for the
partner. SAML 1.1 defines no sign-out.

## OAuth 2.0

**No test job drives an enterprise OAuth 2.0 sign-in end to end.** The
fields below are the ones the relationship requires before it is ready; the
values are placeholders. The consumer providers Discord, GitHub, X and TikTok
are OAuth 2.0 relationships, and their sign-ins are tested
([below](#consumer-and-social-providers)).

An OAuth 2.0 relationship runs the authorization code flow with no ID Token.
The person is read off the access token when it is a JWT (verified against
`fedJwks` or `fedJwksUri`), and otherwise from `fedUserinfoUrl`. **Every
sign-in through one logs a warning**, because an access token says a client
was authorized, not that a person signed in. Prefer OpenID Connect where the
partner offers it.

```bash
api federation/create '{"id":"partner-oauth","role":"service-provider","protocol":"oauth2",
  "peer":"https://as.partner.example"}'
api federation/set '{"id":"partner-oauth","field":"fedSsoUrl","value":"https://as.partner.example/authorize"}'
api federation/set '{"id":"partner-oauth","field":"fedTokenUrl","value":"https://as.partner.example/token"}'
api federation/set '{"id":"partner-oauth","field":"fedUserinfoUrl","value":"https://as.partner.example/me"}'
api federation/set '{"id":"partner-oauth","field":"fedClientId","value":"<client id>"}'
api federation/set '{"id":"partner-oauth","field":"fedClientSecret","value":"<secret>"}'
api federation/enable '{"id":"partner-oauth"}'
```

Where the profile answer names the person somewhere other than `sub`, `id` or
`user_id`, set `fedSubjectClaim` to the field's path (for example `data.id`).

## Starting a sign-in

Once a relationship is ready, a person reaches the partner in one of three
ways:

* **The sign-in screen** shows a button for each usable relationship
  (`federation.loginButtons`, on by default).
* **An application's own partners.** Add the relationship's id to the
  application's `appFederationRelationship`. With one usable partner, the
  browser goes straight there; with several, the person chooses on
  `/authn/select-idp`. Set `appFederationAutoRedirect` to `FALSE` to show the
  sign-in screen with only those partners as buttons instead.
* **A link** to `/federation/login/<id>`, optionally with `?returnTo=<a path
  on this service>`. The relationship's page has **Start a federated sign-in
  through this partner**.

```bash
api applications/add '{"application":"fmb-webapp","attribute":"appFederationRelationship",
  "value":"fmb-upstream"}'
```

The names here are from the in-process test `tests/federation_map_bands.js`.
`fedHomeRealmDomain` on a relationship sends an OpenID Connect authorization
request whose `domain_hint` is one of its values straight to that partner,
unless the application names partners of its own.

## Who a partner may sign in

A partner signs in only the person its subject is **linked** to. The link is
a `federationLink` value on the person's entry: the relationship, the
partner's issuer, and the partner's stable identifier for them (OpenID
Connect's `sub`, a SAML persistent NameID). What happens to a subject nobody
has linked is the relationship's `fedSubjectPolicy`:

| `fedSubjectPolicy` | An unlinked subject |
|---|---|
| `link-at-first-sign-in` (the default, also when empty) | a local person with the confirm-lookup name signs in here first, then is linked; a name with no entry gets a new entry `<relationship>~<subject>` when `fedAutocreateUsers` is on |
| `pre-linked` | refused (`STS-FED-0091`); links are made by an administrator, the API or SCIM |
| `jit-namespaced` | always a new entry `<relationship>~<subject>`, when `fedAutocreateUsers` is on |
| `any-existing` | matched by name onto a local person. **Development only, and a warning:** the partner can sign in any local account it can name |

The confirm-lookup name comes from `fedUsernameSource` (the jobs use
`preferred_username`). [Federation](federation.md#which-people-a-partner-may-assert)
describes each policy in full. Taken from `sts_federation_subject_policy.js`
(relationship `oidc-link`) and `sts_federation_realms.js`.

**Choose the policy** in the relationship's **Settings**: pick it in the
`fedSubjectPolicy` drop-down, then **Set**.

```bash
api federation/set '{"id":"oidc-link","field":"fedSubjectPolicy","value":"pre-linked"}'
```

### Link a person by hand

**Console:** **Directory → Users**, the person, tab **Federation links**.
Under **Link a partner's subject**, pick the **Relationship**, enter the
**Subject** (the ID Token's `sub` or the persistent NameID, never a name or
an address) and, if it differs from the relationship's `fedPeer`, the
**Issuer**. Click **Link**. **Remove** on a link removes it.

**API:**
```bash
api users/federation-link '{"user":"fed-pre","relationship":"oidc-front","subject":"<the partner'"'"'s sub>"}'
api users/federation-link '{"user":"fed-pre","relationship":"saml","subject":"fed-pre"}'   # a SAML NameID
api users/federation-unlink '{"user":"fed-pre","link":"<the value federationLinks lists>"}'
```

The job reads the partner's `sub` for the person from the partner realm's
`GET /admin-api/users?user=<name>` (`subject`). A person's links are
`federationLinks` on that same read; a relationship's are `links` on
`GET /admin-api/federation?relationship=<id>`. **Removing a link ends every
session that partner signed the person in to.**

**Through SCIM**, the iya-sts extension
`urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User` carries
`federationLinks`, a list of `{relationship, subject, issuer?}`:

```json
{ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User",
              "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User"],
  "userName": "sp-scimmed",
  "name": { "givenName": "Subject", "familyName": "sp-scimmed" },
  "emails": [{ "value": "sp-scimmed@fs.example.net", "type": "work" }],
  "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User": {
    "federationLinks": [{ "relationship": "oidc-link", "subject": "<sub>" }] } }
```

### Rules on top of the policy

Each applies to linked people too. A refusal writes nothing on the entry.

| Field | Kind | What it requires |
|---|---|---|
| `fedSubjectGroup` | list | membership of one of these groups (cn or DN) |
| `fedSubjectDomain` | list | the address the partner sent, and the entry's own `mail`, in one of these domains |
| `fedSubjectPattern` | single | the entry's DN to match this regular expression whole |
| `fedMayAssertAdministrators` | switch, off | when off, a console administrator is refused (`STS-FED-0093`). **Turning it on is a warning**: the partner's key then signs administrators in to the console |

```bash
api federation/add-value '{"id":"oidc-link","field":"fedSubjectDomain","value":"nowhere.example"}'
api federation/remove-value '{"id":"oidc-link","field":"fedSubjectDomain","value":"nowhere.example"}'
api federation/set '{"id":"oidc-link","field":"fedMayAssertAdministrators","value":"TRUE"}'
```

In the console, a list field is in **Lists** (**Add**, **Remove**), and a
switch in **Switches**.

## What a sign-in writes

| Field | Default | What it does |
|---|---|---|
| `fedAutocreateUsers` | `TRUE` in development, `FALSE` in product, when created | whether a sign-in creates a missing person |
| `fedUpdateUserAttributes` | `TRUE` | overwrite a returning person's attributes from each assertion |
| `fedAttributeMap` | none | extra mappings, `<incoming name>=<LDAP attribute>`, beside a built-in table of OpenID Connect claims, SAML `urn:oid:` names and AD FS claim URIs |
| `fedProvisionGroups` | `FALSE` | turn group names the partner sends into memberships. It never joins a group that grants anything by being held |
| `fedProvisionCap` | empty (unlimited for an enterprise partner) | how many people this relationship may create |
| `fedProvisionIdleMinutes` | empty (off) | disable a person whose only way in is this relationship, once they have not signed in for this long |

**For product mode, map the names the attribute policy needs.** Taken from
`sts_federation_consumer.js`:

```bash
for m in given_name=givenName family_name=sn email=mail; do
  api federation/add-value '{"id":"consumer-oidc","field":"fedAttributeMap","value":"'"$m"'"}'
done
```

A name the partner sent and nothing wrote is listed on the relationship's
page under **Sent and not written**, with a **Map** form beside it.

---

# This service as the identity provider

Every protocol endpoint here already answers a foreign service provider, so
an identity-provider-side relationship does not decide whether the partner is
answered. Register the partner as an application first (for SAML 2.0, see
[Configuring SAML profiles](configure-saml.md)). The relationship then names
that application and adds two things: a **release list** and **how this
service authenticates people for the partner**.

No over-HTTP job creates an identity-provider-side relationship. The values
are from two in-process tests.

**Console:**
1. **Add a relationship**: **Id** `fmb-broker`, **This service is**
   *Identity provider*, **Protocol** *OpenID Connect*, **Partner** the
   partner's own identifier (`https://sp.example`), then **Add**.
2. In **Settings**, **Set** `fedApplication` to the identifier of the
   partner's application entry (`fmb-partner-app`).
3. In **Lists**, **Add** `email` to `fedRelease`.
4. Optionally pick a `fedAuthnMechanism` and **Set** it.
5. **Turn on** `fedEnabled`.

**API:**
```bash
api federation/create '{"id":"fmb-broker","role":"identity-provider","protocol":"oidc",
  "peer":"https://sp.example","application":"fmb-partner-app"}'
api federation/add-value '{"id":"fmb-broker","field":"fedRelease","value":"email"}'
api federation/enable '{"id":"fmb-broker"}'
```

The release value `email` is from `tests/attribute_claims.js`; the rest from
`tests/federation_map_bands.js`.

**`fedRelease` can only remove.** It narrows what the claim and attribute
pages, the groups claim and a client's own claims request would add. It never
removes `sub`, `iss`, `exp` or a NameID. **An empty list is no policy, not
"release nothing"**: adding the first value starts the filtering.

**`fedAuthnMechanism`** is one of `password`, `password-mfa`, `webauthn`,
`spnego`, `wallet` and `federation`. Empty says nothing, and the sign-in falls
through to the application entry and then the sign-in screen.

**An identity bridge.** With `federation`, the person signs in through
another, service-provider-side relationship of this realm, named in
`fedAuthnRelationship`:

```bash
api federation/set '{"id":"fmb-broker","field":"fedAuthnMechanism","value":"federation"}'
api federation/set '{"id":"fmb-broker","field":"fedAuthnRelationship","value":"fmb-upstream"}'
```

---

# Encrypted assertions

Every enterprise SAML 2.0, WS-Federation and OpenID Connect
service-provider-side relationship holds an encryption key pair, issued under
the realm's Intermediate when the relationship is created. (A consumer
provider's relationship is created with none.) The partner encrypts to it.
Taken from `sts_federation_encryption.js` (relationships `enc-saml`,
`enc-self-ec`, `enc-oidc`, `enc-oidc-self`).

**Where the key is published.** For SAML 2.0 and WS-Federation, in the
relationship's `metadata` as `KeyDescriptor use="encryption"`. For OpenID
Connect, at its `jwks` URL (`/federation/jwks/<id>`). The relationship's page
shows the certificate and the algorithms under **What to configure at the
partner** and **Encryption**.

| Field | Values (default first) |
|---|---|
| `fedEncryptionKeyType` | `rsa-3072` (the SAML 2.0 and WS-Federation default), `ec-p256` (the OpenID Connect default); for OpenID Connect only, the post-quantum `x-wing` and `ml-kem-768`, from Internet-Drafts few partners implement yet |
| `fedKeyManagementAlgorithm` | XML: `rsa-oaep` (RSA key), `ecdh-es` (EC key). JOSE: `RSA-OAEP-256` or `RSA-OAEP` (**a warning: SHA-1**) for an RSA key; `ECDH-ES`, `ECDH-ES+A128KW` or `ECDH-ES+A256KW` for an EC key; `HPKE-10-KE` for `x-wing`, `ML-KEM-768` for `ml-kem-768`. Empty means the key type's default |
| `fedContentEncryptionAlgorithm` | XML: `aes256-gcm`, `aes128-gcm`. JOSE: `A256GCM`, `A128GCM` |

AES-CBC, `rsa-1_5` and `RSA1_5` are refused in every mode, on the field and
on arrival. Changing `fedEncryptionKeyType` issues a key of the new type at
once:

```bash
api federation/set '{"id":"enc-self-ec","field":"fedEncryptionKeyType","value":"ec-p256"}'
```

**A SAML 2.0 partner that is an iya-sts realm** encrypts when its application
for this service names the certificate from this relationship's metadata:

```bash
# in the identity-provider realm
api applications/create '{"identifier":"<our entityID>","name":"federation fes",
  "protocols":["saml2"],
  "fields":{"samlEntityId":["<our entityID>"],
            "samlAssertionConsumerService":["<assertionConsumerService>"],
            "samlSigningCertificate":["<our signing certificate, PEM>"],
            "samlEncryptionCertificate":"<our encryption certificate, PEM>",
            "saml2EncryptAssertion":"TRUE",
            "saml2KeyTransportAlgorithm":"rsa-oaep",
            "saml2EncryptionAlgorithm":"aes256-gcm"}}'
```

**An OpenID Provider** encrypts the ID Token when the client registers
`id_token_encrypted_response_alg` and `_enc` with this relationship's key. The
job registers it at an iya-sts partner like this (in development: a product
realm will not register an implicit-grant client):

```
POST /realm/fei/oauth2/register
{"client_name":"fe-oidc","redirect_uris":["<assertionConsumerService>"],
 "response_types":["id_token"],"grant_types":["implicit"],
 "token_endpoint_auth_method":"none",
 "id_token_encrypted_response_alg":"ECDH-ES","id_token_encrypted_response_enc":"A256GCM",
 "jwks":<the document at /federation/jwks/enc-oidc>}
```

then sets the `client_id` it was given as the relationship's `fedClientId`. An
encrypted ID Token must be signed inside (signed, then encrypted).

**Rotate the key** with **Rotate the encryption key** on the relationship's
page, or:

```bash
api federation/rotate-key '{"id":"enc-saml"}'
```

The new key is published at once. The one it replaced still decrypts for
`federation.encryptionKeyGraceS` (86400 s), then the scheduler job
`federation.encryption-key-retire` removes it.

---

# Sign-out

Taken from `sts_federation_signout.js`. A partner's sign-out ends only the
session that partner started here; a sign-out here offers the person the
partner's own.

| Protocol | Give the partner | Set here |
|---|---|---|
| SAML 2.0 | `singleLogout` as its `SingleLogoutService` (Redirect and POST) | `fedSloUrl`, the partner's `SingleLogoutService`; `fedSloBinding` `HTTP-Redirect` (the default) or `HTTP-POST` |
| WS-Federation | `signOutCleanup` as its sign-out cleanup URL | — |
| OpenID Connect | `backchannelLogout` as `backchannel_logout_uri`; `frontchannelLogout` as `frontchannel_logout_uri`, with `frontchannel_logout_session_required`; `postLogoutRedirect` as `post_logout_redirect_uri` | `fedEndSessionUrl`, the partner's `end_session_endpoint`, for a sign-out here that ends there |
| SAML 1.1, OAuth 2.0 | — | — (neither defines a sign-out) |

**SAML 2.0, with an iya-sts partner:**
```bash
api federation/set '{"id":"saml","field":"fedSloUrl","value":"<its HTTP-Redirect SingleLogoutService>"}'
# at the partner (an iya-sts realm): where its LogoutResponse and LogoutRequest go
api saml2/set-logout-service '{"sp":"<our entityID>","value":"<singleLogout>"}'
```

**OpenID Connect front-channel, with an iya-sts partner:** the partner's
client carries `oauthFrontchannelLogoutUri` (this relationship's
`frontchannelLogout`) and `oauthFrontchannelLogoutSessionRequired` `TRUE`. For
RP-Initiated Logout from here:

```bash
api federation/set '{"id":"oidc-t","field":"fedEndSessionUrl","value":"https://oidc-partner.invalid/logout"}'
```

| Switch | Default | What it does |
|---|---|---|
| `fedAcceptSignout` | `TRUE` | honour the partner's sign-out. Off, every one is refused (`STS-FED-0123`) |
| `fedRequireSignedLogout` | `TRUE` | require a SAML logout message to be signed. **Off is a warning**: anybody who can name a session can end it. Product refuses it off |

A WS-Federation `wsignoutcleanup1.0` is unsigned by its specification, so it
draws a page, and the session in that browser ends only when the person
presses its button.

---

# A partner's Shared Signals

A partner can send this realm CAEP and RISC events about the people it signs
in. A partner that signs nobody in (a device manager, an HR system) is a
relationship of protocol `ssf`. Taken from `sts_ssf_foreign_receiver.js`,
whose partner `partner-a` is another realm of this service, with a client
`realm-b-receiver` registered there.

**Console:** on the relationship's page, in **Shared Signals from this
partner**: **Set** `fedSignalsTokenUrl`, `fedSignalsClientId`,
`fedSignalsClientSecret` and `fedSignalsDelivery` (`poll` or `push`),
**Turn on** `fedSignalsEnabled`, then **Create stream** (or **Discover**
first). **Verify** asks the partner for a verification event; **Poll now**
polls at once.

**API:**
```bash
for kv in "fedSignalsTokenUrl=https://<host>/realm/a/oauth2/token" \
          "fedSignalsClientId=realm-b-receiver" "fedSignalsClientSecret=$SECRET" \
          "fedSignalsDelivery=poll" "fedSignalsEnabled=TRUE"; do
  api federation/set "$(jq -n --arg f "${kv%%=*}" --arg v "${kv#*=}" \
    '{id:"partner-a",field:$f,value:$v}')"
done
api federation/signals-create-stream '{"id":"partner-a"}'
api federation/signals-verify '{"id":"partner-a"}'
```

The SSF issuer is `fedSignalsIssuer`, or `fedPeer` when that is empty; set it
for a SAML or WS-Federation partner, whose entityID is not its SSF issuer.
The three `fedSignals*` credentials fall back to `fedTokenUrl`,
`fedClientId` and `fedClientSecret`; `fedSignalsBearer` is the alternative.
An `ssf` relationship has `fedSignalsEnabled` on from the start, and its
people are linked by hand with `users/federation-link`, naming the `issuer`
its events use.

[Shared Signals → Receiving from a federation partner](shared-signals.md#receiving-from-a-federation-partner)
has the default reactions, push delivery, and **Unblock**
(`federation/signals-unblock`).

---

# Consumer and social providers

Google, Apple, GitHub, Discord and the rest of the catalogue are
relationships of the *consumer* category, made from a built-in profile.
**They are off in a realm until `federation.consumerProviders` is on.** A
newcomer gets an entry of their own (`fedSubjectPolicy` `jit-namespaced`,
`fedAutocreateUsers` on in both modes), and an address is never used to match
an existing person. [Consumer and social providers](federation-consumer-providers.md)
has the catalogue and what to register at each provider.

Taken from `sts_federation_consumer.js`, which drives the `generic-oidc`
profile against another realm of this service.

**Console:**
1. **Protocols → Federation**, tab **Settings**: set
   `federation.consumerProviders` to `true`, then **Save Federation**.
2. Tab **Consumer and social providers**: on the provider's row, enter the
   **Id**, the **Client ID** and the **Client secret**, then **Add**.
3. On the new relationship's page, **Set** whatever its page lists as still
   missing. Register its `assertionConsumerService` as the redirect URI at
   the provider.
4. **Turn on** `fedEnabled`.

**API:**
```bash
api config/set '{"key":"federation.consumerProviders","value":"true"}'
api federation/create '{"id":"consumer-oidc","role":"service-provider","protocol":"oidc",
  "provider":"generic-oidc","peer":"<the provider'"'"'s issuer>","clientId":"cs-consumer"}'
api federation/set '{"id":"consumer-oidc","field":"fedSsoUrl","value":"<its authorization_endpoint>"}'
api federation/set '{"id":"consumer-oidc","field":"fedResponseType","value":"id_token"}'
# fedJwks: paste the provider's JWKS, as in the OpenID Connect front-channel recipe
api federation/enable '{"id":"consumer-oidc"}'
```

For a catalogued provider the profile writes the endpoints, issuer, scope and
token authentication, so the create is enough:

```
POST /admin-api/federation/create
{ "id": "google", "role": "service-provider", "protocol": "oidc",
  "provider": "google", "clientId": "<client id>", "clientSecret": "<secret>" }
```

`GET /admin-api/federation?category=consumer` lists the consumer relationships.

### Sign in with Apple

Apple also needs `fedTeamId`, `fedKeyId` and `fedClientSigningKey` (the
key's `.p8` file, pasted whole), and the code comes back by `form_post`. The
values below are from the in-process test
`tests/federation_consumer_providers.js`:

```bash
api federation/create '{"id":"cp-apple","role":"service-provider","protocol":"oidc",
  "provider":"apple","clientId":"com.example.web"}'
api federation/set '{"id":"cp-apple","field":"fedTeamId","value":"TEAM123456"}'
api federation/set '{"id":"cp-apple","field":"fedKeyId","value":"KEY1234567"}'
jq -n --rawfile k AuthKey.p8 '{id:"cp-apple",field:"fedClientSigningKey",value:$k}' |
  curl -sk -X POST "$BASE/admin-api/federation/set" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' --data-binary @-
api federation/enable '{"id":"cp-apple"}'
```

**Apple's server-to-server notifications.** Register
`https://<host>/federation/notifications/cp-apple` (in a trust realm,
`/realm/<id>/federation/notifications/cp-apple`) as the notification endpoint
at Apple. `consent-revoked` and `account-delete` remove the person's
connection through Apple and end the sessions it started.

There is no `clientSecret` for Apple: its client secret is a short-lived JWT
this service signs with that key for every token request.

## Related

* [Federation](federation.md): the behaviour, every setting and every relationship field.
* [Consumer and social providers](federation-consumer-providers.md) and [Shared Signals](shared-signals.md).
* [Configuring OpenID Federation](configure-oidfed.md): trust through a chain of signed statements.
* [Configuring SAML profiles](configure-saml.md), [Configuring OpenID Connect flows](configure-oidc-flows.md) and [Configuring OAuth 2.0 grants](configure-oauth2-grants.md): this service as the identity provider to applications.
* [Sessions](sessions.md) and [Signing out](signing-out.md).
