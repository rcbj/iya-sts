---
title: "Configuring WS-Federation"
---

# Configuring WS-Federation

This page shows how to set up iya-sts as a WS-Federation 1.2 identity
provider, for each message of the passive requestor profile it supports: the
relying party to register, the settings to change, and the request the
relying party then sends. Each recipe is given twice: once as steps in the
**admin console** (`/admin`) and once as **Management API** calls
(`/admin-api`).

The values come from this repository's test jobs, and each recipe names the
job it is taken from. Most of them run against a service in both development
and product mode. Change the identifiers and URLs to your own. How the
profile *behaves*, and every setting with its default, are on
[WS-Federation](ws-federation.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor. The SOAP token service is on
[Configuring WS-Trust](configure-ws-trust.md).

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/wsfed` | **Protocols → WS-Federation** | Who may start a sign-in: the relying party, this identity provider, or both. Save with **Save WS-Federation**. |
| `/admin/saml2`, tab **SAML assertions** | **Protocols → SAML** | The WS-Federation assertion lifetime, under the heading **WS-Federation**. Save with **Save assertion settings**. |
| `/admin/applications/new` | **Applications → New application ›** | Register a relying party. Tick **WS-Federation** under **Protocol families it is declared for**. |
| `/admin/applications?application=<id>` | click an application's row | The **Configuration** tab's **WS-Federation** sub-tab holds the relying party's attributes; save with **Save WS-Federation**. The **Return addresses** tab confirms or discards a `wreply` that development mode recorded. |

Each setting is also `POST /admin-api/config/set` with `{key, value}`, and
`GET /admin-api/wsfed` returns the page's settings. The current list of
endpoints is at `/admin/sts-metadata`, and every operation is in
`/admin-api/openapi.json`.

Every path on this page is per [trust realm](trust-realms.md). In a realm, put
`/realm/<id>` in front of it: `/realm/<id>/wsfed`,
`/realm/<id>/admin-api/...`. `sts_idp_initiated_wsfed.js` makes a realm of
its own first, in the mode the service runs in. Its names carry a per-run
tag, and `example` stands in for it on this page:

```bash
api realms/create '{"id":"wsi-example","domain":"wsi-example.example.net",
  "name":"#715 WS-Federation initiation"}'
```

### What development and product mode change

| | Development | Product |
|---|---|---|
| `wtrealm` | Any relying party. It is recorded in the register. | Must be a registered relying party, or the answer is a 404 page. |
| `wreply` | Used as given. With none, the registered `wsfedReplyUrl`. | Must equal one of the `wsfedReplyUrl` values exactly. An address that development recorded must be confirmed first. |
| The password at the sign-in screen | Any password except `invalid`. | Checked. |
| Given name, surname, mail, display name, UPN | Invented. | Read from the person's directory entry, or left out. |

The `wauth` step-up, the `wreqptr` refusal, the `wctx` round trip and
`/wsfed/initiate` behave the same in both modes.

"Registered" means created by an administrator (the console or
`/admin-api`), by an LDAP add under `ou=applications`, by RFC 7591, by an
OpenID Federation, or by this service's own seeding. An entry that a
development-mode request created by being seen does not count, even after it
is edited. So every recipe here registers its relying parties first, in both
modes.

## The endpoint

The passive requestor endpoint is `/wsfed`, and the message is the `wa`
parameter. `GET /wsfed` with no `wa` describes every parameter as this realm
treats it. A sign-in response is a page that posts a form to `wreply`. The
form carries `wresult`, a WS-Trust `RequestSecurityTokenResponse` around a
signed assertion.

## Register the relying party

A relying party is named by its `wtrealm`, and the response is posted to its
`wreply`. Register the `wtrealm` as the identifier, and each reply address on
`wsfedReplyUrl`.

Taken from `sts_idp_initiated_wsfed.js`, which runs in development and product
mode.

**Console:**
1. **Applications → New application ›**.
2. Under **What it is called**, set **Identifier** to `urn:wsi:example:plain`.
3. Under **Protocol families it is declared for**, tick **WS-Federation**.
4. In `wsfedReplyUrl`, enter `https://plain-example.wsi.example.test/wsfed`, one address per line.
5. Click **Create the application**.

The create copies the identifier into `wsfedRealm` when you leave it empty.

**API:**
```bash
api applications/create '{"identifier":"urn:wsi:example:plain","name":"urn:wsi:example:plain",
  "protocols":["wsfed"],
  "fields":{"wsfedRealm":["urn:wsi:example:plain"],
            "wsfedReplyUrl":["https://plain-example.wsi.example.test/wsfed"]}}'
```

**A `wreply` that development mode recorded** is marked as observed on the
entry, and product mode refuses it until you confirm it. On the
application's **Return addresses** tab, click **Confirm** (or **Discard**).
Through the API:

```bash
api applications/confirm-address '{"application":"urn:wsi:example:plain",
  "attribute":"wsfedReplyUrl","value":"https://plain-example.wsi.example.test/wsfed"}'
```

`applications/discard-address` takes the same body. Adding the address
yourself with `applications/add` confirms it too.

## Sign in: wsignin1.0

The relying party sends the browser to:

```
GET /wsfed?wa=wsignin1.0&wtrealm=<wtrealm>&wreply=<reply URL>&wctx=<state>
```

`sts_xml_schema_validation.js` uses
`wtrealm=https://wsrp-p-1.example.com/` and
`wreply=https://wsrp-p-1.example.com/signin`, with the relying party
registered for both protocols as on
[Configuring WS-Trust → The delegation rules](configure-ws-trust.md#the-delegation-rules).
`sts_idp_initiated_wsfed.js` uses `wctx=sp`.

The person signs in at the service's sign-in screen, the same one every
protocol uses, so a person already signed in is not asked again. The browser
then posts `wa=wsignin1.0`, `wresult` and `wctx` to `wreply`.

* **`wreply`** is optional. With none, the response goes to the registered
  `wsfedReplyUrl`, and the request is refused if there is none. It must be an
  absolute `http` or `https` URL.
* **`wctx`** comes back byte for byte. The initiation job sends
  `rm=0&id=passive ru=%2Fhome é` to check it.
* **`wfresh`** is a maximum age in **minutes**. `0` always shows the sign-in
  screen.
* **`whr`** is recorded. To send a relying party's people to a federation
  partner, set `appFederationRelationship` on its entry; see
  [Federation](federation.md).
* **`wreqptr`** is refused. Send the RST by value in `wreq`.

A `wsignin1.0` may arrive as a cross-site form POST. The session cookie is
`SameSite=Lax`, so such a request goes to the sign-in screen even when the
person has a session. Use a GET to avoid that.

## Token type and RSTR version

The default token is a SAML 1.1 assertion in a February 2005
`RequestSecurityTokenResponse`. The schema job asks for all four combinations:

| Ask with | Token | RSTR |
|---|---|---|
| nothing | SAML 1.1 | WS-Trust 2005/02, one `RequestSecurityTokenResponse` |
| `trust=1.3` | SAML 1.1 | WS-Trust 1.3, an RSTR Collection |
| `tokenType=saml2` | SAML 2.0 | WS-Trust 2005/02 |
| `tokenType=saml2&trust=1.3` | SAML 2.0 | WS-Trust 1.3 |

`tokenType` and `trust` are this service's own test switches. `tokenType`
also takes `saml11`, `saml1`, `1.1`, `saml20` and `2.0`. The standard way to
ask is a `wreq` RST, whose `wst:TokenType` wins over `tokenType`:

```
wreq=<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
       <wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>
     </wst:RequestSecurityToken>
```

The two values accepted here are `urn:oasis:names:tc:SAML:1.0:assertion` and
`urn:oasis:names:tc:SAML:2.0:assertion`, the types the metadata offers. Any
other value, including the token profile URIs `/sts` accepts, is refused with
a 400 page. An `AppliesTo` in `wreq` that differs from `wtrealm` is logged,
and `wtrealm` wins.

The assertion's issuer is the realm's OAuth 2.0 issuer. Pin
`global.publicBaseUrl` so it does not follow the host a request arrived on.

## Assertion lifetime and attributes

The assertion lives `wsfed.assertionLifetimeMin` minutes (default `60`). One
relying party can have its own value in `wsfedAssertionLifetimeMin`.

**Console:** **Protocols → SAML → SAML assertions**, the row under
**WS-Federation**, then **Save assertion settings**. For one relying party,
set `wsfedAssertionLifetimeMin` on its **Configuration → WS-Federation**
sub-tab (under **Advanced view (every field)**) and click
**Save WS-Federation**.

**API:**
```bash
api config/set '{"key":"wsfed.assertionLifetimeMin","value":120}'
api applications/set '{"application":"urn:wsi:example:plain",
  "attribute":"wsfedAssertionLifetimeMin","value":"30"}'
```

The value `120` and `30` are examples; no test sets them.

The assertion carries the built-in claims under Microsoft claim URIs, and the
SAML 1.1 set of custom attributes (the SAML 2.0 set for a SAML 2.0 token). To
add one to every assertion:

```bash
api saml-attributes/add '{"set":"saml11","name":"dept","value":"engineering"}'
```

That call is from `sts_saml11.js`. In product mode the person's name and mail
come from their directory entry, so create people with their attributes
filled in.

## wauth: demand a sign-in method

`wauth` makes the relying party's demand. `tests/wsfed_wauth_step_up.js`
sends each of these:

| `wauth` | Met by |
|---|---|
| `urn:oasis:names:tc:SAML:1.0:am:password` | a password |
| `http://schemas.microsoft.com/claims/multipleauthn` | two factors: a password and a one-time code, or a password and a security key |
| `urn:oasis:names:tc:SAML:1.0:am:HardwareToken` | a security key, alone or after a password |

The password demand also accepts
`urn:oasis:names:tc:SAML:1.0:am:unspecified`,
`urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`,
`urn:oasis:names:tc:SAML:2.0:ac:classes:Password`,
`http://schemas.xmlsoap.org/ws/2005/05/identity/authenticationmethod/password`
and
`http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password`.
Any other value is refused.

A demand the session does not meet sends the person to sign in again with
that method required, once, in both modes. The assertion then reports what
happened. A demand still unmet on the way back is refused. No setting is
needed, but the person must hold the factor: a TOTP or a security key
enrolled. A multi-factor demand needs a second factor that the realm offers;
see [Authentication](authentication.md).

```
GET /wsfed?wa=wsignin1.0&wtrealm=urn:wauth-step-up:rp&wctx=ctx-1
          &wreply=https://rp.wauth-step-up.example/wsfed
          &wauth=http://schemas.microsoft.com/claims/multipleauthn
```

## Who may start a sign-in

Two switches, each a realm setting with a per-relying-party override. Both
are on the relying party's **Configuration → WS-Federation** sub-tab, in the
section **Who may start a sign-in**:

| Setting | Override on the entry | Default | Governs |
|---|---|---|---|
| `wsfed.spInitiatedSso` | `wsfedSpInitiatedSso` | on | a `wsignin1.0` at `/wsfed` |
| `wsfed.idpInitiatedSso` | `wsfedIdpInitiatedSso` | off | the link `/wsfed/initiate/{rp}` |

The realm settings are on **Protocols → WS-Federation**. Save with
**Save WS-Federation**.

### Identity-provider-initiated sign-in

WS-Federation has no request for this, so the link is this service's own:

```
GET /wsfed/initiate/<wtrealm or slug>[?wctx=…]
GET /wsfed/initiate?wtrealm=<wtrealm>[&wctx=…]
```

Use the query form for a `wtrealm` that is a URL. Taken from
`sts_idp_initiated_wsfed.js`:

**Console:** on the relying party's **Configuration → WS-Federation**
sub-tab, set `wsfedIdpInitiatedSso` to `TRUE`, check that `wsfedReplyUrl`
holds an address, and click **Save WS-Federation**.

**API:**
```bash
api applications/create '{"identifier":"urn:wsi:example:open","name":"urn:wsi:example:open",
  "protocols":["wsfed"],
  "fields":{"wsfedRealm":["urn:wsi:example:open"],
            "wsfedReplyUrl":["https://open-example.wsi.example.test/wsfed"],
            "wsfedIdpInitiatedSso":"TRUE"}}'
```

or for every relying party in the realm (an entry's own `FALSE` still wins):

```bash
api config/set '{"key":"wsfed.idpInitiatedSso","value":true}'
api config/reset '{"key":"wsfed.idpInitiatedSso"}'
```

The same rules hold in both modes:
* the relying party must be registered (404 otherwise);
* a `wreply` on the link is refused, even an empty one;
* the response goes to the first registered, confirmed `wsfedReplyUrl`, and
  the link is refused when there is none;
* only `wctx`, `tokenType` and `trust` are read from the link.

The job turns risk scoring off in its realm (`risk.assessSignIns` `false`),
because product mode's issuance policy asks an unknown automated client for
a security key. A person in a browser does not need that. The link also works
from `/launch/{app}`; see
[Identity-provider-initiated sign-in](idp-initiated-sso.md).

### Only from the link

The job's `urn:wsi:<tag>:idp-only` relying party sets
`wsfedIdpInitiatedSso` to `TRUE` and `wsfedSpInitiatedSso` to `FALSE`. Its
own `wsignin1.0` gets a 403 page, and the link still signs people in. A
`wsignin1.0` carries no signature, so this switch closes the door for
everybody. It does not prove who sent a request while it was open.

## Sign out

`wsignout1.0` ends the person's session, which every protocol here shares.
The page then loads each relying party's cleanup URL as an image:

```
GET /wsfed?wa=wsignout1.0[&wtrealm=<wtrealm>][&wreply=<URL>]
```

* **The cleanup URL** is the `wreply` each sign-in response was posted to,
  with `wa=wsignoutcleanup1.0` added. Nothing to configure.
  `wsfedSignOutUri` can be set on an entry, but the sign-out does not read it
  yet.
* **With `wreply`**, the page offers a link back rather than redirecting, so
  the cleanup images can finish.
* **`wsignoutcleanup1.0`** ends the session and sends no cleanups of its own.
* **Several accounts in one browser** (`authn.multipleAccounts`, off by
  default; see [Multiple accounts](multiple-accounts.md)): `wsignout1.0` asks
  which account to sign out of when more than one signed in to `wtrealm`.
  `wsignoutcleanup1.0` ends all of them.

`tests/multi_account_logout.js` and `tests/backchannel_logout.js` send these
messages. The protocol-independent `/logout` sends the same cleanups; see
[Signing out](signing-out.md).

## Metadata

| URL | What it is |
|---|---|
| `/FederationMetadata/2007-06/FederationMetadata.xml` | The realm's signed metadata, at the path AD FS uses. |
| `/wsfed/metadata/<wtrealm or slug>` | The same document for one registered relying party. Unregistered is a 404 in both modes. |

Load either into the relying party. It names the `PassiveRequestorEndpoint`
(`/wsfed`), the `SecurityTokenServiceEndpoint` (`/sts`), the token types
offered and the signing certificate. The same entity is also the SAML 2.0 and
SAML 1.1 identity provider.

## Related

* [WS-Federation](ws-federation.md): the behaviour and every setting.
* [Configuring WS-Trust](configure-ws-trust.md), [Configuring SAML profiles](configure-saml.md)
  and [Configuring OpenID Connect flows](configure-oidc-flows.md).
* [Identity-provider-initiated sign-in](idp-initiated-sso.md),
  [Signing out](signing-out.md), [Federation](federation.md),
  [Trust realms](trust-realms.md).
