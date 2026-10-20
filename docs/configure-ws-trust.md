---
title: "Configuring WS-Trust"
---

# Configuring WS-Trust

This page shows how to set up iya-sts as a WS-Trust security token service,
for each request it supports: the relying party to register, the settings to
change, and the request the client then sends. Each recipe is given twice:
once as steps in the **admin console** (`/admin`) and once as **Management
API** calls (`/admin-api`).

The values come from this repository's test jobs, and each recipe names the
job it is taken from. They run against a service in both development and
product mode. Change the identifiers, URLs and passwords to your own. How the
service *behaves*, its faults and every setting with its default, are on
[WS-Trust](ws-trust.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor. The browser profile is on
[Configuring WS-Federation](configure-ws-federation.md).

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/wstrust` | **Protocols → WS-Trust** | The token lifetime, its ceiling, the JWT signing algorithm and the JWT certificate header. Save with **Save WS-Trust**. |
| `/admin/applications/new` | **Applications → New application ›** | Register a relying party. Tick **WS-Trust** under **Protocol families it is declared for**. |
| `/admin/applications?application=<id>` | click an application's row | The **Configuration** tab's **WS-Trust** sub-tab holds `wstrustAppliesTo` and `wstrustJwtScope`; save with **Save WS-Trust**. The delegation controls are on the **Every protocol** sub-tab, in the section **Delegation / Impersonation**. |
| `/admin/delegation` | **Monitoring → Delegation** | Every `OnBehalfOf` and `ActAs` act, allowed or refused, with the rule that decided it. |

Each setting is also `POST /admin-api/config/set` with `{key, value}`, and
`GET /admin-api/wstrust` returns the page's settings. The current list of
endpoints is at `/admin/sts-metadata`, and every operation is in
`/admin-api/openapi.json`.

Every path on this page is per [trust realm](trust-realms.md). In a realm, put
`/realm/<id>` in front of it: `/realm/<id>/sts`, `/realm/<id>/admin-api/...`.
Several jobs below make a realm of their own first, and give it its mode with
`overrides` (from `sts_xml_schema_validation.js`). That job's names end in a
per-run stamp, and `-1` stands in for it on this page:

```bash
api realms/create '{"id":"xsdp-1","domain":"xsdp-1.example.net","name":"xsdp-1",
  "overrides":{"global.mode":"product"}}'
```

### What development and product mode change

The same registration behaves differently in the two modes (`global.mode`).
Development mode makes things up. Product mode refuses anything that was not
registered or does not verify.

| | Development | Product |
|---|---|---|
| The `AppliesTo` | Any address, or none. It is recorded in the application register. | Must resolve to a **registered** application (`wstrustAppliesTo`, then `samlEntityId`), or one of this identity provider's own names. Otherwise the fault is `wst:InvalidScope`. A request with no `AppliesTo` gets `wst:InvalidRequest`. |
| A password | Any password except `invalid`. | Checked against the person's password, or the application's client secret. |
| A token presented as a credential | Believed. | Must be one this realm signed, unexpired, and addressed to its holder or to this identity provider. |
| `OnBehalfOf` / `ActAs` | Needs no requester credential. The delegation policy is asked, and the token is issued even when it would refuse. | Needs the requester's own credential, and the delegation policy must allow the act. |
| An assertion credential with no NameID | A subject such as `saml-subject` is invented. | Refused. |

"Registered" means created by an administrator (the console or
`/admin-api`), by an LDAP add under `ou=applications`, by RFC 7591, by an
OpenID Federation, or by this service's own seeding. An entry that a
development-mode request created by being seen does not count, even after it
is edited. So every recipe here registers its relying parties first, in both
modes.

## The endpoint

The security token service is `POST /sts`. It speaks WS-Trust 1.4, 1.3, and
the 2005/02 and 2004/04 namespaces, over SOAP 1.1 (`text/xml`) or SOAP 1.2
(`application/soap+xml`). The answer is in the namespace and SOAP version the
request used. `GET /sts` describes the endpoint and names the issuer every
token carries: the realm's OAuth 2.0 issuer. `GET /sts/cert` is the
certificate a relying party verifies an assertion with.

## Register the relying party

The relying party is the service the token is for. A request names it by the
`AppliesTo` address, and the token's audience is that address. Register it
with the address as its identifier.

Taken from `sts_xml_schema_validation.js` (the second relying party, `wsSrc`).

**Console:**
1. **Applications → New application ›**.
2. Under **What it is called**, set **Identifier** to `https://wssrc-p-1.example.com/`.
3. Under **Protocol families it is declared for**, tick **WS-Trust**.
4. Click **Create the application**.

The create copies the identifier into `wstrustAppliesTo`, the WS-Trust
identifier attribute, when you leave that attribute empty. To answer to more
than one address, add each one to `wstrustAppliesTo` on the application's
**Configuration → WS-Trust** sub-tab.

**API:**
```bash
api applications/create '{"identifier":"https://wssrc-p-1.example.com/",
  "name":"wssrc","protocols":["wstrust"],
  "fields":{"wstrustAppliesTo":["https://wssrc-p-1.example.com/"]}}'
```

An application whose SAML entityID is the address works too: an `AppliesTo`
is looked up in `wstrustAppliesTo` first and `samlEntityId` second. The match
is exact and case-sensitive.

## Issue a token with a UsernameToken

The simplest request is an `Issue` with a person's username and password in
the WS-Security header. With no `TokenType`, the token is a signed SAML 2.0
assertion. The schema job sends this request in all three namespaces it
validates, over both SOAP versions:

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password>…</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
          <wsa:Address>https://wssrc-p-1.example.com/</wsa:Address>
        </wsa:EndpointReference>
      </wsp:AppliesTo>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>
```

```bash
curl -sk -X POST "$BASE/sts" -H 'content-type: application/soap+xml' --data-binary @rst.xml
```

The person must exist, with a password. In product mode the password is
checked. Create the person as on
[Configuring SAML profiles → Attributes](configure-saml.md#attributes).

| Namespace | `wst:` namespace URI |
|---|---|
| WS-Trust 1.3 (and 1.4) | `http://docs.oasis-open.org/ws-sx/ws-trust/200512` |
| WS-Trust 1.4 elements (`ActAs`) | `http://docs.oasis-open.org/ws-sx/ws-trust/200802` |
| February 2005 | `http://schemas.xmlsoap.org/ws/2005/02/trust` |
| April 2004 | `http://schemas.xmlsoap.org/ws/2004/04/trust` |

The operation is the last path segment of `wst:RequestType`, so
`<ns>/Issue` works in every namespace.

**A person who holds a second factor** is refused their own password at
`/sts` in product mode, with the same fault a wrong password gets. They
present an app password scoped to `wstrust` instead; see
[Authentication → The password-only doors, and app passwords](authentication.md#the-password-only-doors-and-app-passwords).

**Every token is a bearer token.** The RSTR repeats the `wst:KeyType` the
request named, or `…/Bearer` when it named none. No proof key is issued, and
the assertion's subject confirmation is always `bearer`.

## Choose the token type

`wst:TokenType` picks the token:

| `wst:TokenType` | Token |
|---|---|
| none, or any value not below | SAML 2.0 assertion |
| `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1`, or `urn:oasis:names:tc:SAML:1.0:assertion` | SAML 1.1 assertion |
| `urn:ietf:params:oauth:token-type:jwt` | JWT, returned in a `wsse:BinarySecurityToken` with that `ValueType` |

The chain jobs ask for SAML 2.0 with
`http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0`.
Add the element after `RequestType`:

```xml
<wst:TokenType>urn:ietf:params:oauth:token-type:jwt</wst:TokenType>
```

The JWT is an RFC 9068 access token (`typ: at+jwt`). It is signed with the
realm key for `wstrust.jwtAlgorithm` and verifies against `/oauth2/jwks`.
Its `sub` is the person's `urn:uuid:` subject, so a JWT is refused for a name
the directory does not hold. [WS-Trust → Token types](ws-trust.md#token-types)
lists every claim.

### Scopes in a JWT

A JWT carries no `scope` unless the application the `AppliesTo` names lists
some on `wstrustJwtScope`. Each one is judged as an access token's scope is,
with that application as the client. In product mode it must also be on
`oauthAllowedScope`, so the application must be declared for OAuth 2.0 too.
A scope that would be dropped is warned about where you set it, and is left
off the token.

Taken from `wstrust_chain_kit.js` (every chain job). It declares `chain.read`
and lists one undeclared scope, which product mode leaves off.

**Console:** on the application's page, **Configuration → OAuth 2.0 / OpenID
Connect**, add `chain.read` to `oauthAllowedScope`. Then on
**Configuration → WS-Trust**, add `chain.read` to `wstrustJwtScope` and click
**Save WS-Trust**.

**API:**
```bash
api applications/add '{"application":"apigw1-wsdel","attribute":"oauthAllowedScope","value":"chain.read"}'
api applications/add '{"application":"apigw1-wsdel","attribute":"wstrustJwtScope","value":"chain.read"}'
```

### What a token carries

The token's claims and attributes are the `AppliesTo` application's
settings, with the subject's values. They are configured where the OAuth
and SAML ones are, with no WS-Trust copy:
* a SAML 2.0 assertion: the realm's SAML 2.0 custom attributes and the
  application's `saml2CustomAttributes`;
* a SAML 1.1 assertion: the `saml11` set and `saml11CustomAttributes`;
* a JWT: the access-token custom claims, and the application's
  `oauthClaimsAccessToken`;
* all three: the groups claim (`appGroupsClaim`, `appGroupsClaimName`,
  `appGroupsClaimValue`) and the roles claim.

The chain jobs set every one of these on each tier
(`wstrust_chain_kit.js`, `CLAIM_FIELDS`). See
[Applications → Custom claims, SAML attributes and token lifetimes](applications.md#custom-claims-saml-attributes-and-token-lifetimes).

## Renew, Validate and Cancel

The same body with another `RequestType`, and the token in a target element.
The schema job sends each of these, with the SAML 2.0 assertion it was issued,
in every namespace and SOAP version:

| `RequestType` | Target element | Answer |
|---|---|---|
| `…/Renew` | `wst:RenewTarget` | A fresh token for the subject. |
| `…/Validate` | `wst:ValidateTarget` | `wst:Status` with `…/status/valid` when the target holds a token, and `…/status/invalid` when it is empty. |
| `…/Cancel` | `wst:CancelTarget` | `wst:RequestedTokenCancelled`. Refused in the 2004/04 namespace, which has no Cancel. |

```xml
<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew</wst:RequestType>
<wsp:AppliesTo>…</wsp:AppliesTo>
<wst:RenewTarget><saml:Assertion …>…</saml:Assertion></wst:RenewTarget>
```

Every operation authenticates the requester first, so each needs the same
credential an Issue does. `Validate` reports whether a token is *present*, not
whether it verifies, and `Cancel` recalls nothing already issued. In product
mode a `Renew` that issues needs a registered `AppliesTo`, like an `Issue`.
In development mode a `Renew` with no credential is issued for the subject the
`RenewTarget` names.

## Lifetime, JWT algorithm and certificate header

These are the settings on **Protocols → WS-Trust**:

| Setting | Default | What it does |
|---|---|---|
| `wstrust.tokenLifetimeMin` | `60` | The lifetime when the request carries no `wst:Lifetime`. |
| `wstrust.maxTokenLifetimeMin` | `1440` | A longer requested lifetime is cut to this, in both modes. |
| `wstrust.jwtAlgorithm` | `RS256` | The JWT's `alg`: `RS256`–`RS512`, `PS256`–`PS512`, `ES256`–`ES512` or `EdDSA`. |
| `wstrust.jwtCertificateHeader` | `x5u` | Whether a JWT names its signing chain: `x5u`, `x5c`, `both` or `none`. |

**Console:** change the value on **Protocols → WS-Trust** and click
**Save WS-Trust**. **Reset** on a row puts the default back.

**API:** `tests/saml_family_hardcoded.js` switches the algorithm like this:

```bash
api config/set '{"key":"wstrust.jwtAlgorithm","value":"ES256"}'
api config/reset '{"key":"wstrust.jwtAlgorithm"}'
```

A client asks for a lifetime with `wst:Lifetime`. The same test asks for a
year, and receives `wstrust.maxTokenLifetimeMin`. The RSTR's own
`wst:Lifetime` states what was issued:

```xml
<wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <wsu:Created>2026-01-01T00:00:00Z</wsu:Created>
  <wsu:Expires>2027-01-01T00:00:00Z</wsu:Expires>
</wst:Lifetime>
```

A SAML token's signature algorithm, clock skew and attributes are the shared
SAML settings on **Protocols → SAML**; see
[SAML 2.0 Web Browser SSO → The assertion settings every application inherits](saml2-sso.md#the-assertion-settings-every-application-inherits).

## An application as the requester

A middle tier that has no person entry can authenticate as its own
application. A `UsernameToken` whose `Username` names no person, and names an
application by identifier or client_id, is checked against that
application's client secrets. A person of the same name is always tried
first.

Taken from `sts_wstrust_own_token_chain.js`, which gives each tier a fresh
client secret instead of a service account.

**Console:** on the application's page, open **Credentials → Client secret**
and click **Generate a client secret** (or **Regenerate the client secret**).
Copy the value: it is shown once. That tab is drawn for an application
declared for OAuth 2.0, OpenID Connect, OpenID4VCI or mutual TLS. The test
jobs declare `oauth2` beside `wstrust` for this reason and for
[the JWT scopes](#scopes-in-a-jwt).

**API:**
```bash
api applications/regenerate-secret '{"application":"webapp1-wsot2"}'
# → {"ok":true,"clientSecret":"…", …}
```

`regenerate-secret` replaces every secret the application holds. The secret
then goes in the request as the password:

```xml
<wsse:UsernameToken>
  <wsse:Username>webapp1-wsot2</wsse:Username>
  <wsse:Password>…the client secret…</wsse:Password>
</wsse:UsernameToken>
```

A token issued to an application is about the application: a SAML NameID is
its identifier, and a JWT's `sub` is `urn:sts:client:<client_id>` in RFC 9700
mode (which product mode implies) and the bare client_id otherwise.

### A service account instead

The other chain jobs (`sts_wstrust_chain_delegation.js` and the rest) give
each requester a **service account** of the application's name. The
application entry is still what the delegation policy reads. The account
needs an owner while the realm's service-account policy says so, which is the
default. The jobs name the console's Admin Write group (`admin.writeGroup`,
default `admin-write`):

```bash
api users/create '{"username":"webapp1-wsdel","invent":false,
  "credential":"password","password":"<password>",
  "serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"webapp1-wsdel","sn":"webapp1-wsdel",
                "displayName":"webapp1-wsdel (web application)"}}'
```

In the console, tick **Service account** on **Users → New user**. See
[Service accounts](service-accounts.md#making-one).

## A token as the requester's credential

The `wsse:Security` header may carry a token this realm issued instead of a
`UsernameToken`: a SAML 2.0 or SAML 1.1 assertion as it came in the RSTR, or
the `wsse:BinarySecurityToken` a JWT came in. Put it in the header exactly as
the RSTR returned it.

In product mode the token must verify with this realm's key, be unexpired,
and be addressed to one of:
* an audience its holder's application registers. This is the token a tier
  asks for about itself, with its own identifier as the `AppliesTo`;
* this identity provider: its OAuth issuer, its SAML entityID, the issuer
  name `GET /sts` reports, or the `/sts` address.

`sts_wstrust_own_token_chain.js` does both steps at each tier: an `Issue`
with the application's client secret and its own identifier
(`https://webapp1-wsot2.example.com`) as the `AppliesTo`, then the next
request with the returned token in `wsse:Security`. Its matrix sends every
credential type with every `OnBehalfOf` token type and every issued type.

## OnBehalfOf: impersonation

`wst:OnBehalfOf` asks for a token **about** somebody else. The relying party
sees what reads as that person's own sign-in. Nobody is added to the
token's delegation chain.

The values are from `sts_wstrust_chain_impersonation.js`: four tiers,
`webapp1-wsimp`, `apigw1-wsimp`, `esb1-wsimp` and `sp1-wsimp`, each registered
as `https://<identifier>.example.com`. The person `bob_end_user-wsimp`
signs in to the web application, and each tier exchanges the token for the
next one.

**1. Register each tier.** The three requesters impersonate, and may reach
only the tier after them. The last tier needs only its identifiers.

**Console:** create each application as in
[Register the relying party](#register-the-relying-party), with
**Identifier** `webapp1-wsimp` and `https://webapp1-wsimp.example.com` added
to `wstrustAppliesTo` and `samlEntityId`. Then, on its page, open
**Configuration → Every protocol**. In the section
**Delegation / Impersonation**:
- **Add to** `appDelegationSemantics` the value `impersonation`.
- **Set** `appDefaultDelegationSemantics` to `impersonation`.
- **Add to** `appAllowedToDelegateTo` the value `apigw1-wsimp`.

Then click **Save Every protocol**.

**API:**
```bash
api applications/create '{"identifier":"webapp1-wsimp","name":"webapp1-wsimp (web application)",
  "protocols":["wstrust","saml2"],
  "fields":{"wstrustAppliesTo":["https://webapp1-wsimp.example.com"],
            "samlEntityId":["https://webapp1-wsimp.example.com"],
            "appDelegationSemantics":["impersonation"],
            "appDefaultDelegationSemantics":"impersonation",
            "appAllowedToDelegateTo":["apigw1-wsimp"]}}'
# apigw1-wsimp delegates to esb1-wsimp, esb1-wsimp to sp1-wsimp;
# sp1-wsimp has only the two identifier attributes.
```

The jobs also declare `saml11` and `oauth2`, for the claim settings and the
JWT scope. Each requester needs a credential: a service account or a client
secret, as [above](#an-application-as-the-requester).

**2. The person signs in.** The web application sends the person's
`UsernameToken` in an `Issue` whose `AppliesTo` is its own address,
`https://webapp1-wsimp.example.com`.

**3. Each tier exchanges it.** The requester authenticates as itself, puts
the token it holds inside `wst:OnBehalfOf`, and names the next tier:

```xml
<s:Header><wsse:Security>
  <wsse:UsernameToken><wsse:Username>webapp1-wsimp</wsse:Username>
    <wsse:Password>…</wsse:Password></wsse:UsernameToken>
</wsse:Security></s:Header>
<s:Body><wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
  <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
  <wsp:AppliesTo …><wsa:EndpointReference …>
    <wsa:Address>https://apigw1-wsimp.example.com</wsa:Address>
  </wsa:EndpointReference></wsp:AppliesTo>
  <wst:OnBehalfOf><saml:Assertion …>…bob's assertion…</saml:Assertion></wst:OnBehalfOf>
</wst:RequestSecurityToken></s:Body>
```

The token inside the element may be a SAML 2.0 or SAML 1.1 assertion, or a
JWT in its `wsse:BinarySecurityToken`, as this realm issued it.
`sts_wstrust_jwt_chain_impersonation.js` and
`sts_wstrust_saml11_chain_impersonation.js` run the same chain with JWTs and
with SAML 1.1 assertions.

## ActAs: delegation

`wst14:ActAs` asks for a token about the subject that also says the requester
is **acting**. Each hop adds its requester to the chain: a SAML 2.0
assertion gets one `del:Delegate` per party in its Delegation Restriction
condition, a JWT gets a nested `act` claim, and a SAML 1.1 assertion gets a
`delegates` attribute. [Delegation → WS-Trust](delegation.md#ws-trust-onbehalfof-and-actas)
shows each form.

Taken from `sts_wstrust_chain_delegation.js` (tag `wsdel`). Register the tiers
as for `OnBehalfOf`, but with `delegation`:

```bash
api applications/create '{"identifier":"webapp1-wsdel","name":"webapp1-wsdel (web application)",
  "protocols":["wstrust","saml2"],
  "fields":{"wstrustAppliesTo":["https://webapp1-wsdel.example.com"],
            "samlEntityId":["https://webapp1-wsdel.example.com"],
            "appDelegationSemantics":["delegation"],
            "appDefaultDelegationSemantics":"delegation",
            "appAllowedToDelegateTo":["apigw1-wsdel"]}}'
```

The request is the `OnBehalfOf` request with the element changed:

```xml
<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/ws-trust/200802">
  <saml:Assertion …>…</saml:Assertion>
</wst14:ActAs>
```

After three hops the assertion `sp1-wsdel` receives names
`webapp1-wsdel`, `apigw1-wsdel` and `esb1-wsdel`, least to most recent.
`sts_wstrust_jwt_chain_delegation.js` and
`sts_wstrust_saml11_chain_delegation.js` run it with JWTs and SAML 1.1.

### The delegation rules

The rules are the same for WS-Trust, RFC 8693 token exchange and Kerberos.
The requester is the actor. The token inside the element is the subject's,
and its audience is S. The `AppliesTo` is the target, R.

* **A delegation:** S must delegate to R (`appAllowedToDelegateTo` on S, or
  `appAllowedToActOnBehalfOf` on R). The actor must be S, R, or a party R
  accepts.
* **An impersonation:** the actor must reach R. That is,
  `appAllowedToDelegateTo` on the actor names R, or R accepts the actor.
* **Semantics:** an actor with an empty `appDelegationSemantics` may only
  delegate. Impersonation needs `impersonation` in the list.
* **A person as the actor** needs the role `delegation.actorRole` names
  (`DELEGATION_ACTOR` by default). An application needs no role.
  `sts_xml_schema_validation.js` sends an `OnBehalfOf` from a person without
  it, which product mode refuses.

The other way to allow a pair is on the target. The schema job sets it on R:

```bash
api applications/create '{"identifier":"https://wsrp-p-1.example.com/","name":"wsrp",
  "protocols":["wsfed","wstrust"],
  "fields":{"wsfedRealm":["https://wsrp-p-1.example.com/"],
            "wsfedReplyUrl":["https://wsrp-p-1.example.com/signin"],
            "wstrustAppliesTo":["https://wsrp-p-1.example.com/"],
            "appAllowedToActOnBehalfOf":["xsd-req-p-1"]}}'
```

Both elements in one request are refused in every mode, with
`wst:InvalidRequest`. A refusal is `wst:RequestFailed` in product mode. In
development mode the token is issued, and the act on **Monitoring →
Delegation** says what product mode would have refused. Every rule, the
protected subjects and the realm settings are on
[Delegation and impersonation](delegation.md). The live policy is
`GET /admin-api/delegation/policy`.

## An encrypted SAML 2.0 assertion

`POST /sts?encrypt=1` encrypts a SAML 2.0 assertion. It is not part of
WS-Trust. The key is the first `X509Certificate` in the request, which a
WS-Security signature's `KeyInfo` carries. The algorithms are
`saml2.encryptionAlgorithm` and `saml2.keyTransportAlgorithm`.

`sts_xml_schema_validation.js` puts the certificate in the security header:

```xml
<wsse:Security xmlns:wsse="…">
  <wsse:UsernameToken>…</wsse:UsernameToken>
  <ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Certificate>MIIC…</ds:X509Certificate>
  </ds:X509Data>
</wsse:Security>
```

```bash
curl -sk -X POST "$BASE/sts?encrypt=1" -H 'content-type: application/soap+xml' --data-binary @rst.xml
```

The answer carries an `EncryptedAssertion`. With no certificate, or one that
cannot be used, development mode returns the assertion unencrypted and logs
it, and product mode refuses the request.

## Related

* [WS-Trust](ws-trust.md): the behaviour, the faults and every setting.
* [Delegation and impersonation](delegation.md): every rule an `OnBehalfOf`
  or `ActAs` is decided by.
* [Configuring WS-Federation](configure-ws-federation.md), [Configuring SAML profiles](configure-saml.md)
  and [Configuring OAuth 2.0 grants](configure-oauth2-grants.md).
* [Service accounts](service-accounts.md), [Trust realms](trust-realms.md).
