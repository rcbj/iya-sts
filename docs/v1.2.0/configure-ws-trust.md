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
token carries: the realm's OAuth 2.0 issuer. `GET /sts/metadata` is the
WSDL, a port type for each version and WS-SecurityPolicy for the
credentials the running service accepts. `GET /sts/metadata/capabilities`
says which credential can be exchanged for which token type, and
`POST /sts/mex` serves both over WS-MetadataExchange. `GET /sts/cert` is the certificate a relying party verifies an
assertion with.

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

## A signed request as the requester's credential

A requester can sign the RST with a certificate instead of sending a
password (WS-Security 1.1, X.509 Token Profile 1.1). The signature covers the
SOAP `Body` and the `wsu:Timestamp`, and the certificate maps to one person
or application. [WS-Trust → A signed request](ws-trust.md#a-signed-request)
lists every check.

**1. Give the requester a message-signing certificate.** Either:

* issue one from the realm's message-signing Issuing CA. **Console:** open
  the person on **Users** or the application on **Applications**, then
  **Message-signing certificates**, choose a key algorithm and a file
  password, and download the PKCS#12. **API:**
  ```bash
  api applications/issue-signing-certificate \
    '{"application":"esb1","keyAlg":"rsa-2048","password":"<file password>"}'
  api users/issue-signing-certificate \
    '{"username":"alice","keyAlg":"ec-p256","password":"<file password>"}'
  ```
  The reply is the only copy of the private key. A holder may have
  `pki.messageSigningCertificateMax` (5) valid ones; revoke one with
  `revoke-signing-certificate`;
* or store a certificate from your own authority on the entry, as for a
  [TLS client certificate](tls.md#a-certificate-from-an-outside-certificate-authority)
  (`users/add-certificate`, or the person's **Certificates** section). Its key
  usage must include `digitalSignature`.

**2. Sign the request.** Configure the client's WS-Security stack to add a
`wsu:Timestamp` with `Created` and `Expires`, to sign the Body and the
Timestamp with exclusive canonicalization and RSA-SHA256 or ECDSA-SHA256, and
to put the certificate in a `wsse:BinarySecurityToken` referenced from the
signature's `KeyInfo`. The header looks like this:

```xml
<wsse:Security>
  <wsu:Timestamp wsu:Id="ts">
    <wsu:Created>2026-10-28T17:00:00Z</wsu:Created>
    <wsu:Expires>2026-10-28T17:05:00Z</wsu:Expires>
  </wsu:Timestamp>
  <wsse:BinarySecurityToken wsu:Id="x509" ValueType="…#X509v3"
      EncodingType="…#Base64Binary">MIIC…</wsse:BinarySecurityToken>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod
          Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod
          Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#body">…</ds:Reference>
      <ds:Reference URI="#ts">…</ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>…</ds:SignatureValue>
    <ds:KeyInfo><wsse:SecurityTokenReference>
      <wsse:Reference URI="#x509" ValueType="…#X509v3"/>
    </wsse:SecurityTokenReference></ds:KeyInfo>
  </ds:Signature>
</wsse:Security>
```

with `<s:Body wsu:Id="body">` around the RST. A certificate this realm issued
may instead be named by a `#ThumbprintSHA1` or `#X509SubjectKeyIdentifier`
`KeyIdentifier`, or an `X509IssuerSerial`, with no BinarySecurityToken.

**3. Send it once.** In product a signed request is accepted once: send each
request with a new Timestamp. A UsernameToken may travel beside the signature
if your stack adds one, but it must name the same person or application.

`tests/wstrust_message_signature.js` signs requests this way, with keys made
at run time, and asserts each refusal.

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

## An encrypted response

XML Encryption of a WS-Trust response is per application, and it is off
until that application turns it on. The algorithms are `wstrust.encryptionAlgorithm` and
`wstrust.keyTransportAlgorithm`, overridable on the application. They are
not the SAML assertion settings.

Set the response switch and name the issued SAML 2.0 assertion. The same
shape names any other element, including a SOAP header or the body. The
expression is one value of `wstrustEncryptResponseElements`:

```
//*[local-name()='Assertion' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']
```

```bash
api applications/set '{"application":"https://wsrp.example/","attribute":"wstrustEncryptResponse","value":"true"}'
api applications/add '{"application":"https://wsrp.example/","attribute":"wstrustEncryptResponseElements","value":"<the expression above>"}'
```

A request or a response that does not match the configured map stops
processing and returns a fault. Nothing is issued, and the clear response
is not sent. The fault stays in the clear, in both modes.

The recipient is one certificate, and a step that cannot be used does not
fall through:

1. `wstrustEncryptionCertificate` on the application, base64 DER or PEM,
   when it is set. A value that is not a readable certificate is
   `wst:RequestFailed` (`STS-WSTRUST-0077`).
2. Otherwise `wstrustResponseRecipientXPath`: the first
   `ds:X509Certificate` or `#X509v3` `BinarySecurityToken` that expression
   selects. Nothing, or an element that is not one of those, is
   `wst:InvalidRequest` (`STS-WSTRUST-0076`). A certificate element whose
   text is not a certificate is `STS-WSTRUST-0077`.
3. Otherwise the first signer certificate element the request's WS-Security
   signature names: the `#X509v3` `BinarySecurityToken` the reference
   points at, or a `ds:X509Certificate` in that signature's `KeyInfo`.

A thumbprint, Subject Key Identifier or issuer and serial is not a
recipient. A certificate inside an assertion is not one either. With the
switch on and no recipient, the fault is `STS-WSTRUST-0076`. An empty map,
an expression that matches nothing, or a cipher that fails is
`STS-WSTRUST-0077`.

`wstrustResponseRecipientXPath` may select only a certificate the
request's accepted WS-Security signature vouches for: the signer's own
`BinarySecurityToken`, or a certificate inside a part the signature
references. Anything else, and anything in an unsigned request, is
`wst:InvalidRequest` (`STS-WSTRUST-0081`). For a requester that does not
sign, set `wstrustEncryptionCertificate` instead.

```bash
curl -sk -X POST "$BASE/sts" -H 'content-type: application/soap+xml' --data-binary @rst.xml
```

The answer carries `xenc:EncryptedData`, not an `EncryptedAssertion`. A
message-signing certificate permits `digitalSignature` only, so under
paranoid PKI mode (on in product) the request is refused once that
certificate has been found: encryption needs `keyEncipherment` or
`keyAgreement`. Set `wstrustEncryptionCertificate` to a certificate that
may encrypt. A certificate with no `keyUsage` may encrypt (RFC 5280).

## An encrypted request

Encrypting a request is off until it is turned on. With
`wstrust.acceptEncryptedElements` (the application's
`wstrustAcceptEncryptedElements`) on, a client may encrypt any header or the
Body to this realm's XML Encryption certificate. That includes the shapes WSS4J, WCF and
Metro send under the WSDL's `sp:AsymmetricBinding`
([the metadata document](ws-trust.md#the-metadata-document)): the Body's
content, a WS-Security 1.1 `EncryptedHeader`, and one `EncryptedKey` in the
security header listing them. The signature may be made before or after
the encryption.

```bash
api applications/set '{"application":"https://wsrp.example/","attribute":"wstrustAcceptEncryptedElements","value":"true"}'
```

Off, ciphertext is accepted only where the application's
`wstrustEncryptRequestElements` names it, and anything else is
`wst:InvalidRequest` (`STS-WSTRUST-0080`). The WSDL offers request
encryption only while the service-wide setting is on: under
`sp:Basic256Sha256` where AES-256-CBC is read (never in product), and on
the `IyaSuite` ports, with AES-256-GCM and RSA-OAEP over SHA-256, in both
modes.

The request map makes encryption required.
`wstrustEncryptRequest` and `wstrustEncryptRequestElements` require each
named element to arrive encrypted. An empty map, a clear match or a miss is
`wsse:FailedCheck` (`STS-WSTRUST-0075`) and processing stops, as is a
ciphertext that will not open whether or not the switch is on. An expression outside the
subset this service evaluates — `/`, `//`, `*`, an element name,
`prefix:local`, `|`, and `local-name()`, `namespace-uri()` and `@attr`
joined by `and` — is `wst:RequestFailed` (`STS-WSTRUST-0079`).

### The certificate a client encrypts to

The client needs this realm's XML Encryption certificate before it sends an
encrypted request. Where it gets it depends on
`wstrust.advertiseEndpointIdentity`:

* **Off, the default.** The WSDL names no certificate. Fetch it and
  configure the client with it:

  ```bash
  curl -sk "$BASE/saml2/metadata" > idp.xml   # the KeyDescriptor use="encryption"
  curl -sk "$BASE/sts/cert" > sts.pem          # the same certificate while
                                               # saml.signatureAlgorithm is RSA
  ```

  The first `md:KeyDescriptor use="encryption"` of `/saml2/metadata` is
  always the right certificate. `/sts/cert` is the XML signing certificate, and is the
  same one only while `saml.signatureAlgorithm` is an RSA algorithm (the
  default).
* **On.** Every port of `/sts/metadata` also carries the certificate as a
  `wsa:EndpointReference/wsid:Identity`. WCF and the toolkits that copy it
  read it from there. The element is from WS-AddressingIdentity, a
  Microsoft specification that was never standardised, which is why it is
  off by default.

  ```bash
  api config/set '{"key":"wstrust.advertiseEndpointIdentity","value":true}'
  ```

In development mode the key is regenerated on every start, so fetch the
certificate again after a restart. In product mode it changes when the
`xml` key rotates. The setting changes only what the WSDL says; which
ciphertext is accepted is still the settings above.

### An application's own decryption key pair

An application may hold a decryption key pair of its own. A request for that
application is then encrypted to the application's certificate and not to
the realm's, so a client of one application never holds the certificate that
opens another's requests, and a key that leaks exposes one application's
traffic. Give it one in either of two ways.

**Issue one from the realm's certificate authority.** The realm needs a
certificate authority first (**Protocols → PKI**, or `api pki/build`). The
certificate is issued with the `key-encipherment` profile: `keyEncipherment`
for an RSA key, `keyAgreement` for an EC key, never `digitalSignature`. Its
subject is the realm's standard name with `CN=<application>-encrypt`, for
example `CN=esb1-encrypt, O=iya-sts`, and its subjectAltName is
`urn:sts:application:<application>`.

* **Console:** **Directory → Applications**, open the application, the
  **Credentials** tab, **WS-Trust decryption key pair**. Choose `rsa-3072`
  (the default) or `ec-p256` and press **Issue a key pair**.
* **API:**
  ```bash
  api applications/issue-wstrust-decryption-key \
    '{"application":"esb1","keyAlg":"rsa-3072"}'
  ```

**Or upload a key pair you made.** Paste one PEM certificate and its
unencrypted PEM private key (PKCS#8, PKCS#1 or SEC 1; PKCS#12 is not taken).
The key must be the certificate's, RSA of at least 2048 bits or EC on P-256,
P-384 or P-521, and the certificate's key usage, if it has one, must include
`keyEncipherment` (RSA) or `keyAgreement` (EC).

```bash
api applications/upload-wstrust-decryption-key "$(jq -n \
  --arg c "$(cat esb1-encrypt.pem)" --arg k "$(cat esb1-encrypt.key)" \
  '{application:"esb1",certificate:$c,privateKey:$k}')"
```

| Refused | Code |
|---|---|
| Not one PEM certificate, or a private key that is encrypted or does not parse | `STS-ADMIN-0946` |
| A private key that is not the certificate's | `STS-ADMIN-0947` |
| A key that is not RSA of 2048 bits or more, or EC on P-256, P-384 or P-521 | `STS-ADMIN-0948` |
| A key usage without `keyEncipherment` (RSA) or `keyAgreement` (EC), or an expired certificate | `STS-ADMIN-0949` |
| A certificate another application holds, or an application that does not exist | `STS-ADMIN-0950` |

**Give the client the certificate.** The private key never leaves this
service: no page, API answer or directory read carries it, and where keys
persist it is sealed on the application's entry. The certificate is public.
Download it from the same section of the console (**Download the
certificate (PEM)**), or read it from the API:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$BASE/admin-api/applications?application=esb1" \
  | jq -r '.credentials.wstrustDecryption.certificatePem' > esb1-encrypt.pem
```

The section shows the subject, the issuer, the serial, the validity and two
thumbprints: the SHA-256 one, and the `#ThumbprintSHA1` a WSS4J or WCF client
names the certificate by. The realm's WSDL is one document for the whole
realm, so it never names an application's certificate, even with
`wstrust.advertiseEndpointIdentity` on: configure the client with the
downloaded certificate out of band.

**How a request is opened.** The key is chosen by the recipient the
`EncryptedKey` names: the certificate itself, its `#ThumbprintSHA1` or
`#X509SubjectKeyIdentifier` `KeyIdentifier`, or its `X509IssuerSerial`. So a
request whose `AppliesTo` is itself inside the ciphertext still opens. The
opened request is then held to the key that opened it:

* ciphertext opened with an application's key in a request for any other
  application is `wsse:FailedCheck` (`STS-WSTRUST-0082`);
* a request for an application that holds its own key, encrypted to the
  realm's certificate, is `wsse:FailedCheck` (`STS-WSTRUST-0083`).

An application with no key pair of its own is unchanged: its requests are
encrypted to the realm's certificate. What a request may encrypt is still the
settings above, and the certificate a response is encrypted to is still the
requester's (*An encrypted response*).

**Remove it** with **Remove the key pair**, or
`api applications/remove-wstrust-decryption-key '{"application":"esb1"}'`.
Requests for the application are then opened with the realm's key again.
Removing is not revocation: a certificate issued here stays valid until it
expires, and is on no revocation list.

## Require a signed request

To refuse a request for an application unless it carries a WS-Security
signature, turn on `wstrustSignRequest`. With no map, the signature must
cover the Body, which every accepted signature does. To require the headers
signed too, add the Header preset to `wstrustSignRequestElements`, or tick
its **Header** box under *Message protection in the console*, below, and
press **Save**:

```bash
api applications/set '{"application":"https://wsrp.example/","attribute":"wstrustSignRequest","value":"true"}'
api applications/add '{"application":"https://wsrp.example/","attribute":"wstrustSignRequestElements","value":"/soap11:Envelope/soap11:Header/*[not(local-name()='"'"'Security'"'"' and namespace-uri()='"'"'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'"'"')] | /soap12:Envelope/soap12:Header/*[not(local-name()='"'"'Security'"'"' and namespace-uri()='"'"'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'"'"')]"}'
```

A request with no accepted signature is `wsse:FailedCheck`
(`STS-WSTRUST-0084`). A header block the signature does not reference is
`wsse:FailedCheck` (`STS-WSTRUST-0085`). So is an expression that matches
nothing: a request that carries no header blocks fails the Header preset.
What the signature is and whose it is are unchanged
(*A signed request as the requester's credential*).

## A signed response

To have an application's answers signed, turn on `wstrustSignResponse`:

```bash
api applications/set '{"application":"https://wsrp.example/","attribute":"wstrustSignResponse","value":"true"}'
```

Each answer then carries a `wsu:Timestamp`, a `BinarySecurityToken` holding
the realm's XML signing certificate (the one its SAML assertions are
signed with, for `saml.signatureAlgorithm`), and a
`ds:Signature` over the Timestamp and the Body. A client verifies it with
that certificate, which it should already trust as the realm's signer. To
sign the headers as well, add the Header preset to
`wstrustSignResponseElements` (its **Header** box); the map
then names what is signed beside the Timestamp, so keep the Body preset in it
too.

With response encryption also on, the answer is signed and then encrypted.
Set `wstrustResponseProtectionOrder` to `encrypt-then-sign` for the other
order, or `wstrustEncryptSignature` to `true` to encrypt the signature as
well. An expression that matches nothing is `wst:RequestFailed`
(`STS-WSTRUST-0086`) and the token is not sent.

The WSDL is one document per realm. Turning on the realm's
`wstrust.signResponse` puts `sp:IncludeTimestamp` into its binding, so a
WS-SecurityPolicy client expects every answer signed; an application that
signs while the realm does not is configured on the client by hand.

## Message protection in the console

On the application's page, **Configuration → WS-Trust** has two views. Choose
one with the **Simplified view** and **Advanced view** buttons at the top
of the form.

* **Simplified view** shows **General** first, with the fields that have
  nothing to do with signing or encrypting a message (`wstrustAppliesTo`
  and `wstrustJwtScope`), and then the **Message protection** table.
* **Advanced view** shows General, the Message protection table, and then
  every other field, in these sections:

| Section | Request message processing | Response message processing |
|---|---|---|
| **General** | `wstrustAppliesTo`, `wstrustJwtScope` | |
| **Message encryption** | `wstrustEncryptRequest`, `wstrustAcceptEncryptedElements`, `wstrustEncryptRequestElements` | `wstrustEncryptResponse`, `wstrustEncryptResponseElements`, `wstrustEncryptionAlgorithm`, `wstrustKeyTransportAlgorithm`, `wstrustEncryptionCertificate`, `wstrustResponseRecipientXPath`, `wstrustEncryptSignature` |
| **Message signing** | `wstrustSignRequest`, `wstrustSignRequestElements` | `wstrustSignResponse`, `wstrustSignResponseElements`, `wstrustResponseProtectionOrder` |

The application's decryption key pair is on its **Credentials** tab.

### The Message protection table

The table has a **Body** box and a **Header** box for each of the four XPath
maps: encryption of the request and of the response
(`wstrustEncryptRequestElements`, `wstrustEncryptResponseElements`) and
signing of the request and of the response (`wstrustSignRequestElements`,
`wstrustSignResponseElements`). Ticking a box **replaces** the map's
expressions with a fixed set: with Body or Header ticked, the map holds the
sets of the ticked boxes and nothing else. The expressions the map held
before are remembered while the page is open, and unticking the map's last
box puts them back. After a reload nothing is remembered, and unticking a
box takes out only that box's expressions. **Save** stores the map.

The boxes store nothing of their own. A box is ticked whenever its map holds
all of its expressions, including expressions typed by hand or set through
the Management API:

| Box | Encryption map | Signing map |
|---|---|---|
| Body | `/soap11:Envelope/soap11:Body/* \| /soap12:Envelope/soap12:Body/*` (the Body's content) | `/soap11:Envelope/soap11:Body \| /soap12:Envelope/soap12:Body` |
| Header | every header block but `wsse:Security`, in SOAP 1.1 and 1.2 | the same |

A map is read only while its switch is on. The switch is the attribute shown
in the table's last column, or the realm's setting when that attribute is
empty.

### The XPath builder

Each field that holds XPath expressions has an **XPath builder…** button in
its card: `wstrustEncryptRequestElements`, `wstrustEncryptResponseElements`,
`wstrustResponseRecipientXPath`, `wstrustSignRequestElements` and
`wstrustSignResponseElements`. It opens the builder in a window over the
page, for that field. The builder makes a list of expressions for you:

1. Paste a sample SOAP message into its box. A sample Issue request is there
   to start with.
2. Click **Show the elements**, then click an element name. The builder
   writes an absolute expression for that element, using this service's
   prefixes (`soap11`, `soap12`, `wst`, `wsse`, `wsu`, `wsa`, `saml`, …)
   and not the sample's own. It marks every element of the sample the
   expression matches. An element in a namespace this service has no prefix
   for is written as `*[local-name()='…' and namespace-uri()='…']`.
3. Click **Add to the list**. Repeat steps 2 and 3 for each element you
   want. The bin beside an expression takes it off the list.
4. Click **Add the list to the field**. A map gets each expression it does
   not already hold as a new value. `wstrustResponseRecipientXPath` holds
   one expression, so for that field the list must hold exactly one, and it
   replaces the field's value. The builder closes, and the field's card
   says what was added.
5. Click **Save** on the form.

The sample is parsed in your browser and never sent. Close the builder with
**Close**, the **×** or the Esc key. The list stays until you add it or
open the builder for another field.

## Related

* [WS-Trust](ws-trust.md): the behaviour, the faults and every setting.
* [Delegation and impersonation](delegation.md): every rule an `OnBehalfOf`
  or `ActAs` is decided by.
* [Configuring WS-Federation](configure-ws-federation.md), [Configuring SAML profiles](configure-saml.md)
  and [Configuring OAuth 2.0 grants](configure-oauth2-grants.md).
* [Service accounts](service-accounts.md), [Trust realms](trust-realms.md).
