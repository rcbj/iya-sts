---
title: "Configuring SAML 2.0 and SAML 1.1 profiles"
---

# Configuring SAML 2.0 and SAML 1.1 profiles

This page shows how to set up iya-sts, as a SAML identity provider, for each
SAML 2.0 binding and profile and each SAML 1.1 profile it supports. Each
recipe covers the service provider (SP) to register, the settings to change,
and what the SP sends. It is given twice: once as steps in the **admin
console** and once as **Management API** calls.

The values come from this repository's test jobs, and each recipe names the
job it is taken from. For SAML 2.0 these include the four interoperability
jobs, which run real Shibboleth, pysaml2, SimpleSAMLphp and Keycloak service
providers. How each profile *behaves* is covered on
[SAML 2.0 Web Browser SSO](saml2-sso.md) and [SAML 1.1](saml11.md), along
with every setting and its default. This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/saml2` | **Protocols → SAML → SAML 2.0 identity provider** | Register an SP, import one from MDQ, and change the `SAML` and `SAML 2.0` settings groups. |
| `/admin/saml2?sp=<entityID>` | click an SP's row | Upload its metadata, set its certificates and logout address, and find the IdP metadata URL to give it. |
| `/admin/saml11` | **Protocols → SAML → SAML 1.1 identity provider** | Register a relying party, and change the `SAML` and `SAML 1.1` settings groups. |
| `/admin/saml-assertions` | **Protocols → SAML → SAML assertions** | Change the signing, encryption, lifetime and NameID settings (the `SAML 2.0 assertions` and `SAML 1.1 assertions` groups). |
| `/admin/saml-attributes` | **Protocols → SAML → Custom SAML attributes** | Add attributes to every assertion. |
| `/admin/applications?application=<id>` | **Directory → Applications** | Set per-SP overrides with **Set** / **Add to** / **Remove from**. |

Each settings group is saved with its own **Save <group>** button, for example
**Save SAML 2.0**. The API equivalents are `POST /admin-api/config/set`,
`/config/set-many` and `/config/reset`.

**What development and product mode change.** Development mode answers any
SP, registers it the first time it appears (`saml2.autocreateApplications`
and `saml11.autocreateApplications`, both on by default), and sends a response
to whatever consumer address the request names. Product mode does none of
this:
* An SP must be registered. Its per-SP endpoints answer 404 otherwise.
* The consumer address must be one that is registered, matching exactly.
* Requests must be signed (`saml2.requireSignedAuthnRequests` is `auto`, which means on in product mode).
* Assertions are always signed.
* `rsa-1_5` and SHA-1 are refused.

---

# SAML 2.0

## Register the SP from its metadata (recommended)

When the SP's metadata is consumed, one save registers its assertion consumer
services (ACS) and their bindings, its logout endpoints, its signing and
encryption certificates, its NameID formats, and its `AuthnRequestsSigned` /
`WantAssertionsSigned` flags. All four interoperability jobs do this, through
`saml_peer_kit.js`.

**Console:**
1. On **SAML 2.0 identity provider**, in **Register a service provider**, enter the SP's **entityID** (for example `https://sp.example.com/saml`) and click **Register**.
2. Click the new row. Under **Its metadata**, paste the SP's metadata into **Upload a document** (or pick it under **or a file**), and click **Consume it**.
3. In **The endpoints it is configured from**, copy the **Metadata** URL. That is the IdP metadata to load into the SP.

**API:**
```bash
api applications/create '{"identifier":"https://sp.example.com/saml","name":"Example SP",
  "protocols":["saml2"],"fields":{}}'

jq -n --arg d "$(cat sp-metadata.xml)" '{sp:"https://sp.example.com/saml",document:$d}' |
  curl -sk -X POST "$BASE/admin-api/saml2/upload-metadata" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' --data-binary @-

# the IdP metadata to give the SP
curl -sk "$BASE/saml2/metadata/$(jq -rn --arg s https://sp.example.com/saml '$s|@uri')"
```

If you declare `saml2` with no `samlEntityId`, the identifier is used as the
entityID, which is why `"fields": {}` is enough. The interoperability jobs
first create a realm for the SP; the IdP's entityID there is that realm's
OAuth 2.0 issuer, which is not a setting (#523):

```bash
api realms/create '{"id":"sp1","domain":"sp1.example.net","name":"sp1"}'
```

**To have the metadata fetched from a URL instead of uploaded:** set
`samlSpMetadataUrl` on the application, then click **Refresh the metadata**
on its page (or **Refresh it now** on the SP's SAML 2.0 page). Through the
API:
```bash
api applications/set '{"application":"https://sp.example.com/saml",
  "attribute":"samlSpMetadataUrl","value":"https://sp.example.com/saml/metadata"}'
api applications/refresh-metadata '{"application":"https://sp.example.com/saml"}'
```
The fetch goes through the federation outbound policy: `https` only, with the
certificate verified in product mode.

**Stale metadata is refreshed in the background** while
`saml2.spMetadataRefresh` is on (the default). **Metadata that has expired**
refuses every request from that SP. To require the metadata itself to be
signed, set a trust anchor. `saml2.metadataTrustAnchors` does it for every
SP. For one SP, use **Metadata signing certificate → Set** on its page, or
the API:

```bash
api saml2/set-metadata-signing-certificate '{"sp":"https://sp.example.com/saml","value":"MIIC…"}'
```

## Register the SP by hand

Without metadata, register the addresses and certificates yourself. The
values here are from `sts_xml_schema_validation.js`.

**Console:**
1. On **Applications → New application ›**, enter the **Identifier** and tick **SAML 2.0**.
2. Fill in `samlEntityId`, **Where responses go back to** (the ACS) and **Where a sign-out goes** (the SLO address).
3. Click **Create the application**.
4. On `/admin/saml2?sp=…`, under **Its signing certificates**, paste the certificate into **Replace them with** and click **Set**.

**API:**
```bash
api applications/create '{"identifier":"https://sp-d.example.com/saml","name":"sp-d",
  "protocols":["saml2"],
  "fields":{"samlEntityId":["https://sp-d.example.com/saml"],
            "samlAssertionConsumerService":["https://sp-d.example.com/acs"],
            "samlSingleLogoutService":["https://sp-d.example.com/slo"],
            "samlSigningCertificate":["<PEM or base64 DER>"]}}'
```

Setting `samlSpMetadata` directly only stores the document; nothing in it is
used. To register from metadata, use **Consume it** or `upload-metadata`.
Once metadata has been consumed, the ACS must be one of its endpoints, in
every mode.

In development mode, a certificate that a signed request carries is recorded
as **observed**. It is trusted only once you click **Confirm — trust it** or
call `saml2/confirm-signing-certificate {"sp":…}`. Clicking **Discard** or
calling `…/discard-signing-certificate` drops it.

## Web Browser SSO: request bindings

The SP sends its `AuthnRequest` to `/saml2/sso` (or the per-SP
`/saml2/sso/<entityID or slug>`):

| Binding | How it is sent |
|---|---|
| HTTP-Redirect | `GET`, with `SAMLRequest`, and `SigAlg` / `Signature` in the query when signed |
| HTTP-POST | `POST`, with an enveloped signature |
| HTTP-POST-SimpleSign | `POST`, with `SigAlg` / `Signature` form fields |

The IdP metadata publishes all three as `SingleSignOnService`. HTTP-Artifact
is not supported for the request. No setting is needed.

Every request, in every mode, is checked as follows:
* `Destination` must be the endpoint the request arrived at, and a signed request must carry one.
* `IssueInstant` may be at most one minute in the future and no older than `saml2.requestTtlMin`.
* `Version` must be `2.0`.
* Each request ID is answered once.

The request the schema job builds is:

```xml
<samlp:AuthnRequest ID="_…" Version="2.0" IssueInstant="…"
    Destination="https://idp.example.com/saml2/sso"
    AssertionConsumerServiceURL="https://sp-d.example.com/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp-d.example.com/saml</saml:Issuer>
</samlp:AuthnRequest>
```

`ForceAuthn`, `IsPassive`, `RequestedAuthnContext` and `NameIDPolicy` are
honoured; [SAML 2.0 Web Browser SSO](saml2-sso.md) describes each one.

## Web Browser SSO: response bindings

The response is sent on the binding the request's `ProtocolBinding` names.
If the request instead gives an `AssertionConsumerServiceIndex`, the binding
of that consumed ACS endpoint is used. HTTP-POST is the default. The
Shibboleth job uses its indexes `1` (POST), `2` (SimpleSign) and `3`
(Artifact).

| Binding | What the SP receives |
|---|---|
| HTTP-POST | A self-submitting form with a signed Response. The assertion is signed too. |
| HTTP-Redirect | The Response in the query, signed with a query-string signature. A Response longer than `saml2.redirectWarnLength` (8000) is still sent, with a warning in the log. |
| HTTP-POST-SimpleSign | The Response with `SigAlg` / `Signature` form fields. |
| HTTP-Artifact | See [below](#http-artifact-and-artifact-resolution). |

**Signing** is set by `saml2.signResponse` and `saml2.signAssertion` (both
`true`), on **SAML assertions**. Turning off assertion signing is refused in
product mode. The per-SP overrides are `saml2SignResponse` and
`saml2SignAssertion` (`TRUE`/`FALSE`):

```bash
api applications/set '{"application":"https://sp.example.com/saml",
  "attribute":"saml2SignResponse","value":"FALSE"}'
```

## HTTP-Artifact and artifact resolution

The SP receives a `SAMLart` and resolves it over SOAP at `/saml2/ars` (or
`/saml2/ars/<sp>`). The per-SP IdP metadata publishes that endpoint as
`ArtifactResolutionService`. Each artifact can be resolved once, across the
whole cluster. It expires after `saml2.artifactTtlS` (300 s); the per-SP
override is `saml2ArtifactTtlS`.

**The resolver must authenticate.** It must be the SP the artifact was minted
for. Where signed requests are required (in product mode by default), it
must also do one of these:
* sign the `ArtifactResolve` with a key whose certificate is registered in `samlSigningCertificate`; or
* present one of those certificates as its TLS client certificate.

The schema job signs the request like this:

```
POST /saml2/ars
Content-Type: text/xml; charset=utf-8
SOAPAction: ""

<soap:Envelope><soap:Body>
  <samlp:ArtifactResolve ID="_…" Version="2.0" IssueInstant="…"
      Destination="https://idp.example.com/saml2/ars">
    <saml:Issuer>https://sp-d.example.com/saml</saml:Issuer>
    <samlp:Artifact>…</samlp:Artifact>
  </samlp:ArtifactResolve>          <!-- enveloped signature with the SP's key -->
</soap:Body></soap:Envelope>
```

The SP asks for this binding with
`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"`.

## IdP-initiated (unsolicited) SSO

Here the sign-in starts at the IdP, and the SP receives a Response with no
`InResponseTo`:

```
GET /saml2/unsolicited/<sp entityID or slug>?shire=<ACS URL>&target=<RelayState>[&binding=post|simplesign|artifact]
GET /saml2/unsolicited?providerId=<sp>&shire=<ACS URL>&target=<RelayState>
```

The Shibboleth job uses
`shire=https://sp.example.com/Shibboleth.sso/SAML2/POST&target=https://sp.example.com/peer/env`.
The Redirect binding is refused here. In product mode, the SP and the
`shire` must both be registered. To turn this off, set
`saml2.unsolicitedSso` (**Identity-provider-initiated sign-in**, on by
default) to `false`:

```bash
api config/set '{"key":"saml2.unsolicitedSso","value":false}'
```

## Signed AuthnRequests

`saml2.requireSignedAuthnRequests` (**Require signed requests from service
providers**) takes one of these values:
* `auto` (the default): required in product mode, not in development.
* `on`: required in every mode.
* `off`: not required.

An SP whose metadata says `AuthnRequestsSigned="true"` must sign whatever the
setting says. A signature that is present is always verified, and only
against `samlSigningCertificate`, never against the `KeyInfo` in the
message. The same rules apply to the logout messages and to the
`ArtifactResolve` caller.

```bash
api config/set '{"key":"saml2.requireSignedAuthnRequests","value":"on"}'
api saml2/set-signing-certificate '{"sp":"https://sp.example.com/saml","value":"MIIC…"}'
```

The pysaml2 job cycles the setting through `off`, `on` and `auto`, sending an
unsigned request each time. The request is accepted with `off` and refused
with `on`. With `auto` it is refused in product mode and accepted in
development.

## Encrypted assertions

To encrypt, set `saml2.encryptAssertion` (**Encrypt the assertion**) for every
SP, or `saml2EncryptAssertion` for one. **An SP whose consumed metadata
publishes a `use="encryption"` key is encrypted to in every mode** without
either setting.

Taken from `sts_saml_encryption.js`:

```bash
api applications/create '{"identifier":"https://enc-gcm.example.com","name":"enc-gcm",
  "protocols":["saml2"],
  "fields":{"samlAssertionConsumerService":["https://enc-gcm.example.com/acs"],
            "samlSigningCertificate":["<base64 DER>"],
            "samlEncryptionCertificate":"<base64 DER>",
            "saml2EncryptAssertion":"TRUE"}}'
api applications/set '{"application":"https://enc-gcm.example.com",
  "attribute":"saml2EncryptionAlgorithm","value":"aes128-gcm"}'
```

| Setting (and per-SP attribute) | Values |
|---|---|
| `saml2.encryptionAlgorithm` (`saml2EncryptionAlgorithm`) | `aes256-gcm` (the default), `aes128-gcm`, `aes256-cbc`, `aes128-cbc` |
| `saml2.keyTransportAlgorithm` (`saml2KeyTransportAlgorithm`) | `rsa-oaep-mgf1p` (the default), `rsa-oaep`, `rsa-1_5` (development only) |
| `saml2.encryptLogoutNameId` (`saml2EncryptLogoutNameId`) | encrypts the NameID in a LogoutRequest |

The key to encrypt to is looked for in this order:
1. `samlEncryptionCertificate`
2. a registered `samlSigningCertificate`
3. in development only, an observed certificate

If none is found, development mode sends the assertion unencrypted and logs a
warning, and product mode refuses the request.

## NameID formats

The IdP offers these formats: `unspecified`, `emailAddress`, `persistent`,
`transient`, `X509SubjectName` and `entity`. The default format is set by
`saml2.nameIdFormat` (**Default NameID format**); the per-SP override is
`saml2NameIdFormat`:

```bash
api applications/set '{"application":"https://sp.example.com/saml","attribute":"saml2NameIdFormat",
  "value":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}'
```

An SP asks for a format with `NameIDPolicy`. If its consumed metadata lists
`NameIDFormat`s, a request for any other format is answered with
`InvalidNameIDPolicy`. After changing the format on the SP, upload its
metadata again. The Keycloak job does this.

## Attributes

Every assertion carries `uid`, `mail`, `givenName`, `sn` and `displayName`,
both under those names and under their `urn:oid:` names. For example, mail is
`urn:oid:0.9.2342.19200300.100.1.3`. Product mode reads the values from the
person's directory entry, so create people with their attributes filled in:

```bash
api users/create '{"username":"alice","invent":false,"credential":"password","password":"<password>",
  "attributes":{"cn":"Alice Example","givenName":"Alice","sn":"Example",
                "displayName":"Alice Example","mail":"alice@example.com"}}'
```

**To add an attribute to every assertion**, use **Custom SAML attributes** →
**Add**, or the API. Values may use `${subject}` and `${audience}`:

```bash
api saml-attributes/add '{"set":"saml2","name":"department","value":"engineering"}'
```

**Attribute query.** `POST /saml2/aa` takes a signed `samlp:AttributeQuery`
in a SOAP envelope. It answers only for a subject that has a live session
with the asking SP.

## Single Logout

`/saml2/slo` (or `/saml2/slo/<sp>`) accepts a LogoutRequest or a
LogoutResponse on Redirect, POST or SimpleSign. The service looks for the
address to send its LogoutResponse to in this order:
1. the SLO endpoint in the SP's consumed metadata
2. `samlSingleLogoutService`
3. `saml2.defaultSingleLogoutService`
4. the last ACS used (a guess, which is logged)

**Console:** on `/admin/saml2?sp=…`, under **Where its LogoutResponse goes**,
enter the address in **Add one** and click **Add**.

**API:**
```bash
api saml2/set-logout-service '{"sp":"https://sp.example.com/saml","value":"https://sp.example.com/saml/slo"}'
```

`GET /saml2/slo` with no message shows an IdP-initiated sign-out page with a
link for each SP. A back-channel (SOAP) LogoutRequest ends the session named
by its `SessionIndex`; the Keycloak job sends one.

## Metadata Query (MDQ)

Point the realm at an MDQ responder, and an SP can be looked up by entityID.
The lookup URL is `<base>/entities/<percent-encoded entityID>`.

```bash
api config/set-many '{"saml2.mdqBaseUrl":"https://mdq.example.org/","federation.outbound":true}'
api saml2/mdq-import '{"sp":"https://sp.example.com/saml"}'
```

The console equivalent is **Import one from the Metadata Query responder** →
**entityID** → **Import**. In development mode, a request from an unknown SP
triggers a lookup. In product mode a lookup is never triggered by a request,
and refusals are listed in the **Metadata Query lookups refused** table. An
operator's import is refused unless `saml2.metadataTrustAnchors` is set, or
`saml2.mdqImportWithoutAnchors` is `true`. `sts_saml_unregistered.js` is the
job that covers this.

---

# SAML 1.1

The SAML 1.1 identity provider serves the Browser/POST and Browser/Artifact
profiles, Shibboleth 1.x's AuthnRequest, and a SOAP responder that also acts
as an attribute authority. Its endpoints are `/saml11/sso`,
`/saml11/responder` and `/saml11/metadata`, each with an optional
`/<relying party>` path segment.

## Register the relying party

Taken from `sts_saml11.js`.

**Console:**
1. On **Applications → New application ›**, enter the **Identifier** and tick **SAML 1.1**.
2. Fill in `samlEntityId` and **Where responses go back to** (the relying party's `shire`, which is `samlAssertionConsumerService`).
3. Click **Create the application**.
4. On its page, **Add to** `samlSigningCertificate` the relying party's certificate (base64 DER). That form has no field for the certificate.

(**SAML 1.1 identity provider → Register a relying party → Register**
creates the entry with only its identifier. In product mode, you must then
add `samlAssertionConsumerService` as well.)

**API:**
```bash
api applications/create '{"identifier":"urn:test:saml11:rp1","name":"SAML 1.1 relying party",
  "protocols":["saml11"],
  "fields":{"samlEntityId":["urn:test:saml11:rp1"],
            "samlAssertionConsumerService":["https://rp.example.com/saml11/acs"],
            "samlSigningCertificate":["<base64 DER>"]}}'
```

**Per-relying-party overrides.** Use **Set** on the application page, or the
**What SAML 1.1 issues for this relying party** section of the new-application
form. The attributes are `saml11AssertionLifetimeMin`, `saml11SignAssertion`,
`saml11SignResponse`, `saml11NameIdFormat` and `saml11ArtifactTtlS`.

**Settings** (on **SAML 1.1 identity provider** and **SAML assertions**):

| Setting | Default | What it does |
|---|---|---|
| `saml11.defaultProfile` | `post` | The profile used when the request names none: `post` or `artifact`. |
| `saml11.signAssertion` / `saml11.signResponse` | `true` | Signs the assertion / the Response. Turning either off is refused in product mode. |
| `saml11.nameIdFormat` | `…:1.1:nameid-format:unspecified` | The NameIdentifier format. |
| `saml11.artifactTtlS` | `300` | How long an artifact stays valid. |

`sts_saml11.js` flips each of these through `config/set-many` and restores
them with `config/reset`. For example:
```bash
api config/set-many '{"saml11.defaultProfile":"artifact"}'
api config/reset '{"key":"saml11.defaultProfile"}'
```

## Browser/POST

```
GET /saml11/sso?providerId=urn:test:saml11:rp1&shire=https://rp.example.com/saml11/acs
               &TARGET=https://rp.example.com/done?x=1[&profile=post]
```

After signing in, the person's browser posts a signed `samlp:Response` to the
`shire`. The Response has `Recipient` set to the `shire` and uses the
`cm:bearer` confirmation. `TARGET` is returned unchanged.

The profile is chosen by the `profile` parameter first. If there is none, the
binding of the registered `shire` decides. Failing both,
`saml11.defaultProfile` applies.

In product mode, the `shire` must exactly match a registered
`samlAssertionConsumerService`, and a request that names no registered
relying party is refused.

## Browser/Artifact and the SOAP responder

With `profile=artifact`, or a `shire` registered on the artifact binding, or
`saml11.defaultProfile` set to `artifact`, the relying party receives
`<shire>?SAMLart=…&TARGET=…`. It resolves that at `/saml11/responder` with a
signed request:

```xml
<!-- POST /saml11/responder, Content-Type: text/xml, inside a SOAP envelope -->
<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
    RequestID="_req…" MajorVersion="1" MinorVersion="1" IssueInstant="…">
  <ds:Signature>…</ds:Signature>            <!-- RSA-SHA256, exc-c14n, over RequestID -->
  <samlp:AssertionArtifact>…</samlp:AssertionArtifact>
</samlp:Request>
```

The request is signed with the key of the relying party's registered
`samlSigningCertificate`. Presenting that certificate as the TLS client
certificate works too. A signature is required wherever
`saml2.requireSignedAuthnRequests` requires one, which in product mode is
always, because that setting also governs SAML 1.1 callers. An artifact can
be resolved once.

## Attribute authority

The same responder answers `samlp:AttributeQuery` and
`samlp:AuthenticationQuery`:

```xml
<samlp:AttributeQuery Resource="urn:test:saml11:rp1">
  <saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject>
</samlp:AttributeQuery>
```

Development mode answers anybody. Product mode answers only when all three of
these hold:
* the query names a registered relying party, through `Resource` or the path;
* the caller authenticates as that relying party, by signing or with its TLS certificate;
* the subject has a live session that gave that relying party this NameIdentifier.

## Shibboleth 1.3 AuthnRequest

```
GET /saml11/sso?providerId=<SP entityID>&shire=<ACS>&target=<relay>&time=<epoch seconds>
```

The IdP metadata advertises this profile. Register the SP with its
`samlEntityId` and `samlAssertionConsumerService`, or upload its metadata as
in [SAML 2.0](#register-the-sp-from-its-metadata-recommended). Metadata is
consumed only when its `SPSSODescriptor` also names the SAML 2.0 protocol, as
a dual-protocol Shibboleth SP's does. For a pure SAML 1.1 relying party,
register the addresses by hand.

## NameIdentifier formats and attributes

SAML 1.1 has no NameIDPolicy. The format comes from `saml11.nameIdFormat` or
the per-relying-party `saml11NameIdFormat`:

| Format | NameIdentifier value |
|---|---|
| `emailAddress` | the person's mail |
| `X509SubjectName` | `CN=<username>` |
| `WindowsDomainQualifiedName` | `IYASTS\<username>` |
| `unspecified` | the username |

Custom attributes use the `saml11` set:
```bash
api saml-attributes/add '{"set":"saml11","name":"dept","value":"engineering"}'
```

SAML 1.1 tokens are also issued by WS-Federation's `wsignin1.0`; see
[WS-Federation](ws-federation.md).

## Related

* [SAML 2.0 Web Browser SSO](saml2-sso.md) and [SAML 1.1](saml11.md): the behaviour and every setting.
* [SAML assertions (RFC 7522)](saml-assertions.md): a SAML assertion exchanged at the OAuth token endpoint.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md) and [Configuring OpenID Connect flows](configure-oidc-flows.md).
