---
title: SAML 2.0 assertions
nav_order: 6
---

# SAML 2.0 assertions — RFC 7521 and RFC 7522

An application can authenticate at the token endpoint, or present an
authorization grant, with a **signed SAML 2.0 assertion** instead of a shared
secret. Both halves of the profile are implemented here.

**This is the same framework as [JWT assertions](jwt-assertions.md) and a
different profile of it.** RFC 7521 defines two request parameters, an error
vocabulary and a list of checks; RFC 7523 says the assertion is a JWT and RFC
7522 says it is a SAML 2.0 `<Assertion>`. If you already have a SAML identity
provider and an OAuth client, this is the profile that lets the first authorize
the second without either learning the other's format.

**They are separate implementations in this service, not one with a format
flag**, and so is the key material: an application holds **two key pairs**, one
per profile, and **neither can sign for the other**. That is the part most worth
knowing before you start, and it is the last section on this page.

## Two uses of one format, and they are not the same feature

| | Parameter | The `<Subject>` is | What it replaces |
|---|---|---|---|
| **§2.2 client authentication** | `client_assertion` + `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:saml2-bearer` | the CLIENT, necessarily (item 3B) | a client secret |
| **§2.1 an authorization grant** | `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer` + `assertion` | a PERSON | an authorization code |

The assertion is **base64url**-encoded in both (§2.1: "the padding bits are set
to zero"). Standard base64 is accepted too and logged as a warning — several
widely-deployed stacks send it, because the assertion is base64 everywhere else
in SAML, and refusing it would send you to look at your signature code.

### The `token_endpoint_auth_method` is this service's own name

RFC 7522 registers no value in the IANA *OAuth Token Endpoint Authentication
Methods* registry — it defines a `client_assertion_type` and stops. So a client
that authenticates this way is registered here with
`oauthTokenEndpointAuthMethod: "saml2_bearer"`, which is **a name this service
invented** and publishes in `token_endpoint_auth_methods_supported`. Nothing on
the wire is invented: the `client_assertion_type` is RFC 7522's URN exactly.

## The shortest path from nothing to a working grant

```bash
# 0. An /admin-api token. The management API takes one; see Configuration.
ADMIN=$(curl -sk -X POST https://localhost:8081/oauth2/token \
  -d grant_type=client_credentials -d client_id=sts-management-api \
  -d client_secret="$ADMIN_API_CLIENT_SECRET" \
  -d 'scope=admin:read admin:write' \
  --data-urlencode "resource=https://localhost:8081/admin-api" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
H="Authorization: Bearer $ADMIN"

# 1. A certificate authority for this realm. See PKI.
curl -sk -X POST https://localhost:8081/admin-api/pki/build \
  -H "$H" -H 'Content-Type: application/json' -d '{"organisation":"Acme"}'

# 2. An application, and a SAML signing key pair for it. `purpose` is the
#    whole difference from the JWT page: without it you get an RFC 7523 key
#    pair, which this profile will not accept.
curl -sk -X POST https://localhost:8081/admin-api/applications/create \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"identifier":"webapp1","protocols":["oauth2"],
       "fields":{"oauthClientId":"webapp1"}}'
curl -sk -X POST https://localhost:8081/admin-api/pki/issue \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"identifier":"webapp1","purpose":"saml"}'

# 3. Declare the <Issuer> it will assert under. THIS IS THE TRUST DECISION and
#    it is a separate act from holding a key. It is also a SEPARATE ATTRIBUTE
#    from the JWT profile's: declaring `oauthAssertionIssuer` does not declare
#    this one.
curl -sk -X POST https://localhost:8081/admin-api/applications/add \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"application":"webapp1","attribute":"oauthSamlAssertionIssuer",
       "value":"https://idp.acme.example"}'

# 4. The private key and the certificate are on the entry. Read them back.
curl -sk "https://localhost:8081/admin-api/applications?application=webapp1" \
  -H "$H" | python3 -c '
import sys,json
f=json.load(sys.stdin)["application"]["fields"]
open("saml-signer.pem","w").write(f["oauthSamlAssertionPrivateKey"])
open("saml-signer.crt","w").write(f["oauthSamlAssertionCertificate"])
print("thumbprint:", f["oauthSamlAssertionThumbprint"])'

# 5. Present it. ASSERTION is the base64url of the signed XML below.
curl -sk -X POST https://localhost:8081/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer \
  -d "assertion=$ASSERTION" -d scope='openid profile'
```

Alternatively, register a certificate you already hold — an existing identity
provider's signing certificate, PEM, several blocks in one value if you are
mid-rotation — on `oauthSamlAssertionSigningCertificate`, and skip steps 1, 2
and 4 entirely. That attribute and the issued one are both read.

## The assertion

```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_3f2a…" IssueInstant="2026-09-11T10:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.acme.example</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">…</ds:Signature>
  <saml:Subject>
    <saml:NameID>alice</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
          NotOnOrAfter="2026-09-11T10:02:00Z"
          Recipient="https://localhost:8081/oauth2/token"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2026-09-11T09:59:00Z"
                   NotOnOrAfter="2026-09-11T10:02:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://localhost:8081/oauth2/token</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="department">
      <saml:AttributeValue>engineering</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

The signature is an **enveloped XML Signature over the `<Assertion>` itself**,
placed after the `<Issuer>`, with the enveloped-signature and exclusive-c14n
transforms. A `<Response>` will not do: that is the browser profile's envelope,
and this profile takes the assertion out of it.

Every `<Attribute>` except `scope` is **carried onto the issued token** (item 8).
A single-valued attribute becomes a string claim and a multi-valued one stays a
list. `scope` is read as a constraint instead: the request's `scope` is narrowed
to what the assertion names and never widened.

## What is checked

All eleven items of §3, including the three most implementations get wrong.

| Item | What it says here |
|---|---|
| 1 `<Issuer>` | required, compared by **Simple String Comparison** (RFC 3986 §6.2.1) — no case folding, no trailing-slash tolerance |
| 2 `<AudienceRestriction>` | must name this authorization server. The token endpoint URL, the issuer identifier or the base URL all count. **There is no setting that turns this off** |
| 3 `<Subject>` | required; for client authentication the `<NameID>` MUST be the `client_id` |
| 4 an expiry | from the `<Conditions>` `NotOnOrAfter` **or** a `<SubjectConfirmationData>` one. **Either satisfies it** — half the implementations in the world require the first |
| 5 `<SubjectConfirmation>` | at least one `bearer` one; its `Recipient` is checked against the token endpoint; its `Address` is **read and reported and never enforced** (the item leaves it to the server, and a source address is a proxy's as often as a client's) |
| 6 the instants | both with `oauth2.clientAssertionSkewS`. **An expired `<SubjectConfirmation>` is DISCARDED and the others still considered** — the item's own words, "MUST reject the `<SubjectConfirmation>` (but MAY still use the rest of the Assertion)" — where an expired `<Conditions>` makes the whole assertion invalid. And the `ID` is remembered until the assertion expires, so a **replay is refused** |
| 7 `<AuthnStatement>` | carried and reported, never required. Its presence says the issuer authenticated the subject itself; its absence says the client is acting autonomously on their behalf, and the reports say which |
| 8 `<AttributeStatement>` | carried onto the token, as above |
| 9 the signature | **required**. An unsigned assertion is refused by name — it is this profile's `alg: "none"` |
| 10 encryption | a whole `<saml:EncryptedAssertion>`, and an `<EncryptedID>` inside the `<Subject>`, are decrypted with this realm's own key. **Encryption does not stand in for a signature**: a document that is only encrypted is still refused under item 9 |
| 11 the `<Conditions>` in full | `NotBefore`, and a `<Condition>` type this service does not understand makes the assertion **Invalid** per SAML core §2.5.1 rather than being ignored |

`oauth2.saml2BearerMaxLifetimeS` (300s) is item 6's invitation to refuse an
expiry "unreasonably far in the future", taken.

## The two things that are not permissive

This mock checks almost nothing. Two things here are real, and both default to
on.

### The `<Issuer>` must be declared

An assertion grant has **no browser, no password and no consent step anywhere in
it**, so the signature is the entire security of the grant. "Accept any signed
assertion" means anybody who can reach this port getting an access token as
anybody. So the `<Issuer>` must be on an application entry as
`oauthSamlAssertionIssuer`, and `oauth2.saml2BearerRequireRegisteredIssuer`
turns that off if you want to see what happens.

**It is a separate attribute from the JWT profile's.** Being trusted to assert
in one document format is not being trusted to assert in the other, and an
operator who wrote one attribute has not accidentally written two.

What is still permissive is everything around it: the `<Subject>` need not be
anybody this service has heard of — an assertion for a name nobody has ever used
mints that person exactly as typing it at the sign-in screen does — and the
scope is checked against nothing.

### A certificate that merely chains is not enough

**This is the one place this service is stricter for RFC 7522 than for RFC
7523, and there is no setting that changes it.**

A JWT assertion may carry its certificate chain in `x5c` and be accepted because
the chain reaches this realm's Root CA. A SAML assertion may not. A chain proves
the **realm** issued a key and says nothing about **which application** holds it
— so accepting one would let an application's own RFC 7523 leaf sign a SAML
assertion, which is exactly the crossing the two key pairs exist to prevent.

A certificate in `<ds:KeyInfo>` is used to *choose* among what is registered
against the asserting party and never as a key in its own right. One matching
nothing registered is refused by name.

## Two key pairs, one application

| | RFC 7523 | RFC 7522 |
|---|---|---|
| issued with | `purpose: "jwt"` (the default) | `purpose: "saml"` |
| declared on | `oauthAssertionIssuer` | `oauthSamlAssertionIssuer` |
| registered by hand on | `oauthJwks` | `oauthSamlAssertionSigningCertificate` |
| the key material | `oauthAssertionJwks`, `oauthAssertionCertificate`, `oauthAssertionCertificateChain`, `oauthAssertionPrivateKey` | `oauthSamlAssertionCertificate`, `oauthSamlAssertionCertificateChain`, `oauthSamlAssertionPrivateKey` |
| the key handle | `oauthAssertionKid` | `oauthSamlAssertionThumbprint` |
| a chain to the Root alone | accepted | **refused** |

**The two sets share no attribute name and no verifier reads the other's.** So:

* issuing one key pair leaves the other untouched;
* *Take the key pair off* on `/admin/pki` takes **one** profile's off and leaves
  the other working;
* an assertion signed with the wrong profile's key is refused even though the
  certificate is a real one this realm's own CA issued.

The SAML leaf also carries RFC 7522's grant-type URN as a second URI
`subjectAltName`, so a certificate read out of context says which profile it was
issued for.

`/admin/pki` shows **one row per application per profile**, because every fact
on such a row — the key handle, the expiry, the declared issuer, whether there
is a key pair to take off — is per profile.

## What it still does not do

* **Revocation is published and never consulted.** Since 2026-09-11 every
  certificate authority here signs a CRL and answers OCSP, and the certificate
  issued for this profile names both inside itself — but nothing in this
  service fetches a list when an assertion arrives, so a certificate revoked on
  `/admin/pki` still verifies an RFC 7522 assertion here. *Take the key pair
  off* is a third act again: it stops this service accepting what that key
  signs, puts nothing on any list, and does not stop the certificate chaining.
  See [What is not checked](what-is-not-checked.md).
* **The `Address` on a `<SubjectConfirmationData>` is not enforced**, for the
  reason in the table above.
* **A `<Response>` is not accepted**, nor is a SAML 1.1 assertion: RFC 7522 is
  the SAML 2.0 profile and says so, and this service refuses a `Version` that is
  not `2.0` by name rather than failing somewhere in the `<Conditions>`.
