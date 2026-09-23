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
| 6 the instants | both with `oauth2.clientAssertionSkewS`. **An expired `<SubjectConfirmation>` is DISCARDED and the others still considered** — the item's own words, "MUST reject the `<SubjectConfirmation>` (but MAY still use the rest of the Assertion)" — where an expired `<Conditions>` makes the whole assertion invalid. And the `Issuer` and `ID` are remembered until the assertion expires, so a **replay is refused** — in the same used-assertion history the JWT profile uses: once, ever, across both sections, surviving a restart in the `ldif` and `postgres` stores, and spent only when the token request issues tokens (see [JWT assertions](jwt-assertions.md) for what "used" means) |
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

### The registered certificate's whole chain is validated at every use

Since 2026-09-13, in both modes. The certificate that verified the signature
counts only while its trust chain holds: every link verifies and is in date,
every issuer is a CA permitted to sign certificates within its path length, the
certificate itself is not a CA and may sign, and the path ends at **this
realm's** certificate authority or at a self-signed root registered with it.

* A certificate this realm issued may be registered alone.
* One from another authority must be registered with its whole chain. On
  `oauthSamlAssertionSigningCertificate` the chain goes **in the same value**,
  as further PEM blocks after the certificate; an uploaded certificate keeps its
  chain in `oauthSamlAssertionCertificateChain`.
* A self-signed certificate registered by value is its own whole chain — its
  self-signature and validity are checked, and a `cA=TRUE` on it is not refused.

A refusal is `invalid_grant` (`invalid_client` for client authentication),
recorded as `STS-PKI-0156` to `STS-PKI-0161`. Until that date the chain was
checked when a certificate was registered and never again.

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

## A person can be the issuer too (2026-09-13)

A person may hold an RFC 7522 key pair on their own directory entry —
`stsSamlAssertionCertificate`, its chain, `stsSamlAssertionThumbprint` and a
sealed `stsSamlAssertionPrivateKey`, a set sharing no name with the JWT one — and
sign a SAML assertion **about themselves**: the `<Issuer>` is their username (or
`stsSamlAssertionIssuer`, if one is declared) and the `<Subject>` must name the
same person. One naming anybody else is refused `invalid_grant` with a sentence
saying why; a party that may assert about other people is an application with
`oauthSamlAssertionIssuer` declared on it.

The key pair is issued, uploaded or taken off from the **Credentials** section of
`/admin/users?user=<name>`, or through `/admin-api/pki/issue`,
`/pki/upload-certificate` and `/pki/revoke` with `target: "person"` and
`purpose: "saml"`. As for an application, the verifier checks only the
certificate registered on the person's entry — a chain to the Root alone is still
refused, and the person's RFC 7523 key does not sign for this profile.

**A person can issue it themselves**, on `/portal/signing-key`: the RFC 7522 card
has its own *Generate* and *Take off*, the private key is shown once with the
`<Issuer>`, `<Subject>`, audience and certificate thumbprint to use, and taking
it off leaves their RFC 7523 key working. `pki.personSelfService` turns the
self-service door off for both profiles; it takes away no key already held.

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.saml2BearerGrant` | `STS_OAUTH2_SAML2_BEARER_GRANT` | `true` | yes | Whether the token endpoint performs the §2.1 grant; the metadata advertises it only while it is on. It does **not** affect §2.2 client authentication. |
| `oauth2.saml2BearerRequireRegisteredIssuer` | `STS_OAUTH2_SAML2_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Whether a §2.1 assertion whose `<Issuer>` no application declares on `oauthSamlAssertionIssuer` is refused. Turning it off does not make the grant accept an unsigned assertion or a merely chaining certificate. |
| `oauth2.saml2BearerMaxLifetimeS` | `STS_OAUTH2_SAML2_BEARER_MAX_LIFETIME_S` | `300` | yes | The most seconds between `IssueInstant` and the expiry (the `<Conditions>` one, else the `<SubjectConfirmationData>` one). Zero switches the check off. |
| `oauth2.clientAssertionSkewS` | `STS_OAUTH2_CLIENT_ASSERTION_SKEW_S` | `60` | yes | How far out the asserting party's clock may be, for both instants of item 6, and how long past expiry an assertion is remembered. Shared with the JWT profile. |
| `oauth2.assertionReplayCacheSize` | `STS_OAUTH2_ASSERTION_REPLAY_CACHE_SIZE` | `1000` | yes | Unexpired rows the used-assertion history holds per realm, for RFC 7522 and RFC 7523 together; a full history refuses the next assertion rather than forgetting a live one. |
| `pki.personSelfService` | `STS_PKI_PERSON_SELF_SERVICE` | `true` | yes | Whether `/portal/signing-key` lets a person issue their own key pair, for both profiles; off takes away no key already held. |
| `pki.personSelfServicePerIdentity` | `STS_PKI_PERSON_SELF_SERVICE_PER_IDENTITY` | `5` | yes | How often one person may press Generate there in a `security.rateLimitWindowS` window. |
| `pki.personSelfServicePerAddress` | `STS_PKI_PERSON_SELF_SERVICE_PER_ADDRESS` | `5` | yes | The same limit counted per client address. |

Whether the registered certificate is checked for revocation is
`pki.revocationCheck`, and the hierarchy that issues the key pairs is
configured on [PKI](pki.md#configuration). See
[Configuration](configuration.md) for how a value resolves and where it is
changed — the console page, or `POST /admin-api/config/set`.

## Design decisions

* **RFC 7522 is a second implementation, not a format flag on RFC 7523.** The
  framework is shared and nothing else is: an XML document with an enveloped
  signature, `<Conditions>` and a `Recipient` has checks a JWT has no
  equivalent for, and a shared implementation would be a switch in every one.
* **Its two sections are one verification.** XML Signature over a shared
  secret is something no SAML implementation emits, so the only difference
  between client authentication and the grant is what the `<Subject>` has to
  be.
* **The `<Issuer>` must be declared, on an attribute of its own.** Being
  trusted to assert in one format is not being trusted in the other — see
  [above](#the-issuer-must-be-declared).
* **A certificate that merely chains to the realm is not enough.** A chain is
  evidence about the realm, not the application, so the verifier uses only a
  certificate registered under the RFC 7522 attributes. This is the one place
  the service is stricter than for RFC 7523 — see
  [above](#a-certificate-that-merely-chains-is-not-enough).
* **Two key pairs per application, sharing no attribute.** Neither can sign for
  the other profile, and taking one off leaves the other working — see
  [above](#two-key-pairs-one-application).
* **The three lenient readings of section 3 are implemented as written.** An
  expiry on either element satisfies item 4, an expired
  `<SubjectConfirmation>` is discarded rather than voiding the assertion (item
  6), and an unknown `<Condition>` makes the assertion invalid (item 11) — see
  [above](#what-is-checked).
* **A signature is required, and encryption does not stand in for one.** An
  unsigned assertion is refused by name — it is this profile's `alg: "none"`.
* **One replay history with the JWT profile.** An assertion is accepted once,
  ever, survives a restart in the persisted stores, and is spent only when
  tokens are issued.
* **`saml2_bearer` is published as this service's own name.** RFC 7522
  registers no token endpoint authentication method, so the name is invented
  and advertised in the metadata; nothing on the wire is invented.
* **A person may be the issuer, only about themselves.** A party that may
  assert about other people is an application an operator declared — see
  [above](#a-person-can-be-the-issuer-too-2026-09-13).
* **Standard base64 is accepted and logged.** RFC 7522 asks for base64url, but
  widely deployed stacks send base64, and refusing it would send a client
  author to look at their signature code.

## What it still does not do

* ~~**Revocation is published and never consulted.**~~ **Consulted since
  2026-09-12**: the registered certificate that verified an assertion is checked
  for revocation after its chain (`STS-PKI-0129`). *Take the key pair off* is a
  third act again: it stops this service accepting what that key signs, puts
  nothing on any list, and does not stop the certificate chaining. See
  [What is not checked](what-is-not-checked.md).
* **The `Address` on a `<SubjectConfirmationData>` is not enforced**, for the
  reason in the table above.
* **A `<Response>` is not accepted**, nor is a SAML 1.1 assertion: RFC 7522 is
  the SAML 2.0 profile and says so, and this service refuses a `Version` that is
  not `2.0` by name rather than failing somewhere in the `<Conditions>`.

## Related

* [JWT assertions](jwt-assertions.md) — the RFC 7523 profile, and what "used"
  means for the shared replay history
* [PKI](pki.md) — where the key pairs and their certificates come from
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md) — the token endpoint these are
  presented at
* [SAML 2.0 Web Browser SSO](saml2-sso.md) — the browser profile, whose
  `<Response>` this grant does not accept
* [Federation](federation.md) — a foreign SAML identity provider signing people
  in, rather than authorizing a token
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md) and [error codes](error-codes.md)
