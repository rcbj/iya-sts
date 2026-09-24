---
title: JWT assertions
nav_order: 5
---

# JWT assertions — RFC 7521 and RFC 7523

An application can authenticate at the token endpoint, or present an
authorization grant, with a **signed JWT** instead of a shared secret. Both
halves of the profile are implemented here.

**RFC 7521 is a framework and RFC 7523 is the only profile of it anybody uses**,
which is why they arrive together and why a reader looking for "the RFC 7521
part" will find nothing else: 7521 defines two request parameters, an error
vocabulary and a list of checks, and 7523 says the assertion is a JWT and names
the claims. Neither is testable without the other.

## Two uses of one format, and they are not the same feature

Reading one and concluding the other is covered is the mistake this page exists
to prevent. It is also the mistake this service had made: the metadata named RFC
7523, client authentication was complete, and the grant did not exist.

| | Parameter | The `sub` is | What it replaces |
|---|---|---|---|
| **§2.2 client authentication** | `client_assertion` + `client_assertion_type` | the CLIENT, necessarily | a client secret |
| **§2.1 an authorization grant** | `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` + `assertion` | a PERSON | an authorization code |

They share a format, a claim set and one **used-assertion history** and nothing
else. A request may legitimately carry both — a client authenticating with its
own assertion and presenting somebody else's as the grant — but not the SAME
document twice: an assertion is accepted **once, ever**, whatever it is presented
as, so a JWT that authenticated a client is refused as a grant and the reverse.

What "used" means, precisely:

* **Only a successful use counts.** An assertion is held while its token request
  is being answered and becomes spent only if that response issues tokens. A
  request refused for a different reason — a bad `resource`, an invalid scope, a
  role the application requires — releases it, and the same assertion may be
  retried. A replay racing the first request is refused.
* **It is remembered until the assertion would have expired** — its `exp` plus
  `oauth2.clientAssertionSkewS` — and not longer. A later document may reuse a
  `jti` once the first has expired.
* **It survives a restart** in the `ldif` and `postgres` stores, in both modes,
  and on `postgres` two processes cannot both accept one assertion. In the
  default `memory` mode it lives as long as the process.
* **It is listed** at `/admin/used-assertions` and `GET /admin-api/used-assertions`,
  per trust realm. No assertion is stored, only its issuer and identifier.

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

# 2. An application, and a signing key pair for it.
curl -sk -X POST https://localhost:8081/admin-api/applications/create \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"identifier":"webapp1","protocols":["oauth2"],
       "fields":{"oauthClientId":"webapp1"}}'
curl -sk -X POST https://localhost:8081/admin-api/pki/issue \
  -H "$H" -H 'Content-Type: application/json' -d '{"identifier":"webapp1"}'

# 3. Declare the `iss` it will assert under. THIS IS THE TRUST DECISION and it
#    is a separate act from holding a key — see below.
curl -sk -X POST https://localhost:8081/admin-api/applications/add \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"application":"webapp1","attribute":"oauthAssertionIssuer",
       "value":"https://issuer.acme.example"}'

# 4. The private key is on the entry. Read it back and sign with it.
#    The ENTRY holds it sealed under the key-encryption key in product mode;
#    this endpoint comes through common/applications.js and opens it for you,
#    which is why what lands in signer.pem is a PEM either way.
curl -sk "https://localhost:8081/admin-api/applications?application=webapp1" \
  -H "$H" | python3 -c '
import sys,json
f=json.load(sys.stdin)["application"]["fields"]
open("signer.pem","w").write(f["oauthAssertionPrivateKey"])
print("kid:", f["oauthAssertionKid"])'

# 5. Present it.
curl -sk -X POST https://localhost:8081/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d "assertion=$ASSERTION" -d scope='openid profile'
```

The assertion in step 5 is an ordinary JWT:

```json
{
  "iss": "https://issuer.acme.example",
  "sub": "alice",
  "aud": "https://localhost:8081/oauth2/token",
  "iat": 1789000000,
  "exp": 1789000120,
  "jti": "5c7b…",
  "department": "engineering"
}
```

and what comes back is an access token **for alice**, carrying `department`.

## Holding a key is not being trusted to assert

The two are separate acts and the console draws them in separate columns,
because an application commonly has one and not the other.

* **A key pair** lets an application SIGN. That is all §2.2 needs — client
  authentication, where the assertion says who is calling — so an application
  with a key pair and no declared issuer can already authenticate at the token
  endpoint with `private_key_jwt`.
* **A declared `iss`** (`oauthAssertionIssuer`) is what §2.1 needs — the
  authorization grant, where the assertion says who the token is *for*.

An assertion a client issues **about itself** needs no declaration: its `iss` is
its own `client_id`, and that lookup already succeeds. Asking an operator to
write the client_id down a second time under another attribute would be a
configuration step with no decision in it.

## A person can be the issuer too, and their key may only speak for them

Everything above has an **application** as the issuer: a party
an operator declared, vouching for somebody else. RFC 7523 asks no such thing —
§3 claim 1 wants `iss` to be "a unique identifier for the JWT issuer" and claim
2 says the `sub` of an authorization grant "typically identifies an authorized
accessor or resource owner" — so a person holding a key of their own and signing
*this is me, issue a token for me* is the profile read literally. It is the
shape most people want to exercise: no browser, no password, a signature and an
access token.

```bash
# A person, and a signing key pair for them. `target=person` is the whole
# difference; the hierarchy, the profile and the certificate are the same.
curl -sk -X POST "$STS/admin-api/users/create" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"username":"alice"}'

curl -sk -X POST "$STS/admin-api/pki/issue" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"alice","target":"person"}' > issued.json

# THE PRIVATE KEY IS IN THAT REPLY AND IN NO OTHER. Keep it now.
jq -r .privateKeyPem issued.json > alice.pem
```

The public half lands on alice's own directory entry as `stsAssertionJwks`,
`stsAssertionCertificate`, `stsAssertionCertificateChain`, `stsAssertionKid` and
`stsAssertionExpiresAt`; the private half is there too as
`stsAssertionPrivateKey`, sealed under the key-encryption key wherever that key
outlives the process. **It is handed over once and there is no read door for it
afterwards** — an application's is readable through `/admin-api/applications`,
and nothing draws a person's entry through a module that would open the seal, so
the alternatives were a page that prints somebody's private key on every visit
or a key nobody can ever collect.

The assertion is an ordinary one, signed with `alice.pem`, with `iss` and `sub`
both `alice`, and it is presented at the token endpoint exactly as the
application's is. **No declaration is needed**: a person's own username is
accepted as their `iss` for the reason a client's own `client_id` is. Write
`stsAssertionIssuer` on the entry (or pass `issuer` to the issue call) if they
should assert under some other name.

### A person can do it themselves

They do not need you. **`/portal/signing-key`** in the user
portal is the same act, performed by the person the key is for: they sign in,
press *Generate my RFC 7523 signing key*, and the private half is shown once on
the page that comes back — with the claims, the `kid` and the algorithm printed
beside it, and a `curl` line to spend it with. The same page issues the RFC 7522
(SAML) key pair on a card of its own; see
[SAML assertions](saml-assertions.md#a-person-can-be-the-issuer-too).

It is the same code path as the call above (`issueSigningKeyPair()` then the
same write), so what lands on the entry is identical; what differs is that the
portal's door is rate limited, and that `pki.personSelfService` turns it off
without taking away a key anybody already holds. An operator issuing from
`/admin/pki` is unaffected by that setting.

**The page can only offer this because of the rule below.** A self-service
button that minted a key able to assert about anybody would hand every person
who can sign in a token as every other person.

### The rule

**A person's assertion may only be about themselves.** `iss` and `sub` must name
the same person, and one naming anybody else is refused `invalid_grant` with a
sentence saying so.

A key issued to one resource owner is *that person's credential*, not permission
to speak for the others — without the rule, everybody ever issued a key on
`/admin/pki` could obtain a token as anybody in the realm, with the signature
verifying and the claims well formed while they did it. **A party that may
assert about other people is an application** with `oauthAssertionIssuer`
declared on it, which is a decision an operator makes deliberately. That is the
whole difference between the two controls on that page.

The rule holds for a certificate presented in an `x5c` as well, with nothing on
the entry to consult: the leaf this service issues to a person carries
`urn:sts:person:<name>` as a URI subjectAltName, and that name is what is
checked. Before people could hold a key pair, *it chains here* and *it may
assert about somebody* were one sentence.

**Taking a person's key pair off clears their issuer declaration with it**,
where the application control leaves `oauthAssertionIssuer` alone — an
application may hold a JWKS it registered itself beside the one this service
issued, and a person may not. Like the application's, it is **not revocation**:
the certificate is still valid and on no list, and what changes is that this
service will no longer accept what the key signs.

**A person's key pair can also be replaced by a certificate
they already hold**, and a person can hold an RFC 7522 (SAML 2.0) key pair beside
this one — both from the Credentials section of `/admin/users?user=<name>`, or
through `/admin-api/pki/upload-certificate` with `target=person`. The rule above
holds for an uploaded key exactly as for an issued one. [PKI](pki.md) has the
section.

## The one thing that is not permissive

Almost everything in this service is a turnstile. This is not, and the reason is
worth reading before turning it off.

An assertion grant has **no browser, no password and no consent step anywhere in
it**. The signature is the entire security of the grant. So "accept any signed
assertion" means anybody who can reach this port gets an access token as
anybody, and the token that comes out is indistinguishable from one somebody
signed in for.

That puts this feature in the same category as [federation](what-is-not-checked.md)
rather than in the category everything else here is in: **there is no permissive
answer available.** `oauth2.jwtBearerRequireRegisteredIssuer` is ON by default,
and those two refusals are the only ones in this service that are.

**What is still permissive is everything around it.** The `sub` need not be
anybody this service has heard of — an assertion for a name nobody has ever used
mints that person exactly as typing the name at the sign-in screen does — and
the scope is not checked against anything. What is real is that somebody holding
a private key this service was told to trust signed the document.

**Turning the requirement off does not make the grant credulous.** Without it
the signature must still verify against a key this service holds for the issuer;
what goes away is the requirement that somebody wrote the issuer down first.

## Which key verifies it

Three sources, ORed, and they are three attributes rather than one because each
was arranged deliberately:

| Source | Attribute | What it is |
|---|---|---|
| Registered by value | `oauthJwks` | RFC 7591's member. What a party with a key of its own uses. |
| Issued by this service | `oauthAssertionJwks` | What `/admin/pki` wrote, public half only, carrying `x5c` and `x5t#S256`. |
| Presented with the signature | the JWS `x5c` header | Used **only after** the chain has been shown to reach this realm's Root CA. |

**A certificate that arrives WITH the signature is not evidence on its own.**
Taking a public key out of an unchecked `x5c` would be verifying a signature
against a key the signature came with, which proves nothing at all — so it is
used only when this service can see that it issued it. That is the point of
holding a certificate authority.

### The certificate's whole chain is validated every time the key is used

In both modes, for both halves of RFC 7523. When the key that
verified an assertion carries a certificate — a JWK with `x5c` in `oauthJwks`,
`oauthAssertionJwks` or a person's `stsAssertionJwks`, or the JWS `x5c` header —
the signature counts only if that certificate's trust chain holds **at that
moment**:

* the first certificate holds the key that verified the signature (RFC 7517
  section 4.7);
* every link verifies, names its issuer, and is inside its validity window —
  the leaf's and every intermediate's;
* every certificate that signs another is a CA (`basicConstraints cA=TRUE`),
  its KeyUsage permits `keyCertSign`, and its `pathLenConstraint` holds;
* the signing certificate is not a CA and its KeyUsage permits
  `digitalSignature`;
* the path ends somewhere this service trusts. For a certificate issued by this
  realm's certificate authority that is **this realm's Intermediate** — the leaf
  may be registered alone. For anybody else's, the chain must be registered with
  it **up to and including a self-signed root**; the registration is the trust
  decision, and nothing is fetched to complete a chain. A self-signed
  certificate is its own whole chain.

Until that date a registered chain was checked when it was registered and never
again, so an expired certificate or a replaced Root went on verifying
assertions; and the `x5c` header's path check looked at signatures but not at
who was entitled to make them, so an issued leaf — a person's included — could
sign a certificate of its own and present it. A refusal is `invalid_grant` (or
`invalid_client` for client authentication), recorded as `STS-PKI-0156` to
`STS-PKI-0161`. **A bare key, with no certificate, has no chain and is still
accepted.** Revocation is checked after the chain (`STS-PKI-0129`).

**`jwks_uri` is recorded and never followed.** Fetching a URL somebody
registered in order to verify a credential is a server-side request forgery with
a specification citation attached, and it is the same refusal WS-Federation's
`wreqptr` gets here. A client that registers only that is told to register
`jwks` instead, by name, at the moment it authenticates.

## Every optional component, because "optional" is where implementations differ

| | |
|---|---|
| §3 claim 5, `nbf` | checked, against `oauth2.clientAssertionSkewS` |
| §3 claim 6, `iat` | checked, and it **bounds the lifetime** (`oauth2.jwtBearerMaxLifetimeS`, 300s) — RFC 7521 §5.2 invites a server to refuse an unreasonable one and leaves "unreasonable" to it |
| §3 claim 7, `jti` | spent once, ever, against the used-assertion history above, and **required** here. §3's own last paragraph says a server MAY refuse a reused assertion; one with no `jti` cannot be remembered, so accepting it means accepting a bearer credential this service has no way to spend |
| §3 claim 8, other claims | carried onto the issued access token |
| §3 claim 10 | the assertion may be **encrypted** — see below |
| RFC 7521 §4.1, `scope` | **narrowed** against what the assertion carries and never widened. Where the assertion names none, the request decides |
| RFC 7521 §5.2 (5), `aud` | may be an array; any member may match. Both the token endpoint and the issuer are accepted, because RFC 7523 and OpenID Connect Core §9 name different ones and deployments differ |
| RFC 7521 §6.2, `client_id` | may be omitted where the assertion identifies the party |
| RFC 7521 §6.3, `cnf` | carried and **reported, never enforced** — this grant has no parameter in which a presenter could prove possession of the named key, so demanding one would refuse every conforming client |
| RFC 7521 §4.2 | an `error_description` on every refusal that names what to change |

**The profile's own twelve claims are stripped before the rest are copied onto
the token** — `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `scope`, `cnf`,
`typ`, `azp` and `client_id`. An `exp` copied off an assertion would be a token
lifetime chosen by whoever signed it.

**Every JWS algorithm this service verifies is accepted**, the eleven
post-quantum ones included; `assertion_signing_alg_values_supported` in the
metadata is that table read from the module that performs the algorithms.
`alg: "none"` is refused **by name**, citing claim 9 — it is the forgery every
JWT implementation has had at some point, and a caller sending one deserves to
be told which rule it broke rather than being told its assertion did not verify.

## An encrypted assertion

RFC 7523 §3 claim 10: the assertion may be a **nested JWT** — a JWE whose
plaintext is the JWS. Both parameters take one.

Which key opens it depends on what the sender could possibly have had:

| Family | Encrypted to | Available to |
|---|---|---|
| `RSA-OAEP-256`, `RSA-OAEP` | this service's own RSA key, from `/oauth2/jwks` | anybody. **This is what a client should use.** |
| `ECDH-ES` and its three key-wrapping forms | this service's own EC key of the matching curve, from the same JWKS | anybody |
| `A128KW` … `A256GCMKW`, `dir`, the three `PBES2` forms | the **client secret**, which is the only shared key that exists between this service and a client | a client that has one |

Six content encryption algorithms against all sixteen: `A128GCM`, `A192GCM`,
`A256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`.

**`RSA1_5` is deliberately absent and the refusal names it.** RFC 8017
deprecated PKCS#1 v1.5 encryption, and implementing it safely means making an
unwrap failure indistinguishable from every later failure — a property of a
whole code path rather than of one function. A caller that sends one is told
this is a refusal and not an omission.

**The `cty` is checked and not assumed.** RFC 7519 §5.2 says a nested JWT
carries `cty: "JWT"`; one declaring something else is refused rather than being
handed to a JWS parser that would report a base64 problem three frames away.
And a JWE whose plaintext is **not signed** is refused citing claim 9:
encryption does not stand in for a signature, because an encrypted document says
nothing about who wrote it.

## It is recorded as a delegation

One party asked this service to issue a credential in **another party's name**,
so the act lands in the delegation register beside RFC 8693's two shapes and is
drawn on `/admin/delegation`.

It is filed as `delegation` rather than `impersonation`, and the distinction is
RFC 8693 §1.1's own: impersonation produces a token indistinguishable from one
the subject obtained themselves, and this one is not — the issuer is on the
assertion, the assertion's `jti` is in the register, and a resource server
holding the token can be told which trusted party asserted the subject. The
party is acting **openly**, which is what the word means.

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.jwtBearerGrant` | `STS_OAUTH2_JWT_BEARER_GRANT` | `true` | yes | Whether the token endpoint performs the §2.1 grant. The metadata advertises it only while it is on, because a `grant_types_supported` member is a promise. It does **not** affect §2.2. |
| `oauth2.jwtBearerRequireRegisteredIssuer` | `STS_OAUTH2_JWT_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Whether a §2.1 assertion from an issuer no application declares on `oauthAssertionIssuer` is refused. See [above](#the-one-thing-that-is-not-permissive) before turning it off. |
| `oauth2.jwtBearerMaxLifetimeS` | `STS_OAUTH2_JWT_BEARER_MAX_LIFETIME_S` | `300` | yes | The most seconds between `iat` and `exp`. Zero switches the check off. |
| `oauth2.clientAssertionSkewS` | `STS_OAUTH2_CLIENT_ASSERTION_SKEW_S` | `60` | yes | How far out somebody else's clock may be for `exp`, `nbf` and `iat`, and how long past its expiry a `jti` is remembered. It answers one question, so it applies to both halves of the profile. |
| `oauth2.assertionReplayCacheSize` | `STS_OAUTH2_ASSERTION_REPLAY_CACHE_SIZE` | `1000` | yes | Unexpired rows the used-assertion history holds per realm, for RFC 7523 and RFC 7522 together; a full history refuses the next assertion rather than forgetting a live one. |
| `pki.personSelfService` | `STS_PKI_PERSON_SELF_SERVICE` | `true` | yes | Whether `/portal/signing-key` lets a person issue their own key pair; off takes away no key already held. |
| `pki.personSelfServicePerIdentity` | `STS_PKI_PERSON_SELF_SERVICE_PER_IDENTITY` | `5` | yes | How often one person may press Generate there in a `security.rateLimitWindowS` window. |
| `pki.personSelfServicePerAddress` | `STS_PKI_PERSON_SELF_SERVICE_PER_ADDRESS` | `5` | yes | The same limit counted per client address. |

Whether a registered or presented certificate is checked for revocation is
`pki.revocationCheck`, and the hierarchy that issues the key pairs is
configured on [PKI](pki.md#configuration). See
[Configuration](configuration.md) for how a value resolves and where it is
changed — the console page, or `POST /admin-api/config/set`.

## Design decisions

* **RFC 7521 and RFC 7523 are one feature.** RFC 7521 has no wire format of its
  own, so everything it asks for is implemented through RFC 7523 and neither is
  testable without the other.
* **Client authentication and the grant are two features that share one
  history.** Each is implemented in full, and an assertion is accepted once,
  ever, whatever it is presented as — see
  [above](#two-uses-of-one-format-and-they-are-not-the-same-feature).
* **An assertion is spent only when tokens are issued.** A request refused for
  another reason releases it, so a fixable mistake does not burn the document.
* **`jti` is required where the RFC says optional.** An assertion with no `jti`
  cannot be remembered, and accepting it would be accepting a bearer
  credential this service has no way to spend.
* **The issuer of a grant must be declared, and that refusal is on by
  default.** A grant has no browser, password or consent step, so the
  signature is its entire security — see
  [above](#the-one-thing-that-is-not-permissive).
* **Holding a key is not being trusted to assert.** A key pair is enough for
  client authentication; speaking about somebody else takes a separate
  declaration — see [above](#holding-a-key-is-not-being-trusted-to-assert).
* **A person's key may only speak for that person.** A party that may assert
  about other people is an application an operator declared — see
  [above](#the-rule).
* **The signature is verified before any claim is believed.** The unverified
  `iss` is used only to find candidate keys and decides nothing.
* **A certificate that arrives with the signature is checked, not read, and a
  chain is validated at every use.** A key taken from an unchecked `x5c` would
  prove nothing — see [above](#which-key-verifies-it).
* **`jwks_uri` is recorded and never followed.** Fetching a URL a client
  registered in order to verify its credential is a server-side request
  forgery; a client is told to register `jwks` instead.
* **Scope is narrowed and never widened; `cnf` is carried and never
  enforced.** The grant has no parameter in which to prove possession of a
  `cnf` key, so demanding one would refuse every conforming client.
* **The profile's own claims are stripped before the rest reach the token.** An
  `exp` copied off an assertion would be a token lifetime chosen by whoever
  signed it.
* **`alg: "none"` and `RSA1_5` are refused by name.** A caller is told which
  rule it broke, rather than that its assertion did not verify — see
  [above](#an-encrypted-assertion).
* **It is recorded as a delegation, not an impersonation.** The issuer is on
  the assertion and the act is visible — see
  [above](#it-is-recorded-as-a-delegation).

## Related

* [SAML assertions](saml-assertions.md) — the RFC 7522 profile of the same
  framework
* [PKI](pki.md) — where the key pairs and their certificates come from
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md) — the token endpoint these are
  presented at
* [OAuth security profiles](oauth-security.md) — RFC 9700 and OAuth 2.1 modes,
  which verify every declared client authentication method
* [Accepted tokens](accepted-tokens.md)
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md) and [error codes](error-codes.md)
