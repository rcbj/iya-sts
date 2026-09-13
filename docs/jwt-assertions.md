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

They share a format, a claim set and a replay cache and nothing else. A request
may legitimately carry both — a client authenticating with its own assertion and
presenting somebody else's as the grant.

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

Since 2026-09-11. Everything above has an **application** as the issuer: a party
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

Since 2026-09-12 they do not need you. **`/portal/signing-key`** in the user
portal is the same act, performed by the person the key is for: they sign in,
press *Generate my signing key*, and the private half is shown once on the page
that comes back — with the claims, the `kid` and the algorithm printed beside
it, and a `curl` line to spend it with.

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
| §3 claim 7, `jti` | checked against a replay cache and **required** here. §3's own last paragraph says a server MAY refuse a reused assertion; one with no `jti` cannot be remembered, so accepting it means accepting a bearer credential this service has no way to spend |
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

## The settings

| Setting | Default | What it does |
|---|---|---|
| `oauth2.jwtBearerGrant` | `true` | Whether the token endpoint performs the §2.1 grant. The metadata advertises it only while it is on, because a `grant_types_supported` member is a promise. It does **not** affect §2.2. |
| `oauth2.jwtBearerRequireRegisteredIssuer` | `true` | Whether an assertion from an issuer nobody declared is refused. See above before turning it off. |
| `oauth2.jwtBearerMaxLifetimeS` | `300` | The most seconds between `iat` and `exp`. Zero switches the check off. |
| `oauth2.clientAssertionSkewS` | `60` | How far out somebody else's clock may be. It answers one question, so it applies to both halves of the profile. |
