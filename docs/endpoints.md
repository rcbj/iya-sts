---
title: Endpoints
nav_order: 4
---

# Endpoints

**There is no list of endpoints in this documentation, and that is deliberate.**
There are 264 of them, they change, and a list written here would be wrong within
a month with nothing to say so — this number was 144 when the sentence was
written, which is the point it is making.

Ask the service instead:

```bash
curl -s localhost:8081/admin/sts-metadata            # a page
curl -s 'localhost:8081/admin/sts-metadata?format=json' | jq
```

Both are **behind the console gate** since the page moved into `/admin` on
2026-08-24: with no browser sign-on session the first is a 302 to the sign-in
screen and the second is a `401 login_required`, because a redirect to an HTML
login screen is not an answer a program can read. The gate cannot be turned
off; sign in at `/authn/login` (any username in development mode, where no
password is checked). **Everything under `/admin-api` needs an OAuth 2.0
access token** audienced to that API (`admin:read` to read, `admin:write` to
write); `ADMIN_API_AUTH_REQUIRED=false` turns that off.

## What that page is

`GET /admin/sts-metadata` answers "what does this thing speak, what can I call,
what may I call it with, and which specification is it pretending to
implement". It is a page of the admin console, with the console's sidebar,
breadcrumb and gate banner. `?format=json` gives the same document
machine-readably, and the **Download** button at the top of the page is that URL
asked for as a file (an `<a download>`, since the page runs no script).

It reads the endpoint list **off the running Express router**, walked per
request, so it cannot go stale by omission; the table in `sts_metadata.ts`
supplies only the *name* and *description* for a path the router reports. Each
row carries the method, the path, a sentence about what the endpoint is for, and
a link to the specification it implements. Every **coverage note starts
`full`, `partial` or `mock`** and says what is missing — a list of fifty
specifications that did not mention that development mode checks no passwords
and validates no access tokens would be the most misleading thing in the
service.

**Each path is a link to that path, where that is honest** — about half of them.
A link is a GET, so a path the router answers only for POST would land on
Express's own `Cannot GET /oauth2/token`, and a route pattern with a
`:parameter` or a `*` is not the address of anything. Those are listed unlinked
with the reason shown — "POST only", "takes :id", "wildcard". The followable
endpoints that *do* something when clicked (`/oauth2/authorize`,
`/oauth2/logout`, `/oauth2/userinfo`, `/issuer/offer`, `/oid4vp/start`) carry an
`effect` note: the first answers **400** when followed bare, since it needs
`client_id` and `redirect_uri`, and UserInfo answers **401**, being a protected
resource. Links are root-relative, so they follow whichever host the page was
reached at, and open in a new tab. The test follows every link and fails if one
does not reach a handler — telling a route that correctly answers 404 for a
resource that does not exist (which proves the route is registered) from
Express's own `Cannot GET /path` for an unregistered one.

It also reports **drift**, in six arrays, and this repository's own
`tests/vendored/sts_metadata.js` fails on all six:

| Field | Means |
|---|---|
| `undocumentedPaths` | A route is registered and nothing describes it |
| `stalePaths` | Something describes a path that is not registered — what a rename produces |
| `unknownSpecIds` | A description cites a specification the page does not know |
| `unknownProtocolGroups` | A protocol card at the top names an endpoint group with no rows |
| `unknownProtocolSpecIds` | A protocol card cites a specification the page does not know |
| `unclaimedGroups` | A group of endpoints no protocol card claims — a family added to the service and not to the page |

The last three are about the one part of the page that is **not** derived: the
thirteen protocol cards at the top. Two of those families register no route at
all and four live mostly on a raw socket, so the list cannot be read off the
router — and a hand-written list on a derived page is exactly the thing that
needs checking.

A route registered and undescribed still appears, marked UNDOCUMENTED, with
its methods, because the page's first duty is to be a true list of what is
callable. A description whose path is not registered is the more dangerous
half: the page would advertise an endpoint that answers 404, and a rename is
exactly when nobody thinks to check the index. The test also catches an *idle*
claim — a specification listed that no endpoint links to.

All six empty is the service agreeing with its own description of itself. That
is the check worth running after any change that adds or renames a route.

## Its one blind spot

**A protocol that registers no HTTP route is invisible to the router walk.** Four
things here are exactly that:

- the Kerberos KDC on raw TCP and UDP 88
- the LDAP directory on 389
- the same directory over TLS on 636
- the SPIFFE gRPC listeners — a Unix socket and a TCP port each for the Workload
  API and the SPIRE Server API

Those are described by hand in the page's own table — the Kerberos sockets in
the text of the three HTTP rows the walk can see (`/KdcProxy`,
`/krb5/principals`, `/krb5/service`), since a described entry with no route
behind it would trip the stale-path check. If you add one, describe it there or
it goes unlisted with nothing failing.

**The TLS family used to be a milder version of the same thing and no longer
is.** It had two listeners of its own, 8443 and 9443, which spoke HTTP and so
looked as though they belonged on the main listener, while `/admin/sts-metadata`
— walking that listener's router — could not see them; their rows there were the
plain-HTTP views only and the listeners were described in the text. Both were
deleted on 2026-09-16. Everything that family answers is now a route on the
router the page walks: `/tls`, `/tls/sign-in`, `/tls/server-certificate`,
`/tls/forwarded` and the two truststore controls.

## The index of its own cryptography

`GET /admin/crypto-metadata` is the second metadata page, and it is not a
summary of the first. Where that one answers *what can I call*, this one
answers the question underneath it: **when this service signs, verifies,
encrypts or decrypts something, what does it actually use** — which digest,
which signature algorithm, which cipher, which key, and which envelope (JOSE,
XMLDSIG and XML Encryption, WS-Security, COSE, X.509, Kerberos) the primitive
is wrapped in. It has one section per protocol family, with the four verbs as
four separate columns, because they are four different exposures and this
service does a different amount of each. `?format=json` and
`GET /admin-api/crypto` are the machine-readable forms.

**Every algorithm table on it is read from the module that performs the
algorithm** — the JWS rows from `common/crypto.js`'s algorithm table, the XML
signature, digest and canonicalization tables from the vendored `xmldsig.js`,
the Kerberos encryption types from the codec, the SPIFFE authority key types,
the COSE algorithms from the WebAuthn verifier, and so on across eleven modules
— because a hand-kept list of algorithms disagrees with the code silently. Only
the per-family prose and the standards list are hand-written, and every coverage
note there starts `full`, `partial` or `mock`. **It checks its family list
against the endpoint page's in both directions**, so a protocol family added
without a crypto profile is reported, and so is a profile naming a family that
no longer exists.

**Its post-quantum section's headline is deliberately not the flattering one:
the signatures are partly post-quantum and the key establishment is entirely
classical.** ML-DSA, SLH-DSA and the six composite algorithms can sign an ID
Token, a UserInfo response and a published JWK. Every key establishment
mechanism — RSA-OAEP, RSAES-PKCS1-v1_5, ECDH-ES, TLS's own key exchange — is
broken by Shor's algorithm, and there is no ML-KEM anywhere. The two halves are
reported apart because the threat differs: a signature is checked when it is
presented, while ciphertext captured today can be kept and opened later.
Symmetric cryptography is a third category, where Grover costs a square root
and the answer is key length — which makes **Kerberos the family least affected**,
having no public-key cryptography in it at all. The most instructive row is
DPoP, whose list excludes the post-quantum algorithms on purpose: a proof is
bound through the RFC 7638 thumbprint, which is defined for RSA, EC, OKP and
`oct` and not for `AKP`, so a proof signed with ML-DSA would verify perfectly
and bind to nothing.

**It publishes no private key and no secret** — key types, key identifiers,
curve names, certificate fingerprints and validity dates, all already readable
from `/oauth2/jwks`, `/tls/server-certificate` and the SPIFFE bundle endpoint.

## The other things the service publishes about itself

Each of these is generated from the same table the behaviour reads, so none of
them can drift from what the service does:

| Ask | Get |
|---|---|
| `GET /.well-known/openid-configuration` | The OpenID Provider Configuration |
| `GET /.well-known/oauth-authorization-server` | The RFC 8414 document |
| `GET /.well-known/{openid-configuration,oauth-authorization-server}/realm/<id>[/<server>]` | Either document for a realm's issuer, or a named server inside it (RFC 8414's inserted form); `/realm/<id>[/<server>]/.well-known/openid-configuration` is the appended form |
| `GET /.well-known/webfinger?resource=…` | WebFinger (OIDC Discovery section 2): the issuer for an `acct:`, e-mail, host or `https` resource, by realm domain or `/realm/<id>` path |
| `GET /oauth2/rfc9700` | Every Security BCP requirement, with what is and is not enforced |
| `GET /oauth2/oauth21` | Every OAuth 2.1 requirement the mode adds, which it inherits from RFC 9700 mode, and what it exempts |
| `GET /oauth2/fapi` | The FAPI profile in force (`oauth2.fapi`, or a named authorization server's own at `/{id}/oauth2/fapi`) and every FAPI 1.0 Baseline requirement with how it is enforced |
| `GET /admin-api/openapi.json` | The management API, generated from its operation table |
| `GET /admin/api-explorer` | The same, in a small explorer that also shows the `curl` line. A page of the **admin console** since 2026-09-09, behind its session and roles — it was `GET /admin-api/docs` until that API began requiring an access token a browser cannot carry |
| `GET /spiffe` | The trust domain, every socket this process has bound — the default realm's four and two more for each realm whose SPIFFE is turned on, each row naming its realm — and all 42 SPIRE methods with a reason for each of the six that are unimplemented. Reached under a realm prefix it is that realm's answer |
| `GET /admin/ldap/service` | The directory's state, both listeners separately, and the fact that it is schemaless |
| `GET /federation` | Every configured federation relationship in both directions, and the URL to give each partner |
| `GET /admin/ldap/federations` | The federation register as the directory holds it, with its schema — and the one container here where an `ldapmodify` is a security change |
| `GET /tls` | The certificate the main port presents, the client certificate it asks for, and what a verified one does and does not mean (`GET /tls/sign-in` turns one into a session) |
| `GET /admin/tls/trust` | Every client-certificate trust anchor, with where each came from (`tls.trustAnchorsFile` or added at runtime), and the add and remove controls. An admin console page; `GET /admin-api/tls/trust` and `POST /admin-api/tls/trust/{add,remove}` are its management-API twins. An anchor added at runtime is persisted in the default realm's `ou=trustAnchors`; one from the file comes back at every start |
| `GET /scim` | The SCIM authentication schemes that are switched on |
| `GET /krb5/principals` | The principal database, passwords included in development mode for the reason that page gives; in product mode the passwords are withheld and the page says why. A directory person keyed from their own password is listed with `directoryKeys: true` and never with a key |
| `GET /admin/kerberos/principals` | Who the KDC holds a STORED long-term key for: directory people whose keys were derived from their own password (product mode), and service principals created with a random key — with create, rotate, delete and clear controls. A create or a rotate shows an MIT keytab ONCE — a rotate's carries the previous kvno too. Each row lists the PREVIOUS key versions still accepted for tickets issued under them (kvno, enctypes, expiry; `krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS`), with a Drop previous versions control that ends that window at once. And the realm's `krbtgt` key (#169) — where it comes from, its kvno, its last and next rotation, the versions kept — with Rotate the krbtgt key and Rotate and invalidate, both queued on the scheduler and neither showing a key. An admin console page; `GET /admin-api/kerberos/principals` and `POST /admin-api/kerberos/principals/{create-service,rotate-service,delete-service,clear-person-keys,drop-previous-service-keys,drop-previous-person-keys,reset-person-keytab,rotate-krbtgt,rotate-krbtgt-invalidate}` are its twins, and only the create and rotate replies and a person's keytab carry key material |
| `OPTIONS /gnap` and `GET /.well-known/gnap-as-rs` | GNAP's two discovery documents — the client's (RFC 9635 section 9) and the resource server's (RFC 9767 section 3.1), both read off the `gnap.*` settings and the authorization server profile. See [GNAP](gnap.md) |
| `GET /gnap/keys` | The public keys that verify GNAP's self-contained token formats without introspection |
| `GET /.well-known/openid-federation` | The realm's OpenID Federation Entity Configuration: its Federation Entity Keys, its federation, OpenID Provider, authorization server and verifier metadata, its superiors, and the Trust Marks it carries. The rest of the federation's endpoints are `/oidfed/*`. See [OpenID Federation](oidfed.md) |
| `GET /oidfed/historical-keys` | Every Federation Entity Key the realm has retired or revoked, signed, with why |
| `GET /admin-api/status` | Which console pages exist — what the parity test reads |

**Two rows in that table are behind the console's gate, and their `/admin-api`
twins are not.** `GET /admin/ldap/service` and `GET /admin/ldap/federations`
became admin console pages on 2026-09-01 — they were `/ldap` and
`/ldap/federations` — along with `/admin/ldap/directory`,
`/admin/ldap/applications` and `/admin/ldap/spiffe`. They need a sign-on session
and a console role, because a dump of every attribute of every entry prints
`oauthClientSecret` and `fedClientSecret` in the clear. Every one of them is
mirrored by an operation under `GET /admin-api/ldap/…`, which is not gated: that
is the door a script uses, and the one to reach for when nobody holds a role.

## Named authorization servers

One process is several authorization servers. Any path component works and is
created on first sight:

```bash
curl -s localhost:8081/tenant1/.well-known/oauth-authorization-server | jq .issuer
```

Its endpoints live under that name (`/tenant1/oauth2/token`), its tokens carry it
in `iss` and `aud`, and **a credential does not cross between them** — an
authorization code issued by one is refused by another's token endpoint. The
capabilities in its document *drive* those endpoints rather than describing them,
so there is no second table that could disagree.

**A named authorization server has a GNAP grant endpoint too**, at
`/tenant1/gnap`. Its GNAP members — start modes, finish methods, key proofs,
token formats — are set on `/admin/authorization-servers` beside the OAuth ones
and are ENFORCED at that endpoint, and they appear only in its GNAP discovery
document, never in its OAuth metadata.
