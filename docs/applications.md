---
title: Applications
---

# Applications

A person who authenticates here has a directory entry and a row on
`/admin/users`. The **application** on the other side of that authentication
has one too: an entry under `ou=applications` in the embedded directory. It
answers the question *what applications has this service seen?*, whatever
protocol brought each one.

**The entries are the registry, not a copy of one.** Every protocol endpoint
that checks a client's configuration reads it from these entries, so an
`ldapmodify` of one is a configuration change.

```
dc=example,dc=com
├── ou=users          people
├── ou=groups         groups, which grant nothing by being groups
│                     (a token can carry them, see groups.claim)
└── ou=applications   OAuth clients, OIDC relying parties, SAML 2.0 and 1.1
                      service providers, WS-Federation applications, WS-Trust
                      relying parties, the OpenID4VP verifier, Kerberos services
```

The directory is a tree per [trust realm](trust-realms.md), so each realm has a
registry of its own. `GET /admin/ldap/applications` lists the entries and
publishes the schema; `?format=json` is the machine-readable form.

## Features

### One entry per identifier

An entry appears the first time an identifier is **accepted**:

* a `client_id` at the authorization or token endpoint;
* a `wtrealm` on a `wsignin1.0` response;
* an `AppliesTo` on an issued WS-Trust token;
* a Kerberos service principal name on a TGS-REP, **and again when a ticket
  for it is accepted**;
* the OpenID4VP Verifier's own `client_id`.

The key is the identifier verbatim, not lower-cased and not namespaced by
protocol. An application that appears under one name in two protocols is
**one entry with two kinds**, not two entries.

The Kerberos service recorded at both ends is still one entry: both halves
write `SPN@REALM`. The acceptor's half is the only one that fires for a ticket
**another KDC issued** — a real Active Directory, for example — so the service
a client presented that ticket to is recorded too.

One sighting can name **more than one kind at once**, because some
applications really are two things in one request. A `wtrealm` is a
WS-Federation application *and* the audience of the SAML 1.1 or 2.0 assertion
it was handed. An `AppliesTo` handed a SAML 2.0 assertion is a WS-Trust
relying party *and* that assertion's service provider. This is the same rule
that makes `alice`, `alice@REALM` and her `urn:uuid:<entryUUID>` subject one
person on `/admin/users`, and it is what [federation](federation.md) needs: a
relying party that federates over both OIDC and SAML is one relationship.

Each protocol records its application where it accepts it, not at a shared
funnel. The user side has one funnel; this side cannot, because in the
authorization code flow the person is authenticated by the sign-in service,
which knows nothing about OAuth and never reads a `client_id`. So each protocol
records its own application at the point it decides that application is real.

### The directory is the source of truth

Nothing shadows these entries in memory. Every query is a directory read, and
nothing is cached. Three things follow.

**An `ldapmodify` is a configuration change.** Add a value to
`oauthRedirectUri` on a client's entry and the next authorization request is
matched against it — no restart, no reload.

**RFC 7591 registrations live here too.** `POST /oauth2/register` writes an
entry, and RFC 7592's read, update and delete operate on it. The whole
registration document is kept verbatim in `appRegistrationJson`, because RFC
7591 permits arbitrary metadata and no fixed set of attributes can hold it. When
the record is rebuilt, that document is the *starting point*, and every member
that has an attribute of its own is then overwritten from the attribute. An
operator who edits `oauthRedirectUri` is therefore never ignored by the check
that reads it.

**Deleting a registration keeps the entry.** `appRegistered` becomes `FALSE`,
the `client_secret` and the registration access token are removed, and the
history stays. The registry records what this service has *seen*; losing the
fact that an application was ever here because its registration was withdrawn
would lose history, not configuration.

### What the checks read

The checks read the **attributes**, never the registration document, through
one function (`clientConfigOf()`). The exact-match redirect-URI check, whether
a client is public or confidential, the client-secret check, the scopes a
client may be issued (`oauthAllowedScope`), consent, delegated permissions and
the CORS allowlist all resolve to attributes on an entry. It does not matter
whether a registration, a console form, the management API or `ldapmodify` put
them there. `appRegistered` records *how* an application got here, not whether
what it holds counts.

That makes one `client_id` able to exercise both halves of RFC 6749 section
2.1.1 without a restart: set `oauthTokenEndpointAuthMethod` to `none` and the
client becomes public — PKCE is required of it and its secret is no longer
checked — and set it back and it is confidential again.

Which of these checks are enforced depends on the mode: product mode implies
[RFC 9700 mode](oauth-security.md) and enforces all of them; see
[Development and product mode](#development-and-product-mode) below.

### Software statements (RFC 7591 section 2.3)

A registration may carry a `software_statement`: a signed JWT of client
metadata, vouched for by whoever publishes the software rather than by the
installation registering it. **A trusted statement's claims take precedence
over the registration's own JSON** (section 3.1.1), and the statement comes
back unmodified in the response (section 3.2.1).

```
POST /oauth2/register
  { "software_statement": "eyJhbGciOiJSUzI1NiIsInR5cCI6InNvZnR3YXJl…",
    "client_name": "Acme Mobile" }

201 { "redirect_uris": ["com.acme.mobile:/oauth2/cb"],   <- from the statement
      "client_name": "Acme Mobile",                      <- from the JSON
      "software_statement": "eyJhbGciOiJSUzI1NiIsInR5cCI6InNvZnR3YXJl…",
      "client_id": "sts-client-…", … }
```

**Who is trusted is declared**, the same way an RFC 7523 assertion issuer is:

* **This realm itself**, for a statement issued from an application's own page
  (*Software statements → Issue a statement*) or with
  `POST /admin-api/applications/issue-software-statement`. It is typed
  `software-statement+jwt`, names as issuer the address the request arrived
  on, names the application in `sub`, and is signed with the realm's key — so
  in development mode, where the key is regenerated at each start, it stops
  verifying at the next restart.
* **An application that declares the issuer** in
  `oauthSoftwareStatementIssuer` — the software publisher. Its statements
  verify against its `jwks`, its RFC 7523 key pair from `/admin/pki`, or an
  `x5c` this realm issued to it.

Everything else is refused **in every mode**. A document that is not a JWS, is
unsigned or HMAC-signed, names no `iss`, does not verify, has expired, is
addressed (`aud`) to another server, or is one of this realm's *other* JWTs is
`invalid_software_statement`. An issuer nothing declares is
`unapproved_software_statement`. `oauth2.softwareStatementRequireTrustedIssuer`
turns the second refusal off; a statement accepted that way is recorded as
unverified, and its claims lose to the JSON.

**In product mode a trusted statement is a second way through a closed
endpoint.** With `oauth2.openRegistration` off, a registration carrying one is
accepted while `oauth2.softwareStatementOpensRegistration` is on (the default),
and `registration_endpoint` stays in the discovery documents. A client admitted
that way must present a trusted statement from the same issuer with every RFC
7592 update, so it cannot `PUT` away the metadata the statement fixed.
`oauth2.softwareStatementRequired` demands a statement on every registration.

**A statement is not spent.** Section 2.3 expects every copy of the software to
present the same one, so no `jti` history is kept. The entry records how a
statement let a client in, as `appSoftwareStatementIssuer`,
`appSoftwareStatementTrusted` and `appSoftwareStatementPublisher`.

The rest of dynamic registration — the OpenID Connect Registration rules it
applies, RFC 7592 updates — is on
[OAuth 2.0 and OpenID Connect](oauth-oidc.md#dynamic-registration-and-software-statements).

### The applications that are this service

Every other entry arrives because somebody *presented* an identifier. This
service's own surfaces never are presented from outside, so they are seeded at
startup, under `ou=applications` with everything else:

| Entry | What it is | Realms |
|---|---|---|
| `sts-admin-console` | The admin console at `/admin`: a confidential OpenID Connect relying party on the authorization code grant, redirect URI `/admin/callback` | every realm |
| `sts-user-portal` | The user portal at `/portal`: the same shape, redirect URI `/portal/callback` | every realm |
| `sts-management-api` | The [management API](management-api.md): a confidential OAuth client on `client_credentials`, with `client_secret_basic`, scope `admin:read admin:write`, and no redirect URI | every realm |
| `sts-debugger-api` | The [embedded protocol debugger's](admin-console.md#the-embedded-protocol-debugger) api: a resource server that defines one delegated permission, `urn:sts:debugger-api:debugger` | default realm, only while the debugger is embedded |
| `sts-debugger-ui` | The embedded debugger's browser client: a relying party granted that permission | default realm, only while the debugger is embedded |

They are **full RFC 7591 registrations rather than labels**, and they are
load-bearing. `/admin`, `/portal` and the debugger are relying parties of this
service's own authorization server: an unauthenticated request is sent to
`/oauth2/authorize` with the entry's `client_id`, comes back to its redirect
URI with a code, and the code is redeemed at `/oauth2/token`. The three hosted
surfaces authenticate there with `private_key_jwt`, using a key this service
issued them; the management API has a `client_secret`. Each entry also carries
a registration access token, so `GET /oauth2/register/sts-admin-console`
returns the registration to whoever holds it. RFC 9700 mode checks these
clients by the same rules as anybody else's.

The console, portal and debugger entries carry `oauthGlobalConsent` for
`openid`, `profile`, `email` and `offline_access` (and the debugger's
permission), so a person is not asked whether they consent to this service
reading their own profile. It is an attribute rather than an exemption, so an
operator who wants the consent screen removes the values.

The `sts-admin-console` entry is the client the console signs in *as*; it does
not make anybody an administrator. The [console roles](admin-console.md#who-may-use-the-console)
decide that.

**They are seeded only where the identifier is free.** An operator who
deleted one meant it, and re-creating it would make the delete appear not to
work. Deleting one of these entries **takes the surface it names offline**. In
the default `memory` persistence mode nothing is written down, so the next start
seeds them again, with new secrets; with a store on, the directory that was
written down replaces the seeded one, so a deletion survives the restart.
`applications.seedInternal` turns seeding off, and takes effect at the next
start. The management API's default-realm secret is pinned by
`adminApi.clientSecret` where that is set.

### The schema, and what "schema" means here

`node-ldapjs` has **no schema subsystem**: it is protocol machinery — messages,
filters, DN parsing, a client and a server. So the applications schema is
defined by this service, published on `/admin/ldap/applications`, and
**enforced by nothing in LDAP** — a vocabulary, not a constraint, like the rest
of this schemaless directory. See [LDAP](ldap.md) and
[LDAP schema](ldap-schema.md).

Where a standard name exists it is used. `applicationProcess` (RFC 4519) is the
one registered object class that fits an application, and it brings `cn` and
`description`. No registered LDAP schema has a `client_id`, a set of redirect
URIs, an `entityID` or a service principal name, because products that store
OAuth clients keep them in their own databases. So `stsApplication` is this
service's own class, and its attributes are this service's own names, as
`x509subject`, `didSubject` and `authnMethod` are on the user entries.

**The published table is the definition.** The entry is built by walking it,
and an attribute that is not in it is refused when this service writes it.
`multi` accumulates a repeat and `single` is assigned, which stops a counter
growing a value per sign-in. Beside the identity and the counters
(`appAuthentications`, `appSessions`, `appUsers`) sit the protocol-specific
attributes: `oauthClientId`, `oauthRedirectUri`, `oauthGrantType`,
`oauthTokenEndpointAuthMethod`, `oauthConfidential`, `samlEntityId`,
`samlAssertionConsumerService`, `wsfedRealm`, `wsfedReplyUrl`,
`wstrustAppliesTo`, `krb5ServicePrincipalName`, `oid4vpClientId`,
`federationPartnerId`, `ldapBindDn`, `scimClientId`, `spiffeWorkloadId`, and
more for the features that read them (`oauthAllowedScope`, `appCorsOrigin`,
`oauthPermission`, `oauthGlobalConsent` and the rest — the published table is
the full list).

**Every protocol family has an identifier attribute, and all but one
accumulate.** Fourteen families share eleven attributes: OAuth 2.0, OpenID
Connect and OpenID4VCI share `oauthClientId` (a relying party *is* an OAuth
client, and a wallet authenticates as one), and both SAML profiles share
`samlEntityId`, because those specifications share the identifier and two
attributes for one fact would be two spellings that disagree. They are `multi`
because one application legitimately answers to two `client_id`s or two SPNs,
one per environment. The exception is mutual TLS's
`oauthTlsClientAuthSubjectDn`, which stays single-valued because RFC 8705
section 2.1 matches a certificate against "the single expected subject", and a
client registers at most one of the five subject parameters.

**Four of them are declaration only.** Nothing in this service writes
`federationPartnerId`, `ldapBindDn`, `scimClientId` or `spiffeWorkloadId`: LDAP
and SCIM authenticate the *caller* rather than an application identifier,
SPIFFE files identities under `ou=spiffe`, and a federation relationship lives
under `ou=federations`. They exist because *what is this application called
when it talks to us that way* is a fact an operator has, and a value in one
grants nothing.

**The client secret is stored on the entry.** `oauthClientSecret` and
`appRegistrationAccessToken` hold credentials this service minted. That is the
same decision `/krb5/principals` makes about the Kerberos fixture passwords: a
test service whose accounts are unusable without reading the source is worse
than one that says what they are. Be precise about the cost: wherever the
secret is checked, anyone who can read it can authenticate as that client. In
product mode an LDAP search never returns it — credential attributes are
withheld from every reader of the socket — and the console shows it to an
administrator only, marked as a credential. It is never written to the audit
log.

**`appSessions` and `appUsers` are counts, not lists.** The ids themselves are
deliberately not on the entry — an application used by two thousand people
would otherwise carry two thousand values — so the count increments when the id
differs from the *last* one recorded. That is right for the ordinary case and
undercounts somebody alternating between two applications.

### Declared and derived

An entry holds two kinds of fact, and the line between them decides what may
be changed from the console and the API.

* **Declared** is what this application is allowed to do: its redirect URIs,
  grant types, scopes, secret, whether it is confidential, the protocol
  families it is for. It is configuration, it is what the checks read, and it
  is editable.
* **Derived** is what happened: the counters, the first and last sighting, the
  kinds and protocols it has been seen in, the redirect URIs it actually used.

A form that could rewrite the derived facts would make the page lie about the
service's own behaviour, in a way indistinguishable from the recording being
broken, so the console and the API refuse them with a list of what is not
editable. `ldapmodify` still reaches every attribute: an operator with an LDAP
client is doing something deliberate, and refusing it *there* is not the same
as not offering it here.

### The console page and the API

`/admin/applications` (**Directory → Applications**) is the other side of
`/admin/users`: that page lists every identity that has authenticated here, and
this one lists what they authenticated *to*. Filter by identifier or name and
by kind, page with `?page=` and `?per=`, and `?application=<id>` drills into
one: every attribute of its directory entry with what the published schema says
each attribute *is*, paged under `?attributesPage=`. `?format=json` returns the
same data, and `GET /admin-api/applications` is the same view with the same
parameters.

**"Every attribute" is meant literally.** The drill-down shows the whole entry,
including the operational attributes `createTimestamp` and `modifyTimestamp`
and anything an `ldapmodify` wrote by hand.

The DN is published as **`entryDN`** — RFC 5020's name, and the name an
`ldapsearch` filter matches it by here — and it is **computed on every read
rather than stored**. A stored copy would be a second definition of the same
fact, and the one that goes stale when somebody renames an entry. It appears at
the top of the drill-down, on every row of the list, on
`/admin/ldap/applications`, and as `dn` on every application in the API's
reply, because the DN is the address an `ldapsearch` or `ldapmodify` is aimed
at. Attribute names come back **canonically spelled** — `oauthClientId`, not
`oauthclientid` ([LDAP](ldap.md)).

Both the page and the API **write**: `create`, `set`, `add`, `remove`,
`revoke-registration` and `forget`, as forms on the page and as
`POST /admin-api/applications/{action}`. Every action calls the same function
in `applications.js` that a protocol endpoint and an `ldapmodify` reach, against
the same entries, so a form post and an `ldapmodify` are one act arriving by
two routes, each visible to the other immediately.

* **`create` configures a relying party before it connects.** Without it, the
  only ways to give an unregistered client its own redirect URIs would be
  `/oauth2/register` or the global `oauth2.redirectUris` setting. The entry
  records that it was created by hand.
* **`revoke-registration`** keeps the entry and its history, and takes away
  only the registration, the secret and the registration access token.
* **`forget` is the one operation that loses a fact**, which is why it is
  separate from `revoke-registration`.

The page marks `oauthClientSecret` and `appRegistrationAccessToken` as
credentials where it prints them. Two counting caveats are on the page:
`Sessions` and `Users` count *changes* rather than distinct sets, and `?kind=`
does not partition the list, because a record commonly carries two kinds.

### `/admin/applications/new`

`create` also has a page of its own. Name a `client_id`, `wtrealm`,
`AppliesTo`, entityID or service principal name that has never connected, tick
the **protocol families** it is declared for, and fill in **what each protocol
will call it** and **where its responses go back to**.

The families are a closed list of fourteen: OAuth 2.0, OpenID Connect, SAML
2.0, SAML 1.1, WS-Federation, WS-Trust, Kerberos v5, OpenID4VCI, OpenID4VP,
Federation, LDAP, SCIM 2.0, SPIFFE and TLS / mutual TLS. They land on
`appAllowedProtocol`; the identifiers and addresses land on the schema's own
attributes. `GET /admin-api/applications/new` returns the same vocabulary as
JSON, so a caller can read what a create will accept from the service.
`POST /admin-api/applications/create` takes the families as `protocols` and the
attributes as `fields`, keyed by attribute name.

**Eleven identifier fields cover the fourteen families, and three fields take
redirect URIs**, because only three families send a response back through a
browser: `oauthRedirectUri`, `samlAssertionConsumerService` and
`wsfedReplyUrl`. Multi-valued fields take **one value per line** — newline
separated, not comma separated, since a redirect URI may legally contain a
comma and may not contain a newline.

**The entry lands in the trust realm the console is showing**, at that
realm's `ou=applications`. An `ldapsearch` under that realm's base DN sees it;
another realm's registry has never heard of it.

The page posts `action=create` to `/admin/applications`, the same action the
short row at the foot of the list posts. That inline row still takes an
identifier and a name, for somebody already looking at the list.

#### Importing a protected resource's metadata (RFC 9728)

Tick *Use a protected resource metadata document* and paste the JSON, upload
the file, or name the URL it is published at (usually
`https://<host>/.well-known/oauth-protected-resource`). The page shows the
document in three tabs — the raw JSON, a table of its values, and the fields
read from it, editable — and fills in the create form:

* the document's `resource` as the default **name**, as
  `oauthPermissionBaseUri` and as `oauthAudience`;
* one **permission** per `scopes_supported` value, with the resource prefix
  taken off (`https://api.example.com/read` under `https://api.example.com` is
  `read`);
* a **client_id** generated at random;
* OAuth 2.0 ticked.

Nothing is created until **Create** is pressed. The document is kept on the
entry as `oauthResourceMetadata`, and `oauthResourceMetadataUrl` where it was
fetched.

* **Its `authorization_servers` are compared with this realm's.** Each one that
  is an issuer this realm publishes is shown green; one that is not is a
  warning, and the application can still be created.
* **A fetch follows the federation outbound policy** — `federation.outbound`,
  https with the certificate verified (#171), no redirects,
  `federation.maxResponseBytes`, `federation.outboundTimeoutMs` — and needs
  Admin Write, because the URL is one an administrator names.
* **In product mode** the URL may not resolve to a loopback, private,
  link-local or reserved address (the name is resolved once and the connection
  pinned to the checked address), and a document whose `resource` is not the
  identifier its well-known URL was built from (section 3.3), or is not https,
  is refused. Development mode reports both and imports anyway. A malformed
  document is refused in both modes.
* `signed_metadata` is decoded and shown, and **not verified or applied** —
  this service holds no key for the resource.

`POST /admin-api/applications/load-resource-metadata` does the same for a JSON
caller (`document` or `url`) and returns the proposed application in `plan`;
the create is then `POST /admin-api/applications/create` with those values.

#### Declared families and recorded ones

**`appAllowedProtocol` and `appProtocol` must not be read as one thing.** The
first is declared and editable; the second is what happened, accumulated by the
endpoints, and refused to every form. The drill-down shows them side by side
under *Protocol families*, with a **Declared** column and a **Recorded** one.
The match between them is made on the entry's *kinds* rather than on protocol
labels, because a federation partner's sighting is recorded under whichever
protocol its relationship speaks and would be indistinguishable by label from
an ordinary OAuth client's.

*Recorded* is not the same as *has authenticated*:
`POST /admin-api/applications/create` and the **Register** buttons on
`/admin/saml2` and `/admin/saml11` take a `kind`, so a hand-made entry can be
recorded in a family it has never connected in. The Authentications count
answers that question. Five families — LDAP, SCIM, SPIFFE, mutual TLS and
OpenID4VCI — have no kind at all, because this service records no application
identifier in them; those rows say *never recorded here* rather than *no*.

**Declaring a family grants nothing, and with one exception refuses nothing.**
An application declared for SAML 2.0 alone is still issued an access token at
`/oauth2/token`, and one declared for nothing is treated exactly as it would
otherwise be. The exception is SAML 2.0 in product mode: the per-service-provider
paths `/saml2/metadata/{sp}`, `/saml2/sso/{sp}` and `/saml2/slo/{sp}` answer
only for a registered service provider — an entry of that kind, or one declared
for SAML 2.0 (#112) — see [SAML 2.0 Web Browser SSO](saml2-sso.md). What
otherwise takes effect is the configuration underneath: redirect URIs, grant
types, scopes and the secret.

### CORS: which pages may read an answer

CORS is an **allowlist on every path**, in both modes. An application's
**`appCorsOrigin`** — a list of exact origins such as
`https://spa.example.com`, no path, no wildcard — is where a third-party origin
goes. An origin is echoed back when:

| The request | The origin must be |
|---|---|
| comes from this service's own origin — the address it was made to, `global.publicBaseUrl`, the embedded debugger, or `global.corsOrigins` | nothing more: always allowed |
| **names a client** — a `client_id` in the query or body, a `client_assertion`'s `sub`, `/oauth2/register/{client_id}`, a Basic user name, a JWT access token's `client_id` or `azp`, a GNAP instance reference | listed in **that application's** `appCorsOrigin`. A name no application answers to gets no CORS header at all, so a page sees a CORS error rather than `invalid_client` |
| **names no client** — discovery, a JWKS, a DID document, credential issuer metadata, and **every preflight** (which carries no body and no `Authorization`) | listed by **any** application in the realm |

**An empty list allows no third-party origin.**

* Nothing sends `Access-Control-Allow-Credentials`.
* The answer exposes `WWW-Authenticate`, `DPoP-Nonce`, `Location`, `Link`,
  `Replay-Nonce` and `Retry-After`.
* Every response carries `Vary: Origin`.
* A navigation (a SAML or WS-Federation form post) is left alone.
* In RFC 9700 mode `/oauth2/authorize` gets no CORS header for anyone.

Values are stored normalised (`HTTPS://App.Example.com:443/` is held as
`https://app.example.com`), and a path, `*`, `null` or a user name is refused
(`STS-REG-0150`). Set it from the application's page,
`POST /admin-api/applications/add` with `attribute: appCorsOrigin`, or
`ldapmodify`; RFC 7591 registration has no member for it. A withheld header is
logged as `STS-HTTP-0019` (a preflight), `STS-HTTP-0020` (no client named),
`STS-HTTP-0021` (unknown client) or `STS-HTTP-0022` (the client does not list
the origin).

## Development and product mode

| | Development | Product |
|---|---|---|
| A client's redirect URIs | matched exactly in RFC 9700 mode; otherwise an address is observed and recorded | matched exactly (product implies RFC 9700 mode) |
| SAML ACS and WS-Federation reply addresses | recorded, and an observed address is marked | an address nobody registered is refused until confirmed |
| The client secret and declared authentication method | checked in RFC 9700, OAuth 2.1 and FAPI mode | checked |
| An unknown `client_id` | accepted, and an entry is recorded | refused |
| Software statements from an undeclared issuer | refused (both modes) while `oauth2.softwareStatementRequireTrustedIssuer` is on | the same; a trusted statement also opens a closed registration endpoint |
| RFC 9728 import from a URL | internal addresses and a mismatched `resource` are reported, then imported | refused |
| Credential attributes over LDAP | readable by a search | never returned by a search, filter or compare |
| SAML 2.0 per-SP paths for an unregistered SP | answered | refused |
| CORS | the allowlist | the allowlist |

See [What is not checked](what-is-not-checked.md) for the full picture.

## Configuration

The live source for every setting is its console page and
`GET /admin-api/config`; this table is a copy of rows in `common/config.js`.

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `applications.max` | `STS_APPLICATIONS_MAX` | `500` | yes | How many entries may live under `ou=applications`. Past it a new application is refused and warned about rather than an old one evicted; separate from `ldap.maxEntries`. |
| `applications.seedInternal` | `STS_APPLICATIONS_SEED_INTERNAL` | `true` | no | Seed this service's own surfaces (console, portal, management API, and the debugger's two clients) as applications at startup. |
| `portal.applicationScanLimit` | `STS_PORTAL_APPLICATION_SCAN_LIMIT` | `1000` | yes | How many registry entries `/portal/applications` asks the issuance policy about for one person before it stops. |
| `global.corsOrigins` | `STS_CORS_ORIGINS` | empty | yes | Origins CORS treats as this deployment's own, beside its listen addresses, `global.publicBaseUrl` and the embedded debugger. A value that is not an origin is ignored and logged. |
| `oauth2.softwareStatementRequireTrustedIssuer` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRE_TRUSTED_ISSUER` | `true` | yes | Refuse a software statement whose issuer nothing in the realm trusts (`unapproved_software_statement`). Off, it is accepted unverified and its claims lose to the JSON. |
| `oauth2.softwareStatementOpensRegistration` | `STS_OAUTH2_SOFTWARE_STATEMENT_OPENS_REGISTRATION` | `true` | yes | A trusted statement is accepted where registration is otherwise closed (product mode with `oauth2.openRegistration` off). |
| `oauth2.softwareStatementRequired` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRED` | `false` | yes | Refuse a registration or update that carries no statement. |

`adminApi.clientSecret` pins the management API client's secret; it is on
[Management API](management-api.md#configuration).

## Design decisions

* **The entries are the registry.** A cache in front of the directory would be
  a second store, and an operator's `ldapmodify` would be ignored by the one
  check that matters.
* **The key is the identifier, not the protocol.** An application is one entry
  that accumulates kinds rather than being filed twice, which is what a
  federation relationship over several protocols needs.
* **There is no *Kind* select on the create page.** A family is *declared*
  and a kind is *derived*, written when a protocol recognises the identifier,
  so a select would let a form assert a sighting that had not happened. The
  kinds fill themselves in as the application is used.
  `POST /admin-api/applications/create` still accepts `kind`, because the
  SAML **Register** buttons pass one, and that is a protocol module's statement
  rather than a person's guess.
* **Nothing refuses a protocol because a family was not declared** (bar the
  SAML 2.0 product-mode case above). Refusing a protocol in development would
  remove a test case rather than add one.
* **One value per line, not per comma**, because a redirect URI may contain a
  comma and may not contain a newline.
* **`entryDN` is computed, not stored**, so it cannot go stale when an entry
  is renamed.
* **Seeded entries are left alone once they exist**, and a deleted one stays
  deleted for as long as the directory remembers it.

## In the running service

| Where | What |
|---|---|
| `/admin/applications` | The registry: list, filter, drill-down, and the edit actions. `GET /admin-api/applications`, `POST /admin-api/applications/{action}` |
| `/admin/applications/new` | Create an application, with its families, identifiers, redirect URIs and an RFC 9728 import. `GET /admin-api/applications/new` |
| `/admin/ldap/applications` | The entries as the directory holds them, and the published schema |
| `/admin/delegation` | Delegated permissions defined and granted on application entries ([Admin console](admin-console.md#delegated-permissions)) |
| `/admin/consent` | Global consent on application entries, and per-person consent |
| `POST /oauth2/register` | RFC 7591 registration, which writes an entry |
| `/portal/applications` | The applications a signed-in person may use |

## Related

* [Admin console](admin-console.md)
* [Management API](management-api.md)
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md): registration, scopes, consent
* [Security profiles](oauth-security.md): RFC 9700 mode
* [LDAP](ldap.md) and [LDAP schema](ldap-schema.md)
* [Federation](federation.md)
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
