---
title: LDAP
---

# LDAP

iya-sts runs an **embedded LDAP v3 directory**
([RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)) on two raw sockets: TCP
389 in the clear and TCP 636 over TLS (LDAPS). It is not a side feature. The
directory is the store for people, groups, applications, federation partners,
roles, policies, password policies and the SPIFFE registry, so what any other
protocol here reads about somebody is what an `ldapsearch` shows. Every
[trust realm](trust-realms.md) has a directory tree of its own, behind the same
two sockets.

## Features

### Operations

The directory implements simple bind, unbind, add, delete, modify, modifyDN,
compare and search. Search takes
[RFC 4515](https://www.rfc-editor.org/rfc/rfc4515) filters and all three scopes,
and there is a root DSE. Result codes 0, 2, 4, 11, 16, 32, 49, 66 and 68 can all
be produced, along with the product-mode refusals below.

A modify is **atomic**. The changes are applied to a copy, and the copy replaces
the stored entry only once every change has been accepted — applying them in
place and rolling back on failure is the same thing written so that a bug leaves
half a change behind. `deleteOldRdn` on a
modifyDN is honoured, as RFC 4511 section 4.9 requires.

There is no StartTLS, no SASL and no extended operation. The directory is built
on the [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs) fork, and ldapjs
implements none of those. LDAPS on 636 is the encrypted way in.

### Two sockets, one directory

Port 636 is the **same directory over TLS**: the same handlers, the same store
and the same rules. It presents the certificate the main HTTPS port presents, so
one truststore covers both. `GET /tls/server-certificate` returns that
certificate followed by its chain and this service's Root:

```bash
curl -k -s https://localhost:8081/tls/server-certificate > /tmp/sts.pem
LDAPTLS_CACERT=/tmp/sts.pem ldapsearch -H ldaps://localhost:636 -x \
  -D "cn=admin,dc=example,dc=com" -w 'password!' \
  -b "dc=example,dc=com" "(objectClass=*)"
```

The certificate is regenerated on every start, unless `tls.certificateFile`
supplies one, so fetch it again after a restart rather than switching
verification off — `LDAPTLS_REQCERT=never` is the habit that endpoint exists to
avoid, and here it would also hide the one thing on this listener worth
checking. The certificate is re-keyed on 636 whenever the listener certificate
is re-issued, for example after a new Root is built on `/admin/pki`.

**No client certificate is asked for on 636.** This listener proves the
*server* to the client and nothing more; a certificate offered to it is not
requested and would not be a login if it were. Signing in with a client
certificate is the main HTTPS port's business (`GET /tls/sign-in`, see
[TLS](tls.md)). `/admin/ldap/service` says this, so nobody has to work out why
the certificate they configured was never sent.

**TLS does not make a bind checked.** What 636 adds is that the password is not
on the wire in the clear. In development mode it is still not verified — "it is
over TLS" is exactly the sentence people substitute for "it is authenticated".

The two listeners bind separately. "389 is up and 636 is not" is an ordinary
outcome, for example on a host run that is not root. A listener that fails to
bind does not stop the service. The failure is recorded and published on
`GET /admin/ldap/service` — `listening` and `listenError` for 389, and a `tls`
object carrying `ldaps`, `port`, `listening` and `error` for 636 — because that
page is HTTP and answers 200 whichever of them is up; it is the only way to tell
a running listener from one whose port another process (the host's own `slapd`,
say) holds. The console's user page reads the same fields and warns in three
cases rather than two, because telling somebody no client can connect while
LDAPS is answering costs them an afternoon. Both sockets bind `global.host`, and LDAPS
takes `tls.minVersion` and `tls.ciphers`. With `global.proxyProtocol` set to
`v2`, both sockets read a PROXY protocol header first, so the audit log and the
bind rate limit see the client's real address.

### A tree per trust realm, named by DN

Each realm's directory is rooted at the
[RFC 2247](https://www.rfc-editor.org/rfc/rfc2247) mapping of its DNS domain.
The default realm's domain is `global.domain` (`example.com`, so
`dc=example,dc=com`). A realm created without a domain of its own gets
`<id>.<global.domain>`, and a realm's domain is fixed when the realm is created.

```
dc=example,dc=com            the default realm
dc=acme,dc=example,dc=com    realm "acme", created with no domain
dc=iyasec,dc=io              a realm whose domain is iyasec.io
```

LDAP has no path or header to carry a realm in, so **the DN is the realm**. An
operation is answered in the realm whose base contains the DN it names. Where
one realm's domain sits inside another's, the deepest base wins. The root DSE
publishes one `namingContexts` value per realm, and a DN outside every realm's
base is refused. **A modifyDN may not move an entry between realms.** That is
refused with `affectsMultipleDSAs` (71). Each realm's entries are in a separate
store, so a subtree search from one base never returns another realm's entries.

### The containers

Every realm's tree has the same containers under its base:

| Container | What it holds |
|---|---|
| `ou=users` | people, and every identity that is the subject of a credential: a TLS client certificate, a DID, a SPIFFE workload |
| `ou=groups` | groups (`groupOfNames` and the other group classes) |
| `ou=applications` | the application registry: OAuth clients, relying parties, SAML service providers, Kerberos services, GNAP clients |
| `ou=federations` | federation relationships with foreign identity services |
| `ou=roles` | role membership |
| `ou=policies` | the XACML policy repository |
| `ou=peps` | remote XACML Policy Enforcement Points |
| `ou=passwordPolicies` | password policy profiles |
| `ou=spiffe` | SPIFFE registration entries (`ou=entries`) and attested agents (`ou=agents`) |
| `ou=trustAnchors` | the client-certificate truststore, in the default realm only |

`ou=crl` is created when a CRL is first published. The containers are seeded in
both modes. **Nothing caches these registries.** An `ldapmodify` of an
application's `oauthRedirectUri` changes which redirect URI is accepted on the
next request. An `ldapmodify` of an entry under `ou=federations` is a
**security change**, because `fedSigningCertificate` decides whose assertions
this service believes.

### An entry for everybody who authenticates

With `ldap.autocreateUsers` on (the default), an entry appears at
`uid=<name>,ou=users,<base>` the first time somebody authenticates through any
protocol here. **One person is one entry**, however they arrive. `alice`,
`alice@REALM` and her `sub` all name one entry, and a client certificate whose
subject CN is `alice` folds onto that entry too. A DID or a SPIFFE ID, which
names nobody by itself, is filed under a name made from a digest of it, with the
identifier on the entry as `didSubject` or `spiffeSubject`. An LDAP bind never
creates an entry, because the DN it presents already names one.

An add under `ou=users` for a username that another entry already answers to is
refused `entryAlreadyExists` (68), whichever door it comes through: an LDAP add,
the console, `/admin-api` or [SCIM](scim.md).

Beside the person's own attributes, the directory records what this service
learned about them. The names are this service's own, not schema:

* `authnMethod`, `mfaAuthenticated` and `mfaLastAuthTime`: how they
  authenticated, where the protocol said so.
* The `x509*` attributes: a verified client certificate or an issued X509-SVID.
* `oauthConsent`: the scopes they consented to.
* `federationAttribute`: which attributes came from a federation partner.
* `pwdAccountLockedTime`: the account is **disabled**. Every door refuses the
  person, and everything they hold is ended. See
  [signing out](signing-out.md).

In development mode an auto-created person is also given an invented `cn`, `sn`,
`givenName`, `displayName` and `mail`. Product mode invents nothing.

How each kind of identity — a name, a certificate, a DID, a SPIFFE ID — is
placed, and what the `authnMethod` attributes mean exactly, is under
[How an identity becomes an entry](#how-an-identity-becomes-an-entry) below.

### `entryUUID`: the stable identifier

Every entry carries an operational `entryUUID`
([RFC 4530](https://www.rfc-editor.org/rfc/rfc4530)). The value is kept through
a rename and is new when an entry is deleted and created again. **A person's
`sub` in every token is `urn:uuid:<entryUUID>`**, and a SCIM `id` is the bare
value. It is returned only when a search asks for it by name. No client can
write it in either mode (`STS-LDAP-0076`, result 19). In product mode
`createTimestamp`, `modifyTimestamp` and `entryDN` are read-only too, for
administrators as well.

### Schemaless, with five rules

The directory is **schemaless on purpose**. No object class is enforced, no
attribute syntax is checked, and no `must`/`may` is consulted.
`/admin/ldap/service` says so. Five rules are enforced anyway:

* an add whose parent does not exist is `noSuchObject` (32) — a directory is a
  tree, and a client that has never seen this refusal will write its first
  entry into a real directory and not understand the error;
* a delete of an entry with children is `notAllowedOnNonLeaf` (66);
* a modify `delete` of an absent attribute is `noSuchAttribute` (16);
* deleting an attribute's last value deletes the attribute, since an LDAP
  attribute always has at least one value (RFC 4511 section 4.1.7) — which is
  why a second delete of the same attribute is a 16 rather than a no-op;
* an add under `ou=users` whose username is already taken is
  `entryAlreadyExists` (68). This rule is the service's own, not the protocol's.

A real directory would refuse most of what this one accepts; where that matters
it is a difference a client developer should be told about, rather than one
hidden by an invented schema.

**Referential integrity is deliberately not enforced.** Deleting a person leaves
their DN in every group that lists them. It is a feature of some directories and
not of the protocol — OpenLDAP needs an overlay for it and Active Directory does
it in the DSA — so the dangling member is the honest result, and it is what a
`member`-based group search then shows. `/admin/groups` reports those dangling
members separately from the ones that resolve, rather than one number that
would make a group of seven whose members are five look untouched, and the
audit row of the delete records how many memberships it left dangling.

### Search size limit

A search that matches more than `ldap.sizeLimit` entries (500) returns that many
entries and then `sizeLimitExceeded` (4). The entries already sent are a valid
partial answer, and the result code is how the client knows the answer is
partial. Page through a large directory with a narrower filter or base.

### Size of the directory

`ldap.maxEntries` (2000) caps how many entries the process holds, counted across
every realm. When the directory is full, a create is refused through any door.
Over SCIM that refusal is a 500.

### Groups

What counts as a group is two rules: an entry under `ou=groups`, **or** an entry
with a group object class wherever it sits. `member` and `uniqueMember` hold DNs
and `memberUid` holds a bare name. Nesting is shown and never expanded, and
nothing maintains `memberOf`.

**A group grants nothing by being a group.** The exceptions are the groups a
role or roster names: the console's `cn=admin-read` and `cn=admin-write`, the
XACML `REMOTE_PEPS` and `XACML_USER` groups, and a configured role's members.
Tokens can carry the groups a person is in. See the `groups.*` settings below.

### The password policy is a directory entry

A realm's password policy is the entry `cn=default,ou=passwordPolicies,<base>`.
It is not seeded: an absent entry means the built-in defaults apply. Its
attributes are:

| Attribute | Default | Meaning |
|---|---|---|
| `pwdMinLength` | 12 | minimum length |
| `pwdInHistory` | 5 | how many previous passwords may not be reused (the current one is refused as well) |
| `stsPwdMinSymbols` | 1 | how many symbols are required |
| `stsPwdRequireUppercase` | TRUE | an uppercase letter is required |
| `stsPwdRequireDigit` | TRUE | a digit is required |
| `stsPwdGeneratedLength` | 20 | the length of a generated password |

The `pwd*` names are those of
[draft-behera-ldap-password-policy](https://datatracker.ietf.org/doc/html/draft-behera-ldap-password-policy),
which OpenLDAP's ppolicy overlay reads. The draft defines no composition rule,
so those attributes are `stsPwd*`. Edit the policy on **Directory → Policies**
(`/admin/policies`), or with an `ldapmodify`.

**An LDAP add or modify of `userPassword` is hashed**, in both modes. The value
is stored as a scrypt hash and never as sent. A person's entry also carries
`pwdHistory` (previous hashes, in the draft's form) and `pwdChangedTime`. In
product mode the policy is enforced on an LDAP write, and a refusal is
`constraintViolation` (19). A password set over LDAP also gives the person
[Kerberos](kerberos.md) keys.

### Signing out closes the connection

A bind sets the authorization state of a **connection** (RFC 4511 section 4.2),
so the connection is the session. A [global sign-out](signing-out.md) at
`/logout` closes every connection, on 389 and 636, bound as that person
(`logout.ldapDisconnect`). There is no Notice of Disconnection. The socket is
closed.

## Development and product mode

| | Product | Development |
|---|---|---|
| Bind | An anonymous bind is `inappropriateAuthentication` (48). **Any bind on 389** is `confidentialityRequired` (13). A DN with an empty password is `unwillingToPerform` (53). **Only a person binds**: a DN that is not under `ou=users` — an application's, a federation's — is 49 before its password is read; an application reads the directory through [SCIM](scim.md) instead. A DN or address past its failed-bind limit is 53, even with the right password. After those checks the password is verified against the entry's `userPassword`, and a wrong one is 49. A person who holds or must hold a second factor is refused their own password with the same 49 (a bind cannot ask for the second factor) and binds with an [app password](authentication.md#the-password-only-doors-and-app-passwords) scoped to `ldap` | Every bind succeeds: any DN, any password, anonymous, on 389 and 636 alike. The exceptions are the password `invalid` and a disabled account, which get 49 |
| Read | A read needs a bind (`insufficientAccessRights`, 50). The root DSE and a base read of a CRL entry can be read first. What a bound identity may then read is below | No restriction |
| Who reads what | Admin Read or Admin Write reads everything in scope (the default realm's roster: every realm; a realm's own: that realm). Anybody else reads **their own entry**; of **other people**, only `ldap.directoryReadableAttributes` (**none by default**); a **group** only if they are in it, and then `cn`, `description` and `objectClass` (members too with `ldap.groupMembersReadable`); and the containers by name. Applications, federations, policies, roles, trust anchors and SPIFFE registrations are invisible. An entry they may not see answers `noSuchObject` (32), exactly as a missing one; an attribute they may not read is absent from the result and **cannot be matched by a filter**; a compare of one is 50 | Everything |
| Credentials on the wire | A search never returns a secret attribute (`userPassword`, client secrets, reset tokens, private keys). A filter cannot match on one, and a compare against one is refused. Administrators are included | Returned like any attribute |
| Write | Anonymous writes nothing. Admin Write in the default realm writes anything, and a realm's own administrator writes that realm. Anybody else may modify only the attributes in `ldap.selfWritableAttributes`, on their own entry. Refusals are 50 | Any connection may add, modify, rename or delete any entry in any realm |
| `userPassword` | Held to the password policy (19). A pre-hashed `$scrypt$` value is refused, and so is a change to `pwdHistory` or `pwdChangedTime` | Hashed. A pre-hashed value is kept as given, which is how a directory moves between two instances |
| Seed data | The containers only. The `roles.remotePepGroup` and `roles.xacmlUserGroup` groups are created **empty** | `cn=admin`, alice, bob and carol, `cn=developers`, `cn=directory-admins`, and the two privileged identities `cn=remote-pep-1` and `cn=xacml-user-1` |
| Invented attributes | None | A persona for each auto-created person |

The failed-bind limit is the sign-in screen's: `security.rateLimitPerIdentity`
and `security.rateLimitPerAddress` inside `security.rateLimitWindowS`. **Only
failures count**, so a connection pool that binds fifty times at once is not
locked out. On a cluster the count is shared across nodes.

Product mode logs a warning at startup while `ldap.plainListener` is on. A
verified bind on 389 is a real password sent in the clear, so turn 389 off in
production. With 389 on, product mode answers only the root DSE there.

### What a bound identity may read (product mode)

A person bound over LDAPS reads their own entry and, by default, **nobody
else's** — another person's DN answers `noSuchObject` exactly as a DN that does
not exist, so the directory cannot be walked for usernames. To publish an
address book, list the attributes in `ldap.directoryReadableAttributes`, for
example `objectClass,cn,displayName,uid,mail`.

> **Warning.** Widening `ldap.directoryReadableAttributes` shows every person
> in the realm to every other person who has a password: a list of usernames
> and addresses to phish or to guess passwords against. `telephoneNumber` and
> the like are personal data, and `memberOf` or `employeeType` say who the
> administrators are. `ldap.groupMembersReadable` has the same effect for the
> groups a person is in — on the console role groups, it names every
> administrator.

A filter is evaluated against only what the reader may read, so
`(telephoneNumber=555*)` cannot find another person's number a digit at a time,
and a compare of an attribute the reader may not read is refused with 50
whether or not the entry holds it. The console, `/admin-api` and SCIM read the
directory through the service itself, never through this socket, and have
gates of their own; a SCIM client with `scim:read` reads the whole realm, as a
provisioning client must.

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `ldap.port` | `LDAP_PORT` | `389` | restart | The plain LDAP listener. A host run that is not root fails to bind 389; the failure is recorded, not thrown. |
| `ldap.tlsPort` | `LDAPS_PORT` | `636` | restart | The LDAPS listener, presenting the service's TLS certificate; it binds independently of 389. |
| `ldap.plainListener` | `LDAP_PLAIN_LISTENER` | `true` | restart | Whether the plain listener starts at all; off leaves LDAPS as the only way in, which product mode wants. |
| `ldap.autocreateUsers` | `LDAP_AUTOCREATE_USERS` | `true` | yes | Creates `uid=<name>,ou=users,<base>` the first time somebody authenticates through any protocol. |
| `ldap.maxEntries` | `LDAP_MAX_ENTRIES` | `2000` | yes | How large the directory may grow, across every realm in the process. |
| `ldap.sizeLimit` | `LDAP_SIZE_LIMIT` | `500` | yes | The server-side search size limit, past which a search ends with `sizeLimitExceeded`. |
| `ldap.selfWritableAttributes` | `LDAP_SELF_WRITABLE_ATTRIBUTES` | `telephoneNumber,mobile,homePhone,displayName,preferredLanguage,postalAddress,street,l,st,postalCode,userPassword` | yes | In product mode, the attributes a person bound as themselves may modify on their own entry; empty allows none. |
| `ldap.directoryReadableAttributes` | `LDAP_DIRECTORY_READABLE_ATTRIBUTES` | empty | yes | In product mode, the attributes a person may read on **other** people's entries; empty (the default) means they read only their own. See the warning above before widening it. |
| `ldap.groupMembersReadable` | `LDAP_GROUP_MEMBERS_READABLE` | `false` | yes | In product mode, whether a person may read the member list of a group they are in. See the warning above. |
| `groups.claim` | `STS_GROUPS_CLAIM` | `true` | yes | Puts the person's directory groups in every access token, ID Token and SAML assertion, omitted for somebody in no group. |
| `groups.claimName` | `STS_GROUPS_CLAIM_NAME` | `groups` | yes | The claim or SAML attribute name the groups are carried under. |
| `groups.claimValue` | `STS_GROUPS_CLAIM_VALUE` | `cn` | yes | Whether each group is named by its common name or its whole DN. |
| `groups.claimFromMemberOf` | `STS_GROUPS_CLAIM_FROM_MEMBEROF` | `true` | yes | Whether a group named in the person's own `memberOf` counts when the group does not list them back. |
| `credentials.factorScanLimit` | `STS_CREDENTIALS_FACTOR_SCAN_LIMIT` | `5000` | yes | How many entries the second-factor columns on `/admin/users` and `GET /admin-api/mfa` read before they stop. |
| `logout.ldapDisconnect` | `LOGOUT_LDAP_DISCONNECT` | `true` | yes | Whether a sign-out closes the directory connections bound as that person. |
| `global.domain` | `STS_DOMAIN` | `example.com` | restart | The default realm's DNS domain, whose RFC 2247 mapping is its directory base. |

The bind rate limit uses `security.rateLimitPerIdentity`,
`security.rateLimitPerAddress` and `security.rateLimitWindowS`. The console's
two role groups are named by the `admin.*` settings, and the XACML groups by
`roles.remotePepGroup` and `roles.xacmlUserGroup`.

This table is a copy of the rows in the service's settings table. The live
source is **Protocols → LDAP / LDAPS** (`/admin/ldap`), where the `ldap.*`
settings are drawn, and `GET /admin-api/config`. `POST /admin-api/config/set`
changes one, and a runtime setting can be set per trust realm. See
[Configuration](configuration.md) for how a value is resolved.

## Design decisions

* **The directory is the store, not a copy of one.** SCIM, the console,
  `/admin-api` and LDAP write the same entries, and nothing caches them. A value
  changed with `ldapmodify` is what the next token, redirect or policy decision
  reads.
* **The realm is named by the DN, not by a port.** An LDAP request carries no
  path or header, and a listener per realm would make a realm reachable by port
  as well as by name. Putting the realm in the base DN makes
  `ldapsearch -b "dc=acme,dc=example,dc=com"` mean what it says, and new realms
  are reachable at once.
* **Every bind succeeds in development, except `invalid`.** A mock that checked
  passwords could not be pointed at by a client that has none. The reserved
  value keeps `invalidCredentials` (49) reachable, and 49 is the code an LDAP
  client's error handling is built around: a directory that could not produce
  one would make "the bind failed" untestable. It is the same convention the
  password grant, WS-Trust and the WS-Federation sign-in screen follow.
* **Schemaless, with the rules whose absence would teach something false.** A
  directory is still a tree, a leaf is still a leaf, and one person is still one
  entry. Inventing a schema would hide the difference from a real directory
  instead of stating it.
* **No referential integrity.** It is a feature of some directories, not of the
  protocol. A dangling group member is the honest result, and the console
  reports it.
* **Two ports rather than StartTLS.** StartTLS is an extended operation
  (RFC 4511 section 4.14) that upgrades a connection already in progress,
  ldapjs implements none, and LDAPS on 636 is what most clients speak. Which of
  the two is the standardised one is the opposite of what the port numbers
  suggest: RFC 4513 specifies StartTLS, and left `ldaps://` as the de-facto
  scheme it already was.
* **Two server objects, one set of handlers.** ldapjs chooses between a plain
  and a TLS server at construction, so LDAPS is a second server object and every
  handler is registered on both. The failure this prevents is a handler that
  lands on one listener and not the other — a search that works on 389 and fails
  on 636, read as a TLS fault when it is not. Each socket keeps its own port,
  its own bind failure and its own answer to "are you up".
* **One certificate for every TLS socket.** LDAPS presents the main port's
  certificate rather than a second one, so one anchor, fetched once, verifies
  every socket. Two keypairs would mean an `ldapsearch` that fails with
  `unable to get local issuer certificate` against a truststore built for the
  HTTPS port — an error that names nothing and reads as a broken directory.
* **Write authorization reuses Admin Write.** The console, the management API
  and SCIM already decide who may change what this service holds. A second
  roster for the socket would drift from the first.
* **Self-service writes use an allowlist.** The directory is schemaless, and the
  attributes that matter look ordinary. `memberOf` grants console roles,
  `employeeType` feeds the seeded XACML policy, and `mail` and `cn` are asserted
  in tokens.
* **Credentials never leave on the wire in product mode, even to an
  administrator.** Every reader that needs a secret goes through the service's
  own functions. A socket that handed an administrator every client secret would
  make one stolen administrator password worth every application's credentials.
* **The bind rate limit counts failures only.** Counting successes would lock a
  connection pool out of its own directory. A success clears its DN's counter
  and never its address's.
* **`entryUUID` is the subject.** A rename does not change a person's `sub` or
  SCIM `id`, and a name deleted and reused does not inherit somebody else's.
* **A size-limited search always ends.** It ends with `sizeLimitExceeded` after
  the entries it sent, because RFC 4511 section 4.5.2 makes the final result
  mandatory.
* **A disabled account is `pwdAccountLockedTime`**, the draft's standard name
  for an administrative lock. It is enforced at every door, not only at a
  password bind.
* **Listeners start after the service loads, and a failure is recorded.** A port
  already held by the host's own `slapd` must not stop the rest of the service.

## How an identity becomes an entry

With `ldap.autocreateUsers` on, an entry is grown at `uid=<name>,ou=users,<base>`
the first time anybody authenticates through **any** family here — the sign-in
screen, WS-Trust, WS-Federation, a Kerberos AS-REQ, a passwordless WebAuthn
assertion. Every one of those reaches the directory through the single point at
which a credential is ACCEPTED, so it is one rule and not one per protocol. A
failure to write the entry is caught and logged: **a directory must never be
able to fail an authentication.**

Two identities are skipped on purpose:

* **An LDAP bind** seeds nothing, because the identity a bind presents is a DN
  that already names an object in this very directory —
  `uid=cn=admin\,dc=example…` would be nonsense, and this service's own binds
  would grow the directory without bound.
* **An OAuth client** seeds nothing: a client is not a person, and `ou=users` is
  for people.

### One entry per person, however they get in

`rcbj` at the sign-in screen, `urn:uuid:<entryUUID>` in a token, `rcbj@STS.MOCK`
in a Kerberos AS-REQ and `rcbj` on a WS-Security `UsernameToken` are one entry.
The subject is resolved through the directory, and the realm (and the legacy
`urn:sts:user:` prefix an older token may carry) is stripped first, so every
name-shaped family — OAuth 2.0, OpenID Connect, both SAML profiles,
WS-Federation, WS-Trust, Kerberos, SPNEGO — lands on `uid=rcbj,ou=users` and
simply adds a line to its `description`.

Before any entry is named, the directory asks whether this person already has
one, matching on the two things that can carry a username under `ou=users`: the
entry's own **naming RDN value**, whatever attribute type names it, and any
**`uid`** it carries. Case-insensitively, and only among entries directly under
`ou=users`, because the directory is schemaless and placement is the only rule
that cannot be lied to. So a client certificate saying `CN=rcbj` folds onto
`uid=rcbj` rather than building `cn=rcbj` beside it, in either order.

**The same check answers at every other door.** An `ldapadd` under `ou=users`
whose username is already here is `entryAlreadyExists` (68) naming the entry
that holds it — so `uid=rcbj` and `cn=rcbj` cannot both exist, and neither can
`sn=someone` carrying `uid: rcbj`. The console's create form on `/admin/users`,
`POST /admin-api/users/create` and SCIM get the same refusal. Without that the
fold could be undone from the other side in a single operation.

### How they authenticated

Most families say nothing about *how*: `amr` is an OIDC vocabulary, and a
Kerberos AS-REQ, a WS-Trust UsernameToken and an LDAP bind have nothing to put
in it, so nothing is written for them. An absent attribute means "this service
was never told", which is a different claim from "this service checked and it
was one factor". What the sign-in screen does say lands in three attributes,
kept separate because merging them loses one of the three:

* `authnMethod` — every RFC 8176 method this person has *ever* used here,
  accumulated;
* `mfaAuthenticated` — `TRUE` or `FALSE` for the **most recent**
  authentication, overwritten rather than appended;
* `mfaLastAuthTime` — when multi-factor last happened, never cleared.

So a person who used a key yesterday and a password today reads `FALSE` with the
timestamp still there, the honest answer to both questions. A WebAuthn second
factor writes `mfaAuthenticated: TRUE` on the entry the password step already
named, not a second entry. A **passwordless** WebAuthn sign-in is recorded as
`authnMethod: hwk` with no `pwd` beside it — the only place a reader can tell it
from a password sign-in afterwards — and `["hwk"]` alone is one factor, so
`FALSE`. These names are this service's own and not schema (there is no
standard attribute for "this account used more than one factor"; Active
Directory's `msDS-*` attributes name something else). Like a group they **grant
nothing** — nothing decides anything on them — and, unlike a group, no token
carries them.

### A client certificate

A verified TLS client certificate's subject is already a DN, so it is not placed
as `uid=<name>`. It goes at the subject itself where that lies under this
directory's base, and otherwise under `ou=users` named by the CN — or, where
that CN is somebody this directory already holds, **onto their existing
entry**. The subject's other RDNs are kept as attributes, and the certificate's
own facts (the whole subject, the issuer, the serial, the validity) are written
as `x509*` attributes, which are this service's names rather than schema. The
console finds such an entry again by the `x509subject` it recorded rather than
by a name, which is exact and stays right if the naming rule ever changes.
[TLS](tls.md) carries the reasoning, including why `userCertificate` is not one
of those attributes.

### A decentralized identifier

Three places hand over a DID: the subject of an issued `ldp_vc` (a `did:jwk`
built from the holder key the wallet proved possession of), whatever DID
presents a credential to the OID4VP Verifier, and the `did:jwk` that
`/did/generate` mints on request. Each gets an entry, which matters most at the
Credential Issuer: OID4VCI lets the authorization server be somebody else, so a
**foreign** access token whose subject this service has never seen is the
ordinary case, and without an entry the credential would describe somebody with
no directory entry to read from.

A DID is neither a DN nor a name but one long opaque string. Writing it out as
`uid=<the did>` is correct and unusable — a `did:jwk` carries a base64url JWK,
so the DN runs to several hundred characters of key material — and a container
of its own would put it outside `ou=users`, where credential attributes are
filled in and group membership is reported. So the entry goes under `ou=users`,
**named by a short digest** — `uid=did-<12 hex of the SHA-256 of the DID>` —
with the identifier kept whole as `didSubject` and its method as `didMethod`
(this service's names; nobody has registered LDAP attributes for DID Core).
**On those entries the `uid` is not the identity; `didSubject` is.** The console
finds the entry by it, and in development the persona that fills a credential's
claims is invented from the DID rather than from the digest.

A DID generally names nobody by itself, but at the Credential Endpoint this
service *does* know who it belongs to: it decides who a credential is about from
the access token and derives the holder's DID from the proved key in one call,
so the DID goes onto **that person's** entry as a `didSubject` value beside
their name. `didSubject` is multi-valued, so a wallet holding several keys for
one person puts several DIDs on one entry. When that DID is later presented to
the Verifier, the entry that records it is found and nothing new is created. A
DID with no link still gets its own digest-named entry, because inventing a
person to attach it to would be worse.

**None of the three is a sign-on**, and each record says so. A presentation to
the Verifier at `/oid4vp/verifier` starts no session and issues no token; it is
*recorded*. (A presentation to `/authn/wallet` is a sign-on, of the entry the
credential was issued for rather than of its DID — see
[OpenID4VP and wallet sign-in](oid4vp.md).) A credential request records that an access token was
presented, not that anybody authenticated; in development mode this service does
not verify one it did not issue, and product mode refuses one it cannot verify.
`/did/generate` records an identity this service *created*, with nothing
presented. The `did:web` that endpoint returns for `?method=web` gets no entry:
it is this service's OWN identity, published at `/.well-known/did.json`, and an
entry for it would file the issuer among the people.

### A SPIFFE identity

Filed exactly like a DID and for the same reasons: `uid=spiffe-<12 hex>,ou=users`,
with the identifier kept whole as a multi-valued `spiffeSubject` and
`spiffeTrustDomain` and `spiffePath` beside it. The entry is found by that
attribute, so one workload arriving three ways (an X509-SVID at the SPIRE Server
API, an agent attesting, a JWT-SVID validated) is **one** entry with one
description line per route. Two differences are deliberate:

* It **never folds onto a person** of a similar name: the last segment of a
  SPIFFE path is exactly the kind of short word (`db`, `web`, `api`) that
  collides with a username, and a workload called `db` is not the DBA.
* It goes under `ou=users`, not `ou=applications`: that container holds what
  this service is *asked about* — the audience of a token — and a SPIFFE
  identity is the **subject** of one, like a machine's TLS client certificate.

**Issuing an X509-SVID also writes the entry.** Every SVID this trust domain
mints writes the certificate onto the holder's entry using the **same six
`x509*` attributes**, in the same strings, that a verified TLS client
certificate writes — two spellings of one DN would be two people on
`/admin/users`. These six are **assigned** rather than appended, because an SVID
is re-minted every half-lifetime; `x509svidsIssued`, `x509firstIssued` and
`x509lastIssued` keep the history. [SPIFFE](spiffe.md) has the rest, including
why `spiffeCredentialStatus` is not a revocation.

### What the entry holds (development mode)

The attributes that make an entry a person — `objectClass`, `uid`, `cn`, `sn`,
`givenName`, `displayName` and `mail` — are written when it is created, and in
development the name in them is an **invented** one rather than the login name
repeated: those are attributes an issued credential asserts, so deriving them
from the login name would make every credential say the login name back. The
`uid` and the DN stay the login name, because those two *are* the identity. On
top of that, every attribute the credential claim set on `/admin/vc` selects and
the entry does not already carry is filled in — a birthdate, a nationality, the
five components of an address — invented from the same username seed, so an
LDAP client and a wallet describe one person. **Nothing already on the entry is
ever overwritten**, which is why seeded people keep their own names and an
operator's `ldapmodify` survives every later sweep. Product mode invents
nothing.

## Every operation is audited

Every operation on the directory is an audit event:
`/admin/audit?category=directory` lists an entry created, deleted, updated,
renamed, searched, compared or bound to, over 389 and 636 alike, with the bound
DN as the actor and the socket as the channel. In product mode a named simple
bind's row says it was verified.

* **No value is ever recorded.** A modify names the attributes it changed,
  because a modify is where a `userPassword` gets set; a compare says whether it
  matched and not what was tried, because comparing against `userPassword` is
  how a client checks a password without binding.
* **What counts as a user is placement**, the same rule `/admin/groups` reports
  by: an add under `ou=users` is a `user.create`, and the identical add one level
  over is a `group.create`. Believing the `objectClass` the client sent would
  file both wrongly in a directory with no schema.
* **A delete records how many memberships it left dangling.** Referential
  integrity is not enforced, so this is the only record of *when* a dangling
  member arrived; `/admin/groups` can show the state but not the moment.

## How an attribute name is spelt

The store lower-cases every attribute name, because `@ldapjs/attribute`
lower-cases a type on the way in — an entry added as `objectClass` comes back
as `objectclass`. That is harmless for matching, since attribute descriptions
are case-insensitive (RFC 4512 section 2.5), and not harmless for *reading*: a
page showing `givenname` where every schema document says `givenName` reads as a
bug. So the directory keeps a table of conventional spellings and puts them back
on the way out.

The table covers about a hundred and fifty names, far more than this service
writes, and that is the point: a client can `add` any attribute it likes, and a
verified client certificate's subject becomes attributes RDN by RDN, so which
types arrive is decided by whoever issued the certificate. The reader who most
needs the conventional spelling is the one looking at an attribute this service
did not write (`seeAlso`, an ordinary RFC 4519 type, is the example that made
the case).

It is two lists split by who defined the name — the standard types, with the
specification named per group (RFC 4519, RFC 4524's COSINE, RFC 2798's
inetOrgPerson, RFC 2307's NIS, RFC 4512's operational and root-DSE attributes,
RFC 4530, RFC 5020, RFC 3045, PKCS#9), and this service's own inventions, each
saying why nothing standard was used. `memberOf` sits in neither: it is
ubiquitous and was never registered by anybody, and its conventional spelling
must not be read as the attribute being maintained — nothing here maintains it.

Each name is written once, as the canonical spelling, and the lower-cased key is
derived from it, so a typo cannot hide in a key. Four sets of spellings reach
the table — the two lists, the credential claim catalogue and the applications
schema — through one function, and a **second spelling of a name already known
is logged as a warning** naming both, first spelling winning. It is a warning
and not a failure, because a table of capitalisations must never stop the
service starting.

## Two ldapjs defects this service routes around

Both are in ldapjs's `SearchResponse.prototype.send()`, and both would hit a
real client built on ldapjs too.

* **A second, case-sensitive attribute filter.** After the handler has chosen
  what to send, `send()` compares each attribute name *lower-cased* against the
  requested list held *exactly as the client sent it*, so a client asking for
  `telephoneNumber` gets back everything it asked for except `telephoneNumber`.
  Every attribute whose conventional spelling has a capital in it is silently
  dropped from a *selective* search, and a search asking for everything looks
  perfect. `send()`'s `nofiltering` argument does **not** turn this off, though
  its documentation reads as if it does.
* **`messageId` defaults to 1.** Passing a `SearchResultEntry` instance avoids
  the filter, but then `send()`'s `if (!entry.messageId)` never fires and the
  next line throws `SearchEntry messageId mismatch` for every search after the
  first on a connection — a search that returns zero entries and ends
  successfully, which reads as an empty directory.

This service builds each result as a `SearchResultEntry` carrying the request's
own `messageId`, which sidesteps both.

## In the running service

* **Protocols → LDAP / LDAPS** (`/admin/ldap`): what the sockets are set to (the
  ports, the base, auto-creation and the two ceilings), with every `ldap.*`
  setting.
* **Directory → The directory service** (`/admin/ldap/service`): whether 389 and
  636 actually bound, how many entries are held, whether they persist, the bind
  policy, and the structural rules.
* **Directory → Every entry** (`/admin/ldap/directory`): the whole store, DN by
  DN, with where each entry came from (seeded, added over LDAP, or created
  because somebody authenticated) and every attribute — which is what lets a
  reader tell an empty directory from a search filter that matched nothing. The
  filter searches whole entries, not only DNs.
* **Application entries**, **Federation entries**, **Role entries**, **Policy
  entries**, **PEP entries** and **SPIFFE entries** (`/admin/ldap/applications`,
  `/federations`, `/roles`, `/policies`, `/peps`, `/spiffe`): each container as
  the directory holds it, with its published attribute schema.
* **Users**, **Groups** and **Policies** (`/admin/users`, `/admin/groups`,
  `/admin/policies`): people, groups with dangling and nested members, and the
  password policy.

These pages need an Admin Read session, because they show client secrets in the
clear. The management API mirrors all of them: `GET /admin-api/ldap`,
`/admin-api/ldap/directory`, `/admin-api/ldap/service` and the rest.
`GET /admin/sts-metadata` cannot list the two raw sockets, because they register
no HTTP route. `/admin/ldap/service` is where they are reported.

Every LDAP failure is recorded under an `STS-LDAP-NNNN` code on the audit row
and the log line, and never sent to a client. See [error codes](error-codes.md).

## Related

* [SCIM](scim.md): provisioning into this directory over HTTP
* [SPIFFE](spiffe.md): the registry under `ou=spiffe`
* [TLS and mutual TLS](tls.md): the certificate 636 presents
* [Trust realms](trust-realms.md)
* [Persistence](persistence.md): where the directory is written down
* [Signing out](signing-out.md) and [sessions](sessions.md)
* [Kerberos](kerberos.md): keys derived from a directory password
* [XACML](xacml.md): policies and PEPs held in this directory
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md)
