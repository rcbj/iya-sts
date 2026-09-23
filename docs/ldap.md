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
the stored entry only once every change has been accepted. `deleteOldRdn` on a
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
verification off. **No client certificate is asked for on 636.** The certificate
is re-keyed on 636 whenever the listener certificate is re-issued, for example
after a new Root is built on `/admin/pki`.

The two listeners bind separately. "389 is up and 636 is not" is an ordinary
outcome, for example on a host run that is not root. A listener that fails to
bind does not stop the service. The failure is recorded and shown on
`/admin/ldap/service`, which is the only way to tell a running listener from one
whose port another process holds. Both sockets bind `global.host`, and LDAPS
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

* an add whose parent does not exist is `noSuchObject` (32);
* a delete of an entry with children is `notAllowedOnNonLeaf` (66);
* a modify `delete` of an absent attribute is `noSuchAttribute` (16);
* deleting an attribute's last value deletes the attribute;
* an add under `ou=users` whose username is already taken is
  `entryAlreadyExists` (68). This rule is the service's own, not the protocol's.

**Referential integrity is deliberately not enforced.** Deleting a person leaves
their DN in every group that lists them. `/admin/groups` reports those dangling
members separately.

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
| Bind | An anonymous bind is `inappropriateAuthentication` (48). **Any bind on 389** is `confidentialityRequired` (13). A DN with an empty password is `unwillingToPerform` (53). A DN or address past its failed-bind limit is 53, even with the right password. After those checks the password is verified against the entry's `userPassword`, and a wrong one is 49 | Every bind succeeds: any DN, any password, anonymous, on 389 and 636 alike. The exceptions are the password `invalid` and a disabled account, which get 49 |
| Read | A read needs a bind (`insufficientAccessRights`, 50). The root DSE can be read first | No restriction |
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

**What product mode still does not decide** is what each bound identity may
read. Anybody who has bound reads every non-credential attribute of every entry
in the realm. See [what is not checked](what-is-not-checked.md).

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
  client's error handling is built around.
* **Schemaless, with the rules whose absence would teach something false.** A
  directory is still a tree, a leaf is still a leaf, and one person is still one
  entry. Inventing a schema would hide the difference from a real directory
  instead of stating it.
* **No referential integrity.** It is a feature of some directories, not of the
  protocol. A dangling group member is the honest result, and the console
  reports it.
* **Two ports rather than StartTLS.** StartTLS is an extended operation, ldapjs
  implements none, and LDAPS on 636 is what most clients speak.
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

## In the running service

* **Protocols → LDAP / LDAPS** (`/admin/ldap`): what the sockets are set to (the
  ports, the base, auto-creation and the two ceilings), with every `ldap.*`
  setting.
* **Directory → The directory service** (`/admin/ldap/service`): whether 389 and
  636 actually bound, how many entries are held, whether they persist, the bind
  policy, and the structural rules.
* **Directory → Every entry** (`/admin/ldap/directory`): the whole store, DN by
  DN, with where each entry came from (seeded, added over LDAP, or created
  because somebody authenticated) and every attribute. The filter searches whole
  entries, not only DNs.
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
