---
title: "Configuring LDAP"
---

# Configuring LDAP

This page shows how to set up the embedded LDAP v3 directory and point an
LDAP client such as `ldapsearch` or `ldapmodify` at it. Each recipe covers
the people, groups and settings to create, and what the client then sends.
It is given twice: once as steps in the **admin console** and once as
**Management API** calls.

The values come from this repository's test jobs, and each recipe names the
job it is taken from. Most are `tests/vendored/` jobs, which run against a
service over its own sockets in both development and product mode. A few are
in-process tests in `tests/`, and the recipe says so. Change the names,
passwords and domains to your own.

How the directory *behaves*, and every setting with its default, is on
[LDAP](ldap.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token and the `api` shell helper used
below. The examples here also use plain `curl` for the `GET` calls.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/ldap` | **Protocols → LDAP / LDAPS** | The `ldap.*` settings: ports, the plain listener, the search limits, and who may read and write what in product mode. Saved with **Save LDAP**. |
| `/admin/ldap/service` | **Directory → As the directory holds it → The directory service** | Whether 389 and 636 actually bound, the base DN, the certificate 636 presents, and the bind policy. |
| `/admin/ldap/directory` | **Directory → As the directory holds it → Every entry** | Every entry, DN by DN, with every attribute. |
| `/admin/users` | **Directory → Users** | Create a person (**Create a user** → **Create ›**), and on a person's page set a password or make an app password. |
| `/admin/groups` | **Directory → Groups** | Create a group and add members. |
| `/admin/policies` | **Directory → Policies** | The password policy and the attribute policy. |
| `/admin/rbac` | **Server configuration → Admin roles** | Give somebody Admin Read or Admin Write, which is what lets them read or write the whole directory over LDAP in product mode. |
| `/admin/listeners` | **Server configuration → Listeners** | The **Listener: LDAPS** group: whether 636 asks for or requires a client certificate, and its TLS versions and ciphers. |

The live state of both sockets is `GET /admin-api/ldap/service`. Read it
first when a client cannot connect. It is the only place that says whether a
listener is up, because the page answers 200 either way.

**What development and product mode change.** In development mode every bind
succeeds (any DN, any password, anonymous, on 389 and 636), except the
password `invalid` and a disabled account. Any connection may read and write
anything. Product mode does none of this:
* A bind is verified against the entry's `userPassword`, and only an entry under `ou=users` may bind.
* An anonymous bind is refused (48), and so is any bind on 389 (13, `confidentialityRequired`). Use LDAPS on 636.
* A read needs a bind (50). The root DSE is the one exception.
* A person reads their own entry and nothing of anybody else's, unless `ldap.directoryReadableAttributes` says otherwise.
* Only Admin Write writes. A person may change only the attributes in `ldap.selfWritableAttributes`, on their own entry.
* A secret attribute (`userPassword`, client secrets, private keys) is never returned, even to an administrator.
* A new person must carry what the realm's attribute policy requires: `uid`, `cn` and `sn` always, and by default `givenName` and `mail` too.
* Nothing is seeded but the containers. There is no `cn=admin`, alice, bob or carol.

So in product mode, create the person you will bind as before you connect.
Every recipe below does.

## Trust the LDAPS certificate

Port 636 presents the same certificate as the main HTTPS port.
`GET /tls/server-certificate` returns it with its chain and this service's
Root. Give that file to the client as its CA. `sts_ldaps.js` checks that the
handshake verifies with it and that the two ports present one certificate.

```bash
curl -sk "$BASE/tls/server-certificate" > sts.pem
export LDAPTLS_CACERT=$PWD/sts.pem
```

The certificate's key is kept across a restart only where minted state
persists. In development, fetch the file again after a restart rather than
setting `LDAPTLS_REQCERT=never`.

Then read the root DSE. It answers an unbound connection in every mode, and
its `namingContexts` lists every realm's base:

```bash
ldapsearch -H ldaps://localhost:636 -x -b "" -s base namingContexts
```

Use `ldaps://`, not `-Z` or `-ZZ`. The directory has no StartTLS.

## Put a person in the directory and bind as them

The person is created through the management API with a real password, as
product mode requires of anybody who binds. Then they bind over LDAPS and
read their own entry. Taken from `sts_ldaps.js`; the job adds a run stamp to
the name and a random part to the password.

**Console:**
1. On **Directory → Users**, under **Create a user**, click **Create ›**.
2. Under **Who they are**, set **Username** to `ldaps-run1`.
3. Under **How they get in**, choose **A password I type**, and type the password in **Password** and **Again**.
4. Under **What is known about them**, fill in **Common name** (`cn`) `LDAPS ldaps-run1`, **Given name** `LDAPS`, **Surname** `ldaps-run1`, **Display name** `LDAPS ldaps-run1` and **Email address** `ldaps-run1@ldaps.test`.
5. Click **Create the user**.

**API:**
```bash
api users/create '{"username":"ldaps-run1","invent":false,
  "credential":"password","password":"Ldaps-Example-Passw0rd-Aa1!",
  "attributes":{"cn":"LDAPS ldaps-run1","givenName":"LDAPS","sn":"ldaps-run1",
                "displayName":"LDAPS ldaps-run1","mail":"ldaps-run1@ldaps.test"}}'
```

The answer's `dn` is the entry, `uid=ldaps-run1,ou=users,dc=example,dc=com`
in the default realm. `invent: false` writes only what you sent. Leave it out
in development to have the rest of a persona made up.

**The client:**
```bash
ldapsearch -H ldaps://localhost:636 -x \
  -D "uid=ldaps-run1,ou=users,dc=example,dc=com" -w 'Ldaps-Example-Passw0rd-Aa1!' \
  -b "uid=ldaps-run1,ou=users,dc=example,dc=com" -s base '(objectClass=*)'
```

What the job expects in each mode:

| The client does | Product | Development |
|---|---|---|
| bind with the right password on 636 | accepted | accepted |
| bind with a wrong password | 49 `invalidCredentials` | accepted |
| bind anonymously | 48 `inappropriateAuthentication` | accepted |
| search without binding | 50 `insufficientAccessRights` | answered |
| read the root DSE without binding | answered | answered |
| bind with the right password on 389 | 13 `confidentialityRequired` | accepted |

In development mode you can also bind as the seeded `cn=admin,dc=example,dc=com`
with any password but `invalid`. The examples on [LDAP](ldap.md) use
`password!`.

**The entry's `entryUUID` is the person's subject.** It comes back only when
asked for by name. A token's `sub` for this person is `urn:uuid:<entryUUID>`,
and a SCIM `id` is the bare value.

```bash
ldapsearch ... -b "uid=ldaps-run1,ou=users,dc=example,dc=com" -s base '(objectClass=*)' entryUUID
```

## Turn off the plain listener

A verified bind on 389 would send a real password in the clear, so product
mode refuses every bind there, answers only the root DSE, and logs a warning
at startup while 389 is on. Turn it off. `ldap.plainListener` takes effect at
the next restart.

**Console:** on **Protocols → LDAP / LDAPS**, set **Plain LDAP listener** to
off, click **Save LDAP**, and restart the service.

**API:**
```bash
api config/set '{"key":"ldap.plainListener","value":false}'
```

Or set `LDAP_PLAIN_LISTENER=false` in the container's environment. The ports
themselves are `ldap.port` (`LDAP_PORT`, 389) and `ldap.tlsPort`
(`LDAPS_PORT`, 636), also read at startup. A host run that is not root cannot
bind either; `/admin/ldap/service` then says so.

## Write the directory over LDAP

In product mode only somebody holding **Admin Write** may add, delete or
rename an entry, or change somebody else's. This recipe gives that role to a
person, then adds people and a group over LDAP and adds a member. Taken from
`sts_directory_bulk_load_ldap.js`, which binds as a person it created and,
in product mode, grants Admin Write first. In development mode any
connection may write, and the grant is not needed.

**Grant Admin Write.** Create the person first, as in the recipe above.

**Console:** on **Server configuration → Admin roles**, under **Grant a role**,
use **Find a person** to pick them, choose **Admin Write** as the **Role**, and
click **Grant**.

**API:**
```bash
api rbac/grant '{"username":"bulk-ldap-binder","role":"write"}'
```

`rbac/revoke` with the same body takes it back. A grant made in the default
realm covers every realm. A grant made at `/realm/<id>/admin-api` covers that
realm only.

**Add a person.** The job writes the same object classes and `uid` as the
console's create. In product mode the entry must carry the attribute
policy's required attributes, which by default are `cn`, `sn`, `givenName`
and `mail`:

```bash
ldapadd -H ldaps://localhost:636 -x \
  -D "uid=bulk-ldap-binder,ou=users,dc=example,dc=com" -w "$BIND_PASSWORD" <<'EOF'
dn: uid=dave,ou=users,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: dave
cn: Dave Davis
sn: Davis
givenName: Dave
mail: dave@example.com
EOF
```

**Add a group, then a member.** The group is a `groupOfNames` with no
`member` at first, which this schemaless directory accepts. A member is a DN:

```bash
ldapadd -H ldaps://localhost:636 -x -D "$BIND_DN" -w "$BIND_PASSWORD" <<'EOF'
dn: cn=engineering,ou=groups,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: engineering
description: Created over LDAP.
EOF

ldapmodify -H ldaps://localhost:636 -x -D "$BIND_DN" -w "$BIND_PASSWORD" <<'EOF'
dn: cn=engineering,ou=groups,dc=example,dc=com
changetype: modify
add: member
member: uid=dave,ou=users,dc=example,dc=com
EOF
```

The refusals a client may meet on these writes:

| Result | Why |
|---|---|
| 32 `noSuchObject` | the parent container does not exist |
| 50 `insufficientAccessRights` | product mode, and the bound identity does not hold Admin Write |
| 68 `entryAlreadyExists` | another entry already answers to that username, under whatever naming attribute |
| 19 `constraintViolation` | product mode, and a `userPassword` breaks the password policy |
| 65 `objectClassViolation` | product mode, and the new person lacks an attribute the realm's attribute policy requires |
| 11 `adminLimitExceeded` | the directory is full (`ldap.maxEntries`, 2000 by default, across every realm) |

A `userPassword` in an add or modify is stored as a scrypt hash in both modes.
In development a value that is already a `$scrypt$` hash is kept as given,
which is how a directory moves between two instances. Product mode refuses one.

## Let people change their own entry

In product mode a person bound as themselves may modify only the attributes
in `ldap.selfWritableAttributes`, on their own entry. The default list is
`telephoneNumber`, `mobile`, `homePhone`, `displayName`, `preferredLanguage`,
`postalAddress`, `street`, `l`, `st`, `postalCode` and `userPassword`.
Taken from the in-process test `tests/directory_write_authorization.js`.

```bash
ldapmodify -H ldaps://localhost:636 -x \
  -D "uid=ldaps-run1,ou=users,dc=example,dc=com" -w "$PASSWORD" <<'EOF'
dn: uid=ldaps-run1,ou=users,dc=example,dc=com
changetype: modify
replace: telephoneNumber
telephoneNumber: +1 555 0100
-
replace: displayName
displayName: Probe
EOF
```

A modify that mixes an allowed attribute with one that is not (`mail`, say)
is refused 50 as a whole, and nothing in it is applied. `memberOf` is never
writable this way, because it grants console roles.

**To change the list:**

**Console:** on **Protocols → LDAP / LDAPS**, edit **Attributes a person may
change on their own entry** and click **Save LDAP**.

**API:**
```bash
api config/set '{"key":"ldap.selfWritableAttributes","value":"telephoneNumber,mobile,userPassword"}'
```

Think before adding an attribute a token carries (`mail`, `cn`, `givenName`,
`sn`) or one a policy reads (`employeeType`): a person who can write it can
assert it about themselves. An empty list lets nobody change anything.

## Publish an address book

In product mode a person bound over LDAPS reads their own entry and, by
default, nobody else's. Another person's DN answers 32 `noSuchObject`, as a
DN that does not exist does. To let people read some attributes of each
other, list them in `ldap.directoryReadableAttributes`. Taken from
`sts_ldap_read_authorization.js`, which widens the list to
`objectClass,cn,uid,mail` in a throwaway product-mode realm and puts it back
afterwards.

**Console:** on **Protocols → LDAP / LDAPS**, set **Attributes a person may
read of other people** to `objectClass,cn,uid,mail`, and click **Save LDAP**.

**API:**
```bash
api config/set '{"key":"ldap.directoryReadableAttributes","value":"objectClass,cn,uid,mail"}'
api config/reset '{"key":"ldap.directoryReadableAttributes"}'    # back to self-only
```

What the job then sees, bound as an ordinary person:
* a subtree search of `ou=users` returns the other person with `mail` but without `telephoneNumber`;
* `(telephoneNumber=*)` matches only the reader, because a filter cannot see an attribute the reader may not read;
* a compare of the other person's `mail` answers, and a compare of their `telephoneNumber` is 50.

A group is visible to a person only if they are in it, and then only its
`cn`, `description` and `objectClass`. **Members may read their group's
member list** (`ldap.groupMembersReadable`, off by default) shows the members
too. Administrators read everything in their scope whatever these say.

Read the warning on [LDAP](ldap.md#what-a-bound-identity-may-read-product-mode)
before widening either setting. An address book hands everybody with a
password the list of usernames and addresses.

## A trust realm's own tree

Every [trust realm](trust-realms.md) has a tree of its own, rooted at the
RFC 2247 mapping of its DNS domain, behind the same two sockets. The DN names
the realm, so a client changes realm by changing its base. Taken from
`sts_ldap_read_authorization.js`, which creates one realm in each mode.

**Console:** on **Server configuration → Trust realms**, create the realm
with its id and domain.

**API:**
```bash
api realms/create '{"id":"ldrp1","domain":"ldrp1.example.net","name":"LDAP realm",
  "overrides":{"global.mode":"product"}}'
curl -sk "$BASE/realm/ldrp1/admin-api/groups" -H "Authorization: Bearer $TOKEN"
```

The second call answers the realm's `baseDn`, `usersDn` and `groupsDn`, here
`dc=ldrp1,dc=example,dc=net`. A realm's domain is fixed when it is created. A
realm created without one gets `<id>.<global.domain>`.

Create people and groups in the realm through `/realm/<id>/admin-api`, or on
the console while it shows that realm. A realm may have administrators of its
own; this one reads only its realm:

```bash
api() { curl -sk -X POST "$BASE/realm/ldrp1/admin-api/$1" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$2"; }
api users/create '{"username":"ldr-admin","invent":false,"credential":"password",
  "password":"'"$PASSWORD"'","attributes":{"cn":"LDR ldr-admin","givenName":"LDR",
  "sn":"ldr-admin","mail":"ldr-admin@ldr.test"}}'
api rbac/grant '{"username":"ldr-admin","role":"read"}'
```

That person then binds as `uid=ldr-admin,ou=users,dc=ldrp1,dc=example,dc=net`
and reads the whole realm, applications included. A modifyDN may not move an
entry from one realm to another (71, `affectsMultipleDSAs`).

## Groups

Groups made on the console or through the API are `groupOfNames` entries
under `ou=groups`, and LDAP sees them at once. Taken from
`sts_ldap_read_authorization.js`.

**Console:**
1. On **Directory → Groups**, under **Create a group**, set **cn** to `ldr-in` and, optionally, a **Description**.
2. In **Members**, put one username or DN per line, for example `ldr-reader`.
3. Click **Create**.
4. To add somebody later, open the group, type them in **User or DN** under **Add a member**, and click **Add**.

**API:**
```bash
api groups/create '{"group":"ldr-in"}'
api groups/add-member '{"group":"ldr-in","member":"ldr-reader"}'
```

`members` on `groups/create` takes a list at once
(`"members":["alice","bob"]`). A bare name resolves to that person's own
entry, wherever it is.

Nothing maintains `memberOf`, and nesting is shown but never expanded.
A group grants nothing by being a group, except the groups a role names,
such as the console's `cn=admin-read` and `cn=admin-write`. Whether tokens
carry a person's groups is the `groups.*` settings on [LDAP](ldap.md).

## The password policy

A realm's password policy is the entry `cn=default,ou=passwordPolicies,<base>`.
It is enforced on an LDAP write of `userPassword` in product mode, and a
refusal is 19 `constraintViolation`. Taken from the in-process test
`tests/password_policy.js`, which saves the profile below and then sets a
password over LDAP.

**Console:**
1. On **Directory → Policies**, open the **Password policy** tab.
2. Set **Minimum length** to `8`, **Previous passwords that may not be reused** to `1`, **Minimum number of symbols** to `0`, **Require an uppercase letter** to off, **Require a number** to on, and **Length of a generated password** to `16`.
3. Click **Save the profile**.

**API:**
```bash
api policies/save-password-policy '{"minLength":8,"history":1,"minSymbols":0,
  "requireUppercase":false,"requireDigit":true,"generatedLength":16}'
api policies/reset-password-policy '{}'    # delete the entry; the built-in defaults apply
```

**A save must carry all six fields.** One that leaves a field out is refused
by name for each, rather than resetting it. The built-in defaults are 12, 5,
1, on, on and 20. The generated length must be at least the minimum length.

**Over LDAP**, the policy is an ordinary entry that `ldapsearch` can read.
In the job, a modify of `userPassword` to `weak` is refused 19 and writes
nothing, and `Ldap-Passw0rd!` is accepted and stored as a hash:

```bash
ldapmodify -H ldaps://localhost:636 -x -D "$ADMIN_DN" -w "$ADMIN_PASSWORD" <<'EOF'
dn: uid=password-policy-ldap-probe,ou=users,dc=example,dc=com
changetype: modify
replace: userPassword
userPassword: Ldap-Passw0rd!
EOF
```

A password set over LDAP is what every other door then checks, and it gives
the person [Kerberos](kerberos.md) keys too.

## People who hold a second factor: app passwords

An LDAP bind cannot ask for a second factor. So in product mode a person who
holds or must hold one is refused their own password at a bind, with the
same 49 a wrong password gets. They bind with an **app password** scoped to
`ldap` instead. Development mode accepts every password, so there the app
password simply works too. Taken from `sts_second_factor_doors.js`.

**Console:** on the person's page, open the **Second factors** tab. Under
**App passwords**, give it a name, tick **LDAP bind**, and click **Make an
app password**. It is shown once.

**API:**
```bash
api users/create-app-password '{"user":"bob","name":"mail client","doors":["ldap"]}'
```

The answer's `appPassword` (six groups of four characters) is the bind
password. The person can also make their own on `/portal/app-passwords`. An
app password is refused at the sign-in screen and at every door it does not
name.

## Ask for, or require, a client certificate on 636

By default 636 sends no CertificateRequest. A bind is how a directory client
says who it is. Two settings in the **Listener: LDAPS** group change that:

| Setting | Default | What it does |
|---|---|---|
| `ldap.ldapsDisableOptionalClientCertificate` | `true` | Off asks every connection for a certificate and requires none. |
| `ldap.ldapsRequireClientCertificate` | `false` | On refuses at the handshake any connection without a certificate that chains to the client truststore. Wins over the row above. |

A certificate presented to 636 is verified but **binds nobody**. There is no
SASL EXTERNAL. The bind still decides who the connection is.

**Console:** on **Server configuration → Listeners**, change the row in the
**Listener: LDAPS** group and click **Save Listener: LDAPS**.

**API:**
```bash
api config/set '{"key":"ldap.ldapsRequireClientCertificate","value":true}'
```

These two rows are not in any test job's recipe; their behaviour is held by
the in-process tests `tests/ldaps_no_certificate_request.js` and
`tests/listener_tls_policy.js`.

## Large searches

There is no paged-results control and no other LDAP control. A search that
matches more than `ldap.sizeLimit` entries (500) returns that many and ends
with 4 `sizeLimitExceeded`. One that runs past `ldap.timeLimit` seconds (30),
or the client's own shorter `-l`, ends with 3 `timeLimitExceeded`. In both
cases the entries already sent are a valid partial answer. Narrow the base or
the filter to read the rest. Both settings are on **Protocols → LDAP /
LDAPS**:

```bash
api config/set '{"key":"ldap.sizeLimit","value":2000}'
```

## What the directory does not offer

The client has to manage without these. [LDAP](ldap.md) says why for each.

* **StartTLS.** Use `ldaps://` on 636.
* **SASL**, including EXTERNAL and GSSAPI. Only a simple bind.
* **Controls and extended operations.** No paged results, no Who am I? (so
  `ldapwhoami` does not work), and no Password Modify (`ldappasswd`). Change
  a password with an `ldapmodify` of `userPassword`.
* **A schema.** No object class or syntax is checked.
* **Referential integrity.** Deleting a person leaves their DN in every group.
* **Replication.** There is no LDAP replication protocol. Several nodes share
  one directory through the [persistence](persistence.md) store.

## Related

* [LDAP](ldap.md) and [LDAP schema](ldap-schema.md): the behaviour, every setting, and the attributes.
* [Configuring SCIM 2.0](configure-scim.md): provisioning into the same directory over HTTP.
* [Trust realms](trust-realms.md), [TLS and mutual TLS](tls.md) and [Persistence](persistence.md).
* [Management API](management-api.md): the token, and the OpenAPI document at `/admin-api/openapi.json`.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md), [Configuring OpenID Connect flows](configure-oidc-flows.md) and [Configuring SAML profiles](configure-saml.md).
