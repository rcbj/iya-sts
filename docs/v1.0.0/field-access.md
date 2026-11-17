---
title: Field-level access
nav_order: 15
---

# Field-level access

This page lists who may read or change which fields of a person, an application
and the other records iya-sts keeps, and how a record's state changes the answer.
It describes product mode. [Authorization](authorization.md) covers the decision
of whether a request is allowed at all.

Each row below is enforced in the code, and is not a convention.

## Who is asking

| Consumer | Holds |
|---|---|
| **Administrator (read)** | Admin Read: `admin:read` at `/admin-api`, in the realm's console |
| **Administrator (write)** | Admin Write: `admin:write` |
| **A realm's administrator** | The same, confined to that realm |
| **Owner** | A person named owner of a group, role or application: `OWNER_READ` and `OWNER_WRITE`, decided by policy |
| **The person** | Their own account: a token for `/account-api`, or an LDAP bind as themselves |
| **SCIM client** | A credential with `scim:read` or `scim:write` |
| **Report user** | `report:use` or `report:admin` |
| **A relying party** | The claims released in a token or an assertion |
| **An outside source** | A federation partner or an attribute source writing onto an entry |

## A person's entry

| Field | Read | Write |
|---|---|---|
| Credentials: `userPassword`, `pwdHistory`, TOTP secret, recovery codes, Kerberos keys, device secret hashes, the other attributes the catalogue marks secret | **Nobody over LDAP, administrators included.** A search never returns one, a filter cannot match on one, and a compare is refused | The person, through the portal, with the current password proved. An administrator, through the password and credential operations of `/admin-api` |
| `userPassword` over LDAP | Never returned | Not by a person: it is not in `ldap.selfWritableAttributes` by default. An administrator's write meets the password policy |
| Operational attributes: `createTimestamp`, `modifyTimestamp`, `entryDN` | Readable | Nobody, administrators included |
| `pwdHistory`, `pwdChangedTime` | `pwdHistory` is withheld with the credentials | The service only |
| `memberOf` | Their own | Through group membership, never as a field |
| Second-factor requirement: `stsMfaRequired` | Administrators | Administrator. A person cannot clear their own requirement |
| Identity verifications: `stsIdaVerification` | Withheld from every LDAP read. The issuing operations read it | Service only, through its verification flows |
| Attributes in `ldap.selfWritableAttributes` | The person, on their own entry | The person, over LDAP |
| The fixed attribute list on the portal | The person | The person, at `/account-api` |
| Custom attributes | The person, only if `stsAttributePortalVisible` is set. Administrators always | The person, only if `stsAttributePortalEditable` is set. Editable implies visible. Administrators always |
| Another person's attributes | Not over LDAP by default. List names in `ldap.directoryReadableAttributes` to publish an address book | No |
| Group members | Not over LDAP by default. `ldap.groupMembersReadable` lets a person read the members of a group they are in | Administrators, and owners of the group |

Administrators write people through a closed list of attributes on the console and at `/admin-api`. An unlisted attribute is refused, not stored.

## An application or client

| Field | Read | Write |
|---|---|---|
| Client secrets, assertion private keys, GNAP keys, the registration access token | **Masked as `(set — not returned)` in every GET answer.** An administrator with Admin Write can reveal one, and the reveal is audited. A DID's private key is shown only when it is generated | Administrator (write) |
| A secret destination's credentials | Never returned or revealed; sent only to its own secrets manager | Administrator (write) |
| A federation client secret (`fedClientSecret`) | No page or API answer returns it | Administrator (write) |
| Ordinary registration fields | Admin Read. The client itself through RFC 7592 with its registration access token | Administrator (write), the client through RFC 7592, an owner by policy |

Exporting an application with its credentials requires Admin Write.

## Fields no outside source may write

A federation partner's mapping and an attribute source cannot write:

* the entry's identity and structure: `uid`, `objectClass`, `memberOf`,
  `userPassword` and operational attributes;
* any attribute this service keeps, by prefix: `sts*`, `app*`, `fed*`,
  `federation*`, `pwd*` and `hoba*`.

A mapping that targets one is refused when it is saved and dropped at sign-in.

## Fields a token or assertion may carry

No claim can release a secret or binary attribute (`userPassword`, photos,
certificates and the like), or an attribute with a `sts`, `hoba`, `app` or `pwd`
prefix.

## SCIM

A SCIM client with `scim:read` reads the realm's users and groups. The `password`
attribute is write-only and is never returned. `groups` on a user, and the
derived and meta attributes, are read-only. Writes to them are ignored as the
specification requires.

## Reports

The reporting catalog publishes no credential attributes. Selecting one is an
unknown field, so a report cannot contain it.

## How state changes the answer

| When | Rule |
|---|---|
| The account is **disabled** (`pwdAccountLockedTime`) | Refused at every door. It cannot be issued anything, and an administrator's enable is what clears it |
| `pwdReset` is set | The person must change the password first; other password doors refuse it |
| The entry is a **service account** | A browser session is refused. It is exempt from the second-factor requirement unless its policy says otherwise |
| An object is **protected** (a built-in role, a console group, this service's own applications) | An owner cannot change it, whatever the object says |
| A custom attribute **has values** | It cannot be removed, and its syntax and cardinality cannot change |
| A **secret destination** credential is set | It can be replaced and never read |
| A realm is **being removed** | No new session starts in it |
| A write would conflict with a realm's **attribute policy** | It is refused |
| The caller is a **realm's administrator** | Settings and pages that belong to the whole service are refused |

## Related

* [Authorization overview](authorization.md)
* [LDAP](ldap.md#what-a-bound-identity-may-read-product-mode)
* [Policies](policies.md)
* [Data classification](data-classification.md)
