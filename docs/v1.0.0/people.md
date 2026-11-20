---
title: People
nav_order: 9
---

# What a user is here

A **user** is protocol-independent. Whichever protocol authenticated
them, the user is one **person**: one directory entry under the realm's
`ou=users`. How that person sits beside an application is the
[Directory](directory.md) chapter. The admin console's **Directory → Users**,
`/admin-api/users` and SCIM's Users are that entry. A [service account](service-accounts.md) is a
person with a flag on the entry. An
[application](applications.md#what-an-application-is-here) is a
different entry, under `ou=applications`, and a group is a different
entry again.

The [session](sessions.md) is the record of a sign-in. A token, an assertion
and a ticket are drawn from that session and from this entry. A credential
the service accepts is evidence that the holder is this person.

## One person, one entry

The entry appears the first time the person authenticates, when
`ldap.autocreateUsers` is on, or when an administrator, SCIM or a
[bulk import](bulk-import.md) creates it. How a typed name, a client
certificate, a DID, a SPIFFE ID or a partner's subject is placed is
[LDAP](ldap.md#how-an-identity-becomes-an-entry).

Two facts hold however the person arrives:

* The **subject** is `urn:uuid:` plus the entry's `entryUUID`. It is the
  `sub` of every token, and a SCIM `id` is the bare UUID. It survives a
  rename of the entry, and it is new when the entry is deleted and created
  again.
  [LDAP](ldap.md#entryuuid-the-stable-identifier).
* The **filing name** is the entry's `uid`. The distinguished name is
  `uid=<that name>,ou=users,<the realm's base>`. Once the entry exists, the
  username on what this service issues is that name.

A name that already belongs to an entry under `ou=users` reaches that entry.
In development mode a name that belongs to nobody can still create one;
[What is not checked](what-is-not-checked.md) says where. Product mode
creates nobody because a request named them.

Each [trust realm](trust-realms.md) has its own people. The same filing name
in two realms is two entries.

A disabled account is `pwdAccountLockedTime` on the entry. Every door
refuses that person.
[Admin console](admin-console.md#password-and-second-factors).

## The names

| Name | What it is |
|---|---|
| Filing name | the `uid`. The username on an issued token. On an ID Token that releases the profile, `preferred_username` is the same name. |
| Subject | `urn:uuid:<entryUUID>`. The `sub` of every token. |
| Sign-in name | the filing name, or a live `stsPseudonym`. What the person may type where a username is asked for. |
| Recovery address | the verified `mail`. Where a password reset and an address verification are sent. [Mail](mail.md). |
| Also known as | `alsoKnownAs`, an identity-assurance value on the person's Identity attributes. It is a label the entry holds. |

`/admin/users` is one row per person, keyed on the filing name. A spelling
they typed is kept among the names they were seen under.
[Admin console](admin-console.md#users--adminusers).

## Sign-in names

A **sign-in name** is another name for the same person (#644). Where this
service looks a username up — the sign-in screen, whichever protocol sent
the browser there, and the other doors that ask who a username is — a live
sign-in name signs in this person. The session's subject stays
`urn:uuid:<entryUUID>`. The username on what is issued afterwards stays the
filing name, so a client that keys an account on `username` or
`preferred_username` keeps one account.

Matching ignores case. The spelling that was stored is the spelling that is
shown. The name is unique in the realm, including when that realm runs in
more than one [cell](cells.md).

At most eight live sign-in names sit beside the filing name. The attributes
are listed on the [LDAP schema](ldap-schema.md) page: `stsPseudonym` for a
live name, and `stsPseudonymVerifyToken`, `stsPseudonymVerifyExpires` and
`stsPseudonymVerifyAddress` for one address that is still waiting. The token
is withheld. A waiting address is not yet a name anyone can sign in with.

### Adding and removing one

The person adds and removes names at **`/portal/pseudonyms`**, on their own
account. Those account API operations take no username: the person is the
access token's subject. [Account API](account-api.md).

An administrator uses **Sign-in names** on the person's **Contact** tab,
which needs Admin Write, or `POST /admin-api/users/set-pseudonyms`
(`setUserPseudonyms` in the live OpenAPI document,
[Management API](management-api.md)). The body names the person (`user`, or
`username` for the same field) and exactly one of `add`, `remove` and
`cancelPending`.

A name that is not an email is live as soon as it is stored. An email the
person adds waits for a link mailed to that address, unless the address is
already their verified recovery address, in which case it is live at once.
The link opens `/portal/verify-pseudonym`. Opening the link spends nothing;
confirming it spends the link, and the address becomes a sign-in name. That
page confirms a sign-in name. `/portal/verify-email` confirms the recovery
address. The link lasts `mail.verificationTtlMinutes`, the same lifetime as
an address verification. One address can be waiting: adding another
unverified email replaces it. **Cancel the pending link** drops it. While
the service cannot send mail, the portal will not add an email name.

An email an administrator sets, or a [bulk import](bulk-import.md) carries,
is live at once. It is refused when that address is already somebody else's
mail, or when the name is already somebody else's filing name or sign-in
name. The administrator's answer names the person and does not repeat the
sign-in name. On the portal the person is told the reason in a sentence,
for example that somebody else in the realm already answers to that name, or
that the address is already somebody else's.

An administrator's change is audited as `admin.pseudonym.set`. The row
records that the sign-in names changed. It does not record the name.

SCIM's user has no sign-in-name attribute. An LDAP add or modify of
`stsPseudonym` or of the three pending attributes is refused. A bulk import
may carry `stspseudonym` and may not carry the pending attributes.

Removing a sign-in name leaves the person, the filing name and the subject
in place. Adding a name the person already holds leaves the entry as it is.
Removing a name the person does not hold does the same.

### What a sign-in name leaves unchanged

| | Stays |
|---|---|
| Issued subject | `urn:uuid:<entryUUID>` |
| Issued username, and `preferred_username` | the filing `uid` |
| Access token | `username` is the filing name. The token carries no list of sign-in names. |
| SAML NameID | the session's filing name, or the mail address when the requested format is an email |
| Kerberos | the principal the keys were sealed under. An alias is not a second principal, and an email is not a principal. |
| LDAP bind | the entry's distinguished name, `uid=<filing name>,ou=users,<base>` |
| Recovery mail | `mail`, and `/portal/verify-email` |

### A name the directory will not store

The person is told in a sentence. The [error code](error-codes.md) is
recorded on the audit row and in the log, and it is never sent.

* Empty, or longer than 254 characters: "A pseudonym is one name of at most
  254 characters."
* A character a distinguished name reserves (comma, equals, plus,
  less-than, greater-than, hash, semicolon, quotation mark or backslash):
  "A pseudonym cannot contain a character a distinguished name reserves."
  A space is allowed.
* A distinguished name, a `urn:uuid:` subject, a UUID, a DID or a SPIFFE
  identity: "A pseudonym cannot be a distinguished name, a subject, a DID,
  or a SPIFFE identity."
* The name `invalid`: "That name is reserved."
* The person's own `uid`: "That name is already this person's uid."
* A further name when eight are already stored: "A person holds at most
  eight pseudonyms."
* Somebody else's filing name or live sign-in name: "Somebody else in this
  realm already answers to that name."
* An email that is somebody else's mail address: "That address is already
  somebody else's."

## Where a person is visible

* **Directory → Users**, `/admin/users`, and `GET /admin-api/users?user=`.
  The list is who this service has seen. The entry is what the directory
  holds, so a person created and not yet authenticated is in the directory
  and absent from the list until they authenticate.
  [Admin console](admin-console.md#users--adminusers).
* The person's own account at [`/portal`](user-facing-pages.md#the-user-portal).
* The directory, directly under the realm's `ou=users`.
  [LDAP](ldap.md#an-entry-for-everybody-who-authenticates).
* SCIM, `GET /scim/v2/Users`. [SCIM](scim.md).
* A [session](sessions.md)'s subject, and the `sub` of everything issued
  from it.
