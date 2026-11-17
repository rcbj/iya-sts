---
title: Directory
nav_order: 8
---

# Directory

iya-sts is a **user** and an **application**. Both are
protocol-independent. A [user](people.md) is one person, whichever
protocol authenticated them. An [application](applications.md) is one
application, whichever protocol it spoke. OAuth, OpenID Connect, SAML,
WS-Trust, WS-Federation, Kerberos, GNAP and the others name that pair.
A token, an assertion and a ticket say those two objects in the
protocol that asked.

The [session](sessions.md) is the record of one sign-in. It belongs to
the user. The application is the other party. A credential the service
accepts is evidence about the user.

The directory is where a realm keeps them. Each
[trust realm](trust-realms.md) has a tree of its own.
[LDAP](ldap.md#the-containers) lists every container. The object is an
entry, and the service reads that entry the next time it needs it. A
[policy](policies.md) is what the user and the application are held to.

| Object | Where it lives | Page |
|---|---|---|
| **User** | `ou=users` | [People](people.md) |
| **Application** | `ou=applications` | [Applications](applications.md) |
| **Policy** | the kind's own container | [Policies](policies.md) |

A [group](admin-console.md#groups--admingroups) is an entry under
`ou=groups`. It can name a policy for its members. What a group grants by
being named in a roster or a role is on that page.

The relationship is one way. The user and the application are the
holders. A group is a third holder. The profile lists nobody.
[Who names which kind](policies.md#who-names-which-kind) and
[how one is chosen](policies.md#how-one-is-chosen).

## A person

[People](people.md) defines the entry: the subject, the filing name, and a
sign-in name. A [service account](service-accounts.md) is that entry with
a flag.

As a holder, a person names an attribute policy, and a service account
names a service-account policy. The person's groups name the other kinds.
The application they are signing in to names its own.

## Configuring a person

These doors write the same entry.

| What you are doing | Where |
|---|---|
| Create the person, and set the username | **Directory → Users**, [Creating a person](admin-console.md#creating-a-person--adminusersnew). `POST /admin-api/users/create`. [Put a person in the directory and bind as them](configure-ldap.md#put-a-person-in-the-directory-and-bind-as-them). [SCIM](configure-scim.md#create-a-person-and-a-group-and-add-a-member). [Bulk import](bulk-import.md) |
| Attributes the realm requires, and custom attributes | [The attribute policy](policies.md#the-attribute-policy) |
| The attributes on the entry | [Changing a person's attributes](admin-console.md#changing-a-persons-attributes). The catalogue is [LDAP schema](ldap-schema.md) |
| A sign-in name | [Adding and removing one](people.md#adding-and-removing-one) |
| Password, lock, second factors | [Password and second factors](admin-console.md#password-and-second-factors). The rules are the [password policy](policies.md#password-policy) |
| What the person may change | [`/portal`](user-facing-pages.md#the-user-portal) and the [Account API](account-api.md) |
| Make the entry a service account | [Service accounts](service-accounts.md#making-one) |
| One entry per username | [One entry per person](ldap.md#one-entry-per-person-however-they-get-in) |

## An application

[Applications](applications.md#what-an-application-is-here) defines the
entry: the identifier, the filing name, and the name each protocol
calls it. A resource server is that entry used as an audience.
[One application, one entry](applications.md#one-application-one-entry).

As a holder, an application names a password, authentication, passkey,
locale or post-login policy for a sign-in to it. The profile it names
is a candidate while this application is the one in hand.
[Who names which kind](policies.md#who-names-which-kind).

## Configuring an application

These doors write the same entry.

| What you are doing | Where |
|---|---|
| Create the application, and set the identifier | **Directory → Applications**, [New application](applications.md#adminapplicationsnew). `POST /admin-api/applications/create`. [RFC 7591](applications.md#software-statements-rfc-7591-section-23). An LDAP add under `ou=applications`. In development, the first acceptance of the identifier. [One application, one entry](applications.md#one-application-one-entry) |
| The identifier, the filing name, and a protocol name | [The names](applications.md#the-names) |
| What each protocol calls it, and where a browser is sent back | [New application](applications.md#adminapplicationsnew). [One entry per identifier](applications.md#one-entry-per-identifier) |
| Which families it is declared for | [Declared families and recorded ones](applications.md#declared-families-and-recorded-ones) |
| The secret, and whether the client is public | [The client secret](applications.md#the-client-secret). [What the checks read](applications.md#what-the-checks-read) |
| Grants, scopes, consent, a delegated permission | [The console page and the API](applications.md#the-console-page-and-the-api). [Delegated permissions](admin-console.md#delegated-permissions) |
| Which origins may read an answer | [CORS](applications.md#cors-which-pages-may-read-an-answer) |
| How its people may sign in, and which second factors | [Sign-in mechanisms](applications.md#sign-in-mechanisms-how-its-people-may-sign-in). [Second factors](applications.md#second-factors-which-ones-its-people-may-use) |
| Name a policy for a sign-in to it | [Named policies](policies.md#named-policies). [Who names which kind](policies.md#who-names-which-kind) |
| A software statement | [Software statements](applications.md#software-statements-rfc-7591-section-23) |
| Move one between deployments | [Exporting and importing an application as LDIF](applications.md#exporting-and-importing-an-application-as-ldif) |
| Withdraw the registration, or remove the entry | [Registration and a sighting](applications.md#registration-and-a-sighting) |
| Change what a protocol checks | [OAuth grants](configure-oauth2-grants.md), [OpenID Connect flows](configure-oidc-flows.md), [SAML](configure-saml.md), [WS-Trust](configure-ws-trust.md), [WS-Federation](configure-ws-federation.md), [Kerberos](configure-kerberos.md), [GNAP](configure-gnap.md) |

## A policy

[Policies](policies.md) is the seven profiles, which holder names which
kind, and how the lowest precedence is chosen. An XACML policy in
`ou=policies` is a different object.
[Authorization](authorization.md).

## Configuring a policy

| What you are doing | Where |
|---|---|
| Edit `default`, add a named profile, see who names it | **Directory → Policies**. [Writing and deleting](policies.md#writing-and-deleting) |
| Save or remove one from the API | The operations [Writing and deleting](policies.md#writing-and-deleting) names. The live list is `GET /admin-api/openapi.json` |
| Decide which holder names which kind | [Who names which kind](policies.md#who-names-which-kind) |
| Change what a profile's fields do | The kind's own page, from [The seven kinds](policies.md#the-seven-kinds) |
| Read the password policy as an entry | [The password policy is a directory entry](ldap.md#the-password-policy-is-a-directory-entry) |

## Reaching the directory

* [LDAP](ldap.md) — the protocol, the containers, and how an identity becomes an entry.
* [LDAP schema](ldap-schema.md) — the attributes a person and a group carry.
* [Configuring LDAP](configure-ldap.md).
* [SCIM 2.0](scim.md) and [Configuring SCIM](configure-scim.md).
* [Bulk directory import](bulk-import.md).
