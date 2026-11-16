---
title: Service accounts
---

# Service accounts

A **service account** is a person entry used by a program (issue #221). It
is an ordinary entry under `ou=users`. The auxiliary class
`stsServiceAccount` and the attribute `stsServiceAccount: TRUE` mark it as a
service account. It is **not** an application. How that person sits beside
an application and a policy is the [Directory](directory.md#a-person) chapter.

A service account keeps everything a person entry has: a password, app
passwords, Kerberos keys, a `sub`, groups and roles. Shared Signals report
on it under the person's `iss_sub`, and RISC's account lifecycle applies to
it. The flag adds two things:

- **A policy.** The service-account policy is the third kind of policy on
  **Directory → Policies**, next to the password and authentication
  policies.
- **Optional password rotation.** Each new password is pushed to a secrets
  manager before this service starts accepting it.

## Making one

You can set the flag in three ways:

- On the console, tick **Service account** on **Users → New user**, or use
  the **Service account** tab of an existing person's page.
- Through the management API, call
  `POST /admin-api/users/set-service-account` with `user`, `owners`,
  `destination` and `secretName`. `POST /admin-api/users/create` accepts
  the same fields with `serviceAccount: true`.
- Over LDAP, an administrator with Admin Write can modify the entry. The same
  rules apply, and the directory adds or removes the auxiliary class with the
  flag.

**A remote XACML PEP's identity is one automatically.** An entry that joins
the `remote-peps` group (`roles.remotePepGroup`) becomes a service account
owned by the realm's Admin Write group, or by its bootstrap administrator in
a realm without that group. The seeded `remote-pep-1` and any entry already
in the group become one when the service starts. See
[The PEP's entry is a service account](remote-pep.md#the-peps-entry-is-a-service-account).

The person can never set the flag on their own entry, whatever
`ldap.selfWritableAttributes` says. SCIM does not carry the flag.

### It cannot be undone

**Once a person is a service account, nothing makes them an ordinary person
again.** The console has no button for it, and the other doors refuse it:

- `POST /admin-api/users/set-service-account` with `serviceAccount: false`
  on a service account is refused (STS-SVCACCT-0060). On a person who is
  not a service account it changes nothing.
- An LDAP modify that deletes or replaces `stsServiceAccount` on a service
  account is refused with `constraintViolation` (STS-SVCACCT-0064).

The console's **Make them a service account** button says so in an amber
box, and you must tick **I understand that making them a service account
cannot be undone** before the button works. **Users → New user** says it
beside the **Service account** box.

**Deleting the entry is still allowed**, by every door that deletes a
person. That ends the account; it does not make it a person. A person
created later with the same username is a new person and inherits nothing
from the account.

Until 1.1.0, `serviceAccount: false` cleared the flag, the owners, the
destination and the rotation state. A program that sends it now gets a 400.

| Attribute | What it is |
|---|---|
| `stsServiceAccountOwner` | The DN of a person or group responsible for the account, one value per owner and at most 25. At least one is required while the policy's `requireOwner` is on, which is the default. |
| `stsSecretDestination` | The DN of the push destination, an application entry. |
| `stsSecretName` | The secret's name or path at that destination. The secret must already exist, because a push never creates one. |
| `stsPasswordRotatedAt` | When the password was last rotated. |
| `stsPreviousPassword`, `stsPreviousPasswordExpires` | The previous password's hash and when it stops being accepted. The hash is never returned by any read. |
| `stsRotationFailures`, `stsRotationLastError`, `stsRotationLastAttempt` | The rotation's state, kept on the entry so that any node can carry on from it. |
| `stsServiceAccountPolicy` | The [named service-account policy](#named-policies) that governs the account, or absent for `default`. Only a service account may hold it, and it is cleared with the flag. |

**Users** lists service accounts with a tag. The filter
`?kind=service` (or `?kind=person`) shows only service accounts (or only
everyone else), on the console and at `GET /admin-api/users`.

### Owners

An account can have more than one owner. Each owner is a person or a group
in the realm, and a group stands for everyone in it. You can name at most 25
owners. While the policy's `requireOwner` is on, which is the default, an
account must have at least one.

**Once an account has an owner, it always has one**, whatever `requireOwner`
says. `requireOwner` off lets you make an account with no owner, and edit
it while it has none. But a change that would take away the last owner is
refused: the last owner's **Remove**, `owners: []` on
`set-service-account` (STS-SVCACCT-0061), and an LDAP modify that deletes
the last `stsServiceAccountOwner` (STS-SVCACCT-0065). Add the new owner
first, then remove the old one.

**An owner cannot remove themselves.** Removing your own DN is refused
(STS-SVCACCT-0062; over LDAP, the bound DN, STS-SVCACCT-0066). So is
removing a group when that group is your only way of owning the account
(STS-SVCACCT-0063; STS-SVCACCT-0067), because it removes you too. You may
remove a group you are in while you still own the account in another way.
Another administrator may remove you, as long as an owner remains. The
rules apply to whoever's token or bind makes the change; development's open
management API, with no token, names nobody, so only the last-owner rule
applies there.

If the person or group that is an account's last owner is **deleted**, the
deletion is not refused. Their DN is taken off the account's owners and, in
the same change, **the realm's administrator becomes the owner**: the
realm's Admin Write group (`admin.writeGroup`, `admin-write` by default),
or its bootstrap administrator if the realm has no such group (or the group
is what was deleted). This happens whichever way the entry is deleted: a
SCIM `DELETE`, an LDAP delete, or a person moved to another cell. The audit
log has two rows: the removal, and an `admin.service-account.owner-added`
row by `system` naming the new owner and the deleted one.

If the realm has neither, the account is left with no owner and
STS-SVCACCT-0068 is logged. Add an owner on the **Service account** tab (or
with `POST /admin-api/users/add-service-account-owner`, or an LDAP modify
adding `stsServiceAccountOwner`); nothing refuses that.

Deleting one of several owners only removes that one. An account that had
no owner before (made with `requireOwner` off) is not changed.

On the console, the **Service account** tab lists the owners in a table. To
add an owner:

1. Choose **people** or **groups** and type part of a username or a group's
   name.
2. Press **Find**. The results show five at a time, with **Previous** and
   **Next**.
3. Press **Add** beside the owner you want.

For an account that is already a service account, **Add** and **Remove** save
the change as soon as you press them. The search results stay on the page, so
you can add several owners one after another. You cannot remove the last
owner, or yourself.

For a person who is not a service account yet, the table is a draft. Nothing
is saved until you press **Make them a service account with these owners and
push destination**, which saves the owners, the destination and the secret
name together. On **Users → New user** you type the owners instead, one per
line.

### Push destination

The push destination is chosen with a search too, and the search finds only
secret destinations (**Directory → Secret destinations**):

1. Type the secret's name or path in **Secret name or path**.
2. Type part of a destination's name, DN or provider and press **Find**.
3. Press **Use** beside the destination you want.

For a service account, **Use** saves the destination and the secret name at
once. The two go together, so type the secret name first. A destination that
is set already is marked **in use**, and one that cannot be pushed to yet is
marked **not usable now**. Once a destination is set, **Save the secret name**
changes only the name, and **Clear the push destination** removes both. The
password is then no longer rotated, and the owners stay.

Through the management API, `owners` is the whole list. It replaces the
owners the account has, so to add one you send the existing owners as well.
Each entry is a DN, a username or a group's `cn`; a string is read as one
owner per line.

To change one owner or the destination without sending the rest, use the
three actions the console uses:

| Action | Body | What it does |
|---|---|---|
| `add-service-account-owner` | `user`, `owner` | Adds one owner and keeps the others and the destination. An owner already listed is `ok` with `changed: false`. |
| `remove-service-account-owner` | `user`, `owner` (the DN) | Removes one owner. Refused for an owner the account does not list, and for the last owner while the policy requires one. |
| `set-service-account-destination` | `user`, `destination`, `secretName` | Sets both, or clears both when both are empty, and keeps the owners. |

Each answers `account`, the service account as it now stands. To find a
destination, `GET /admin-api/secret-destinations?q=<text>` narrows the list to
destinations whose name, identifier, DN or provider contains the text, and
`matched` counts them.

## The policy

Each realm has a `default` profile, `cn=default,ou=serviceAccountPolicies`,
and may hold [named profiles](#named-policies) beside it. A realm without its
own `default` inherits the default realm's, and if that does not exist
either, the built-in defaults below apply. **Every default is the more secure
choice.**

| Field | Default | What it does |
|---|---|---|
| `exemptFromSecondFactor` | off | When on, the authentication policy's second-factor requirements do not apply, and neither does the rule that refuses a password alone at a password-only door. `amr` still says `pwd`. |
| `allowBrowserSignIn` | off | When off, the sign-in screen, the portal and the console refuse the account, whatever first factor it presents. Making a person a service account also ends their browser sessions. |
| `allowLdapBind`, `allowWsTrust`, `allowScim`, `allowSsf`, `allowEst`, `allowKerberos`, `allowPasswordGrant` | on | Which password doors accept the account. At a closed door, the right password is refused as a wrong password is. |
| `rotationEnabled` | off | Turns on automatic rotation, described below. It cannot be turned on while the realm has no push destination. |
| `rotationIntervalDays` | 30 | How often the password rotates. |
| `rotationOverlapMinutes` | 60 | How long the previous password is still accepted after a rotation. |
| `generatedLength` | 32 | The length of a rotated password. It can never be shorter than the password policy's minimum. |
| `requireOwner` | on | Whether an account must name at least one owner. |
| `rotationAlarmFailures` | 3 | How many failed rotations in a row raise an alarm. |

The policy applies **in both modes**, as the authentication policy does. In
development mode, which checks no password, a closed door still refuses the
account.

### Named policies

[Policies](policies.md#service-account-policy) is the rule this kind shares
with the others: the account names the profile. Some accounts need different
rules from the rest, for example a deployment
pipeline that rotates every week while every other account rotates monthly.
For that, create a **named policy** on **Directory → Policies →
Service-account policy → New policy**, or with
`POST /admin-api/policies/save-serviceAccount-policy` naming `profile`.
A name is lower-case letters, digits and hyphens. A named policy has every
field in the table above and a `precedence` from 1 to 1000. It belongs to
the realm it was made in and is never inherited by another realm.

**The account names its policy.** Set `stsServiceAccountPolicy` on the
account's **Policies** tab, with
`POST /admin-api/users/set-attribute`, or over LDAP. The value is `default`
or a named policy the realm holds; anything else is refused. Only a service
account may hold it (STS-SVCACCT-0048).

Every rule follows the account's own policy: the doors, the browser, the
second-factor exemption, whether an owner is required, and the rotation's
interval, overlap, length and alarm threshold. An account that names nothing
follows `default`. An account that names a policy the realm does not hold
also follows `default`, and STS-SVCACCT-0047 is logged. This can only
happen to an entry restored or copied from elsewhere, because every write is
checked and a named policy an account still names cannot be deleted
(STS-SVCACCT-0049). The **Named policies** tab lists the accounts that name
each one.

## Rotation

The `service-accounts.rotate` scheduler job runs hourly on one node. It
rotates every service account that names a destination, whose own policy
turns rotation on, and whose interval under that policy has passed. The job
is off in a realm where no policy, `default` or named, turns rotation on. **Rotate now** on the account's page, or
`POST /admin-api/users/rotate-password`, queues the same work as
`service-accounts.rotate-now`. Each rotation goes through these steps:

1. It takes a per-account claim, so the job and a rotation started by hand
   never rotate the same account at once.
2. It draws a password with the password policy's generator, held to the
   account's own password policy (the named one a group of the account
   names, else `default`), at the length the account's service-account
   policy sets.
3. It **pushes** that password to the destination as a new version. If the
   push fails, **nothing changes**: the failure is counted and the next run
   tries again.
4. Only after the push succeeds does it **commit** the password. The previous
   password stays accepted for the overlap. The account's Kerberos keys are
   derived again, and the KDC keeps the previous key version for at least as
   long, so tickets issued under it can still be decrypted. The old password
   itself never pre-authenticates.
5. It sends a CAEP `credential-change` (`password`, `update`, initiated by
   `system`) and writes an audit row.

**While rotation is on, the account's password cannot be set by hand**,
whether from the console, the API or an LDAP modify. The destination is the
source of truth.

The overlap is checked when a password is read. The
`service-accounts.previous-cleanup` job only clears hashes that have already
expired. A sign-in with the previous password is logged, because it means a
consumer has not picked up the new password yet. It is not recorded as a
failure for risk scoring.

**Monitoring → Service accounts** (`GET /admin-api/service-accounts`) lists
every account with its destination, last and next rotation, how long the
previous password remains valid, and the failure count. An account that has
reached the alarm threshold is flagged. A failed rotation logs
STS-SVCACCT-0044 or STS-SVCACCT-0046. The alarm is STS-SVCACCT-0042. A
password that was pushed but could not be committed is STS-SVCACCT-0045,
which is raised as an alarm at once.

Destinations are application entries registered under **Directory → Secret
destinations**. Each one holds the write credential for its secrets manager.

## Its certificates name it `urn:sts:sa:`

Every certificate this service issues names its holder in a URI
subjectAltName. An ordinary person's says `urn:sts:person:<username>`; a
service account's says **`urn:sts:sa:<username>`**. Underneath it is the same
person entry. Every place that reads a certificate treats it as that person,
so the same rules apply: an RFC 7523 assertion it signs may name only itself,
and it binds to LDAP as its own entry.

The name is chosen when a certificate is issued, from whether the entry is a
service account at that moment. That covers TLS client and message-signing
certificates, RFC 7523 and RFC 7522 key pairs, and certificates enrolled over
ACME, EST or SCEP.

- **A certificate issued before keeps working.** One that says
  `urn:sts:person:<username>` and was issued before the entry became a
  service account (or before this change) is still accepted everywhere it
  was. Only certificates issued from now on use `urn:sts:sa:`. To move a
  holder to the new name, issue a new certificate and revoke the old one.
- **`urn:sts:sa:` is a claim about the entry.** A certificate naming
  `urn:sts:sa:<name>` where that entry is not a service account, or does
  not exist, is refused. The codes are STS-TLS-0063 (a TLS client
  certificate), STS-OAUTH-1011 (an assertion's `x5c`), STS-PKI-0277 (an
  uploaded certificate), STS-WSTRUST-0074 (a WS-Trust requester) and
  STS-ENROLL-0097 (ACME, EST or SCEP).
- **An enrollment request may ask for either name.** The certificate it
  gets carries `urn:sts:sa:<username>`.

A remote PEP's identity is a service account, so a PEP certificate issued
now names `urn:sts:sa:<username>`.

## A service account is not a Kerberos service principal

The two are easy to confuse, because Active Directory puts a service's SPN on
a user account (or a managed service account) and calls that account the
service account. In iya-sts they are two different kinds of entry, and a
Kerberos service principal is never a service account.

| | Service account | Kerberos service principal |
|---|---|---|
| **The entry** | A **person** entry under `ou=users` with `stsServiceAccount: TRUE` | An **application** entry whose identifier is `<spn>@<realm>`, e.g. `HTTP/apigw1.example.com@EXAMPLE.COM` |
| **Its Kerberos role** | A **client**. It gets a TGT with an AS exchange, pre-authenticated with its password, where the policy's `allowKerberos` door is open | A **service**. It holds an SPN, accepts tickets (AP-REQ), and asks the KDC for S4U2Self and S4U2Proxy tickets with its own TGT |
| **Its key** | Derived from its password, as every person's is, and derived again when the password changes or rotates; the KDC keeps the previous key version for the overlap | Random, one per enctype, made on the Kerberos **Principals** page (`/admin/kerberos/principals`) or by `POST /admin-api/kerberos/principals/create-service`; replaced by **Rotate** (`rotate-service`) |
| **What a program is given** | Its password, read from the push destination when rotation is on, used with `kinit <name>@<REALM>` | A keytab, handed over **once** by the create or a rotate, used with `kinit -k` and by the acceptor |
| **Delegation rules** | It delegates nothing: it is a client. Like any person it can be *protected from* delegation (`stsNotDelegated`, `delegation.protectedGroups`) | `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf` and `appDelegationSemantics` on the entry, read by the KDC and by the one delegation policy every protocol shares ([Delegation and impersonation](delegation.md)) |
| **Governed by** | The service-account policy on **Directory → Policies** | The application's own entry, like any other application |

Three consequences are worth knowing:

- **An SPN cannot be put on a service account.** A service that accepts
  Kerberos tickets is registered as a service principal, whatever program
  runs it. Its owner and its rules sit on that application entry.
- **A rotating service account has no keytab.** **Reset password and
  download keytab** sets the password, and only the rotation may set a
  rotating account's password (STS-SVCACCT-0013). Its consumers read the
  password from the destination and authenticate with it; a rotation pushes
  the password, never a keytab.
- **The same program can be both.** A service that accepts tickets for its
  SPN *and* signs in somewhere else as a client of its own holds two
  identities: the service principal's keytab for the first, and a service
  account's password for the second.

See [Kerberos, KKDCP and SPNEGO](kerberos.md) for service principals,
their keys and delegation.

## What it is not

- **Not an application.** An OAuth client is a non-human identity of its own
  kind, with its own Shared Signals subject (see
  [CAEP events](caep-events.md)).
- **Not a Kerberos service principal.** An SPN lives on an application entry
  (see [above](#a-service-account-is-not-a-kerberos-service-principal)).
- **Not exempt from the opt-out rule silently.** A service account has no
  holder to opt out of RISC (RISC section 2.8), and the portal and the
  register say so rather than applying the rule.
