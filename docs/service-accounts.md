---
title: Service accounts
---

# Service accounts

A **service account** is a person entry used by a program (issue #221). It
is an ordinary entry under `ou=users`. The auxiliary class
`stsServiceAccount` and the attribute `stsServiceAccount: TRUE` mark it as a
service account. It is **not** an application.

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
  `POST /admin-api/users/set-service-account` with `user`, `owner`,
  `destination` and `secretName`. Send `serviceAccount: false` to make the
  person an ordinary person again. `POST /admin-api/users/create` accepts
  the same fields with `serviceAccount: true`.
- Over LDAP, an administrator with Admin Write can modify the entry. The same
  rules apply, and the directory adds or removes the auxiliary class with the
  flag.

The person can never set the flag on their own entry, whatever
`ldap.selfWritableAttributes` says. SCIM does not carry the flag.

| Attribute | What it is |
|---|---|
| `stsServiceAccountOwner` | The DN of the person or group responsible for the account. It is required while the policy's `requireOwner` is on, which is the default. |
| `stsSecretDestination` | The DN of the push destination, an application entry. |
| `stsSecretName` | The secret's name or path at that destination. The secret must already exist, because a push never creates one. |
| `stsPasswordRotatedAt` | When the password was last rotated. |
| `stsPreviousPassword`, `stsPreviousPasswordExpires` | The previous password's hash and when it stops being accepted. The hash is never returned by any read. |
| `stsRotationFailures`, `stsRotationLastError`, `stsRotationLastAttempt` | The rotation's state, kept on the entry so that any node can carry on from it. |

**Users** lists service accounts with a tag. The filter
`?kind=service` (or `?kind=person`) shows only service accounts (or only
everyone else), on the console and at `GET /admin-api/users`.

## The policy

Each realm has one profile, `cn=default,ou=serviceAccountPolicies`. A realm
without its own profile inherits the default realm's profile, and if that
does not exist either, the built-in defaults below apply. **Every default is
the more secure choice.**

| Field | Default | What it does |
|---|---|---|
| `exemptFromSecondFactor` | off | When on, the authentication policy's second-factor requirements do not apply, and neither does the rule that refuses a password alone at a password-only door. `amr` still says `pwd`. |
| `allowBrowserSignIn` | off | When off, the sign-in screen, the portal and the console refuse the account, whatever first factor it presents. Making a person a service account also ends their browser sessions. |
| `allowLdapBind`, `allowWsTrust`, `allowScim`, `allowSsf`, `allowEst`, `allowKerberos`, `allowPasswordGrant` | on | Which password doors accept the account. At a closed door, the right password is refused as a wrong password is. |
| `rotationEnabled` | off | Turns on automatic rotation, described below. It cannot be turned on while the realm has no push destination. |
| `rotationIntervalDays` | 30 | How often the password rotates. |
| `rotationOverlapMinutes` | 60 | How long the previous password is still accepted after a rotation. |
| `generatedLength` | 32 | The length of a rotated password. It can never be shorter than the password policy's minimum. |
| `requireOwner` | on | Whether an account must name an owner. |
| `rotationAlarmFailures` | 3 | How many failed rotations in a row raise an alarm. |

The policy applies **in both modes**, as the authentication policy does. In
development mode, which checks no password, a closed door still refuses the
account.

## Rotation

The `service-accounts.rotate` scheduler job runs hourly on one node. It
rotates every service account that names a destination and whose interval
has passed. **Rotate now** on the account's page, or
`POST /admin-api/users/rotate-password`, queues the same work as
`service-accounts.rotate-now`. Each rotation goes through these steps:

1. It takes a per-account claim, so the job and a rotation started by hand
   never rotate the same account at once.
2. It draws a password with the password policy's generator, at the policy's
   length.
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
