---
title: "Post-login activities"
---

# Post-login activities

A **post-login activity** is something a realm asks a person to do after they
sign in, before they are sent back to the application. There are two ways to
switch it on: the **policy**, per realm and targeted by group, or **starting**
an activity for some groups (or the whole realm), which asks them at sign-in
and mails them reminders. Either way the rules come from the policy.
[Passkeys → Post-login activities](passkeys.md#post-login-activities-moving-people-to-post-quantum-passkeys)
walks through a rollout; this page is the reference.

Three activities exist today:

| Activity | What the person is asked |
|---|---|
| `pqc-mail-encryption` | To move their **mail encryption to a post-quantum key**: an OpenPGP key whose encryption subkey is ML-KEM (RFC 9980), or an uploaded ML-KEM S/MIME certificate. A person whose mail is encrypted to a classical key is asked; a person whose mail is not encrypted can be invited or required. See [The mail-encryption activity](#the-mail-encryption-activity) below. |
| `piv-reissue` | To **enrol new PIV slot certificates** on their YubiKey: a certificate this realm issued is replaced when a classical CA signed it and the realm's EST Issuing CA is now post-quantum, or when it is about to expire. The old certificate is revoked when the new one is first used to sign in. See [The PIV re-issue](#the-piv-re-issue) below. |
| `pqc-passkey-migration` | To register a **post-quantum (ML-DSA) passkey**. A person who holds a classical passkey and no ML-DSA one is asked for an ML-DSA one. All their passkeys are asked about at once, because a passkey has no role: one ML-DSA passkey is enough, and it signs them in and answers the second step as the realm allows. A person with no passkey can be invited or required to register one. |

Each activity has its own block of fields on the policy, with its own
switch, Skip and allotted time, so a profile saved before an activity
existed reads it as off. When several are due at one sign-in, the person
is asked every required one and at most one they may skip; mail encryption
is asked before the passkey migration and the PIV re-issue, because mail
encrypted to a classical key today can be read once that key falls; the
other two are about forgery, which a key can only suffer once it has
fallen.

## Before you start

- Post-login activities are **off by default** in every realm: the policy is
  off, and no activity is started.
- The realm has to be able to make an ML-DSA passkey. Passkeys must be on
  (`webauthn.enabled`), the realm must accept a passkey in at least one use
  (`webauthn.primaryAllowed` or `webauthn.mfaAllowed`, and the matching row
  of the authentication policy), and an ML-DSA algorithm must be offered at
  registration. The default `webauthn.algorithms` offers one, as do
  `webauthn.pqcAlongsideClassical` and `webauthn.pqcOnly`. See
  [Passkeys and WebAuthn](passkeys.md#algorithms-classical-and-post-quantum).
  If the realm cannot make an ML-DSA passkey, nobody is asked and no sign-in is
  held.
- The person's device or browser has to be able to make an ML-DSA passkey. If
  it can't, the registration fails and nothing changes. Under a required
  activity, the person cannot finish signing in (see *Skip, and the allotted
  time* below).

## Setting it up

Open **Directory → Policies → Post-login activity policy** in the
[admin console](admin-console.md) for the realm. Through the
[management API](management-api.md): `GET /admin-api/policies` (the
`postLogin` member), `POST /admin-api/policies/save-postLogin-policy` and
`reset-postLogin-policy`.

| Field | Default | What it does |
|---|---|---|
| Ask after sign-in (`enabled`) | off | When on, people this profile reaches are asked after they sign in. |
| Activity (`activity`) | `pqc-passkey-migration` | What they are asked to do. |
| Skip puts it off for (`snoozeDays`) | 7 days | How long **Skip** puts the activity off (1–90). |
| Allotted time (`graceDays`) | 0 | Counted from the person's **first** invitation. Once it has passed, Skip is gone and the sign-in is held until the activity is done. 0 means no deadline. |
| A person with no passkey (`noPasskey`) | `leave` | `leave`: not asked. `invite`: asked, and can always skip. `require`: asked, and can skip only until the allotted time has passed. |
| How a classical passkey is migrated (`method`) | `automatic` | `upgrade`: the person uses the classical passkey once, then an ML-DSA passkey **replaces it in place** on the same authenticator. `alongside`: an ML-DSA passkey is added beside it. `automatic`: `alongside` where the person's passkey policy offers two lanes, `upgrade` where it offers one. |
| A passkey counts as post-quantum when (`attestation`) | `any` | `any`: its key algorithm is ML-DSA. `post-quantum`: its recorded attestation is post-quantum too; a person whose ML-DSA passkey has a classical attestation, or none recorded, is asked for one beside it, whatever `method` says. |
| A person with no passkey whose device cannot make ML-DSA (`noPasskeyFallback`) | `none` | `none`: ML-DSA only. `classical`: a retry with the classical algorithms is offered after the ML-DSA registration fails — a classical passkey is better than a password, and the person is asked to migrate it later. |

Until [#1135](https://github.com/rcbj/iya-sts/issues/1135) a profile also
had **Registered by a person with no passkey as** (`noPasskeyRole`,
`primary` or `mfa`), and a person was asked about their passkeys one role at
a time. A passkey has no role now, so the field is gone; a profile stored
with it still loads.

### Which profile applies: groups and applications name it

[Policies](policies.md#post-login-activity-policy) is the rule this kind
shares with the others. The `default` profile reaches everyone in the realm.
A realm without its own
`default` profile follows the default realm's.

A **named profile** lists nothing: it has its fields and a `precedence`
(1–1000). What it applies to **names it**:

- **a group**, in `stsPostLoginPolicy` on the group's entry: on the group's
  page under *Policies this group names*, or with
  `POST /admin-api/groups/set-policy`;
- **an application**, in `appPostLoginPolicy`: a field of the application's
  Configuration tab, *Every protocol*, or `POST /admin-api/applications/set`.

Each takes `default` or a named post-login profile of the realm, and nothing
else. When a person signs in to an application, the candidates are the
profile the application names and the profile each of the person's groups
names; the one with the lowest `precedence` wins (ties by name), and
`default` applies when nothing names one. A profile that a group or an
application still names cannot be deleted (`STS-AUTHN-0543`). A name the
realm does not hold — written with an LDAP client — counts for nothing
(`STS-AUTHN-0542`).

**An application is known only at a sign-in.** The reminder mails of a
[started activity](#starting-an-activity) and the
[progress report](#following-the-migration) are about a person, not a sign-in, so they use
the profile the person's **groups** select. The profile an application names
applies when the person signs in to that application.

**To exclude a group**, create a named profile, switch `enabled` off, give
it a lower precedence than the profile that would otherwise reach its
members, and name it from the group. That keeps its members out of the policy
and out of every started activity, mails included.

**To exclude an application**, do the same and name the profile from the
application. A sign-in to that application asks nothing, unless a profile one
of the person's groups names has a lower precedence still. The person may
still be asked when they sign in to another application, and a started
activity may still mail them.

**Example: a pilot group, required within 30 days**

```json
POST /admin-api/policies/save-postLogin-policy
{ "profile": "pqc-pilot", "precedence": 10,
  "enabled": true, "activity": "pqc-passkey-migration",
  "snoozeDays": 3, "graceDays": 30,
  "noPasskey": "invite" }

POST /admin-api/groups/set-policy
{ "group": "pqc-pilot", "attribute": "stsPostLoginPolicy",
  "policy": "pqc-pilot" }
```

## What the person sees

1. They sign in at the sign-in screen as usual: password, passkey, one-time
   code, and so on.
2. If they are due the activity, the session is **held, not started**. They see
   `/authn/post-login` (**Register a post-quantum passkey**), with **Register
   a post-quantum passkey**, **Skip for N day(s)** while skipping is still
   allowed, and **Start over**.
3. **Register** goes to the passkey page. For an **upgrade** the person first
   uses their classical passkey once, then creates the ML-DSA passkey on the
   same authenticator, which replaces the old one there and here: one
   passkey, nothing left behind. For **alongside** the ML-DSA passkey is
   added beside the classical one — in its own lane, or on another
   authenticator where the realm has one lane (the page says which). Either
   way only ML-DSA is offered. When it is done, the session the sign-in was
   held for starts and the person goes back to the application.
4. **Skip** puts the activity off for `snoozeDays`. The held session then
   starts.

**If the device cannot make it.** When the browser reports that the ceremony
did not complete, the person is taken back to the post-login page, which
names the error and says what to do: register on a separate security key
that supports ML-DSA, or ask an administrator; and Skip, while it is still
allowed. On the person's page under Directory → Users an administrator can
upgrade a classical passkey, or enrol a passkey where the person's passkey
policy has `adminEnrolment` on
([Passkeys](passkeys.md#an-administrator-enrols-a-passkey)). Each such failure
leaves an audit row `authn.post-login.unsupported` with the error name and
the browser and platform, so you can see where the move is stalling. Filter
the audit log (`/admin/audit`) by that action.

The new passkey does not change how this sign-in authenticated. The session
keeps the `amr` and `acr` of the sign-in the person had already completed.

## The mail-encryption activity

The second block of the policy. Its fields may be left out of a save
through the management API: what the profile stored is kept, so a client
written before the block existed is not refused.

| Field | Default | What it does |
|---|---|---|
| Ask for post-quantum mail encryption (`mailEnabled`) | off | When on, a person whose mail is encrypted to a classical key (an OpenPGP key whose encryption key is not ML-KEM, or an S/MIME certificate whose key is not ML-KEM) is asked after signing in. A named profile with this off excludes the people it reaches. |
| Mail encryption: Skip puts it off for (`mailSnoozeDays`) | 7 days | 1–90. |
| Mail encryption: allotted time (`mailGraceDays`) | 0 | From the first invitation to this activity; 0 means no deadline. |
| Mail encryption: a person whose mail is not encrypted (`mailNoKey`) | `leave` | `leave`, `invite` (always skippable) or `require`. |
| Mail encryption: what is offered (`mailPrefer`) | `either` | `either` (an OpenPGP key and an S/MIME certificate, the kind the person uses now first), `openpgp` or `smime`. |
| Mail encryption: keep the classical OpenPGP key for (`mailKeepClassical`) | 90 days | How long the classical OpenPGP key a post-quantum one replaces stays beside it (0–3650; 0 removes it at once). |

**Who is asked.** Only where the realm can take what the step offers: an
OpenPGP key needs one of RFC 9980's ML-KEM composites
(`ML-KEM-768+X25519`, `ML-KEM-1024+X448`) on `openpgp.algorithms` (empty
names every algorithm), and an S/MIME certificate needs a runtime that can
encrypt to ML-KEM. A person with no mail address is not asked: a key is
registered for the address on the person's entry.

**What the person does.** For OpenPGP, they press *Get a challenge to
sign*, sign the text with their new key (`gpg --clearsign`) and paste the
signed text and the public key. The proof of possession, the user-id rule
and the allow list are those of the portal's [OpenPGP page](openpgp.md);
the key's encryption subkey must also be ML-KEM, or it is refused
(STS-OPENPGP-0033) before anything is written. An OpenPGP card cannot hold
such a key yet, so the key is kept in software and nothing is recorded as
hardware-bound. For S/MIME, they paste a certificate whose key is ML-KEM
and which names their address (STS-AUTHN-0600 for any other). This
service does not issue ML-KEM S/MIME certificates. Mail to the person is
then encrypted with the new key.

**The classical OpenPGP key is kept for a while.** When a post-quantum
key replaces a classical one at this step, the classical key stays on the
person's entry, and is published in the Web Key Directory with the new
one, for `mailKeepClassical` days, so a correspondent that cannot use the
new key can still find the old one. Mail from this service goes to the new
key at once. After that, the scheduler job
`post-login.mail-classical-retire` (hourly, **Monitoring → Scheduler**)
removes it from the entry and the directory; a key past its time is
already left out of the directory whether or not the job has run. A
registration on the portal outside this step replaces the key as before.

## The PIV re-issue

The third block of the policy. Like the mail-encryption block, its fields
may be left out of a save through the management API.

| Field | Default | What it does |
|---|---|---|
| Ask for PIV certificate re-issue (`pivEnabled`) | off | When on, a person holding a [PIV slot certificate](hardware-tokens.md#piv-certificate-profiles) this realm issued, in a slot `pivSlots` names, is asked after signing in to enrol a new one when it is due. A named profile with this off excludes the people it reaches. |
| PIV re-issue: Skip puts it off for (`pivSnoozeDays`) | 7 days | 1–90. |
| PIV re-issue: allotted time (`pivGraceDays`) | 0 | From the first invitation to this activity; 0 means no deadline. |
| PIV re-issue: slots (`pivSlots`) | `9a,9c,9d,9e` | The slots looked at, comma-separated. |
| PIV re-issue: what makes a certificate due (`pivTrigger`) | `both` | `classical-issuer`, `expiring` or `both`. |
| PIV re-issue: renew this long before expiry (`pivRenewDays`) | 30 days | 1–365, for `expiring` and `both`. |
| PIV re-issue: what is issued (`pivTarget`) | `reissue` | `reissue`, or `rekey`, which asks nobody (below). |

**Who is asked.** Slot by slot, the person's newest valid certificate of
that slot's profile (`piv-auth` 9a, `piv-sign` 9c, `piv-key-management`
9d, `piv-card-auth` 9e) is due when:

* `classical-issuer`: its issuer signed it with a classical algorithm **and**
  the realm's EST Issuing CA has a post-quantum or composite key. A
  certificate re-issued under a classical CA would be no better, so nobody
  is asked for this until the EST Issuing CA is rebuilt with an ML-DSA or
  SLH-DSA key on **Protocols → PKI**;
* `expiring`: it expires within `pivRenewDays`.

A slot whose profile is not in `est.allowedProfiles` is never asked for,
since the enrolment would be refused, and a person who holds no PIV
certificate is not asked: this activity re-issues, it does not hand out
cards. **The key on the card stays classical**: a YubiKey makes no
post-quantum key today, so `pivTarget` `rekey` asks nobody; it is there
for when a card can.

**What the person does.** For each due slot the step shows the
certificate and why it is due, and the `ykman` commands that make a new
key and request in the slot (`ykman piv keys generate`, `ykman piv
certificates request`) and the attestations (`ykman piv keys attest`,
`ykman piv certificates export f9`). They paste the request, the slot's
attestation and the f9 certificate. Everything the
[PIV enrolment form](hardware-tokens.md#piv-key-attestation) checks is
checked: the profile, the attestation, and that the certificate is the
person's own. The new certificate is shown with the command that writes
it to the card (`ykman piv certificates import <slot> certificate.pem`).
When every due slot has a new certificate, *Continue* finishes the
activity and the sign-in goes on.

**The old certificate keeps working until the new one is used.** It is
revoked (reason `superseded`) the first time the person signs in with the
new certificate, over TLS or at the sign-in screen, not when it is
issued: a person whose import failed still has a card that signs them in.
If that revocation fails it is tried again at the next sign-in
(STS-PIV-0038). A certificate the person never uses goes on being valid
until it expires.

## Skip, and the allotted time

- **The first invitation starts the clock.** iya-sts records when the person was
  first asked, until when they skipped, and when they finished. This is kept
  per person per realm in the store `post_login.progress`.
- While a skip is in force, the person is not asked.
- Once `graceDays` have passed since the first invitation, the activity is
  **required**. Skip is gone, and a skip still in force no longer counts. The
  sign-in is held until the passkey is registered.
- `noPasskey: invite` is never required.

## Following the migration

Where each person stands is a report, not a console page. Open the reports
application (`/report`) and choose the `postLoginProgress` source: one row
per person and activity, with when they were first asked, how often they
were asked and skipped, whether they did it, when the allotted time ends, and
whether it already has. Its page offers three predefined queries — progress
by activity, the people past their grace period, and the people who skipped
most. See [Reports](reporting.md#postloginprogress) for every field.
Two more sources follow the passkeys themselves:
[`passkeyHistory`](reporting.md#passkeyhistory), the share of people
holding an ML-DSA passkey day by day, and
[`passkeyCeremonies`](reporting.md#passkeyceremonies), where registrations
fail and on which clients.

## Starting an activity

Open **Directory → Post-login activities** (`/admin/post-login-activities`),
the **Start an activity** tab. A started activity does two things while it
runs:

- **At sign-in it asks its people.** Everybody it reaches — the members of
  its groups, or everybody in the realm — is asked at their next sign-in,
  **even where the post-login policy is off**. You do not have to switch the
  policy on as well.
- **By mail it reminds them.** The activity is otherwise asked only when a
  person signs in, so somebody who rarely signs in may not be asked before a
  deadline; the reminders bring them to the sign-in.

**The rules come from the policy.** For each person, the profile the policy
selects for them on **Directory → Policies** — the named profile of lowest
precedence among those the application and their groups name, else
`default` — supplies the snooze, the allotted
time, the method, what a person with no passkey is asked, the
attestation and the fallback. The started activity only switches it on.

**Excluding still works.** A named profile with `enabled` off that reaches a
person (at a lower precedence than any profile that would switch it on) keeps
them out of every started activity, as it keeps them out of the policy. One a
group names keeps its members out of the mails too; one an application names
keeps them out at a sign-in to that application only. The `default` profile
being off excludes nobody: that is how every realm starts.

**Paused or ended, it asks nobody.** A person the policy itself switches on
is still asked, as before.

**Choose the groups first, or none.** Search for a group by part of its name
or DN; the results come twenty at a time, with *next* and *previous* links.
Pick a result to add it to the list of groups, pick more to add more, and
**Remove** any you did not mean. The activity mails the members of every
group on the list — their union, so somebody in two of the groups is mailed
once. With no group chosen, it reaches everybody in the realm. Whether a
person is in a group is read from their own memberships when they sign in.

Then fill in the form and press **Start**:

| Field | What it means |
|---|---|
| Activity | The post-login activity: `pqc-passkey-migration`. |
| Days between reminders | No person is mailed twice within this many days (1–365, default 7), whichever started activity sent the last mail. |
| Most mails per person | The most this started activity sends one person (1–20, default 3). |
| People read per run | How many people one run reads (1–20000, default 1000). |

A scheduler job, `post-login.activity-mail`, runs about every ten minutes in
a realm with a started activity running (Run now on **Monitoring →
Scheduler** starts it at once). Each run reads the next slice of the
activity's people and mails those it is due for: the activity reaches them
and no named profile switched off excludes them, the realm can make the
passkey, and they have not done it.
When it reaches the end of the people it starts again from the beginning;
that next pass sends the reminders.

- **The mail only sends the person to sign in.** Its one link opens the
  user portal (`/portal`), which sends them to the sign-in page. It carries no code or token and nothing about the person. The
  activity is asked at the sign-in, as always.
- **It goes to the address on the person's entry**, never one from a request.
  Somebody with no address, or who declined notifications on `/portal/email`,
  is not mailed. A realm with no mail transport mails nobody, and the page
  says so.
- **A mail is not an invitation.** The allotted time still starts at the first
  time the person is asked at a sign-in.
- **Pause** stops the asking at sign-in and the mailing, and keeps the
  activity's place. **Resume** carries on from there. **End** stops both for
  good. Only one may run at a time for
  the same activity and the same groups (in any order), or for the same
  activity across the whole realm.

The **Activities** tab lists every activity started in the realm, with its
groups, its numbers, its state and what its runs have done.

The same controls are on the management API:
`GET /admin-api/post-login-activities` (with `groupq`, `groupfrom` and
`groups` it also answers the group search the page draws), and
`POST /admin-api/post-login-activities/start`, `/pause`, `/resume` and `/end`
(the bodies are in `GET /admin-api/openapi.json`). The start takes `groups`,
a list of group names or DNs; a group the realm does not have is refused by
name (STS-AUTHN-0530) and nothing is started. Starting, pausing and ending
need Admin Write.

```json
{ "activity": "pqc-passkey-migration", "groups": ["engineering", "finance"],
  "intervalDays": 7, "maxMails": 3 }
```

**Who was asked and mailed, and when, is a report.** The person's progress
row records who asked them at a sign-in (`askedBy`: `policy`, or the started
activity's id) and each mail (`mailedBy`, the started activity that mailed
them; how many mails it sent them; the first and the last), and the
`postLoginProgress` source in the
[reports application](reporting.md#postloginprogress) reads it. The console
page shows only each started activity's own counts.

## Sign-ins that don't use the sign-in screen

A federated sign-in, a wallet, Kerberos (SPNEGO) or a client certificate can
finish without the sign-in screen.

- **Optional activity:** these sign-ins are not interrupted.
- **Required activity:** these sign-ins are **refused** with STS-AUTHN-0473.
  The person is told to sign in at the sign-in screen, where they will be asked
  to register the passkey.

Programs signing in with a key (SCIM, the SPIRE Server API) are never asked.

## Audit rows

| Action | When |
|---|---|
| `authn.post-login.asked` | A person was asked; `askedBy` says whether the policy or a started activity asked. |
| `authn.post-login.skipped` | A person skipped; the row includes when the skip ends. |
| `authn.post-login.done` | A person did the activity: for the passkey migration the row includes the passkey's algorithm; for mail encryption the kind (`openpgp` or `smime`), the fingerprint or serial, and when a kept classical key goes. |
| `piv.reissued`, `piv.superseded` | A PIV re-issue enrolled a new certificate (with the serial it replaces), and later revoked the old one when the new one was first used. |
| `openpgp.classical-kept`, `openpgp.classical-retired` | A classical OpenPGP key was kept beside a post-quantum one, and later removed. |
| `authn.post-login.held` | A required activity refused a sign-in at a door that can't ask for it. |
| `authn.post-login.unsupported` | The person's device did not complete the passkey ceremony; the error name, the browser and the platform. |
| `webauthn.key.possibly-replaced` | A new passkey under the same user handle and AAGUID may have replaced an older one on its authenticator ([Passkeys](passkeys.md#a-passkey-that-may-have-been-replaced-on-its-authenticator)). |
| `admin.post-login-policy.change` | A profile was saved or reset. |
| `admin.post-login-activity.change` | A post-login activity was started, paused, resumed or ended; the row says which, and a start lists its groups. |
| `authn.post-login.activity-run` | One run of a started activity's job: how many people were read, mailed, not due, held back by the interval or the maximum, and refused by the mail channel. One row per started activity per run, never per person. |

## Error codes you will meet

| Code | Meaning |
|---|---|
| STS-AUTHN-0470, 0471, 0472 | A profile was not saved: bad name, bad values, or no directory. |
| STS-AUTHN-0473 | A required activity refused a sign-in at a door that can't ask for it. |
| STS-AUTHN-0474 | Skip was refused because the allotted time has passed. |
| STS-AUTHN-0475 | The realm could no longer make an ML-DSA passkey, so the held session started without one. |
| STS-AUTHN-0450 – 0458 | An upgrade ceremony did not complete; the classical passkey is unchanged. |
| STS-AUTHN-0490, 0491, 0492 | A post-login activity was not started or changed: bad values or too many groups, no such started activity or the wrong state, or one already running for the same people. |
| STS-AUTHN-0530 | A post-login activity was not started: a group it names does not exist in the realm. |
| STS-AUTHN-0493 | A started activity's run could not read its people (or one of its groups is gone); its place did not move. |
| STS-AUTHN-0494 | The mail channel refused some reminders (no address, declined, a ceiling). |
| STS-AUTHN-0495 | A post-login activity is running in a realm with no mail transport. |
| STS-AUTHN-0542 | A group or an application names a post-login profile the realm does not hold; that reference counts for nothing. |
| STS-AUTHN-0543 | A named post-login profile was not deleted: a group or an application still names it. |
| STS-AUTHN-0600 | The mail-encryption step refused an S/MIME certificate whose key is not ML-KEM. |
| STS-AUTHN-0601, 0602 | The step was sent a kind of key it does not offer, or another activity's act. |
| STS-AUTHN-0603 | The realm can no longer take anything the mail-encryption step offered, so the held session started without it. |
| STS-AUTHN-0620, 0621 | A PIV re-issue act named a slot the step does not ask for, or one whose profile the realm no longer enrols. |
| STS-AUTHN-0622 | *Continue* was pressed before every due slot had a new certificate. |
| STS-AUTHN-0623 | The realm no longer enrols any profile the PIV step asked for, so the held session started without it. |
| STS-PIV-0038, 0039 | A superseded PIV certificate could not be revoked at its successor's first use (tried again next time), or a re-issued certificate was used by somebody else (nothing revoked). |
| STS-OPENPGP-0033 | An OpenPGP key registered at the step has no ML-KEM encryption subkey. |
| STS-OPENPGP-0031, 0032 | A classical OpenPGP key could not be kept, or could not be removed by the job. |

See [error codes](error-codes.md) for the full list.

## Related

- [Passkeys and WebAuthn](passkeys.md): lanes (and `lanes` per population
  on the passkey policy), algorithms, requiring a post-quantum passkey at
  sign-in, and the upgrade ceremony.
- [Authentication](authentication.md)
- [Admin console](admin-console.md)
