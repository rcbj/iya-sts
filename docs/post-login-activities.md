---
title: "Post-login activities"
---

# Post-login activities

A **post-login activity** is something a realm asks a person to do after they
sign in, before they are sent back to the application. In iya-sts it is a
policy: you switch it on per realm, and you target it at people by group.
[Passkeys → Post-login activities](passkeys.md#post-login-activities-moving-people-to-post-quantum-passkeys)
walks through a rollout; this page is the reference.

One activity exists today:

| Activity | What the person is asked |
|---|---|
| `pqc-passkey-migration` | To register a **post-quantum (ML-DSA) passkey**. A person who holds a classical passkey to sign in with is asked for an ML-DSA one to sign in with. A person whose second factor is a classical passkey is asked for one as a second factor. A person with no passkey can be invited or required to register one. |

More activities will use the same policy and the same step.

## Before you start

- Post-login activities are **off by default** in every realm.
- The realm has to be able to make an ML-DSA passkey. Passkeys must be on
  (`webauthn.enabled`), the role must be allowed (`webauthn.primaryAllowed` or
  `webauthn.mfaAllowed`), and an ML-DSA algorithm must be offered at
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
| Registered by a person with no passkey as (`noPasskeyRole`) | `primary` | `primary`: a passwordless sign-in. `mfa`: a second factor. |
| How a classical passkey is migrated (`method`) | `automatic` | `upgrade`: the person uses the classical passkey once, then an ML-DSA passkey **replaces it in place** on the same authenticator. `alongside`: an ML-DSA passkey is added beside it. `automatic`: `alongside` where the person's passkey policy offers two lanes, `upgrade` where it offers one. |
| A passkey counts as post-quantum when (`attestation`) | `any` | `any`: its key algorithm is ML-DSA. `post-quantum`: its recorded attestation is post-quantum too; a person whose ML-DSA passkey has a classical attestation, or none recorded, is asked for one beside it, whatever `method` says. |
| A person with no passkey whose device cannot make ML-DSA (`noPasskeyFallback`) | `none` | `none`: ML-DSA only. `classical`: a retry with the classical algorithms is offered after the ML-DSA registration fails — a classical passkey is better than a password, and the person is asked to migrate it later. |

### Targeting by group

The `default` profile reaches everyone in the realm. A realm without its own
`default` profile follows the default realm's.

A **named profile** reaches the members of the groups it lists in
`selectGroups` (a group's cn or DN). When several named profiles reach the same
person, the one with the lowest `precedence` (1–1000) wins.

**To exclude a group**, create a named profile for that group, switch `enabled`
off, and give it a lower precedence than the profile that would otherwise reach
its members.

**Example: a pilot group, required within 30 days**

```json
POST /admin-api/policies/save-postLogin-policy
{ "profile": "pqc-pilot",
  "selectGroups": ["pqc-pilot"], "precedence": 10,
  "enabled": true, "activity": "pqc-passkey-migration",
  "snoozeDays": 3, "graceDays": 30,
  "noPasskey": "invite", "noPasskeyRole": "primary" }
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

## Mail campaigns

The activity is asked only when a person signs in, so somebody who rarely
signs in may not be asked before a deadline. A **mail campaign** reminds them
by mail. Open **Directory → Post-login campaigns** (`/admin/post-login-campaigns`)
and start one:

| Field | What it means |
|---|---|
| Activity | The post-login activity: `pqc-passkey-migration`. |
| Group | Optional. A group's name or DN: only its members are mailed. Empty is everybody in the realm. |
| Days between reminders | No person is mailed twice within this many days (1–365, default 7), whichever campaign sent the last mail. |
| Most mails per person | The most this campaign sends one person (1–20, default 3). |
| People read per run | How many people one run reads (1–20000, default 1000). |

A scheduler job, `post-login.campaign-mail`, runs about every ten minutes in a
realm with a campaign running (Run now on **Monitoring → Scheduler** starts it
at once). Each run reads the next slice of the campaign's people and mails
those the activity is due for: the post-login policy reaches them, the realm
can make the passkey, and they have not done it. When it reaches the end of
the people it starts again from the beginning; that next pass sends the
reminders.

- **The mail only sends the person to sign in.** Its one link opens the
  user portal (`/portal`), which sends them to the sign-in page. It carries no code or token and nothing about the person. The
  activity is asked at the sign-in, as always.
- **It goes to the address on the person's entry**, never one from a request.
  Somebody with no address, or who declined notifications on `/portal/email`,
  is not mailed. A realm with no mail transport mails nobody, and the page
  says so.
- **A mail is not an invitation.** The allotted time still starts at the first
  time the person is asked at a sign-in.
- **Pause** stops mailing and keeps the campaign's place. **Resume** carries on
  from there. **End** stops it for good. Only one campaign at a time may run
  for the same activity and the same people.

The same controls are on the management API:
`GET /admin-api/post-login-campaigns`, and
`POST /admin-api/post-login-campaigns/start`, `/pause`, `/resume` and `/end`
(the bodies are in `GET /admin-api/openapi.json`). Starting, pausing and ending
need Admin Write.

**Who was mailed, and when, is a report.** Each mail is recorded on the
person's progress row (the campaign, how many mails it sent them, the first and
the last), and the `postLoginProgress` source in the
[reports application](reporting.md#postloginprogress) reads it. The console
page shows only each campaign's own counts.

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
| `authn.post-login.asked` | A person was asked. |
| `authn.post-login.skipped` | A person skipped; the row includes when the skip ends. |
| `authn.post-login.done` | A person registered the passkey; the row includes its algorithm. |
| `authn.post-login.held` | A required activity refused a sign-in at a door that can't ask for it. |
| `authn.post-login.unsupported` | The person's device did not complete the passkey ceremony; the error name, the browser and the platform. |
| `webauthn.key.possibly-replaced` | A new passkey under the same user handle and AAGUID may have replaced an older one on its authenticator ([Passkeys](passkeys.md#a-passkey-that-may-have-been-replaced-on-its-authenticator)). |
| `admin.post-login-policy.change` | A profile was saved or reset. |
| `admin.post-login-campaign.change` | A mail campaign was started, paused, resumed or ended; the row says which. |
| `authn.post-login.campaign-run` | One run of a campaign's job: how many people were read, mailed, not due, held back by the interval or the maximum, and refused by the mail channel. One row per campaign per run, never per person. |

## Error codes you will meet

| Code | Meaning |
|---|---|
| STS-AUTHN-0470, 0471, 0472 | A profile was not saved: bad name, bad values, or no directory. |
| STS-AUTHN-0473 | A required activity refused a sign-in at a door that can't ask for it. |
| STS-AUTHN-0474 | Skip was refused because the allotted time has passed. |
| STS-AUTHN-0475 | The realm could no longer make an ML-DSA passkey, so the held session started without one. |
| STS-AUTHN-0450 – 0458 | An upgrade ceremony did not complete; the classical passkey is unchanged. |
| STS-AUTHN-0490, 0491, 0492 | A campaign was not started or changed: bad values, no such campaign or the wrong state, or one already running for the same people. |
| STS-AUTHN-0493 | A campaign's run could not read its people; its place did not move. |
| STS-AUTHN-0494 | The mail channel refused some reminders (no address, declined, a ceiling). |
| STS-AUTHN-0495 | A campaign is running in a realm with no mail transport. |

See [error codes](error-codes.md) for the full list.

## Related

- [Passkeys and WebAuthn](passkeys.md): lanes (and `lanes` per population
  on the passkey policy), algorithms, requiring a post-quantum passkey at
  sign-in, and the upgrade ceremony.
- [Authentication](authentication.md)
- [Admin console](admin-console.md)
