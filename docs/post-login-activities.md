---
title: "Post-login activities"
---

# Post-login activities

A **post-login activity** is something a realm asks a person to do after they
sign in, before they are sent back to the application. In iya-sts it is a
policy: you switch it on per realm, and you target it at people by group.

One activity exists today:

| Activity | What the person is asked |
|---|---|
| `pqc-passkey-migration` | To register a **post-quantum (ML-DSA) passkey**. A person who signs in with a classical passkey is asked for one to sign in with. A person whose second factor is a classical passkey is asked for one as a second factor. A person with no passkey can be invited or required to register one. |

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
   `/authn/post-login` (**Register a post-quantum passkey**), with **Register**,
   **Skip for N day(s)** while skipping is still allowed, and **Start over**.
3. **Register** goes to the passkey page, which offers ML-DSA only. When the
   passkey is registered, the session the sign-in was held for starts and the
   person goes back to the application. Their classical passkey stays
   registered; they can remove it at `/portal/keys`.
4. **Skip** puts the activity off for `snoozeDays`. The held session then
   starts.

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
| `admin.post-login-policy.change` | A profile was saved or reset. |

## Error codes you will meet

| Code | Meaning |
|---|---|
| STS-AUTHN-0470, 0471, 0472 | A profile was not saved: bad name, bad values, or no directory. |
| STS-AUTHN-0473 | A required activity refused a sign-in at a door that can't ask for it. |
| STS-AUTHN-0474 | Skip was refused because the allotted time has passed. |
| STS-AUTHN-0475 | The realm could no longer make an ML-DSA passkey, so the held session started without one. |

See [error codes](error-codes.md) for the full list.

## Related

- [Passkeys and WebAuthn](passkeys.md): lanes, algorithms, requiring a
  post-quantum passkey at sign-in, and upgrading a classical one at
  `/portal/keys`.
- [Authentication](authentication.md)
- [Admin console](admin-console.md)
