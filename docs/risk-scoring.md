---
title: Risk scoring
---

# Risk scoring

iya-sts scores every sign-in for the risk that it is not the person it claims
to be, and records why. It compares where and how a person is signing in with
where and how they have signed in before, and with the whole realm's
sign-ins. It also looks for signals that a comparison can't see: an address
on a Tor or reputation list, an automated client, a TLS client this person
has never used, and a run of refused passwords.

> **The decision is an XACML policy, not code.** The score, its level and
> its signals are given to the issuance policy that every session and every
> token already passes through, and the policy decides: by default HIGH is
> refused, and MEDIUM asks for a second factor or a security key. You can
> change those rules in the policy without a new release. Product mode
> enforces what the policy decides; development mode records it and lets the
> sign-in through (see [How a score decides](#how-a-score-decides)).

Every assessment is shown in the admin console at **Monitoring → Risk**
(`/admin/risk`) and returned by `GET /admin-api/risk`.

## Features

- **A score for every sign-in** that starts or re-authenticates a session:
  the sign-in screen and its second factors, federation, SPNEGO, a client
  certificate, a wallet and WS-Trust. API callers that authenticate on
  every request (SCIM, SPIRE) are not scored, and neither is a session
  started without authenticating.
- **A published statistical model.** The score is Freeman et al.'s model
  ("Who Are You? A Statistical Approach to Measuring User Authenticity",
  NDSS 2016), ported from das-group's reference implementation. It weighs how
  unusual a sign-in's features are for this person against how common they
  are in the realm.
- **Evaluators** add what the model can't see. Each one multiplies the score
  when it is present (see [Evaluators](#evaluators)).
- **A level** in CAEP's own terms: LOW, MEDIUM or HIGH. A person's first
  sign-in is UNSCORED, because there is nothing yet to compare it with.
- **A history of refused passwords** from every door that checks one: the
  sign-in screen, an LDAP bind, the OAuth password grant, WS-Trust, SCIM and
  Shared Signals Basic authentication, and EST. Each is attributed to a
  person, or to a digest of a name that matched nobody, and to a network.
- **External datasets** supply geolocation, the network an address belongs
  to, Tor exits, IP reputation and your own allow and deny lists. The
  deployment supplies them and imports them into its own database at install
  time. None is shipped with iya-sts (see [Datasets](#datasets)).

## How a sign-in is scored

For each sign-in the service:

1. **Looks the address up** in the active datasets: its country, city and
   network (ASN), and which lists it is on.
2. **Reads the device** from the browser's `User-Agent`: the browser and its
   major version, the operating system and the device type. It also notes
   whether the client is automated. The header itself is never kept; a
   fingerprint of it stands in for it.
3. **Scores it with the model** against the person's history and the realm's,
   both as they stood before this sign-in.
4. **Applies the evaluators** and sets the level.
5. **Records the assessment**, adds the sign-in to both histories, and
   updates the person's current standing and the session's last context.

### The model

The model compares two things for each feature: how likely this sign-in's
value is for the whole realm, and how likely it is for this person. A value
the person uses all the time scores low. A value they have never used scores
high, and higher still if it is rare in the realm too. The two features are
hierarchies, so a value seen before at a coarser level still counts for
something:

| Feature | Levels, most specific first |
|---|---|
| Where | the address → its network (ASN) → its country |
| What with | the User-Agent → browser and version → operating system and version → device type |

The score is near or below 1 when a sign-in is as likely to be the person as
an attacker, and far below 1 for a familiar one. A sign-in from a new network
on a new device scores well above 1.

### Evaluators

| Signal | Factor | When |
|---|---|---|
| `tor-exit` | ×5 | the address is on the active Tor exit list |
| `reputation` | ×5 | the address is on the active IP reputation list |
| `operator-deny` | ×50 | the address is on this realm's operator deny list |
| `operator-allow` | ×0.2 | the address is on this realm's operator allow list |
| `automated-client` | ×10 | the User-Agent belongs to an automated client |
| `new-tls-stack` | ×2 | the connection's TLS client fingerprint (JA4) is one this person has not signed in with before |
| `new-device` | ×2 | the browser's fingerprint is one this person has not signed in from before (only with `risk.fingerprinting` on) |
| `account-failures` | ×3 | five or more refused passwords for this person in the last hour |
| `network-failures` | ×3 | twenty or more refused passwords from this network in the last hour |
| `authenticator-compromised` | ×50 | the security key's model is reported revoked or compromised in the FIDO metadata |

These factors are a first calibration. You can change any of them for a
realm with `risk.signalFactors`, without a new release. It takes a list of
`signal=factor` pairs, such as `tor-exit=8,new-device=1.5`. The service
ignores an entry that names no signal, or whose factor is not a positive
number, and logs it once (`STS-RISK-0026`).

### Calibration

Monitoring → Risk Scoring has a **Calibration** section, and
`GET /admin-api/risk/metrics` has a `calibration` member. They suggest
changes from the window's own assessments; nothing is applied until you
apply it.

- **Thresholds**: for MEDIUM-or-worse and for HIGH, the report shows the
  share of sign-ins at that level now, and the score that the target share
  of sign-ins reaches. The targets are `risk.calibrationMediumPercent` (5)
  and `risk.calibrationHighPercent` (1). A threshold is suggested only once
  the window has 100 assessments.
- **Factors**: for each signal, the report compares how often a sign-in
  carrying it was answered "this wasn't me" on `/portal/sign-ins` with how
  often any answered sign-in was. It suggests the current factor scaled by
  that ratio, bounded to ×0.1–×100, and says whether to raise it, lower it
  or keep it. A signal needs 20 answered sign-ins before a factor is
  suggested.

The page gives the `risk.signalFactors` value that would apply every
suggestion. The answers are a biased sample: people are more likely to be
asked about a sign-in that was flagged. Read a suggestion as a direction to
check, not a measurement.

### Levels

| Level | Score |
|---|---|
| LOW | below `risk.mediumScorePercent` ÷ 100 (1 by default) |
| MEDIUM | from `risk.mediumScorePercent` ÷ 100 |
| HIGH | from `risk.highScorePercent` ÷ 100 (10 by default) |
| UNSCORED | a first sign-in with no evaluator signal |

## How a score decides

A score decides nothing by itself. The service's **issuance policy** — the
XACML policy asked before anything is issued, whether a session, an access
token, an ID token, a SAML assertion, a WS-Federation or WS-Trust token, a
Kerberos ticket or a GNAP grant — is given the risk of the authentication as
four attributes, and decides on them in the same evaluation that decides the
person's roles:

| Attribute | What it holds |
|---|---|
| `urn:sts:xacml:risk-level` | `LOW`, `MEDIUM`, `HIGH` or `UNSCORED` |
| `urn:sts:xacml:risk-score` | the score (absent for a first sign-in) |
| `urn:sts:xacml:risk-signal` | every evaluator that fired, such as `tor-exit` |
| `urn:sts:xacml:risk-satisfied` | the step-ups the authentication already meets: `second-factor`, and `security-key` when a WebAuthn key was used |

The built-in policy has three risk rules, ahead of the role rule, and a risk
Deny overrides a role Permit:

| Risk | Decision |
|---|---|
| LOW or UNSCORED | decided on roles alone |
| MEDIUM, with a signal about the device or TLS client (`automated-client`, `new-tls-stack`) | refused until the authentication used a **security key** |
| any other MEDIUM | refused until the authentication carried a **second factor** |
| HIGH | refused |

**An authentication with no assessment is decided on roles alone.** Nothing
unknown is ever a reason to refuse.

**Where a person can act, a step-up is a question, not a refusal:**

- **The sign-in screen** asks for the factor before any session exists.
- **The wallet sign-in** asks for it after the presentation.
- **`/oauth2/authorize`** on an existing session sends the person to sign in
  again with the factor demanded.
- **Doors that cannot ask** refuse, unless the authentication already meets
  the demand: SPNEGO, a federated sign-in, WS-Trust, the token endpoint and
  the Kerberos KDC.

**A step-up never offers to enrol a new factor.** A person who holds nothing
that answers it is refused, because an elevated risk suspects exactly the
person who knows the password and would enrol their own.

**A client is told nothing about the risk.** A refusal says only that
authentication failed. The level, the signals and the assessment are on the
audit record, under `STS-RISK-0016` (refused) and `STS-RISK-0017` (a step-up
the door could not ask for).

**Every session carries the risk it was decided on**, and every token issued
on it is decided on that risk. An issuance with no session, such as a Kerberos
service ticket, uses the person's last assessed risk held by that node, for
`risk.standingValidMinutes`.

### Changing the rules

The rules are an ordinary policy on **XACML → Policies**: a realm's own
override of `role-issuance` replaces the built-in document in that realm. You
can permit MEDIUM, refuse it outright for administrators, add a rule on any
attribute of the person's directory entry, or change which signals demand a
key — the `role-issuance` template's `keySignals` parameter. Building the
template with `decideRisk` set to `no` gives the roles-only policy.

**An override written before these rules existed reads no risk attribute**,
and that realm then refuses nothing on risk. The console says so on the
policy's status.

## When a person's risk changes

Every assessment updates the person's **standing**: their current level.
When the level changes, a second built-in policy, **`risk-response`**, is
asked what should happen. It is asked once for each possible reaction, and a
Permit means the reaction is taken:

| Reaction | The built-in policy takes it when |
|---|---|
| **Announce** a CAEP `risk-level-change`, naming the person | the level changes, except a person's first level being LOW |
| **End everything the person holds** — every session and token, with back-channel Logout Tokens | the level crosses into HIGH |
| **Tell RISC a credential is compromised** (`credential-compromise`) | the level crosses into HIGH on evidence about a credential (`account-failures` by default) |
| **Disable the account** (RISC reason `hijacking`) | never, unless you build the policy with a score (`disableFromScore`): anyone who can make a person's sign-ins look risky could otherwise lock them out |

Each reaction is taken once per assessment, however many times the change is
seen. In development mode only the announcement is made; the other reactions
are recorded as observed, unless `risk.enforceInDevelopment` is on. The
console and portal are receivers of this service's own Shared Signals, so an
announcement also reaches their signal inboxes.

Like the issuance policy, `risk-response` is an ordinary policy on **XACML →
Policies**, named by `xacml.riskResponsePolicy`. A realm's own override
decides for that realm, and disabling the override takes no reaction at all.

### Live sessions

A session's risk is not fixed at sign-in:

- **A session presented from a different device, TLS client or network** is
  assessed again in the background. A different device means a different
  browser or operating system; a browser that updated itself is not one. The
  new assessment becomes the session's risk, so the next token issued on it
  is decided on it. A cookie replayed from another machine is the case this
  is for, and it usually scores HIGH.
- **The `risk.rescore` job** re-checks every live session, every
  `risk.rescoreEveryS` seconds, against the active datasets and the failure
  history. A session whose address has since become a Tor exit or been
  denied, or whose person's password is being guessed, is raised, never
  lowered.

Both update the person's standing, so a change is answered by `risk-response`
as any other is.

### What people say about their own sign-ins

Each person sees their own assessed sign-ins of the last thirty days on the
user portal, at **Recent sign-ins** (`/portal/sign-ins`): when, from where,
with what browser and system, and at what level. Each has two buttons:

- **This wasn't me** puts the person's risk at HIGH. By default that ends
  every session they hold, this one included, and RISC is told their
  credential is compromised. They are asked to sign in again and change their
  password.
- **This was me** is recorded, and lowers the person's risk to LOW only when
  it is said from a different session that is itself low-risk. Said from the
  flagged session itself, it moves nothing: that session could be the one an
  attacker is using.

Each sign-in can be answered once. Administrators see the answers on
Monitoring → Risk.

## Browser fingerprinting (optional, off by default)

With `risk.fingerprinting` on in a realm, the sign-in screen runs one
script, [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs)
(MIT). It computes an identifier from what the browser exposes (its canvas,
audio and font behaviour, and similar) and puts it in a hidden field of the
form. The script sends nothing anywhere, and the form works exactly as before
if the script is blocked. The service keeps only a keyed digest of the
identifier, never the identifier. A browser this person has never signed in
from is the signal `new-device` (×2).

**A browser fingerprint is personal data** about the person's device,
collected without them doing anything, so turning it on is your decision to
make and document. Before you turn it on, complete a privacy impact
assessment. At least:

| Question | What to record |
|---|---|
| Purpose | Detecting sign-ins from a browser the person has not used before, as one input to the risk score. |
| Lawful basis | Yours to decide: legitimate interest in account security is the usual one. Record the balancing test. |
| Data collected | A digest of the FingerprintJS identifier, per sign-in, in the risk history. No raw identifier is kept. |
| Retention | `risk.assessmentRetentionDays` and `risk.historyRetentionDays`. |
| Who can see it | Administrators, on Monitoring → Risk (as a digest), and the person, on `/portal/sign-ins` (as a device). |
| Notice | What the people who sign in are told, and where. |
| Alternatives considered | Security keys and passkeys identify a device far better and are not personal data in the same way. JA4 and the User-Agent are already scored without a script. |
| Opt-out | The setting is per realm; there is no per-person opt-out. |

## Breached passwords

In product mode, a password is checked against Have I Been Pwned's **Pwned
Passwords** when it is set, and one that has appeared in a data breach is
refused (NIST SP 800-63B section 3.1.1.2). The check uses **k-anonymity**:
only the first five characters of the password's SHA-1 are sent, to
`risk.breachApiUrl`. The service matches the rest itself, so neither the
password nor its full digest ever leaves it. Nothing from the corpus is kept
beyond a short cache of the answers.

Every door that sets a password is checked: the portal's password change,
activation link and reset link, the forced change at sign-in, the console and
`/admin-api`, and an LDAP add or modify of `userPassword`. A password the
service generates is not checked.

With `risk.breachCheckAtSignIn` on, a correct password typed at the sign-in
screen is checked too. One that has appeared in a breach must be changed
before the sign-in finishes.

**If the API cannot be reached, the password is set unchecked.** An outage of
a service you do not run should not stop people changing their passwords.
The request goes through the same outbound rules as every other:
`federation.outbound` switches it off, and product mode verifies its TLS.
Point `risk.breachApiUrl` at a mirror to keep the check inside your network.
Development mode checks no password.

## Datasets

**iya-sts distributes no third-party dataset.** None is in the repository,
the container images or the tests. Each deployment obtains its datasets under
the provider's terms and imports them into its own database. There are three
ways in:

- **At install time, with the loader.** Run it inside the image, with
  `STS_DATABASE_URL` set:

  ```bash
  node risk/risk_install.js \
    --manifest datasets.json \
    --accept-terms dbip-lite,tor-project \
    --operator "Jo Operator" \
    --terms-log ./risk-terms-acceptance.log \
    --check-terms
  ```

  `datasets.json` lists the datasets, each with `dataset`, `format`, and
  either a `url` or a `file`. Each can also carry `version`, `publishedAt`
  and `sha256`. The loader downloads over HTTPS only. It gunzips a `.gz` file
  and imports each dataset the same way the console does.
- **Through a watched directory.** Set `risk.datasetsDirectory` and put each
  file beside a JSON manifest with the same fields, `file` naming the file.
  The `risk.dataset-directory` job imports each manifest once.
- **Through the console or the API.** Paste a list on Monitoring → Risk, or
  send `POST /admin-api/risk/import`. This suits small lists; a file of
  millions of rows belongs in the loader or the directory.

The running service never fetches a dataset. It does fetch the CRLs of a
FIDO BLOB's signing chain when a BLOB is uploaded to it, as it does for any
certificate chain presented to it.

| Dataset | What it holds | Formats |
|---|---|---|
| `geo.city` | country, region, city and coordinates | DB-IP Lite "IP to City" CSV |
| `geo.country` | country; used where no city dataset answers | DB-IP Lite "IP to Country" CSV, IPinfo Lite CSV |
| `asn` | the network (ASN) and its operator | DB-IP Lite "IP to ASN" CSV, IPinfo Lite CSV |
| `iplist.tor-exit` | Tor exit addresses | one address, CIDR block or range per line |
| `iplist.reputation` | an IP reputation list | the same |
| `iplist.operator-deny`, `iplist.operator-allow` | your own lists, one per realm | the same |
| `fido.mds3` | every FIDO-certified authenticator model and its status reports, by AAGUID | the MDS3 BLOB exactly as FIDO publishes it: one signed JWT |

### The FIDO metadata

The FIDO Alliance's Metadata Service (MDS3) lists every certified
authenticator model. It also says when a model has been **revoked**, or its
keys can be extracted, or its user verification bypassed. A security key of
such a model proves possession of something anybody may hold, so a sign-in
with one carries the signal `authenticator-compromised` (×50) and is HIGH.
The `risk.rescore` job raises a live session resting on such a key when a new
BLOB reports it. RISC's `credential-compromise` then names a FIDO credential,
not a password.

Load it with the loader, adding `fido-mds3` to `--accept-terms`:

```json
{ "datasets": [ { "dataset": "fido.mds3", "format": "fido-mds3-jwt",
                  "url": "https://mds3.fidoalliance.org/" } ] }
```

Before anything is kept, each BLOB goes through the checks MDS3 section 3.1.8
names:

- **The signature and the chain.** The chain must end at the FIDO root,
  GlobalSign Root CA - R3, which is found in the Node.js root store; iya-sts
  ships no FIDO certificate. `risk.mdsTrustAnchors` pins a different root.
- **Revocation.** Each certificate in the chain is checked against its CRL,
  under the same revocation policy as any other presented certificate.
- **A serial number greater than any BLOB already processed.** An older one
  is a rollback and is refused.

As FIDO's terms require, **only the latest BLOB is kept**: when a new one
becomes active, the older one's rows are deleted at once. It stops answering
`risk.mdsStaleGraceDays` after the date the BLOB says the next one is due; run
the loader again before then, or set `risk.mdsUrl` and let the
`risk.mds-refresh` scheduler job download it daily (MDS3 section 3.2 — hourly
once the active BLOB is overdue), under the same acceptance and the same
checks. An authenticator the metadata does not list, including one that
attests nothing (the all-zero AAGUID), is simply unknown.

**The same BLOB serves WebAuthn attestation (#105).** A security key's
registration is checked against it: the model's attestation root
certificates anchor its attestation chain, and a model a status report calls
REVOKED, USER_VERIFICATION_BYPASS or a KEY_COMPROMISE is refused outright
(`STS-AUTHN-0237`) rather than scored. See
[Authentication](authentication.md).

### Each version is checked before it becomes active

- **A SHA-256 you name must match the file.**
- **A version with far fewer rows than the active one is refused.** "Far
  fewer" is set by `risk.datasetShrinkLimitPercent` (50 by default); a
  truncated download looks exactly like a smaller dataset.
- **A file with no valid row is refused.**
- **A refused version is kept**, with its reason, and the active version
  stays active.
- **Loading the same version twice loads nothing.**

**Rollback** makes the previous version active again. A superseded version's
rows are deleted after `risk.supersededRetentionDays`; its record stays.

**A stale dataset counts for nothing.** Geolocation and ASN data older than
`risk.geoStaleAfterDays`, and Tor or reputation lists older than
`risk.ipListStaleAfterHours`, are left out of every lookup and marked stale
on the page. Stale or missing data never refuses anybody, and never stops the
service from starting.

### Providers and their terms

**No provider's data is imported until somebody has accepted that provider's
current terms.** The acceptance is recorded in the database and on the audit
log, with:

- who accepted,
- through which door (the loader, the console or the API),
- from which deployment,
- when,
- the text of the terms they accepted.

The loader also appends each acceptance to its `--terms-log` file. You can
accept terms in three ways:

- with the loader's `--accept-terms`,
- on Monitoring → Risk, with the button beside each provider or the checkbox
  on the import form,
- with `POST /admin-api/risk/accept-terms`.

The dataset directory never accepts terms on anyone's behalf.

If a later iya-sts release restates a provider's terms, the earlier
acceptance no longer covers them, and imports from that provider stop until
somebody accepts again. With `--check-terms` the loader also fetches each
provider's own terms page, and warns when it has changed since the last
acceptance.

| Provider | Terms | What it means for you |
|---|---|---|
| **DB-IP Lite** | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) | **The recommended default.** Attribution with a link back is required wherever its results are shown. The console credits it everywhere a result appears: the source linked, the licence named and linked, and a note that the data was reformatted here. |
| **IPinfo Lite** | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) | **IPinfo data must stay in your database and must not be bundled with a software distribution.** ShareAlike binds whoever distributes the data. DB-IP Lite covers the same country and ASN data without ShareAlike. |
| **Tor Project exit list** | as published by the Tor Project | Check the terms of the exact list you download. |
| **FireHOL lists** | each list's own terms | An aggregate: each list inside it (DShield, Feodo, Fullbogons, Spamhaus DROP and others) keeps its own terms. Use it internally and never redistribute it. |
| Your own lists | yours | Nothing to accept. |
| **MaxMind GeoLite2** | GeoLite EULA | **Not supported.** An import naming it is refused. |
| **FIDO MDS3** | FIDO Alliance metadata terms | Contractual metadata, not open data: use it for FIDO authentication, keep only the latest BLOB, and do not copy or redistribute it. |
| **Pwned Passwords** | the range API, which carries no licensing or attribution requirement | Asked by k-anonymity when a password is set; nothing is imported, so there is nothing to accept. |

## What is kept about the people who sign in

Risk scoring builds a profile of how each person signs in. That profile is
personal data:

| What | Kept for |
|---|---|
| **Each assessment.** The address is sealed under the key-encryption key and also kept as its /24 (IPv4) or /48 (IPv6) network. It also holds the country, city and ASN; the browser family, OS and device type; a fingerprint of the User-Agent; the TLS client fingerprint; which kind of credential answered; the score, the level and the signals. | `risk.assessmentRetentionDays` (90 days) |
| **How often each person has used each network, address and device.** The address is kept only as a keyed digest. | `risk.historyRetentionDays` (180 days since last use) |
| **Each refused password.** It names the person, or holds a keyed digest of a name that matched nobody (never the name as typed), with the network and the error code. | `risk.failureRetentionDays` (30 days) |

This data is written to the database **only where the key-encryption key can
seal it**, and product mode requires a key-encryption key. Without one it is
held in the service process and is gone at the next restart. The page says
which applies.

The `risk.retention` job deletes whatever is past its retention every hour.
`risk.assessSignIns` turns scoring off, and `risk.recordFailures` turns off
the failure history.

**The lawful basis for this processing, the notice you give the people who
sign in, and the retention your policy requires are yours to decide and
document.** The settings above are how you put those decisions into effect.

## Development and product mode

| | Development | Product |
|---|---|---|
| Scoring and recording | on | on |
| Where the history is kept | in the process, unless a key-encryption key exists | in the database (a key-encryption key is required) |
| The issuance policy decides on the risk | yes, and the decision is recorded | yes |
| A refusal or step-up on risk is enforced | no, unless `risk.enforceInDevelopment` is on | yes |

## Configuration

Every setting below can be changed while the service runs, on Monitoring →
Risk or with `POST /admin-api/config/set`. The live list, with current
values, is on that page and at `GET /admin-api/config`. This table is a copy,
kept in step with `common/config.js`.

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `risk.assessSignIns` | `STS_RISK_ASSESS_SIGN_INS` | `true` | Score and record every sign-in, and give the issuance policy its risk. |
| `risk.enforceInDevelopment` | `STS_RISK_ENFORCE_IN_DEVELOPMENT` | `false` | Enforce the policy's risk decisions in development mode too. |
| `risk.fingerprinting` | `STS_RISK_FINGERPRINTING` | `false` | Fingerprint the browser at the sign-in screen. Complete the privacy impact assessment first. |
| `risk.breachCheck` | `STS_RISK_BREACH_CHECK` | `on` | Refuse a password known from a data breach (product mode). |
| `risk.breachCheckAtSignIn` | `STS_RISK_BREACH_CHECK_AT_SIGN_IN` | `true` | Also ask for a breached password to be changed at sign-in. |
| `risk.breachApiUrl` | `STS_RISK_BREACH_API_URL` | `https://api.pwnedpasswords.com/range/` | Where the five-character prefix is sent. |
| `risk.breachCacheMinutes` | `STS_RISK_BREACH_CACHE_MINUTES` | `60` | How long one prefix's answer is reused. |
| `risk.breachCacheSize` | `STS_RISK_BREACH_CACHE_SIZE` | `5000` | How many answers each process keeps. |
| `risk.breachTimeoutMs` | `STS_RISK_BREACH_TIMEOUT_MS` | `3000` | How long a password being set waits for the API. |
| `risk.mdsTrustAnchors` | `STS_RISK_MDS_TRUST_ANCHORS` | *(empty)* | The certificates a FIDO MDS3 BLOB's chain must end at; empty uses GlobalSign Root CA - R3 from the Node.js root store. |
| `risk.mdsStaleGraceDays` | `STS_RISK_MDS_STALE_GRACE_DAYS` | `7` | How long past its `nextUpdate` the active BLOB still answers. |
| `risk.mdsUrl` | `STS_RISK_MDS_URL` | *(empty)* | Where `risk.mds-refresh` downloads the BLOB from; empty dials nobody. |
| `risk.mdsRefreshS` | `STS_RISK_MDS_REFRESH_S` | `86400` | How often it does, hourly once the BLOB is overdue. |
| `risk.mdsMaxBytes` | `STS_RISK_MDS_MAX_BYTES` | `33554432` | The most it reads of a BLOB. |
| `risk.rescoreEveryS` | `STS_RISK_RESCORE_EVERY_S` | `300` | How often the `risk.rescore` job re-checks every live session. |
| `xacml.riskResponsePolicy` | `STS_XACML_RISK_RESPONSE_POLICY` | `risk-response` | The policy asked what happens when a person's risk changes. |
| `risk.standingValidMinutes` | `STS_RISK_STANDING_VALID_MINUTES` | `720` | How long a person's last assessed risk stands in for an issuance with no session. |
| `risk.standingCacheSize` | `STS_RISK_STANDING_CACHE_SIZE` | `20000` | How many people's standing each process holds. |
| `risk.mediumScorePercent` | `STS_RISK_MEDIUM_SCORE_PERCENT` | `100` | The score, in hundredths, from which a sign-in is MEDIUM. |
| `risk.highScorePercent` | `STS_RISK_HIGH_SCORE_PERCENT` | `1000` | The score, in hundredths, from which a sign-in is HIGH. |
| `risk.signalFactors` | `STS_RISK_SIGNAL_FACTORS` | *(empty)* | Factors over the built-in ones, as `signal=factor`, comma-separated. |
| `risk.calibrationMediumPercent` | `STS_RISK_CALIBRATION_MEDIUM_PERCENT` | `5` | The share of sign-ins calibration aims to have at MEDIUM or worse. |
| `risk.calibrationHighPercent` | `STS_RISK_CALIBRATION_HIGH_PERCENT` | `1` | The share of sign-ins calibration aims to have at HIGH. |
| `risk.recordFailures` | `STS_RISK_RECORD_FAILURES` | `true` | Record every refused password. |
| `risk.failureRetentionDays` | `STS_RISK_FAILURE_RETENTION_DAYS` | `30` | How long a refused password is kept. |
| `risk.assessmentRetentionDays` | `STS_RISK_ASSESSMENT_RETENTION_DAYS` | `90` | How long an assessment is kept. |
| `risk.historyRetentionDays` | `STS_RISK_HISTORY_RETENTION_DAYS` | `180` | How long a value nobody has signed in with since is remembered. |
| `risk.datasetsDirectory` | `STS_RISK_DATASETS_DIRECTORY` | *(empty)* | The directory the dataset job imports from; empty turns the job off. |
| `risk.datasetsDirectoryScanS` | `STS_RISK_DATASETS_DIRECTORY_SCAN_S` | `300` | How often that directory is read. |
| `risk.datasetShrinkLimitPercent` | `STS_RISK_DATASET_SHRINK_LIMIT_PERCENT` | `50` | How much smaller than the active version a new one may be before it is refused. |
| `risk.supersededRetentionDays` | `STS_RISK_SUPERSEDED_RETENTION_DAYS` | `30` | How long a superseded version's rows are kept for rollback. |
| `risk.geoStaleAfterDays` | `STS_RISK_GEO_STALE_AFTER_DAYS` | `45` | Age after which geolocation and ASN data counts for nothing. |
| `risk.ipListStaleAfterHours` | `STS_RISK_IP_LIST_STALE_AFTER_HOURS` | `24` | Age after which a Tor or reputation list counts for nothing. |

## Design decisions

- **Every score can be explained after the fact.** An assessment keeps every
  value that went into it, the dataset versions that answered, and the
  signals. It can be explained after the datasets have rotated.
- **Nothing is fetched while anybody signs in.** Datasets are imported ahead
  of time and read locally, so a provider outage delays a refresh and nothing
  else.
- **One published model, calibrated in the open.** The model is ported
  rather than invented, and it is held to the reference implementation's own
  scores on a synthetic history. The evaluator factors are visible on every
  assessment.
- **Addresses are never kept in the clear.** An address is kept sealed, as a
  network prefix, or as a keyed digest.
- **Authorization is policy.** What a score leads to is written in XACML, in
  the one policy every issuance passes through, so it can be changed without
  a release and read in one place.

## Receivers act on it

This service's own console and portal receive the CAEP `risk-level-change`
events it sends. At `HIGH`, each one ends its own sessions for that person
(product mode), as the `signal-response` policy permits. See
[Signals received](signals-received.md#what-the-console-and-the-portal-do-with-a-signal).

## In the running service

- **Monitoring → Risk** (`/admin/risk`) shows everything on this page: the
  assessments, people by current standing, a lookup of any address, every
  dataset and its versions, the providers, their terms and who accepted
  them, and the refused passwords. It also shows the data credits and these
  settings. `?subject=` narrows the assessments to one person.
- **A realm's own administrators** see both pages for their realm, at
  `/realm/<id>/admin/risk` and `/realm/<id>/admin/risk-scoring`. They see:
  - the realm's assessments;
  - its people's standings;
  - its refused passwords;
  - its operator allow and deny lists, which they can also manage.

  The following belong to the whole service, so they are left off the page
  for them and refused if they try:
  - the shared datasets;
  - the providers' terms and who accepted them;
  - the `risk.` settings;
  - the per-process counts.
- **Monitoring → Risk Scoring** (`/admin/risk-scoring`) measures the
  scoring itself over the last hour, day, week or 30 days:
  - assessments over time, stacked by level;
  - the counts by level, by score band, by decision, by door, by phase and
    by country;
  - how many people stand at each level now;
  - every signal beside its factor and how often it fired, which is where
    calibration starts;
  - what people said about their own sign-ins.

  The counts above come from the store. On postgres they cover every node.
  The page also shows figures for the process that drew it, since that
  process started:
  - assessments made and failed, and the time to assess (mean, p50, p95,
    p99 and max);
  - the reactions taken, observed only, or failed;
  - the `risk.rescore` runs;
  - the breached-password screening counts.

  `GET /admin-api/risk/metrics?window=24h` returns the same data as JSON.
- **Each person's page under Directory → Users** opens with their current
  risk, drawn large in the level's colour: LOW green, MEDIUM amber, HIGH
  red, grey for someone never assessed. It shows the score, the level it
  came from, when it changed, the signals that moved it, and a link to that
  person's assessments. `GET /admin-api/users?user=` carries the same
  standing as `risk` (`null` when never assessed).
- **`GET /admin-api/risk`** returns the same view as JSON. Its actions are
  `POST /admin-api/risk/import`, `activate`, `rollback`, `delete` and
  `accept-terms`, described in the
  [OpenAPI document](management-api.md).
- **Error codes** `STS-RISK-0001` to `STS-RISK-0026` are listed on
  [Error codes](error-codes.md).

## Related

- [XACML](xacml.md): the issuance policy, and the console where it is
  edited.
- [CAEP events](caep-events.md): `risk-level-change`, which risk scoring will
  send.
- [Sessions](sessions.md) and [Authentication](authentication.md): what is
  scored.
- [Persistence](persistence.md) and
  [Encryption at rest](encryption-at-rest.md): where the history is kept, and
  what seals it.
- [TLS and mutual TLS](tls.md): the connection a JA4 fingerprint is read from.
