---
title: Mail
---

# Mail

This service sends mail for four things:

- **A forgotten password.** A person asks for a reset link at
  `/portal/forgot-password`, which the sign-in screen links to.
- **Address verification.** A single-use link proves that a person receives
  mail at the address on their entry.
- **An administrator's links.** A reset link or an activation link can be
  mailed to the person instead of being shown to the administrator.
- **Security notices.** A person is told when their account is disabled, when
  an administrator ends their sessions, when their password changes, when a
  credential is marked compromised, when recovery is started, when a
  credential of theirs is added or removed, and when the address on their
  entry changes. The last notice goes to the old address.

It **receives** no mail. Every message goes to **the address on a directory
entry**. No request, form or API parameter takes an address.

## Choosing a transport

`mail.transport` names one of the transports below. It is set for the whole
service, and a [trust realm](trust-realms.md) may override it with its own.
Every `mail.*` setting is an ordinary realm-overridable setting. Server
configuration → **Mail** (`/admin/mail`) shows and edits them.

| `mail.transport` | What it is | Needs |
|---|---|---|
| `default` | Development: the **capture** transport. Product: **off**. | nothing |
| `capture` | Keeps each message, body included, and shows it on Monitoring → **Mail outbox**. Sends nothing. **Refused in product mode.** | development mode |
| `smtp` | A relay you run, the Google Workspace SMTP relay, or the Amazon SES SMTP interface | `mail.smtpHost` (or a preset) |
| `ses` | Amazon SES v2 | the `@aws-sdk/client-sesv2` package |
| `acs` | Azure Communication Services Email | the `@azure/communication-email` package (and `@azure/identity` for managed identity) |
| `gmail` | The Gmail API, sending as a Google Workspace mailbox | the `@googleapis/gmail` package |
| `off` | Nothing is sent. A message is refused as it is queued (`STS-MAIL-0001`). | nothing |

The three cloud SDKs are **optional peers**, not dependencies. Build the image
with the ones you use:

```bash
docker build --build-arg STS_CLOUD_SDKS="@aws-sdk/client-sesv2" -t iya-sts .
```

**In product mode a configured transport that cannot be built stops the
service** (`STS-MAIL-0002`). The causes are a missing SDK, an unreadable secret
and a half-configured option. The check runs at startup, so a broken transport
is found then rather than by a person who never receives their reset link.

### Development captures

In development mode, `default` is the capture transport. Every message is kept
whole, and Monitoring → Mail outbox shows it: open a row, and the text part
and the HTML source are there, links included. This is how you follow a reset
link on a machine with no mail server.

If you configure a real transport, development sends through it. That is how
the test suite delivers to Mailpit.

### A self-hosted relay (`smtp`)

| Setting | |
|---|---|
| `mail.smtpHost`, `mail.smtpPort` | The relay. 587 is submission with STARTTLS, and 465 is implicit TLS (RFC 8314). |
| `mail.smtpTls` | `starttls` requires the upgrade, and a relay that does not offer it is refused (`STS-MAIL-0014`). `implicit` uses TLS from the first byte. **There is no cleartext option and no option to skip verification, in either mode.** |
| `mail.smtpCaFile` | A PEM trust anchor for a relay whose certificate does not chain to the system store, beside that store rather than instead of it. |
| `mail.smtpServerName` | The name the relay's certificate must carry, when it is not `mail.smtpHost`. |
| `mail.smtpAuth` | `none`, `plain`, `login` or `xoauth2`, sent only after TLS is up. |
| `mail.smtpUser` and the SMTP password secret | See [Secrets](#secrets). For `xoauth2`, the secret is either an access token or JSON with `clientId`, `clientSecret`, `refreshToken` and `accessUrl`. |
| `mail.smtpClientCertFile`, `mail.smtpClientKeyFile` | A client certificate, for a relay that authenticates by certificate. |

The relay's certificate is verified against its name, TLS 1.2 at the least.

### Google Cloud

Google Cloud has no transactional mail API of its own. There are two
Google-native routes, and this service supports both:

- **The Google Workspace SMTP relay.** Set `mail.transport=smtp` and
  `mail.smtpPreset=google-workspace-relay`, which gives
  `smtp-relay.gmail.com:587` with STARTTLS. In the Workspace admin console
  (Apps → Gmail → Routing → SMTP relay service), allow this service's sending
  IP address, or require SMTP AUTH and set `mail.smtpAuth` with an app
  password or XOAUTH2.
- **The Gmail API** (`mail.transport=gmail`). Create a service account with
  domain-wide delegation of the `https://www.googleapis.com/auth/gmail.send`
  scope, and store its JSON key as the Gmail key secret. `mail.gmailSender` is
  the Workspace mailbox it impersonates, and `mail.from` must be that mailbox
  or one of its send-as aliases.

### Amazon SES

`mail.transport=ses` sends through SES v2's `SendEmail` with the raw message.
`mail.sesRegion` names the region, and `mail.sesConfigurationSet` optionally
names a configuration set for event destinations.

**The credentials come from the default provider chain**: the task role on ECS
Fargate ([AWS cluster](aws-cluster.md)), and an instance profile or environment
variables elsewhere. Grant `ses:SendEmail` (and `ses:SendRawEmail`) on the
identity of `mail.from`. The SES SMTP interface is also reachable as
`mail.transport=smtp` with `mail.smtpPreset=aws-ses-smtp`, using SES SMTP
credentials as the username and password.

### Azure Communication Services

`mail.transport=acs`. **Managed identity is the default** (`mail.acsAuth`),
and it needs no secret: set `mail.acsEndpoint` to
`https://<resource>.communication.azure.com` and grant the identity a role
on the Communication Services resource that allows it to send mail.
`connection-string` instead reads the resource's connection string from the
secret store.

Sending is a long-running operation, and each attempt waits for its outcome
within `mail.timeoutMs`. Engagement tracking is switched off for every
message.

## Secrets

The SMTP password, the DKIM private key, the Azure connection string and the
Gmail service account key are never a setting's value. Each one is read
through the same mechanism as the database password (see
[Persistence](persistence.md)): a provider (`file`, `aws`, `gcp`, `azure` or
`vault`), a location, and a field.

| Secret | Settings | Default field |
|---|---|---|
| SMTP password | `mail.smtpPassword{Provider,Ref,Field}` | `smtpPassword` |
| DKIM private key | `mail.dkimKey{Provider,Ref,Field}` | `dkimKey` |
| Azure connection string | `mail.acsConnectionString{Provider,Ref,Field}` | `acsConnectionString` |
| Gmail service account key | `mail.gmailKey{Provider,Ref,Field}` | `gmailServiceAccount` |

**An empty location means the key-encryption key's.** So one JSON secret can
hold the key-encryption key, the database password and these four side by
side. A secret is read when the transport is built, which happens again after
any Mail setting changes, and at least once an hour, so a secret rotated in
your secret store is used within the hour without a restart. Rotating these
secrets is your job, in your secret store and at the provider. `/admin/secrets` shows where each secret is and
whether it was read, never what it is.

## The sender's domain: SPF, DKIM and DMARC

Receivers judge a message by its From domain. Before you send from
`no-reply@idp.example.com` (the default From is `no-reply@` the realm's DNS
domain; `mail.from` changes it), make the domain able to vouch for the
message.

| Transport | SPF | DKIM | DMARC |
|---|---|---|---|
| Your own relay | Your relay's addresses in the domain's SPF record | Signed by the relay, or by this service: see below | `_dmarc` TXT, `p=quarantine` or `p=reject` once aligned |
| Google Workspace relay | `include:_spf.google.com` | Workspace's DKIM for the domain (Apps → Gmail → Authenticate email) | as above |
| Gmail API | as above | as above | as above |
| Amazon SES | a custom MAIL FROM domain with its `include:amazonses.com` record | Easy DKIM (three CNAMEs) or BYODKIM | as above |
| Azure Communication Services | the SPF record Azure shows when you verify the domain | the two `selector1`/`selector2` CNAMEs Azure shows | as above |

**DKIM from this service**, for your own relay only: set `mail.dkimDomain`,
`mail.dkimSelector`, `mail.dkimAlgorithm` and the DKIM key secret. This
service then signs every message it hands the relay (RFC 6376,
relaxed/relaxed). The signing is done by `common/crypto.js`, not by the mail
library. `rsa-sha256` needs a key of at least 2048 bits (RFC 8301), and
`ed25519-sha256` (RFC 8463) is supported. Publish the public key at
`<selector>._domainkey.<domain>`.
**DKIM has no post-quantum algorithm registered yet.**

### Rotating the DKIM key

A DKIM key is replaced under a **new selector**, and the old selector's record
stays in DNS for an overlap, so mail signed just before the switch still
verifies when it is checked later. This service decides which key signs. DNS
is yours.

1. Put the new private key in the DKIM key's secret, under
   `mail.dkimNextKeyField` (`dkimNextKey` by default), and set
   `mail.dkimNextSelector` to its selector.
2. Publish the record the log gives you (`mail: publish the DKIM record for
   the next selector as the TXT record …`) at
   `<next selector>._domainkey.<domain>`. It is `v=DKIM1; k=rsa; p=…`, or
   `k=ed25519` for an Ed25519 key.
3. Set `mail.dkimSwitchAt` to an ISO 8601 time. From then on, messages are
   signed with the next selector, **but only once DNS answers the next
   selector's name with its key**. Until it does, the current selector keeps
   signing and `STS-MAIL-0245` is logged.
4. Keep the old selector's record published for at least a week after the
   switch.
5. Make the next selector the current one: move the key to the
   `mail.dkimKeyField` member, set `mail.dkimSelector` to the new selector,
   and clear `mail.dkimNextSelector`, `mail.dkimNextKeyField` and
   `mail.dkimSwitchAt`. Then withdraw the old record.

## What happens to a message

1. **It is queued**, in the realm's outbox. The address is read from the
   entry, and the message is rendered in the person's `preferredLanguage` (see
   [Messages](#messages)). The outbox is persisted and shared exactly where
   this service persists what it mints: in product mode on PostgreSQL, sealed
   at rest.
2. **It is sent at once** by the process that queued it. The `mail.deliver`
   scheduler job, on the cluster's leader every `mail.deliverS`, is the safety
   net: a retry whose backoff has passed, or a node that died mid-send. Each
   attempt is claimed with a lease, so **a message is sent once for the
   cluster**.
3. **A failure worth repeating is retried with backoff**: a timeout, a lost
   connection, an SMTP 4xx, or throttling (`mail.attempts`, `mail.backoffS`,
   doubling). A permanent refusal (an SMTP 5xx, a rejected sender, a failed
   login, a certificate that does not verify) is a **dead letter** at once.
4. **A dead letter** stays on Monitoring → Mail outbox until an administrator
   retries it (`POST /admin-api/mail/outbox/retry`), or until
   `mail.retentionS` removes it. A retry goes to the address the entry holds
   *now*.
5. **A sent message keeps no body.** The outbox and the audit log say who, which
   message and when, and never what it said. The body holds reset and
   verification links and codes, so it is dropped the moment the message is
   sent. A dead letter keeps its body, because a retry sends that body; it
   loses it when the retry succeeds, or with the row when `mail.retentionS`
   removes it.

### Ceilings and duplicates

`mail.ratePerRecipient` and `mail.ratePerCategory` cap how many messages one
person is sent in `mail.rateWindowS`, counted across the cluster. A storm of
events or a hostile "forgot password" button therefore cannot turn this service
into a mail cannon (`STS-MAIL-0010`). A notice about one act is sent once in
`mail.dedupWindowS`, however many doors reported it.

## Messages

Each message has a built-in wording in every language this service has a
catalog for (#539): English, French (and Canadian French), Spanish (and
Spanish as written in Spain), Simplified and Traditional Chinese (and Hong
Kong), Filipino, Swedish, German, Arabic and Hindi. Everything but English
was machine-written and has not been reviewed by a native speaker yet.

- **Which language:** the recipient's `preferredLanguage` (an Accept-Language
  value such as `de-CH, de;q=0.8`), then the realm's
  [locale policy](languages.md#the-locale-policy) default, then English. A
  regional tag reads its region's wording where it differs and its
  language's otherwise. `zh-TW` and `zh-HK` are sent Traditional Chinese and
  never Simplified, `de-CH` is sent German, and a language with no catalog
  (`ja`) passes to the next one in the list.
- **A realm's own wording wins.** A realm may reword any message, in any
  language, on `/admin/mail`, and its wording in a language always wins
  over the built-in wording in it.
- **What fills a message is translated too.** Who did something, what kind
  of credential it was and when it happened are in the recipient's
  language. Times are in UTC and say so. A reason somebody wrote, or one a
  Shared Signals event carries, is sent as it was written.
- `mail.defaultLanguage` was the default until #539. A start that still
  names it is refused and told so.

**A realm's wording is checked when it is
saved** (`STS-MAIL-0016`):

- **A link is a placeholder** such as `{{link}}`. Its value is this service's
  own address, and a template may not write `http:`, `https:` or `mailto:`.
  **The link is built on `global.publicBaseUrl`**, never on the address a
  request arrived at. In product mode a message with a link is refused until
  that setting is set (`STS-MAIL-0015`).
- **The HTML part is held to an allow-list**: text formatting, tables and links, checked by a sanitization library. A template the library would change is refused.
- **The HTML part loads nothing and runs nothing**: no image, stylesheet,
  frame, form, script, event handler, `src`, `style`, CSS `url()`, or `data:`
  or `javascript:` URI. A message that loads nothing when it is opened tells
  nobody when it was read.
- Every value is escaped, and a value can never add a line to a header.

**Every message is wrapped in the realm's layout** (#64): the `layout`
message on `/admin/mail`, reworded like any other. It carries the message's own
body as `{{content}}` — exactly once in the text part and once in the HTML part
— and its subject as `{{subject}}`, and says why the person received it
(`{{reason}}`). A layout without `{{content}}`, or with it twice, is refused
when it is saved. It is never sent on its own.

## Categories, and what a person may decline

| Category | Messages | May be declined |
|---|---|---|
| Security notices | disabled, sessions ended, password changed, a credential added or removed, compromised, recovery started, address changed, an unusual sign-in, refused sign-in attempts, a sign-in code or link (#64), a refused reset | **no** |
| Links somebody asked for | reset, activation, verification, test | **no** |
| Notifications | a finished report, an access request waiting on the portal, a started post-login activity's reminder | yes, on `/portal/email` |

## The uses

**Forgot your password?** This is offered where `mail.selfServiceReset` is on,
a transport is available, and the mode checks passwords (product). **By
default a person gives three things** (#64, `mail.resetRequiresBackupCode`):
their username, the verified address on the account, and one of their recovery
codes. A link is mailed only when all three are right, and the recovery code is
used up then. A wrong code with the right username and address tells the
address owner that somebody tried. **The page says the same sentence whatever
happened**, and says it before any work is done, so neither the wording nor the
timing reveals whether an account exists. Behind the answer:

- The link goes only to a **verified** address
  (`mail.resetRequiresVerifiedAddress`, on by default).
- The account's current password keeps working until the link is used.
- RISC `recovery-activated` is sent with the person as the initiating entity.

> **Warning.** `mail.resetRequiresBackupCode=false` is a weaker setting. The
> form goes back to one field — a username or the address on the account — and
> a reset is then exactly as strong as the mailbox it goes to. A person who
> holds no recovery codes cannot reset their own password while it is on; an
> administrator can.

> **Warning.** `mail.resetRequiresVerifiedAddress=false` is a weaker setting.
> It mails reset links to addresses that an import, a provisioning feed or an
> administrator wrote, and that nobody ever proved. Turn it off only for a
> directory whose addresses you trust as written.

**Which addresses are verified** (#64). An address is verified as written
when an administrator sets it (the console, `POST /admin-api/users/create` or
`set-mail`), when SCIM provisions it, when an administrator writes it over LDAP,
or when a federation partner sends it — unless the partner says
`email_verified: false`. An address a PERSON provides is verified by a link:
changing it themselves over LDAP sends them one, and on `/portal/email` a new
address stays **pending** — resets and codes still go to the old one — until
the link sent to the new one is followed; the old address is then told it
changed. An address this service invented for a development persona is never
verified.

**Address verification.** A person sends themselves a link from
`/portal/email`, or an administrator sends one (`POST /admin-api/mail/verify`).
Opening the link spends nothing: it draws a button, so a mail scanner that
follows every link verifies nothing. The button records **the address** as
verified. An entry whose `mail` changes is therefore unverified with nothing to
clear. A link is bound to the address the account had when it was sent, so it
outlives no change of address by anybody. In product mode, UserInfo's
`email_verified` is `true` exactly when the `email` it sends is that verified
address, and `false` otherwise.

**Emailed sign-in codes and links** (#64) are the authentication policy's, on
[the sign-in service's page](authentication.md#emailed-codes-and-links), and
off by default. Where a realm cannot send mail they are never offered, and
Directory → Policies draws them disabled with the reason.

**An administrator's links.** On `/admin/users` the reset-link form, and the
activation choice on `/admin/users/new`, have a **mail the link** box. It is
ticked whenever the realm has a transport. The API equivalent is `deliver:
"mail"`. A mailed link is not shown to the administrator.

**A started post-login activity's reminder** (#1111) asks a person to sign
in, where the [post-login activity](post-login-activities.md#starting-an-activity) then asks
them to do it. Each activity has its own message, which a realm may reword
like any other: `post-login-reminder` for the post-quantum passkey (the
message it has always been), `post-login-reminder-mail-encryption` for a
post-quantum mail-encryption key and `post-login-reminder-piv-reissue` for a
new PIV certificate. It goes to the address on their entry,
and its one link opens the user portal on this service's own address, which
sends them to sign in. The
link signs nobody in and carries nothing about the person. It is a
notification, so a person may decline it; the activity is still asked at their
next sign-in.

**Security notices** are sent to the person (`mail.securityNotices`). When
*the service* acted, for example when risk scoring disabled an account or
marked a credential compromised, every member of the realm's Admin Write roster
who has an address is told as well (`mail.notifyAdministrators`).

**A credential added or removed** (#2163) is a security notice too. A person
is told when any of these of theirs is added or removed:

- a passkey or security key
- an authenticator app
- an app password
- a one-time code token or a YubiKey OTP
- a set of recovery codes. Generating or removing a set is told, and
  spending one code is not.
- a certificate, including a smart card's
- a certificate sign-in binding (`stsCertificateBinding`, `stsPivCardUuid`)
- an S/MIME certificate or an OpenPGP key

The message names the kind and its label, never anything secret. It says
when the change was made and whether the person did it (on the portal or at
sign-in) or an administrator did. It also says what to do if it was not them.
It is sent whichever way the change was made: the portal, the sign-in screen,
`/admin-api` and the console, SCIM, or an LDAP write.

**One act is one message.** When an administrator removes every second factor
of a person, or a hardware token is reported lost, the person is sent one
message that lists every change. The same change reported twice in
`mail.dedupWindowS` is sent once. A change the service makes on its own is not
mailed. Examples are a certificate superseded by its renewal, or a passkey a
policy no longer accepts. A password change keeps its own message.

`mail.credentialChangeNotices` (on by default, per realm) turns these off.
Nothing is sent while `mail.securityNotices` is off or no transport is
configured.

**An unusual sign-in, and a run of refused passwords** (#2162), are security
notices too, `mail.signInAlerts`. A sign-in that succeeds looking unusual is
told with when, roughly where, with what and how, and a link to the person's
recent sign-ins. Unusual means a new device, a new country, an anonymising
network, refused passwords just before, or a risk level at or above
`mail.signInAlertLevel`. As many refused passwords as the sign-in limit allows
are told whether or not anybody signs in. Each kind is told at most once in
`mail.signInAlertWindowS`. See
[Risk scoring](risk-scoring.md#the-person-is-told-of-an-unusual-sign-in).

**A credential that expires soon** (#2247) is a security notice too,
`mail.expiryReminders` (on by default, per realm). A person is reminded
before any of these of theirs expires:

| What | How the message says to renew it |
|---|---|
| a certificate this realm issued over ACME, EST or SCEP | on the portal's **Certificates** page |
| a PIV smart card or security key certificate | on the portal's **Tokens and keys** page, on PIV |
| an S/MIME certificate mail to them is encrypted to | on the portal's **Tokens and keys** page, on OpenPGP and S/MIME |
| a TLS client certificate this realm issued them, from the portal or an administrator | on the portal's **Signing keys** page |
| a certificate stored on their entry for certificate sign-in | ask their administrator |

They are reminded at each of `mail.expiryReminderDays` before it expires
(30, 7 and 1 days by default), once at each. A certificate first seen inside
one of them, because it was issued for less than 30 days, is told at the
nearest and never at a day it has already passed. Every certificate due is in
one message, each with the day it expires, and the message links to the
portal. `mail.expiryReminderKinds` narrows which kinds are named (`certificate`,
`piv`, `smime`, `tls-client`, `signin-certificate`). The
`mail.credential-expiry` scheduler job sends them hourly in every realm; it is
off while the setting, security notices or a transport is.

The reminders read an index of when each certificate expires, kept in step
with every write of a person's entry, so a run reads only the certificates
due and never the directory. A certificate that was on an entry before 1.2.0
is added to the index by the job, a slice of the realm's people per run, so
in a large realm its first reminder may come a few days after the upgrade.

What is not reminded: an SSH user certificate, which lasts an hour at most
and is asked for again at each use; and passkeys, authenticator apps, one-time
code tokens, recovery codes, app passwords and passwords, which do not expire
here. The PIV re-issue post-login activity is unchanged: it renews a PIV
certificate at a sign-in, and is still off by default. See
[Post-login activities](post-login-activities.md).

## Encrypted mail

A person can choose to have their mail encrypted with PGP/MIME to their
OpenPGP key or with S/MIME to their certificate, and a realm can require it
for chosen messages (`mail.encryptionRequired`). An encrypted message goes out
under a neutral subject. S/MIME mail is an AuthEnvelopedData under
AES-256-GCM (`smime-type=authEnveloped-data`), which a reader can tell has
not been changed; `mail.smimeContentEncryption` `aes256-cbc` returns to the
AES-256-CBC EnvelopedData of earlier releases for a mail client that cannot
read it, and `/admin/mode` reports ASVS 5.0.0 11.3.3 as not met while it is
set in product mode. See [OpenPGP keys and encrypted
mail](openpgp.md#encrypted-mail).

## Where to look

| | |
|---|---|
| Server configuration → Mail (`/admin/mail`) | The transport, whether it could be built, where links point, a test message, a verification link, each message's wording, and the settings |
| Monitoring → Mail outbox (`/admin/mail/outbox`) | Every message, its state and attempts, the dead letters and their Retry. In development, the captured bodies. |
| `/portal/email` | A person's own address, its verification, what they decline, and what was sent to them, twenty a page (`sentPage`) |
| `GET /admin-api/mail`, `/admin-api/mail/outbox` | The same, over JSON ([Management API](management-api.md)) |
| [Error codes](error-codes.md) | `STS-MAIL-0001` to `STS-MAIL-0034` |
