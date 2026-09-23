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
  credential is marked compromised, when recovery is started, and when the
  address on their entry changes. The last notice goes to the old address.

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
| `mail.smtpCaFile` | A PEM trust anchor for a relay whose certificate does not chain to the system store. |
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
any Mail setting changes. `/admin/secrets` shows where each secret is and
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
`<selector>._domainkey.<domain>`. To rotate the key, use a new selector.
**DKIM has no post-quantum algorithm registered yet.**

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
   message and when, and never what it said.

### Ceilings and duplicates

`mail.ratePerRecipient` and `mail.ratePerCategory` cap how many messages one
person is sent in `mail.rateWindowS`, counted across the cluster. A storm of
events or a hostile "forgot password" button therefore cannot turn this service
into a mail cannon (`STS-MAIL-0010`). A notice about one act is sent once in
`mail.dedupWindowS`, however many doors reported it.

## Messages

Each message has a built-in English wording. A realm may reword any of them,
in any language, on `/admin/mail`. A person's `preferredLanguage`, an
Accept-Language value such as `de-CH, de;q=0.8`, chooses the language, then
`mail.defaultLanguage`, then English. **A realm's wording is checked when it is
saved** (`STS-MAIL-0016`):

- **A link is a placeholder** such as `{{link}}`. Its value is this service's
  own address, and a template may not write `http:`, `https:` or `mailto:`.
  **The link is built on `global.publicBaseUrl`**, never on the address a
  request arrived at. In product mode a message with a link is refused until
  that setting is set (`STS-MAIL-0015`).
- **The HTML part loads nothing and runs nothing**: no image, stylesheet,
  frame, form, script, event handler, `src`, `style`, CSS `url()`, or `data:`
  or `javascript:` URI. A message that loads nothing when it is opened tells
  nobody when it was read.
- Every value is escaped, and a value can never add a line to a header.

## Categories, and what a person may decline

| Category | Messages | May be declined |
|---|---|---|
| Security notices | disabled, sessions ended, password changed, compromised, recovery started, address changed | **no** |
| Links somebody asked for | reset, activation, verification, test | **no** |
| Notifications | none yet (#62, #64) | yes, on `/portal/email` |

## The uses

**Forgot your password?** This is offered where `mail.selfServiceReset` is on,
a transport is available, and the mode checks passwords (product). A person
names their account, by username or by the address on it. **The page says the
same sentence whatever happened**, and says it before any work is done, so
neither the wording nor the timing reveals whether an account exists. Behind
the answer:

- The link goes only to a **verified** address
  (`mail.resetRequiresVerifiedAddress`, on by default).
- The account's current password keeps working until the link is used.
- RISC `recovery-activated` is sent with the person as the initiating entity.

> **Warning.** `mail.resetRequiresVerifiedAddress=false` is a weaker setting.
> It mails reset links to addresses that an import, a provisioning feed or an
> administrator wrote, and that nobody ever proved. Turn it off only for a
> directory whose addresses you trust as written.

**Address verification.** A person sends themselves a link from
`/portal/email`, or an administrator sends one (`POST /admin-api/mail/verify`).
Opening the link spends nothing: it draws a button, so a mail scanner that
follows every link verifies nothing. The button records **the address** as
verified. An entry whose `mail` changes is therefore unverified with nothing to
clear. In product mode, UserInfo's `email_verified` is `true` exactly when
the `email` it sends is that verified address, and `false` otherwise.

**An administrator's links.** On `/admin/users` the reset-link form, and the
activation choice on `/admin/users/new`, have a **mail the link** box. It is
ticked whenever the realm has a transport. The API equivalent is `deliver:
"mail"`. A mailed link is not shown to the administrator.

**Security notices** are sent to the person (`mail.securityNotices`). When
*the service* acted, for example when risk scoring disabled an account or
marked a credential compromised, every member of the realm's Admin Write roster
who has an address is told as well (`mail.notifyAdministrators`).

## Where to look

| | |
|---|---|
| Server configuration → Mail (`/admin/mail`) | The transport, whether it could be built, where links point, a test message, a verification link, each message's wording, and the settings |
| Monitoring → Mail outbox (`/admin/mail/outbox`) | Every message, its state and attempts, the dead letters and their Retry. In development, the captured bodies. |
| `/portal/email` | A person's own address, its verification, what they decline, and what was sent to them |
| `GET /admin-api/mail`, `/admin-api/mail/outbox` | The same, over JSON ([Management API](management-api.md)) |
| [Error codes](error-codes.md) | `STS-MAIL-0001` to `STS-MAIL-0034` |
