---
title: Release notes
---

# Release notes

## 1.2.0

### Behaviour change: more administrator acts need a recent sign-in

Until now, only changing a person's credentials through the console or
`/admin-api` asked an administrator to have signed in within
`account.recentAuthMinutes` (15 minutes in product mode). The same is now
asked for granting or removing a role, an administrator role included;
creating, changing or removing a trust realm; every PKI act, including a
CA, an Intermediate, a certificate, a revocation and the signer truststore;
the signing keys, the data keys and the key-encryption key; the TLS client
truststore; the secret push destinations; the krbtgt key and a person's
keytab; every setting, the mode among them; and every change only a
Security Administrator may make (ASVS 5.0.0 7.5.3). The console asks for
the sign-in again and carries on. The API answers 401 with RFC 9470's
`insufficient_user_authentication` and `max_age` (`STS-API-0145`).

**Upgrading.** Nothing to run. A program calling `/admin-api` with its own
client credentials is not asked. A script that uses a person's token for
these acts must sign that person in again when it gets the 401. Development
mode does not ask, since `account.recentAuthMinutes` is 0 there.
### HSTS can be preloaded

A new setting, `security.hstsPreload` (off by default), adds `preload` to
the `Strict-Transport-Security` header product mode sends, so the domain
can be submitted to the browsers' HSTS preload list (ASVS 5.0.0 3.7.4). It
is sent only while `security.hstsIncludeSubDomains` is on; with that off
the header carries no `preload`, `/admin/mode` says so and the log records
`STS-CORE-0181`. Preloading binds the whole registrable domain and takes
months to undo: see [Preloading](tls.md#preloading).

**Upgrading.** Nothing changes until the setting is turned on.
### Behaviour change: a signed-in person's own budgets on the account and report APIs

In product mode a signed-in caller now has a budget of its own, counted by
the access token's subject rather than by address (ASVS 5.0.0 2.4.2):

- **`/account-api`**: every change to the person's own account (every
  operation that takes a token and is not a `GET`: profile edits,
  credentials enrolled or removed, consents withdrawn, device changes)
  counts against `account.writesPerSubject` in `account.writeWindowS`, 300
  in ten minutes by default.
- **`/report-api`**: an ad hoc query or preview, a job queued, a saved
  definition run and a result downloaded count against
  `report.actsPerSubject` in `report.actWindowS`, 240 in ten minutes by
  default.

Past it the act is refused with HTTP 429 and `Retry-After` until the window
passes (`STS-ACCOUNT-0024`, `STS-REPORT-0062`); reads, other people and
other callers are not affected. The refusal carries `messages`, and the
portal and the reports page draw it in their own language. Until 1.2.0 these
acts were bounded only by the per-address ceiling,
`security.requestsPerAddressPerMinute`. Both budgets are off (0) in
development mode, as that ceiling is.

**Upgrading.** Nothing to run. The defaults are far above what a person
does; a program that writes to a person's account or runs reports for one
subject faster than that should spread its work out or have the setting
raised. See [Account API](account-api.md#what-an-answer-looks-like) and
[Reports](reporting.md#errors).

### Behaviour change: CSV exports neutralise spreadsheet formulas

A report exported as CSV, and the passkey report's CSV export, now put a
single quote (`'`) in front of any text value whose first character is
`=`, `+`, `-`, `@`, a tab, a carriage return or NUL, so a value someone
chose (a username, a display name) cannot run as a formula when the file
is opened in a spreadsheet (ASVS 5.0.0 1.2.10). The quote is visible in
the cell. Numbers are not touched: a negative count is still a number.
Until 1.2.0 a report's CSV quoted only per RFC 4180, and the passkey
export did not catch a leading NUL. A program that reads these files and
compared a text cell starting with one of those characters byte for byte
now sees the quote in front. See [Reporting](reporting.md#formats).
### Changed: the image's optional SDKs come from a lockfile

The Vault client every image carries, and the SDKs the `STS_CLOUD_SDKS` build
argument adds, were installed with a bare `npm install`: the newest version the
registry had that day, with install scripts on. They are now pinned in the
repository's `sdk/` directory, one npm workspace per SDK, and installed from
`sdk/package-lock.json` with `npm ci --ignore-scripts` (ASVS 5.0.0 15.2.4).
`STS_CLOUD_SDKS` takes the same package names as before. A name the lockfile
does not pin, or a `name@version` whose version it does not hold, now fails the
build instead of installing something unpinned; to move a pin, change it in
`sdk/packages/` and run `npm install --package-lock-only --ignore-scripts` in
`sdk/`.
### Changed: product mode keeps the build to administrators

In product mode the page footer no longer shows the version and its build
line, the sign-in (`/authn-api`) and portal (`/account-api`) OpenAPI documents
give `info.version` as `1`, the front page's, portal's and reports' answers
carry an empty version, and the User-Agent of the requests this service makes
to partners is `sts (<component>)` without `/<version>` (ASVS 5.0.0 13.4.6).
The console and `/admin-api` show the build as before, and development mode is
unchanged. A page's cached files are now keyed by a random key the image build
draws rather than by the build instant and commit. The new setting
`security.publishBuildInfo` (`auto`, `on`, `off`; environment
`STS_SECURITY_PUBLISH_BUILD_INFO`) puts the build back everywhere with `on`.

### Behaviour change: an uploaded sign-in logo loses its metadata

A realm's sign-in logo is shown to everybody who opens a sign-in page, so
it is now cleaned before it is kept, as profile photos already were: a
JPEG's EXIF (a GPS position, a camera, a date), XMP and comments, a PNG's
text chunks and animation frames, a WebP's EXIF and XMP chunks, and
anything after the end of the image are removed (ASVS 5.0.0 14.2.8). The
pixels are not changed. The digest, size and sides the console and `GET
/admin-api/branding` show describe the cleaned file. A file that cannot be
read to the end of its image is refused with `STS-AUTHN-0624`.

Profile photos use the same code, and two things changed for them: a JPEG
now ends at its first end-of-image marker, so a second image a phone
appends after it (a Multi-Picture Format depth or gain map, which carries
its own EXIF) is no longer kept, and an APP2 segment is kept only when it
is an ICC colour profile.

**Upgrading.** Nothing to run. A logo uploaded before 1.2.0 is served as it
was stored, metadata included, until it is uploaded again; upload it again
to clean it. See [Sign-in appearance](sign-in-appearance.md#the-logo).
### Fixed: an LDAP substring filter cannot stall the directory

An LDAP search's substring assertion (`(cn=*smith*)`) is matched in one
linear pass instead of by a regular expression, which a filter such as
`(cn=*a*a*a*...*b)` against a long value made backtrack for a very long time
(ASVS 5.0.0 1.3.12, #2137). Ordinary filters match exactly what they matched
before; a value holding a line break is now matched across it, as RFC 4517
asks. A search whose substring assertion holds more than 32 components is
refused with adminLimitExceeded (11), recorded as `STS-LDAP-0226`. See
[LDAP](ldap.md#how-a-filter-value-is-matched).
### Fixed: federated sign-ins no longer pile up cookies

In product mode each federated sign-in sets a cookie that binds it to the
browser that started it (`sts_fed_flow_…`). Until 1.2.0 none was ever
cleared, so a person who started many sign-ins within ten minutes could fill
their Cookie header until the service answered 431 (ASVS 5.0.0 4.2.5,
#2139). The cookie is now cleared by the partner's answer, whether it signs
the person in or is refused, and one browser holds at most eight: a ninth
start clears the oldest. Nothing to configure; a cookie set by an earlier
build still binds its sign-in.
### New: named truststores

Every place the service checks a signature, a certificate chain or the
certificate of a server it connects to is now a **use case** that trusts a
list of named **truststores**: node's default store (`system`), this
service's Root, the shipped vendor roots, the signer and client-certificate
truststores, what each older anchor or CA setting names, SPIFFE trust domain
bundles, and truststores you create. Protocols → PKI trust gains
**Truststores**, **Use cases** and **System truststore** tabs, and
`/admin-api/truststores` is the same controls. **Nothing changes on upgrade**:
each use case's default list names exactly what it trusted before, and every
older setting and page keeps working. A use case's truststores are consulted
in development as well as product mode; paranoid PKI mode decides only what
is checked. Two defects are fixed on the way: a CA file named for an outbound
family or the SMTP relay no longer drops the signer truststore under paranoid
PKI mode, and PKINIT can be given an outside smart-card CA. New refusals:
`STS-PKI-0300` to `0307`. See [Truststores](truststores.md).

### Behaviour change: S/MIME mail is authenticated encryption

Mail encrypted to a person's S/MIME certificate is now a CMS
AuthEnvelopedData (RFC 5083) under AES-256-GCM (RFC 5084), sent as
`application/pkcs7-mime; smime-type=authEnveloped-data` as S/MIME 4.0
(RFC 8551) asks, so the recipient can tell the message was not changed on
the way (ASVS 5.0.0 11.3.3). Until 1.2.0 it was an EnvelopedData under
AES-256-CBC (`smime-type=enveloped-data`), which has no integrity
protection. RSA, EC and ML-KEM certificates are handled as before; only the
content encryption and its container changed.

**Upgrading.** Nothing to run: an existing deployment sends GCM from the
first message after the upgrade, retries of mail already queued included.
For a recipient whose mail client cannot read AuthEnvelopedData, set
`mail.smimeContentEncryption` to `aes256-cbc` (in the realm, or
`STS_MAIL_SMIME_CONTENT_ENCRYPTION`) to send exactly what 1.1 sent. While it
is `aes256-cbc` in product mode, `/admin/mode` reports ASVS 5.0.0 11.3.3 as
not met. See [OpenPGP and S/MIME](openpgp.md#encrypted-mail).
### New: PKINIT checks Microsoft's paChecksum2

The KDC now checks MS-PKCA's `paChecksum2` — the request body's SHA-256,
SHA-384 or SHA-512 — whenever a PKINIT client sends one, beside RFC 4556's
SHA-1 `paChecksum`, which stays required. A mismatch is refused
(`STS-KRB-0261`), and so is one over SHA-1 in product mode or over an
unlisted digest (`STS-KRB-0260`). The new setting
`krb5.pkinitRequirePaChecksum2` (off by default, because MIT Kerberos does
not send one) refuses a request without it (`STS-KRB-0262`). See
[Kerberos](kerberos.md).

### New: WS-Trust message integrity, and signed answers

A WS-Trust application can require its requests signed and name what the
signature must cover (`wstrustSignRequest`, `wstrustSignRequestElements`),
and can have its answers signed with the realm's XML signing key over a
`wsu:Timestamp` and the Body or the elements it names
(`wstrustSignResponse`, `wstrustSignResponseElements`). With encryption
also on, `wstrustResponseProtectionOrder` chooses sign-then-encrypt or
encrypt-then-sign, and `wstrustEncryptSignature` encrypts the signature
too. Each has a realm setting beside it (`wstrust.signRequest`,
`wstrust.signResponse`, `wstrust.responseProtectionOrder`,
`wstrust.encryptSignature`), all off by default. The WSDL's binding carries
`sp:IncludeTimestamp` while the realm signs its answers. On the
application's WS-Trust tab, **Body** and **Header** checkboxes write the
common expressions into the four encryption and signing maps, replacing
what a map held and putting it back when the last box is unticked, and an
**XPath builder** writes one for an element clicked in a sample message.
Putting a map to use turns its switch on, and giving it back turns the
switch back.
The tab has a simplified and an advanced view, the advanced one in General,
Message encryption and Message signing sections, each split into request
and response processing. Each field that holds XPath expressions has a
button that opens the XPath builder for that field in a window over the
page, where a list of expressions is built and added to it.
The XPath subset gains `not(…)`. New refusals: `STS-WSTRUST-0084`,
`0085`, `0086` and `0087`. See [Message integrity](ws-trust.md#message-integrity).

### New: a WS-Trust answer encrypted to the request's signing certificate

`wstrustRecipientIgnoresKeyUsage` (the realm's `wstrust.recipientIgnoresKeyUsage`,
off by default) lets an application's answers be encrypted to a certificate whose
`keyUsage` does not permit encryption, such as the request's signing certificate:
this realm's message-signing certificates permit `digitalSignature` only. Only that
check is waived; the certificate's validity, path and revocation are still checked.
It is in the **Message encryption → Response message processing** section of the
application's WS-Trust tab. See [WS-Trust](ws-trust.md#xml-encryption).

### Fixed: a WS-Trust answer element encrypted by a custom expression

A response encryption expression naming an element below the top of the
answer, such as `//wst:RequestedSecurityToken` or `//wst:Lifetime`, was
encrypted as text declaring that element's namespace prefix twice. That is
not well-formed XML, and a receiver that parses what it decrypts strictly,
such as Apache WSS4J, could not read the answer. The Body and Header
presets were not affected. Each prefix is now declared once.

### Fixed: WS-Trust requests signed by Apache WSS4J or CXF

A WS-Security signature carrying an `InclusiveNamespaces` prefix list on its
`SignedInfo`, which WSS4J and Apache CXF write by default, was refused as a
signature that does not verify (`STS-KEYS-0012`). It is now verified as its
signer made it.

### New: dynamic selectable roles

A role can be **dynamic selectable**: nobody is a member of it, and a person
chooses it at sign-in for the application they are signing in to, from the
roles that role's own XACML policy permits them. A role marked `required`
must be chosen. The choice is kept on the sign-on session, is asked of each
role's policy again at every issuance, and appears in the roles claim and
the SAML 2.0, SAML 1.1 and WS-Federation roles attribute for that
application only. Single sign-on into another application carries no
choice: the portal's **Sign in again** asks for a fresh sign-in, and an
application that requires a role the session did not choose for it sends
the person to sign in again. Flows with no sign-in screen (the password
grant, token exchange, the assertion grants, the device grant, CIBA,
WS-Trust, Kerberos and LDAP) never carry a chosen role, and are refused
where a role is required (`STS-XACML-0332`). See
[Dynamic selectable roles](dynamic-roles.md).

### New: a person is mailed when a credential of theirs is added or removed

Until now only a password change was mailed. A person is now also told when
any of these is added or removed (ASVS 5.0.0 6.3.7):

- a passkey or security key, an authenticator app or an app password
- a one-time code token or a YubiKey OTP
- a set of recovery codes, a certificate or a certificate sign-in binding
- an S/MIME certificate or an OpenPGP key

The message says what changed, when, and whether the person or an
administrator did it, and what to do if it was not them. Several changes made
by one act, such as an administrator removing every second factor, are one
message. Assigning an OATH or YubiKey OTP token through `/admin-api`, and
retiring a lost token's one-time code credentials, now also send a CAEP
`credential-change` event, as the other doors already did.

**Upgrading.** Nothing to run. The notices are on wherever a transport is
configured. To keep the old behaviour, set `mail.credentialChangeNotices` to
`false`. See [Mail](mail.md#the-uses).

### Behaviour change: a password reset signs you out everywhere

Setting a new password from a reset link a person asked for at
`/portal/forgot-password` now ends every session they had, on every device,
as a reset an administrator issues already did. A reset usually follows a
password somebody else may know, and a session opened with it should not
outlive the new one (ASVS 5.0.0 7.4.3). The page that confirms the new
password says so. If the sessions cannot be ended, the password is still set
and `STS-PORTAL-0638` is logged.

### Fixed: a password check takes as long for an account that does not exist

In product mode, a password presented for a name with no stored password, for
an account holding a stored value this service cannot read, for a disabled
account, or for a service account at a door its policy closes was refused at
once, while a wrong password for a real person took one password-hash
computation. The response time said which accounts exist (ASVS 5.0.0 6.3.8).
Those refusals now verify the presented password against a hash nobody holds,
made once per process at the password policy's current parameters, and discard
the result, so every refusal costs the same. What is refused, and the error
code recorded for it, are unchanged. This applies at every door that checks a
person's password: the sign-in screen, the password grant, an LDAP bind, a
WS-Trust UsernameToken, SCIM, SSF and EST HTTP Basic.

### Fixed: the console, portal and reports say why they cannot open without WebCrypto

The admin console, the user portal and the reports application sign in with
the browser's WebCrypto, which a browser offers only to a page opened over
HTTPS (or `localhost`). Opened over plain HTTP, or in a browser too old to have
WebCrypto, each one used to stop with a blank page. Each now checks before it
signs in and, where WebCrypto is missing, shows one sentence in the page's
language saying that this browser cannot run the page securely, usually
because the page was not opened over HTTPS or the browser is too old.

### Create pages mark what the create requires

Each Directory object has a create page that marks a field required exactly
when the create refuses it empty. New user marks the owners required while
**Service account** is ticked, and the push destination and the secret's
name each once the other is filled in. New policy no longer marks a field
the save accepts empty, such as the passkey policy's sign-in hints or the
attribute policy's required attributes.

A policy save through the management API that leaves `profile` out still
edits the default profile, as in 1.0.0. A save whose `profile` is empty or
null, and the console's new-policy form without a name, are refused with
"A name is required." (`STS-ADMIN-0549`). A named authentication policy
saved without a `name` is refused with `STS-AUTHN-0532`, as before.

### Behaviour change: a client that declares no scopes is issued `openid` alone

In product mode a client whose `oauthAllowedScope` lists nothing, typically
one that registered itself (RFC 7591) without a `scope` member, is now
issued `openid` and nothing else. Every other scope it asks for is refused
`invalid_scope` (`STS-OAUTH-0578`) until it is declared. Until 1.2.0 such a
client got `openid`, `profile`, `email`, `address`, `phone`,
`offline_access` and the realm's OpenID4VCI scopes, so a client nobody had
thought about could hold refresh tokens that outlive the person's session
(ASVS 5.0.0 10.4.11).

`oauth2.undeclaredClientScopes` chooses the set: `openid` (the default),
`identity` (the identity scopes, never `offline_access`), or `legacy` (the
old set). Development mode still issues any scope a client asks for. This
service's own clients declare their scopes and are not affected. A client's
OAuth tab now names the set it gets when it declares none.

**Upgrading from 1.1.** Run the upgrade script before starting the 1.2.0
image ([The audit log is append-only](#new-the-audit-log-is-append-only-in-the-database)
says why it must come first). It stores `legacy` for a store that holds any
application and has no value of its own, so every existing client keeps the
scopes it had. A second run writes nothing. A store still on 1.0.0 runs
`upgrade-1.0.0.sql` first.

```bash
docker compose exec -T postgres \
  psql -U sts -d sts -v ON_ERROR_STOP=1 \
  -f - < postgres/upgrade-1.1.0.sql

mariadb --abort-source-on-error -u root -p sts \
  < mariadb/upgrade-1.1.0.sql
```

A store that is only in memory starts fresh and gets the default. Without a
database (the LDIF store), or in a cell or tier database that does not hold
both the directory and the settings, set `oauth2.undeclaredClientScopes` to
`legacy` yourself. While it is `legacy` or `identity`, `/admin/mode` reports
ASVS 5.0.0 10.4.11 as not met. Declare in each client's `oauthAllowedScope`
the scopes it needs, then set the setting to `openid`.

### Behaviour change: an anonymous wallet keeps the scopes its offer named

A Credential Offer's pre-authorized code may be redeemed by a wallet that
names no client (OpenID4VCI 1.0 section 6.1). Its access token now carries
the scopes of the configurations the offer named, read from the offer and
not from the request, and keeps them in product mode, where the change above
would otherwise have issued that absent client `openid` alone. Without them
the credential was issued but not recorded for the person: `/portal/wallet`
did not list it and it could not sign them in. Until 1.2.0 such a token
always carried `identity_credential`, whichever configuration was offered.
A wallet that names a client is still issued only what that client
declares.

### Behaviour change: this service declares the scopes it asks a partner for

Where this service is the relying party and registers itself, it now
declares the scopes it will ask for, so a partner that issues a client only
what it declared (this service's own OP, in product mode, since the change
above) issues them. A relationship with `fedRegister` sends its `fedScope`
as the RFC 7591 registration's `scope`, and a realm's Entity Configuration
publishes, as its `openid_relying_party` metadata's `scope`, every scope its
OpenID Federation relationships (`fedTrustAnchor`) ask for. Until 1.2.0
neither carried a `scope`, and such a partner refused everything past
`openid` (`invalid_scope`). A partner that limits the scopes a client may
register may now refuse or trim the registration; set the relationship's
`fedScope` to what the partner offers.

**Upgrading.** Nothing to run. A relationship already registered with
`fedRegister` keeps its registration, which declared nothing; clear its
`fedClientId` (or press **Register at the partner**) to register again with
its scopes. An automatic OpenID Federation registration picks the scope up
when the OP registers the realm again, once the earlier registration ends.

### New: the audit log is append-only in the database

Where the audit log is stored (product mode on PostgreSQL or MariaDB, or
any deployment with request workers or several nodes), each event is now one
sealed row of a table of its own, `sts_audit`. The database role the service
connects as may add rows and read them, and may not change or delete one
(ASVS 5.0.0 16.4.2). Until 1.2.0 the log was kept with sessions and tokens,
where that role could rewrite it: the keyed checksums showed a change, and
nothing stopped one.

Old rows leave through two functions the table's owner owns. Retention runs
every ten minutes (the `audit.retain` scheduler job), removes what is past
each realm's `audit.maxEvents`, and keeps at least 1000 rows per realm
whatever the service asks. A removed realm's rows go once the realm is gone.
The audit page shows each realm's newest `audit.maxEvents` events across
every process.

A data key that audit rows are sealed under is no longer destroyed while
they remain, because those rows cannot be re-encrypted. Retention removes
them, and then the key can go.

If the service's role can still change the table (it owns it, or holds
`UPDATE`, `DELETE` or `TRUNCATE` on it), the service starts, logs
`STS-AUDIT-0019`, and `/admin/mode` reports the requirement as not met.

**Upgrading from 1.1.** Run the upgrade script as the table owner **before
starting the 1.2.0 image**. It creates `sts_audit` and its two functions,
gives the application role `SELECT` and `INSERT` on it and nothing more, and
records schema version 33. On MariaDB it also replaces the application
account's database-wide grant with one grant per table, because MariaDB
cannot take one table out of a database grant. A 1.2.0 image started first
does not start: its role cannot create the table (`STS-STORE-0029`, naming
the script). At its first start the 1.2.0 service copies the audit rows the
old log held into `sts_audit`, with their checksums, and removes the old
rows. The commands are the ones under [the scopes change](#behaviour-change-a-client-that-declares-no-scopes-is-issued-openid-alone).
A new install gets everything from `postgres/schema.sql` or
`mariadb/schema.sql`.

### Behaviour change: three report sources need `REPORT_ADMIN`

The report sources `auditEvents`, `authActivity` and `credentialHolders`
hold who did what, from where, and who holds which credential, which the
console keeps behind Admin Read. A report over one of them now needs
`REPORT_ADMIN` (ASVS 5.0.0 8.2.3, #2126). A caller holding only
`REPORT_USE` is refused (`forbidden`, `STS-REPORT-0061`) a query, a job, a
saved definition, a run and a download over them; every other source is
unchanged. The catalog marks the three `adminOnly`, the page offers them
only to a caller who may use them, and the access-control policy decides
them too, with `reportAdminSources` for sources a realm adds.

**Upgrading.** Nothing is removed. A definition a report user saved over one
of these sources stays visible to its owner, who may change its source or
delete it; its runs and its schedule are refused with `STS-REPORT-0061`
(each skipped occurrence noted on the definition) until its owner holds
`REPORT_ADMIN`. A realm that overrides `access-control` keeps its override:
the catalog's check refuses these sources without it, and rebuilding the
override from the template adds the rule to the policy. See
[Reports](reporting.md#who-can-open-it) and
[Field access](field-access.md#reports).

## 1.1.0

1.1.0 upgrades a deployment that is already running 1.0.0. Keep the
database volume. The 1.0.0 service can keep answering while the database
is upgraded. Start the 1.1.0 image after the upgrade script exits 0.

A store that is only in memory has nothing to upgrade. A database whose
schema version is below 31 is a pre-release build, and the script refuses
it. Those builds are covered under
[Not backwards compatible with earlier builds](#not-backwards-compatible-with-earlier-builds).

### PostgreSQL

Release 1.0.0's database is schema version 31. 1.1.0 adds two indexes on
`sts_sessions` and records schema version 32 beside it:

* `sts_sessions_started`, so the console's session pages can list sessions
  newest first without sorting the whole table.
* `sts_sessions_subject_band`, used by the per-subject session sweep.

The script also stores `xacml.pepAuthentication` = `either` in every realm
that has a registered remote PEP and no value of its own, so PEPs that
authenticate by client certificate keep working on 1.1.0's new default,
`token` ([The remote PEP authenticates with its key](#the-remote-pep-authenticates-with-its-key-the-client-certificate-is-retired)).
It prints what it stored. That step needs the directory and the settings
in the same database; in a cell or tier database that lacks either, it
writes nothing and says so.

Run the script as the table owner, from a checkout of 1.1.0. On the
compose stack the owner is `sts`. The application role `sts_app` cannot
create an index.

```bash
docker compose exec -T postgres \
  psql -U sts -d sts -v ON_ERROR_STOP=1 \
  -f - < postgres/upgrade-1.0.0.sql
```

Against a database you reach directly:

```bash
psql -v ON_ERROR_STOP=1 -f postgres/upgrade-1.0.0.sql \
     "postgres://owner@host:5432/sts"
```

Do not pass `--single-transaction`. The indexes are built with
`CREATE INDEX CONCURRENTLY`, which PostgreSQL refuses inside a
transaction. For a large `sts_sessions` table,
`-v sts_maintenance_work_mem=1GB` gives this session more memory for the
build and does not change the server. `-v sts_schema=sts` selects the
schema and is the default.

Then start the 1.1.0 image. If it starts before the script has run, it
still starts and answers every request; the session pages and the
per-person session sweep are slower until the indexes exist:

* As the application role (`sts_app`, the normal case), which cannot
  create an index, it logs `STS-STORE-0172` once, naming the two indexes
  and this script. Run the script; nothing needs restarting afterwards.
* As a role that owns `sts_sessions`, it builds the missing indexes
  itself, in the background, with `CREATE INDEX CONCURRENTLY`, without
  holding up writes or its own start. A build that fails logs
  `STS-STORE-0173` and is tried again at the next start.

Replacing the image before the script does not damage the volume.

**Leave the volume in place.** `docker compose down -v` deletes the
directory, the realm registry and the setting overrides, and in product
mode the sealed signing keys and everything minted under them.

**Do not run `postgres/schema.sql` again for this upgrade.** On a 1.0.0
database that script rebuilds `sts_ldap_entries_asked_names`, which
version 31 already has, and sets the application role's password again.
`postgres/upgrade-1.0.0.sql` does neither.

A second run finds the indexes already valid and changes nothing else. If
the script stops because an index of one of those names has the wrong
definition, drop that index and run the script again. An index left
invalid by an interrupted build is dropped and built again by the script.

Returning to the 1.0.0 image ignores both indexes. Leave them.

[PostgreSQL schema](postgres-schema.md) records what version 32 adds.

### MariaDB

MariaDB is the [second engine](persistence.md#a-second-engine-mariadb).
Its upgrade adds `sts_sessions_started`, records schema version 32, and
stores `xacml.pepAuthentication` = `either` in each realm with a registered
remote PEP, as the PostgreSQL script does.
`sts_sessions_subject_band` is PostgreSQL only. The build does not block
writers. Run it as an account that can `ALTER` the table,
in the service's database, and pass `--abort-source-on-error`:

```bash
mariadb --abort-source-on-error -u root -p sts \
  < mariadb/upgrade-1.0.0.sql
```

`sts` is that database's name. Use the name from the connection string
when it differs (`sts_store` in the MariaDB example). The same cautions
apply: leave the database in place, and do not run `mariadb/schema.sql`
again, which sets the application account's password on every run. A
second run inserts nothing. A valid index of the wrong shape is left as
it is; drop it and run the script again, then start the 1.1.0 image.
A 1.1.0 image started first still starts: an account that may not alter
the table logs `STS-STORE-0172`, and one that may builds the index in
place in the background (`STS-STORE-0173` if that fails).

### Behaviour changes: a deleted object leaves nothing behind

1.1.0 makes a delete complete. An application, person or group created
again under a deleted one's identifier, username or DN inherits nothing
from it. Each of these changes what 1.0.0 did:

* **Over LDAP, a group may not list a member that does not exist.** An
  add or modify that names a `member`, `uniqueMember` or `memberUid` with
  no entry behind it is refused with result code 19
  (`constraintViolation`). 1.0.0 accepted it. A script that adds a group's
  members before their entries must create the entries first. A dangling
  member that a 1.0.0 directory already holds is kept, and the console
  still reports it.
* **A delete takes the deleted entry's references with it.** A deleted
  person, group or application is taken out of every group that listed
  it and every role it was a member of. A deleted application no longer
  confers any role, and a deleted person or group is no longer an owner
  of any role, group, application or service account. 1.0.0 left these
  references in place, so whatever was next created under the same name
  or DN got them. Each removal is written to the audit log.
* **Deleting an application deletes the roles it owns.** A role made for
  one application (`<role>@<application>`, its `roleApplication` naming
  that application) is deleted with it, as the console's Delete role
  deletes one, with a `roles.delete` audit row for each. Its members and
  permissions go with it. A role owned by another application, and a
  realm-wide role, are not touched. In 1.0.0 these roles stayed, and an
  application registered again under the same identifier found them
  waiting, members included. If you still need such a role, create it
  again once the new application exists.

None of these changes the stored data or needs a migration step. They
apply to deletes made after the 1.1.0 image starts. References a 1.0.0
service left behind before the upgrade stay until you remove them on the
console or through `/admin-api`.

### Behaviour changes: a service account is for good

1.1.0 holds three rules about [service accounts](service-accounts.md#it-cannot-be-undone)
at every door: the console, `/admin-api` and an LDAP modify. Each changes
what 1.0.0 did:

* **A service account cannot be made an ordinary person again.**
  `POST /admin-api/users/set-service-account` with `serviceAccount: false`
  on a service account is answered 400 (`STS-SVCACCT-0060`), and an LDAP
  modify that deletes or replaces `stsServiceAccount` is refused with
  result code 19 (`STS-SVCACCT-0064`). 1.0.0 cleared the flag, the owners,
  the destination and the rotation state. The console's **Make them an
  ordinary person** button is gone, and its **Make them a service
  account** button now asks you to confirm that it cannot be undone.
  Deleting the entry is still allowed.
* **A service account that has an owner always keeps one**, whatever the
  policy's `requireOwner` says. Removing the last owner, sending
  `owners: []`, or an LDAP modify deleting the last
  `stsServiceAccountOwner` is refused (`STS-SVCACCT-0061`,
  `STS-SVCACCT-0065`). In 1.0.0 this was allowed while `requireOwner` was
  off. An account made with no owner under `requireOwner` off can still
  be edited without naming one.
* **An owner cannot remove themselves.** Taking your own DN off an
  account's owners, or the group that is your only way of owning it, is
  refused (`STS-SVCACCT-0062`, `STS-SVCACCT-0063`; over LDAP, for the bound
  DN, `STS-SVCACCT-0066`, `STS-SVCACCT-0067`). Another administrator may
  remove you.
* **Deleting an account's last owner makes the realm's administrator the
  owner.** When the person or group that is a service account's only owner
  is deleted (SCIM `DELETE`, an LDAP delete), the realm's Admin Write group
  becomes its owner, or the realm's bootstrap administrator if there is no
  such group. An `admin.service-account.owner-added` row by `system` says
  so. In 1.0.0 the account was left with no owner. If the realm has
  neither, it still is, and `STS-SVCACCT-0068` is logged.

Existing service accounts are unchanged, and nothing needs a migration
step. A script that un-made a service account, or emptied its owners,
gets the refusal instead.

### AuthZEN ignores members it does not define

In 1.0.0, an [AuthZEN](authzen.md) request carrying a member that AuthZEN
1.0 does not define was refused with 400. In 1.1.0 it is accepted, and the
member is ignored, as AuthZEN 1.0 section 10.1.1 requires ("receivers MUST
ignore unknown fields"). This covers every request under `/access/v1`:
an evaluation, an evaluations batch, the three searches and an access
request. It applies at the top level and inside `subject`, `action`,
`resource`, `page` and `options`. An Action Search's `action`, which the
search does not define, is ignored too.

Nothing else about a request changes. A defined member is still checked
for type and presence. A property inside `properties` or `context` still
needs a conversion rule. BULK's `items` on an access request is still
refused. A request that worked in 1.0.0 gets the same answer.

`STS-AUTHZEN-0009` is retired. Other APIs still refuse members they do not
declare. The remote PEP's AuthZEN endpoint in the `xacml-pep` container
follows the same rule.

### AuthZEN requires `Content-Type: application/json`

AuthZEN 1.0 section 10.1 says a request MUST carry `Content-Type:
application/json`. In 1.0.0 the evaluation, the evaluations batch and the
three searches read any body as JSON, whatever it was labelled. In 1.1.0
a request labelled anything else, or not labelled at all, is answered
`415 Unsupported Media Type` (`STS-AUTHZEN-0117`) once the caller is
admitted. A `charset` parameter is accepted. A caller that sent JSON as
`text/plain`, or with no `Content-Type`, has to send the header. The
remote PEP's AuthZEN endpoint is unchanged.

### An AuthZEN resource search names the policy's resource ids

In 1.0.0 a [Resource Search](authzen.md#searching) for a resource type
this service has no objects of (anything but `application`, `api` and
`delegation`) answered no results, whatever the policy permitted. In
1.1.0 its candidates are the resource ids the realm's policies compare
`resource-id` with, and each is a result only where the policy permits
it as that type. Section 8.5 asks for every resource of the type the
subject may act on. The three types this service has objects of answer as
before.

### Policies can be exported and imported, whole or one at a time

New in 1.1.0: Directory → Policies has an **Export and import** tab, and
`/admin-api` has `POST /admin-api/policies/transfer/export`, `inspect` and
`import` with `GET /admin-api/policies/transfer` beside them. An export is a
JSON document signed under the realm's new Policy Export Signing CA, with the
signer's whole chain inside it. An import from another realm asks whether to
trust that realm's signer first. An export may carry every policy the realm
stores or only the ones named, each by its kind and name, and every stored
policy has an Export button of its own. An import may write every policy in
the document or only the ones ticked. [Policies](policies.md#export-and-import)
has the details.

### A federated OpenID Provider may leave out its `issuer`

This applies to a federation relationship that finds its OpenID Provider
through an [OpenID Federation](configure-oidfed.md#this-service-as-a-federated-relying-party) Trust Anchor
(`fedTrustAnchor`). In 1.0.0, the sign-in was refused with `STS-FED-0149`
when the provider's resolved `openid_provider` metadata had no `issuer`.
In 1.1.0 an absent `issuer` is read as the provider's Entity Identifier.
OpenID Federation for OpenID Connect 1.1 section 5.1.2 allows no other
value. An `issuer` that is present and names another entity is still
refused. The ID Token's `iss` is still checked against the Entity
Identifier. Nothing this service publishes changes.

### New: export and import a person as LDIF

A person's page under **Directory → Users** has an **Import / export** tab,
the one an application's page has had since 1.0.0. **Export** saves the
person as an LDIF file of one record: the attributes a create takes, and,
only when its box is ticked, their credentials **unencrypted** (the
password as its stored hash, the authenticator app, passkeys, recovery
codes, app passwords and stored certificates). **Import** creates a person
from such a file in the realm the console is in, and never overwrites one
who is already there. Both need Admin Write and a recent sign-in. The API
is `POST /admin-api/users/export-ldif` and `/import-ldif`; see
[Exporting and importing a person as LDIF](admin-console.md#exporting-and-importing-a-person-as-ldif).
Nothing that existed in 1.0.0 changes.

### An ISO mdoc is issued

The issuer offers `IdentityCredentialMdoc` (`mso_mdoc`). It is signed with
COSE ES256 (`-7`) or ESP256 (`-9`) by a document signer that chains to an
ECDSA Issuing Authority CA this realm mints on first use
(`GET /oid4vci/mdoc-iaca`, and `GET /admin-api/mdoc-iaca`). The credential
names `GET /oid4vci/status-lists/mdoc`. A wallet sign-in accepts an mdoc
only when this realm issued it. The Digital Credentials API still does not
carry one, and the Mobile Security Object is not signed with a post-quantum
algorithm.

The verifier's default document type and namespace are now the type this
realm issues (`urn:iya:sts:mdoc:identity`, `urn:iya:sts:mdoc`), not the
mobile driving licence. A deployment that asked for
`org.iso.18013.5.1.mDL` sets `oid4vp.expectedDoctype` and
`oid4vp.mdocNamespace`.

### `bbs-2023` is the W3C cryptosuite

Until 1.1.0 an `ldp_vc` this service issued was labelled `bbs-2023` but
used a private format: no W3C bbs-2023 implementation could verify it, and
the Verifier could verify no other issuer's. It now follows *W3C Data
Integrity BBS Cryptosuites v1.0* (baseline), in issuance, presentation and
verification ([Verifiable credentials](verifiable-credentials.md#bbs-2023)).

* **The base proof** is the specification's: blank nodes relabelled by HMAC,
  the statements named by the configuration's mandatory JSON pointers hashed
  into the BBS header, and the other statements signed as messages
  (`oid4vci.ldpVcMandatoryPointers`, `oid4vci.ldpVcDidMandatoryPointers`;
  default `/issuer,/type,/validFrom,/validUntil`). The proof carries no
  `created`.
* **A presentation is a reveal document**, the credential with only what the
  holder reveals, carrying a derived `DataIntegrityProof`. Presented on its
  own, its presentation header must be the request's nonce; inside a
  `VerifiablePresentation`, the presentation's proof carries the nonce as its
  `challenge` and the client as its `domain` (OpenID4VP 1.0 B.1.3.2.5), and
  the header may be the nonce or empty.
* **The BBS key is published as the specification's Multikey**:
  `publicKeyMultibase` is `z` and base58btc of `0xeb01` and the 96-byte key,
  at `/bbs/keys/{kid}` and in the DID document. It was `u` and the raw bytes.
* **Credentials issued by 1.0.x cannot be presented by default.** Their
  proofs are in the old, non-standard format and cannot be turned into the
  new one, so a realm refuses a presentation in it, naming it as the pre-W3C
  format (`STS-VC-0181`). **Holders need their credential issued again**:
  a refresh or a new issuance from 1.1.0 gives a W3C one. A 1.0.x credential
  expires after `oid4vci.credentialLifetimeS` (thirty days by default)
  anyway.
* **`oid4vc.bbs2023LegacyFormat`** (per realm, default `false`) makes a realm
  use the old format again: it issues its `ldp_vc` credentials in it and
  accepts presentations in it, as well as W3C ones. Turn it on only while a
  wallet that has not moved to W3C bbs-2023 is in use, and off once it has;
  a credential issued under it cannot be presented once it is off. The old
  format is named `iya-bbs-2023-legacy` in the metadata and in the
  credential, never `bbs-2023`, and every use is logged
  (`STS-VC-0182` for a presentation, `STS-VC-0183` for an issuance).

### The remote PEP authenticates with its key; the client certificate is retired

A remote XACML PEP authenticates every call it makes to the service — the
registration, the pulls, the heartbeat, the PIP, the decision records and
the AuthZEN forward — with a DPoP-bound access token from an RFC 7523
assertion it signs with its own key (`PEP_ASSERTION_KEY`). The key is
generated where the PEP runs and certified with `issue-pep-credential`; the
service never holds it ([How the PEP authenticates to the service](remote-pep.md#how-the-pep-authenticates-to-the-service)).

* **`xacml.pepAuthentication` defaults to `token`.** A PEP that presents only
  a client certificate is refused (401, `STS-XACML-0289`). `either` and
  `certificate` stay available for an older PEP image or another
  implementation.
* **The 1.1.0 upgrade script keeps a 1.0.0 deployment's PEPs working.**
  Every PEP 1.0.0 registered authenticated by its client certificate, so
  `postgres/upgrade-1.0.0.sql` and `mariadb/upgrade-1.0.0.sql` store
  `xacml.pepAuthentication` = `either` in every realm with at least one
  registered remote PEP (an entry under its `ou=peps`), only where the realm
  stores no value. When the default realm has a PEP its `either` is
  service-wide, so the script also stores `token` in each other realm with no
  PEP and no value. A realm with no PEP, and a new installation, get
  `token`.
* **Then move each realm to `token`**: give each PEP its key
  (`issue-pep-credential`, then `PEP_ASSERTION_KEY` on the 1.1.0 PEP image),
  and once every PEP in the realm holds its tokens, set
  `xacml.pepAuthentication` to `token` or reset it
  ([Upgrading a deployment whose PEPs use a certificate](remote-pep.md#upgrading-a-deployment-whose-peps-use-a-certificate)).
  Without the script (the LDIF store, or a split cell database), set
  `either` yourself before the PEPs reconnect. If a PEP is refused anyway,
  the 401 says that `either` would accept its certificate, and the service
  logs a warning under `STS-XACML-0289` once per realm.
* **The PEP ignores `PEP_TLS_CERT`** and says so once at start
  (`STS-XPEP-0135`). `PEP_TLS_KEY` is still read as the assertion key while
  `PEP_ASSERTION_KEY` is unset. `GET /`'s `credential.clientCertificate` is
  always `false`.
* **The CRL-only plain listener binds only with `PEP_CRL_HTTP=true`.** It
  served the client certificate's CRLs. A PEP with a CRL directory and no
  switch says once that it is not bound (`STS-XPEP-0136`).
* **An anonymous request to `/xacml/pep/*`** is now a 401 (`STS-XACML-0289`)
  in a realm on the default, where it was the access policy's 403.
* **The seeded client `sts-remote-pep`** no longer declares
  certificate-bound tokens; an entry a pre-release build seeded with the flag
  has it removed at the next start (audited as `application.update`). A token
  request through it with no DPoP proof is `STS-OAUTH-1012`.
* **The test stacks and the AWS suite runner** mint no client certificate
  for the PEP and post no trust anchor for it.

### A remote PEP's directory entry is a service account

The entry a remote XACML PEP's client certificate maps to is now a
[service account](service-accounts.md), owned by the realm's Admin Write
group, or by its bootstrap administrator where that group does not exist
([details](remote-pep.md#the-peps-entry-is-a-service-account)).

* **When it happens.** An entry becomes one when it joins `remote-peps`. The
  seeded `remote-pep-1` and every entry already in the group become one at
  the next start, so an existing deployment needs no step of its own.
* **What changes.** The PEP's connection is unaffected: mutual TLS is not a
  service-account door. A browser sign-in as the entry is now refused
  (STS-SVCACCT-0010) unless the realm's service-account policy allows it.
* **When it waits.** A realm with no Admin Write group and no bootstrap
  administrator leaves the entry as it is and logs STS-SVCACCT-0051: a
  service account is never made without an owner.
* **The console and the API.** The PEP's Overview tab shows it, with the
  owners and a link to the person's Service account tab. Each row of
  `GET /admin-api/xacml/peps` carries `identityAccount`. The change is
  additive.

### The remote PEP binds no plain-HTTP listener by default

The remote XACML PEP container (`iyasec/iya-sts-xacml-pep`) no longer binds
its plain-HTTP decision API on 9090 or its plain-HTTP reverse proxy on 9180
unless you ask for them. Over HTTPS, 9443 and 9543 behave as before.

* **To keep the old behaviour**, add `PEP_HTTP=true` (the API) and
  `PEP_PROXY_HTTP=true` (the proxy) to the container's environment. With
  `docker-compose.yml`, set `XACML_PEP_HTTP=true` and
  `XACML_PEP_PROXY_HTTP=true` on the host.
* **A container that sets `PEP_PORT` or `PEP_PROXY_PORT` without the
  switch** logs `STS-XPEP-0106` once at start, naming the line that brings
  the listener back. A switch set to anything other than `true` or `false`
  leaves the listener off and logs `STS-XPEP-0107`.
* **The image's healthcheck** probes `/healthcheck` over HTTPS on
  `PEP_HTTPS_PORT` when plain HTTP is off. A PEP with no HTTPS pair yet
  reports itself unhealthy until it has one. If something gates on that
  health, turn `PEP_HTTP=true` on.
* **`docker-compose.yml`'s default `PEP_NOTIFY_URL`** is now
  `https://xacml-pep:9443/notify`. The old `http://` default was refused unless
  `xacml.pepNotifyAllowHttp` was on.
* **The client credential's CRL stays reachable.** A credential minted with
  `tests/tools/pep-credential.js --crl-base=http://<pep>:9090/crl` names the
  PEP's plain port, and with plain HTTP off nothing answered there, so the
  service could not fetch the list and refused every pull as
  unauthenticated. With `PEP_HTTP` off the PEP now binds `PEP_PORT` for
  `GET /crl/<name>` and nothing else, whenever it has a CRL directory to
  serve. `PEP_CRL_HTTP=false` turns it off and `PEP_CRL_HTTP=true` binds it
  even with no directory; a value that is neither logs `STS-XPEP-0115`.
  **Since the client certificate was retired (above), only
  `PEP_CRL_HTTP=true` binds it.**
  Anything else asked of that port is a 404 (`STS-XPEP-0114`). The Listener
  tab shows it as *listening, CRLs only*.
* **Admin console**: the remote PEP's Listener tab shows the two listeners as
  *off*, each with its switch. A listener the PEP reports *off* no longer
  holds its port, so a listener defined on the tab may use 9090. A listener
  the PEP has not reported, or reported with no state, reads *not reported*
  (it read *listening* before), and an environment plain-HTTP listener with
  no report reads as its default, *off*.

### The nudge to a remote PEP is HTTPS only, and verifies with no setting

The service sends a remote PEP's "pull now" nudge over HTTPS only, in every
mode, and always verifies the PEP's certificate.

* **Trust with nothing set.** The PEP's HTTPS listener certificate is issued
  by the realm's Remote PEP listeners (`pep-tls`) Issuing CA, and the nudge
  verifies against that chain by default, with the host checked against the
  notify URL's. A certificate from this service's Root but another Issuing
  CA (another realm's PEP, a custom listener) is refused (`STS-XACML-0260`).
  `xacml.pepNotifyCaFile` is still read, as an additional anchor for a PEP
  certified elsewhere. The nudge that 8081 refused with "self-signed
  certificate in certificate chain" (`STS-XACML-0070`) is delivered.
* **`xacml.pepNotifyAllowHttp` and `xacml.pepNotifySkipTlsVerification` are
  retired.** Both are still accepted, so a configuration naming them keeps
  starting, and both are ignored; one that is on logs `STS-XACML-0258` once
  per process. Remove them. `GET /admin-api/xacml/peps`' `notify.transport`
  reports `allowHttp` and `skipTlsVerification` as `false`.
* **A PEP registered with an `http://` notify URL** is shown with that URL
  unusable, *plain http, the nudge is sent over HTTPS only*, and goes on
  converging by polling. Set its notify URL to
  `https://<host>:<PEP_HTTPS_PORT>/notify` (the PEP's Settings tab now
  refuses an `http://` one, `STS-XACML-0239`). `STS-XACML-0259` is recorded
  for a nudge refused that way; `STS-XACML-0073` and `STS-XACML-0074` are
  retired.
* **The PEP** answers `POST /notify` on its HTTPS listener only (a 404 over
  plain HTTP, `STS-XPEP-0112`), and **rejects** an `http://`
  `PEP_NOTIFY_URL`, or an `http://` `notifyUrl` an older service stored
  (`STS-XPEP-0113`, at ERROR, once per value). A rejected URL means the PEP
  advertises no notify URL at all, not the derived one, until it is fixed
  or unset. It is reported with `rejected: true`
  (`peps[].settingsInUse.values.notifyUrl.rejected` on
  `GET /admin-api/xacml/peps`), and the PEP's Settings tab and Notify column
  say it is rejected.
* **Admin console**: the Notify column of the Remote PEPs tab, and the PEP's
  Overview, show *usable*, *unusable* with a one-line reason, or *none*, and
  two words about the last nudge; the full sentences are under *Details*.
* **The PEP derives its notify URL when none is set.** With neither the
  PEP's Settings tab `notifyUrl` nor `PEP_NOTIFY_URL` set, the PEP advertises
  `https://<host>:<PEP_HTTPS_PORT>/notify`. `<host>` is the DNS name in the
  HTTPS listener certificate it serves that equals its hostname, else the
  certificate's first DNS name, else `PEP_NAME` if that is a DNS name, else
  the container's hostname. So a certificate naming the PEP's registered
  name first and `xacml-pep` second, on a container named `xacml-pep`, gives
  `xacml-pep`. A PEP with no HTTPS certificate yet
  advertises none until it has one, and a new certificate derives the URL
  again. The PEP logs the derived URL at INFO, and reports its source as
  `derived` (`GET /admin-api/xacml/peps`'
  `peps[].settingsInUse.values.notifyUrl.source`). The Notify column says
  *derived by the PEP from its HTTPS listener certificate*. The service still
  checks the URL as before: https only, the certificate verified, and the
  host checked against it. **`docker-compose.yml` and the test stack no
  longer set a notify URL**, so they derive it. `XACML_PEP_NOTIFY_URL`
  still sets one, and an empty one now means unset.
* **The PEP reports its hostname, and the realm's default certificate names
  it.** The PEP sends `hostname` (the value the derivation reads) on its
  registration and heartbeat. The service stores it and adds it to the
  default names of the PEP's HTTPS listener certificate, beside the
  registered name and the notify host, for both the environment pair and a
  defined listener's certificate. So on a fresh install the derived notify
  URL uses the hostname with no names added by hand. The PEP's Overview tab
  and `GET /admin-api/xacml/peps` (`peps[].hostname`) show it. The service
  accepts only a DNS name, never an IP address, and refuses anything else
  with 400 (`STS-XACML-0261`). A PEP that reports none keeps today's
  defaults, and an older service ignores the member. A certificate issued
  before this does not name the hostname: issue it again, or let a defined
  listener renew.

### The reverse proxy's fixes from the 8081 demonstration

* **The service's cookies never reach the application.** A browser sends
  cookies by host, not port, so where the service and the proxy share a host
  `__Host-sts_session` and the rest were forwarded upstream. The proxy now
  strips every cookie the service names on the pull
  (`realm.serviceCookiePrefixes`: `sts_*`, `__Host-sts_*`, `__Secure-sts_*`),
  and the managed setting `proxyStripCookies` (`PEP_PROXY_STRIP_COOKIES`) adds
  names, a trailing `*` for a prefix. The application's own cookies are
  untouched. A service older than this sends no list, and the PEP strips the
  same three prefixes.
* **An identity header with no value is not sent.** A person in no group sent
  an empty `X-Iya-Groups`; an empty string or list now sends no header, for
  every identity header.
* **`X-Iya-Amr` is sent.** The identity endpoint answered every proxy
  session's access token with no `amr`; it now reads the token's own `amr`,
  `acr` and `auth_time`.
* **A proxy session a CAEP signal ended clears its cookie** on the redirect
  to sign in, as the documentation said.
* **Between a sign-out and its signal**, a browser whose identity the service
  refused because its session had ended got a 403; it is now sent to sign in
  with the proxy session ended, and anything else gets a 401.
* **The account chooser shows usernames.** The service's ID Token carries no
  `preferred_username`, so an account was labelled by its `urn:uuid` subject;
  the sign-in now asks the service's session endpoint, whose answer also
  carries the person's display name (`name`), shown beside it.
* **A route's identity is edited on the route's own page.** The Reverse
  proxy tab drew a *How route … forwards the identity* form under its table
  for every route; that is now only the identity part of the route page's
  form, which the route id in the table links to.
  `POST /admin-api/xacml/set-pep-route-identity` is unchanged.
* **`/admin-api/xacml/*` PEP acts take `pep` as well as `name`**, the name
  `GET /admin-api/xacml/peps` takes as `?pep=`. `name` still works; both
  naming different PEPs is refused (`STS-XACML-0038`).

[Plain HTTP is off by default](remote-pep.md#plain-http-is-off-by-default)
has the precedence and the reasons.

### New: a remote PEP route's own page, and several accounts in one browser

* Each reverse-proxy route has a console page of its own, where every
  value can be edited and the route renamed
  ([A route's own page](remote-pep.md#a-routes-own-page)).
* A session route can let one browser hold several signed-in accounts and
  switch between them (`multipleAccounts`, off by default; the bound is
  `proxyMaxAccounts`, `PEP_PROXY_MAX_ACCOUNTS`, default 5;
  [Several accounts in one browser](remote-pep.md#several-accounts-in-one-browser)).

### Changed: every reverse-proxy route is authorized by its own policy

* **Every request on every route is decided in XACML by that route's own
  policy, never by the realm's root.** Each route makes one `authorization`
  choice: an existing policy, a simple generated policy (a resource, CRUD
  or read/write, and the roles for each action), or Public, which generates
  a policy too ([Authorizing a route](xacml.md#authorizing-a-route)). The
  route forms draw the choice as one selector, with a search for the policy
  and for each action's roles.
* **An empty methods list is deny-all**, and a route takes any method by
  listing all seven. Every route states its `methods`.
* **Not compatible with the proxy documents of earlier builds**, which the
  proxy feature's unreleased state allows: `public`, `resource` and
  `action` are refused as members, `methods` and `authorization` are
  required, and a remote PEP and the service upgrade together. Save each
  route's choice again (or edit the document) after the upgrade.

### Credentials are signed by a key of their own, whose certificate names the issuer

Until now, a `dc+sd-jwt` or `jwt_vc_json` credential and its Token Status
List Token were signed with the realm's general JOSE key. That key also
signs ID Tokens, access tokens, metadata and Security Event Tokens, and its
certificate named no issuer. A wallet following HAIP 1.0 section 6.1.1 had
nothing in `x5c` to compare the credential's `iss` with
([Verifiable credentials](verifiable-credentials.md#the-credential-signing-certificate)).

* **Each realm signs its credentials and their status lists with a
  dedicated key** for each algorithm family (RSA, each curve, each
  post-quantum algorithm). That key signs nothing else. It is made the first
  time a credential needs it, is published in `/oauth2/jwks` and in the DID
  document, and is accepted by this realm's Verifier. It is not accepted
  for any of the realm's other tokens.
* **Its certificate binds the issuer.** The subjectAltName holds one
  `uniformResourceIdentifier` for every issuer identifier the realm answers
  to, plus the `did:web` of each. With `global.publicBaseUrl` (or the
  credential application's listener) pinned, that is exactly one issuer.
  Otherwise it is each `tls.hostnames` and `tls.ips` name on the main port.
  The extended key usage is `id-kp-documentSigning` (RFC 9336). There is no
  DNS name and no TLS usage, so no TLS stack takes the certificate for a
  server certificate. keyUsage is `digitalSignature` alone. A post-quantum
  key, ML-DSA included, has a certificate over itself, never over a
  partner's key.
* **It is re-issued when the issuer identifiers change** (a new
  `global.publicBaseUrl`, a listener, a host name), at the next credential.
  The certificate it replaces is not revoked, so credentials issued under it
  keep verifying.
* **Revoking the live certificate takes effect at once.**
  * After `superseded`, `affiliationChanged` or `cessationOfOperation`, the
    same key gets a new certificate.
  * After any other reason, including `keyCompromise` and
    `certificateHold`, the next credential is signed by a new key. The old
    key is no longer published or accepted while the revocation stands
    (`STS-PKI-0287`).
* **A credential whose `iss` the certificate does not name** is still
  issued with its `x5c`. That happens when a request reaches the service by
  a name nobody configured. The service logs a warning once per realm and
  address (`STS-PKI-0283`), and a strict wallet refuses the credential. Pin
  `global.publicBaseUrl`, or add the name to `tls.hostnames`.
* **`keys.credentialSigner`** (`STS_KEYS_CREDENTIAL_SIGNER`): `dedicated`, the
  default, or `realm-key`, which keeps 1.0.0's behaviour for a deployment
  whose verifiers pinned the realm's general key. Credentials already issued
  verify either way. `ldp_vc` and `mso_mdoc` are not affected, and neither
  is the trusted list, which its scheme operator signs.

### WS-Trust uses XML Encryption selected by an XPath expression map; `?encrypt=1` is retired

`POST /sts?encrypt=1` encrypted the issued SAML 2.0 assertion to the
requester's certificate. That query parameter was this service's own test
control. It was never part of WS-Trust, and it is retired. A request that
still carries `encrypt=1` is handled as if the parameter were absent:
nothing is encrypted because of it, and the parameter alone is not a fault.

XML Encryption of a WS-Trust message is now chosen per application, once
for the request and once for the response. Each direction is a checkbox
and an XPath expression map: a list of expressions, one per value, naming
what must be element-encrypted. An expression may select a SOAP header,
the SOAP body, or any other element, so a SAML assertion, a JWT, a
username token and any other token are covered by the same map. Each
selected element is replaced by `xenc:EncryptedData` with `Type`
`http://www.w3.org/2001/04/xmlenc#Element`, and the key sits inside that
element. The response is not wrapped in `saml:EncryptedAssertion`.

This does not use the SAML assertion settings.
`saml2.encryptAssertion`, `saml2.encryptionAlgorithm`,
`saml2.keyTransportAlgorithm` and `samlEncryptionCertificate` are
unchanged and apply to SAML only. WS-Trust has its own settings and its
own attributes.

* **Each direction has a checkbox and its XPath map.** Both checkboxes
  default to off, and an application may override either.
  * `wstrust.encryptRequest` (`wstrustEncryptRequest`) requires every
    expression in `wstrustEncryptRequestElements` to arrive as XML
    Encryption. The service verifies a WS-Security signature on the
    message as it arrived, then decrypts those elements with the realm's
    XML private keys.
  * `wstrust.encryptResponse` (`wstrustEncryptResponse`) replaces every
    match of `wstrustEncryptResponseElements` in the response.
  * A switch that is on with an empty map is a fault. An expression that
    matches nothing is a fault. Either one stops processing at once and
    returns that fault: nothing is issued, and the clear response is not
    sent.
* **An expression is a stated subset of XPath.** It may use `/` and `//`,
  `*`, an element name, `prefix:local`, a union with `|`, and the
  predicates `local-name()`, `namespace-uri()` and `@attr`, joined by
  `and`. Any other expression is `wst:RequestFailed`
  (`STS-WSTRUST-0079`). Write `local-name()` and `namespace-uri()` when
  one expression should match SOAP 1.1 and SOAP 1.2. A prefix is resolved
  from the namespaces declared on the element, and from SOAP 1.1, SOAP
  1.2, WS-Addressing, WS-Security, WS-Security Utility, WS-Trust, SAML,
  XML Signature and XML Encryption.
* **The algorithms are WS-Trust settings, overridable per application.**
  `wstrust.encryptionAlgorithm` (`wstrustEncryptionAlgorithm`) defaults to
  `aes256-gcm`. `aes128-gcm` is also available, and `aes256-cbc` and
  `aes128-cbc` only where broken algorithms are allowed.
  `wstrust.keyTransportAlgorithm` (`wstrustKeyTransportAlgorithm`)
  defaults to `rsa-oaep-mgf1p`. `rsa-oaep` is also available, and
  `rsa-1_5` only where broken algorithms are allowed. Where legacy hashes
  are not allowed, `rsa-oaep-mgf1p` is used as `rsa-oaep`. An
  elliptic-curve recipient uses ECDH-ES whatever the key transport says.
* **The response is encrypted to one recipient, and a configured step
  that cannot be used does not fall through to the next.**
  1. `wstrustEncryptionCertificate` on the application, when it is set:
     base64 DER or PEM. A value that cannot be used is a fault.
  2. Otherwise `wstrustResponseRecipientXPath`: the first
     `ds:X509Certificate` or `#X509v3` `BinarySecurityToken` that
     expression selects in the request. An expression that is set and
     matches nothing, or that selects an element that is not one of
     those two, is `wst:InvalidRequest` (`STS-WSTRUST-0076`). A
     certificate element whose text is not a certificate is
     `wst:RequestFailed` (`STS-WSTRUST-0077`). The next source is not
     tried.
  3. Otherwise the first signer certificate element the request's
     WS-Security signature names, in document order. That is the
     `#X509v3` `BinarySecurityToken` the signature's reference points
     at, or a `ds:X509Certificate` in that signature's `KeyInfo`.
  A thumbprint, Subject Key Identifier or issuer-serial that does not
  carry the certificate element is not a recipient. A certificate inside
  an assertion, or inside `OnBehalfOf` or `ActAs`, is not the signer's.
  With response encryption on and no recipient, the fault is
  `wst:InvalidRequest` (`STS-WSTRUST-0076`) in both modes. A cipher
  failure, a response expression that matches nothing, or a certificate
  the encryption-recipient check refuses is `wst:RequestFailed`
  (`STS-WSTRUST-0077`). Under paranoid PKI mode the certificate must
  permit `keyEncipherment` or `keyAgreement`. A message-signing
  certificate permits `digitalSignature` only, so set
  `wstrustEncryptionCertificate` when the signer's certificate cannot be
  an encryption recipient. A certificate with no `keyUsage` may encrypt
  (RFC 5280).
* **A request element the map requires, sent in clear, is refused in both
  modes.** After decryption every request expression must select at least
  one node, and every selected node must be one restored from ciphertext
  or inside one. A clear match, a miss, or a decrypt that fails is
  `wsse:FailedCheck` (`STS-WSTRUST-0075`), WS-Security 1.1's code. Development mode no longer
  answers in clear when encryption was required and could not be done.
* **Arbitrary ciphertext is a setting, off by default.** With
  `wstrust.acceptEncryptedElements` (an application's
  `wstrustAcceptEncryptedElements`) on, an encrypted element anywhere in a
  request is opened: an `EncryptedData` of type Element or Content, a
  WS-Security 1.1 `EncryptedHeader`, its key in its own `KeyInfo` or in an
  `EncryptedKey` in the security header that lists it. Off, ciphertext is
  accepted only where the request map names it, and anything else is
  `STS-WSTRUST-0080`. A ciphertext must open with this realm's keys either
  way. A signature is verified in the order the security header gives, so
  a request signed before it was encrypted verifies, and what opens outside
  the signed Body is `STS-WSTRUST-0046` in product.
* **A map's prefixes are the service's.** `wst`, `wsa`, `saml` and the
  rest mean what [WS-Trust](ws-trust.md#xml-encryption) lists, whatever the
  request declares.
* **An encrypted answer announces itself.** Its `EncryptedKey` and
  `ReferenceList` are in a `wsse:Security` header, so WSS4J and WCF decrypt
  it in their own security processing.
* **A recipient expression selects only what the signature covers.** The
  certificate `wstrustResponseRecipientXPath` selects must be the signer's
  own token or inside a part the accepted signature references, or the
  request is `STS-WSTRUST-0081`.
* **The WSDL describes it** ([the metadata document](ws-trust.md#the-metadata-document)).
  The message signature is an `sp:AsymmetricBinding` under
  `sp:Basic256Sha256` on the eight ports, and under this service's own
  suite, `urn:iya-sts:ws-securitypolicy:algorithm-suite:1`
  `Basic256GcmRsaOaepSha256` (AES-256-GCM, RSA-OAEP over SHA-256,
  RSA-SHA256), on eight more `IyaSuite` ports. A request may
  sign every header and the Body, and may be encrypted where the realm
  accepts it under the port's suite; an answer may be encrypted where the
  service-wide cipher is that suite's. Each choice is optional. An
  `sp:IssuedToken` now carries the nested `wsp:Policy` WS-SecurityPolicy
  requires; without it Apache CXF would not load the WSDL.
* **The encryption certificate as each port's identity is a setting, off by
  default.** With `wstrust.advertiseEndpointIdentity` on, every port
  carries the realm's encryption certificate in a
  `wsa:EndpointReference/wsid:Identity`, where WCF reads it. That element is
  from WS-AddressingIdentity, a Microsoft specification that was never
  standardised, so the WSDL does not carry it by default. Off, a client is
  configured with the certificate from `/saml2/metadata`
  ([The encryption certificate](ws-trust.md#the-encryption-certificate)).
* **An RST may name a cipher only inside the application's policy.**
  Absent `wst:EncryptionAlgorithm` and `wst:EncryptWith`, the
  application's settings are used as they stand. Either element may name
  a cipher only when response encryption is already on and the name is
  the configured algorithm. Anything beyond that is `wst:InvalidRequest`
  (`STS-WSTRUST-0078`). `wst:UseKey` and `wst:ProofEncryption` stay
  unimplemented, because this service issues bearer tokens.
* **`STS-WSTRUST-0012` and `STS-WSTRUST-0013` are retired.** They named
  the query parameter. A fault response is not encrypted.

To encrypt the issued SAML 2.0 assertion, set `wstrustEncryptResponse`
to `true` and add this as one value of
`wstrustEncryptResponseElements`:

```
//*[local-name()='Assertion' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']
```

Callers that looked for `EncryptedAssertion` find `EncryptedData`.

Nothing already stored has to be migrated, and there is no upgrade-script
step. Both switches default to off, so a deployment that never sent
`?encrypt=1` is unchanged. A caller that did has to set the application
as above. The query parameter no longer encrypts the assertion.

### New: an application's own WS-Trust decryption key pair

An application may now hold a decryption key pair of its own, so a request
for it is encrypted to its certificate rather than to the realm's XML
Encryption certificate (#1668). On the application's **Credentials** tab,
**WS-Trust decryption key pair**, and through three new management API
operations:

* **Issue** one from the realm's certificate authority
  (`POST /admin-api/applications/issue-wstrust-decryption-key`): the
  `key-encipherment` profile, `rsa-3072` or `ec-p256`, subject
  `CN=<application>-encrypt` with the realm's organisation.
* **Upload** a PEM certificate and its unencrypted private key
  (`upload-wstrust-decryption-key`). The key must be the certificate's, RSA
  of 2048 bits or more or EC on P-256, P-384 or P-521; each refusal has its
  code, `STS-ADMIN-0946` to `0950`.
* **Remove** it (`remove-wstrust-decryption-key`).

The private key is sealed where keys persist and is never shown, answered
or logged. The certificate is on the page, with a download, and in
`credentials.wstrustDecryption` of `GET /admin-api/applications?application=`.
The WSDL does not name it: configure the client out of band.

A request is opened with the key its `EncryptedKey` names, so a request
whose `AppliesTo` is inside the ciphertext still opens. Ciphertext opened
with an application's key in another application's request is
`wsse:FailedCheck` (`STS-WSTRUST-0082`), and a request for an application
with its own key encrypted to the realm's key is `STS-WSTRUST-0083`. An
application without one is unchanged. Four new directory attributes carry
it (`wstrustDecryptionCertificate`, `wstrustDecryptionCertificateChain`,
`wstrustDecryptionPrivateKey`, `wstrustDecryptionKeySource`); nothing
existing has to be migrated, and there is no upgrade-script step.

## 1.0.0

1.0.0 is the first release of iya-sts. Every build before it was a
pre-release.

### SAML service provider metadata written through the API is read

Writing an application's `samlSpMetadata` through `POST /admin-api/applications/set`
or `add`, or through the console's field grid, now reads the document the way
creating the application or uploading the document always has: its assertion
consumer services, their bindings and its certificates are registered. Until
1.1.0 those doors stored the text and registered nothing, so a SAML 1.1 relying
party updated that way was answered with the Browser/POST profile at a consumer
its metadata declares for Browser/Artifact.

A document that does not describe the application is now refused with HTTP 400
and nothing is written, as the create and upload doors already refuse it
(`STS-ADMIN-0935`). Writing an empty value still clears it.

### An inbound OpenID Connect ID Token's `iat` is held to the sign-in

A federation relationship that signs people in from an OpenID Connect partner
now refuses an ID Token whose `iat` is before the sign-in started or after now,
each end widened by `oauth2.clockSkewS` (OpenID Connect Core 3.1.3.7, step 10;
`STS-FED-0253`). Nothing is redeemed and UserInfo is not asked after the
refusal. Until 1.1.0 any `iat` was accepted, so an ID Token issued a week
earlier signed a person in. This applies to every relationship, not only the
FAPI profiles. A partner whose clock is behind this service's by more than the
skew is now refused; raise `oauth2.clockSkewS` for it.

### Not backwards compatible with earlier builds

**1.0.0 is not backwards compatible with the pre-release builds that came
before it.** Moving an existing deployment from a pre-release build to 1.0.0
works in many situations, but there are edge cases with no clean upgrade path.
Stored settings, directory entries, persisted data or client configurations
created by an earlier build may need to be recreated rather than carried
forward.

This is deliberate. The earlier builds were pre-release versions, and we are
not attempting to keep 1.0.0 compatible with them.

**If this causes you trouble, open an issue** on the GitHub repository:
[github.com/rcbj/iya-sts/issues](https://github.com/rcbj/iya-sts/issues). Say
which build you are moving from and what did not carry over.

### Backwards compatibility from here on

**Our goal is backwards compatibility going forward.** Releases after 1.0.0
are intended to upgrade cleanly from 1.0.0 and from each other. The steps
from a running 1.0.0 deployment to 1.1.0 are in
[1.1.0](#110) above. Where a later release cannot upgrade cleanly, its
notes on this page will say so and describe the path.

### Version numbers

A build reports its version as `M.N.O.<build>`. `M.N.O` is the release, and
for 1.0.0 the release build is `1.0.0.0`. Other builds of the same code carry
the UTC time they were built as their build number. After 1.0.0, each change
published from `main` is the next patch release (1.0.1, 1.0.2, …), and a new
minor or major release starts when the repository's `VERSION` file is set to
it. **A release that needs an upgrade script is a minor (or major) release,
never a patch**: going from one patch release to the next never asks you to
run anything against your database. That is why the release after 1.0.0 is
1.1.0. The running service shows its version on the admin console and in its
metadata.

**Release candidates.** Before a release is published, its candidate may be:
`iyasec/iya-sts:1.1.0-candidate` and `iyasec/iya-sts-xacml-pep:1.1.0-candidate`
(also on `ghcr.io/rcbj`), each beside its full `1.1.0.<build>` tag. A candidate
is for testing. It reports its version as `1.1.0.<build>` like any other build,
and it is not the release: `:1.1.0` and `:latest` are published only by the
release itself. A newer candidate replaces the `-candidate` tag.
