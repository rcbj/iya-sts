---
title: Admin console
---

# Admin console

`GET /admin` is an operator's view of the running service. The pages under it
exist for something the protocol endpoints cannot do: the interesting behaviour
of a client is what it does when something changes *underneath* it. A client
that gets a good token and reads it correctly has been tested against the easy
half. What it does when the token it holds stops being valid, or when the token
it reads grows a claim it was not expecting, is the other half, and the console
is how you cause either without editing this service and restarting it.

**Every page also answers `?format=json`, and every form also accepts a JSON
body**, because a console reachable only by clicking is one no test can assert
against. The [management API](management-api.md) at `/admin-api` is the same
console for a machine: every control has an operation there.

This page covers who may use the console, how it is laid out, and the pages
whose behaviour needs explaining. Pages that belong to one protocol are
documented on that protocol's page — the table on the [Overview](index.md)
maps each **Protocols** page to its documentation — and the application
registry has a page of its own, [Applications](applications.md).

## Who may use the console

**Every page and every form under `/admin` needs a sign-in and one of two
roles**:

* **Admin Read** may look at every page and change nothing.
* **Admin Write** may post every form. **Write implies read**, because a role
  that could change a page it was not allowed to see would be a trap rather
  than a permission.

The console is an **OpenID Connect relying party** of this service's own
authorization server, as the user portal is: an unauthenticated request is sent
to `/oauth2/authorize` as the seeded client `sts-admin-console`, the person signs
in at the sign-in screen, and the code comes back to `/admin/callback`. The
console session is tied to the sign-on session it came from and ends with it;
**Sign out** ends both. See [Sessions](sessions.md) and
[Signing out](signing-out.md).

**There is no setting that turns the gate off.** What `global.mode` changes is
whether the password typed at the sign-in screen is *checked*:

* **In development mode** no password is checked, so the gate is a turnstile
  and not a lock: it proves that somebody *typed* a name that holds a role.
  What it buys is what a test service is for — a client, or a person, can be
  driven through a 302 to a sign-in screen, a 401 with no session, a 403 with
  the wrong role, and a role model that can be granted and revoked.
* **In product mode** the password is verified, and the console is the
  administrative surface of a deployed identity service.

### The roles are two directory groups

The two roles are **two ordinary groups in the embedded directory** —
`admin.readGroup` and `admin.writeGroup`, `cn=admin-read` and `cn=admin-write`
by default — not a store of the console's own. So there are **four doors onto
one membership**, and a grant made through any of them is visible through all
of them:

* the **Admin roles** page, `/admin/rbac`;
* `POST /admin-api/rbac/grant` (and `revoke`);
* an `ldapmodify` on 389 or 636 — in product mode bound as somebody who
  already holds Admin Write (see `ldap.selfWritableAttributes` on
  [LDAP](ldap.md));
* a SCIM `PATCH` of the group.

A role no test can grant is a role no test can exercise.

**Each trust realm has administrators of its own, confined to it.** The
console asks the roster of the realm a person signed in through; the default
realm's roster is the service roster over every realm. A realm's own
administrators cannot reach anything about the process as a whole.
[Trust realms](trust-realms.md) covers it.

### The bootstrap administrator

At startup the service makes **`admin`** (`admin.bootstrapUsername`) in the
default realm if it is absent, puts it in both role groups, and marks a newly
created account `pwdReset: TRUE`, so its first sign-in asks for a new password
before anything else. In development any password gets it to that screen; in
product mode its password is `admin.bootstrapPassword`, or one generated and
written to the log once. It cannot be deleted or renamed through the console,
`/admin-api`, SCIM or LDAP. Taking `admin` out of the role groups is still
possible, and is on you.

**In development mode, until `admin` first signs in to `/admin`, anybody who
signs in holds both roles**, and every page says so in a banner. Its first
console sign-in ends that window for everybody who holds no role, which is why
the screen tells you to grant yourself a role first if you will need the
console afterwards. `admin.openWhenEmpty` turns the window off. Where no
bootstrap administrator was seeded, the console is open while *neither* group
has a member. A deployment whose roster already had members when `admin` was
first seeded has the window closed at once.

**Product mode never opens that window**, whatever `admin.openWhenEmpty` says —
only the roster decides, and at first the roster is `admin` alone. Until
`admin` has claimed the console, its roles are honoured only from a
**password** sign-in through its own realm, and only that sign-in claims it:

* a federation partner asserting `admin`, a certificate whose CN is `admin`, a
  wallet or a Kerberos ticket holds nothing (`bootstrap_password_required`,
  `STS-ADMIN-0796`);
* anybody else is refused until granted a role (`STS-ADMIN-0797`);
* the embedded debugger waits for the claim (`STS-DBG-0033`);
* a realm with no bootstrap administrator and an empty roster is closed and
  logged at startup (`STS-ADMIN-0798`) — `POST /admin-api/rbac/grant` with an
  `admin:write` token is the way in.

### What the roles grant, and what they do not

**What the two groups grant is the admin console** (and the embedded debugger).
They appear on `/admin/groups` like any other group, deliberately: a membership
store the console kept for itself could not be seen by an `ldapmodify` and
would drift from the directory with nothing comparing the two. Outside `/admin`
they grant nothing: no token's scopes change, no assertion gains an attribute,
no Kerberos PAC is affected, and a member of `admin-write` gets the same answer
from `/oauth2/token` as anybody else. `groups.claim` carries `admin-write` into a
token exactly as it carries `developers`, and nothing reads it there.

### The management API is gated separately

`/admin-api` requires an OAuth 2.0 access token, not a console session, so it
is the way back in when nobody holding a role can sign in: the screen that
grants a role is behind the gate that role opens, and
`POST /admin-api/rbac/grant` with an `admin:write` token is not. See
[Management API](management-api.md), including what `adminApi.authRequired`
does in each mode.

**Do not put a development-mode instance on a public address.** No password is
checked there, so anybody who can reach the port can sign in as anybody,
including an administrator, and the console can revoke tokens, add claims to
every future token and assertion, and create people in the directory.

## How the console is laid out

### The navigation

The navigation is a grouped list down the left. Its five sections:

* **Overview** — `/admin`, the one page whose job is to point at the others.
  It is a section of one on purpose: it cannot sit under a heading naming a
  kind of content.
* **Protocols** — a page, or a group of pages, per protocol family: OAuth2 /
  OIDC (settings, authorization servers, token lifetimes, custom claims,
  UserInfo claims), SAML, Verifiable Credentials, XACML, SCIM, Shared Signals,
  CAEP and RISC, Federation, OpenID Federation, GNAP, the second factors,
  Kerberos, LDAP, WS-Trust, WS-Federation, PKI, certificate issuance (ACME,
  EST, SCEP and SPIFFE) and TLS. [Overview](index.md#protocols-by-the-admin-consoles-protocols-menu)
  maps each to its documentation.
* **Directory** — users, groups, roles, applications, policies, and *As the
  directory holds it*: the raw entries under each container and the directory
  service itself.
* **Monitoring** — metrics, sessions, tokens, used assertions, delegation,
  the Shared Signals monitors, consent, XACML decisions, GNAP grants, the
  enrollment monitors, OAuth activity, SCIM metrics, sign-out, the database,
  encryption, the secret store, caches, the scheduler, the mail outbox, risk,
  the audit log and the error codes.
* **Server configuration** — trust realms, configuration, mode, persistence,
  cluster, mail, admin roles, the protocol debugger, the service metadata, the
  API explorer, key pairs and cryptography.

A console page is filed by the question it answers, which is why the three
Monitoring pages that describe what the service did — how much
(`/admin/metrics`), what came out (`/admin/tokens`), and what happened in order
(`/admin/audit`) — sit together.

### The breadcrumb trail

Every page carries one line under the navigation — `Admin console ›
Applications › rfc9700-debugger` — including `/admin` itself, where it is the
single crumb. The navigation answers *what else is there*; the trail answers
*where am I and how do I get back*.

* On a drill-down, the section's own tab is a link too — still bold because
  you are inside that section, and underlined so it cannot be read as
  unclickable.
* **The last crumb is never a link**: it is the page being drawn.
* A long last crumb is cut to 44 characters with the whole of it in the
  tooltip, because a `did:jwk` is hundreds of characters with nowhere to break.
* The trail has no crumb for a section, because a section has no page of its
  own and a crumb that could not be a link would be a dead one.

**The trail goes back to the list *as you left it*.** A drill-down link is
built with the filter and page you were looking at —
`?q=client&per=25&page=3&application=beta` — and the trail's section crumb
spends exactly that, so *back* lands on page 3 of that filter.

* Which parameters belong to a list is a **whitelist per section**, because
  what comes out of it goes into a URL this service hands to a browser.
* Every control on a drill-down carries the whole current query, so paging the
  tables on a user's page keeps it.
* The *rows per table* form carries the filter as hidden inputs, but **not**
  the list's page, since changing `per` changes what page 4 means.
* Every form on the application and authorization-server drill-downs carries
  the list as one opaque `back` field, which the handler **rebuilds** through
  the same whitelist rather than echoing. A redirect target taken from a
  request body would be an open redirect, and one carrying a newline a header
  injection; the worst a hand-written `back` can reach is another page of the
  same list.
* Four views take a trail leaf — the four that drill in: `?user=`, `?group=`,
  `?application=` and `?profile=`. A parameter that only *filters* a list does
  not; the filter has its own **clear** link.
* `?format=json` ignores all of it: a caller has the URL it asked for.

### Paging

Lists are **filtered and then paged**, with `?page=` and `?per=` — in that
order, because paging and then filtering gives a page 2 whose length depends on
page 1. `?per=` is capped, so a typed `?per=5000` cannot draw the page the cap
exists to prevent.

* **An out-of-range page is clamped to the last one** rather than answered with
  an empty table — a revocation can shorten the list between two clicks, and an
  empty table would read as "nothing matched".
* **A filter form carries no page number**, so changing a filter or the page
  size returns to page 1.
* **Every button acts on an identifier, never a row number**, so a row issued
  or revoked between the render and the click cannot make the wrong one the
  target.
* A `?format=json` reply carries `page`, `pages` and `matched`, so a test can
  walk the whole list.

**A drill-down with several lists pages each separately.** `?user=` answers
with five lists and `?group=` with two, so each list has a page parameter
**named after the array it moves** — `sessionsPage`,
`tokensOnEndedSessionsPage`, `tokensWithNoSessionPage`, `artifactsPage`,
`membersPage`, `claimedPage` — while `?per=` stays shared, because *rows per
table* is one choice for a page. Moving one list leaves the others where they
were. A session's own token table is moved by `session-<session id>Page`,
named after the session rather than numbered, so the link still moves the same
session after the list around it has changed. Session blocks start at five per
page, because each is itself a table.

Three lists on those pages are deliberately **not** paged: the spellings an
identity has been seen under, the protocols it authenticated through, and its
authentication events. The first two are bounded by how many exist, the third
is capped at fifty, and all three are on the `user` object that goes out whole
in the JSON reply.

**The management API pages the same way.** `GET /admin-api/users` and
`GET /admin-api/groups` take the same parameters and reply with a
`<name>Paging` object beside each array — `sessionsPaging`, `membersPaging`, and
so on — carrying `page`, `pages`, `perPage`, `firstRow`, `lastRow` and `total`.
Each session carries its own `tokensPaging`. The counts around them stay counts
of the whole list: a group's `memberCount`, `presentCount` and `danglingCount`.
The `session-<id>Page` parameter is described in the operation's prose rather
than listed, because OpenAPI has no way to spell a query parameter whose name
is built at runtime.

**Nothing in the console runs a script** (`script-src 'none'`). Paging is
links and query parameters; the diagrams are drawn on the server. The one
exception is the [API explorer](management-api.md#the-explorer).

## Directory

### Users — `/admin/users`

**`/admin/users` answers *who has this service seen, and what do they hold
right now?*** It lists every userid presented in an interaction that
**succeeded**:

* the name typed at the sign-in screen, or on a password grant;
* the subject of a WS-Security `UsernameToken` or a WS-Trust `OnBehalfOf`;
* the client principal in a Kerberos AS-REQ, or in an AP-REQ this service
  accepted (over a raw socket or through SPNEGO);
* the subject of an exchanged token.

A request that was *refused* records nothing, so this is a list of identities
that got somewhere, not of names that were tried. Applications are never listed
here — they are on [Applications](applications.md).

`?user=<name>` drills into one: the names they were seen under, every
authentication with the method that performed it, each sign-on session they
hold **with the tokens issued on that session underneath it**, the tokens that
belong to no session, and the assertions, tickets and credentials issued to
them. A **revoke-user** button invalidates everything revocable for that
identity under any of its spellings. The list has *Valid*, *Expired* and
*Revoked* columns, and the drill-down a matching tile, because "12 issued, 1
valid" does not say what the other eleven are.

**What one row is.** One person reaches this service as `alice` at the
sign-in screen, `urn:uuid:<entryUUID>` in every token, `alice` as a SAML
`NameID` and `alice@EXAMPLE.COM` as a Kerberos principal. The row is keyed on
the **local name**: a `urn:uuid:` subject is resolved through the directory to
the entry's current name (so a rename does not split one person into two rows),
the older `urn:sts:user:` prefix is still read and stripped, and the realm is
split off at the last `@`. The cost is shown rather than hidden: two different
people called `alice` in two Kerberos realms are one row, which the Realms
column makes visible. Case is never collapsed.

**The list is built from three sources**: the authentications recorded, every
token's `sub`/`username`, and every artifact's subject. An identity can be
issued something without ever authenticating here — a token exchange presents
somebody else's token, a WS-Trust `OnBehalfOf` names a delegated subject, an
anonymous RST issues an assertion for `anonymous`, and a Kerberos S4U2Self ticket
is for a user who was never near this KDC. Such a row is listed and **marked
as never authenticated**. The methods column is honest in the same way: in
development "sign-in screen (password)" checked nothing, while "AS-REQ with
PA-ENC-TIMESTAMP" did, and an S4U row says the user was not there and names the
service that asked in their stead.

**Putting a token under a session uses nothing on the wire.** No token carries
a session identifier for the console's sake. The session is carried where it
genuinely exists: on the authorization code, through the token endpoint, and
through a **refresh**, which is looked up by the refresh token's own `jti` so
that later generations stay under their session. A grant that never had a
session — `password`, `client_credentials`, the pre-authorized code and token
exchange — is shown as issued with no browser session at all. Tokens naming a
session that has since ended get their own heading: the session expired and the
tokens it produced outlived it, which is the ordinary end state.

#### The person's directory entry

A person's page also shows their **LDAP object**. Every person who authenticates
anywhere here has an entry at `uid=<name>,ou=users,<base>` ([LDAP](ldap.md)),
and the two are the same authentication seen from two sides. What is shown is
the entry itself: its DN, where it came from (`seed` or `authentication`), its
two generalized-time stamps in the directory's own format, and **every
attribute with every value, the operational ones included**. `?format=json`
carries the same object under `ldap`.

Where there is no entry, the section says **which** of five reasons it is:
auto-creation is switched off; the identity is a *client*, not a person; it has
never authenticated here (it is only the subject of something issued);
everything it has done here is an *LDAP bind*, which presents a DN rather than a
user name; or the entry was deleted or renamed through the protocol. It also
lists any **other** entry outside `ou=users` whose `uid` names the same person,
and says so loudly when the directory's listener is down — the entry can be in
this process's store while no client can connect to read it. A build without
the directory says "no directory is loaded", which is a different answer from an
entry that is not there.

#### Changing a person's attributes

Under the entry, **Change their attributes** offers the three controls the
[Applications](applications.md) page has: **Set** replaces every value of an
attribute with one (an empty value removes it), **Add to** appends a value to
an attribute that holds several, and **Remove from** takes one value off. Each
writes that one attribute of the entry in place, as an `ldapmodify` would, and
needs **Admin Write**. `POST /admin-api/users/set-attribute`,
`/add-attribute` and `/remove-attribute` are the same three, and
`GET /admin-api/users?user=<name>` publishes the list under
`attributeEditor`, with what each attribute holds.

**What may be changed** is the person schema — `person`,
`organizationalPerson`, `inetOrgPerson` and the Identity Assurance claims —
and the credential catalogue, less what has a door of its own or is not text:

| Not offered | Use instead |
|---|---|
| `userPassword` | the password controls on the same page, or `POST /admin-api/users/set-password`, which hashes it |
| `mail` | **Set the address**, in the same section (`POST /admin-api/users/set-mail`), which marks the address verified and tells the former one |
| `uid`, and the attribute the entry's DN is named by | nothing: a rename is not an attribute edit |
| the certificates, photographs, `audio`, `userPKCS12` | an LDAP client: their values are binary |
| group memberships, credentials, what sign-ins record | Groups, the credential controls |

**What a value must look like.** `cn` and `sn` can never be emptied (RFC 4519
requires them of every person). An attribute its schema declares single-valued
— `displayName`, `employeeNumber`, `preferredLanguage`, `c`,
`schacDateOfBirth`, and this service's own employee status and place of birth
— is set, never added to. A country is an ISO 3166-1 alpha-2 code (stored
upper-case), a date of birth a real date (`YYYY-MM-DD` is accepted and stored
as `YYYYMMDD`), `preferredLanguage` a language range, `labeledURI` an http or
https URL with an optional label, and `manager`, `secretary` and `seeAlso` a
DN — checked for its shape only, since this directory keeps no referential
integrity. No value may hold a line break or exceed 1024 characters.

A change is reported to [Shared Signals](shared-signals.md) as a SCIM or LDAP
write of the same attribute is. An identity verification covers a value only
while the entry still holds it, so changing a verified value lets that
verification lapse for it.

#### Creating a person — `/admin/users/new`

The list page has one control: a name, and a button to **`/admin/users/new`**,
where the person is described. It is a box for every attribute a person here
can carry — the same catalogue *Credential claims* chooses from, so a value typed
here is the value an issued credential asserts. **Only the username is
required, and an empty box records no value.**

**Fill with example data** writes what this service would invent into the
boxes you left empty, touching nothing you filled in and creating nobody. It is
development-mode only, and computed on the server. Leaving a field empty is not
a promise it stays empty: **Populate** on *Credential claims* fills every
missing selected attribute on every person.

**It is also where somebody is given a way in.** Four choices:

* **a password generated and shown once** — the default, here and on
  `POST /admin-api/users/create` when `credential` is not sent, drawn from the
  system's cryptographic random generator until it satisfies this realm's
  password policy;
* a password you type, held to that policy in product mode;
* no credential at all (enough in development mode, and what
  `credential: none` asks for);
* **no credential and a single-use, time-limited activation link, shown once**,
  at which the person chooses a password, a security key or both at
  `/portal/activate`.

A generated password or link is shown in the body of the page that comes back,
never in a redirect, because a secret in a URL is a secret in the browser's
history and every proxy log. Issuing another activation link invalidates the
first, which is also how a lost one is replaced.

**The catalogue is not the whole schema.** It is the twenty-seven claim-bearing
attributes *Credential claims* chooses from; `inetOrgPerson` allows fifty. So
`departmentNumber`, `roomNumber`, `manager`, `carLicense` and the rest reach an
entry over **SCIM** or **LDAP**. All fifty are drawn on the person's own
`/portal` Overview, with the LDAP name and RFC under each.

**A username that is already there is refused**, naming the entry that holds
it — the same refusal an `ldapadd` gets (`LDAP_ENTRY_ALREADY_EXISTS`, 68),
because both call one function. `POST /admin-api/users/create` takes the same
attributes, and `GET /admin-api/users/new` publishes the catalogue it validates
them against. **The new person does not appear in the users list** until they
authenticate somewhere: that list is who this service has *seen*, and the entry
is what the directory *holds*.

#### Password and second factors

A person's page has a *Password and second factors* section, drawn for a holder
of Admin Write. Each control is an action on `POST /admin/users` and on
`POST /admin-api/users/{action}`:

* **Disable the account** / **Enable the account** writes the password-policy
  lock `pwdAccountLockedTime` on the entry, reported as *Account: DISABLED*.
  While it is set **every door refuses that person**: a password anywhere (the
  sign-in screen, an LDAP bind, the OAuth password grant, a WS-Trust
  UsernameToken, SCIM and SSF Basic, EST), a session from any sign-in (a
  security key, federation, SPNEGO, a client certificate, a wallet), a Kerberos
  AS-REQ (`KDC_ERR_CLIENT_REVOKED`), every token grant made on their behalf
  including a refresh, every assertion, and the management API. Disabling also
  **ends everything they hold**, as a global logout does: their sessions (with
  back-channel Logout Tokens to their relying parties and CAEP
  `session-revoked`), tokens, outstanding codes, directory connections and
  Kerberos tickets; RISC receivers are told `account-disabled`. **SCIM's
  `active: false` is the same act**, and `active: true` the enable.
* **Reset password** generates a password this realm's policy accepts, stores
  it, marks it for change at the next sign-in (`pwdReset`), withdraws any reset
  link, signs the person out everywhere, and shows the password **once**.
* **Send a reset link** removes the current password (into the history, so it
  cannot be set again), signs the person out everywhere, and shows a single-use
  link to `/portal/reset-password` once. It lasts
  `security.passwordResetTtlMinutes`; issuing another replaces it. With **mail
  the link** ticked (`deliver: "mail"` on the API) it is mailed to the address
  on the person's entry and not shown to the administrator at all. A person may
  also ask for one at `/portal/forgot-password` ([Mail](mail.md)).
* **Disable passkeys** removes every security key that could sign the person
  in on its own, leaving their password and second factors. It is offered only
  while they have a password, so it cannot lock anybody out.
* **Disable all MFA** removes the authenticator app, every second-factor key and
  the recovery codes.
* **Require MFA** / **Stop requiring MFA** marks the person (`stsMfaRequired`),
  so the sign-in screen makes them enrol an authenticator app or a security key
  at `/authn/mfa-setup` before it starts a session. The authentication policy's
  `requireSecondFactor: always` does the same for everybody in the realm. In
  product mode either one also refuses the person's own password at the five
  password-only doors (LDAP bind, WS-Trust, SCIM, SSF and EST Basic), where an
  app password is used instead.
* **App passwords** lists the person's app passwords — name, id, the doors each
  is scoped to, when made and last used, never the password — with **Revoke**
  per row, and **Make an app password** generates one scoped to the doors
  ticked and shows it once. `POST /admin-api/users/create-app-password` and
  `revoke-app-password`, and `GET /admin-api/users/app-passwords` (paged), are
  the same acts. See [Authentication](authentication.md#the-password-only-doors-and-app-passwords).

Every one of them sends Shared Signals to the streams that asked: a CAEP
`credential-change` for each credential created, updated or removed, a RISC
`account-credential-change-required` for a reset and a reset link, RISC
`recovery-activated` for a reset link, RISC `credential-compromise` when the
reset is marked as caused by one, and RISC `recovery-information-changed` when
recovery codes go. The per-item **Clear** buttons and **Set password** send them
too, and so does completing a reset link. `caep.autoEmitTypes` and
`risc.autoEmitTypes` name these types by default. See
[CAEP events](caep-events.md).

### Policies — `/admin/policies`

**Directory → Policies** holds every kind of policy a realm has.
`GET /admin-api/policies` answers each as a member, and
`POST /admin-api/policies/{save,reset}-{password,authn}-policy` writes them.

**The password policy** is a minimum length (12), how many previous passwords
may not be reused (5), a minimum number of symbols (1), and whether an uppercase
letter and a number are required (both yes). It is the **default profile**,
stored as `cn=default,ou=passwordPolicies` in the realm's directory in the shape
of draft-behera-ldap-password-policy (`pwdMinLength`, `pwdInHistory`, with
`pwdHistory` and `pwdChangedTime` kept on each person), with the composition
rules as this service's own `stsPwd*` attributes. Until it is saved the built-in
defaults are in force. **It is enforced in product mode only**, at every door
that sets a password: the console, `/admin-api`, `/portal/password`,
`/portal/activate` and an LDAP add or modify of `userPassword`, which is hashed
on the way in. Development mode applies no rule and records the history anyway.
[LDAP](ldap.md#the-password-policy-is-a-directory-entry) has more.

**The authentication policy** (#64) is a separate policy on the same page:

* which mechanisms the realm accepts as a **first** factor — a password, a
  passkey, a TLS client certificate, a Kerberos ticket, a wallet, a federation
  partner, an emailed code, an emailed sign-in link;
* which it accepts as a **second** — a password after another factor, a
  security key, an authenticator app, a recovery code, a wallet, an emailed
  code or link;
* whether a second factor is required of everybody
  (`requireSecondFactor: always`) or of those who hold one (`if-held`).

It is `cn=default,ou=authnPolicies`. **A realm with none of its own follows the
default realm's**, and the built-in defaults apply where neither exists.

**The emailed code and the emailed sign-in link are off by default**, because
NIST SP 800-63B-4 section 3.1.3.1 says email SHALL NOT be used for out-of-band
authentication; the page says so beside them. Turned on, they are offered only
where the realm can send mail, and only to a person whose address is
**verified**. As a second factor a person opts in on `/portal/mfa`; as a first
factor the sign-in screen offers "Email me a sign-in code" and "Email me a
sign-in link" beside the password, and answers an unknown account with the same
page as a real one. A code is six digits, and a link is a single-use URL that
works only in the browser that asked for it; each is kept as a scrypt hash,
valid for at most ten minutes and spent once, and a person's emailed factor is
turned off after `emailFailureLimit` consecutive failures. An emailed factor is
`amr ["otp"]` and never satisfies a risk step-up.

**Which addresses are verified.** An address an administrator sets (the
console, `/admin-api/users/create` or `set-mail`), SCIM provisions, an
administrator writes over LDAP, or a federation partner sends (unless it says
`email_verified: false`) is verified as written. An address a *person*
provides is verified by following a link: on `/portal/email` the new address
stays pending until they do, and the old one is told when it changes. See
[Authentication](authentication.md) and [Mail](mail.md).

### Groups — `/admin/groups`

`/admin/groups` reports the *directory* rather than what this service has
issued. It lists every group with what it is made of, and `?group=<dn>` drills
into one: every attribute the entry holds, operational ones included, and every
member resolved to the entry it names.

**Two controls.** **Create a group** is below the list's table: it puts a
`groupOfNames` at `cn=<name>,ou=groups` and takes members one per line or
comma-separated, each a user name or any DN (a group can hold another group,
and no user name names one). **Add a member** is on the drill-down; a create
lands you on the group it just made. `POST /admin-api/groups/create` and
`POST /admin-api/groups/add-member` are the same acts.

Three behaviours are the directory being consistent with itself:

* **A member that names nothing is written, not refused.** This directory
  does no referential integrity, so refusing here would make the *dangling*
  state this page reports impossible to produce from it.
* **An empty group is allowed**, although RFC 4519 makes `member` MUST on a
  `groupOfNames`: SCIM already creates one, and the two doors should not
  disagree about what the directory holds.
* **Adding somebody already in the group changes nothing and is not an error**,
  so a script that adds on every run does not fail on its second.

Removing a member is an `ldapmodify`, a SCIM `PATCH`, or **Admin roles** for
the two role groups; deleting a group is an `ldapdelete` or a SCIM `DELETE`.

**What counts as a group is two rules.** An entry under `ou=groups`, *or* an
entry carrying a group `objectClass` (`groupOfNames`, `groupOfUniqueNames`,
`posixGroup`, `groupOfURLs`) wherever it sits. The directory is schemaless, so
either rule alone would lose one of those cases. The list says which rule caught
each row.

**Membership is read from `member`, `uniqueMember` and `memberUid` together.**
`memberUid` holds a bare user name where the other two hold a DN, so it is
resolved under `ou=users`. Three disagreements are reported rather than smoothed
over, and each is a state a client can reach in two operations:

* a **dangling** member — a value naming an entry this directory does not
  hold. Deleting a user does not remove its DN from the groups that list it,
  so the count of membership values and the count that resolve are shown
  separately: a group whose seven members resolve to five is not seven members
  with nothing wrong.
* a member that is itself a **group**. Nesting is shown and never expanded: the
  row links to that group's page and nobody inside it is counted, because
  nothing in this service walks a group tree.
* an entry whose own **`memberOf`** names a group that does not list it back.
  In directories that have `memberOf` the server keeps it in step with
  `member`; this one keeps nothing in step. Those entries are listed under their
  own heading.

**A member links to `/admin/users` only for somebody this service has seen
authenticate**, and is marked *never here* otherwise. The directory holds an
entry for whoever somebody wrote one for — including `alice`, `bob` and `carol`,
who are seeded in development — while the users page holds whoever has
presented a credential.

#### What a group grants

**A group grants nothing by being a group.** What a group grants is what a role
or a roster names it for: the two console roles (above), the XACML
`REMOTE_PEPS` and `XACML_USER` rosters ([XACML](xacml.md)), and a configured
role's group members (`/admin/roles`). Both pages say so where a reader will
see it.

**A token can carry a group, which is a different sentence.** With
`groups.claim` on — the default — every OAuth 2.0 access token, OIDC ID Token,
SAML 2.0 assertion and SAML 1.1 assertion carries a claim naming the groups its
subject is in, read from these entries when the token is minted. Carrying a
fact is not acting on it. No Kerberos PAC carries a group. It is worth carrying
because a groups claim is one of the few things a relying party actually
branches on, and a client that has never seen one — or has seen names where the
next identity provider will send DNs — has never run that code.

* **The claim is omitted for somebody in no group** — absent, not an empty
  array — so a caller who has never touched `ou=groups` gets the tokens it
  always got.
* **Membership is read per token and never cached**: an `ldapmodify` changes
  the very next token.
* **Both membership rules are read** — `member`, `uniqueMember` and
  `memberUid` from the group's side, and the person's own `memberOf`.
  `groups.claimFromMemberOf` (on by default) decides whether a `memberOf` a
  group does not return counts; either way the group must exist here, since a
  `memberOf` naming nothing must not invent a group. A group listing a DN that
  is not stored still counts from the group's side.
* **`groups.claimValue` chooses `cn` or the whole DN**, because an OIDC
  provider usually sends names and Active Directory sends DNs.

A typed custom claim and a ticked directory attribute of the same name both
**win over** it. `groups.claimName` naming something this service sets itself
(`exp`, `scope`, …) is **refused at issuance**, and `/admin/claims` says why.
In an assertion the claim is **one `<Attribute>` with several
`<AttributeValue>` children**; one element per group with the same name would
leave a relying party reading the first. The settings are on [LDAP](ldap.md).

### Applications — `/admin/applications`

The other side of `/admin/users`: every OAuth client, OpenID Connect relying
party, SAML service provider, WS-Federation application, WS-Trust relying
party, OpenID4VP verifier and Kerberos service, one entry per identifier. It is
a **registry** that lives in the directory, so an `ldapmodify` there changes
what the protocol endpoints do. It carries forms to create an application before
it connects and to change what it is *allowed* to do — never its counters or
sightings. [Applications](applications.md) documents the page,
`/admin/applications/new`, the schema and CORS.

## Monitoring

### Metrics — `/admin/metrics`

`/admin/metrics` counts endpoint calls by the **route Express matched** — the
pattern `/oauth2/register/:client_id`, not the URL, or every registered client
would get a row — with the status classes, the average and worst latency, and
when each was last called. Then every token by `typ`, with how many are valid,
expired, revoked, not yet valid and DPoP-bound, and every assertion, ticket
and credential the same way.

All of it is computed **when the page is drawn**, not kept up to date as things
happen. "Valid" and "expired" are functions of the clock, so a counter
incremented at issuance would be wrong a second later.

**Sessions are reported twice, and the two numbers disagree on purpose.** A
*sign-on session* is real: a browser holding a session cookie
([Sessions](sessions.md)). An *artifact-derived session* is an inference, and
the page states its definition: a subject has one in a protocol family when
that family has issued it at least one artifact that is still valid. A
`client_credentials` token is the second and not the first (no person, no
browser); a browser that signed in but was issued nothing is the first and not
the second; a Kerberos client is never the first. Within Kerberos a **TGT
counts as the session and a service ticket does not** — the TGT is the
credential the session consists of, and a service ticket is one use of it.

### Tokens — `/admin/tokens`

`/admin/tokens` lists what was issued and invalidates what can be. It lists
**every JWT, SAML assertion, Kerberos ticket and SPIFFE SVID, in one table,
newest first** — assertions whether WS-Trust or a WS-Federation sign-in issued
them. One table rather than four, because a WS-Federation sign-in that produces
an ID Token and a SAML 1.1 assertion is *one event*. A filter for the family
sits beside the one for the kind, and the kind list is grouped by family and
built from the same structure, so the two cannot disagree. Expiry is normalised
to milliseconds, so one table can sort a JWT's `exp` (seconds) beside an
artifact's expiry.

**A row is one issuance, not one credential.** Redeeming an authorization code
returns an access token, a refresh token and an ID Token in one reply;
`response_type=id_token token` returns two in one fragment. OAuth 2.0 and OIDC
are the only families that do this, so every other row is a *set of one*.

* The grouping comes from an identifier the **issuer** stated when it built
  the reply — never from two rows sitting close together in time, which could
  merge two people's replies. The identifier is in no token and is not a claim.
* **A set is one response, not one grant.** A refresh makes a new set beside
  the old one; the refresh lineage joining the generations is drawn on each
  credential's own page.
* **State** reads `mixed` when members disagree (an access token and its
  refresh token have very different lifetimes); **Expires** shows the first
  member to go and the last; **Detail** is the access token's scope.
* A filter matches a set when *any* member matches, and the neighbours come
  with it.
* `/admin/tokens/set` opens a reply, member by member, with each credential's
  own identifier, expiry and button. **Revoke set** revokes every revocable
  member in one act, into the same revocation set `/oauth2/revoke` writes to, so
  nobody revokes two credentials of three and leaves a refresh token able to
  mint another. A set holding nothing revocable is refused rather than
  answered "revoked 0".

**Only the JWTs have a button, and the rows without one are the reason to list
them.** Nothing consults this service about a SAML assertion or a Kerberos
ticket: an assertion is valid because its signature verifies and its
`Conditions` hold, and a ticket because the service it names can decrypt it. A
SPIFFE SVID has no revocation either — the answer there is a short lifetime and
rotation. The only thing that ends one is its own expiry, and this page is where
you see when that is. Each such row carries the reason in place of a button.

Because a column can mean slightly different things per family — `Detail` is a
scope, or whether an assertion was signed, or a ticket's enc-type — the page
carries **a legend**. A Kerberos ticket has **no identifier** to put in the
`jti` column: none exists for anyone to quote. **OpenID4VCI credentials are not
in the table**, only counted on the metrics page; that is a gap, and the page
says so.

**Invalidation** is one `jti`, a whole kind, everything for one subject, or
everything. **It is the same revocation `/oauth2/revoke` performs**: there is
one set of revoked jtis in the service. A token revoked here is reported
inactive by introspection, refused by UserInfo with `invalid_token`, and fails
the refresh grant with `invalid_grant`, immediately.

**A revoke or restore button returns to the page and filter it was clicked
on**, carried as a hidden `back` field and rebuilt rather than echoed. Only
`family`, `kind`, `state`, `per` and `page` survive the rebuild, each
re-encoded — plus, on the users branch, any parameter whose name *ends in*
`Page` and whose value parses as a positive integer (the session blocks' page
parameters are named after the session, so their names are data). The bulk
buttons keep the filter and drop the page. In the JSON reply, the rows are in
**`issued`**, each naming its `family`.

Three further details:

* **It keeps the claims, never the credential** — not the signed token, the
  assertion XML or the ticket. A page rendering a thousand live credentials
  would leak them, and the `jti` is all a button needs.
* **Pasting a whole token works, and its signature is not verified.** The only
  thing read out of it is the `jti`, which is looked up in this service's own
  registry; a forged token yields a jti never issued, and revoking it
  invalidates nothing. RFC 7009's endpoint *does* verify, because there the
  token is a credential being presented.
* **Restore is offered and labelled NON-SPEC.** No authorization server can
  undo a revocation, since a resource server may have cached the refusal; the
  button exists so a test can get back to a working token without a restart
  (which in development mode also loses the signing key).

### Delegation — `/admin/delegation`

`/admin/delegation` answers *who acted on whose behalf, through what, to reach
what.* Three protocol families here can delegate, and each names it
differently: Kerberos has S4U2Self, two flavours of S4U2Proxy and a forwarded
TGT; WS-Trust has `OnBehalfOf` and `ActAs`; OAuth 2.0 Token Exchange has
impersonation and delegation. All eight are recorded against **one model**,
because the question is protocol-independent: *alice never touched the back end,
so why is there a ticket to it in her name, and who asked for it?*

Every act names three **layers**: the *initial identity* the credential is
about, the *intermediary* acting on their behalf, and the *target* being
reached. A layer can be a person, an application, or both — the middle one
routinely is: `HTTP/frontend.example.com` has an entry under `ou=users`
because it authenticates, and one under `ou=applications` because tickets are
issued for it, and the page links to whichever exist. An application marked
*not in the registry* is not an error: an RFC 8693 `audience` nobody has
otherwise mentioned is exactly that.

**Impersonation versus delegation is the axis to read first.** Under a
delegation the credential CARRIES the chain — an `act` claim, a composite
`ActAs`, `S4U_DELEGATION_INFO` in the PAC — so the far end can see who is really
asking. Under an impersonation nothing does, so **this page is the only place
that fact is visible**: nothing in the token, at the resource server or in a
log can recover that a middle tier was involved.

**Refusals are recorded, and are most of what it is for.** A refused
delegation names the two accounts, the attributes and which was missing, at the
moment the decision was made, with the same text the client was sent. It
appears in no other list here, because nothing was accepted.

**The policy tables are configuration rather than history** — *who MAY
delegate to whom*:

* **Kerberos**: `msDS-AllowedToDelegateTo` on the front-end account and
  `msDS-AllowedToActOnBehalfOfOtherIdentity` on the back-end account, with
  `NOT_DELEGATED` and `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` beside them. It
  answers *why would this be refused* before anybody has tried — including a
  front end allowed to delegate but not trusted for protocol transition, whose
  S4U2Self ticket is not forwardable, so S4U2Proxy fails complaining about the
  evidence, two steps from the attribute that caused it.
* **WS-Trust and RFC 8693** (#108): the same model on application entries —
  `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf`,
  `appDelegationSubjectGroup`, `appTrustedToImpersonate` — with people carrying
  `stsNotDelegated` or `stsMayAct`. Enforced in product mode and recorded in
  development; `may_act` is read in every mode. Also
  `GET /admin-api/delegation/policy`, paged. See
  [What is not checked](what-is-not-checked.md#delegation-is-decided-in-all-three-families).

Every act says in its own column whether it was policed.

**Every table on `/admin/delegation` is paged at ten rows** and they share one
`?per=`. Each has a page parameter of its own (`?page=`, `?chainsPage=`,
`?permissionsPage=`, `?grantsPage=`, `?pairsPage=`, `?flagsPage=`,
`?mechanismsPage=`), so moving one leaves the others. `?format=json` still
carries every list whole, with `allowed.filter` and `allowed.paging` reporting
what the browser was shown.

The data is also at `GET /admin-api/delegation`, with the acts, the distinct
*chains* among them (one per edge of the picture) and the policy. Acts are
capped by `delegation.maxRecords`.

#### The pictures

**`/admin/delegation/map`** draws the acts as a diagram, generated on the
server. It has **two bands**: the parties on one plane, in chain order, and this
service in a band of its own above them, with its lines dropping onto whoever it
issued to.

* Every party is on one centreline. A line between **neighbours** lies along
  it; anything else **arcs under it** in a lane of its own.
* A **stick figure** is a party with an entry under `ou=users`, a **rectangle**
  one under `ou=applications`, a **rectangle with a figure inside** a party that
  is both, and a **hexagon** this service, labelled with the trust realm.
* *Acts for* is the delegation relationship — amber for an impersonation,
  green for a delegation. *Reaches* is what the credential was FOR: its
  audience. A dashed grey line from the hexagon is this service having issued
  to whoever asked. A **broken** line jumps a party nobody named — a forwarded
  TGT. **Red** is a chain nothing was ever issued on. A party neither store
  knows is drawn dashed. A party that reached *itself* (S4U2Self) is marked on
  the box.

Under the picture is the same thing in words — every party with its links,
every relationship as a row, and **every credential that came out** (kind and
identifier only, never the credential). It takes the table's five filters and is
drawn from everything that matched, not one page. `?format=json` is the whole
graph (also the `graph` member of `GET /admin-api/delegation`) and `?format=svg`
the document on its own.

**`/admin/delegation/chain`** draws one relationship on its own, linked from
every row. It carries the chain's key rather than a row number, so a link in a
ticket keeps describing the same relationship; a chain whose acts have all
aged out says so rather than answering 404.

**`/admin/delegation/application`** asks *what has been issued because of this
application*: every act it took part in **in any role**, the picture of every
relationship it is in, and every delegated credential that came out, each with
the role the application had. A middle tier is the *intermediary* of chains it
acts on and the *target* of ones that reach it, and offering only what was
issued FOR it would hide what was issued THROUGH it. The chooser is a **search
box over a scrolling pane of at most twenty matches**, searching every spelling
an act presented.

**`/admin/delegation/user`** is drawn from more than the delegation register:
*what has this service done in one person's name, end to end.* Most of that is
not delegation — an authorization code grant, an AS-REQ or a SAML assertion is
not an act — so it draws **every credential ever issued naming them** (JWT,
SAML assertion, Kerberos ticket, SVID, verifiable credential) as a line to the
application holding it, **labelled with the grant or flow that produced it**
and the section that defines it (`authorization_code` beside RFC 6749 §4.1,
`refresh_token` beside §6, `client_credentials`, the password grant, implicit
and hybrid responses, OpenID4VCI's pre-authorized code, RFC 8693 token
exchange). The same person search accepts any spelling — `alice`,
`alice@STS.MOCK` and `urn:sts:user:alice` find one person.

* A **dotted** line into the hexagon is them signing in, one per protocol
  family with the method on it.
* **A solid line out of an application is what its credential is addressed
  to**: an access token issued to a web front end with
  `aud: https://apigw1.example.com` draws a line to the API gateway, labelled
  with the grant. The audience is looked up in the registry by registered
  audience and then by `client_id`, so `https://apigw1.example.com` and the
  bare `apigw1` a scope produces land on one box; the string the token carries
  is in the tooltip. Several audiences draw several lines; an audience that is
  this service's own (a refresh token, or the `<base>/resource` stand-in) draws
  none.
* **That line says what the token may do at the far end**: the delegated
  permissions on its `scope` claim, or `default permissions`. It reports what
  was ISSUED, not what was granted — with enforcement off a token can carry a
  permission its client was never granted.
* An RFC 8693 exchange writes a row in both registers for one credential, so it
  is drawn once, on its delegation line, and the number left off is printed. A
  Kerberos S4U ticket has no identifier to collapse the two on, and the page
  says so.
* The chooser offers the identity register **unioned** with the delegation one,
  so it offers people nothing was issued to: an S4U2Self or an `OnBehalfOf`
  names somebody who was never present, which is the row worth opening.

`/admin/users` links to it; that page is the ledger, where a token is revoked,
and this one is the relationships. All the delegation pages answer
`?format=json` and `?format=svg`, and link back to the table carrying whatever
filter you left it with.

**None of them runs a script.** The layout is computed on the server with
[`@dagrejs/dagre`](https://github.com/dagrejs/dagre) and every shape is this
service's own, so the console stays `script-src 'none'`. The cost is that a
picture does not pan, zoom or drag: the filter is how a busy one is made
readable, and `?format=svg` is how it is opened in something that zooms.

### Delegated permissions

**A third register on `/admin/delegation`, and the one you type.** The acts
are what happened, and the Kerberos table is somebody else's configuration;
this is configuration of this service's own, in the shape Microsoft Entra ID
uses. The page draws all three under headings saying which is which.

* A **resource** application exposes an API: a base URI
  (`oauthPermissionBaseUri` — Entra's Application ID URI, `api://<guid>`;
  anything absolute works here) and a list of permissions (`oauthPermission`).
  A permission is identified by the two joined — `https://example.com/` and
  `write` make `https://example.com/write`.
* A **client** application is granted some of them
  (`oauthDelegatedPermission`).

All three are ordinary attributes on entries in `ou=applications`, so an
`ldapmodify` is a configuration change.

**A permission must be DEFINED before it can be GRANTED** — the one ordering
rule, checked in one place so the console form, `POST /admin-api/permissions/…`
and the generic attribute editor on `/admin/applications` cannot disagree.

**Five actions, on two pages, posting to one handler.** *Expose an API*,
*Define a permission* and each row's *Remove* are on `/admin/delegation`.
**Granting is on the client application's own page** — its *Delegated
permissions* section shows what it holds, what it exposes, and a form that
grants it another — because there the client half is settled by the URL. A grant
written to the resource instead of the client would still succeed and be wrong
only at the token endpoint, later. The select offers neither the application's
own permissions nor ones it already holds. *Revoke* is drawn in both places.
Both forms post to `/admin/delegation` and both are
`POST /admin-api/permissions/{action}`.

The two tables of this register have a **search over the application name**:
`?permq=` matches the application that EXPOSES a permission, and `?grantq=`
matches **both ends** of a grant. Both match the display name and the
identifier.

**A client asks for a permission as an ordinary OAuth scope, and the access
token says both halves:**

```
scope=openid https://example.com/write https://example.com/read
   ->   "aud":   "https://example.com/"
        "scope": "openid read write"
```

The base URI becomes the audience and the permission NAME becomes the scope, so
a resource server checks `aud` once and then reads bare permission names.

**In product mode an ungranted permission is refused** (`invalid_scope`),
whatever the setting says. **In development it refuses nothing by default**:
with `oauth2.delegatedPermissionsEnforced` off, an ungranted permission is
honoured, logged as ungranted and marked on the console. With it on, the request
is refused `invalid_scope` at the authorization endpoint, and at the token
endpoint for grants that never reach it. A grant already issued is not
re-judged.

One-to-many and many-to-one need no store of their own: three permissions
granted to one client are three values on its entry; one permission granted to
three clients is one value on each. A grant naming a permission no application
defines is shown as **dangling**.

**`/admin/delegation/allowed` draws the register.** Every box is an
application, with no person and no service on it — a permission says *this
client may reach that API as whoever is signed in*, and nothing has been issued.
A line is **dashed** until the client has actually asked for that permission.

Under it are the **groupings**. A group is a set of applications reachable from
one another by following grants **ignoring direction**: holding a permission on
an API grants nobody that API's own permissions, so following arrows would
answer a chain question the register cannot pose, while following either way
puts an API and the front ends holding permissions on it in ONE group. Three
states make a group of one: an API nobody has been granted, a client holding
only dangling grants, and an application granted its own permission. A group is
named after the member whose identifier sorts first, so adding a grant inside a
group does not rename it. A search covers every application the register
touches, and a paged table lists the groups; clicking one opens
**`/admin/delegation/cluster`**, which draws that group alone with its members,
every permission it exposes and every grant in it.
`GET /admin-api/permissions/groups` is the same — every group with its counts,
or `?application=` for one application's group with its rows and graph. Neither
picture has a form on it.

### Audit log — `/admin/audit`

`/admin/audit` is the one page that reports **history** rather than state.
Every other page answers a question about now; only this one answers *when*,
*by whom*, and *in what order*. `/admin/metrics` says the directory holds eleven
entries; this page says a twelfth was created at 14:02 and deleted at 14:03 by
somebody bound as `uid=carol` over LDAPS, and that a token was revoked from the
console in the same minute.

**Six categories:**

* **Authentication** — a credential *accepted*, in any protocol family.
* **Session** — a browser sign-on session created or ended, shared by every
  protocol that uses one, so a `wsignout1.0`, an `/oauth2/logout` and a
  `/saml2/slo` produce the same row. It also carries `logout.global` and
  `logout.selective` from `/logout`: **one row per act, not per thing ended**
  (each session ended already wrote its own `session.end`); what they add is
  that these were one act and how much could *not* be ended.
* **Directory** — every LDAP operation, over 389 and 636 alike.
* **Admin** and **API** — the console and `/admin-api`.
* **Protocol** — every other endpoint.

Each arrives through a funnel the service already had: one point every
protocol passes through when a credential is accepted, and the call log every
answered request passes through. Only the directory records per operation,
because what a row says differs — a modify names its changed attributes, a
search how many entries came back. Whether an added entry is a user, a group or
something else is decided by **placement**, since the directory is schemaless,
by the same rule `/admin/groups` uses.

**No credential is ever recorded.** Not a password, a bearer token, an
assertion, or any request or response body. A modify names the attributes it
changed and never their values; a compare says whether it matched and not what
was tried; a refused bind carries the DN, not the password or its length. An
authorization `code` or an `id_token_hint` in a query string is replaced with
`(redacted)`. The one field read from an admin request body is `action`, by
name and capped in length, because those bodies carry pasted JWTs.

**One act usually produces several rows, and they are not duplicates.**
Signing in at `/authn/login` writes three: the HTTP call, the credential
accepted, and the session that came out. A Kerberos AS-REQ authenticates
somebody and starts no session; an LDAP bind does both with no HTTP request; a
`wsignout1.0` against an expired session is a `session.end` marked `refused`.

**Three outcomes, not two.** A `refused` is this service working and saying no,
which is most of what somebody debugging a client wants to see; an `error` is
this service failing. Merging them would bury the row worth paging somebody
about.

**The page observes itself.** Drawing it is console access, so it records an
`admin.view` event and the list is one row longer than when you asked. That is
stated rather than suppressed; `?category=` reads past it.

Filtering is by category, action, outcome, actor and free text, and the filter
vocabulary is read from the table the log records against. The actor filter is
a **substring**, because the actor on a directory row is a bind DN and on a
Kerberos row `alice@REALM`; where an identity has been normalised, the row
carries both the key and the form presented. Paging is `?page=` and `?per=`, but
**walk the list by `seq`**: it is monotonic and never reused, so "everything
after 4,102" is exact while the log is still being written. `?format=json`
carries `oldestSeq` and `newestSeq`; a gap between the last `seq` a caller saw
and `oldestSeq` is how many events the cap discarded.

Two things it deliberately does not have:

* **No client address.** Reached over a container bridge or a published port,
  the address is a fact about the network, not the caller. A row names the
  **channel** instead — `http`, `ldap`, `ldaps`, `grpc` for the SPIFFE gRPC
  surfaces, or `internal` for what the service did on its own.
* **No clear button**, here or on the API. An erase control would make an audit
  log unable to answer the one question it exists for.

Two settings, on the page itself, take effect immediately:
`audit.maxEvents` (5,000) is the cap, and what was dropped is counted and shown
— lowering it discards the excess on the next event. `audit.protocolCalls` (on)
is whether ordinary protocol calls get a row at all; they are the noisiest
category (every JWKS poll is one), and turning them off leaves the other five
categories and `/admin/metrics` untouched.

The log is held per trust realm, in memory, and in product mode on postgres it
is kept in the store with the rest of the minted state
([Persistence](persistence.md)).

## Protocols pages worth explaining

### Token lifetimes — `/admin/token-lifetimes`

The page to reach for when the question is *why has my client stopped
working*. Three lifetimes and one allowance, all in seconds: an **access
token** and an **ID Token** last an hour by default, a **refresh token**
twenty-four hours, and the **clock skew** — 30 seconds — is how far out a clock
may be before this service stops believing a token it signed. The table of
settings is on [OAuth 2.0 and OpenID Connect](oauth-oidc.md#token-lifetimes--admintoken-lifetimes).

Set the access token to 60 and the next one dies in a minute; set the ID Token
to something different and watch which of the two your client notices — a client
quietly treating the ID Token as a session gives itself away.

* **A change reaches the next token and nothing already issued.** A lifetime
  is stamped into a token as `exp`; `/admin/tokens` is where an issued token is
  taken out of circulation.
* **Every lifetime is a whole number of thirty-second units.** Below half a
  minute a token can expire between the response being written and the client
  reading it.
* **The skew is capped at 300 seconds** — what Kerberos allows here. Wider, it
  is a lifetime extension rather than a tolerance.
* **The skew moves the console and the endpoints together.** It is applied
  wherever this service reads back a token it issued — introspection,
  UserInfo, the refresh grant, token exchange, the DPoP-bound token check — and
  to the state every console screen reports, so a token `/admin/tokens` calls
  expired is one introspection calls `active: false`. It is not
  `oauth2.clientAssertionSkewS`, which is about a *client's* RFC 7523 assertion.
* The refresh lifetime is measured from issuance. RFC 9700 mode's
  `oauth2.refreshIdleSeconds` is measured from the last redemption in a refresh
  chain, so a busy client keeps its grant under that one and is still walled by
  this one.

All four are ordinary settings, also on `/admin/oauth2`. `GET
/admin-api/token-lifetimes` and `POST /admin-api/token-lifetimes/set` differ
from `POST /admin-api/config/set-many` in one way: they **refuse** a key that is
not one of the four, so a misspelling fails loudly.
`POST /admin-api/token-lifetimes/defaults` restores the four without disturbing
any other setting.

### Claims — `/admin/claims`, `/admin/userinfo-claims`, `/admin/saml-attributes`

These three pages decide what every access token, ID Token, UserInfo response,
SAML 2.0 assertion and SAML 1.1 assertion carries — **five sets over one
store**. An access token and an ID Token go to different readers, and SAML 1.1
splits a claim URI into `AttributeNamespace` and `AttributeName` where SAML 2.0
has one `Name`. The token sets are *Custom claims* under OAuth2 / OIDC, the
UserInfo set is *UserInfo claims* beside it, and the assertion sets are *Custom
SAML attributes* under SAML. One audit row is written per change whichever page
or API operation made it, and a set posted to the wrong door is refused by name,
saying where it lives.

**The UserInfo page is the one with no "nothing already issued changes"
warning**: that response is built on every call, so a claim added there reaches
a client that signed in an hour ago. It is also the only set a *client* can add
to, with OpenID Connect Core section 5.5's claims request
([OAuth 2.0 and OpenID Connect](oauth-oidc.md#userinfo-and-the-claims-request)).

**Configured claims are additive.** They are added to what the protocol already
puts in the artifact and never replace one. The names this service sets itself
are **refused at configuration time** rather than silently dropped at issuance
— an `exp` settable from a form would produce tokens that fail to verify, and a
settable `scope` would change what UserInfo answers. The reserved list applies
to the two token sets and UserInfo (whose `sub` a client must check against the
ID Token's), not to the SAML sets, where an attribute called `exp` collides with
nothing; the additive rule still protects SAML, because a WS-Federation relying
party keys off the claim URIs this service writes.

**Values may contain `${username}`-style placeholders**, so a claim can carry
the signed-in user's identity. **An unknown placeholder is left exactly as
written**, so a `${dept}` names itself rather than becoming `""`. A JWT claim
value is typed when it unambiguously looks like JSON (an object, an array,
`true`/`false`/`null`, a number) and is a string otherwise — so a value that is
genuinely the four characters `true` must be written `"true"`. SAML values are
never typed, and an assertion expands a shorter list of placeholders —
`${subject}`, `${audience}`, `${now}` and `${iso}` — because it is built from a
subject and an audience; a `${username}` there arrives as written.

**Each set has a second half: LDAP attribute types with a checkbox.** A ticked
attribute becomes a claim whose value is read from the person's own entry under
`ou=users`, so an `ldapmodify` of `uid=alice,ou=users` changes the next access
token and the next assertion, and an LDAP client, an OIDC client and a SAML
relying party see the same person. **Update** installs exactly the ticked
boxes, and **Select all** and **Delete all** are the extremes — all form posts,
with no script.

The catalogue is the same list of attribute types `/admin/vc` and
`/admin/vc-verifier-config` choose from, so there is one spelling of each. The
*selections* are independent: an access token carrying `employee_number` while
the ID Token carries only `email` is a normal arrangement. **Nothing is
selected on a fresh start**, so upgrading never adds a claim to every token.

**Three rules decide a claim's value.** The protocol's own claim wins: an ID
Token always carries `name`, `given_name`, `family_name`, `preferred_username`
and `email` from the sign-in, so ticking `cn`, `givenName`, `sn`, `uid` or `mail`
*on that set* changes nothing — while the same five reach an access token from
the directory. Then a typed claim beats a directory attribute of the same name.
Then the attribute, read from the entry, or invented from the username where
the entry has none — deterministically. A nested claim stays nested in a JWT
(`address.locality` is a member of `address`, per OIDC Core 5.1.1) and becomes
the attribute's literal name in an assertion.

**An assertion never carries two attributes of the same name.** Configured
attributes are filtered against the ones the builder already wrote — by name
for SAML 2.0, and by namespace and name for SAML 1.1.

Every change to a claim set writes an audit row naming the set and what was
added and removed — never a value — in addition to the row the call log writes
for the same POST.

### Credential claims — `/admin/vc`

`/admin/vc` decides what every *future* verifiable credential carries, and its
list is of **LDAP attribute types rather than claim names**, because this
service has a directory: `mail` on `uid=alice,ou=users` is what a wallet is
handed as `email`, so an LDAP client and a wallet see one person. Ten rows are
selected on a fresh start — given name, family name, email, birthdate,
nationality, and the five components of `address`. Three rows are not
RFC 4519/4524/2798: there is no standard attribute type for a birthdate or a
nationality, so the SCHAC schema's names are used, and the page shows each row's
defining document. [OpenID4VCI](oid4vci.md#what-a-credential-says) covers the
issuer side.

**The issuer metadata is built from the same list the credential is**, so
`credential_configurations_supported` cannot advertise different claims from
the ones that arrive. **`ldp_vc` carries a subset**: it is signed over
canonicalized JSON-LD, and a term the vendored context does not define makes
canonicalization throw. Each catalogue row names its JSON-LD term or says it
has none, the builder filters through the context actually loaded, and the page
and `/admin/sts-metadata` name the selected attributes that format leaves out.
The context is vendored because editing it would invalidate every credential
already issued against it.

**A claim's value has three sources, in order.** The **access token** first,
where it carries a claim of that name — a credential contradicting the token
that authorised it would be indefensible. Then **the directory entry**, where an
`ldapmodify` lands. Then **a generated persona**, for a person with no entry, an
entry without the attribute, or no directory. A claim is never left out because
a source was missing.

**Generated values are fake on purpose and deterministic on purpose.** Invented
streets say `Placeholder`, mailboxes are in the RFC 2606 example domains, and
telephone numbers are in the `555-01xx` fiction range, so no value can collide
with a real one. They are seeded from the **normalised** username, so one
username is one whole invented person for the life of the process and across
restarts, whichever spelling (`alice`, `urn:sts:user:alice`,
`alice@EXAMPLE.COM`) arrived. Auto-created entries also get an invented name
rather than the login name three times over; the DN and `uid` keep the login
name, and `displayName` keeps a `(mock)` marker.

**Saving a selection writes to the directory.** Every person under `ou=users`
gains the selected attributes they are missing, invented from their username,
so the directory and the credentials keep describing the same people.

* It **never overwrites** an attribute already on an entry, so the seeded people
  keep their own values and an operator's `ldapmodify` is not undone.
* It writes **one value**, not an appended one.
* It walks **entries under `ou=users`**, not everything with a person
  `objectClass` — a schemaless directory can hold one anywhere.

The same fill runs when an entry is created, when a returning person
authenticates, and once at startup.

**A credential claim grants nothing and nothing reads one back.** It reaches a
credential and stops there.

### Verifier request — `/admin/vc-verifier-config`

The other end of `/admin/vc`, and deliberately a separate setting. `/admin/vc`
decides what an issued credential *carries*; this decides what the Verifier at
`/oid4vp/verifier` — *The Bar Door* — **asks for**, as the `dcql_query` of the
next OID4VP request, and what the presentation is checked against. Keeping them
apart makes the interesting state reachable: a Verifier asking for a claim the
issuer does not mint exercises a wallet's "I cannot satisfy this request" path.
The page also chooses which of the three **credential formats** an unqualified
request asks for, since a presentation cannot convert between them.
[OpenID4VP](oid4vp.md#what-the-bar-door-asks-for) covers the Verifier.

**Its table is of claims, grouped by what the credential can disclose.** An
SD-JWT VC makes one Disclosure per *top-level* claim, so `address` is one unit
however many LDAP attributes feed it. Every row still names its attribute types
and their defining document, and an *Issued now* column reports what the issuer
is configured to mint.

* A claim **not in the catalogue** can be asked for from a text box — the way
  to reach "the wallet cannot satisfy this request".
* Asking for **nothing** is a setting: DCQL reads an absent `claims` member as
  the whole credential, and the page says it is now asking for everything.
* **The DCQL path differs by format**: `["given_name"]` for `dc+sd-jwt`,
  `["credentialSubject","given_name"]` for `jwt_vc_json`, and for `ldp_vc` the
  term the vendored JSON-LD context defines (`birthDate`, and four flat terms
  for `address`). A claim the context has no term for is dropped from an
  `ldp_vc` query and named on the page.
* **What a request asks for is frozen onto it**, so the verdict at
  `/oid4vp/result/:state` records that exchange rather than the console's
  current state.

**This page admits nobody.** A presentation at the bar door starts no session
and issues no token. Signing in with a wallet is `/authn/wallet`, which asks for
a credential this realm issued with a request of its own and is not configured
here ([OpenID4VP](oid4vp.md#signing-in-with-a-wallet)).

### Authorization servers — `/admin/authorization-servers`

Decides what each discovery document *publishes*. One process serves as many
authorization servers as are configured, each selected by the path component
both discovery shapes carry, with its own endpoints, capabilities and issuer.
Any member is settable, including one this service has never heard of, so
every view computes the **drift** between what a profile publishes and what the
service actually does. See
[OAuth 2.0 and OpenID Connect](oauth-oidc.md#multiple-authorization-servers--adminauthorization-servers).

## What the console does not do

* **It does not invalidate a SAML assertion, a Kerberos ticket, an SVID or a
  verifiable credential.** None has a revocation mechanism a relying party
  consults, so a button claiming to revoke one would change a number here and
  nothing out there. (Credentials have status lists — see
  [OpenID4VCI](oid4vci.md#status-lists).)
* **It ends sign-on sessions** (`/admin/logout`, and `/admin/sessions` for the
  service-wide view), through the same function every sign-out uses, with
  back-channel logout to relying parties. What it cannot do is *deliver*
  front-channel logout: that is an iframe in the signed-out person's own
  browser, and the console is not that browser. See
  [Signing out](signing-out.md).
* **It adds no claims to refresh tokens.** A refresh token is presented back to
  this server and nothing else, so a claim in one reaches no relying party.

## What the console keeps

The registries behind these pages are **bounded**: the most recent 5,000
tokens and 5,000 other artifacts, 500 call paths, and 2,000 identities keeping
their 50 most recent authentications each (capped per person, because a test
loop signing one name in a thousand times is normal). What was dropped is
counted and shown. The revoked-jti set is **not** capped and is kept apart from
the token records, so a token whose record has aged out stays revoked. The
audit log is capped by `audit.maxEvents` and the delegation acts by
`delegation.maxRecords`.

In development mode, and with any store but postgres, all of it is **in memory
and dies with the process**, like the signing key. In product mode on postgres
it is minted state and is kept in the store ([Persistence](persistence.md)).

## The embedded protocol debugger

The [Identity Protocol Debugger](https://idptools.com) — the project this
service was extracted from — can be served by this process, in this container,
as a feature of it. **Server configuration → Protocol debugger**
(`/admin/debugger`) and `GET /admin-api/debugger` report the listener, the api
process and its allow-list.

**How it is served.** The debugger project builds its browser client and its
api for embedding (`embedded/build.sh` or `embedded/Dockerfile` in that
project), and this service serves the result:

* **On a listener of its own**, `debugger.port` (8444), in the main port's
  scheme and with its certificate. It is a different **origin** from `/admin`
  on purpose: the debugger's pages carry inline scripts and render tokens and
  assertions from any identity provider, and on the console's origin a flaw in
  either would be a script able to drive the console.
* **Its api as a child process** on a unix socket, forwarded at `/api` with the
  prefix stripped, the browser's cookies and credentials removed, and its own
  Express, dependencies and environment. Nothing of the debugger is loaded into
  this process.
* **Behind this service's own authorization server.** The debugger is an OpenID
  Connect relying party like `/admin` and `/portal` — the seeded client
  `sts-debugger-ui` — and its api is a resource server, `sts-debugger-api`, that
  exposes one delegated permission, `urn:sts:debugger-api:debugger`, which the
  UI's entry is granted ([Applications](applications.md#the-applications-that-are-this-service)).

**Only console administrators get the permission.** The authorization server
issues it to members of the Admin Read or Admin Write group of the default
realm, and to nobody else: it is taken off the grant for any other person, for
any application, and in any realm but the default one. The gate checks the
token on every request, and checks that its subject is *still* an
administrator.

* **In development, a role held only because the console is open to everybody
  does not count** — the debugger stays shut until somebody really is in a role
  group. Grant somebody a role on `/admin/rbac` first.
* **In product mode**, until the bootstrap administrator has claimed the
  console with its password, it is refused the permission too
  (`STS-DBG-0033`); sign in to `/admin` with the password first.

**There is no setting that opens it.** `debugger.enabled` decides whether it is
served — `auto` is on in development mode and off in product mode. In product
mode the api is handed an allow-list and may dial only this service's own
addresses plus `debugger.allowedDestinations` — raw Kerberos, LDAP, TLS and gRPC
relays included — because a relay that dials what its caller names should not
reach an identity provider's private network.

**Running it from a checkout of both projects:**

```bash
(cd ../id-proto-debugger && embedded/build.sh --out ../iya-sts/debugger/embedded)
```

then build and run this service's image (it runs from an image, see
[Getting started](getting-started.md)), publish 8444, open
`https://localhost:8444/` and sign in as a console administrator.

**In a container:** build the debugger project's embedded image and pass it to
this one:

```bash
docker build -f embedded/Dockerfile -t rcbj/id-proto-debugger-embedded:dev .   # in the debugger project
DEBUGGER_IMAGE=rcbj/id-proto-debugger-embedded:dev docker compose build sts   # here
```

and publish 8444. Without a debugger image the build succeeds, and
`/admin/debugger` says the debugger is not installed.

**What it does not change:** the debugger's own standalone deployment — its
client and api containers and the hosted site — is untouched; everything about
authentication lives on this side.

## Configuration

The live source for every setting is its console page and
`GET /admin-api/config`. The console's own `admin.*` settings — the role
groups, `admin.openWhenEmpty`, the bootstrap administrator — are on
[Management API](management-api.md#configuration), beside `adminApi.*`, and are
edited on `/admin/rbac`.

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `audit.maxEvents` | `AUDIT_MAX_EVENTS` | `5000` | yes | How many audit events are held; the dropped are counted and shown. |
| `audit.protocolCalls` | `AUDIT_PROTOCOL_CALLS` | `true` | yes | Whether ordinary protocol endpoint calls get an audit row. |
| `delegation.maxRecords` | `DELEGATION_MAX_RECORDS` | `2000` | yes | How many delegation acts `/admin/delegation` keeps, refusals included. |
| `oauth2.delegatedPermissionsEnforced` | `STS_OAUTH2_DELEGATED_PERMISSIONS_ENFORCED` | `false` | yes | In development mode, refuse a permission the client was not granted. Product mode always refuses. |
| `debugger.enabled` | `STS_DEBUGGER_ENABLED` | `auto` | no | `auto`, `on` or `off`; `auto` serves the debugger in development mode only. |
| `debugger.port` | `STS_DEBUGGER_PORT` | `8444` | no | The debugger's listener. |
| `debugger.allowedDestinations` | `STS_DEBUGGER_ALLOWED_DESTINATIONS` | empty | no | In product mode, the destinations beyond this service's own that the debugger's api may dial. |

The claim, groups and token-lifetime settings are on
[OAuth 2.0 and OpenID Connect](oauth-oidc.md#configuration) and
[LDAP](ldap.md#configuration).

## Related

* [Management API](management-api.md): every console control, for a machine
* [Applications](applications.md): the application registry
* [Trust realms](trust-realms.md): per-realm administrators
* [Sessions](sessions.md) and [Signing out](signing-out.md)
* [What is not checked](what-is-not-checked.md#the-admin-console-at-admin)
* [LDAP](ldap.md): the directory the roles, users and groups live in
* [Endpoints](endpoints.md) and `/admin/sts-metadata`
