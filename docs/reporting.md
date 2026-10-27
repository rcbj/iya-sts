---
title: Reports
nav_order: 11
---

# Reports

Reports is an application at `/report`. A query is one JSON document
against one catalog source. The answer is JSON, CSV or PDF. This service
does not accept a SQL statement, and it does not forward a query to
PostgreSQL or to an operator's attribute-source database.

Open `/report` — the front page links to it — and sign in. The browser uses the public client
`sts-report` (PKCE S256, a DPoP-bound token, `resource` this realm's
`/report-api`). Each realm also has `sts-report-api`, the application for
that API. It exposes `report:use` and `report:admin`. Those two are granted
to `sts-report`, and `sts-report` declares them, the same way the admin
console declares `admin:read` and `admin:write`. The words on the page come from the signed-in user's
language. The API stays language-free, and every error sentence is
English. When several accounts in one browser are enabled, the page uses
the same account switcher as the portal.

`GET /report-api/openapi.json`, after you are signed in, is the API's own
description of every released route. This page is the same surface in
prose. The [endpoint list](endpoints.md) names the paths.
[Reporting](configuration.md#reporting) is every cap.

## Who can open it

- **`report:admin`** is issued only to this realm's administrators (Admin
  Read or Admin Write). An administrator sees every definition and every
  job in the realm, and can edit and delete any definition.
- **`report:use`** is issued to those administrators, and to members of
  the directory group named by `report.usersGroup`. When that setting is
  empty, only the administrators are issued it. An application (a
  `client_credentials` subject) is issued neither scope.

You see the definitions you own. Sharing a definition with a directory
group lets members of that group run it and download the result. The
share body is `{ "groups": ["cn=reporters,ou=groups,…"] }`: each value is
a group DN in this realm. Sharing does not let them edit or delete it.
A definition or a job you may not see is answered as not found. A job id
in a URL is not permission to read it. The same token is required for the
result as for the query that created the job.

## The page

Every report page has the same chrome. A small right-justified bar at
the top holds the controls about you: a field naming the **trust realm**
the page is showing (when the service has several realms it is a
drop-down, and choosing another realm opens that realm's reports
application at the same page, where you sign in as you did here, because
a token belongs to the realm that issued it; `GET /report-api/realms` is
what it reads), the language chooser, and the user menu, which names the
account this tab is signed in as and holds **Sign out** (with several
accounts on it also switches between the browser's signed-in accounts).
Under it the navigation bar holds the pages and Refresh, and under that
a link opens this documentation. At the bottom of the card the service's
**version** is shown, read from the same source every other page reads.

The query form starts with **one filter row**; the `+` beside the last
row adds another, up to the sixteen an `and` may hold. Rows left blank
are ignored. The **Save query** box reveals the Name field and the Save
button; unchecked, the form only runs the query. Once it is ticked, Enter
in the Name box saves.

A **job's page says why the query became a job** (`queuedBecause` on the
job): `every-person` (an auto-mode query whose filter the directory
cannot answer from an index, so it has to read every person), `asked`
(mode `async`, or `POST /report-api/jobs`), `limit` (auto over
`report.syncMaxRows`), `source` (a source that cannot be read
synchronously), `run` (a saved definition run by hand) or `schedule`.

A definition's page names its **owner** by display name or username
(`ownerName`), with the subject kept on the API. Its **query is edited
with the New Query form's own controls**, filled from the saved
document; a filter the rows cannot draw (an `or`, a `not`, an `in`) is
shown as JSON and kept until a row is filled in. Its **schedule** is
edited as a date-time in UTC and seven weekday boxes: with weekdays
ticked the definition runs at that time on those days every week; with
none it runs on that date every year. The sentence under the controls
says which, and shows the cron expression the API stores, so an
expression written by hand on the API that the editor cannot draw is
still seen. Save and Delete are buttons at the foot of the form.

Every field of the application carries a **tooltip** on its label, the
console's shape, saying what the field is for. The outcome of an act — a
save, a delete, a query queued as a job, a refused run, a download that
failed — is shown in a **status bubble** at the top of the page, with a
dismiss; a refusal leaves the form as it was. A failed download names
the API's reason, or the HTTP status when it gave none.

**The Parameters box** on a definition's page is for a saved filter that
names a parameter instead of a value, such as
`{ "op": "eq", "field": "username", "param": "who" }`. The definition
stores a default for it, and a run fills it from the JSON object typed
in the box, for example `{"who": "rcbj"}`; a key given there overrides
the stored default for that run only, and an empty box uses the defaults.
The sentence under the box names the parameters the filter holds, or
says that it holds none, in which case the box is ignored. The query form
writes values, not parameters, so a definition made on the page names
none unless its document is edited through the API.

**How a schedule runs.** An enabled schedule is checked about once a
minute by the `report.schedule` job. The most recent occurrence that has
not yet been taken is queued as a job, owned by the definition's owner;
so the first run follows within a minute of saving an enabled schedule
whose expression has any past occurrence, and later runs follow each
occurrence. The definition page says when the next run is due and which
occurrence was last taken, and lists the reasons a scheduled run did not
happen (`failures` on the API): the owner lost `report:use`, a parameter
has no stored value, the query no longer validates, or the job could not
be queued. A schedule that is saved with the Enabled box clear is kept
and never runs.

**The Definitions and Jobs lists are paged** as the console pages its
tables: first, previous, a window of page numbers, next and last, a line
saying page x of y and rows a–b of n, and a rows-per-page choice (25, 50,
100 or 200), carried in the page's address as `?page=&per=` so a page can
be linked to. `GET /report-api/definitions` and `GET /report-api/jobs`
take `page` and `per` (50 unless given, at most 200) and answer `page`,
`pages`, `per` and `total` beside the rows; the jobs list still answers a
cursor walk with `after` and `limit`.

**`GET /report-api/schedules`** lists every definition that carries a
schedule, each with `nextRunAt`, `lastSlotAt`, its last three skip notes
and its most recent scheduled jobs (at most five, with `jobCount` for the
total). With `report:use` the list is the definitions you own or are
shared (`scope: "mine"`); with `report:admin` it is every one in the
realm (`scope: "realm"`), and `?owner=` narrows it to one owner, given
as a `urn:uuid:` subject or a username. A `report:use` token that names
another owner is refused with `forbidden` (403). `page` and `per` page
it, `per` at most 100.

### The groups a definition is shared with, and who is emailed

The **Groups emailed the result** pane is a search over the realm's
groups (`GET /report-api/groups?q=&page=`, five a page, with Previous
and Next), an Add beside each hit, and the chosen groups in a list with a
Remove beside each. Save sends the list to the share endpoint. Members of
those groups may run the definition and read its result, as before.

**Since #989 those groups are also who is emailed.** When a job of the
definition finishes with Notify on, the owner's notice is sent as before
and each shared group is sent one at the group's own email address, the
`mail` attribute of the group entry, which the console's group page sets
(*Email address*, or `POST /admin-api/groups/set-mail`; a create may give
it too). **A shared group with no address is an error of its own**,
`STS-REPORT-0037`: logged, written on the audit row as `report.notify`
with outcome `error`, and shown as *no email address* beside the group in
the pane. The other recipients are still sent to.

**Filter rows come and go.** The `+` on the last row adds a row; the
trash can beside a row removes it. The last row left is emptied rather
than removed, so there is always one.

**Sort and Group by are behind checkboxes.** Tick **Sort** to choose the
field and the direction on the same row; unticked, the query carries no
order. Tick **Group by**, on its own row under Count, to choose the group
field; a group-by is always
a count, so it counts whether or not **Count** is ticked. A saved
definition with an order or a group opens with the boxes ticked and the
choices shown.

**The result of Run is paged on the page.** Every row the query
returned is kept in the browser and shown fifty at a time, with the same
pager the Definitions and Jobs lists use above and below the table:
first, previous, a window of page numbers, next, last, a "rows N–M of T"
line and a rows-per-page choice (25, 50, 100 or 200). Turning a page or
changing the size redraws from what came back and asks the service
nothing; the query's `limit` still decides how many rows that is.

## The catalog

`GET /report-api/catalog` lists every source. `GET /report-api/catalog/{id}`
is one of them. Each source is bounded: a limit can be honoured without
holding the population. Each source says `paging: "limit"` and
`relationships: []`. There is no second page key and no join. An `offset`,
a `sources` key, or `source` sent as an array, is `invalid_query`.

A field has an id, a type (`string`, `number`, `timestamp` or `boolean`),
an English meaning, and whether it can be filtered, sorted or grouped. A
field that can hold only certain values lists them as `values`, and the
page draws a dropdown of them in a filter row under `equals` and `not
equals`, and offers only `equals`, `does not equal` and `is empty` as the
row's operators. `credentialHolders`' `mechanism`, `role` and `lane` are
the first.
Grouping is only with `aggregate: "count"`. The operators depend on the
type, not on the source:

| Type | Operators |
|---|---|
| string | `eq`, `ne`, `contains`, `startsWith`, `in`, `isNull` |
| number | `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `in`, `isNull` |
| timestamp | `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `isNull` |
| boolean | `eq`, `ne`, `isNull` |

`in` takes an array of 1 to 50 values of that type. The query form does
not offer `in`. Send it on the API. `isNull` names a field and nothing
else. A credential attribute id (`userPassword`, `unicodePwd`,
`ntPassword`, `krb5Key`, `totpSecret`, `webauthnCredential`,
`backupCodes`, `mailSecret`, `clientSecret`) is not a field. Selecting
one is `unknown_field`.

`members` can be selected and cannot be filtered, sorted or grouped.
`entryUuid` and `memberOf` can be filtered and cannot be sorted.

### Indexed filters

A field also says which operators the directory answers with an index
(`indexed`, shown as the Indexed column on a source's page). A filter
using one of them reads only the rows it names, however large the
directory. A person's attributes are stored as one sealed value, so the
directory can filter on very few of them: `username` for `eq`, `in`,
`contains` and `startsWith` (the substring needs three characters or
more), and `mail` and `entryUuid` for `eq` and `in`. Every other field of
`users` is filtered after the rows are read.

A `users` query is answered from the index when its filter is an indexed
leaf, an `and` with an indexed arm (the other arms are applied to the
rows found), or an `or` whose every arm is indexed, up to sixteen lookups.
A `not`, `ne` or `isNull` never narrows.

On a directory held in a database, a `users` query whose filter the index
cannot answer, or that sorts or counts, has to read every person. Such a
query is refused in `sync` mode with `result_too_large` and a sentence
naming the indexed fields, and in `auto` mode it becomes a job and
answers `202` with the job. A query with no filter, no order and no
count stops at its limit and is answered now. The in-memory directory of
a service with no database is small and is always read in full.

### `users`

The directory as it is now. Not a history of accounts. `status` `locked`
means `pwdAccountLockedTime` is set, which is an administrative disable
or any other lock. `active` is the other value.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `username` | string | The directory uid. Indexed: `eq`, `in`, `contains`, `startsWith`. | yes | yes | no |
| `status` | string | `locked` when `pwdAccountLockedTime` is set; `active` otherwise. | yes | yes | yes |
| `createdAt` | timestamp | When the directory created the entry. | yes | yes | no |
| `modifiedAt` | timestamp | When the directory last changed the entry. | yes | yes | no |
| `entryUuid` | string | The entryUUID. Indexed: `eq`, `in`. | yes | no | no |
| `mail` | string | The mail attribute. Indexed: `eq`, `in`. | yes | yes | no |
| `displayName` | string | `displayName`, or `cn` when `displayName` is empty. | yes | yes | no |
| `memberOf` | string | The names of the groups that list this person, joined. | yes | no | no |
| `hasPassword` | boolean | Whether a password is set on the entry. | yes | yes | yes |
| `factors` | number | How many second-factor credentials the person holds: passkeys enrolled as a second factor, authenticator apps, mail factors. `hasPassword` true and `factors` 0 is a password alone. | yes | yes | yes |
| `methodsUsed` | string | The RFC 8176 methods the person has signed in with here (`pwd`, `hwk`, `otp`, …), joined; compared value by value. | yes | yes | no |
| `mfaLastAuthTime` | timestamp | When the person last completed a multi-factor sign-in. | yes | yes | no |

None of the four is indexed: a filter on them reads every person, so on
a large directory it is a job (`mode: auto`), best narrowed by
`memberOf`. "Who has only a password" is `hasPassword` equals `true` and
`factors` equals `0`; "who has signed in with a password" is
`methodsUsed` equals `pwd`.

### `groups`

The directory as it is now. Member lists are selected, not filtered.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `name` | string | The group cn. | yes | yes | no |
| `description` | string | The description attribute. | yes | yes | no |
| `memberCount` | number | How many members the group lists. | yes | yes | no |
| `members` | string | Member names, joined. | no | no | no |

### `applications`

The realm's configured applications, as they are now.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `id` | string | The application identifier. | yes | yes | no |
| `name` | string | The application name. | yes | yes | no |
| `status` | string | `active` when the application is registered and enabled; `disabled` otherwise. | yes | yes | yes |
| `enabled` | boolean | Whether the application is registered and enabled. | yes | yes | yes |

### `federation`

The realm's configured federation relationships, as they are now.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `id` | string | The relationship id. | yes | yes | no |
| `partner` | string | The partner name. | yes | yes | no |
| `protocol` | string | The protocol the relationship speaks. | yes | yes | yes |
| `enabled` | boolean | Whether the relationship is enabled. | yes | yes | yes |

### `authMechanisms`

The realm authentication policy, one row per mechanism with `application`
`realm`, plus one row per mechanism an application lists. An application
that lists none inherits the realm policy and adds no row. This is not a
count of sign-ins. Non-browser doors are outside `appAuthnMechanism`.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `id` | string | The mechanism id. Realm rows use the policy names. An application row uses the value it lists. | yes | yes | no |
| `type` | string | `both`, `primary`, `second` or `other` for a realm row. `primary` for `appAuthnMechanism` and `second` for `appMfaMechanism`. | yes | yes | yes |
| `enabled` | boolean | For a realm row, whether that policy flag is on. For an application row, `true` because the application lists it. A listed second factor the realm has switched off stays off at sign-in. | yes | yes | yes |
| `application` | string | `realm`, or the application identifier. | yes | yes | yes |

### `auditEvents`

The audit ring still held in this process, newest first, capped by
`audit.maxEvents` (5000 unless an operator set another cap). Not a
warehouse of sign-ins.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `timestamp` | timestamp | When the event was recorded. | yes | yes | no |
| `category` | string | The audit category. | yes | yes | yes |
| `action` | string | The audit action. | yes | yes | yes |
| `outcome` | string | The audit outcome. | yes | yes | yes |
| `actor` | string | The account name on the audit row. | yes | yes | no |

### `authActivity`

Sign-in attempts still in that same ring: `authentication`,
`authentication.refused`, `session.refuse` and `session.refused`.
`session.reauthenticate` is not an attempt. The same cap applies. A
session id, an address, a note and a presented credential are not fields.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `timestamp` | timestamp | When the attempt was recorded. | yes | yes | no |
| `day` | string | The UTC calendar day, `yyyy-mm-dd`. | yes | yes | yes |
| `outcome` | string | The audit outcome, such as `success` or `refused`. | yes | yes | yes |
| `mechanism` | string | `detail.method` when the row has one, otherwise `detail.amr`. | yes | yes | yes |
| `actor` | string | The account name on the audit row. | yes | yes | no |
| `application` | string | `detail.application`, or `detail.client_id` when the row has no application. | yes | yes | yes |
| `protocol` | string | The protocol on the audit row. | yes | yes | yes |

### `serviceMetrics`

Numeric leaves of a live service-counter snapshot. Not a time series.
See [Statistics that stay where they are](#statistics-that-stay-where-they-are)
for what this source does not carry. `/admin/metrics` and
`/admin-api/metrics` stay.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `name` | string | `family.leaf`, the snapshot member and the number under it. | yes | yes | no |
| `value` | number | The number at the moment of the read. | yes | yes | no |
| `family` | string | The snapshot member the leaf was read from, such as `calls` or `tokens`. | yes | yes | yes |

### `reportJobs`

Report jobs this realm still holds. Artifacts age out on
`report.artifactRetentionS`. The job row ages out later, on
`report.jobRetentionS`. A job that is still queued or running is kept.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `id` | string | The job id. It is not an authorization. | yes | yes | no |
| `status` | string | `queued`, `running`, `completed`, `failed`, `cancelled` or `expired`. | yes | yes | yes |
| `format` | string | `json`, `csv` or `pdf`. | yes | yes | yes |
| `submittedAt` | timestamp | When the job was queued. | yes | yes | no |
| `completedAt` | timestamp | When the job finished, or null while it has not. | yes | yes | no |
| `byteSize` | number | The stored artifact size, or null before it exists. | yes | yes | no |

### `attributeSources`

The attribute-source register as it is now. Connection details and
secrets are not fields. This source does not run SQL and does not read
the remote table. Values those sources write are already on directory
entries, which is what `users` reads.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `id` | string | The source id. | yes | yes | no |
| `dialect` | string | `postgres` or `mysql`, as configured. | yes | yes | yes |
| `database` | string | The database name. Not the host. | yes | yes | no |
| `table` | string | The table the lookup reads. | yes | yes | no |
| `keyAttribute` | string | The directory attribute the lookup key is taken from. | yes | yes | no |
| `mode` | string | The refresh modes, joined, such as `sign-in` or `schedule`. | yes | yes | yes |
| `onFailure` | string | `keep` or `refuse`, as the source is configured. | yes | yes | yes |
| `enabled` | boolean | Whether the source is enabled. | yes | yes | yes |

### `credentialHolders`

Who holds which authentication credential, as the directory is now: one
row per credential — a passkey, an authenticator app, an enrolled
certificate, a mail factor, a Kerberos key set — with the person who
holds it, its mechanism and role, and its own algorithm. A passkey's role is the one
chosen at its enrolment, `primary` (it signs the person in on its own)
or `mfa` (a second factor after a password), which the service enforces
at sign-in; an authenticator app and an emailed code are `mfa`; a
certificate and a Kerberos key are `primary`.

**How it reads, and why it costs little.** A filter on `mechanism` reads
the holders of that mechanism's attribute through the store's index of
who holds what, so it costs the holders and never the population; a
filter on `memberOf` reads that group's members. A query naming neither
reads every mechanism's holders: on a directory held in a database that
is refused synchronously (`result_too_large`) and becomes a job in
`auto` mode. Nothing new is stored or indexed, and nothing changes what
is sealed: the rows are read from the holders' own entries, as the users
page's census reads them. A recovery code set is one row with its unused
codes counted, the hash scheme as its algorithm and its generation as
`enrolledAt`; no code reaches a row (since schema version 27, which put
the attribute in the index). App passwords are not listed, because their
attribute is not in that index.

**Wallets.** `verifiableCredential` is every credential this realm
issued and still remembers, read from the issuer's register rather than
the directory: one row per issued copy, with its `format`, the holder
key's `algorithm` and `lane`, and the `channel` it was issued over —
`web` when the wallet's request carried a browser Origin, `app`
otherwise. A copy the holder removed is left out. `selfIssued` is every
DID or key a person enrolled, one row each, with the channel the
enrolment recorded (`web`, `app`, `dc_api`, or `admin` for one an
administrator entered) and the key's algorithm, read off a `did:jwk` or
`did:key`, else the algorithm the proof was signed with. A count grouped
by `channel` and `algorithm` is how many wallet credentials there are of
each kind; add `memberOf` for one community. A credential issued or a
subject enrolled before this was recorded has no channel and, for a
`did:web`, no algorithm.

**The password is the one mechanism counted rather than indexed.**
Nearly everyone holds one, so the directory keeps no index of its
holders; it keeps a counter per realm, and that is what a count by
`mechanism` reads for `password`, instantly. A list of password holders
is the population, so it is refused like any read over the cap and runs
only narrowed by `memberOf`. A password row carries the hash scheme as
its `algorithm` (`scrypt` or `argon2id` for a password this service set,
the braced scheme of an imported hash such as `SSHA`) and
`pwdChangedTime` as its `enrolledAt`, and never the hash.

**The holders are counted before they are read.** A mechanism nearly
everyone holds is the population under another name: on a service where
every person has a password, every person also holds Kerberos keys, so
`mechanism` equals `kerberos` names a million people. The store counts
the holders through the index that lists them, no further than one past
the execution's row cap (`report.syncMaxRows` synchronously,
`report.asyncMaxRows` in a job), so the question costs the cap and not
the population; over the cap the query is refused as `result_too_large`
before the first entry is opened. Synchronously the refusal says to run
it as a job, which `auto` mode does, and the job counts again against
its own cap. A `memberOf` filter's members are counted the same way. The
read that does start stops with the query's time cap or its
cancellation, not with its last holder.

**The census is a count of credentials.** `aggregate: "count"` with
`groupBy` `mechanism`, `role`, `algorithm` or `lane` answers how many
passkeys are enrolled as a primary mechanism, how many as a second
factor, how many of each algorithm, and so on; group by `username` for
how many each person holds, and add a `memberOf` filter for one
community. The maintained per-realm passkey aggregate stays on
Monitoring → Passkeys.

| Field | Type | Meaning | Filter | Sort | Group |
|---|---|---|---|---|---|
| `username` | string | The directory uid. | yes | yes | no |
| `displayName` | string | `displayName`, or `cn`. | yes | yes | no |
| `mechanism` | string | `passkey`, `totp`, `emailFactor`, `certificate`, `kerberos`, `password`, `recoveryCodes`, `selfIssued` or `verifiableCredential`; enumerated, a dropdown on the page. Indexed: `eq`, `in`. | yes | yes | yes |
| `role` | string | `primary`, `mfa` or `recovery`; enumerated. | yes | yes | yes |
| `credentials` | number | How many credentials of this mechanism and role the person holds; the same on each of their rows. | yes | yes | no |
| `credentialId` | string | This credential's own id (a passkey's credential id). | yes | yes | no |
| `algorithm` | string | This credential's signature algorithm (a passkey's JOSE name, such as `ES256` or `ML-DSA-65`). | yes | yes | yes |
| `lane` | string | A passkey's or a wallet key's lane, `classical` or `pqc`; enumerated. Empty for the other mechanisms. | yes | yes | yes |
| `channel` | string | Where a wallet credential came from: `web` (a web wallet), `app` (a native wallet), `dc_api` (the browser's Digital Credentials API) or `admin` (entered by an administrator); enumerated. Empty for the other mechanisms. | yes | yes | yes |
| `format` | string | A verifiable credential's format: `dc+sd-jwt`, `jwt_vc_json` or `ldp_vc`. Empty for the other mechanisms. | yes | yes | yes |
| `enrolledAt` | timestamp | When this credential was enrolled, where recorded. | yes | yes | no |
| `lastUsedAt` | timestamp | When this credential was last used, where recorded. | yes | yes | no |
| `methodsUsed` | string | The RFC 8176 methods the person has ever signed in with here. | yes | yes | no |
| `mfaLastAuthTime` | timestamp | When the person last completed a multi-factor sign-in. | yes | yes | no |
| `memberOf` | string | The groups that list this person, by name (`cn`), joined. Indexed: `eq`, `in`, each value a group's name. | yes | no | no |

Every passkey enrolled as a primary mechanism, with its holder, its
algorithm and how many that person holds:

```json
{
  "source": "credentialHolders",
  "select": ["username", "displayName", "algorithm", "lane", "credentials"],
  "where": { "op": "and", "args": [
    { "op": "eq", "field": "mechanism", "value": "passkey" },
    { "op": "eq", "field": "role", "value": "primary" } ] },
  "limit": 500
}
```

How many passkeys there are, by role and algorithm:

```json
{
  "source": "credentialHolders",
  "where": { "op": "eq", "field": "mechanism", "value": "passkey" },
  "aggregate": "count",
  "groupBy": ["role", "algorithm"]
}
```

## The query document

The keys are `source`, `select`, `where`, `orderBy`, `limit`, `format`,
`mode`, `locale`, `aggregate` and `groupBy`. An unknown key is
`invalid_query`. A string body is refused, and the refusal does not
repeat what was sent.

`select` is the field ids to return. `format` is `json`, `csv` or `pdf`
(the default the API uses when the key is omitted is `json`). `mode` is
`auto`, `sync` or `async`. Omitted, it is `auto`. `locale` is a language
tag of at most 35 characters, such as `fil` or `zh-Hans`. Omit it, or
send null, and a PDF is drawn in English. The page sets it from the
user's language when it builds or saves a query.

`limit` is a positive whole number. Zero is `invalid_query`. Omit it and
the synchronous row cap is the limit the size check uses.

`orderBy` is a list of `{ "field", "dir" }` with `dir` `asc` or `desc`.

`where` is one filter, or `and`, `or` or `not`. `and` and `or` take
`args`, a list of 1 to 16 filters. `not` takes `arg`, one filter. A leaf
is `{ "op", "field", "value" }` or `{ "op", "field", "param" }`. A value
and a parameter together are refused. A parameter name is a string. The
bag is supplied beside a saved definition, not inside an ad hoc document
that already has `source`.

A field that is a list drawn as one string — `memberOf`, and the
`credentialHolders` source's `methodsUsed` —
is compared value by value under `eq`, `ne` and `in`: a person in three
groups matches `memberOf` equals any one of them. `contains` and
`startsWith` look at the joined string.

A string value is a string. A number is a finite JSON number. A boolean
is `true` or `false`. A timestamp is a finite number of epoch
milliseconds, or a string `Date.parse` accepts, at most 40 characters.

`aggregate` is `count` or omitted. `groupBy` without a count is refused.
A count's `select` is the group fields. The result rows carry those
fields and `count`.

`mode: auto` is answered in the same call when the source is bounded and
the limit is at most `report.syncMaxRows`. Otherwise it is a job.
`mode: sync` over that cap, or with no limit that fits, is
`result_too_large`. Over `report.asyncMaxRows` is `result_too_large` in
every mode. PDF over `report.pdfMaxRows` or `report.pdfMaxPages` is the
same refusal, and the sentence names CSV. A `users` query on a directory
held in a database that would have to read every person (see *Indexed
filters*) is `result_too_large` in `sync` mode and a job in `auto` mode,
whatever its limit.

### Examples

Equals, and a limit:

```json
{
  "source": "users",
  "select": ["username", "status"],
  "where": { "op": "eq", "field": "status", "value": "locked" },
  "limit": 100,
  "format": "json",
  "mode": "auto"
}
```

Does not equal:

```json
{ "op": "ne", "field": "status", "value": "active" }
```

Contains, and starts with:

```json
{ "op": "contains", "field": "displayName", "value": "Ada" }
```

```json
{ "op": "startsWith", "field": "username", "value": "a" }
```

`in` (API only; the form does not offer it):

```json
{ "op": "in", "field": "username", "value": ["ada", "bea"] }
```

Empty:

```json
{ "op": "isNull", "field": "mail" }
```

Number comparisons, on `groups.memberCount`:

```json
{ "op": "lt", "field": "memberCount", "value": 10 }
```

`le`, `gt` and `ge` are the same shape. A timestamp comparison uses the
same four operators and `eq` / `ne`, with an ISO-8601 string or a number
of epoch milliseconds.

Boolean:

```json
{ "op": "eq", "field": "enabled", "value": true }
```

And, or, and not:

```json
{
  "op": "and",
  "args": [
    { "op": "eq", "field": "status", "value": "active" },
    { "op": "startsWith", "field": "username", "value": "a" }
  ]
}
```

```json
{
  "op": "or",
  "args": [
    { "op": "eq", "field": "protocol", "value": "saml2" },
    { "op": "eq", "field": "protocol", "value": "oidc" }
  ]
}
```

```json
{ "op": "not", "arg": { "op": "eq", "field": "enabled", "value": false } }
```

A count per day:

```json
{
  "source": "authActivity",
  "select": ["day"],
  "aggregate": "count",
  "groupBy": ["day"],
  "orderBy": [{ "field": "day", "dir": "asc" }],
  "limit": 31,
  "format": "csv",
  "mode": "async"
}
```

A saved parameter. The document stores the name. The definition stores
the default. A run may override it:

```json
{ "op": "eq", "field": "username", "param": "who" }
```

```json
{ "who": "ada" }
```

## Running one now, and queueing one

`POST /report-api/queries` with the document.

A synchronous answer is HTTP 200. The body is the format you asked for.
JSON is `application/json`. CSV is `text/csv`. PDF is `application/pdf`.
The call is refused, whole, when the body would pass
`report.syncMaxBytes` or the clock passes `report.syncMaxMs`. Nothing
partial is sent. JSON always says `"truncated": false`.

A job is HTTP 202 and `{ "job": { … } }`. That is what `mode: async`
always does, and what `mode: auto` does when the limit does not fit the
synchronous cap. `POST /report-api/jobs` is the same document, forced to
a job even when it would have fit in one call. An ad hoc job does not
mail the owner.

Read it with `GET /report-api/jobs/{id}`. The states are `queued`,
`running`, `completed`, `failed`, `cancelled` and `expired`. When
`status` is `completed`, `GET /report-api/jobs/{id}/result` is the bytes,
as an attachment. Before that the result is `job_not_ready` (HTTP 409).
After `report.artifactRetentionS` it is `result_expired` (HTTP 410). A
job that ran longer than `report.asyncMaxMs` is `failed`, with
`result_too_large`. Nothing was stored in part.

`GET /report-api/jobs` is newest first. `after` is the previous page's
`next` id. `limit` is how many to return (1 to 200; omitted, 50). `next`
is null on the last page. Listing a job id does not authorize a job the
token cannot see.

`POST /report-api/jobs/{id}/cancel` cancels a queued job. A running job
is asked to stop and is not returned in part.

The owner and `report:admin` also receive the query document on
`GET /report-api/jobs/{id}`. Everyone else who can see the job receives
the status without that document.

## Saving and scheduling

`POST /report-api/definitions` stores a document under a name.

```json
{
  "name": "Locked accounts",
  "document": { "source": "users", "select": ["username"], "limit": 100 },
  "parameters": null,
  "schedule": "",
  "scheduleEnabled": false,
  "notify": false
}
```

`parameters` is the bag a schedule runs with: a plain object of at most
32 keys. A key is at most 64 characters. A value is a string of at most
200 characters, a finite number, a boolean, null, or an array of 1 to 32
of those scalars (what `in` needs). Omit `parameters` on a later
`POST /report-api/definitions/{id}` and the stored bag is kept. Send
`null` and it is cleared. A missing value can still be type-checked at
save time. The dummy used for that check is not stored, and the schedule
will not run until the value is saved.

`schedule` is a UTC cron expression, or empty. `scheduleEnabled` turns
it on. When the minute comes due, the service runs the document as the
owner, and only while that owner may still run reports. The stored
parameter bag is what the run uses. A name the document asks for and the
bag does not hold is written on the definition's failures, and that
occurrence is not consumed: the next pass runs once the value exists.
An owner who can no longer run reports, and a document that no longer
validates, do consume the occurrence. A queue that is already full does
not. A definition that already has a queued or running job of its own
waits for the next occurrence.

`POST /report-api/definitions/{id}/run` is always a job (HTTP 202). The
body is the parameter object, not a query document. A key overrides the
stored default. An empty object, or an empty body, uses the stored
defaults. The stored document already carries `locale`.

`notify: true` mails the owner when a scheduled run finishes
(`report-ready`). The message links to `/report/jobs/{id}`. It does not
contain rows. If the notice cannot be sent, the job still stands as
finished. Ad hoc queries do not notify. With no mail transport, or no
`global.publicBaseUrl`, the notice is skipped.

`GET /report-api/definitions` lists what you may see.
`GET /report-api/definitions/{id}` is one. The document, the parameter
bag, the groups and the recent failures are on the answer when you may
edit it. `DELETE /report-api/definitions/{id}` removes it. A share cannot
delete.

## Formats

All three formats are the same rows. Column names are the catalog field
ids. An empty result is still a whole answer: JSON has `"rows": []`, CSV
is the header line and nothing else, and PDF is one page with the header
and no data rows.

**JSON.** UTF-8. An object:

```json
{
  "source": "users",
  "fields": ["username"],
  "rows": [{ "username": "ada" }],
  "truncated": false
}
```

A string stays a string. A number stays a number. A boolean stays a
boolean. Null stays null. A timestamp is an ISO-8601 string.
`truncated` is always false.

**CSV.** UTF-8, CRLF, RFC 4180. The first line is the field ids. A null
is an empty field. A field is quoted when it contains a comma, a
quotation mark, CR or LF. A quotation mark inside a quoted field is
doubled.

**PDF.** PDF 1.4, Helvetica, WinAnsi, US Letter. A value wraps within
its column: a long value takes as many lines as it needs, broken at a
space where one falls within the line, and a line feed in a value starts
a new line. A cell draws at most 256 bytes; a longer value is cut there
and ends in `...`. A row is as tall as its tallest cell. Forty lines of
data fit on a page, so forty single-line rows do; a row that does not
fit in what is left of a page starts the next page, and a row taller
than a whole page continues on the next. Past `report.pdfMaxRows`, or
past `report.pdfMaxPages` for the pages the wrapped rows need, the call
is refused and asked to use CSV. A character WinAnsi cannot draw is `?`.
The page names the report, the realm, the language and the time. Those
words are drawn in English, Spanish, French, German, Filipino and
Swedish. Chinese is drawn in English, and the page adds
`Requested language:` and the tag you asked for (`zh-Hans` or
`zh-Hant`). A number is its decimal text. A boolean is `true` or
`false`. Null is blank.

## Errors

The body is `{ "error", "error_description" }`. `error` is the public
token. The description is one English sentence. The `STS-REPORT-` code
is recorded and logged. It is not in the body.

| Token | HTTP | When |
|---|---|---|
| `unknown_source` | 404 | The catalog has no such source. |
| `unknown_field` | 400 | The source has no such field, including a credential id. |
| `unsupported_operation` | 400 | The operator, the aggregate or the filter is not allowed on that field. |
| `unsupported_format` | 400 | The format is not `json`, `csv` or `pdf`. |
| `invalid_query` | 400 | The document, the parameter bag, the share list or the definition is the wrong shape. A SQL string, an offset and a second source land here. |
| `result_too_large` | 400 | The row cap, the byte cap, the synchronous time cap, a PDF over its cap, or a synchronous `users` query that would have to read every person of a directory held in a database (see *Indexed filters*; in `auto` mode that query is a job instead). On a **job**, the same token means the job passed `report.asyncMaxMs` or could not store the bytes. The HTTP status of the original submission was already 202. |
| `invalid_token` | 401 | No token, a token that did not verify, an expired token, a token that is not an access token, the wrong issuer, a revoked token, a disabled account, a session that has ended, or a certificate-bound token without that certificate. |
| `invalid_dpop_proof` | 401 | A DPoP-bound token sent as Bearer, or a proof this service refused. |
| `invalid_token` | 403 | The token is not audienced to this realm's `/report-api`. |
| `insufficient_scope` | 403 | The token lacks `report:use` or `report:admin`. |
| `forbidden` | 403 | The token names no person, or this account may not use reports here. |
| `not_found` | 404 | No such definition, including one you may not see. |
| `job_not_found` | 404 | No such job, including one you may not see. An unknown API path is answered the same way. |
| `job_not_ready` | 409 | The result was asked for before the job completed. |
| `result_expired` | 410 | The artifact aged out, or the job completed and the bytes are gone. |
| `too_many_jobs` | 429 | This person or this realm already has as many queued and running jobs as the queue allows. |
| `unavailable` | 400 | A report could not be completed. The code's own note says 500; this API answers 400. |

`GET` or `HEAD` is the only method on `/report` itself. Anything else is
HTTP 404.

What to check when a schedule does nothing:

- The definition's failures, visible to the owner and to `report:admin`.
  "A saved parameter was not given" means the slot was kept. Save the
  value and the next pass can run.
- "The owner can no longer run reports" means `report:use` was lost.
  That occurrence was consumed.
- A queue that answered `too_many_jobs` did not consume the occurrence.
- The cron expression is UTC. `* * * * *` is every minute.
- In a cluster, `STS_REPORT_NODE=true` on one service holds
  `ops.reporting`. The other fronts leave the queue to it while that
  stamp is live. The [compose stack](docker-compose.md) says how to pass
  the variable. It is not set on the default `sts` service.

## Security

Send `Authorization: DPoP` and the proof. The token is for `sts-report`,
audienced to this realm's `/report-api`, with `report:use` or
`report:admin`. Paths sit after the realm prefix. The default realm has
none.

A job id, a definition id and a share are not credentials. Retrieving a
result takes the same token the query took. Group share is run and
retrieve. Edit and delete stay with the owner and with `report:admin`.

The catalog does not publish credential attributes. Audit detail on a
report action is the source, the field ids and the job id. The query
document is not written on the audit row. An attribute-source report
does not include the host, the account or the secret, and it does not
open a connection.

Completion mail is opt-in on the definition, goes to the owner's
account address, and carries a link rather than rows. A mail failure
does not fail the job.

## Statistics that stay where they are

`serviceMetrics` does not replace the console's counters. These
endpoints stay, and a caller that needs what they show keeps calling
them. The difference is the point of this section.

**`GET /admin/metrics` and `GET /admin-api/metrics`** are the live
picture the console draws. Calls by the route Express matched, with
status classes, average and worst latency, and when each was last
called. Tokens by `typ`, with valid, expired, revoked, not-yet-valid
and DPoP-bound. Assertions, tickets and credentials the same way. A
successful `GET` or `HEAD` of `/healthcheck` is not in the call total.
Sessions are reported twice on purpose: sign-on sessions, and
artifact-derived sessions. Within Kerberos a TGT counts as the session
and a service ticket does not. The page is computed when it is drawn.
[Metrics](admin-console.md#metrics--adminmetrics) is that page.

`serviceMetrics` keeps a finite number sitting one level under a family
in that snapshot, read with the user counts left out. A name looks like
`calls.total` or `tokens.held`. It does not keep:

- the top-level `startedAt`, `uptimeMs` and `now`
- `calls.rows`, the per-route table, or `calls.byStatusClass`
- `tokens.byKind` and `artifacts.byKind`
- `sessions.families` (the per-family subject lists). `sessions.distinctSubjects`
  is the one session number that is a leaf
- the user counts a dashboard shows. The report asks for the snapshot
  without walking people, so `users.known`, `users.authenticatedHere`,
  `users.clients` and `users.authentications` are 0. `users.cap` and
  `users.forgotten` are still the real counters. The directory itself is
  the `users` source

It is one moment, not a series. There is no latency column and no
per-route row.

**`GET /admin-api/status`** is the issuer, `startedAt` and the running
totals. **`GET /admin-api/console/dashboard`** mirrors those totals.
Neither is a report.

**`GET /admin-api/database`** is whether PostgreSQL is there, and its
statistics when it is. The answer is `available: false` when this
process has no database. That is not `serviceMetrics`.

**`GET /admin-api/risk/metrics`** is risk scoring. **`GET /admin-api/vc-status`**
is credential status. Neither is a service counter, and neither moved.

## A dedicated reporting node

With the cluster off, the front process drains the queue, drops expired
results and enqueues schedules that are due. Nothing else has to be set.

In a cluster, set `STS_REPORT_NODE` to the string `true` on the service
that should hold the lease `ops.reporting`. Leave it unset on the
default `sts` service. While a reporting node is live, the other fronts
leave the queue to it. The process that holds the lease drains, retains
and schedules on its own.

A running job's fence is held in the process that claimed it. If that
process is gone, the job is failed. Another node does not finish it.
