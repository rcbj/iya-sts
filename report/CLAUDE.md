# CLAUDE.md — `report/`

## A STATIC APPLICATION (#956) — READ THIS FIRST

`/report` and every path under it answer one document (`report_app.ts`),
which loads `/report/report.js` and `/report/report.css`. The script is
built as `report/report-spa.js` (`ReportRuntime extends SpaClient`,
`common/web_spa_client.ts`) and served at `/report/report.js`. It signs in
in the browser as the public client `sts-report` (PKCE S256, `resource`
the realm's `/report-api`, scopes `report:use` and `report:admin`), holds
a DPoP-bound token in memory, and draws every page from `/report-api`.
In product that `resource` is a registered target because `/report-api`
is one of this service's own resource servers
(`common/registered_targets.ts`), compared whole, as `/account-api` is.
Each realm is also seeded with `sts-report-api`, the application that
defines `report:use` and `report:admin` (`oauthPermission`, base this
realm's `/report-api`). `sts-report` holds both as delegated permissions
and declares the same two words on its registration `scope` and
`oauthGlobalConsent`, which is how `admin:read` and `admin:write` sit on
`sts-admin-console`. The browser asks for the words. A start that finds
`sts-report` already present adds a missing grant and a missing declared
scope, and does not rewrite consent, redirects or secrets.
`common/applications.js` seeds both, in every realm.
With `authn.multipleAccounts` on, the account control is the console's
menu: the summary is the account this tab is, and the panel lists the
browser's other signed-in accounts as switch buttons, plus a sign-in as
another account. The panel is taken out of flow, so opening it does not
push the page down. A switch is this tab's own authorization request
(`login_hint`, and the subject the answer must be for). The account the
tab leaves stays signed in. Off, the control is not drawn.
The shell's policy is `script-src 'self'`, `style-src 'self'`, and
`connect-src` the origins of the authorization server and the sign-in
screen, through `app.contentSecurityPolicy()`. The front door links to it
(`home/home.ts`). `docs/reporting.md` is the operator's page. The caps are the Reporting group in `common/config.js`
and `docs/configuration.md`.

| File | What it is |
|---|---|
| `report_app.ts` | The shell, the script and the stylesheet. A non-GET is 404 with `STS-REPORT-0033`. |
| `report_api.ts` | `/report-api`. Every route, including the catalog and the OpenAPI document, takes the token below. |
| `web_report.ts`, `web_report_pages.ts` | The browser runtime and the four pages (catalog, query, definitions, jobs). |
| `catalog.ts` | The ten sources and their fields, and which operators the store indexes (`indexed`, #985). Credential attribute ids are absent, so they cannot be named. |
| `openapi.ts` | `GET /report-api/openapi.json`. Every released route, built from the catalog that is loaded. |
| `query.ts` | Validates one JSON document and decides sync or async. It sends no HTTP response. |
| `limits.ts` | The caps, read when asked. `Limits.fixed` is what a test passes. |
| `formats.ts` | JSON, RFC 4180 CSV, and a PDF 1.4 file in Helvetica WinAnsi. |
| `rows.ts`, `sources.ts`, `executor.ts` | Reading one source, bounded, and writing the artifact. |
| `rights.ts` | Who may be issued the two scopes, and who may see or edit a row. |
| `jobs.ts` | Definitions, the queue, and the six scheduler jobs. |
| `stores.ts` | Realm maps for definitions, jobs and the reporter stamp. Artifact bytes go beside them. |

## The chrome (#986)

rcbj asked for five things on 2026-10-26, all drawn by
`web_report_pages.ts` from `/report-api` answers, the surface rule:

* **Two bars**: a smaller right-justified `.topbar` above with the
  controls about the reader — the realm field, the language chooser, the
  user menu, in that order — and the `.bar` below with the pages and
  Refresh (rcbj, the same day, after seeing the one bar).
* **The trust realm**, first in the top bar, on the console's switcher shape
  (`admin-ui/web_shell.ts`'s `realmChooser()`): the label, a select of
  the realms and a Go button where the service has several, the one
  realm's name otherwise. `GET /report-api/realms` answers the current
  realm and, where `realms.active()`, every realm as `{ id, name, prefix }`
  — the console's shell rows (`admin.ts`, `shellJson()`); it is taken with
  the report token like every route, and tells a holder nothing the
  anonymous realm chooser does not. A choice (the select's change, or Go)
  LEAVES THE PAGE for `<origin><prefix>/report<same path>`: the token in
  hand is audienced to this realm's `/report-api`, so the other realm's
  page signs in as any first load does. The console switches in place
  because its token is the service's; this one is the realm's.
* **A documentation link** under the bar, `DocLinks.markup()` to
  `reporting.html` on the site every surface links to.
* **The version** under the card, from the index's `version` (`GET
  /report-api` carries `common/version.js`'s `load()` as the console's
  shell does; `tests/version.js` lists `report_api.ts` among the drawers).
* **One filter row to begin with**, and the `+` on the last row adds the
  next: the runtime clones the last row, renames its controls to the next
  index, empties them and moves the `+`; `queryDocument()` reads rows
  until the first index with no field control, at most sixteen (an
  `and`'s cap). Nothing is stored for a template.
* **A Save query box**: the Name field and the Save button carry
  `save-only` and `hidden` until it is ticked (`onChange()`); unticked,
  the form runs and saves nothing. **Save is FIRST in the document and
  `disabled` as well as hidden until then** (`actionsHtml()`): Enter in a
  text box activates the form's default button — the first submit button
  in tree order that is not disabled, hidden or not — and with Run first,
  Enter in the Name box ran the query instead of saving it (rcbj,
  2026-10-26: on 8081 that run became a job, and the job page's row count
  was what came back). `.actions .save-only { order: 2 }` draws Save after
  Run.
* **Sign out is in the user menu**, which is therefore drawn for every
  signed-in person; the switch group inside it still appears only with
  `authn.multipleAccounts` on, as before.

The index, the realms view and the version are read once per load
(`ensureChrome()`), after the token is in hand. `tests/report_query.js`'s
`chrome()` holds the realm field's two shapes, the footer, a row with and
without the `+`, and the variable reader over a form double; what it does
not hold is the browser's cloning and the navigation.

## The document

A query is a JSON document: `source`, `select`, `where`, `orderBy`,
`limit`, `format`, `mode`, `locale`, `aggregate`, `groupBy`. One source.
An unknown key is refused. A string, a `query` string, or a second source
(`sources`, or `source` as an array) is `invalid_query`
(`STS-REPORT-0004`), and the refusal does not repeat what was sent.

The catalog is checked before the size cap, so `userPassword` and the
other credential ids are `unknown_field` (`STS-REPORT-0002`) even when the
limit is also too big. Operators are the catalog's per type. `aggregate`
is only `count`. `groupBy` without a count is refused.

`mode: auto` is synchronous when the source is bounded and the limit fits
`report.syncMaxRows`, and a job otherwise. `mode: sync` on an unbounded
source, or over that cap, is `result_too_large` (`STS-REPORT-0005`). Over
`report.asyncMaxRows` is the same refusal in every mode. A limit of 0 is
`invalid_query`. PDF over `report.pdfMaxRows` is refused with the CSV
sentence. `truncated` is always false: a body over `report.syncMaxBytes`
or a sync call over `report.syncMaxMs` is refused rather than sent in
part. A job over `report.asyncMaxMs` fails the same public token,
`result_too_large`, under `STS-REPORT-0034`. The submission has already
answered. Nothing is stored in part.

PDF chrome exists in English, Spanish, French, German, Filipino and
Swedish. Helvetica WinAnsi can draw those. Chinese is drawn in English,
and the page says which language was asked for (`Requested language:
zh-Hans`, or `zh-Hant`). Column headers stay the catalog field ids. The
browser puts the signed-in user's language on the document when it is
built or saved. A later run of that definition posts parameters only, so
the stored document is what the job is drawn in. The API does not fill
the language in, and its errors stay English.

Every standard source says `paging: limit` and `relationships: []`. An
`offset`, a second source and a SQL statement are `invalid_query`. There
is no join. The `in` operator is on string and number fields. The query
form does not offer it; a caller sends an array of one to fifty values.

`users.status` is `locked` when `pwdAccountLockedTime` is set. That value
is the administrative disable and any other lock. The users reader does
not call `account_state.isDisabled`. A scheduled run does not either.

## A filter the store can answer is asked of the store (#985)

On 2026-10-26, on the 8081 installation with about fifty million people,
`username equals rcbj` with the default limit hit `STS-REPORT-0005` every
time: `reportReadUsers()` built the group index, paged every person,
fetched each entry again with `existingUserEntry()`, and applied the
filter only in `Rows.take()`, which keeps paging past a row that does not
match. A job would have met `STS-REPORT-0034` the same way.

**The directory already answers the question, and the rule is to ask
it.** A person's attributes are one sealed AES-GCM value in the store, so
nothing can filter on most of them there; beside the sealed value the row
keeps keyed digests of `uid`, `mail` and `entryUUID` with GIN indexes, and
the RDN value — the `uid`, in the clear, lower-cased — with a trigram
index (`persistence/directory_queries.js`, `sts_ldap_entries_uid_trgm`,
2026-10-20 for `/portal/delegate`). The catalog says which operators each
field is indexed for (`FieldSpec.indexed`; `username` for `eq`, `in`,
`contains`, `startsWith`; `mail` and `entryUuid` for `eq`, `in`; nothing
else), `/report-api/catalog` and the OpenAPI document publish it, and the
source page draws it as the Indexed column with one explaining sentence.
`Catalog.operatorsFor()` still offers `contains` on every string field: a
filter on a sealed field is applied in process, after the indexed one has
named the candidates.

`reportIndexedLookups()` reads the plan's `where` the way
`ldap_server.js`'s `indexedLookupsOf()` reads an LDAP filter: a leaf on an
indexed field and operator is one lookup (`eq`/`in` exact; `contains` and
`startsWith` on `username` the trigram SUPERSET, lower-cased, three
characters or more), an `and` is the lookups of ONE arm (an exact arm
preferred to a substring one), an `or` the lookups of EVERY arm or
nothing, at most sixteen; `not`, `ne`, `isNull` and a sealed field name
nothing. `reportCandidates()` resolves them through the directory's own
doors — `existingUserEntriesAsync()` (`byName`, or the in-memory username
index), `entriesByUuidsAsync()`, the window's `byMail` and
`uidContainsAsync()` — each person once, projections and entries with no
`uid` left out as the walk leaves them, and offers only those rows;
`Rows.take()` applies the whole filter, so the answer is the walk's. The
groups of a candidate come from `groupsOfUser()` (the group index every
token reads), listed-by-the-group only, not from a pass over `ou=groups`.
A lookup the store could not answer whole — a memory directory asked a
substring or an address, or an answer that filled `CANDIDATE_CAP` — falls
back to the walk.

**A synchronous read that would have to see everybody on a windowed
directory is refused BEFORE the walk starts**: no indexed lookup, and a
filter, an order or a count (`reportMustVisitEverybody()`;
`STS-REPORT-0036`, public token `result_too_large`, the description
naming the indexed fields from the catalog). A plain unordered read with
no filter stops at its limit and still walks. `report_api.ts` turns the
refusal of a `mode: auto` query into a job — `auto` means "a job when it
cannot be answered now" — and records no refusal; `mode: sync` keeps it.
A job (`execution: 'async'`) is never refused here; `report.asyncMaxMs`
bounds it. The memory directory walks as it always did: it is in process
and small by construction.

The directory is reached through `reportLdap()`, which answers the double
a test installs with `installDirectory()` or `ldap/ldap_server.js`.
`tests/report_query.js`'s `narrowing()` drives the planner, every lookup
door, the refusal, the auto/async distinction and the memory fallback
against a counted double. **What it does not hold**: a real windowed
directory, which needs a postgres store; `report_api.ts`'s auto-to-job
turn; and the timing on 8081.

## Who may run one

`report:admin` sees every definition and every job in the realm.
`report:use` sees the rows it owns, and the rows shared with a directory
group it belongs to. A share is run and retrieve. Edit and delete stay
with the owner and with `report:admin`. An unknown id and a forbidden id
are the same answer: `not_found` / "No such definition." for a definition
(`STS-REPORT-0019`), `job_not_found` for a job (`STS-REPORT-0020`).

Issuance narrows, and only removes. `oauth2` calls `reportNarrowScope` at
both issuance sites, lazily, and returns before reading
`report.usersGroup` when the scope being issued names neither report
scope. An application subject (`client_credentials`) keeps neither. A
person in Admin Read or Admin Write keeps `report:admin` when they asked,
and keeps `report:use` when they asked, even when `report.usersGroup` is
empty. Anyone else keeps `report:use` only as a member of that group, and
never `report:admin`. Empty `report.usersGroup` therefore means only
administrators are issued `report:use`. The membership probe is
`(username, groupKey)` with the raw group name, not a DN.

A scheduled run asks the same question of the definition's owner. It does
not ask `account_state.isDisabled`: that read walks the directory, and a
job must not.

The definition stores `parameters`, the values that schedule runs with.
A save may still be type-checked with a dummy of a missing parameter.
That dummy is not stored, and a schedule does not run on it. A parameter
the document names and the bag does not hold is `STS-REPORT-0035`: the
occurrence is noted and `lastSlot` stays where it was, so the next pass
can run once the value is saved. An owner who lost `report:use`, and a
query that no longer validates, do consume the slot (`STS-REPORT-0028`).
A submit that fails, including `too_many_jobs`, does not. A busy
definition (a queued or running job of its own) does. A manual run posts
a parameter object. A key in that body overrides the stored default. An
empty body uses the stored defaults.

## The six jobs, and the lease

Registered at load, after the scheduler is in hand (`common/protocol_stack.ts`,
18i-report), so every process lists the same six:

| Job | Kind | When the body runs |
|---|---|---|
| `report.drain` | cluster, realm, **front**, 2 s | Claims queued jobs up to the running caps and writes each artifact. |
| `report.retention` | cluster, realm, **front**, 60 s | Drops artifacts and finished rows past their retention, and fails a running job whose fence is gone. |
| `report.schedule` | cluster, realm, **front**, 60 s | Enqueues each due definition as its owner, while that owner can still run it, using the stored parameter defaults. |
| `report.drain.here`, `report.retention.here`, `report.schedule.here` | per-process, realm, quiet | The same three bodies, only while this process holds `ops.reporting`. |

The fence is a set in this process, which is why the three cluster jobs
carry `onFront`. A worker does not share it. With the cluster off, those
three run on the front and the lease is not offered. In a cluster they run
on a front that does not itself hold `ops.reporting` and sees no other
reporter still live. `STS_REPORT_NODE=true` is the only opt-in:
`reportOfferLease` calls `cluster.lead('ops.reporting')` only then. The
`.here` jobs are what that holder runs, because `reportClusterRuns` is
false for the holder. The variable stays off `AGREEMENT_SETTINGS` and off
the default compose service.

An enqueue is refused (`STS-REPORT-0023`, HTTP 429) when the subject
already has more queued and running jobs than
`max(8, maxConcurrentPerSubject * 4)`, or the realm more than
`max(32, maxConcurrentPerRealm * 8)`. The settings themselves cap jobs
actually running, applied at claim. When both ceilings are full the
refusal is the realm's. The call does not answer 503.

`sources.ts` walks people only through `reportEachEntry`, and only when
the directory is not windowed. The windowed path is a page after a cursor.
Eight `reportGate*` functions pad the text the directory-walk scanner
follows; `reportGateEight` is the last, and it names no directory read.
The job bodies call `reportGateOne` by that name. Do not collapse the pads.

## Where a row lives

Definitions and job rows are `realms.map` (`report.definitions`,
`report.jobs`). The reporter heartbeat is `report.control` key `reporter`,
written with `realms.run(null, …)` so every realm sees one stamp. Artifact
bytes are `sts_report_artifacts` (schema version 26) when the driver has
`putReportArtifact`, `getReportArtifact` and `deleteReportArtifact`.
Otherwise they stay in a map in this process, keyed by realm and job id.
`persistence.js` installs the driver lazily and does not require
`report/jobs`. A delete removes the memory copy as well as the row.

Audit detail is the source, the field ids and the job id. The query
document is not written on the row.

## What the tests hold

`tests/report_query.js` holds the document, the three formats, the fixed
limits (including `asyncMaxMs`), issuance narrowing, an in-memory
artifact, the two added sources' row projections, the OpenAPI paths, an
in-memory schedule that uses stored parameter defaults, and the indexed
lookups against a directory double (#985). It does not open a listener. A
refusal's HTTP status, the DPoP gate and a scheduled run against a
directory are not asserted here.

## The sources

The ten sources are `users`, `groups`, `applications`, `federation`,
`authMechanisms`, `auditEvents`, `authActivity`, `serviceMetrics`,
`reportJobs` and `attributeSources`. `authMechanisms` is the realm policy
(application `realm`) plus one row per value an application lists in
`appAuthnMechanism` or `appMfaMechanism`. An empty list inherits the
realm policy and adds no row. `authActivity` is the four attempt actions
still in the audit ring (`authentication`, `authentication.refused`,
`session.refuse`, `session.refused`). `mechanism` is `detail.method`, or
`detail.amr` when the row has no method. A session id, an address, a note
and a presented credential are not fields. `attributeSources` is the
register. It does not run SQL and it does not read the remote table.
Connection details and secrets are not fields. `serviceMetrics` is one
level of numeric leaves from `admin_stats.snapshot({ withoutUsers: true })`.
It is not a time series, and it is not the per-route or per-kind tables.
`/admin/metrics` and `/admin-api/metrics` stay. `docs/reporting.md` is
the migration note.
