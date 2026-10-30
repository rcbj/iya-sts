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
`sts-report` declares the two words on its registration `scope` and
`oauthGlobalConsent`, which is how `admin:read` and `admin:write` sit on
`sts-admin-console`, and the browser asks for the words. **Until #1030
(2026-10-27) a resource application `sts-report-api` defined the two as
delegated permissions and `sts-report` held the grant**; the bare words
with `resource` never consult a grant, so it decided nothing and both
are gone (*Who may run one*, below). `common/applications.js` seeds
`sts-report`, in every realm.
**`sts-report-api` IS BACK SINCE #1139 (2026-10-29), as something else**:
the reports API's own application object, an OAuth 2.0 RESOURCE of kind
`oauth2-resource-server` holding the audience (`oauthAudience`, the seeded
base + `/report-api`) — rcbj's model, in which every API is an object and a
caller is always a separate client configured to call it. It defines no
permission and holds no grant, so #1030's argument still stands, and it is
NEVER a client: `oauth-oidc/oauth2.ts` refuses its client_id everywhere a
client presents itself (`STS-OAUTH-0985`; `common/CLAUDE.md` has the four
resource objects). The machine caller is `sts-api-client`, seeded a member
of REPORT_USE (`common/roles.js`) and declaring `report:use`; as an
application it reaches only what it defined (`ownerKind`, below), and its
`client_credentials` token is unbound, so it arrives as `Bearer`.
`docs/reporting.md`'s *From another program* is the operator's half.
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
| `catalog.ts` | The seventeen sources and their fields, which operators the store indexes (`indexed`, #985), and a source's predefined queries (`presets`, #1110). Credential attribute ids are absent, so they cannot be named. |
| `passkey_ceremonies.ts` | The `passkeyCeremonies` source's projection of the ceremony audit rows (#1107). A library; reaches `authn/webauthn_ceremonies` lazily. |
| `openapi.ts` | `GET /report-api/openapi.json`. Every released route, built from the catalog that is loaded. |
| `query.ts` | Validates one JSON document and decides sync or async. It sends no HTTP response. |
| `limits.ts` | The caps, read when asked. `Limits.fixed` is what a test passes. |
| `formats.ts` | JSON, RFC 4180 CSV, and a PDF 1.4 file in Helvetica WinAnsi. A PDF cell wraps within its column, up to 256 bytes, and a row is as tall as its tallest cell (#993); the file's header argues the pagination. |
| `rows.ts`, `sources.ts`, `executor.ts` | Reading one source, bounded, and writing the artifact. |
| `passkey_history.ts` | The `passkeyHistory` source's projection (#1109): one stored day of `passkey_report.history` into a row per `scope`. A library; reaches `common/passkey_report` lazily. |
| `rights.ts` | The caller as held ∩ carried, and every question about the API, a definition or a job put to `common/access_gate.ts`. It decides nothing (#1030). |
| `jobs.ts` | Definitions, the queue, the six scheduler jobs, and the registration of `staging.ts`'s seventh. |
| `staging.ts` | A job's report built as a file in `risk.uploadDirectory`, its room checked first, removed when the job ends; the per-process `report.build-cleanup` job (#1045). |
| `stores.ts` | Realm maps for definitions, jobs and the reporter stamp. Artifact bytes go beside them, in sealed pieces since #1045. |

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
  `authn.multipleAccounts` on, as before. **Every control in the top bar
  is drawn by one rule** (`.topbar select, button, .usermenu > summary`),
  after the language chooser came out with the browser's own background
  and the menu with its own shape.
* **A job says why it is a job**: `reportSubmit()` records
  `queuedBecause` (`every-person`, `asked`, `limit`, `source`, `run`,
  `schedule`), the API sets it from the caller or the plan, `jobView`
  carries it and `becauseHtml()` draws one sentence. A row queued before
  the field existed draws nothing.
* **The owner by name**: `reportOwnerName()` resolves the subject through
  `helpers.nameForSubject()` and the entry's `displayName` or `cn`, the
  directory required lazily (rule 1); the subject stays on the API.
* **The schedule editor**: a `datetime-local` read as UTC and seven
  weekday boxes compose the five-field cron the API keeps
  (`scheduleCronOf()`: weekdays → `m h * * d,d`; none → `m h D M *`), and
  `scheduleFieldsOf()` reads one back where it can; the expression is
  always shown under the controls. Weekday names are Intl's in the page's
  language, so they cost no catalog.

The index, the realms view and the version are read once per load
(`ensureChrome()`), after the token is in hand. `tests/report_query.js`'s
`chrome()` holds the realm field's two shapes, the footer, a row with and
without the `+`, and the variable reader over a form double; what it does
not hold is the browser's cloning and the navigation.

## The definition page, and who is emailed (#989)

rcbj, 2026-10-26, after seeing #986's page. Four things:

* **The query is edited with the New Query form's own controls.**
  `queryFormHtml(t, sources, document)` draws both pages; the definition
  page fills it from the saved document (source, fields, filter rows,
  sort, limit, format, count and group-by), and Save reads the document
  off the form with `queryDocument()` as New Query does. A filter the
  rows cannot draw — an `or`, a `not`, an `in`, a value that is not a
  string or number — is shown as JSON and rides back on a hidden
  `whereJson` until a row is filled in (`whereLeaves()` decides). A
  change of source redraws the query block empty for the new fields.
* **The groups pane**: `GET /report-api/groups?q=&page=` is
  `sources.groupSearch()`, a case-insensitive substring over the realm's
  resident groups (`allGroupEntries()`), five a page in name order, each
  with its own `mail`. The page draws the hits with an Add each and a
  Previous/Next pager, and the chosen groups as a list of hidden
  `group` inputs with a Remove each; Save posts the definition, then the
  list to the share endpoint. Enter in the search box searches (a
  keydown handler), not saves. Save and Delete are real buttons at the
  foot, in a two-column `.editor`.
* **The shared groups are emailed the result.** `reportNotify()` calls
  `reportNotifyGroups()` first: `reportGroupRecipients()` splits the
  definition's groups into those with a `mail` attribute and those
  without; each of the first is sent the `report-ready` notice through
  the mail channel's new group recipient (`groupDn`, resolved by the
  directory, `common/CLAUDE.md` 3ba), with a dedup key per job and group;
  each of the second is **`STS-REPORT-0037`**, logged with `log.error`
  and written on the audit row (`report.notify`, outcome `error`, the
  group's DN in the detail), and the others are still sent to. The
  owner's notice is unchanged. A group's address is set on the console's
  group page or at its create (`ldap/CLAUDE.md`).
* **A tooltip on every field** (rcbj, the same day), the console's shape:
  `tip(t, key)` puts a `title` on the field's label from a `report.tip*`
  sentence (`admin-ui/web_kit.ts`'s `tip()` is the model). A new field
  owes a `tipX` key in the seven base catalogs.
* **The schedule's status** (rcbj: a schedule set, no job seen):
  `jobs.scheduleTimes()` puts `nextRunAt` (croner's `cronNext`) and
  `lastSlotAt` on the definition view, and `scheduleStatusHtml()` draws
  them under the editor with one sentence on how a schedule runs and the
  `failures` notes the schedule job left. The mechanism itself is
  unchanged: `lastSlot` starts null, so the first pass after an enabled
  save queues the most recent PAST occurrence within a minute, and each
  later occurrence follows; a save with Enabled clear keeps the schedule
  and never runs.
* **`GET /report-api/schedules` (#992)**: `reportSchedulesView(who, query)`
  — the scheduled definitions the caller may see (`rights.canSee`, so
  owned and shared for `report:use`, the realm for `report:admin`), each
  with `jobs.scheduleTimes()`, its last three notes and its five newest
  jobs whose `queuedBecause` is `schedule`. `?owner=` (a subject or a
  username through `helpers.subjectForName()`) is an administrator's;
  `report:use` naming anyone but itself is `STS-REPORT-0038`, refused
  rather than narrowed, so an answer never means something other than
  what was asked. No page draws it yet.
* **The status bubble** (rcbj, after Download said only "Something went
  wrong"): `flash(kind, text)` puts the console's `.flash` — sticky at the
  top of the card, `ok` or `err`, a dismiss — at the head of `#report`,
  one at a time, and every act reports there: saved, deleted, queued as a
  job, a refused run or save (the form stays), a failed download. **The
  download bug**: `call()` read every `application/json` answer as the
  API's JSON, so a JSON-format result had no `bytes`; `call(…, { raw:
  true })` reads a 200 as bytes whatever its type and a refusal as JSON
  for its description, and the message names the status when there is
  none.
* **The Parameters box explained**: `parametersHelpHtml()` under the Run
  box names the parameters the saved filter holds (`paramNames()` walks
  `param` leaves through `and`, `or` and `not`) or says it holds none and
  the box is ignored, then gives the shape and one example. The query
  form writes values, never parameters, so a page-made definition names
  none; a parameterised one is written through the API.
* `tests/report_query.js`'s `groups()` holds the search's paging and
  matching, the recipients split, the form's prefill in every shape, the
  JSON ride-back, the pane's markup, the tooltips and the parameters
  sentence; `tests/mail.js` the group
  recipient; `tests/directory_group_writes.js` the address on the entry.
  Not held in process: the browser's Add/Remove and search, and a notice
  sent to a real transport.

## The two lists are paged (#997)

`reportPaging()` turns `page` and `per` (50 unless asked, at most 200)
into a slice, and `reportDefinitionsView()` and `reportJobsView()` answer
`page`, `pages`, `per` and `total` beside their rows; the jobs view keeps
the cursor walk (`after`, `limit`) and answers it with no page number.
The page draws `pagerHtml()` above and below each table — the console's
`pageNavPair()` and `perPageForm()` as one line: first/previous, a window
of seven numbers with the current marked, next/last, the where line, and a
rows-per-page select — every page a link under the list's own path with
`?page=&per=`, so the back button and a shared address work; the select
moves to page one through the location (`onChange()`, `data-pager-path`).
`tests/report_query.js` holds both views' paging and the pager's markup.

## One row per credential (#1011)

rcbj, 2026-10-27: "the algorithms field is a comma-separated list; I
need a separate row for each passkey + algorithm — the reports we need
require this granular data." A `credentialHolders` row was a person's
credentials of one mechanism and role with the algorithms joined, so a
count by algorithm counted people. Now `reportHolderRows()` makes a row
per credential — a passkey per key, another mechanism per attribute value
— with `credentialId`, a single `algorithm` and `lane`, and its own
`enrolledAt`/`lastUsedAt`; `credentials` stays the person's count of that
mechanism and role on each of their rows, so grouping by `username` still
answers how many each holds. `algorithms`/`lanes` left the catalog, the
GROUPABLE list and `rows.ts`'s `LIST_FIELDS` (a single value needs no
splitting); `lane` is enumerated (#1007). Nothing changed in what is
read: the same holders, the same entries, more rows out of each.

## One rule for every filter row (#1028)

rcbj, 2026-10-27: index the unencrypted filter fields; a field with no
index is not a search parameter; a field with 20 or fewer values is a
dropdown; a date is a date-time picker; "as cookie-cutter as possible";
no query a user can build may scan. `web_report_pages.ts` now has ONE
rule, driven by the catalog:

* **A field's kind** (`kindOf()`): `choice` (catalog `values`, at most
  `CHOICE_MAX` = 20, or a boolean as true/false), `time` (a timestamp),
  `number`, `text`. **The kind decides the operators** (`OPS_OF`: choice
  eq/ne/isNull; time ge/gt/le/lt/isNull; number the six comparisons and
  isNull; text eq/ne/contains/startsWith/isNull) **and the control**
  (`filterValueHtml()`: a dropdown, a `datetime-local` read as UTC, a
  number box, a text box), and the control carries `data-type`, so
  `queryDocument()` sends a number, a boolean, or ISO UTC text — the API
  refused the strings it sent before.
* **The anchoring first row** of a directory source (#1027) narrows the
  kind's operators to the field's index (`opsFor(spec, true)`): the
  username box offers eq/contains/startsWith, a date ge/gt/le/lt,
  `mechanism` equals. `redrawFilterRow()` redraws the operator select
  whenever the list differs (`data-ops` is the list itself).
* **Finite fields** got `values`: applications.status, authMechanisms.type,
  reportJobs.status and .format, credentialHolders.format,
  attributeSources.dialect and .onFailure, and #1028's users.status.
* **Unindexed fields stay as NARROWING rows**, not first filters — a
  deliberate reading of "shouldn't be a searchable filter field": the
  anchor rule already makes a query that would scan impossible, and
  removing role, algorithm or channel as narrowing filters would undo
  what rcbj asked for in #1002, #1021 and #1027 (`mechanism equals
  passkey and role equals primary`). The non-directory sources (the audit
  ring, the registers, the snapshot) are in-memory lists bounded by their
  own caps; filtering them reads nothing from the store.
* **Run and Save are the definition page's buttons**: `.foot-actions`
  with `.button`s; Save stays first in the document for the Enter reason.

## A job's report is built on disk and stored in pieces (#1045, 2026-10-27)

rcbj, choosing between three answers to "use the risk uploads' temporary
location": *"#2, this is because large data sets will eat up too much memory
potentially."* Until then a job's report was one Buffer from
`executor.finish()`. `putArtifact()` turned it into its base64, a sealed
envelope and the envelope's bytes, all at once, and wrote them as one
`bytea`, and a download read the row back and opened it whole. That is
four copies of a 32 MB report in the heap of the process that runs
`report.drain`, a front process by `ON_FRONT`. The cloud cluster gives a
node a 10 GB volume for temporary files, and risk uploads already use it.

* **ONE DIRECTORY, ONE DEFINITION.** `common/staging_directory.ts` resolves
  `risk.uploadDirectory` and owns the 16 MiB reserve, the mkdir/`W_OK`
  check and the statfs reading. `risk/risk_upload.ts` and `staging.ts`
  both call it. It lives in `common/` because `report/` must not require a
  risk library before the root builds it (`risk/CLAUDE.md`, *The require
  order*). The setting kept its name, because deployments set it.
* **ROOM FIRST.** `ReportStaging.open(asyncMaxBytes)` refuses before a byte
  is written when the directory has less than the cap plus the reserve
  (`STS-REPORT-0049`). It also refuses when the directory cannot be made
  or written, or the file cannot be created (`STS-REPORT-0050`, which is
  also a write that fails part-way, such as ENOSPC). A statfs that will not
  answer is not a refusal, for the upload's reason.
* **THE FORMATS ARE GENERATORS.** `jsonParts()`, `csvParts()` and
  `pdfParts()` yield the document a row or an object at a time. The Buffer
  methods are the parts joined, so every existing caller and test sees the
  same bytes (`tests/report_staging.js` A holds JSON to `JSON.stringify` and
  every PDF xref offset to its object). The PDF is laid out first, so a
  page-cap refusal comes before a byte. Then each page stream is drawn
  when asked for, and only the object offsets are kept.
  `executor.finishToFile()` writes the parts through `StagedReport.write()`,
  which buffers a piece, hashes as it goes and answers false once the cap is
  passed. The synchronous path keeps `finish()`: at most `syncMaxBytes`,
  answered and never stored.
* **SEALED PIECES.** `stores.putArtifactFile()` reads the finished file back
  in 1 MiB pieces and seals each as `{"j":job,"s":seq,"b":base64}`, so a
  piece moved to another job or another place opens and is refused
  (`STS-REPORT-0051`). The driver's `putReportArtifactPieces()` writes them
  to `sts_report_artifact_pieces` (schema 29), and the
  `sts_report_artifacts` row holds `$pieces$1:<count>:<size>`, all in ONE
  `transactionOnce()`. It is never `withTransaction()`, whose conflict retry
  would re-run the body over an iterable already read. A driver without
  the two piece methods (a test double, or memory mode) gets the file read
  whole: memory mode holds its reports in the process anyway.
* **NO MIGRATION.** A row written before #1045 holds the whole report
  (sealed, or in the clear before #1033). `openArtifact()` reads it as one
  piece until its retention ends: 8081's data is kept and nothing is
  rewritten.
* **STREAMED OUT.** `reportServeResult()` opens the artifact and reads the
  FIRST piece before a header leaves, so a missing artifact or an unopenable
  first piece is still the 410 (`STS-REPORT-0029`). `reportStreamPieces()`
  then writes piece after piece, waiting for `drain`, hashing as it goes,
  with `Content-Length` from the marker. A later piece that fails, a byte
  count that differs, or a digest that does not match DESTROYS the response
  rather than ending it, so a client sees a broken transfer and never a
  short file that looks whole.
* **THE FILE IS REMOVED HOWEVER THE JOB ENDS**: `reportRunOne()` removes it
  in a `finally` around the store, and `finishToFile()` removes it on each
  of its own refusals. A process that dies mid-build leaves it, and
  `report.build-cleanup` (per process, quiet, on `risk.uploadSweepS`) is the
  `risk.upload-cleanup` sweep with its own file names
  (`report-build-<pid>x<hex>-<uuid>.part`). It touches the files the
  process holds, removes its own unheld files, and removes another
  process's files untouched for `report.asyncMaxMs` plus fifteen minutes.
  It never touches another name (`STS-REPORT-0052`).

**What is still in memory**: the rows the reader returns before rendering,
bounded by `report.asyncMaxRows`, and a PDF's layout (its wrapped lines).
Neither is a copy of the bytes. A reader that streamed rows into the
renderer would be the next step if the row cap were raised.

**A gap found and not closed here**: the re-encryption job
(`persistence_postgres.js`' `EXTRA_SEALED`, `countSealed()`) does not count
or re-seal `sts_report_artifacts.bytes` or the pieces, so a `report-artifact`
data key the job retires is not held alive by the reports sealed under it.
Those reports then answer as gone (`STS-REPORT-0043`, `STS-REPORT-0051`).
The rows are short-lived, by `report.artifactRetentionS`. Adding `bytea`
columns to that machinery is its own change.

`tests/report_staging.js` holds all of it in process. The postgres SQL of
the two methods is not run against a database there.

## A Shared Signals receiver, and a disabled owner's schedules (#1042, 2026-10-27)

**THE THIRD RECEIVER.** rcbj asked for `/report` to be a receiver beside the
console and the portal; `ssf/CLAUDE.md` (*A STATIC SURFACE HOLDS A TOKEN*)
has the design. This family's half:

* `report_app.ts` registers `POST /report/signals/receive` above the shell
  (which refuses every other POST, STS-REPORT-0033); a refusal there with no
  code of the receiver's own is STS-REPORT-0047.
* `GET /report-api/signals` (`reportServeSignals()`): every signal the
  application's stream delivered in the realm for a report administrator
  (`scope: 'realm'`), the caller's own for anybody else (`scope: 'own'`,
  the person being their username, subject and the address
  `sources.personMail()` asks the directory for), nothing for an
  application. Paged with `page` and `per` (at most 100). Each row carries
  what the application did: the sessions it ended and the tokens of
  `sts-report` it revoked for the person.
* **No page draws it since #1090** (rcbj: "it serves no purpose"): the
  Signals tab, `drawSignals()` and its sixteen `report.signals*` words went.
  The receiver stays — it acts on CAEP and RISC and takes announcements
  (#1086) — and so does this API, whose access rules
  `tests/report_access_policy.js` holds. Refresh moved to the top bar,
  beside the Trust realm field.

**A DISABLED OWNER'S SCHEDULES STOP.** A disable ends what the person holds
and refuses their next sign-in, and a schedule they owned went on running
under their name. `sources.ts`'s `reportOwnerDisabled()` asks the directory
for the owner's entry through its ASYNCHRONOUS door, in the owner's realm,
and reads `pwdAccountLockedTime`: the scheduler skips a due definition with
the note "The owner's account is disabled." (the occurrence consumed), and
the runner fails a job queued before the disable as `forbidden`. Both are
STS-REPORT-0048. An application owner is never disabled here, and a process
that has not loaded the directory has nobody to disable. `rights.ts`'s
comment that the read "walks the directory" was wrong — it is one indexed
lookup — and now says where the question is asked instead.
`tests/report_query.js`'s `disabledOwner()` holds it.

## Post-login progress, and predefined queries (#1110, 2026-10-28)

rcbj: post-login progress (#1096) and a started post-login activity's
per-person mail progress (#1111; its column `mailedBy` since #1123) are
reported HERE, as a source, and not on a console
page. `postLoginProgress` reads `post_login.progress` through
`common/post_login.ts`'s `eachProgressAsync()`, which is the store's
`scanAsync()`: the rows this process holds, then the store a page at a
time with the event loop given back between pages. **A `false` from the
callback ends the walk** (added to `realms.map()`'s `scanAsync()` for
this; `undefined` goes on, so its one older caller is unchanged), and the
reader hands every row to `reportOfferNow()` — `reportOffer()`'s body,
synchronous, because the store's callback cannot await — so a limit, the
time budget and a cancellation stop the paging and not just the taking.

* **Not anchored, not indexed.** The store has no index the planner could
  ask, and the rows are the people a realm has asked or mailed, not the
  population; so nothing is refused at acceptance, an unordered read stops
  at its limit, and a sorted or counted read walks under the caps.
* **The row says what applied when it was written.** `post_login.ts`
  stamps `profile` and `graceDays` on every write (`stamp()`; `role` too
  until #1135, when an activity stopped asking for a key in a role), so
  a report does not ask the directory for each person's profile. A row
  written before #1110 has none; for it alone the reader asks
  `post_login_policy.forPerson()`, once per person. **`askedBy` (#1126)**
  is the row's own the same way — `policy`, or the started activity that
  asked at a sign-in — and is never inferred for an older row: empty there
  is the truth, nobody recorded who asked.
* **`role` is RETIRED, not removed (#1135).** A row written since carries
  none, and its catalog field lost its `primary`/`mfa` enumeration and
  left the *past grace period* preset's columns; a row written before
  keeps the role it was asked for and shows it. The field stays because
  removing it would turn every stored definition that selects, filters or
  groups by it into a query that no longer validates (`STS-REPORT-0004`
  at a run, a schedule's slot spent under `STS-REPORT-0028`).
* **`progress` is one word** (`done`, `past-grace`, `snoozed`, `asked`,
  `mailed`, the first that holds) because the New Query form groups by ONE
  field: "progress by activity" is that word counted, filtered to the
  activity, which the form can draw and save.
* **PRESETS ARE DATA ON THE CATALOG** (`SourceSpec.presets`: `id`, `name`,
  `document`), published by `reportPublicSource()` and the OpenAPI
  `Source` schema, listed on the source's page and opened by
  `/report/query?source=…&preset=…` with the form filled and the save name
  set. They are not stored definitions — a definition has an owner, a
  realm and a share list, and seeding one per realm would give every
  realm an owner nobody chose. Each preset is a document the form can
  draw (one filter leaf, one order, one group), so starting from it and
  saving it keeps it; `tests/report_post_login.js` holds that, and that
  each validates.

`tests/report_post_login.js` drives the source over a real `PostLogin`
on a Map with a moved clock.

## Passkey history (#1109, 2026-10-28)

`passkeyHistory` reads `passkey_report.history`: one row per realm per
UTC day that the passkey report's recount writes and prunes
(`common/CLAUDE.md` 3cs argues the writing). Reported HERE, as a source
with presets, and not as a tab of Monitoring → Passkeys: all reports
live in `/report`.

* **One stored day is several rows, told apart by `scope`** (`realm`,
  `profile`, `algorithm`, `lane`, `attestation`), because the document has
  one aggregate and no pivot: a trend is one `scope` filtered and `day`
  ordered, which is a query the form draws. The alternative, a column per
  algorithm, would be a catalog that changes with the algorithms a realm
  happens to hold. Every row carries every field, `null` where its scope
  has none, so a CSV's columns do not move.
* **Bounded by its retention, not by an index.** The store is a few hundred
  small rows per realm, held in memory, read whole by
  `passkey_report.historyRows()` and offered to the collector a row at a
  time; nothing is anchored or indexed, and the directory is never read.
* **`postQuantumShare` is null, not 0, where nobody holds a passkey**: a 0
  would read as "nobody migrated" on a day there was nobody to migrate.
* Three presets, each one leaf on `scope` and one order on `day`: the
  adoption by day (the one #1109 names), passkeys by algorithm by day, and
  adoption by profile by day. `tests/passkey_history.js` holds them, the
  source and the row, in process and over `/report-api`.

## Every source run against 8081 (#1040, 2026-10-27)

rcbj asked for every query the generator can make, run against 8081
(about a million people) with results. Anchored, every source answers in
under 100 ms. Six things were wrong, and each is fixed where it lives:

* **The audit sources read one process's ring.** `reportAuditEvents()`
  awaits `audit.fresh()` (#820) before `audit.list()`, as the console's
  audit operations do; `authActivity` had answered nothing while the next
  request's `auditEvents` held six sign-ins. A failing `fresh()` fails the
  read.
* **`credentialHolders` asks each kind of lookup on its own**
  (`lookupsOf()`: people, `memberOf`, `mechanism`). One planner call keeps
  ONE arm of an `and`, so `mechanism = password` AND `memberOf = ssf-read`
  kept the mechanism and was refused as a million holders; and an `or` of
  a mechanism and a group read the group's people only, dropping rows.
* **The password's census is its counter.** A count grouped by
  `mechanism` alone, filtered on nothing but mechanisms
  (`reportOnlyMechanisms()`), takes the password's row from
  `holderCountAsync()`'s counter through `Rows.takeCounted()` and reads the
  other mechanisms as before. `docs/reporting.md` had promised it since
  #1019 and nothing did it.
* **A first page answers a read that wants any rows.** A lookup at
  `CANDIDATE_CAP` hands back its first page when the plan has no order and
  no count (`PartialLookup`; `entriesByTimeRangeAsync()`'s `partial`), and
  the read answers when its limit is met there; one that offers the whole
  page without filling it is refused `STS-REPORT-0041` as before, because
  the rows it lacks may be past the page.
* **Everybody is counted before they are read.** A filterless ordered or
  counted `users` read on a windowed directory asks `personCount()` (a
  counter row) and over `report.asyncMaxRows` is refused at once,
  `STS-REPORT-0046`, flat (not `unbounded`, so `auto` queues nothing); it
  had run two minutes as a job into `report.asyncMaxMs`.
* **The catalog says what anchors.** `status` carries `indexedValues:
  ['locked']`, the refusals name it (`Catalog.indexedPhrases()`, `status
  (eq locked)`), and the page's anchored first row offers `locked` alone;
  a field that cannot be filtered (`groups.members`) publishes no
  operators.

Left as they are: `federation` and `attributeSources` are empty on 8081
because nothing is configured, and `credentialHolders` with no filter is
refused because the Kerberos keys' holders are the population.
`tests/report_query.js` holds each (`narrowing()`, `holders()`,
`auditFresh()`).

## Every index on every source, and the anchor rule (rcbj, 2026-10-27)

Three sentences from rcbj the morning the credentialHolders source was
refused for `username equals rcbj`: "use every index available on every
source option"; "username is available on every source option, so apply
the same index across every source type"; and "if there aren't indexes
of fields we could search on, create them; otherwise these shouldn't be
exposed as valid search parameters because the queries will never work
given the constraints we've defined." What that became:

* **Every field the directory indexes declares it, on every source that
  carries the field** (`catalog.ts`): `username` (eq, in, contains,
  startsWith), `mail` and `entryUuid` (eq, in) on `users` AND
  `credentialHolders`; `memberOf` (eq, in) on both — a group's member
  list is an index of who is in it, read through `reportGroupMemberNames()`
  and `existingUserEntriesAsync()` in `reportLookupEntries()`; `name` (eq,
  in) on `groups`, read by DN in `reportReadGroups()` without listing the
  realm's groups. `tests/report_query.js` holds the rule for every source:
  a field named `username`, `mail`, `entryUuid` or `memberOf`, or a
  group's `name`, declares its index wherever it appears, so a new source
  cannot leave one out quietly.
* **THE ANCHOR RULE**: a source read from the directory is `anchored`
  (`users`, `credentialHolders`; published on the catalog and in the
  OpenAPI `Source` schema). On a windowed directory a filter on it that
  names no indexed field — the planner's own test, `reportIndexedLookups()`
  returning nothing — is refused at acceptance, in EVERY mode, as
  `invalid_query` with the indexed fields named (`STS-REPORT-0040`,
  `reportAnchorRefusal()` at the head of `reportReadWork()`), where it was
  `result_too_large` after a wait synchronously and a time-capped job
  otherwise. An `and` is anchored by one indexed arm, an `or` only by
  every arm. A memory directory is not held to it. A query with no filter
  still stops at its limit.
* **The page follows**: the first filter row of an anchored source offers
  only the indexed fields, with `report.tipAnchor` on the select; the rows
  the `+` adds take the full list from a `<template data-field-options>`,
  because they narrow the indexed read; a saved first row whose field is
  not indexed (saved before, or through the API) keeps its field by
  widening its own list.
* **Created by #1028 (schema version 28)**: `status equals locked` is a
  holders read (`pwdaccountlockedtime` joined the asked names;
  `LOCK_ATTRIBUTE`, `USER_FIELDS` for what the row needs), and
  `createdAt` / `modifiedAt` take the four range operators through two
  B-trees over the directory's own generalized-time text columns, led by
  realm and parent over each realm's `ou=users` (`sts_ldap_entries_created`,
  `_modified`; `directory_queries.js`'s `createdBetween` / `modifiedBetween`,
  `ldap_server.js`'s `entriesByTimeRangeAsync()`). The planner turns a
  bound into a `range` lookup — `le` and `gt` moved a second to the
  statement's inclusive-low, exclusive-high form — and two bounds on one
  date in an `and` into ONE span, so "between" is one index read.
  `active` anchors nothing: it is everybody else.
* **Not created**: an index for `displayName` (sealed; it would need a
  keyed digest as `name_keys` has) or a credential's role, algorithm, lane
  or channel (inside the sealed value; indexing them would change what is
  encrypted, which rcbj ruled out). Those stay narrowing fields.

## Signing keys, enrollment credentials and certificates (#1036)

rcbj, 2026-10-27: `username = rcbj` showed no TLS client certificates,
signer certificates, ACME, EST or SCEP credentials. Four mechanisms, all
asked names already (no index change): `jwtSigningKey`
(`stsAssertionJwks`, read with `stsAssertionCertificate`/`Kid`/`KeySource`)
and `samlSigningKey` (`stsSamlAssertionCertificate`, with its thumbprint and
key source), role `signer`, algorithm from the certificate's key
(`reportCertKeyAlg()`, through `common/crypto.js`'s `parseCertificate()`);
`acmeAccountKey` (`stsAcmeEabKey`) and `scepChallenge` (`stsScepChallenge`),
role `enrollment`, one row per value — neither the sealed HMAC key nor the
challenge digest is read. EST authenticates with a password or a client
certificate and keeps no credential. `certificate` rows now read
`cert_enrollment.ts`'s record: `serialHex`, `family` (acme/est/scep) as
`channel`, `profile` as `format`, `keyAlg`, `issuedAt`; a TLS client
certificate is one of these. `channel`'s enumeration grew the protocols and
`issued`/`uploaded`; `format` is open now (profiles are many).
`HOLDER_FIELDS` carries the signing keys' public attributes.

## The wallet mechanisms (#1021)

rcbj, 2026-10-27: how many people hold verifiable credentials from a web
wallet, from a native wallet, and self-issued subjects from either, and
the algorithm of each. Two mechanisms, two different reads:

* **`verifiableCredential` is READ FROM THE REGISTER**, not the entry:
  the credentials this realm issued live in `oid4vc/vc_issued.ts`'s
  store, keyed by credential, so `reportIssuedRows()` takes every live
  row (`rowsForSubject(null)`), files them by subject, counts the
  subjects as the holders, names them (`helpers.nameForSubject`) and
  fetches the entries by name as a group's members are fetched. The
  mechanism carries `register: true`; the attribute-driven doors skip it.
  One report row per KIND of live copy (`reportIssuedRowsFor()`): the
  copies sharing a credential type, format, holder-key algorithm, lane
  and channel are one row with `credentials` their number (rcbj, the
  same day, on 8081: a batch issuance bound four keys to four copies and
  four rows each saying 4 said nothing; one row saying 4 does; copies
  that differ in any of those stay separate rows, so a count by algorithm
  still counts copies), `credentialId` the configuration id, the dates
  the group's earliest issuance and latest wallet report. `format` from
  the row, `algorithm` and `channel` from the copy — **two new fields the
  issuer records** (`Issued.holderAlg`, the holder JWK named as the
  passkey report names a key; `Issued.channel`, `VcIssuer.channelOf(req)`:
  `web` when the credential request carried a browser Origin, `app`
  otherwise — a browser must send one on a cross-origin POST and a native
  wallet sends none; nothing the wallet says about itself is read).
  Deferred issuance reads the deferred request's Origin the same way. A
  copy before #1021 has neither. A test installs a register double with
  `sources.installIssuedRegister()`.
* **`selfIssued` is the `stsSelfIssuedSubject` attribute**, an asked
  name, so an indexed read like the others; one row per enrolled value.
  The channel is #693's `location.kind` (`web`, `app`, `dc_api`; `admin`
  for a value entered by value). The algorithm is what the DID spells —
  `did:jwk` through `jwkOfDidJwk()`, `did:key` through `jwkOfMultikey()`,
  then `Credentials.keyAlgorithm()` — else **`keyAlg`, a new field the
  enrolment records**: `siop.verifyIdToken()` now answers the proof's
  header `alg`, `vc_verifier.ts` carries it on the outcome and
  `vc_signin.ts` hands it to `siop.enrol()`, which keeps it on the value.
  A did:web enrolled before has none.
* **`channel` and `format` are catalog fields** (`channel` enumerated:
  `HOLDER_CHANNELS`), empty on every other mechanism's row, so a count by
  `channel` is a wallet census and the other mechanisms stay as they were.
  `reportHolderCommon()` is the one place a row's common columns are
  built, so both reads say the same about the person.

## Passwords in the reports (#1019)

rcbj, 2026-10-27: "what about username password authentication?" Three
answers, one commit:

* **`password` is the sixth mechanism** (`MECHANISM_TABLE`, attribute
  `userPassword`, role primary; `HOLDER_MECHANISMS` too). Its holder
  COUNT comes from the realm's counter — `ldap_server.js`'s
  `holderCountAsync()` asks `DirectoryWindow.countHoldingAsync()` for
  `userpassword` (`directory_queries.js`'s `COUNTED_ATTRIBUTES`,
  `countHolding`), never the asked-names index, which does not carry it
  and would scan the realm. On 8081 that is 1,000,023 of 50 million, the
  same people as the Kerberos keys (a password derives them), so a list
  is refused as over the cap and runs only narrowed by `memberOf`. **A
  password row never carries the hash**: `reportHolderRows()` reads the
  scheme as the algorithm — `$scrypt$`/`$argon2id$`, this service's own
  stored forms (`common/crypto.js`), or an imported `{SCHEME}` — and
  `pwdChangedTime` as the enrolment, and the test asserts neither hash is
  in a row. (The first probe on 8081 drew an empty algorithm: the parser
  knew only the braced form.)
* **`users` gains `hasPassword`, `factors`, `methodsUsed`,
  `mfaLastAuthTime`** (`reportUserRow()`; `reportSecondFactors()` counts
  every passkey since #1135 — until then only an mfa-role one — and
  authenticator apps and mail factors; recovery codes and app passwords
  are not factors). None is indexed, so a filter on them is a job on a windowed
  directory; "password only" is `hasPassword` true and `factors` 0.
* **`methodsUsed` on `users`** answers who has signed in with a password
  (`pwd`), compared value by value (`LIST_FIELDS` already names it). On
  8081 no entry carries `authnMethod` yet: the load sign-ins predate it.

## A trash can on every filter row (#1017)

rcbj, 2026-10-27. `filterRowHtml()` draws a `remove-filter` button
(U+1F5D1) on every row before the `+`; `removeFilterRow()` removes the
row, renumbers the rows left (`data-filter-row` and the three control
names, as `addFilterRow()` names a clone) and, when the removed row
carried the `+`, appends one to the new last row
(`addFilterButtonHtml()`); the only row left is emptied instead, its
value control a text box again, so `queryDocument()` always finds row
zero. One prose key, `report.removeFilter`, in the seven catalogs.
`tests/report_query.js` drives the three cases on a DOM double.

## The Sort row and the Group by box (#1008, #1013)

rcbj, 2026-10-27: a checkbox labelled Sort that reveals the sort field
and the ascending/descending selects, "and the same for group by"; then,
seeing it on 8081: the three sort controls on ONE row, the selects really
hidden, and a Group by box of its own. The Save query box's shape (#986):
`sortQuery` ticks, the two `.sort-only` selects carry `hidden` until it
does, `onChange()` toggles the attribute, and `queryDocument()` writes no
`orderBy` while the box is unticked, whatever the hidden selects hold (a
form without the box — an older test double — sorts as before). The
Count row is the Count box, the `groupByQuery` box and the `.group-only`
select; a ticked Group by with a field is a count whether or not Count is
ticked, because the API refuses a group-by without one. A saved order or
group draws its box ticked and its select shown. **Group by is a row of
its own** (#1015, rcbj), below Count and above the Save query box, which
the page draws after the query block.

**Why the selects stayed in view at first (#1013)**: `.row { display:
flex }` and `.field label { display: block }` outrank the browser's
`[hidden] { display: none }`, so the attribute hid nothing they styled.
`report_app.ts` now carries `[hidden] { display: none !important }`, one
rule for every gated control, and `.row label` is inline-flex so a box
and its text sit on the row. The labels reuse `report.sort`,
`report.count` and `report.groupBy`, so no catalog changed.

## An enumerated field offers three operators (#1022)

rcbj, 2026-10-27: over `mechanism`, only equals, does not equal and is
empty. `opSelectHtml(t, n, enumerated, chosen)` draws the operator select
with `ENUM_OPS` for an enumerated field (#1007's `values`) and the full
list otherwise, and marks which it holds (`data-ops`); `redrawFilterRow()`
redraws it on a field change only when the list changes, keeping the
operator when the new list still offers it and dropping it to the empty
choice otherwise, before drawing the value control for that operator. A
saved row is drawn with its field's list. The API still validates the
operator: the short list is a convenience, not the gate.

## An enumerated field's filter value is a dropdown (#1007)

rcbj, 2026-10-27: "mechanism equals" on credentialHolders should offer
the possible values. **The enumeration is the catalog's**, not the
page's: `FieldSpec.values` (set through `field()`'s fifth argument;
`HOLDER_MECHANISMS`, held equal to `sources.ts`'s `MECHANISM_TABLE` by a
test because the catalog cannot require sources, and `HOLDER_ROLES`),
published by `reportPublicSource()` and described in the OpenAPI `Field`
schema, so a client can draw the same choice. The page's
`filterValueHtml(n, fields, field, op, value)` draws a `<select>` of the
values with an empty first choice under `eq`, `ne` or no operator yet,
and the text box otherwise; `filterRowsHtml()` draws a saved row the same
way; `onChange()` on `filterFieldN`/`filterOpN` calls
`redrawFilterRow()`, which replaces the control through `outerHTML`
(a text box that would be a text box again is left alone, keeping what
was typed); `addFilterRow()` gives the clone a text box, since its field
is unchosen. `queryDocument()` reads `filterValueN` by name, so a select
reads as the input did. The API still validates the value: the dropdown
is a convenience, not the gate.

## The result of Run is paged in the browser (#1005)

rcbj, 2026-10-27. `showRun()` drew the first fifty rows of a synchronous
answer and dropped the rest without a word. Now it keeps the answer
(`lastRun`: the fields and every row) and `drawRunResult(page)` paints a
slice with `pagerHtml(…, held = true)` above and below: #997's pager with
links that go nowhere — `data-act="result-page"` and the page number,
handled in `onClick()` — and a rows-per-page select marked
`data-result-pager`, handled in `onChange()` (the choice, `resultPer`,
is kept for the tab's next Run). **The location does not change**: a
route would draw the query form again and lose the rows, so this pager
is the one place the page turns without `pushState`. Both Run buttons
(New Query, and a definition's) go through `showRun()`, so both are
paged. `tests/report_query.js`'s `chrome()` drives `showRun()`,
a page link and a size change on a constructor-less instance.

## `credentialHolders`: who holds which credential (#1002)

rcbj, 2026-10-27: who has a passkey as a primary mechanism, who as a
second factor, with what algorithm and how many — generic over mechanisms
and communities, "without changing what fields are encrypted or adding
significant overhead". One row per person, per mechanism, per role,
read from what the directory keeps already:

* **A passkey has no role since #1135** (rcbjBlueMars, 2026-10-29: a key
  is not enrolled `primary` or `mfa` any more; the authentication policy —
  the realm's, and an application's where it overrides — decides which use
  a key may answer at each sign-in). Until then this bullet read *a
  passkey's role is data, not a derivation* — the key's own `role`, chosen
  at enrolment and enforced at sign-in — and `reportHolderRows()` grouped a
  person's keys by it. Now a passkey row's `role` is `MECHANISM_TABLE`'s
  `''` and `credentials` is the person's count of passkeys;
  `keysOfValues()` drops any `role` a stored value still carries, so an
  old key reads like a new one. Its algorithm and lane are
  `keyAlgorithm()`'s. The other mechanisms (`MECHANISM_TABLE`: totp,
  emailFactor, certificate, kerberos, …) have one role each, and
  `HOLDER_ROLES` keeps `primary` and `mfa` for them.
  **A stored definition is not broken by it**: the field and its values
  stay, so `mechanism equals passkey and role equals primary` (#1002's
  example) still validates — and now answers nobody, which is the truth
  rather than a refusal. A definition that grouped passkeys by `role` now
  draws one group, empty.
* **The indexed reads**: `username`, `mail`, `entryUuid` → the users
  source's `reportCandidates()` (rcbj, 2026-10-27: `username equals rcbj`
  was refused as too large until this, the reader knowing only the two
  below), the person's entry and every mechanism of theirs; `mechanism` →
  `holdersAsync('person', attribute, names)`, the store's asked-names
  index, bounded by holders; `memberOf` → the group's `uid=` members by
  `existingUserEntriesAsync()`. The person wins over the group, the group
  over the mechanism, when more than one is named; every filter still
  applies in `Rows.take()`. A query naming none is unbounded in the
  catalog's sense (every mechanism's holders): refused synchronously on a
  windowed directory (`STS-REPORT-0036`), a job otherwise.
* **Counted before read, and stopped with the budget** (found on 8081 the
  night it shipped): every person with a password holds `stsKrb5Keys`, so
  the Kerberos mechanism's holders were a million people, and a query
  naming it — or no mechanism, as a job — read them all, a page at a
  time, for minutes after the client gave up. `ldap_server.js`'s
  `holderCountAsync()` (the store's `countWithAttributeUpTo`, the count
  of the first cap+1 holders, nothing opened — the WHOLE count of 8081's
  million took a minute) is asked first; over `report.syncMaxRows` /
  `report.asyncMaxRows` the read is refused, `STS-REPORT-0039`, as an
  unbounded refusal synchronously (so `auto` queues a job, which counts
  again against its own cap) and flat in a job. A group's
  member names are counted against the same cap. The read that starts
  passes `{ stop }` to `holdersAsync()`, which `DirectoryWindow` asks
  between pages and the in-memory walk between slices, so the budget or a
  cancellation ends the store's paging with a thrown `stopped` error.
* **Recovery codes are here since #1024** (rcbj, 2026-10-27: "similar
  searches on backup codes"): `recoveryCodes`, attribute `stsBackupCodes`,
  role `recovery`, one row per set — the unused codes counted (the stored
  `remaining` when the set is sealed under another key), `scrypt` or
  `plain` as the algorithm, `generatedAt` and `lastUsedAt` — and never a
  code or a hash. It took the store index change #1002 deferred:
  `stsbackupcodes` joined `ASKED_ATTRIBUTES`, which is schema version 27
  and a rebuild of `sts_ldap_entries_asked_names`
  (`persistence_postgres.js`'s advisory step `_v27`, `postgres/schema.sql`).
  **Not here**: app passwords, whose attribute is still outside the index;
  and a maintained per-role aggregate — `passkey_report.ts` keeps
  algorithm, lane and model facets but not role, so the census is the
  engine's count+groupBy over this source.
* **Changing the source redraws the query block on BOTH pages** (rcbj,
  2026-10-27): `onChange()` redrew it only inside the definition form, so
  on New Query the field boxes and the filter dropdown kept the first
  source's fields, and `mechanism` was nowhere to be picked. Now any form
  holding `[data-query-block]` is redrawn for the chosen source.
* **A list field is compared value by value** (found on 8081 the same
  night: `memberOf` equals `group1` found rcbj through the group and then
  dropped the row, because the row says "group1, ssf-manage, ssf-read").
  `rows.ts`'s `LIST_FIELDS` (`memberOf`, `algorithms`, `lanes`,
  `methodsUsed`) are split on ', ' for `eq`, `ne` and `in`; `contains`
  and `startsWith` keep the joined string. This mends the users source's
  `memberOf` filter for anyone in more than one group, too.
* **A wide result scrolls inside its card** (rcbj, 2026-10-27, running
  this source with every field): `tableHtml()` wraps every table in
  `.tablewrap` (`overflow-x: auto`), a cell may break a long value and a
  heading stays on one line. Nothing is dropped or truncated to fit.
* `tests/report_query.js`'s `holders()` drives it against the double.

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

**A PDF cell wrapped, and the page cap moved with it (#993, 2026-10-26).**
rcbj: a PDF from the jobs tab cut every value at its column's edge. A
cell is now laid out on as many lines as its column needs, capped at 256
WinAnsi bytes and ending in `...` when cut, and a page holds forty LINES
rather than forty rows, so `report.pdfMaxPages` is checked against the
pages the layout needs. A row that fits is never split; one taller than
a page continues on the next, because a row cut at the page's foot is
the same clipping seen from below. The layout is a character count over
Helvetica's average advance (the file carries no metrics), the heuristic
`clip()` already used. `tests/report_query.js` `formats()` holds it.

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
and small by construction. **Since 2026-10-27 a FILTER with no indexed
anchor never gets this far**: `reportAnchorRefusal()` refuses it at
acceptance in every mode (`STS-REPORT-0040`, *Every index on every
source*, below); what remains of this paragraph's job path is the
filterless ordered or counted read.

The directory is reached through `reportLdap()`, which answers the double
a test installs with `installDirectory()` or `ldap/ldap_server.js`.
`tests/report_query.js`'s `narrowing()` drives the planner, every lookup
door, the refusal, the auto/async distinction and the memory fallback
against a counted double. **What it does not hold**: a real windowed
directory, which needs a postgres store; `report_api.ts`'s auto-to-job
turn; and the timing on 8081.

## Who may run one — roles, and the PDP (#1030, 2026-10-27)

**Until #1030 this family decided its own authorization in TypeScript**,
three ways at once, and rcbj called it what it was: a departure from the
norms every other surface keeps. A resource application defined the two
scopes as delegated permissions the browser never consulted; who may be
issued them was a group check in `rights.ts` (`report.usersGroup`, plus
the console administrators) rather than a role; and which rows a token
may see was `canSee()` / `canEdit()` / `jobVisible()` — `if`s over the
scope string and a group's member list — where every other access
decision goes through `common/access_gate.ts` to the PDP (the directive
of 2026-09-05). All three are gone; this is what stands:

* **Two native roles** (`common/roles.js`): REPORT_USE authorizes
  `report:use`, REPORT_ADMIN `report:admin`, each seeded in every realm
  with its group (`report-users`, `report-admins`) on `roleMemberGroup`,
  the SSF roles' shape. A person holds one through the group or as a
  direct member; an application as a member. Nothing asks whether the
  application a person signs in to is a member: `sts-report` declares the
  scopes (#110), as the console declares the admin ones. **A console
  administrator IS one since #1038** (rcbj reversed #1030's "the report
  groups are the basis" the same day): see *Console administrators* below.
  `report.usersGroup` is retired.
* **Issuance** is `common/role_permissions.ts`'s with every other gated
  permission: narrowed at the authorization endpoint and in `tokenSet()`,
  `invalid_scope` when nothing is left, STS-ADMIN-0821 on the audit row.
  An application that is a member is issued the scope on
  `client_credentials`.
* **The caller** (`rights.callerOf()`) is held ∩ carried
  (`role_permissions.effectiveRoles()`), the management API's reading:
  the roles the subject holds NOW in this realm, less any whose
  permission the token does not carry. A role taken away after the token
  was minted refuses the next call (STS-REPORT-0018).
* **Every question goes to the gate** on the resource `report-api`
  (`rights.ts`, `reportDecide()`): once per call for the API itself —
  holding a report role, the first rule's any-one — and once per
  definition or job where it is reached, with the row's owner as the
  question's `owner` (so the first rule permits the owner exactly as it
  permits a person their portal account: the token's `sub` against the
  stored owner) and the row in `reportObject` (its kind, the DNs it is
  shared with, the person) for the access-control document's THIRD rule,
  `report-administrators-and-shares` (`xacml/CLAUDE.md`): a PERSON holding
  REPORT_ADMIN on any row; a person holding a report role on a row shared
  with a group they are in — the PIP's `owner-identity`, never a member
  list read here — for the actions `reportSharedActions` lists (`read`,
  `run`). **An application holding either role is an owner and nothing
  else** (rcbj's decision 4): it reaches, runs, edits and deletes only what
  it defined. `canSee` is `read`, `canRun` is `run` (a share's other act),
  `canEdit` is `write` (change, share, delete; everything about a job and
  stopping it), `canSeeJob` is `read` on the job with its definition's
  shares. A hidden row is still `not_found` (`STS-REPORT-0019`,
  `STS-REPORT-0020`); a refusal of the API itself is `STS-REPORT-0044`.
  A list is one decision per row.
* **A scheduled run** asks the same question of the definition's owner
  (`rights.ownerMayRun()`): the owner's roles now (`heldRoles()`, by
  `ownerKind`, which a definition and a job record since #1030) and `run`
  on the definition; refused, the slot is consumed (STS-REPORT-0028). It
  does not ask `account_state.isDisabled`: that read walks the directory,
  and a job must not. `installOwnerCheck()` is the one test seam.
* **`rights.isAdmin(who)`** — a person holding REPORT_ADMIN — is what the
  API answers as `scope: realm` and what lets `GET /schedules` name
  another owner (STS-REPORT-0038); the rows it lists are still decided
  one by one.

`tests/report_access_policy.js` holds it in a child process with the
whole stack: the roles and groups, issuance to a member and not to an
outsider, an application's `client_credentials` token, and the policy
over HTTP for an owner, a report administrator, a shared group's member,
an outsider, an application on its own rows and on a person's, a
withdrawn role, and `permitReportSharing: no` — and its section F holds
the console administrators below.

### Console administrators (#1038, 2026-10-27)

rcbj: "The admin user for the default domain should have /report access in
all realms. The realm admins should have report access in their realms."
After #1030 the default realm's `admin` was narrowed to no report scope
and the page answered *That access token does not carry report:use or
report:admin*. Three parts:

* **The roles come with the roster.** `role_permissions.ts`'s
  `heldRoles()` adds REPORT_ADMIN and REPORT_USE for Admin Write and
  REPORT_USE for Admin Read, in the realm whose roster says so
  (`REPORT_ROLES_OF_ROSTER`). So issuance, held ∩ carried, the PIP and the
  schedule all see them, with no group membership written. In development
  a console open to everybody (an empty roster, or an unclaimed bootstrap
  window) therefore opens every report too.
* **A service administrator crosses realms, as on `/admin-api`.** Under
  `/realm/<id>/report-api`, a JWT that does not verify under the realm's
  key and does under the default realm's is checked WHOLE in the default
  realm (`reportAuthenticateToken()` inside `realms.run()`: issuer,
  audience — the default realm's `/report-api` —, revocation, session,
  sender constraint, declaration, held ∩ carried), and its subject must
  then be a PERSON with Admin Read or Admin Write on the default roster
  now (`rights.serviceAdministrator()`), or STS-REPORT-0045. The caller
  carries `realm`; the row-level decisions run in the realm on screen with
  the caller's default-realm roles, and `person` is left out of
  `reportObject` so the PIP never reads a same-named local person's
  groups. An opaque handle does not cross (it does not say its realm).
* **Rows remember the owner's realm.** A definition or job such a caller
  makes records `ownerRealm` (`jobs.ts`); `ownerMayRun()` asks the
  default realm for the name and roles and refuses once the owner is off
  the default roster; the owner's name (`reportOwnerName()`), the audit
  actor and the notice (`reportNotify()`, mailed from the owner's realm
  with a link carrying this realm's prefix) are resolved there too. A
  row without `ownerRealm` is this realm's, which every row made before
  #1038 is — no migration.

**The page** (`web_report_pages.ts`) keeps `issuerPrefix`, the realm that
issued its token: the token endpoint, discovery and `resource` name that
realm, while pages and API calls name the realm on screen (`url()`,
`urlAt()`; an `elsewhere` base has the load-time prefix swapped).
`switchRealm()` asks the other realm's `/report-api` with the token first
and, on a 200, moves in place with `pushState`; otherwise it navigates
there and signs in as before. A sign-in always resets `issuerPrefix` to
the realm on screen.

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
`putReportArtifact`, `getReportArtifact` and `deleteReportArtifact`, and
since #1045 they are in sealed pieces in `sts_report_artifact_pieces`
(schema version 29) when it also has `putReportArtifactPieces` and
`getReportArtifactPiece` (above, *A job's report is built on disk*).
Otherwise they stay in a map in this process, keyed by realm and job id.
**The bytes are SEALED since #1033** (rcbj: "reports need to be stored
encrypted"): `stores.ts`'s `reportSealBytes()` seals the base64 of the
report with `keystore.seal(…, 'report-artifact')` — the realm's data key of
that class, wrapped under the key-encryption key — and the `bytea` column
holds the envelope's UTF-8; `reportOpenBytes()` opens it on read, passes a
pre-#1033 clear row through until its retention ends, and answers a row
that will not open as gone (`STS-REPORT-0043`). **Without a key-encryption
key the report is refused, never written in the clear**
(`STS-REPORT-0042`); `reportRunOne()` fails the job with that code. The
in-process map is never written anywhere and stays plain.
`persistence.js` installs the driver lazily and does not require
`report/jobs`. A delete removes the memory copy as well as the row.

Audit detail is the source, the field ids and the job id. The query
document is not written on the row.

## Passkey ceremonies, and their predefined queries (#1107, 2026-10-28)

**`passkeyCeremonies` reads the audit ring as `authActivity` does**:
`reportAuditEvents()` (the `fresh()` wait, the `audit.maxEvents` cap),
then `passkey_ceremonies.ts`'s `rowsOf()` keeps the `webauthn.ceremony`
and `webauthn.algorithm-mismatch` rows and projects them, and
`reportOffer()` takes them into the bounded collector. No index: the ring
is a list in memory and the audit store indexes no detail field, so
nothing is declared and nothing scans a store. The row shape is
`authn/webauthn_ceremonies.ts`'s header; its `role` is the USE an
assertion answered (`primary` | `mfa`) and empty on a registration since
#1135, a key having no role (an older registration row keeps the role it
was enrolled in); the folded `authenticator`
(#1108) is read back with its `unfold()`, which reads a pre-#1108 row
too, and `postQuantum` / `postQuantumOffered` are
`passkey_policy.isPostQuantum()` of the names. A mismatch row's
`ceremony` is empty so a count by ceremony does not count it twice. A
ceremony row's `offered` may carry, after its first `|`, the client rule
that narrowed the offer or would have (#1112); the source splits there and
publishes it as `offerRule`, and reads the algorithm names before it.
The doors are listed in the catalog (`CEREMONY_DOORS`) rather than read
from the ceremony module, which the browser bundle would then carry;
`tests/report_passkey_ceremonies.js` holds the door field to naming every
door the module writes. The
source's extra groupable fields are its own list (`CEREMONY_GROUPABLE`),
not `GROUPABLE`, which applies to every source's field of that id.

**ITS PREDEFINED QUERIES ARE #1110's `presets`** (`{ id, name, document }`
on the source; `PresetSpec`, `source()`'s fifth argument). #1107 asked for
predefined definitions and was built beside #1110, which brought the
mechanism — data, not stored definitions, published by
`reportPublicSource()` and the OpenAPI `Source`, listed on the source page,
`/report/query?source=…&preset=…` filling the form — so this branch carries
#1110's hunks for it verbatim rather than a second mechanism. The form
draws a flat `and` of comparisons, so a preset is written that way, and
`whereLeaves()` now takes a boolean value (a saved or preset filter on a
boolean field drew no rows before).

## The AuthZEN searches as sources, run as the owner (#1176, 2026-10-30)

`authzenSubjects`, `authzenResources` and `authzenActions` are AuthZEN 1.0's
three searches (`authzen/CLAUDE.md`, *Search*), read through
`authzen.runSearch()`. **rcbj's decisions (2026-10-29):** "reports should run
with the permissions of the person logged into the report", and the person is
the CALLER. So `reportRunOne()` puts `reportActor(job)` and `job.ownerRealm`
on `control`, and `reportReadAuthzen()` asks with that name as
`urn:sts:xacml:authzen:caller` and `sts-report` as the application, with
`checkScope: false`, because the person is not a PEP and the report rights
have already admitted them. A scheduled run therefore asks as the owner AT
RUN TIME, never with what they held when they saved the definition.

* **The inputs are required `eq` filters**, checked in `reportReadWork()`
  beside the anchor rule (`reportAuthzenInputs()`, `STS-REPORT-0054`): a
  search is asked with one value per input, so an input inside an `or` or a
  `not` is not one. `Catalog.authzenInputs()` holds the lists.
* **One call per run**, with the page as large as
  `authzen.searchMaxCandidates`. The search decides every candidate on each
  call anyway, and the report pages its own rows. One `authzen.search` audit
  row per run, its summary starting `report searched`.
* **An owner from another realm (#1038) is refused** (`STS-REPORT-0055`,
  `forbidden`). The caller is a NAME, and in the realm the report runs in
  that name is somebody else, or nobody. So is a run with the search APIs off
  (`unavailable`).
* A search's own refusal (an unknown action, an undeclared property) fails
  the job under the search's `STS-AUTHZEN-*` code.
* Tests: `tests/authzen_evaluation.js` R1–R10, against that file's realm and
  policy (rule `reportOwnerAudits`).

## What the tests hold

`tests/report_query.js` holds the document, the three formats, the fixed
limits (including `asyncMaxMs`), an in-memory
artifact, the two added sources' row projections, the OpenAPI paths, an
in-memory schedule that uses stored parameter defaults (with the access
PEP installed, so the views are the policy's), and the indexed
lookups against a directory double (#985). It does not open a listener. A
refusal's HTTP status, the DPoP gate and a scheduled run against a
directory are not asserted here; issuance and the policy's every case are
`tests/report_access_policy.js`'s (#1030).
`tests/report_passkey_ceremonies.js` holds the `passkeyCeremonies` source
(#1107): its fields, the projection over both row shapes, the three
predefined queries run against a known ring, rows the ceremony module
writes reaching it, and the definitions published and filling the form.

## The sources

The seventeen sources are `users`, `groups`, `applications`, `federation`,
`authMechanisms`, `auditEvents`, `authActivity`, `serviceMetrics`,
`reportJobs`, `attributeSources`, `credentialHolders`,
`postLoginProgress`, `passkeyHistory`, `passkeyCeremonies` (above,
#1107) and the three AuthZEN searches (below, #1176). `authMechanisms` is the realm policy
(application `realm`) plus one row per value listed by the named
authentication policy an application names (`appAuthnPolicy`, #1148; its
own `appAuthnMechanism` and `appMfaMechanism` until then). An application
on `default`, or whose policy lists none, inherits the realm policy and
adds no row; a policy that does not exist adds none. Since #1237 it also
has a row per value listed by the policy each group names (`stsAuthnPolicy`,
found per named policy through the group index, never a walk of the
groups), with the `group` and `policy` columns saying where a row came
from. `authActivity` is the four
attempt actions still in the audit ring (`authentication`,
`authentication.refused`, `session.refuse`, `session.refused`). `mechanism` is
`detail.method`, or `detail.amr` when the row has no method. A session id, an
address, a note and a presented credential are not fields. `attributeSources` is
the register. It does not run SQL and it does not read the remote table.
Connection details and secrets are not fields. `serviceMetrics` is one level of
numeric leaves from `admin_stats.snapshot({ withoutUsers: true })`. It is not a
time series, and it is not the per-route or per-kind tables. `/admin/metrics`
and `/admin-api/metrics` stay. `docs/reporting.md` is the migration note.
