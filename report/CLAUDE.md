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
| `catalog.ts` | The eleven sources and their fields, and which operators the store indexes (`indexed`, #985). Credential attribute ids are absent, so they cannot be named. |
| `openapi.ts` | `GET /report-api/openapi.json`. Every released route, built from the catalog that is loaded. |
| `query.ts` | Validates one JSON document and decides sync or async. It sends no HTTP response. |
| `limits.ts` | The caps, read when asked. `Limits.fixed` is what a test passes. |
| `formats.ts` | JSON, RFC 4180 CSV, and a PDF 1.4 file in Helvetica WinAnsi. A PDF cell wraps within its column, up to 256 bytes, and a row is as tall as its tallest cell (#993); the file's header argues the pagination. |
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
`redrawFilterValue()`, which replaces the control through `outerHTML`
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

* **A passkey's role is data, not a derivation** — the key's own `role`
  (`primary` | `mfa`, `Credentials.ROLES`), chosen at enrolment and
  enforced at sign-in; its algorithm and lane are `keyAlgorithm()`'s.
  The other mechanisms (`MECHANISM_TABLE`: totp, emailFactor,
  certificate, kerberos) have one role each.
* **The indexed reads**: `mechanism` → `holdersAsync('person', attribute,
  names)`, the store's asked-names index, bounded by holders; `memberOf` →
  the group's `uid=` members by `existingUserEntriesAsync()`. The group
  wins when both are named; the mechanism filter still applies in
  `Rows.take()`. A query naming neither is unbounded in the catalog's
  sense (every mechanism's holders): refused synchronously on a windowed
  directory (`STS-REPORT-0036`), a job otherwise.
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
* **Not here**: recovery codes and app passwords, whose attributes are
  outside the asked-names index (a store index change, its own ticket);
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

The eleven sources are `users`, `groups`, `applications`, `federation`,
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
