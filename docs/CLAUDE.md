# docs/

The user-facing documentation, published as a GitHub Pages site by
`../.github/workflows/pages.yml`.

## The versioned site (2026-11-17)

**The site is versioned, one folder per release, and the pages being
written are in `v1.2.0/`.** Every page name below (`error-codes.md`,
`openapi/`, `debugger/`, ...) is a path inside that folder. What stays at
this root is the Jekyll machinery the versions share and nothing else:
`_config.yml`, `_layouts/`, `_includes/`, `_data/`, `assets/main.scss`,
`assets/search.js` (the header's search box, *Search* below),
`logo.png` (the header draws it on every page, and both Dockerfiles'
`io.artifacthub.package.logo-url` name `docs/logo.png` on main), this file,
`search.md` (the results page) and `index.md`, the landing page that lists
the versions.

* **`v1.0.0/` IS A FROZEN SNAPSHOT** of `docs/` on main at 7907e7e86, the
  site 1.0.0 was published with, taken with `git archive` less the
  machinery above. It is not edited, regenerated or checked: a fix to
  1.0.0's documentation is not something this repository makes after the
  release. `_data/navigation/v1-0-0.yml` is main's `navigation.yml` from
  the same commit, with only its header comment changed.
* **`v1.1.0/` IS A FROZEN SNAPSHOT** of this folder at the `v1.1.0` tag
  (13122f15e, which is main when 1.1.0 shipped). It is not edited,
  regenerated or checked, for the same reason as `v1.0.0/`.
  `_data/navigation/v1-1-0.yml` is that tag's sidebar.
* **EVERY GENERATOR AND EVERY TEST TOUCHES THE LATEST FOLDER ONLY**
  (rcbj, 2026-11-17: deliberately simple, to be made cleverer later).
  `common/error_codes.js --docs`, `tests/tools/regenerate-openapi-pages.sh`,
  `tests/tools/regenerate-model-docs.sh` and `common/certificate_trust.ts`
  write into `v1.2.0/`, and the tests that read a page read it there. Each
  names the folder once, as a literal; there is no version-aware machinery.
* **The service links to its OWN version's folder**:
  `common/web_doc_links.ts`'s `ORIGIN`, the footer (`common/web_footer.ts`)
  and the front door (`home/home.ts`) name
  `https://rcbj.github.io/iya-sts/v1.2.0/`.
* **The sidebar is version-aware.** `_includes/version.html` reads the
  version from the page's first path segment, against
  `_data/versions.yml` (newest first; the first row is the latest).
  `_includes/sidebar.html` draws that version's
  `_data/navigation/<nav>.yml` with every `url` prefixed by the folder, so
  a url in a navigation file is the page's address INSIDE its version
  (`/configuration.html`), the API reference's `/api/` included. The latest's data file is named `v1-2-0.yml`,
  not `v1.2.0.yml`, because Jekyll drops the dots from a data file's name
  when it makes the key. The frozen versions keep `v1-1-0.yml` and
  `v1-0-0.yml`. The header carries the switcher: the version
  read, and each other one linked to the same page when it has it and to
  its overview when it does not. A row's `status`, when it has one, is
  drawn beside that version in the switcher (`_data/versions.yml`). A
  page of an older version opens with a line naming the latest
  (`_layouts/default.html`).

* **THE API REFERENCE IS PER VERSION TOO** (rcbj, 2026-11-17). TypeDoc
  is not committed: `pages.yml`'s `jsdoc` job generates one reference per
  row of `_data/versions.yml`, the latest from the commit being deployed
  and every other from its row's `ref` (a release tag, `v1.1.0`, `v1.0.0`), each
  with THAT tree's own `run-jsdoc.sh`, and the build copies each to
  `/<folder>/api/`. `api/index.html` here is a redirect to the latest
  version's reference, so the address 1.0.0 published still answers.

* **THE OLD TOP-LEVEL ADDRESSES REDIRECT** (rcbj, 2026-11-17). Every
  address the unversioned site published (`/configure-oauth2-grants.html`),
  which bookmarks and every running 1.0.0 service link to, gets a small
  no-script redirect page to the same page in the newest version that has
  it. `.github/scripts/root-redirects.sh` writes them into the built site
  in `pages.yml`, so none is committed and a new page is covered without a
  hand edit; a real top-level page (`index.md`, `api/index.html`) is
  never overwritten.

**Making the next release's snapshot** (when 1.2.0 ships and develop moves
on): `git mv` the pages in `v1.2.0/` to the new release's folder and
restore `v1.2.0/` from the `v1.2.0` tag, which is what this folder did for
1.1.0. Add the new row at the TOP of `_data/versions.yml` and its
`_data/navigation/<nav>.yml`, drop `status` from the row that just
shipped, and repoint every reference to the latest
folder: `git grep -n 'docs/v1\.2\.0'` and `git grep -n 'iya-sts/v1\.2\.0'`
find them, and so does a path joined as `'docs', 'v1.2.0'` (generators,
tests, `REUSE.toml`, the prose catalogs, the `CLAUDE.md` files, the
README). A translated catalog changes only the path; its entry's `en`
hash is updated to the new English, since the wording did not change.
`REUSE.toml` keeps the MIT annotation of each frozen debugger chapter as
well as the latest one.
**The release notes are folded in at the same time** (*Release notes*,
below): before the `git mv`, replace the loop in the shipping release's
`release-notes.md` with the text it renders — every note under its heading,
in the page's order (the kinds, then the issue number), each body as
written — and delete that release's `_release_notes/<folder>/`, so a frozen
page is static text like every other. Then give the new latest folder's page
a `## <next>` section holding the loop with its folder name changed, add
`_release_notes/<next folder>/`, and move `tests/release_notes.js`'s two
paths to it. A built site of the shipping release, before and after the
fold, must render the same entries.

## Release notes: one file per change (#2218, rcbj 2026-11-25)

**A change to the release being written adds a FILE of its own and never
edits `v1.2.0/release-notes.md`.** Almost every pull request that dropped
out of the develop merge queue on 2026-11-24/25 dropped on a conflict in
that page, because every change appended at the same spot. The file is
`_release_notes/v1.2.0/<issue>-<slug>.md` (the slug a few lowercase words
of the title, hyphenated):

```markdown
---
title: "LDAP messages have a maximum size before bind"
kind: security
issue: 2220
---
The paragraph or paragraphs you would have written under 1.2.0, in
markdown. A link is relative to `docs/v1.2.0/` (`[LDAP](ldap.md#limits)`).
```

* **`kind`** is one of `added`, `changed`, `behaviour-change`, `fixed`,
  `security`, and gives the heading its label: `New:`, `Changed:`,
  `Behaviour change:`, `Fixed:`, `Security:`, then the title. The title
  therefore carries no label of its own. An optional **`heading`** replaces
  the whole drawn heading; the migrated entries use it where the old one
  had another label or none (`New documentation: …`, `HSTS can be
  preloaded`), so their anchors did not move. A new note should not need
  it.
* **The body has no `#`, `##` or `###` heading** (it would break the page's
  outline); `####` is fine. Two notes for one issue take two slugs.
* **The page gathers them at build**: `_config.yml` declares the
  `release_notes` collection with `output: false`, and the `## 1.2.0`
  section of the page is a Liquid loop over the notes under
  `_release_notes/v1.2.0/`, drawn by kind (behaviour changes first, then
  security, new, changed, fixed) and by issue number within a kind. Two
  notes of one issue come in no fixed order. The body arrives already
  converted to HTML, which is why `jekyll-relative-links` (a generator that
  runs on the page's own source) never sees its links, and the loop turns
  `.md"` and `.md#` into `.html` itself.
* **A released version's section stays static text**, on this page and on
  the frozen pages; the fold at release time is in *Making the next
  release's snapshot*, above.
* `tests/release_notes.js` holds the names, the front matter, the kinds,
  the links and the loop. It cannot build the site; a change to the loop
  is checked by building it, which works locally with GitHub's own image
  (`ghcr.io/actions/jekyll-build-pages`, `bundle exec jekyll build` with
  `BUNDLE_GEMFILE=/Gemfile`, since its entrypoint needs a GitHub token for
  the metadata plugin), removed afterwards.

**The split with `CLAUDE.md` is by AUDIENCE, and it is the thing to get right
when adding a page.** A `CLAUDE.md` answers "why is this code the way it is" for
whoever is about to change it. A page here answers "how do I use this service"
for somebody who is not going to read the source. The same fact belongs in one of
them, not both — if a page here starts explaining why a module inverts a
dependency, it is in the wrong file.

**Do not restate what the service publishes about itself.** This project's
strongest documentation is live: `GET /admin/sts-metadata` lists every endpoint from
the running Express router and cannot go stale, `GET /oauth2/rfc9700` publishes
every requirement with what is and is not enforced, `GET /spiffe` publishes the
forty-two SPIRE methods with a reason for each of the six that are unimplemented,
`GET /admin/ldap/service` says the directory is schemaless, and `GET /admin-api/openapi.json`
is generated from the model in `models/api/` (#1390). A page that copies any of those lists is a
second copy that will be wrong within a month — LINK to them and say what a
reader should look for.

**Every page is plain markdown with a YAML front matter block** carrying `title`
and `nav_order`. Jekyll's `minima` theme renders it. The search index is the
one file a script writes, and it writes it into the built site rather than
into this directory (*Search*, below). The release-notes page is the one
page that is ASSEMBLED, by Jekyll itself and not by a script here
(*Release notes*, above).

**ONE PAGE IS GENERATED, AND IT IS THE EXCEPTION THAT PARAGRAPH NOW NAMES.**
`error-codes.md` is written by `node common/error_codes.js --docs` from the
table in that module, and must not be edited by hand — `tests/error_codes.js`
fails when the two differ. It passes both tests above rather than breaking them:
the list of codes is published by NO endpoint a reader could be linked to
instead (a code is recorded on the audit row and in the log, and is never sent
to a client), and a hand-kept copy of several hundred rows beside the table
they come from is the second copy that is wrong within a week. The page is
committed, so it still reads in the repository and on the site with no build
step here; what the generator replaces is the typing, not the file.

**AND `openapi/` IS THE SECOND (rcbj, 2026-11-06).** Each published API's OpenAPI
document as pages to read, written by `tests/tools/regenerate-openapi-pages.sh`
and held by `tests/openapi_pages.js`. It is a copy of what the service publishes,
which the rule above refuses; rcbj asked for it because a reader of this site
has no running service to ask, and generating it removes the reason for the rule.
A changed operation or model owes a regeneration in the same commit.

**AND THE MODEL READING PAGES ARE THE THIRD (#1390).**
`data-model-directory.md` and `data-model-persistence.md` are written by
`node common/model_emit.js --docs` from the directory catalogue and the
PostgreSQL model, the same model the TypeSpec emitter writes. A host
runs that as `tests/tools/regenerate-model-docs.sh`, because the emitter
is compiled only in an image. They must not be edited by hand.
`tests/model_directory.js` and `tests/model_postgres.js` fail when they
differ. The API models are not another copy of this kind: their reading
form is `openapi/`, above. `postgres-schema.md` stays the explanation of
the tables and is not regenerated. `ldap-schema.md` stays the explanation
of the names.

Adding a page: write the markdown in the latest version's folder, add it
to the right section of that version's `_data/navigation/<nav>.yml` so it
appears in the sidebar, and link it from
`index.md`. A console or portal screen that page explains gets its row in
`common/web_doc_links.ts` in the same change (`admin-ui/CLAUDE.md`, *A link
to the documentation*). There is no index to regenerate.

**A sidebar item may link to a SECTION of another page** (rcbj, 2026-10-30,
#564): the *Authorization* section gathers the pages about a decision
(`authorization.md`, the overview, then XACML, FGA, AuthZEN, the remote PEP,
delegation) and LINKS to the authorization sections that belong on the
OAuth, configuration, GNAP, devices and console pages, rather than moving
them and splitting those pages. Such an item's `url` carries a `#` fragment,
which is a kramdown id of the target page; the sidebar never marks it
current, because `page.url` has no fragment. `tests/doc_links.js` holds
every sidebar fragment, and every link in `authorization.md`, to a heading
of its page, so renaming a heading fails there rather than quietly landing a
reader at the top of a long page.

**The sidebar is four small overrides of minima 2.5.1, the version GitHub
Pages ships**: `_layouts/default.html` (minima's, with the sidebar
beside the content), `_includes/header.html` (the logo, `docs/logo.png`, as
the title, the version switcher, and the menu button a narrow screen
needs), `_includes/sidebar.html` and `assets/main.scss` (minima's
stylesheet imported, then the layout). `_includes/version.html` is the
versioned site's, above. No script draws the menu: the narrow-screen
menu is a checkbox, as minima's own header was. The header's search box is
`assets/search.js` (*Search*, below). `header_pages` is gone: it put
every page across the top, and at twenty-six pages that was not navigation.

## Search (#2305)

The header's box searches the guides of the version the reader is on. The
landing page, and `search.md`, search the latest until a query names
another (`?v=v1.0.0`). `assets/search.js` fetches
`<folder>/search-index.json` the first time a reader searches that
version and matches in the browser. The index is not a file in `docs/`.
`pages.yml` runs `.github/scripts/docs-search-index.js` on the built
site, after Jekyll, the API copy and the root redirects, under sudo. The
script reads the rendered HTML, the `<main class="page-content">` only
(the sidebar lists every page), and skips `<folder>/api/` (the TypeDoc
tree). A new page is included on the next build, with no hand edit. A
local `jekyll serve` has no index until the script is run on that
`_site`, and the box then says the index is not available.

`search.md` stays at this root, outside every version folder, so a frozen
version's pages are not edited to add a results page. The box on a frozen
version still searches that version: the script indexes every folder
`_data/versions.yml` names.

**A protocol page has one shape**: Features, Development and
product mode, Configuration (a table of every `common/config.js` key for the
family: setting, environment variable, default, runtime, what it does), Design
decisions, In the running service, Related. The configuration table is a copy
of rows in `common/config.js` and will drift when a row changes — the live
source is the protocol's console page and `GET /admin-api/config`, and the
table says so; update it when you change a row for that family.

## `debugger/`, a chapter that is mostly a COPY (#1717, 2026-11-13)

**rcbj asked for the embedded debugger's documentation to be a chapter here.**
Two of its pages are this service's own and are written like any other page
here: `debugger/index.md`, the chapter and its table of guides, and
`debugger/access.md`, which covers reaching the debugger, who may use it, turning it on, and
`DEBUGGER_IMAGE=debugger-none`. **Everything else under `debugger/` is a
COPY of the id-proto-debugger user guides at the release the image embeds
(0.9.5)** — its `docs/v0.9.5/oauth2-oidc/`, `saml/` and `wstrust/` with the
screenshots, `saml-assertion.md`, `saml-decoders.md`, `jwt-tools.md`,
`digital-signature.md` and `what-is-a-protocol-debugger.md` — under that
project's MIT licence (`REUSE.toml`).

The copies were changed in exactly these ways, and a refresh repeats them:
`nav_order` added; a note under the title saying where the page came from;
`https://localhost:3000` → `https://localhost:8444` and `:4000` → `:8444/api`
(the embedded build's own addresses); "the mock STS" → iya-sts; links to this
site made relative; links to debugger pages that were NOT copied pointed at
`github.com/rcbj/id-proto-debugger/blob/<release>/docs/v<release>/`; and
the "start it from a checkout" and "regenerating the screenshots" passages replaced by
pointers to `access.md` and to that project. Its developer notes (`kerberos.md`,
`scim.md`, `ssf.md` and the rest, which begin by listing the source files they
cover) were not copied: this directory is for somebody using the service.

**A bump of `DEBUGGER_IMAGE` owes a refresh of the copies**, or the guides
describe a debugger the image no longer carries; the release named in
`index.md`, in each page's note and in the GitHub links is the one to move.

## `sessions.md` and `caep-events.md`, and the line between them

`sessions.md` and `caep-events.md` are close enough together that the split
needs stating, or the next person to add to either will add to the wrong one:

* **`sessions.md` defines the NOUN.** What a session IS in each of the three
  senses this service uses the word, what the record holds, how one is created
  and ended, and the six places one is visible. It is the page every other one
  can point at instead of re-explaining.
* **`caep-events.md` is about what goes OUT.** Which activity fires each of the
  eight CAEP events, what each carries, and the three gates one passes on its
  way to a receiver.

Both were written against a rule this directory already had and which they
strain: *do not restate what the service publishes about itself.* The catalogue
of CAEP members IS published live, at `/admin/caep` and `/admin-api/caep`, so
that page links to it and documents the TRIGGERS instead — which no endpoint
can report, because a trigger is a fact about the code. The same test decided
`sessions.md`: the session RECORD's fields are published nowhere, so they are
written out; the row shape of `/admin-api/sessions` is in the OpenAPI document,
so it is not.

## `directory.md`, and the pages that own one object

`directory.md` is the Directory chapter. A user and an application are
protocol-independent, and that pair is what the service is about. The
chapter says how they relate to a policy, and which page configures
each. It does not restate the object. The objects' own pages stay where
they are:

* **`people.md` defines the person.** The subject, the filing name, and
  sign-in names (`stsPseudonym`, #644). The attribute rows stay in
  `ldap-schema.md`, the console's Users page stays in `admin-console.md`,
  how an identity is placed stays in `ldap.md`, and the session record
  stays in `sessions.md`.
* **`applications.md` defines the application.** The identifier, the
  filing name, the name each protocol calls it, and a registration
  beside a sighting, then its fields, the console page and the
  per-application settings.
* **`policies.md` is which profile applies**, and the attribute policy's
  fields. The split with the kind's own page is the section below. An
  XACML policy in `ou=policies` is `authorization.md` and `xacml.md`, not
  a profile.

A new fact about how the three objects relate goes in `directory.md`. A
new fact about one object goes on that object's page. The sidebar's
*Configuring a person*, *Configuring an application* and *Configuring a
policy* items are sections of `directory.md`, so renaming those headings
fails `tests/doc_links.js`.

## `policies.md`, and the pages that own one kind

`policies.md` is the account of **Directory → Policies** after #1234: the
seven kinds, and the one rule they share — the holder names the profile, the
lowest precedence applies, and a dangling name means what that kind says.
The fields of a kind stay on the page that already owned them
(`authentication.md`, `passkeys.md`, `languages.md`, `service-accounts.md`,
`post-login-activities.md`, `configure-scim.md`). A new fact about *which
profile applies* goes in `policies.md`. A new fact about *what a profile's
rows do* goes on the kind's page. The console's documentation link for
`/admin/policies` points here (`common/web_doc_links.ts`).

## The API reference under /api/ is generated, not written here (2026-09-27)

The sidebar's *API reference* is TypeDoc output built from the source's
`/** */` blocks. `.github/workflows/pages.yml` runs it in a `jsdoc` job and
copies the pages into the built site after Jekyll, so nothing under `docs/`
holds them. Locally, `./run-jsdoc.sh` writes the same pages to `./apidocs/`.

- **Tooling:** `tests/tools/jsdoc/` holds the TypeDoc config, a tsconfig, and
  its own pinned TypeScript 6. The repository's TypeScript 7 has no JavaScript
  API for TypeDoc to call.
- **What is covered:** `server.js`, `sts_metadata.ts` and every service
  directory, never the vendored copies.
- **Page text:** a function's page shows its JSDoc block and nothing else.
  The `//` prose above it stays in the source.
- **Rebuilds:** `pages.yml` no longer filters on `docs/**`, because a source
  change now changes the site.
