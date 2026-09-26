# CLAUDE.md — `risk/`

**Risk scoring (#62).** The plan, with the libraries and the schema, is on
issue #62: the plan comment (§1–§9) and the library comment after it. This
file is the maintainer's half: what is here, why it is shaped as it is, and
what is not here yet.

| File | What it is |
|---|---|
| `risk_store.ts` | Where risk scoring keeps what it keeps. The postgres driver's `risk*` methods when the driver has every one (`RISK_GROUP`); the same methods over maps in this process otherwise. The address arithmetic (`addressNumber`, `addressText`, `rangeOf`, `prefixOf`) every lookup rests on. |
| `risk_datasets.ts` | The external datasets: the catalogue, the formats, import, verification, activation, rollback, deletion, retention, the dataset directory, lookups, and the two scheduler jobs. |
| `risk_failures.ts` | Every refused password, attributed to a person or a name's digest and a network. |
| `risk_model.ts` | **The Freeman et al. score, ported** from das-group's notebook (MIT; the notice is at its head and in `LICENSE.md`). Pure: it reads counts and answers a number. |
| `risk_engine.ts` | **Assessing one sign-in**: enrichment, the device, the history read before it is moved, the model, the evaluators, the level, and every row it writes. Since P3 also the FACTS the issuance policy decides on (`factsOf()`, `factsForIssuance()`), the step-ups an authentication meets (`satisfiedBy()`), whether a risk Deny is enforced, each person's standing per process, and the decision written back onto the assessment (`settle()`). **It decides nothing itself**: the issuance policy does. |
| `risk_terms.ts` | **Whose data, on what terms, and who accepted them**: the provider table, each provider's credit as its licence asks (`attributionOf()`), and the recorded acceptance without which no provider's data is imported. |
| `risk_install.ts` | **The install-time loader**: an operator's CLI, not part of the running service, that pulls each dataset into the database under the provider terms the operator accepts by name. |
| `risk_upload.ts` | **A dataset file uploaded** (#215): the console's multipart form and `POST /admin-api/risk/upload`, streamed to `risk.uploadDirectory`, hashed on the way, handed to `importVersion()` by path; the per-process `risk.upload-cleanup` job. |
| `risk_expand.ts` | **The one expansion path** (#215): gzip and zip told apart by content and expanded as `importVersion()` reads them — an upload, the dataset directory and the loader alike — with the decompression-bomb and one-entry refusals. A utility class of static methods; no slot. |

`admin-ui/risk_admin.ts` is Monitoring → Risk; `/admin-api/risk`,
`/admin-api/risk/:action` and `/admin-api/risk/upload` are its rule 7 twins. **Since P3 (2026-09-22) the
issuance policy decides on the score**: see *Risk is decided by the issuance
policy*, below.

## Phases, and where this directory is

| Phase | State |
|---|---|
| P0 | **Done** (2026-09-22): every refused session answered (`authn/CLAUDE.md`), authentication events with context, JA4 on the main port (`tls/CLAUDE.md`). |
| P1 | **Done**: schema version 7, the datasets, the failure history, the page. |
| P2 | **Done** (2026-09-23): the model (a port of Freeman et al. from `das-group/rba-algorithm`, MIT), `sts_risk_assessments`, `sts_risk_feature_counts`, `sts_risk_subjects`, `sts_risk_session_context`, device signals (`bowser`, `isbot`). Observe only. |
| P3 | **Done** (2026-09-22): the risk facts in every issuance request, three risk rules in the built-in `role-issuance` policy, step-up at the doors that can ask, enforced in product and observed in development. The design change is on #62 (comment 5787912263). |
| P4 | **Done** (2026-09-22): the `risk-response` policy and the reactions it permits, taken once per assessment; continuous evaluation of a live session's device, TLS client and network; the `risk.rescore` job; CAEP risk-level-change emitted on its own. |
| P5 | **Done** (2026-09-22): FIDO MDS3 — the `fido.mds3` dataset, the BLOB verified to the FIDO root and its chain's revocation checked, a rollback refused, the latest BLOB only, and `authenticator-compromised` scored at sign-in and by the rescore job. Mail (#63) is its own ticket. |
| P6 | **Done** (2026-09-22): "this was me" / "this wasn't me" on `/portal/sign-ins` (schema 9's `feedback`); breached passwords by the Pwned Passwords k-anonymity range API (`common/breached_passwords.ts`); optional browser fingerprinting, off by default, scored `new-device` (`authn/CLAUDE.md` argues the script). |

## THE LICENCE BOUNDARY: NOTHING THIRD-PARTY IS SHIPPED (2026-09-22)

An independent licence review of the plan's libraries and data sources (the
comment on #62 after the library comment) found the software clean and the
DATA the thing to be careful with. Its recommendations are built in, and they
are one rule with three consequences:

**iya-sts distributes no third-party dataset.** Every dataset is an
ADMINISTRATOR-SUPPLIED input, obtained by the deployment under its provider's
terms and pulled into the deployment's own database at install time. There
are three classes of asset, and only the first ships:

| Class | What | Rule |
|---|---|---|
| **A. Dependencies that ship** | `bowser` (MIT), `isbot` (Unlicense), FingerprintJS ≥5 or ThumbmarkJS (MIT), the Freeman port (MIT — keep das-group's notice with the ported code, P2), JA4 in-tree (BSD-3, notice in `LICENSE.md`) | Licence-compatible with MIT. |
| **B. Administrator-supplied datasets** | DB-IP Lite, IPinfo Lite, the Tor exit list, FireHOL lists, FIDO MDS3, Pwned Passwords, MaxMind GeoLite2 | Inputs, never project assets. `PROVIDERS` in `risk_datasets.ts` carries each one's terms, and the page draws them. |
| **C. Test data** | Every fixture | SYNTHETIC: documentation and reserved address ranges (RFC 5737, 3849, 2544), documentation ASNs (RFC 5398), invented names — each provider's FORMAT, none of its DATA. `tests/no_third_party_datasets.js` fails on a provider's file in the tree. |

What each provider's terms change here:

* **DB-IP Lite (CC BY 4.0) — a link, not a sentence.** Its licence asks a web
  application for a link back on every page that displays or uses its
  results. So the attribution is DATA on the version (`attribution`,
  `parameters.attributionUrl`), every lookup carries `attributions` with the
  link, and Monitoring → Risk draws it as an anchor beside the dataset and
  under every lookup. A later page that shows a result (P2's assessments)
  owes the same, which is why it travels with the values.
* **IPinfo Lite (CC BY-SA 4.0) — ShareAlike.** Supported as an
  administrator-supplied import only; nothing IPinfo-derived ships. A
  deployment that distributes its own populated database has ShareAlike to
  resolve first, and the page says so.
* **FireHOL is an aggregate**, not "public": level 1 carries DShield, Feodo,
  Fullbogons and Spamhaus DROP, each under terms of its own. Supplied and used
  internally; never shipped.
* **The Tor exit list**: the exact list's terms are the operator's to check.
* **FIDO MDS3 is contractual metadata, not open data** (P5): the latest valid
  BLOB is used and a statement no longer in it is deleted — so, unlike a GeoIP
  dataset, **an MDS3 version gets no rollback retention** — and the metadata is
  not copied or redistributed. Tested with a SYNTHETIC BLOB signed by a test
  key.
* **Pwned Passwords is not CC BY 4.0** (that is HIBP's breach and paste data):
  the API carries no licensing or attribution requirement, and the
  downloadable corpus's terms are checked before the filter is built — by the
  deployment, from its own download (P6). The filter is never shipped.
* **GeoLite2 stays unsupported** until the EULA question is settled
  (`supported: false`; an import naming it is refused).
* **A provider's attribution cannot be replaced by the importer**: only the
  operator's own list may carry one of its choosing.

**Pulling the data at install time is `risk_install.ts`.** `node
risk/risk_install.js --manifest datasets.json --accept-terms
dbip-lite,tor-project` with `STS_DATABASE_URL` set. A dataset whose provider
is not named in `--accept-terms` is refused and its terms printed; a URL is
fetched over HTTPS only, kept as it arrived, and imported exactly as an
upload is — a `.gz` or `.zip` expanded by `risk_expand.ts` as it is read
(#215; the loader gunzipped by the address's NAME until then). It is an operator's tool, run by an init container or a deploy
step — **for the datasets it loads, the running service dials nobody**. The
one exception is the FIDO MDS3 BLOB since #105: MDS3 section 3.2 says a FIDO
server MUST be able to download it, so `risk.mdsUrl` (empty by default) is
fetched by the `risk.mds-refresh` scheduler job — see *The FIDO metadata*,
below, and the root `CLAUDE.md`'s row of addresses the service dials. It imports the service's datasets and the
default realm's lists; another realm's list goes through the console or the
API, where the realm is known to exist.

## AN ACCEPTANCE IS RECORDED, AND AN IMPORT NEEDS ONE (2026-09-23)

The second licence review on #62 approved the plan on four conditions, and
this is the first of them: **operator accountability for third-party terms**.
Until it, only the install-time loader asked, and it recorded nothing; the
console, the API and the dataset directory imported a provider's data with
nobody having agreed to anything.

* **No provider's data is imported without an acceptance of its CURRENT
  terms** (`STS-RISK-0014`), from any door: the loader's `--accept-terms`,
  the console's checkbox or its *I have read and accept these terms* button,
  the API's `acceptTerms: true` or `POST /admin-api/risk/accept-terms`. The
  dataset directory never accepts on anyone's behalf; it needs one recorded
  already. The operator's own list needs none.
* **An acceptance is a row in `sts_risk_terms_acceptances` (schema 8)**,
  appended and never changed: the provider, the terms TEXT as this build
  states it and its DIGEST, who (the console's administrator, the loader's
  `--operator` or OS user, or "a management API client", whose request the
  audit log names), the door, the deployment (host name), the provider's
  terms-page digest when the loader fetched it, and when. Also an audit row
  (`risk.terms.accept`), and a JSON line in the loader's `--terms-log` —
  written where the loader runs, never in the source tree. **Acceptances are
  not personal data about the people who sign in**, so they go to the
  database whenever there is one, sealing or not.
* **Terms that change must be accepted again.** The acceptance is of the
  digest: a build that restates a provider's terms stops that provider's
  imports until somebody accepts the new text, and the page says *the terms
  changed since they were accepted*. The loader's `--check-terms` fetches the
  provider's own terms page and warns (`STS-RISK-0015`) when it differs from
  the page seen at the last acceptance, which is how a change on the
  PROVIDER's side is noticed.
* **A credit is what CC BY 4.0 section 3(a) asks**: the attribution linked to
  the source, the licence named and linked, and that the data was imported
  and reformatted here (`attributionOf()`). Every lookup and every assessment
  carries its providers' credits, and Monitoring → Risk draws a *Data
  credits* block under everything it shows — the failures' networks
  included — for every provider an active dataset holds.
* **The review's other conditions**: DB-IP's attribution on every output (the
  credits block); IPinfo documented in the operator-facing README as data that
  must stay in the deployment's database and never be bundled with a
  software distribution, with DB-IP the documented default; and the
  fingerprinting opt-out, which binds P6 — off by default, per realm, a
  console and API switch, and its own scripted-page argument. The README's
  *What is kept about the people who sign in* is the privacy statement a
  deployment builds its own notice from; the lawful basis is the
  deployment's.

## THE DATA IS IN THE DATABASE, AND THAT IS A POSTGRES GUARANTEE

rcbj's rule (2026-09-22): **everything a score takes from an external source is
kept in the database.** So a dataset is imported into `sts_risk_*` rows by
version, with its provenance in `sts_risk_dataset_versions`, and looked up with
SQL — one descending probe of the primary key per lookup. That is why the
`maxmind` library proposed at first is not a dependency: the CSV releases of
DB-IP Lite and IPinfo Lite are imported, and a `.mmdb` never has to be read.

**The schema has thirteen tables and P1 uses six of them.** The other seven
(`assessments`, `feature_counts`, `session_context`, `subjects`,
`fido_authenticators`, `geo_locations`, `dataset_blobs`) were added in the same
schema version so that the schema moves once for the subsystem. `postgres/
CLAUDE.md` and the driver's block argue the DDL; the plan's §7 gives every
column.

**On `memory` and `ldif` there are no risk tables**, and `risk_store.ts`
answers the same methods from maps in the process. The data is gone at the next
restart and `describe()` says so on the page. A GeoIP file of millions of rows
imported into memory costs memory; postgres is where that belongs.

## A DATASET ARRIVES AS A FILE, AND IS VERIFIED BEFORE IT IS ACTIVE

`risk_datasets.ts`'s header has the four rules. What they cost to get right:

* **The service fetches nothing.** A version is pulled in at install time
  (`risk_install.ts`), uploaded as a file or pasted as a list (on the page or
  the API), or dropped in `risk.datasetsDirectory` with a JSON manifest by an
  operator pipeline.
* **A refused version is kept.** A SHA-256 that does not match
  (`STS-RISK-0002`), a file with no row (`STS-RISK-0004`), a version that
  shrank past `risk.datasetShrinkLimitPercent` (`STS-RISK-0003`, the truncated
  download) — each is a row in `sts_risk_dataset_versions` with its reason, and
  the active version is untouched. A version already recorded is never loaded
  twice: `beginVersion()` inserts `ON CONFLICT DO NOTHING`, which is also what
  makes the directory job safe on every node.
* **The version's name is its SHA-256 by default**, so the same file seen again
  is the same version.
* **Activation is one transaction with a `risk-dataset` change row**, so every
  other process drops its lookup cache through `persistence.js`'s applier. In
  memory the store tells its own listeners. Nothing polls.
* **Stale counts for nothing and never refuses.** A lookup leaves a stale
  dataset out and names it in `stale`. The page draws the state.
* **An operator list is per realm**, and refused for a realm that does not
  exist; every other dataset is the whole service's (`realm = ''`).

**Retention is a scheduler job**, `risk.retention` (hourly, cluster):
superseded versions past `risk.supersededRetentionDays` and refused versions
lose their rows, and failures past `risk.failureRetentionDays` are deleted.
Batched `DELETE`, because the application role has no `TRUNCATE` and cannot
create a partition. **The directory import is the other job**,
`risk.dataset-directory`, off while `risk.datasetsDirectory` is empty.

## A DATASET FILE IS UPLOADED, STREAMED, AND EXPANDED AS IT IS READ (#215)

rcbj (2026-09-24): pasting a DB-IP city file into a text box does not work,
so Monitoring → Risk takes a FILE — `POST /admin/risk/upload`, a plain
multipart form with no script — and `POST /admin-api/risk/upload` takes the
same file as its body with the fields as query parameters. `risk_upload.ts`'s
header has the six rules; what they cost to get right:

* **THE BODY PARSERS SKIP EXACTLY THESE TWO PATHS.** `common/app.js` drains
  every body into memory at 5 MB, and a handler reading a drained stream
  waits for ever. `app.isStreamedUpload()` is the one predicate — method and
  path after the realm prefix, case-insensitive with an optional trailing
  slash, because that is how express routes — and it reads `baseUrl` too,
  since the console gate asks it from inside `app.use('/admin', …)` where
  express has taken the mount off `req.path`, and a predicate reading
  `req.path` alone would leave the gate checking a token it cannot see. A
  body that reaches the
  handler already read is refused, STS-RISK-0031, rather than waited on.
* **AUTHENTICATION IS ON THE HEADERS, THE REST IS IN THE FIELDS.** The gate
  (session, role, policy) and the API's token gate run before the route. The
  console's CSRF token and a realm administrator's reach are in the form, so
  the gate leaves the token to the upload (the same predicate), and the form
  sends its FIELDS BEFORE ITS FILE — the token first, as `withCsrf()` puts it
  — and `receiveForm()` checks the token, the realm (`admin_scope.ts`'s
  `/admin/risk` rule) and `datasets.precheck()` (dataset, format, realm,
  provider, terms) when the file part begins, before it writes a byte. A
  field after the file is refused, but only after the fields before it
  passed, so a forged form is refused as forged. A declared length over
  `risk.uploadMaxBytes` (STS-RISK-0028) and a directory with no room
  (`statfs`, STS-RISK-0029) are refused before the body is read at all.
* **A REFUSAL NEVER DESTROYS THE REQUEST.** `stream.pipeline()` would, and
  its first stream is the request whose socket the 413 still has to go out
  on. The request is unpiped and drained, and the route answers
  `Connection: close`.
* **THE DISPATCH PATH ALREADY STREAMS**: `request_pool.js`'s `proxy()` pipes
  the body to its worker, and the parsers — and this exemption — run there.
  The import runs in the process that received the upload.
* **EXPANDED BY CONTENT, NEVER ONTO DISK** (`risk_expand.ts`): gzip by
  1f 8b, zip by `PK\x03\x04`, plain otherwise, streamed into
  `importVersion()`'s line reader — so the disk an upload needs is its own
  size. A zip holds one data entry (directories and `__MACOSX/` aside) or is
  refused as ambiguous (STS-RISK-0033). The expanded bytes are counted and
  refused at `min(risk.expandedMaxBytes, max(16 MiB, risk.expansionMaxRatio
  × stored))` (STS-RISK-0032); a zip entry's declared size is held to the
  same before it is read. A corrupt stream is STS-RISK-0034. The dataset
  directory and the loader share it, so **a `sha256` anywhere is of the file
  as delivered**, compressed.
* **ASYNCHRONOUS**: `importVersion()`'s `onBegun` answers the upload (202)
  the moment the version is recorded `loading`; a refusal before that is the
  answer. The upload hands its streamed digest in (`fileSha256`) rather
  than have the file read twice.
* **CRASH LEFTOVERS HAVE TWO JOBS AND NO TIMER.** Every batch stamps the
  version's `progressAt` through `store.touchVersion()`, which writes only
  while the row is still `loading`; `risk.stalled-imports` (cluster) refuses
  a version with no stamp for `risk.importStallMinutes` (STS-RISK-0035), and
  the importer, finding its stamp refused, stops rather than write `ready`
  over it. `risk.upload-cleanup` (per process, quiet) touches the files its
  process holds, removes its own unheld ones and another process's untouched
  for the same time (STS-RISK-0036), and never a file whose name is not an
  upload's. In the cluster stack each node has its own upload volume.
* **NODE'S 300 s `requestTimeout` BOUNDS AN UPLOAD**, which the docs say:
  a very large file over a slow link goes through the loader or the
  directory. The cluster stack's balancer is L4 and needs nothing
  (`tests/cluster/haproxy.cfg` says why).

## THE FAILURE HISTORY IS WRITTEN WHERE EVERY PASSWORD DOOR MEETS

`credentials.verify()` and `verifyAsync()` call `noteRefusal()`, which requires
`risk_failures.ts` LAZILY and records the refusal without anybody waiting. The
sign-in screen and its password factor, the password grant, an LDAP bind,
WS-Trust, SCIM and SSF Basic and EST all arrive there; **Kerberos does not**,
because pre-authentication is decided in the parent project's locked KDC codec.
Left out on purpose: `no-store` and `store-error` (the service failed) and
`password-reset-required` (the password was right).

**What a row holds is the argument of the plan's §7 and it is not negotiable
here**: the person's `sub` when the name resolves, otherwise a keyed digest of
the name (people type their password into the username field); the /24 or /48
prefix; the address only sealed; never the name as typed. **It goes to the
database only where it can be sealed** — a key-encryption key exists, which
product mode requires — and is held in the process otherwise.

## EVERY SIGN-IN IS SCORED, AND NOTHING IS DECIDED BY IT (P2, 2026-09-23)

`authn/authn.ts`'s `assessRisk()` hands every session that is established or
re-authenticated to `risk_engine.ts`'s `assess()`, and does not wait. A keyed
API caller (SCIM, SPIRE) and an unauthenticated session are not assessed.
Token-only grants (the password grant, an LDAP bind) make no session and are
not assessed yet; they reach the decision in P3 through the issuance gate.

**THE MODEL IS A PORT, AND THE TEST SAYS SO.** `risk_model.ts` follows the
notebook's code — its weightings, its unsmoothed user side, its smoothing at
the first level only, its quarter of the population likelihood for a value
the person never used, its refusal to score a first sign-in. Its own test
vectors come from das-group's RBA dataset, which is third-party data and not
here, so `tests/risk_model.js` holds the port to the notebook's functions,
run unchanged on a synthetic seeded history: all 82 scores reproduced exactly.
**That is why its MIT notice travels with the file**; had it been written from
the paper alone, the review on #62 would have wanted that recorded instead.

**THE FEATURES**, the notebook's two hierarchies:

| Feature | Levels (weight) | Where the value comes from |
|---|---|---|
| address | the address (0.6), its ASN (0.3), its country (0.1) | a KEYED DIGEST of the address — never the address — and the active datasets |
| browser | the User-Agent (0.539), browser and major version (0.268), OS and version (0.188), device type (0.005) | the event's `uaFingerprint`, and `bowser` on the header, read and dropped |

The history is `sts_risk_feature_counts`: a row per (subject, level, value)
for the person and for the realm's population (`'*'`), the population's
combination rows (`ip>asn`, valued `<address digest>|<asn>`) for the one
distinct count the smoothing needs, and a `user` row per person for the
number of users. It is read BEFORE the sign-in is counted — the notebook's
order — and moved with one statement, so two nodes never lose a count.

**THE EVALUATORS** are factors on the score, in `SIGNALS`: a Tor exit (×5),
the reputation list (×5), the operator's deny list (×20; ×50 until #226) and allow list
(×0.2), an automated client (×10), a JA4 this person never signed in with
(×2), five refused passwords for the person in the last hour (×3), twenty from
the network (×3). **They are a first calibration and deliberately visible**:
every assessment on the page lists its signals, and what they should be is
read off that record before P3 lets anything be decided by them.

**THE LEVEL** is CAEP's own: LOW, MEDIUM from `risk.mediumScorePercent` (100,
a score of 1 — the model's even odds), HIGH from `risk.highScorePercent`
(1000); UNSCORED for a first sign-in with no signal — **and for every
sign-in before the person has `risk.minimumHistory` (5) earlier ones**
(2026-09-23, rcbj): with one or two sign-ins the model is mostly the
population's prior, and a new person's second sign-in read as MEDIUM and was
asked for a security key. `new-device` and `new-tls-stack` wait for the same
history; the evidence signals (lists, an automated client, refused passwords,
a compromised security key) apply however new the person is. The person's standing
(`sts_risk_subjects`) keeps the level it came from, which is what P4's
`risk-level-change` will say.

**WHAT IS KEPT is personal data, so it follows the failures' rule**: in the
database only where the key-encryption key can seal and digest it, in the
process otherwise. An assessment holds the address sealed and as a prefix,
the provider attributions with the values (DB-IP's link travels with every
row that shows a location), the dataset versions that answered, and the
signals. `risk.assessmentRetentionDays` and `risk.historyRetentionDays` bound
it, through the `risk.retention` job.

## RISK IS DECIDED BY THE ISSUANCE POLICY (P3, 2026-09-22)

**rcbj's directive: every authorization decision is XACML policy**, so the
rules can be changed in `ou=policies` without a rebuild. So nothing in this
directory decides anything. `risk_engine.ts` states FACTS, the embedded PEP
(`xacml/xacml_role_pep.ts`) puts them in the ENVIRONMENT category of the
issuance request every door already asks (`common/issuance_gate.js`), and the
built-in `role-issuance` policy decides roles and risk in ONE evaluation. A
separate `risk-decision` policy asked only at `startSession()` was the first
design and was dropped the same day: one policy is what every session AND
every token passes through.

| Attribute (`xacml_templates.ts`'s `RISK_ATTRIBUTE`) | What |
|---|---|
| `urn:sts:xacml:risk-level` | LOW, MEDIUM, HIGH, UNSCORED |
| `urn:sts:xacml:risk-score` | the score (absent for a first sign-in) |
| `urn:sts:xacml:risk-signal` | a bag of `SIGNALS` keys that fired |
| `urn:sts:xacml:risk-satisfied` | a bag: `second-factor` (acr `mfa`), `security-key` and `second-factor` (amr `hwk`) |
| `urn:sts:xacml:risk-held` | a bag (#226): what the person HOLDS — `second-factor` (an app or a key), `security-key` (a key) — from `credentials.mechanismsFor()`, asked by the PEP's `heldFactors` dep |

**THE THREE RULES** are Deny rules ahead of the role rule, under
ordered-deny-overrides, each carrying the obligation
`urn:sts:xacml:obligation:risk` (`risk-action` refuse or step-up,
`risk-step-up-factor`): HIGH refuses; MEDIUM with a key signal (template
parameter `keySignals`, default `automated-client, new-tls-stack`) asks for a
security key; any other MEDIUM asks for a second factor. **The obligation is
how the PEP tells a risk Deny from a role Deny**, which matters twice: the
risk one is only OBSERVED in development (`mode.observesRiskOnly()`,
`risk.enforceInDevelopment`) — the PEP asks again without the facts and the
roles decide — and only a risk Deny can be answered by a step-up.

## #226: THE DAY RISK LOCKED EVERY ADMINISTRATOR OUT (2026-09-25)

**What happened.** With IPinfo, FireHOL-style block lists and Pwned loaded on
a compose stack, every sign-in to the console and the portal was refused:
`operator-deny` ×50 on `172.29.0.1`, the Docker bridge, over a model score
of 0.42 — 21.1, HIGH, and `risk-high` refused the console like anything
else. A block list carried the bogons (172.16.0.0/12), and every person
arrives through the bridge from the same address, so the whole population
was listed at once. rcbj had to wipe the instance; `STS_RISK_ASSESS_SIGN_INS
=false` would have recovered it and nobody knew. **Three changes, rcbj's
decisions of 2026-09-26:**

* **`risk.listsMatchSpecialPurpose`** (ON by default: lists mean what they
  say). Off, `RiskEngine.countedLists()` sets the Tor, reputation and deny
  lists aside for a loopback, private, link-local or reserved address — the
  set `federation_http.ts`'s `internalAddressProblem()` refuses to dial, so
  the service has one list of internal addresses. The allow list is never
  set aside. The model row of the assessment names what was
  (`listsSetAside`). The rescore job reads the same function.
* **A known context caps the ADDRESS evidence at MEDIUM** (`ADDRESS_SIGNALS`:
  the three raising lists and `network-failures` — what everybody behind one
  NAT shares). Known means `risk.minimumHistory` earlier sign-ins from this
  address digest AND this User-Agent fingerprint, counted separately from
  the person's own history (the two are not a joint count; nothing records
  the pair, and a new one would start empty). The score is held just under
  the HIGH line rather than the level relabelled, so score, level and the
  bands stay one story; the model row says `knownContext` and what was
  `capped`. `riskOf()` carries `knownContext` so the rescore job caps a list
  a session gains later. Credential evidence is never capped.
* **The console is never refused on risk.** `role-issuance`'s `neverLockOut`
  (default `sts-admin-console`; `none` for no application, since a blank
  answer is the default) excludes those applications from the three rules
  and adds two Deny step-ups (a key if the person holds one, else a second
  factor if they hold one) and a PERMIT rule, ANDed with the role condition,
  whose obligation `urn:sts:xacml:obligation:risk-alarm` makes the PEP audit
  `xacml.issuance.alarm` and warn under STS-RISK-0038. **A policy decision,
  not an `if`**: the PEP only supplies `risk-held` and reads the obligation.
  It is the one place a step-up the person cannot answer is not a refusal,
  and it is rcbj's call that a bricked cluster is worse than an alarmed
  permit. `operator-deny` went from ×50 to ×20 the same day.

**Two more found on rcbj's stack the same day.** (1) The six second-factor
finishers in `authn.ts` handed `startSession()` no application, so after a
step-up the policy was asked about `""` and the console's rules never
matched — see the comment at the gate call in `startSession()`. (2) A
sign-in that CROSSES into HIGH triggers `risk-end-sessions`, taken a moment
after the assessment is answered — after the door has started the session
the policy just permitted on that same risk. It ended that session: the
`admin` user's alarm-permitted console sign-in lost its authorization code
150 ms later. So `noteChange()` now takes, for a sign-in (`phase` user), the
ids of what the person holds IN THE SAME TICK as the assessment
(`account_state.heldBy()` → `logout.heldIds()`), and the reaction ends only
those; nothing held means nothing ended (an empty selection is a GLOBAL
logout to `terminate()`). A session re-assessment or the rescore job still
ends everything. The alarm is raised on the SESSION decision only, once per
sign-in, not on every code and token issued on it.

**UNKNOWN NEVER DENIES.** No assessment puts no attribute in the request, and
every risk rule is then inapplicable: the datasets' rule carried into the
decision.

**WHERE THE FACTS COME FROM**, in the gate's order: the caller's own
(`startSession()` hands in the assessment its door made BEFORE the session
existed); the session the caller hands the gate (`session.risk`, what the
sign-in established, with the session's own `amr`/`acr` — the authorization
endpoint, the token endpoint by the grant's `sid`, SAML 2.0 and 1.1,
WS-Federation, GNAP); otherwise the person's STANDING held in this process
(`risk.standingValidMinutes`, `/admin/caches`' `risk.standings`) — which is
all a Kerberos service ticket has, because the KDC is the parent's locked code
and asks synchronously, and what WS-Trust reads from the store before it asks.
**A standing held per process is a known gap**: a node that did not see the
sign-in or read the store holds none, and decides that ticket on roles.

**THE GATE'S TWO SHORTCUTS WAIVE THE ROLE QUESTION ONLY.** No application
named, or `roles.enforceIssuance` off, used to answer "allowed" without
asking; with risk facts the policy is asked with `rolesWaived`, and only a
Deny about risk refuses. Either shortcut would otherwise be a way round every
risk decision.

**THE DOORS.** Each door that authenticates a person calls
`authn.assessSignIn()` after the credential verifies and before
`startSession()`:

| Door | A step-up |
|---|---|
| the sign-in screen (`finishPasswordSignIn()`) | asked for there, as a configured second factor is; the assessment rides on the step and the finisher's session is decided on it again with both factors |
| the wallet door (`beginSecondFactorAfterWallet()`) | asked for after the presentation |
| `/oauth2/authorize` on an existing session | sends the person to re-authenticate with the factor demanded, RFC 9470's road |
| SPNEGO, federation's ACS, WS-Trust, the token endpoint, the KDC | cannot ask: refused, unless the event already meets it (a ticket or an assertion claiming `mfa`) |
| `GET /tls/sign-in` | not assessed before its session — it runs inside a realm switch an await could lose — so it is decided on the person's standing and assessed after, as in P2 |

**A STEP-UP NEVER ENROLS.** A person holding nothing that answers the demand
is refused (STS-RISK-0018), because an elevated risk suspects exactly the
password-holder who would enrol their own authenticator.

**A CLIENT IS TOLD NOTHING.** The PEP's refusal sentence is "Authentication
failed." or "A stronger authentication is required." — issuance sites put
`why` in an error_description, a SOAP fault or a SAML status — and the level,
the signals and the assessment are on the audit row (STS-RISK-0016, -0017).

**WHAT WAS DECIDED is written back onto the assessment** (`settle()`): the
decision (`permit`, `step-up`, `refuse`, `observe:<action>`), the policy, the
refusal's code and the session it became. An assessment made after the
session (a door that assessed nothing) keeps `observe`.

**A REALM OVERRIDE WRITTEN BEFORE P3 READS NO RISK ATTRIBUTE** and decides
nothing on risk; `issuancePolicyState()` says so on the console rather than
rewriting the operator's document.

## A CHANGE OF RISK IS ANSWERED BY POLICY TOO (P4, 2026-09-22)

**The reactions are rules**, for P3's reason: ending somebody's access is an
authorization decision. When an assessment moves a person's standing
(`sts_risk_subjects`) to a new level, `risk_engine.ts`'s `noteChange()` asks
the built-in **`risk-response`** policy (`xacml/xacml_risk_pep.ts`,
`xacml.riskResponsePolicy`) — ONCE PER REACTION, the action-id naming it
(`RISK_RESPONSE` in `xacml_templates.ts`) and a Permit meaning do it:
`risk-announce` (CAEP risk-level-change, `ssf.ts`'s `riskAutoEmit()`),
`risk-end-sessions` (`account_state.endEverything()`),
`risk-credential-compromise` (RISC, `account_signals.ts`) and `risk-disable`
(`account_state.setDisabled()`, RISC reason `hijacking`). **Not one question
with a list of obligations**: a combining algorithm that stops at its first
Permit returns that rule's obligations only, and a reaction dropped by the
combining is the worst way for this to fail.

**The built-in document** announces every change but a person's first LOW
(every new person's second sign-in), ends everything on crossing into HIGH,
tells RISC on crossing into HIGH with a credential signal
(`credentialSignals`, default `account-failures`), and **builds no disable
rule** unless `disableFromScore` is given: a reaction an attacker can aim at
somebody else is the operator's decision.

**ONCE PER ASSESSMENT**: `claimAction()` records, per reaction, the
assessment it was last taken for (`sts_risk_subjects.actions`; a
conditional UPDATE on postgres), so a retry or a second node answering the
same change takes nothing. **Development announces and observes the rest**
(`enforced()`), one `risk.response` audit row either way.

**A reaction happens only where somebody proved the password**: a sign-in is
assessed after its credential verified, so an attacker who knows a name and
not the password cannot end its owner's sessions by signing in badly.

**CONTINUOUS EVALUATION.** `authn.ts`'s `sessionOf()` compares every
presented session with the authentication it rests on — the device FAMILY
(`familyOf()`: browser and OS without versions, carried on `session.risk`),
the JA4 and the /24 or /48 — and on a change assesses it again in the
background, `phase: 'session'`: scored against the history and NOT counted
into it, since a replayed cookie's context is not where the person signs
in. The answer becomes `session.risk` (`adoptSessionRisk()`). A context is
assessed once (`riskDriftKey`). A browser updating itself is not a new
device; that was the first false positive the test found.

**THE `risk.rescore` JOB** (`risk.rescoreEveryS`, a cluster job) re-checks
every live session against the lists and the failure history and RAISES one
that gained a signal (`rescoreSession()`, `phase: 'rescore'`) — never lowers
it: a list that rotated an address out is not a reason to trust a session
more than its sign-in did. The device and the model cannot move without a
request, which is continuous evaluation's business.

## THE FIDO METADATA (P5, 2026-09-22)

**Since #105 (2026-09-23) it is also WebAuthn's trust source**, and two things
here changed for it rather than a second MDS client being written:

* **`lookupAuthenticatorBy(kind, key)`** finds a model by AAGUID, AAID or
  attestation key identifier (`acki`, how a fido-u2f authenticator is found),
  and the row's `metadataStatement` — kept whole but for its icon since P5 —
  carries the `attestationRootCertificates` the attestation chain must reach.
  The postgres driver's `riskLookupFido()` returns the statement too; the
  memory store always did.
* **`risk.mds-refresh`**, a cluster scheduler job, downloads the BLOB from
  `risk.mdsUrl` through `federation_http.fetchPublished()` (with `maxBytes`,
  `risk.mdsMaxBytes`: a BLOB is megabytes) daily, hourly once the active one is
  past its nextUpdate, and hands it to `importVersion()` — the recorded
  acceptance and every check below apply unchanged. A published serial not
  above the active one is not imported (the ordinary day, and not a rollback
  worth an audit row); a download that fails is `STS-RISK-0027`.
  `mdsState()` / `mdsSnapshot()` report the active BLOB to `/admin/webauthn`.

`authn/webauthn_attestation.ts` refuses a registration from a model this data
calls compromised (`STS-AUTHN-0237`) — the same `compromised` flag the scorer
reads.

`fido.mds3` is a dataset like the others — imported by `importVersion()`
from the loader, the directory or an upload, under a recorded acceptance of
`fido-mds3`'s terms — with its own path, `importMds()`, because it is one
signed document rather than lines, and MDS3 section 3.1.8 says what must be
true of it before a byte is kept:

* **Signature and chain**: `pki.verifyFidoMdsBlob()` — the header's `x5c`
  to the FIDO root with `verifyPathToAnchors()`, the signature with
  `crypto.verifyCompactJws()` and an algorithm list named here. **The root is
  not shipped**: with `risk.mdsTrustAnchors` empty it is GlobalSign Root CA -
  R3 out of node's `tls.rootCertificates`, by name. A chain and signature
  check belongs in `pki.js` and `crypto.js` (rcbj's rule of 2026-09-21), and
  that is where it is.
* **Revocation**: `revocation_status.verdictFor()` on the chain, fetching
  its CRLs, under the mode's revocation policy — the same question a
  presented chain is asked. In the loader it is the loader that dials; on an
  upload it is the service, as for any presented chain.
* **Rollback**: the serial `no` must exceed every BLOB already processed
  (`parameters.mdsNo`), or STS-RISK-0024.
* **The latest only** (`latestOnly`, FIDO's terms): activating a BLOB
  deletes every older version's rows at once; the version rows stay as the
  record. The shrink check does not apply — the signature is the integrity
  check, and a BLOB may legitimately list fewer models.
* **Stale** past its own `nextUpdate` plus `risk.mdsStaleGraceDays`.

The rows (`sts_risk_fido_authenticators`, from schema 7) are one per key a
model is listed under — AAGUID, AAID, attestation key identifier — with the
status reports, the latest status by date, the certification level, and
**`compromised` if any report ever said REVOKED, USER_VERIFICATION_BYPASS or
one of the three KEY_COMPROMISE statuses** (a later "update available" does
not recall a key the model already leaked). The metadata statement is kept
without its icon.

**Scored**: `lookupAuthenticator()` by the AAGUID the WebAuthn ceremony
recorded on the event; a compromised model is `authenticator-compromised`
(×50 — HIGH on its own), and the assessment records the BLOB's version and
the model's certification level. The rescore job checks a live session's key
the same way, so a BLOB that newly reports a model reaches the sessions
resting on it. `risk-response`'s default `credentialSignals` include it, and
RISC `credential-compromise` then names a FIDO credential. An unlisted
model, and the all-zero AAGUID of an authenticator that attests nothing, are
unknown and decide nothing.

## THE REGISTERED DEVICE (#164 phase 5, 2026-09-26)

rcbj's decision 4 on #164: "full integration with risk scoring". The device
register (`common/devices.ts`) is a second source of facts about a sign-in,
beside the datasets, and it enters the engine the way everything else does —
as SIGNALS on the score — so nothing here decides on it either.

**THE FACT ARRIVES WITH THE SIGN-IN.** `authn.assessSignIn()` recognises the
device (`device_recognition.recognize()`, through `registeredDeviceFor()`)
BEFORE it asks the engine, and hands it in as `registeredDevice`; a door that
assesses after the session hands in the event's. The recognition is
remembered on the request, so the event built a moment later is the same
answer and the device's last use moves once. **The gap**: the sign-in
screen assesses BEFORE its own WebAuthn ceremony (P3's order — the
assessment decides whether to ask for one), so a linked platform credential
presented THERE is on the session's event, and so in the policy, the acr and
the token claims (phase 6), but not in that sign-in's score. A certificate
on the connection is scored at every door, and a door that assesses after
its credential (the wallet, federation, a session started directly) scores
whatever it recognised.

| Signal | Factor | When |
|---|---|---|
| `compromised-device` | ×50 | the recognised device is marked compromised — HIGH on its own, as `authenticator-compromised` is |
| `non-compliant-device` | ×3 | the recognised device is `not-compliant` (evidence: not held back for history) |
| `unregistered-device` | ×2 | no device of the PERSON'S OWN was recognised — none, or somebody else's — and they have registered one (`devices.holdsAny()`, an index lookup) or `devices.expectRegistered` is on; waits for `risk.minimumHistory` |
| `compliant-attested-device` | ×0.5 | their own device, compliant, attested |
| `compliant-device` | ×0.8 | their own device, compliant, self-asserted |

**THE SCOPE OF `unregistered-device` IS THE ARGUMENT.** In a realm where
nobody has registered anything it would fire on every sign-in and move
every score by the same factor — calibration noise, not evidence. So it is
about people who registered a device, or a realm that says it expects
everybody to; and it is an ABSENCE, which is why it waits for history as
`new-device` does (a device owner's second sign-in from a laptop would
otherwise be MEDIUM and asked for a second factor on this alone).

**THE LOWERING FACTORS NEEDED NO NEW MACHINERY**: the score is a likelihood
ratio times the evaluators' factors, and `operator-allow` (×0.2) already
lowered it. Two rules keep them honest: a lowering factor alone never makes
an UNSCORED sign-in scored (`LOWERING_ONLY`), and a compromised device is
never "compliant".

**THE DEVICE FEATURE.** Where the person's own registered device proved the
sign-in, the history's `device` feature is `registered:<id>` rather than the
browser fingerprint (P6), and it is never `new-device`: its key was proven
theirs at enrolment, which is stronger than any history. `riskOf()` carries
the id as `device.registered`. Somebody else's device changes nothing about
the fingerprint path.

**THE DEVICE'S OWN LEVEL** (`setDeviceLevel()`): after a sign-in (phase
`user`) the person's own device proved, the device takes THAT SIGN-IN'S
LEVEL through `devices.setRiskLevel(…, { source: 'risk' })`, which sends
CAEP risk-level-change with principal DEVICE only when the level moves. The
same level, not a score of its own: the model is one ratio over the whole
context and nothing in it says which part is the device's; the latest
sign-in the device proved is the best evidence there is about what is
happening on it. UNSCORED sets nothing; a compromised device's HIGH is held
by `setRiskLevel()` itself; a live session's re-assessment sets nothing; a
device that is somebody else's is not moved by this person. A register that
will not store it is STS-DEVICE-0036, and the sign-in stands.

Monitoring → Risk draws the device beside the browser on every assessment
(the model row's `device`, which is a JSON value in both stores, so no
column moved); Monitoring → Devices draws the levels. `tests/device_risk.js`
holds all of it.

## WHAT THE PERSON SAYS ABOUT A SIGN-IN (P6, 2026-09-22)

`/portal/sign-ins` (`portal/portal_sign_ins.ts`) lists a person's own
assessments of thirty days, and `risk_engine.ts`'s `feedback()` records what
they say about one — once, and only about their own (schema 9's
`sts_risk_assessments.feedback`, `feedback_at`):

* **"This wasn't me" is taken at its word**: the standing goes to HIGH with
  `reported-not-me`, and the change is answered by the risk-response policy —
  everything the person holds ended (this session included), RISC told the
  credential is compromised (`reported-not-me` is in the default
  `credentialSignals`). Anybody who can sign in as the person can say it,
  and the worst it does is what should happen to anybody holding the
  password.
* **"This was me" vouches only from somewhere trusted**: it lowers the
  standing to LOW only when said from ANOTHER session that is itself LOW or
  unscored. From the flagged session it is recorded — calibration reads it —
  and moves nothing, or a hijacked session could talk itself back to LOW.

Monitoring → Risk shows each answer beside its assessment.

## MONITORING → RISK SCORING (2026-09-22)

rcbj asked for "a Monitoring → Risk Scoring page that includes metrics about
the risk scoring system". It is `/admin/risk-scoring`, drawn by
`admin-ui/risk_admin.ts` beside `/admin/risk`, and returned as JSON by
`GET /admin-api/risk/metrics`.

**It shows two kinds of number, and the page keeps them apart.**

* **Counts over a window**: the assessments by level, door, decision,
  phase, country, score band, signal and feedback, a series per bucket,
  and the standings. These are rows, so the STORE counts them:
  `risk_store.assessmentMetrics()` and `subjectLevels()`. On postgres the
  driver groups them with GROUP BY, and on the memory store they are counted
  in process. Both hand back the same grouped rows to `metricsOf()`, so the
  two stores cannot answer in different shapes.
* **Counts this process keeps**: things that are not rows (the time to
  assess, a failed assessment, the reactions taken, the rescore runs, the
  breached-password screening). The engine's `tally` and
  `breached_passwords`' own counts hold them for THIS process since it
  started. They are the one per-process part of the page, and the page says
  so.

The score bands are decades around the level thresholds (see
*Calibration*, below). `RiskStore.bandOf()` spells them in TypeScript, and
the driver spells them again in SQL. The 2026-09-22 probes ran a throwaway
postgres and the driver against `tests/risk_metrics.js`'s rows, the
calibration rows included, and gave the same answers from both stores.

## CALIBRATION (2026-09-22)

rcbj asked for the factors to be calibrated. **Nothing can be calibrated
without real sign-ins**, so what was built is the means:

* **The report**: `RiskEngine.calibrate()`, on Monitoring → Risk Scoring
  and in `/admin-api/risk/metrics`.
  - Thresholds come from the window's own score quantiles:
    `percentile_disc` on postgres, and the same index rule in memory.
  - A factor's suggestion is the current factor scaled by its signal's
    "not me" rate against the baseline, where the rates come from the
    answers on `/portal/sign-ins`.
  - Below 100 assessments no threshold is suggested, and below 20 answers
    for a signal no factor is (constants in the engine, both stated on the
    page).
  - `reported-not-me` is left out, because it is the answer rather than
    evidence for one.
* **The knob**: `risk.signalFactors`, per realm, read by `factors()` at
  every scoring site: the evaluators, the live-session re-check and the
  report itself. That makes the report's suggestion the value it
  measures from.

**The answers are a biased sample**, since a flagged sign-in is likelier to
be asked about. The report says so, and it never applies itself.

**The score bands were wrong in the first version of the page.** They were
decades up to "≥ 1", as though the thresholds were fractions of 1. The
score is a likelihood ratio, and MEDIUM and HIGH begin at 1 and 10, so
everything MEDIUM or worse fell into one band. They now run from below 0.01
to 100 and over, and those two thresholds are edges.

## A REALM ADMINISTRATOR ON THE RISK PAGES (2026-09-22)

Both pages were service pages until rcbj asked for "realm admins see
/admin/risk". **Most of what they show is a realm's**:

* the assessments;
* the standings;
* the refused passwords;
* the operator allow and deny lists, whose rows carry the realm.

So they are realm pages now, **with the service's parts cut out in two
places that agree**:

* **The gate**: `admin_scope.ts`'s `/admin/risk` action rule refuses a
  provider's terms, any dataset but a per-realm one, and a list of another
  realm. Its read rule refuses `?realm=` naming another realm.
* **The page**: `risk_admin.ts`'s `realmOnly` view drops the service's
  datasets, providers and acceptances (the acceptances name service
  administrators). The page drops the settings, all `risk.` rows and so all
  service-only, and the scoring page drops `process`, since this process's
  counts are every realm's.

**The data credits stay**, because DB-IP's licence asks for them on any page
that displays its results.

**The unnamed realm is the one the page is drawn in** (`realms.currentId()`),
which it was not before: `realmOf()` answered `default`, and that was right
only while nobody but a service administrator in the default realm saw the
page.

## A PERSON'S RISK ON THEIR USER PAGE (2026-09-22)

rcbj asked for it "large and colorful": `admin.ts`'s `riskBadge()` opens
the Directory → Users page of a person with their standing, in the level's
colour. **The standing is read before the page is drawn**, by
`admin_views.riskFor(req.query)`, which both the console's route and
`/admin-api/users` await and hand to the view as an argument: the user
views are synchronous and the standing is a row in a store that is not.
**It is an argument, not a field on the request**, because
`tests/admin_actions_layer.js` holds that a view reads nothing off the
request but its query — the first version hung it on `req` and failed that. `engine.standingFor()` never rejects;
a store that cannot answer draws the grey UNKNOWN badge, the same as a
person never assessed, because the page must still open.

## BREACHED PASSWORDS (P6, 2026-09-22)

rcbj chose the **range API** over a filter built from the downloadable
corpus (whose terms were the open question): `common/breached_passwords.ts`
sends the first five characters of the password's SHA-1
(`crypto.pwnedPasswordDigest()`) to `risk.breachApiUrl` through
`federation_http.fetchPublished()`, matches the suffix itself, and caches the
answer per prefix. It is in `common/` because every password door reaches
it, and it is a password rule (NIST SP 800-63B 3.1.1.2) before it is a risk
signal.

**THE DOORS STAY SYNCHRONOUS**: `screen()` is awaited at each door and
leaves a VERDICT for a few minutes; `credentials.preparePassword()` —
synchronous, and inside LDAP's atomic modify — reads it with `verdictOf()`
and refuses a breached password (STS-AUTHN-0222). The doors: the portal's
three (activation, reset, change), the forced change at sign-in, the console
and `/admin-api` users routes (`screenAll()` before `runClaimed()`), a typed
keytab-reset password, and LDAP add/modify (`screenedThen()` wraps the two
handlers, which are now `ldapAddNow()` / `ldapModifyNow()`). A door that
did not screen sets the password and is named in the log (STS-AUTHN-0223);
an API that did not answer sets it too (STS-AUTHN-0224). **Product mode
only**, and **OFF in every test run**: `tests/run.js` and
`docker-compose-run-tests.yml` default it off so no run dials the internet;
`tests/breached_passwords.js` turns it on with the API stubbed.

At sign-in (`risk.breachCheckAtSignIn`), a verified password that is
breached sets `pwdReset`, and the existing change step asks for a new one,
saying why.

## THE REQUIRE ORDER, AND THE TRAP IT HIT

The five libraries (the store, the terms, the datasets, the failures and,
since #215, the upload) and the page are built at **18j** in
`common/protocol_stack.ts`, after the scheduler page. **Nothing may require
them before the root does**: a module on the `InstanceSlot` pattern that is
loaded before `deferToRoot()` builds its own default instance, and the root's
install then throws. `persistence.js`, `credentials.ts` and `authn.ts` are
loaded long before 18j, so each reaches this directory with a `require()`
inside the function that runs at request or start time. `tls/client_hello.ts`
hit the same trap through `request_pool.js` in P0.

## Tests

* `tests/risk_datasets.js` — in process, on the memory store: the address
  arithmetic, every format, the refusals, activation, rollback, deletion,
  retention, staleness, per-realm lists, the directory, the failure history,
  the page's actions.
* `tests/risk_upload.js` (#215) — in process: gzip, zip and plain through
  both doors to `active`, the bombs, the ambiguous and corrupt archives, the
  cap and a full disk, the form's CSRF and field order and the route's role
  check, the API's body types, the exemption predicate, both crash jobs, and
  a `.gz` and `.zip` by path. `tests/vendored/sts_admin_risk_upload.js`
  (`local: true`) — the same over HTTP in every mode: a `.gz` through the
  API and a `.zip` through the console with a real session and token, a
  realm's upload, and the refusals.
* `tests/vendored/sts_admin_risk.js` (`local: true`) — over HTTP in every mode,
  so the postgres driver's SQL answers in `single-node` and `cluster`, and in
  `cluster` a version activated on one node is answered by both.
* `tests/postgres_schema.js` — the thirteen tables are in both copies of the
  DDL.
* `tests/risk_model.js` — the port against the notebook, on a synthetic
  history.
* `tests/risk_engine.js` — the device, UNSCORED then LOW, the evaluators to
  HIGH, nothing kept in the clear, the standing and the session context, and
  never a rejection. `tests/authn_session_refusals.js` C7: a real sign-in is
  assessed.
* `tests/risk_decisions.js` (P3) — the built-in policy and its XML round trip,
  every decision through the gate, the two shortcuts, facts from the session
  and from the standing, development observing, and over HTTP: a step-up
  refused for a person with no factor, answered with a code by one who has
  one, a session at HIGH issued no code, a MEDIUM session with a device
  signal sent back for a key, an operator deny list refused — and observed
  in development.
* `tests/risk_mds.js` (P5) — a SYNTHETIC BLOB (a root and signer minted in
  the test): an entry as rows, the verification's four refusals, import,
  rollback refused, the latest only, lookup, staleness, a revoked model
  scored HIGH, and a BLOB under another root refused and recorded.
* `tests/risk_response.js` (P4) — the `risk-response` policy in both shapes
  and its round trips, its decisions, sessions ended once per assessment,
  development observing, a realm override that disables, CAEP's new act, a
  browser update not assessed and a replayed cookie assessed and ended, and
  the rescore job raising a session whose address became a Tor exit.
* `tests/risk_metrics.js` — Monitoring → Risk Scoring on the memory store:
  every count of a window, the old and the other realm's left out, the
  signals beside their factors, a series that adds up, the standings, this
  process's counts, and the page without a script.
  `tests/vendored/sts_admin_risk.js` sections 8 and 9 hold the postgres
  driver's GROUP BY to the same sums over HTTP.
* `tests/risk_realm_admin.js` — a realm administrator on both risk pages:
  the gate's refusals and permissions, the realm-only views, and the pages
  drawn for them.
* `tests/risk_user_badge.js` — the badge on a person's Directory → Users
  page in each colour, grey when never assessed, the same standing on
  `/admin-api/users?user=`, and the link narrowed to the person.

**Not tested yet**: a real DB-IP or IPinfo release at full size — and it will
not be tested with one in this repository, because none may be committed; a
deployment's install-time run is where that is measured. GeoLite2 is not
supported until the EULA question on #62 is settled.
