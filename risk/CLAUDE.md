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
| `risk_engine.ts` | **Assessing one sign-in**: enrichment, the device, the history read before it is moved, the model, the evaluators, the level, and every row it writes. Observe only. |
| `risk_install.ts` | **The install-time loader**: an operator's CLI, not part of the running service, that pulls each dataset into the database under the provider terms the operator accepts by name. |

`admin-ui/risk_admin.ts` is Monitoring → Risk; `/admin-api/risk` and
`/admin-api/risk/:action` are its rule 7 twins. **Since P2 every sign-in is
scored and recorded, and nothing is decided by a score**: that is P3.

## Phases, and where this directory is

| Phase | State |
|---|---|
| P0 | **Done** (2026-09-22): every refused session answered (`authn/CLAUDE.md`), authentication events with context, JA4 on the main port (`tls/CLAUDE.md`). |
| P1 | **Done**: schema version 7, the datasets, the failure history, the page. |
| P2 | **Done** (2026-09-23): the model (a port of Freeman et al. from `das-group/rba-algorithm`, MIT), `sts_risk_assessments`, `sts_risk_feature_counts`, `sts_risk_subjects`, `sts_risk_session_context`, device signals (`bowser`, `isbot`). Observe only. |
| P3–P6 | The decision through XACML, continuous evaluation, fetching, MDS3, fingerprinting — the plan comment. |

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
fetched over HTTPS only (`.gz` gunzipped) and imported exactly as the console
imports one. It is an operator's tool, run by an init container or a deploy
step — **the running service still dials nobody**, so the root `CLAUDE.md`'s
table of the addresses the service dials has no new row, and P5's in-service
fetching may not be needed at all. It imports the service's datasets and the
default realm's lists; another realm's list goes through the console or the
API, where the realm is known to exist.

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
  (`risk_install.ts`), uploaded (a list you can paste, on the page or the
  API), or dropped in `risk.datasetsDirectory` with a JSON manifest by an
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
the reputation list (×5), the operator's deny list (×50) and allow list
(×0.2), an automated client (×10), a JA4 this person never signed in with
(×2), five refused passwords for the person in the last hour (×3), twenty from
the network (×3). **They are a first calibration and deliberately visible**:
every assessment on the page lists its signals, and what they should be is
read off that record before P3 lets anything be decided by them.

**THE LEVEL** is CAEP's own: LOW, MEDIUM from `risk.mediumScorePercent` (100,
a score of 1 — the model's even odds), HIGH from `risk.highScorePercent`
(1000); UNSCORED for a first sign-in with no signal. The person's standing
(`sts_risk_subjects`) keeps the level it came from, which is what P4's
`risk-level-change` will say.

**WHAT IS KEPT is personal data, so it follows the failures' rule**: in the
database only where the key-encryption key can seal and digest it, in the
process otherwise. An assessment holds the address sealed and as a prefix,
the provider attributions with the values (DB-IP's link travels with every
row that shows a location), the dataset versions that answered, and the
signals. `risk.assessmentRetentionDays` and `risk.historyRetentionDays` bound
it, through the `risk.retention` job.

## THE REQUIRE ORDER, AND THE TRAP IT HIT

The four libraries and the page are built at **18j** in
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

**Not tested yet**: a real DB-IP or IPinfo release at full size — and it will
not be tested with one in this repository, because none may be committed; a
deployment's install-time run is where that is measured. GeoLite2 is not
supported until the EULA question on #62 is settled.
