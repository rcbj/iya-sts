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

`admin-ui/risk_admin.ts` is Monitoring → Risk; `/admin-api/risk` and
`/admin-api/risk/:action` are its rule 7 twins. **Since P3 (2026-09-22) the
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
fetched over HTTPS only (`.gz` gunzipped) and imported exactly as the console
imports one. It is an operator's tool, run by an init container or a deploy
step — **the running service still dials nobody**, so the root `CLAUDE.md`'s
table of the addresses the service dials has no new row, and P5's in-service
fetching may not be needed at all. It imports the service's datasets and the
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

**Not tested yet**: a real DB-IP or IPinfo release at full size — and it will
not be tested with one in this repository, because none may be committed; a
deployment's install-time run is where that is measured. GeoLite2 is not
supported until the EULA question on #62 is settled.
