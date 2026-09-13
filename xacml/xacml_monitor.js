'use strict';
//
// File: xacml_monitor.js
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE'S AUTHORIZATION IS ACTUALLY DOING, COUNTED.
//
// Every other page in this family answers a question about CONFIGURATION —
// which policies exist, what one of them says, what the PDP would decide about
// a subject you type in. None of them answers the question somebody has when
// authorization is misbehaving in production, which is *how many decisions are
// being made, by whom, and how many of them are refusals*.
//
// That question needs numbers nobody was keeping. `xacml_pdp.js` has no
// counters and must never grow any — it is a DOM-free library with no I/O,
// which is the claim `xacml-pep/`'s thirty-line `helpers.js` shim exists to
// CHECK, and a counter in the evaluator would also count in the wrong process
// the moment the remote PEP loaded its build-time copy of it. So the counting
// is here, at the PEPs, and this module is a LEAF (rule 3): it registers no
// route, it requires `config`, `realms`, `helpers` and the PEP register, and
// NOTHING requires it that it requires back. That is load-bearing rather than
// tidiness — see *Why this file may not require the console* below.
//
// ---------------------------------------------------------------------------
// A DECISION AND AN ENFORCEMENT ARE TWO DIFFERENT COUNTS AND THIS FILE KEEPS
// THEM APART. IT IS THE WHOLE REASON THE FILE IS SHAPED LIKE THIS.
//
// XACML has FOUR decisions — Permit, Deny, NotApplicable, Indeterminate — and a
// PEP has TWO outcomes, allowed and refused. They are not the same tally seen
// twice:
//
//   * A **deny-biased** PEP refuses a NotApplicable. A **permit-biased** one
//     allows it. So one repository, one request and one decision produce
//     opposite enforcement depending on which PEP asked — which is exactly the
//     case `tests/xacml_pep.js` pins over seven probes because it is the case
//     nobody writes a test for.
//   * **An undischargeable obligation turns a Permit into a refusal** (section
//     7.2). So "allowed" is not even "how many Permits": a PDP that said Permit
//     and a PEP that refused is the specification working, and it is the one
//     enforcement outcome that looks like a bug from the client side.
//
// A page that showed one number called "allows" would therefore be wrong for
// whichever of those two questions the reader had. Both are counted, side by
// side, and the page says which is which.
//
// ---------------------------------------------------------------------------
// FOUR THINGS ASK THE PDP IN THIS PROCESS, AND ONLY THREE OF THEM ENFORCE.
//
// The catalogue below is the whole list and it is DATA rather than prose,
// because `/admin/xacml/monitor` renders it and `GET
// /admin-api/xacml/monitor` publishes it: a fifth caller added without a row
// here would be decisions nobody could see, and the count on the page would be
// quietly short.
//
//   `protected`  the DEMONSTRATION PEP at `/xacml/protected`. The only one
//                whose bias is settable (`xacml.pepBias`) and the only one that
//                discharges obligations, which is why it is the one the bias
//                and the section 7.2 rule are demonstrated on.
//   `issuance`   `xacml_role_pep.js`. Nine issuance sites ask it before this
//                service mints anything, through `common/issuance_gate.js`.
//   `access`     `xacml_access_pep.js`. Five gated surfaces ask it through
//                `common/access_gate.js`.
//   `pdp`        `POST /xacml/pdp` — **NOT A PEP AND NOT COUNTED AS ONE.**
//                Somebody else's PEP asked this service a question and enforced
//                the answer in their own process. This service saw the
//                DECISION and never the enforcement, so that row carries the
//                four decisions and NO allowed/refused figure at all — an empty
//                cell rather than a zero, because zero would read as "it
//                refused nothing".
//
// ---------------------------------------------------------------------------
// A REMOTE PEP'S NUMBERS ARE ITS OWN AND ARE NEVER SILENTLY ADDED TO THESE.
//
// `ou=peps` already holds `xacmlPepDecisions`, `xacmlPepAllowed`,
// `xacmlPepRefused` and `xacmlPepUndischargeable` — reported by the PEP on its
// heartbeat, cumulative in ITS process. This service did not see one of those
// decisions; that is what a remote PEP IS.
//
// So the snapshot carries THREE totals rather than one: `here`, what this
// process decided and enforced; `remote`, what registered PEPs report; and
// `combined`, the sum — offered because it is the figure somebody wants for a
// deployment, and labelled on the page as arithmetic over two different kinds
// of evidence rather than as a measurement. A page that printed only the sum
// would be asserting that this service watched things it did not watch, and a
// PEP that restarts makes its own half go DOWN.
//
// ---------------------------------------------------------------------------
// THE COUNTERS ARE PER TRUST REALM, IN MEMORY, AND DIE WITH THE PROCESS.
//
// Per realm because everything else in this family is: `ou=policies` is per
// realm, so a decision made under `/realm/acme` was made against acme's
// policies and adding it to the default realm's total would be counting two
// different services as one. `realms.map()` is the declaration, which is the
// rule `common/CLAUDE.md` states — **a store becomes per realm at its
// DECLARATION and nowhere else** — and `tests/realm_isolation.js` is the guard.
//
// In memory because these are OBSERVATIONS and this service persists nothing it
// observes. The audit log is already the durable record of a refusal
// (`xacml.issuance.refused`, `xacml.enforcement`), and a second durable copy
// with a different retention rule would be a second answer to "what happened".
// The page says the counters are since this process started, because a number
// with no epoch on it is a number somebody will misread.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE MAY NOT REQUIRE THE CONSOLE, AND THE PAGE IS NOT HERE.
//
// `xacml_access_pep.js` fills `common/access_gate.js`'s decider, and that
// module is required from `common/` — early, and far above `admin-ui/admin.js`
// at 18. If this file required `admin.js` in order to draw its own page, then
// the access PEP requiring this file would drag EVERY CONSOLE ROUTE into the
// express router at `access_gate.js`'s position (rule 1), ahead of `oauth2.js`
// and everything else. The symptom would not be an error: it would be
// `/admin/sts-metadata` reporting a different route order and a middleware
// applying to routes it was written to sit above.
//
// So this file counts and this file publishes a SNAPSHOT; the page that draws
// it is `/admin/xacml/monitor` in `xacml_admin.js`, which already requires the
// console and is required at 23c where that is safe. Same split as
// `common/admin_stats.js` and the pages that render it.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const config = require('../common/config');
// The error-code registry (a leaf). Tagged log lines only: an audit row per
// failed counter would be a second record on the path of every decision.
const errorCodes = require('../common/error_codes');
const realms = require('../common/realms');
// WHAT OTHER PROCESSES DECIDED. A LIBRARY (rule 3) requiring only `config` and
// `realms`, which is what keeps this file's require list to leaves — the
// property the comment above snapshot() says makes it safe to require from
// anywhere. With one process it answers an empty array.
const replication = require('../persistence/persistence_replication');
const peps = require('./xacml_pep_registry');

// ---------------------------------------------------------------------------
// THE CATALOGUE. Every asker of the PDP in this process, in the order the page
// draws them.
//
// `enforces: false` is the one row that is not a PEP and it is the reason this
// is a table with a flag rather than two lists: everything else about the
// `/xacml/pdp` row — its decision counts, its last decision, its place on the
// page — is identical to a PEP's, and two lists would have meant two renderers
// that could disagree about how a decision is displayed.
//
// `bias` is a FUNCTION rather than a value because `xacml.pepBias` is
// runtime-settable and per realm: a value read at require time would be the
// bias this process started with, printed beside counters that were produced
// under a different one.
// ---------------------------------------------------------------------------
const PEPS = [
  { id: 'protected',
    label: 'The demonstration PEP',
    kind: 'embedded',
    where: 'GET /xacml/protected',
    module: 'xacml/xacml.js',
    guards: 'One endpoint that exists to be asked. It guards nothing real — ' +
            'it is the PEP you point a client at to watch a bias and an ' +
            'obligation do their work.',
    enforces: true,
    // THE ONLY ONE WHOSE BIAS IS SETTABLE, and the page says so beside every
    // other row: `xacml.pepBias` governs THIS PEP. The issuance and access
    // PEPs are deny-biased by construction — an issuance or an access that is
    // not permitted does not happen — and a setting that appeared to change
    // that would silently do nothing.
    bias: function () {
      log.debug("Entering bias().");
      log.debug("Leaving bias().");
      return config.value('xacml.pepBias') === 'permit-biased'
        ? 'permit-biased' : 'deny-biased';
    },
    // The one PEP here that discharges obligations at all.
    obligations: true },

  { id: 'issuance',
    label: 'The issuance PEP',
    kind: 'embedded',
    where: 'common/issuance_gate.js, from nine issuance sites',
    module: 'xacml/xacml_role_pep.js',
    guards: 'Everything this service MINTS: an access token, an ID token, a ' +
            'refresh token, a SAML 2.0 or 1.1 assertion, a WS-Federation or ' +
            'WS-Trust token, a Kerberos ticket, a verifiable credential, a ' +
            'sign-on session.',
    enforces: true,
    bias: function () {
      log.debug("Entering bias().");
      log.debug("Leaving bias().");
      return 'deny-biased (fixed)';
    },
    obligations: false },

  { id: 'access',
    label: 'The access PEP',
    kind: 'embedded',
    where: 'common/access_gate.js, from five gated surfaces',
    module: 'xacml/xacml_access_pep.js',
    guards: 'The admin console, the user portal, /scim/v2, the SPIRE Server ' +
            'API, and /admin-api in product mode.',
    enforces: true,
    bias: function () {
      log.debug("Entering bias().");
      log.debug("Leaving bias().");
      return 'deny-biased (fixed)';
    },
    obligations: false },

  { id: 'pdp',
    label: 'The PDP endpoint',
    kind: 'endpoint',
    where: 'POST /xacml/pdp',
    module: 'xacml/xacml.js',
    guards: 'NOTHING. Somebody else\'s Policy Enforcement Point asked this ' +
            'service a question and enforced the answer in their own ' +
            'process. This service saw the decision and never the ' +
            'enforcement.',
    enforces: false,
    bias: function () {
      log.debug("Entering bias().");
      log.debug("Leaving bias().");
      return null;
    },
    obligations: false }
];

const BY_ID = {};
PEPS.forEach(function (row) { BY_ID[row.id] = row; });

// The four decisions, spelled as `xacml_model.js` spells them, keyed the way a
// counter row holds them. Written here rather than imported so that this file
// requires nothing of the engine — it counts strings the engine handed to a
// PEP, and a decision value this table has not heard of lands in `other`
// rather than being dropped, which is what makes a new decision value VISIBLE
// instead of silently uncounted.
const DECISIONS = { Permit: 'permit', Deny: 'deny',
                    NotApplicable: 'notApplicable',
                    Indeterminate: 'indeterminate' };

function emptyRow() {
  log.debug("Entering emptyRow().");
  log.debug("Leaving emptyRow().");
  return { decisions: 0, allowed: 0, refused: 0,
           permit: 0, deny: 0, notApplicable: 0, indeterminate: 0, other: 0,
           undischargeable: 0,
           lastAt: null, lastDecision: null, lastAllowed: null };
}

// PER TRUST REALM. See the header: `ou=policies` is per realm, so a decision
// made under /realm/acme was made against acme's policies, and one total over
// both would be counting two logical services as one.
const counters = realms.map({ persist: 'xacml_monitor.counters',
                              merge: 'own' });

// WHEN THE COUNTING STARTED. Declared here, above its one reader, because a
// module-level `const` used by a function defined above it is legal and reads
// like a bug — and this one is stamped at require time, which is the fact the
// page reports.
const startedAt = new Date().toISOString();

function rowFor(id) {
  log.debug("Entering rowFor().");
  if (!counters.has(id)) {
    counters.set(id, emptyRow());
  }
  log.debug("Leaving rowFor().");
  return counters.get(id);
}

// ---------------------------------------------------------------------------
// THE ONE CALL EVERY ASKER MAKES, AND IT IS PUT IN THE `allowed()`/`refused()`
// FUNNEL RATHER THAN AT THE RETURN SITES.
//
// Each embedded PEP already has exactly two functions every one of its answers
// passes through, which is what makes this two lines per module instead of
// eleven — and, much more importantly, what makes a return path added later
// counted BY CONSTRUCTION rather than by whoever adds it remembering. That is
// the same argument `common/delegation.js`'s header makes for its funnel, and
// the same one `crypto.js` makes about being the one place this service signs.
//
// **IT MUST NEVER THROW INTO ITS CALLER.** Every call site is on the path of an
// authorization decision — an issuance, a sign-in, a request to a gated
// surface — and a counter that could fail one of those would be a monitoring
// feature causing the outage it exists to show. So the body is wrapped and a
// failure is logged and swallowed, which is the rule `admin_stats.js`'s
// observers and `vc_claims.js`'s directory hooks already follow in the same
// direction.
// ---------------------------------------------------------------------------
function record(id, outcome) {
  log.debug("Entering record().");
  try {
    if (!BY_ID[id]) {
      // A NAME THAT IS NOT IN THE CATALOGUE IS LOGGED AND NOT COUNTED. It
      // would otherwise appear as a row on a page whose whole claim is that it
      // lists every asker of the PDP in this process, and a row nothing
      // describes is worse than a missing one.
      log.warn(errorCodes.tag('STS-XACML-0063') +
               'xacml: a decision was recorded against "' + id + '", which ' +
               'is not one of ' +
               'the ' + PEPS.length + ' askers xacml_monitor.js ' +
               'knows about. It is NOT counted — /admin/xacml/monitor claims ' +
               'to list every one of them, and a row with no description ' +
               'would break that claim rather than extend it. Add it to PEPS.');
      log.debug("Leaving record().");
      return;
    }
    // -----------------------------------------------------------------
    // EVERYTHING IS READ BEFORE ANYTHING IS WRITTEN, AND THAT ORDER IS A FIX
    // RATHER THAN A STYLE.
    //
    // The first version incremented `decisions` and THEN read the outcome. A
    // caller whose object threw on a property access — which is exactly what
    // `tests/xacml_monitor.js` provokes, and what a getter, a Proxy or a
    // half-built object does in real life — left the row with the decision
    // counted and no bucket, no allowed and no refused. The row's own
    // arithmetic then no longer reconciled: `allowed + refused + unenforced`
    // was one short of `decisions`, permanently, with nothing to say why.
    //
    // That is the very discrepancy the `unenforced` figure was added to
    // remove, reintroduced by the error path. So the reads happen first and
    // the writes are all-or-nothing: a throw now records NOTHING, which is
    // the only other honest option — half a count is worse than no count,
    // because it is indistinguishable from a real decision.
    // -----------------------------------------------------------------
    const said = outcome || {};
    const decision = String(said.decision || '');
    const enforces = BY_ID[id].enforces;
    const wasAllowed = enforces ? !!said.allowed : null;
    const wasUndischargeable = !!said.undischargeable;
    const bucket = DECISIONS[decision] || 'other';

    const row = rowFor(id);
    row.decisions += 1;
    row[bucket] += 1;
    // `allowed` is only counted where the asker ENFORCES. For the PDP endpoint
    // it is absent rather than false, and the difference is the point: an
    // undefined enforcement is "this service never saw one", and `false` would
    // have been "it refused".
    if (enforces) {
      if (wasAllowed) {
        row.allowed += 1;
      } else {
        row.refused += 1;
      }
      row.lastAllowed = wasAllowed;
    }
    if (wasUndischargeable) {
      row.undischargeable += 1;
    }
    row.lastAt = new Date().toISOString();
    row.lastDecision = decision || null;
  } catch (error) {
    // SWALLOWED, and the comment is the reason rather than an apology: this is
    // on the path of every issuance and every gated request in the service.
    log.error(errorCodes.tag('STS-XACML-0062') +
              'xacml: a decision counter threw and was ignored; the decision ' +
              'itself is unaffected: ' + error.message);
  }
  log.debug("Leaving record().");
}

// ---------------------------------------------------------------------------
// THE SNAPSHOT. What `/admin/xacml/monitor` draws and `GET
// /admin-api/xacml/monitor` answers, out of ONE call so the page and the JSON
// cannot disagree — the rule every view in this console follows.
//
// `policies` comes through an argument rather than by requiring
// `xacml_store.js` here. Not to avoid a cycle (there is none) but because this
// file is required by the access PEP, which is reached from `common/`: keeping
// its require list to four modules that are all leaves is what makes it
// obviously safe to require from anywhere, and the caller already holds the
// store.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THIS PROCESS'S COUNTS FOR ONE ENFORCEMENT POINT, PLUS EVERY OTHER
// PROCESS'S.
//
// `counters` is declared `merge: 'own'`: a decision count is an INCREMENT, so
// two processes writing one row would make the page alternate between their
// tallies while looking entirely plausible. Each writes its own and the fan-in
// is here, in the one function that reports any of it.
//
// **THE `last*` FIELDS TAKE THE LATEST RATHER THAN A SUM**, which is the one
// place a blind sum would be nonsense: "the last decision" across two
// processes is whichever happened most recently, not both of them added
// together. That distinction is why this is a function and not a loop over
// Object.keys.
// ---------------------------------------------------------------------------
function merge(id) {
  log.debug("Entering merge().");
  const mine = counters.has(id) ? counters.get(id) : emptyRow();
  const theirs = replication.remoteRows('xacml_monitor.counters', undefined,
                                        id);
  if (!theirs.length) {
    log.debug("Leaving merge().");
    return mine;
  }
  const out = Object.assign(emptyRow(), mine);
  theirs.forEach(function (row) {
    if (!row) {
      return;
    }
    Object.keys(out).forEach(function (field) {
      if (typeof out[field] === 'number' && typeof row[field] === 'number' &&
          field.indexOf('last') !== 0) {
        out[field] += row[field];
      }
    });
    if (Number(row.lastAt || 0) > Number(out.lastAt || 0)) {
      out.lastAt = row.lastAt;
      out.lastDecision = row.lastDecision;
      out.lastAllowed = row.lastAllowed;
    }
  });
  log.debug("Leaving merge().");
  return out;
}

function snapshot(policies) {
  log.debug('Entering snapshot().');
  const held = policies || { total: 0, enabled: 0, root: null };

  const rows = PEPS.map(function (definition) {
    const counted = merge(definition.id);
    return {
      id: definition.id,
      label: definition.label,
      kind: definition.kind,
      where: definition.where,
      module: definition.module,
      guards: definition.guards,
      enforces: definition.enforces,
      bias: definition.bias(),
      dischargesObligations: definition.obligations,
      decisions: counted.decisions,
      // ABSENT rather than zero where nothing enforced. See record().
      allowed: definition.enforces ? counted.allowed : null,
      refused: definition.enforces ? counted.refused : null,
      permit: counted.permit,
      deny: counted.deny,
      notApplicable: counted.notApplicable,
      indeterminate: counted.indeterminate,
      other: counted.other,
      undischargeable: counted.undischargeable,
      lastAt: counted.lastAt,
      lastDecision: counted.lastDecision,
      lastAllowed: counted.lastAllowed
    };
  });

  // The remote half, out of the register. `all()` already computes `current`
  // and `stale` per row against `syncToken()` and `xacml.pepStaleAfterS`, so
  // nothing about staleness is worked out twice.
  let remoteRows = [];
  try {
    remoteRows = peps.all();
  } catch (error) {
    // A REGISTER THAT CANNOT BE READ MUST NOT TAKE THE PAGE DOWN. The embedded
    // half of this snapshot is this process's own memory and is always
    // answerable; the remote half needs the directory, and a build with no
    // `ldap_server.js` has none.
    log.warn(errorCodes.tag('STS-XACML-0064') +
             'xacml: the remote PEP register could not be read for the ' +
             'monitor, so only the embedded half is reported: ' +
             error.message);
    remoteRows = [];
  }
  const remote = remoteRows.map(function (row) {
    return {
      id: row.name,
      label: row.name,
      kind: 'remote',
      where: row.notifyUrl || 'pulls only — no notify URL',
      module: 'another process',
      guards: row.resource || 'not reported',
      enforces: true,
      bias: row.bias || null,
      // ITS OWN COUNTS, in its own process, reported on a heartbeat. Named the
      // same as the embedded rows' so the page has one renderer, and the page
      // says on every remote row where the numbers came from.
      decisions: Number(row.decisions || 0),
      allowed: Number(row.allowed || 0),
      refused: Number(row.refused || 0),
      undischargeable: Number(row.undischargeable || 0),
      // A REMOTE PEP DOES NOT REPORT THE FOUR DECISIONS and these are null
      // rather than zero. It reports what it ENFORCED; the breakdown by PDP
      // decision is a thing only the process that evaluated knows, and this
      // service did not evaluate.
      permit: null, deny: null, notApplicable: null, indeterminate: null,
      other: null,
      lastAt: row.lastSeen || null,
      lastDecision: null,
      lastAllowed: null,
      // The remote-only facts, which have no embedded equivalent.
      remote: {
        authenticated: !!row.authenticated,
        certificateSubject: row.certificateSubject || '',
        current: !!row.current,
        stale: !!row.stale,
        enabled: row.enabled !== false,
        registeredAt: row.registeredAt || null,
        lastSeen: row.lastSeen || null,
        syncToken: row.syncToken || '',
        policyCount: row.policyCount === undefined ? null
          : Number(row.policyCount),
        version: row.version || '',
        lastNotify: row.lastNotify || ''
      }
    };
  });

  const here = totalOf(rows);
  const there = totalOf(remote);
  const json = {
    // THE GLOBAL SECTION. What the page's tiles are drawn from.
    policies: { total: held.total, enabled: held.enabled, root: held.root },
    peps: {
      embedded: rows.filter(function (row) { return row.kind === 'embedded'; })
                    .length,
      remote: remote.length,
      // The PDP endpoint is deliberately NOT in this figure. It is not a PEP,
      // and counting it would make "how many enforcement points are there"
      // answer one too many on a service with none.
      total: rows.filter(function (row) { return row.kind === 'embedded'; })
                 .length + remote.length
    },
    decisions: {
      here: here,
      remote: there,
      // ARITHMETIC OVER TWO KINDS OF EVIDENCE, offered because it is the
      // figure a deployment wants and labelled on the page as exactly that.
      combined: { decisions: here.decisions + there.decisions,
                  allowed: here.allowed + there.allowed,
                  refused: here.refused + there.refused,
                  unenforced: here.unenforced + there.unenforced,
                  undischargeable: here.undischargeable +
                                   there.undischargeable }
    },
    // WHEN THESE NUMBERS START FROM. A count with no epoch is a count somebody
    // will read as all-time.
    since: startedAt,
    enabled: config.value('xacml.enabled') !== false,
    remotePepsEnabled: config.value('xacml.remotePeps') !== false,
    realm: { id: realms.currentId(),
             name: realms.current() ? realms.current().name : '' },
    rows: rows,
    remoteRows: remote
  };
  log.debug('Leaving snapshot(). ' + rows.length + ' local asker(s), ' +
            remote.length + ' remote PEP(s).');
  return json;
}

// ---------------------------------------------------------------------------
// THE TOTALS OVER A SET OF ROWS, AND THE FOURTH FIGURE THAT MAKES THEM ADD UP.
//
// `allowed` and `refused` skip a row that does not enforce, which is the whole
// reason those members are null rather than 0 there: `Number(null)` is 0 and
// would have quietly added the PDP endpoint's non-existent refusals to the
// refusal total.
//
// **BUT THEN `allowed + refused` IS LESS THAN `decisions`, AND A READER WHO
// NOTICES THAT IS OWED AN ANSWER RATHER THAN A FOOTNOTE.** The gap is real and
// it is exactly the decisions `POST /xacml/pdp` produced for somebody else's
// PEP: this service evaluated them and never saw what was done with them. So
// it is COUNTED, as `unenforced`, and the page draws it — which turns
// "4 decisions, 1 allowed, 2 refused" from an arithmetic error a reader has to
// resolve into three numbers and the one that explains them.
//
// The first draft left it out and the discrepancy showed up the first time the
// page was driven with real traffic on it. A total that does not add up is the
// kind of thing that makes somebody distrust every other number beside it.
// ---------------------------------------------------------------------------
function totalOf(rows) {
  log.debug("Entering totalOf().");
  const out = { decisions: 0, allowed: 0, refused: 0, unenforced: 0,
                undischargeable: 0 };
  rows.forEach(function (row) {
    const decisions = Number(row.decisions || 0);
    out.decisions += decisions;
    if (row.allowed !== null && row.allowed !== undefined) {
      out.allowed += Number(row.allowed);
      out.refused += Number(row.refused);
    } else {
      // Every decision on a row that enforces nothing is an unenforced one.
      out.unenforced += decisions;
    }
    out.undischargeable += Number(row.undischargeable || 0);
  });
  log.debug("Leaving totalOf().");
  return out;
}

// FOR THE TESTS, and named so that it cannot be mistaken for an operator
// control. There is deliberately no button on the console that calls it: a
// console that could zero its own monitoring would make every number on the
// page a number somebody might have reset, and the audit log — which is the
// durable record — cannot be reset either.
// It clears THIS REALM'S counters and not every realm's, because that is what
// `realms.map()`'s `clear()` means (`realmMap()` is the whole-map door) — and
// it is the right scope: a test asserting a count runs inside the realm it
// made the decisions in, and one that reached across realms would be able to
// pass while the isolation was broken.
function resetForTests() {
  log.debug('Entering resetForTests().');
  counters.clear();
  log.debug('Leaving resetForTests().');
}

module.exports = {
  PEPS: PEPS,
  record: record,
  snapshot: snapshot,
  resetForTests: resetForTests
};
