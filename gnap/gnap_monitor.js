// @ts-check
'use strict';
//
// File: gnap_monitor.js
//
// ---------------------------------------------------------------------------
// WHAT GNAP IS DOING, COUNTED PER APPLICATION.
//
// `/admin/gnap/monitor` answers the question somebody has when a GNAP
// integration misbehaves: which client instances and resource servers are
// using this authorization server, and what have they been doing — how many
// grants, how many approved and denied, which interaction modes, which token
// formats, how many rotations and revocations, how many proofs failed. None of
// that is in the grant store, which holds CURRENT state and forgets a finalized
// grant after a day; these are COUNTS since the process started.
//
// It is `xacml/xacml_monitor.js`'s shape, deliberately, and for its reasons:
//
//   * **a LEAF** — it requires config, realms, helpers and the replication
//     reader, and nothing it requires requires it back, so the grant engine can
//     call it on every request and the console can read it without either
//     dragging the other's routes forward (rule 1);
//   * **one call per event, and it NEVER throws into its caller** — every call
//     site is on the path of a grant or a token, and a counter that could fail
//     one would be monitoring causing the outage it exists to show;
//   * **per realm, `merge: 'own'`** — a count is an INCREMENT, so each process
//     writes its own row and `merge()` folds in the others' rows when it is
//     READ, which is what keeps dispatch mode from under-reporting (the defect
//     common/CLAUDE.md records against SCIM's counters, not repeated here).
//
// EVENTS ARE A CLOSED VOCABULARY, and an unknown event is logged and not
// counted — a page whose columns are the vocabulary cannot show a count nobody
// described.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const realms = require('../common/realms');
const replication = require('../persistence/persistence_replication');

// event -> [counter path, label]. The page draws these labels.
const EVENTS = {
  'grant.requested': ['grants', 'grant requests'],
  'grant.approved': ['approved', 'grants approved'],
  'grant.denied': ['denied', 'grants denied by the resource owner'],
  'grant.refused': ['refused', 'grant requests refused'],
  'grant.revoked': ['revoked', 'grants revoked by the client'],
  'grant.modified': ['modified', 'grant modifications'],
  'grant.immediate': ['immediate', 'grants approved with no interaction'],
  'continue.poll': ['polls', 'continuation polls'],
  'continue.interact_ref': ['finishedContinuations', 'continuations after ' +
                                                     'interaction'],
  'continue.too_fast': ['tooFast', 'continuations refused as too fast'],
  'interaction.redirect': ['startRedirect', 'redirect interactions'],
  'interaction.app': ['startApp', 'app interactions'],
  'interaction.user_code': ['startUserCode', 'user code interactions'],
  'interaction.user_code_uri': ['startUserCodeUri',
                                'user code URI interactions'],
  'finish.redirect': ['finishRedirect', 'redirect finishes'],
  'finish.push': ['finishPush', 'push finishes delivered'],
  'finish.push_failed': ['finishPushFailed', 'push finishes that failed'],
  'token.issued': ['tokens', 'access tokens issued'],
  'token.rotated': ['rotations', 'access token rotations'],
  'token.key_rotated': ['keyRotations', 'key rotations'],
  'token.revoked': ['tokenRevocations', 'access tokens revoked by the client'],
  'subject.released': ['subjects', 'subject information releases'],
  'proof.failed': ['proofFailures', 'key proofs that failed'],
  'rs.introspection': ['introspections', 'introspection calls'],
  'rs.introspection_active': ['introspectionsActive', 'introspections ' +
                                                      'answered active'],
  'rs.registration': ['registrations', 'resource sets registered'],
  'rs.derivation': ['derivations', 'downstream tokens derived'],
  'rs.presented': ['presented', 'tokens presented at the demonstration RS']
};

const FORMATS = ['jwt-signed', 'jwt-encrypted', 'macaroon', 'biscuit', 'zcap'];

function emptyRow() {
  log.debug("Entering emptyRow().");
  const row = { lastAt: null, lastEvent: null, formats: {}, errors: {} };
  Object.keys(EVENTS).forEach(function (event) {
    row[EVENTS[event][0]] = 0;
  });
  FORMATS.forEach(function (format) {
    row.formats[format] = 0;
  });
  log.debug("Leaving emptyRow().");
  return row;
}

const counters = realms.map({ persist: 'gnap_monitor.counters', merge: 'own' });

const startedAt = new Date().toISOString();

// `detail.format` counts a token format; `detail.gnapError` counts the RFC
// error a refusal returned, which is the column a client developer reads first.
function record(identifier, event, detail) {
  log.debug("Entering record().");
  try {
    if (!EVENTS[event]) {
      log.warn(errorCodes.tag('STS-GNAP-0650') + 'gnap: the event "' + event +
               '" ' +
               'is not in gnap_monitor.js\'s vocabulary and was not counted. ' +
               'Add it to EVENTS.');
      log.debug("Leaving record().");
      return;
    }
    const id = String(identifier || '(unidentified)');
    const said = detail || {};
    const format = FORMATS.indexOf(said.format) >= 0 ? said.format : null;
    const gnapError = said.gnapError ? String(said.gnapError).slice(0, 40) :
                      null;
    const row = counters.has(id) ? counters.get(id) : emptyRow();
    row[EVENTS[event][0]] += 1;
    if (format) {
      row.formats[format] = (row.formats[format] || 0) + 1;
    }
    if (gnapError) {
      row.errors[gnapError] = (row.errors[gnapError] || 0) + 1;
    }
    row.lastAt = new Date().toISOString();
    row.lastEvent = event;
    // Re-set, because the persistence journal sees a set and not an edit.
    counters.set(id, row);
  } catch (error) {
    // SWALLOWED, for the header's reason: this is on the path of every grant.
    log.error(errorCodes.tag('STS-GNAP-0651') + 'gnap: a counter threw and ' +
              'was ignored; the grant itself is unaffected: ' + error.message);
  }
  log.debug("Leaving record().");
}

// This process's row plus every other process's (merge: 'own').
function merge(id) {
  log.debug("Entering merge().");
  const mine = counters.has(id) ? counters.get(id) : emptyRow();
  const theirs = replication.remoteRows('gnap_monitor.counters', undefined, id);
  if (!theirs.length) {
    log.debug("Leaving merge().");
    return mine;
  }
  const out = JSON.parse(JSON.stringify(mine));
  theirs.forEach(function (row) {
    if (!row) {
      return;
    }
    Object.keys(out).forEach(function (field) {
      if (typeof out[field] === 'number' && typeof row[field] === 'number') {
        out[field] += row[field];
      }
    });
    ['formats', 'errors'].forEach(function (table) {
      Object.keys(row[table] || {}).forEach(function (key) {
        out[table][key] = (out[table][key] || 0) + row[table][key];
      });
    });
    if (row.lastAt && (!out.lastAt || row.lastAt > out.lastAt)) {
      out.lastAt = row.lastAt;
      out.lastEvent = row.lastEvent;
    }
  });
  log.debug("Leaving merge().");
  return out;
}

// Every identifier with a row, in this process or another.
function identifiers() {
  log.debug("Entering identifiers().");
  const out = [];
  counters.forEach(function (row, id) {
    out.push(id);
  });
  // Another process may be counting an application this one has never served.
  (replication.remoteKeys('gnap_monitor.counters') || []).forEach(
      function (key) {
    if (key && out.indexOf(key) < 0) {
      out.push(key);
    }
  });
  log.debug("Leaving identifiers().");
  return out;
}

function snapshot() {
  log.debug("Entering snapshot().");
  const rows = {};
  identifiers().forEach(function (id) {
    rows[id] = merge(id);
  });
  log.debug("Leaving snapshot(). " + Object.keys(rows).length + " row(s).");
  return {
    startedAt: startedAt,
    events: Object.keys(EVENTS).map(function (event) {
      return { event: event, counter: EVENTS[event][0],
               label: EVENTS[event][1] };
    }),
    formats: FORMATS.slice(),
    rows: rows,
    blank: emptyRow()
  };
}

module.exports = {
  EVENTS: EVENTS,
  record: record,
  snapshot: snapshot,
  emptyRow: emptyRow
};
