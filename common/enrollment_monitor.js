// @ts-check
'use strict';
//
// common/enrollment_monitor.js — WHAT THE THREE ENROLLMENT PROTOCOLS HAVE DONE
// (2026-09-13).
//
// The counters behind `/admin/acme/monitor`, `/admin/est/monitor` and
// `/admin/scep/monitor`, and behind their three `/admin-api` operations. One
// module and one vocabulary for all three, because the question each page
// answers is the same question — how many requests, of what kind, from whom,
// for which profile, how many were refused and why — and three copies of a
// counter are three places for "refused" to start meaning different things.
//
// **PER REALM AND MERGED ACROSS PROCESSES**, in `gnap/gnap_monitor.ts`'s shape:
// a `realms.map({ persist, merge: 'own' })` whose rows are this process's own
// counts, and `snapshot()` adds every other process's rows read through
// `persistence_replication.remoteRows()`. A number drawn on the page is
// therefore what the SERVICE did, not what the worker that drew it did.
//
// **A COUNTER NEVER THROWS INTO THE REQUEST IT COUNTS.** `record()` catches
// everything and logs `STS-ENROLL-0090`: a certificate that was issued must
// not turn into a 500 because a map could not be written.
//
// **WHAT IS NOT COUNTED IS A SECRET.** A principal is a username, a client_id
// or an EAB key id; a challenge password, an EAB MAC key and a private key
// never reach this module.

const { log } = require('./helpers');
const errorCodes = require('./error_codes');
const realms = require('./realms');
const replication = require('../persistence/persistence_replication');

const FAMILIES = ['acme', 'est', 'scep'];

// The number of recent rows each family keeps per realm. Enough for a person
// watching a client try something; a history is the audit log's job.
const RECENT = 50;

// The largest number of distinct principals, profiles or codes one table
// keeps before it folds the rest into "(other)". A table keyed by a value a
// caller chooses is a table a caller can grow without bound.
const MAX_KEYS = 200;

const stores = {};
FAMILIES.forEach(function (family) {
  stores[family] = realms.map({ persist: 'enrollment_monitor.' + family,
                                merge: 'own' });
});

const startedAt = new Date().toISOString();

function emptyRow() {
  log.debug("Entering emptyRow().");
  log.debug("Leaving emptyRow().");
  return { requests: 0, issued: 0, refused: 0, revoked: 0,
           credentialsCreated: 0, credentialsRedeemed: 0,
           operations: {}, profiles: {}, principals: {}, codes: {},
           statuses: {}, failInfos: {}, recent: [], lastAt: null };
}

function bump(table, key) {
  log.debug("Entering bump().");
  const name = String(key == null || key === '' ? '(none)' : key)
    .slice(0, 120);
  if (table[name] === undefined && Object.keys(table).length >= MAX_KEYS) {
    table['(other)'] = (table['(other)'] || 0) + 1;
    log.debug("Leaving bump(). Folded.");
    return;
  }
  table[name] = (table[name] || 0) + 1;
  log.debug("Leaving bump().");
}

// ---------------------------------------------------------------------------
// record(family, detail)
//
//   detail.operation   the protocol operation (new-order, simpleenroll,
//                      PKIOperation, create-eab, …)
//   detail.outcome     'issued' | 'refused' | 'revoked' | 'credential' |
//                      'redeemed' | 'answered'
//   detail.status      the HTTP status sent
//   detail.profile     the certificate profile, when there was one
//   detail.principal   who asked (username, client_id, EAB kid, challenge id)
//   detail.target      whom it was for, when that differs
//   detail.errorCode   the STS code of a refusal
//   detail.serialHex   the serial of an issued or revoked certificate
//   detail.failInfo    SCEP only: the RFC 8894 failInfo name a CertRep
//                      FAILURE carried (badAlg, badMessageCheck, badRequest,
//                      badTime, badCertId) — a separate table because a SCEP
//                      refusal is an HTTP 200 whose status says nothing
// ---------------------------------------------------------------------------
function record(family, detail) {
  log.debug("Entering record(). family=" + family);
  try {
    const store = stores[family];
    if (!store) {
      log.warn(errorCodes.tag('STS-ENROLL-0090') + 'enrollment monitor: "' +
               family + '" is not an enrollment family; nothing counted.');
      log.debug("Leaving record(). Unknown family.");
      return;
    }
    const said = detail || {};
    const key = 'counters';
    const row = store.has(key) ? store.get(key) : emptyRow();
    const outcome = String(said.outcome || 'answered');
    row.requests += 1;
    if (outcome === 'issued') {
      row.issued += 1;
    } else if (outcome === 'refused') {
      row.refused += 1;
    } else if (outcome === 'revoked') {
      row.revoked += 1;
    } else if (outcome === 'credential') {
      row.credentialsCreated += 1;
    } else if (outcome === 'redeemed') {
      row.credentialsRedeemed += 1;
    }
    bump(row.operations, said.operation);
    if (said.profile) {
      bump(row.profiles, said.profile);
    }
    if (said.principal) {
      bump(row.principals, said.principal);
    }
    if (said.errorCode) {
      bump(row.codes, said.errorCode);
    }
    if (said.status) {
      bump(row.statuses, said.status);
    }
    if (said.failInfo) {
      // A row written before this table existed has none.
      row.failInfos = row.failInfos || {};
      bump(row.failInfos, said.failInfo);
    }
    const now = new Date().toISOString();
    row.recent = [{
      at: now, operation: String(said.operation || '').slice(0, 60),
      outcome: outcome, status: Number(said.status) || null,
      profile: said.profile ? String(said.profile).slice(0, 40) : null,
      principal: said.principal ? String(said.principal).slice(0, 120) : null,
      target: said.target ? String(said.target).slice(0, 120) : null,
      errorCode: said.errorCode ? String(said.errorCode).slice(0, 40) : null,
      failInfo: said.failInfo ? String(said.failInfo).slice(0, 40) : null,
      serialHex: said.serialHex ? String(said.serialHex).slice(0, 80) : null
    }].concat(row.recent || []).slice(0, RECENT);
    row.lastAt = now;
    store.set(key, row);
  } catch (e) {
    log.error(errorCodes.tag('STS-ENROLL-0090') + 'enrollment monitor: a ' +
              'counter threw and was ignored; the request it counted is ' +
              'unaffected: ' + ((e && e.message) || e));
  }
  log.debug("Leaving record().");
}

function mergeTable(into, from) {
  log.debug("Entering mergeTable().");
  Object.keys(from || {}).forEach(function (name) {
    into[name] = (into[name] || 0) + Number(from[name] || 0);
  });
  log.debug("Leaving mergeTable().");
}

// The family's counters in the ambient realm, this process's and every other
// process's added together.
function snapshot(family) {
  log.debug("Entering snapshot(). family=" + family);
  const store = stores[family];
  if (!store) {
    log.debug("Leaving snapshot(). Unknown family.");
    return null;
  }
  const mine = store.has('counters') ? store.get('counters') : emptyRow();
  const out = JSON.parse(JSON.stringify(mine));
  out.failInfos = out.failInfos || {};
  let theirs = [];
  try {
    theirs = replication.remoteRows('enrollment_monitor.' + family, undefined,
                                    'counters') || [];
  } catch (e) {
    log.debug("Caught in snapshot(): " + ((e && e.message) || e));
    // No coordination in this process: its own counts are the whole answer.
    theirs = [];
  }
  theirs.forEach(function (row) {
    if (!row) {
      return;
    }
    ['requests', 'issued', 'refused', 'revoked', 'credentialsCreated',
     'credentialsRedeemed'].forEach(function (field) {
      out[field] += Number(row[field] || 0);
    });
    ['operations', 'profiles', 'principals', 'codes', 'statuses', 'failInfos']
      .forEach(function (table) {
        mergeTable(out[table], row[table]);
      });
    out.recent = out.recent.concat(row.recent || []);
    if (row.lastAt && (!out.lastAt || row.lastAt > out.lastAt)) {
      out.lastAt = row.lastAt;
    }
  });
  out.recent = out.recent.sort(function (a, b) {
    return String(b.at).localeCompare(String(a.at));
  }).slice(0, RECENT);
  out.startedAt = startedAt;
  out.realm = realms.currentId();
  out.family = family;
  out.processes = 1 + theirs.length;
  log.debug("Leaving snapshot().");
  return out;
}

// Tests only: forget this realm's counts for one family.
function resetForTests(family) {
  log.debug("Entering resetForTests().");
  if (stores[family]) {
    stores[family].delete('counters');
  }
  log.debug("Leaving resetForTests().");
}

module.exports = {
  FAMILIES: FAMILIES,
  RECENT: RECENT,
  record: record,
  snapshot: snapshot,
  resetForTests: resetForTests
};
