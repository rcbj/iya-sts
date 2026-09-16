// @ts-check
'use strict';
//
// File: oauth2_monitor.js
//
// ---------------------------------------------------------------------------
// WHAT THE AUTHORIZATION SERVER IS DOING, COUNTED PER CLIENT (2026-09-13).
//
// The counters behind `/admin/oauth2/monitor` and its `/admin-api` operation.
// The page is the OAuth 2.0 / OpenID Connect family's monitoring page, and it
// is drawn in SECTIONS so that one family has one page however many of its
// mechanisms come to be counted; RFC 9126's pushed authorization requests are
// the first section, because they are the first mechanism here whose life
// happens across two endpoints and a browser — pushed at one, read at another,
// spent at a third moment — which is exactly the story nothing else on the
// console tells. RFC 9470's step-up is the second (2026-09-13), for the same
// kind of story told across a resource server, the authorization endpoint and
// the sign-in screen.
//
// It is `gnap/gnap_monitor.ts`'s shape, deliberately, and for its reasons:
//
//   * **a LEAF** — it requires helpers, error_codes, realms and the replication
//     reader, none of which requires it back, so `par.js` and `oauth2.js` can
//     call it on every request and the console can read it without either
//     dragging the other's routes forward (rule 1);
//   * **one call per event, and it NEVER throws into its caller** — every call
//     site is on the path of an authorization request, and a counter that
//     could fail one would be monitoring causing the outage it exists to show;
//   * **per realm, `merge: 'own'`** — a count is an INCREMENT, so each process
//     writes its own row and `merge()` folds in the others' rows when it is
//     READ, which keeps dispatch mode from under-reporting.
//
// EVENTS ARE A CLOSED VOCABULARY, and an unknown event is logged and not
// counted — a page whose columns are the vocabulary cannot show a count nobody
// described. `section` on each event says which section of the page draws it.
//
// **WHAT IS NOT COUNTED IS A SECRET OR A REQUEST.** A row is keyed by client_id
// and carries numbers and RFC 6749 error words; a request_uri, a parameter and
// a credential never reach this module — the live request_uris are listed by
// `par.js`, which holds them anyway, and only while they live.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const realms = require('../common/realms');
const replication = require('../persistence/persistence_replication');

// The sections of the page, in the order it draws them.
const SECTIONS = [
  { id: 'par', title: 'Pushed authorization requests (RFC 9126)' },
  // RFC 9470 (2026-09-13) — the second section, and the first whose events
  // happen at a RESOURCE server as well as at the authorization endpoint: a
  // challenge is counted against the client_id of the token it refused.
  { id: 'stepup', title: 'Step-up authentication (RFC 9470)' }
];

// event -> [counter, label, section]. The page draws these labels.
const EVENTS = {
  'par.pushed': ['pushed', 'authorization requests pushed (201)', 'par'],
  'par.refused': ['pushRefused', 'pushes refused', 'par'],
  'par.request_object': ['pushedObjects', 'pushes carrying a request object',
                         'par'],
  'par.dpop_bound': ['dpopBound', 'pushes bound to a DPoP key', 'par'],
  'par.redirect_relaxed': ['redirectRelaxed', 'unregistered redirect_uris ' +
                           'accepted under section 2.4', 'par'],
  'par.resolved': ['resolved', 'request_uris read at the authorization ' +
                   'endpoint', 'par'],
  'par.resolve_refused': ['resolveRefused', 'request_uris refused at the ' +
                          'authorization endpoint', 'par'],
  'par.spent': ['spent', 'request_uris spent by an authorization response',
                'par'],
  'par.expired': ['expired', 'request_uris that expired unspent', 'par'],
  'par.deleted': ['deleted', 'request_uris deleted by an administrator',
                  'par'],
  'par.required_refused': ['requiredRefused', 'plain authorization requests ' +
                           'refused because PAR is required', 'par'],
  // Each authorization-endpoint event is ONE PASS, not one flow: a request
  // sent to sign in again is counted `stepup.reauth_*` on the way out and
  // `stepup.met_after_sign_in` (or `stepup.unmet`) on the way back.
  'stepup.met_by_session': ['stepUpMetBySession', 'requirements met by the ' +
                            'session already open', 'stepup'],
  'stepup.sign_in': ['stepUpSignIn', 'sent to sign in with a requirement ' +
                     'and no session', 'stepup'],
  'stepup.reauth_max_age': ['stepUpReauthMaxAge', 'sent to sign in again ' +
                            'because max_age had elapsed', 'stepup'],
  'stepup.reauth_acr': ['stepUpReauthAcr', 'sent to sign in again because ' +
                        'the session did not meet acr_values', 'stepup'],
  'stepup.met_after_sign_in': ['stepUpMetAfterSignIn', 'requirements met by ' +
                               'the sign-in the person was sent to',
                               'stepup'],
  'stepup.unmet': ['stepUpUnmet', 'refused unmet_authentication_requirements',
                   'stepup'],
  'stepup.login_required': ['stepUpLoginRequired', 'refused login_required ' +
                            'under prompt=none', 'stepup'],
  'stepup.challenged': ['stepUpChallenged', 'insufficient_user_authentication ' +
                        'challenges sent by a resource server', 'stepup']
};

// The largest number of distinct error words one row keeps before it folds
// the rest into "(other)". The word comes from this service, but a table keyed
// by any value is a table somebody eventually grows.
const MAX_KEYS = 50;

function emptyRow() {
  log.debug("Entering emptyRow().");
  const row = { lastAt: null, lastEvent: null, errors: {} };
  Object.keys(EVENTS).forEach(function (event) {
    row[EVENTS[event][0]] = 0;
  });
  log.debug("Leaving emptyRow().");
  return row;
}

const counters = realms.map({ persist: 'oauth2_monitor.counters',
                              merge: 'own' });

const startedAt = new Date().toISOString();

// `detail.error` counts the OAuth error a refusal returned, which is the
// column a client developer reads first.
function record(clientId, event, detail) {
  log.debug("Entering record(). event=" + event);
  try {
    if (!EVENTS[event]) {
      log.warn(errorCodes.tag('STS-OAUTH-0427') + 'oauth2: the event "' +
               event + '" is not in oauth2_monitor.js\'s vocabulary and was ' +
               'not counted. Add it to EVENTS.');
      log.debug("Leaving record(). Not in the vocabulary.");
      return;
    }
    const id = String(clientId || '(no client_id)').slice(0, 200);
    const said = detail || {};
    const row = counters.has(id) ? counters.get(id) : emptyRow();
    row[EVENTS[event][0]] = (row[EVENTS[event][0]] || 0) + 1;
    if (said.error) {
      const word = String(said.error).slice(0, 60);
      if (row.errors[word] === undefined &&
          Object.keys(row.errors).length >= MAX_KEYS) {
        row.errors['(other)'] = (row.errors['(other)'] || 0) + 1;
      } else {
        row.errors[word] = (row.errors[word] || 0) + 1;
      }
    }
    row.lastAt = new Date().toISOString();
    row.lastEvent = event;
    // Re-set, because the persistence journal sees a set and not an edit.
    counters.set(id, row);
  } catch (error) {
    // SWALLOWED, for the header's reason: this is on the path of every
    // authorization request that uses PAR.
    log.error(errorCodes.tag('STS-OAUTH-0427') + 'oauth2: a counter threw ' +
              'and was ignored; the request itself is unaffected: ' +
              ((error && error.message) || error));
  }
  log.debug("Leaving record().");
}

// This process's row plus every other process's (merge: 'own').
function merge(id) {
  log.debug("Entering merge().");
  const mine = counters.has(id) ? counters.get(id) : emptyRow();
  const theirs = replication.remoteRows('oauth2_monitor.counters', undefined,
                                        id);
  if (!theirs.length) {
    log.debug("Leaving merge(). This process alone.");
    return mine;
  }
  const out = JSON.parse(JSON.stringify(mine));
  theirs.forEach(function (row) {
    if (!row) {
      return;
    }
    Object.keys(EVENTS).forEach(function (event) {
      const field = EVENTS[event][0];
      if (typeof row[field] === 'number') {
        out[field] = (out[field] || 0) + row[field];
      }
    });
    Object.keys(row.errors || {}).forEach(function (key) {
      out.errors[key] = (out.errors[key] || 0) + row.errors[key];
    });
    if (row.lastAt && (!out.lastAt || row.lastAt > out.lastAt)) {
      out.lastAt = row.lastAt;
      out.lastEvent = row.lastEvent;
    }
  });
  log.debug("Leaving merge().");
  return out;
}

// Every client_id with a row, in this process or another.
function identifiers() {
  log.debug("Entering identifiers().");
  const out = [];
  counters.forEach(function (row, id) {
    out.push(id);
  });
  (replication.remoteKeys('oauth2_monitor.counters') || []).forEach(
    function (key) {
      if (key && out.indexOf(key) < 0) {
        out.push(key);
      }
    });
  log.debug("Leaving identifiers().");
  return out.sort();
}

// Every row merged, and the totals across them.
function snapshot() {
  log.debug("Entering snapshot().");
  const rows = {};
  const totals = emptyRow();
  identifiers().forEach(function (id) {
    const row = merge(id);
    rows[id] = row;
    Object.keys(EVENTS).forEach(function (event) {
      const field = EVENTS[event][0];
      totals[field] += row[field] || 0;
    });
    Object.keys(row.errors || {}).forEach(function (key) {
      totals.errors[key] = (totals.errors[key] || 0) + row.errors[key];
    });
    if (row.lastAt && (!totals.lastAt || row.lastAt > totals.lastAt)) {
      totals.lastAt = row.lastAt;
      totals.lastEvent = row.lastEvent;
    }
  });
  log.debug("Leaving snapshot(). " + Object.keys(rows).length + " row(s).");
  return {
    startedAt: startedAt,
    sections: SECTIONS.slice(),
    events: Object.keys(EVENTS).map(function (event) {
      return { event: event, counter: EVENTS[event][0],
               label: EVENTS[event][1], section: EVENTS[event][2] };
    }),
    rows: rows,
    totals: totals
  };
}

// Forget this realm's counts — for a test. The console deliberately has no
// Reset (`oauth2_monitor_console.js` says why), so nothing else calls this.
function reset() {
  log.debug("Entering reset().");
  counters.clear();
  log.debug("Leaving reset().");
}

module.exports = {
  SECTIONS: SECTIONS,
  EVENTS: EVENTS,
  record: record,
  snapshot: snapshot,
  emptyRow: emptyRow,
  reset: reset
};
