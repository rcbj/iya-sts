// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/ssf_oidfed_paging.js
//
// ===========================================================================
// THREE MORE PAGES WHOSE LISTS GREW WITHOUT A BOUND, PAGED (#313's sweep,
// 2026-10-12).
//
//   A. /admin/ssf: the stream cards, on `streamsPage`, with `streamTotals`
//      counting the whole transmitter for the tiles and `stream` narrowing
//      the cards to one (the dead letters' links carry it).
//   B. /admin/ssf/transmitters: what arrived (`receivedPage`, after
//      `relationship` has narrowed it, and no longer cut at 200), the blocks
//      (`blocksPage`) and the locks (`locksPage`), `counts` keeping each
//      list's length.
//   C. /admin/oidfed: seven lists, each on a parameter of its own — `keysPage`,
//      `subordinatesPage`, `formerPage`, `anchorsPage`, `issuedPage`,
//      `heldPage`, `policiesPage` — and a subordinate's history cut to its
//      latest events with `eventsTotal`.
//
// Each checks that a list is one page, that its parameter moves it and
// nothing else, that a page past the end is clamped, and that walking every
// page reads every row once. The views are fed SYNTHETIC reports: filling a
// realm with real streams, partners and subordinates would be a receiver, a
// federation and an entity per row.
//
// In a CHILD PROCESS, because A fills `admin_views`' Shared Signals reporter
// slot with a stub, and the slot is process-wide.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_oidfed_paging',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_OIDFED_PAGING_OUT;
  const ROOT = process.env.SSF_OIDFED_PAGING_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  const ids = function (rows, key) {
    return rows.map(function (row) {
      return row[key];
    });
  };
  // Walks a list's pages through `answer(page)` and says whether every row
  // was read exactly once.
  const walk = function (answer, member, key, param, total) {
    const seen = [];
    for (let page = 1; page <= 100; page++) {
      const q = { per: '4' };
      q[param] = String(page);
      const view = answer(q);
      const pg = view.paging[member];
      Array.prototype.push.apply(seen, ids(view[member], key));
      if (page >= pg.pages) {
        break;
      }
    }
    const distinct = seen.filter(function (one, i) {
      return seen.indexOf(one) === i;
    });
    return seen.length === total && distinct.length === total;
  };
  (async function () {
    require(ROOT + '/common/app');
    // The console's shell fills the settings reader `ssfJson()` asks.
    require(ROOT + '/admin-ui/admin');
    const views = require(ROOT + '/admin-core/admin_views');

    // --- A. /admin/ssf ----------------------------------------------------
    const STREAMS = 13;
    const detail = [];
    for (let i = 0; i < STREAMS; i++) {
      detail.push({ stream_id: 'st-' + String(i).padStart(2, '0'),
        status: i % 2 ? 'enabled' : 'paused',
        counters: { delivered: i, failed: 1 },
        queue: i % 3 ? [] : [{ jti: 'q' + i }],
        dead: i === 4, deadLetters: i === 4 ? [{}, {}] : [] });
    }
    views.setSignalsReporter({
      report: function () {
        return { streamDetail: detail.slice(), receivedDetail: [] };
      },
      statuses: ['enabled', 'paused', 'disabled'],
      eventTypes: function () {
        return [];
      }
    });
    const ssfAt = function (query) {
      return views.ssfJson({ query: query });
    };
    const first = ssfAt({ per: '5' });
    note(first.streamDetail.length === 5 &&
         first.paging.streams.total === STREAMS &&
         first.paging.streams.param === 'streamsPage',
         'A1. /admin/ssf\'s cards are one page of five, on streamsPage',
         JSON.stringify(first.paging.streams));
    const total = first.streamTotals;
    note(total.streams === STREAMS && total.enabled === 6 &&
         total.delivered === 78 && total.failed === STREAMS &&
         total.waiting === 5 && total.dead === 1 && total.deadLetters === 2,
         'A2. streamTotals counts every stream, not the page',
         JSON.stringify(total));
    const third = ssfAt({ per: '5', streamsPage: '3' });
    note(third.paging.streams.page === 3 &&
         ids(third.streamDetail, 'stream_id').join() === 'st-10,st-11,st-12',
         'A3. streamsPage moves the cards', '');
    const past = ssfAt({ per: '5', streamsPage: '40' });
    note(past.paging.streams.page === past.paging.streams.pages,
         'A4. a page past the end is the last page', '');
    const one = ssfAt({ per: '5', stream: 'st-12' });
    note(one.streamDetail.length === 1 && one.streamFilter === 'st-12' &&
         one.paging.streams.total === 1 && one.streamTotals.streams === STREAMS,
         'A5. stream narrows the cards to one, the totals still whole', '');
    // `paging` is keyed `streams` on this view, not by the member, so the
    // walk is written out.
    note((function () {
           const seen = [];
           for (let page = 1; page <= 10; page++) {
             const v = ssfAt({ per: '4', streamsPage: String(page) });
             Array.prototype.push.apply(seen, ids(v.streamDetail,
                                                  'stream_id'));
             if (page >= v.paging.streams.pages) {
               break;
             }
           }
           return seen.length === STREAMS &&
             seen.filter(function (x, i) {
               return seen.indexOf(x) === i;
             }).length === STREAMS;
         })(),
         'A6. walking every page reads every stream once', '');

    // --- B. /admin/ssf/transmitters ---------------------------------------
    const api = require(ROOT + '/ssf/ssf_transmitters_api');
    const ARRIVED = 230;
    const received = [];
    for (let i = 0; i < ARRIVED; i++) {
      received.push({ relationship: i % 2 ? 'partner-a' : 'partner-b',
        receivedAt: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
        jti: 'r' + i });
    }
    const blocks = [];
    const locks = [];
    for (let i = 0; i < 17; i++) {
      blocks.push({ username: 'person' + i, relationship: 'partner-a' });
      locks.push({ username: 'held' + i, relationship: 'partner-b' });
    }
    let asked = null;
    const transmitters = new api.SsfTransmittersApi({
      log: require(ROOT + '/common/helpers').log,
      loadTransmitters: function () {
        return {
          report: function (o) {
            asked = o;
            return { relationships: [], observeOnly: false,
              blocks: blocks.slice(), locks: locks.slice(),
              received: received.filter(function (r) {
                return !o.relationship || r.relationship === o.relationship;
              }).slice(0, Number(o.limit) || 200) };
          }
        };
      },
      loadViews: function () {
        return views;
      }
    });
    const txAt = function (query) {
      return transmitters.pagedReport(query);
    };
    const tx = txAt({ per: '20' });
    note(tx.received.length === 20 && tx.counts.received === ARRIVED &&
         tx.paging.received.param === 'receivedPage' &&
         !(Number(asked.limit) <= 200),
         'B1. what arrived is a page of the WHOLE inbox, not the first 200',
         JSON.stringify({ shown: tx.received.length, counts: tx.counts,
                          limit: String(asked.limit) }));
    const moved = txAt({ per: '5', locksPage: '3' });
    note(moved.paging.locks.page === 3 && moved.paging.blocks.page === 1 &&
         moved.paging.received.page === 1 &&
         ids(moved.locks, 'username').join() === 'held10,held11,held12,' +
           'held13,held14',
         'B2. locksPage moves the locks and nothing else', '');
    const narrowed = txAt({ per: '20', relationship: 'partner-a' });
    note(narrowed.counts.received === ARRIVED / 2 &&
         narrowed.received.every(function (r) {
           return r.relationship === 'partner-a';
         }),
         'B3. relationship narrows what arrived before it is paged',
         JSON.stringify(narrowed.counts));
    const clamped = txAt({ per: '5', blocksPage: '99' });
    note(clamped.paging.blocks.page === clamped.paging.blocks.pages &&
         clamped.blocks.length === 2,
         'B4. a page past the end is the last page', '');
    note(walk(txAt, 'received', 'jti', 'receivedPage', ARRIVED) &&
         walk(txAt, 'blocks', 'username', 'blocksPage', 17),
         'B5. walking every page reads every row once', '');

    // --- C. /admin/oidfed -------------------------------------------------
    const admin = require(ROOT + '/oidfed/oidfed_admin');
    const make = function (n, f) {
      const out = [];
      for (let i = 0; i < n; i++) {
        out.push(f(i));
      }
      return out;
    };
    const history = make(40, function (i) {
      return { iat: 1700000000 + i, event: 'e' + i };
    });
    const oidfedView = function () {
      return {
        keys: make(9, function (i) { return { kid: 'k' + i }; }),
        subordinates: make(11, function (i) {
          return { entityId: 's' + i, events: i === 0 ? history.slice() : [] };
        }),
        formerSubordinates: make(6, function (i) {
          return { entityId: 'f' + i, events: [] };
        }),
        trustAnchors: make(7, function (i) { return { entityId: 'a' + i }; }),
        issuedMarks: make(8, function (i) { return { id: 'i' + i }; }),
        heldMarks: make(5, function (i) { return { id: 'h' + i }; }),
        markPolicies: make(3, function (i) { return { type: 'p' + i }; })
      };
    };
    const page = new admin.OidfedAdmin({
      log: require(ROOT + '/common/helpers').log,
      parseBody: function () {
        return {};
      },
      errorCodes: require(ROOT + '/common/error_codes'),
      admin: { configSettingsJson: function () {
        return [];
      } },
      oidfed: { view: function () {
        return Promise.resolve(oidfedView());
      } },
      adminViews: function () {
        return views;
      }
    });
    const ofAt = async function (query) {
      return page.oidfedView({ query: query });
    };
    const of1 = await ofAt({ per: '4' });
    const lists = { keys: 9, subordinates: 11, formerSubordinates: 6,
      trustAnchors: 7, issuedMarks: 8, heldMarks: 5, markPolicies: 3 };
    note(Object.keys(lists).every(function (member) {
      return of1[member].length === Math.min(4, lists[member]) &&
        of1.counts[member] === lists[member] &&
        of1.paging[member].total === lists[member];
    }), 'C1. each of the seven lists is one page, its length in counts',
    JSON.stringify(of1.counts));
    const params = { keys: 'keysPage', subordinates: 'subordinatesPage',
      formerSubordinates: 'formerPage', trustAnchors: 'anchorsPage',
      issuedMarks: 'issuedPage', heldMarks: 'heldPage',
      markPolicies: 'policiesPage' };
    note(Object.keys(params).every(function (member) {
      return of1.paging[member].param === params[member];
    }), 'C2. each list moves on its own parameter', '');
    const ofMoved = await ofAt({ per: '4', anchorsPage: '2' });
    note(ofMoved.paging.trustAnchors.page === 2 &&
         ids(ofMoved.trustAnchors, 'entityId').join() === 'a4,a5,a6' &&
         Object.keys(params).every(function (member) {
           return member === 'trustAnchors' ||
                  ofMoved.paging[member].page === 1;
         }),
         'C3. anchorsPage moves the Trust Anchors and nothing else', '');
    const ofPast = await ofAt({ per: '4', keysPage: '77' });
    note(ofPast.paging.keys.page === 3 && ofPast.keys.length === 1,
         'C4. a page past the end is the last page', '');
    const s0 = of1.subordinates[0];
    note(s0.eventsTotal === 40 && s0.events.length === 25 &&
         s0.events[24].event === 'e39',
         'C5. a subordinate\'s history is its latest 25 events, with ' +
         'eventsTotal', JSON.stringify({ total: s0.eventsTotal,
                                         shown: s0.events.length }));
    const seen = [];
    for (let n = 1; n <= 10; n++) {
      const v = await ofAt({ per: '4', subordinatesPage: String(n) });
      Array.prototype.push.apply(seen, ids(v.subordinates, 'entityId'));
      if (n >= v.paging.subordinates.pages) {
        break;
      }
    }
    note(seen.length === 11 && seen.filter(function (x, i) {
      return seen.indexOf(x) === i;
    }).length === 11, 'C6. walking every page reads every subordinate once',
    '');
    finish();
  })().catch(function (e) {
    note(false, 'the child ran to the end', (e && e.stack) || String(e));
    finish();
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-oidfed-paging-' + process.pid +
                                     '-' + Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_OIDFED_PAGING_OUT: out, SSF_OIDFED_PAGING_ROOT: root,
    LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_oidfed_paging',
  describe: '/admin/ssf\'s stream cards, /admin/ssf/transmitters\' three ' +
            'lists and /admin/oidfed\'s seven paged on parameters of their ' +
            'own, clamped, narrowed and walked',
  run: run
};
