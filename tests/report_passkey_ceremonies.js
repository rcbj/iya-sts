// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/report_passkey_ceremonies.js
//
// ===========================================================================
// THE `passkeyCeremonies` REPORT SOURCE AND ITS PREDEFINED QUERIES
// (#1107), over the ceremony rows `authn/webauthn_ceremonies.ts` writes
// (#943, #1108).
//
//   A. The catalog carries the source: every field the row projection
//      makes and no other, none indexed (the audit ring has no index), the
//      door list equal to the ceremony module's, the groupable fields.
//   B. The projection: a ceremony row of the #1108 shape and one of the
//      shape before it read the same, a mismatch row is a row of its own
//      kind with the algorithm that signed and the held ones, any other
//      audit row is skipped, and no address or summary is copied.
//   C. The three predefined queries are valid query documents and,
//      run against a ring of known rows, count what their names say.
//   D. The real path: rows written by `webauthn_ceremonies.record()` and
//      `algorithmMismatch()` reach the source through the audit ring and
//      `audit.fresh()`, as `authActivity`'s do.
//   E. The predefined queries are published in #1110's `presets` shape
//      (`/report-api/catalog`'s projection, the OpenAPI `Source`), and the
//      query form fills from one, boolean filters included.
// ===========================================================================

delete process.env.CONFIG_FILE;

const Catalog = require('../report/catalog');
const Limits = require('../report/limits');
const Query = require('../report/query');

const log = require('bunyan').createLogger({
  name: 'report_passkey_ceremonies',
  level: process.env.LOG_LEVEL || 'info' });

const AT = Date.parse('2026-10-28T09:00:00.000Z');

const FIELDS = ['timestamp', 'day', 'kind', 'ceremony', 'door', 'outcome',
  'errorCode', 'actor', 'application', 'role', 'lane', 'offered',
  'offerRule', 'offeredFirst', 'postQuantumOffered', 'algorithm', 'postQuantum', 'held',
  'client', 'clientError', 'capabilities', 'attachment', 'transports',
  'attestation', 'durationMs'];

function ask(document) {
  log.debug('Entering ask().');
  const query = new Query({ catalog: new Catalog(),
    limits: Limits.fixed({ syncMaxRows: 500, asyncMaxRows: 1000,
                           pdfMaxRows: 100 }) });
  const out = query.validate(document);
  log.debug('Leaving ask().');
  return out;
}

// A ring of known rows, newest first as `audit.list()` answers.
function ring() {
  log.debug('Entering ring().');
  const ceremony = function (n, outcome, detail, extra) {
    return Object.assign({ seq: n, at: AT - n * 1000,
      action: 'webauthn.ceremony', category: 'authentication',
      outcome: outcome, errorCode: outcome === 'refused'
        ? 'STS-AUTHN-0022' : '', actor: 'p' + n, address: '192.0.2.' + n,
      summary: 'SUMMARY ' + n, detail: detail }, extra || {});
  };
  const out = [
    // An ML-DSA registration a Chrome refused (the #1108 shape).
    ceremony(1, 'refused', { ceremony: 'registration', door: 'portal',
      role: 'primary', lane: 'pqc', durationMs: 4200,
      offered: 'ML-DSA-65,ML-DSA-44,ES256', algorithm: '',
      client: 'Chrome 141 on macOS 15', clientError: 'NotSupportedError',
      authenticator: 'platform|internal|' }),
    // Another, on the same client.
    ceremony(2, 'refused', { ceremony: 'registration', door: 'sign-in-step',
      role: 'mfa', lane: 'pqc', application: 'app-one',
      offered: 'ML-DSA-65,ES256', client: 'Chrome 141 on macOS 15',
      clientError: 'NotAllowedError' }),
    // ML-DSA asked, ES256 made, on Firefox: the row before #1108.
    ceremony(3, 'success', { ceremony: 'registration', door: 'portal',
      role: 'primary', lane: 'pqc', offered: 'ML-DSA-65,ES256',
      algorithm: 'ES256', postQuantum: false,
      client: 'Firefox 144 on Linux', attachment: 'cross-platform',
      transports: 'usb,nfc', attestation: 'ES256; ES256 > ES256' }),
    // ML-DSA asked and made.
    ceremony(4, 'success', { ceremony: 'registration', door: 'portal',
      role: 'primary', lane: 'pqc', durationMs: 900,
      offered: 'ML-DSA-65,ES256', algorithm: 'ML-DSA-65',
      client: 'Chrome 141 on macOS 15',
      authenticator: 'platform|internal,hybrid|ML-DSA-65 (PQ)' }),
    // A classical-only registration that failed: not an ML-DSA one.
    ceremony(5, 'refused', { ceremony: 'registration', door: 'portal',
      role: 'mfa', lane: 'classical',
      offered: 'ES256,RS256|learned: Safari 18 on iOS 18',
      client: 'Safari 18 on iOS 18', clientError: 'NotAllowedError' }),
    // A classical sign-in, and its mismatch row.
    ceremony(6, 'success', { ceremony: 'assertion', door: 'usernameless',
      role: 'primary', lane: 'classical', offered: 'ES256,ML-DSA-65',
      algorithm: 'ES256', client: 'Edge 141 on Windows 11',
      application: 'app-two', durationMs: 300 }),
    { seq: 7, at: AT - 7000, action: 'webauthn.algorithm-mismatch',
      category: 'authentication', outcome: 'success', actor: 'p6',
      detail: { used: 'ES256', held: 'ML-DSA-65', door: 'sign-in',
                client: 'Edge 141 on Windows 11' } },
    // Not a ceremony.
    { seq: 8, at: AT - 8000, action: 'authentication', outcome: 'success',
      actor: 'p8', detail: { method: 'passkey' } }
  ];
  log.debug('Leaving ring().');
  return out;
}

function catalog(t) {
  log.debug('Entering catalog().');
  const ceremonies = require('../authn/webauthn_ceremonies');
  const cat = new Catalog();
  const src = cat.source('passkeyCeremonies');
  t.check(!!src, 'A. the catalog has passkeyCeremonies');
  const ids = src ? src.fields.map(function (f) {
    return f.id;
  }) : [];
  t.equal(JSON.stringify(ids), JSON.stringify(FIELDS),
    'A2. the fields are the projection\'s, in order');
  t.check(src && src.fields.every(function (f) {
    return f.indexed.length === 0 && !!f.meaning;
  }) && !src.anchored && src.bounded,
    'A3. bounded, not anchored, and no field declares an index: the ring ' +
    'is a list in memory');
  const door = cat.field('passkeyCeremonies', 'door');
  const meaning = door ? door.meaning : '';
  t.check(ceremonies.DOORS.every(function (d) {
    return meaning.indexOf(d) >= 0;
  }), 'A4. the door field names every door the ceremony module writes',
    JSON.stringify(ceremonies.DOORS));
  const grouped = ['kind', 'ceremony', 'door', 'outcome', 'client',
    'clientError', 'algorithm', 'postQuantum', 'postQuantumOffered',
    'application', 'day', 'lane', 'role', 'attachment', 'offeredFirst'];
  t.check(grouped.every(function (id) {
    const f = cat.field('passkeyCeremonies', id);
    return f && f.group;
  }) && !cat.field('passkeyCeremonies', 'actor').group &&
    !cat.field('passkeyCeremonies', 'durationMs').group,
    'A5. a count groups by the ceremony\'s facts, never by person or ' +
    'duration');
  t.check(cat.field('auditEvents', 'kind') === null &&
    cat.field('credentialHolders', 'algorithm').group === true,
    'A6. the other sources\' fields are as they were');
  log.debug('Leaving catalog().');
}

function projection(t) {
  log.debug('Entering projection().');
  const sources = require('../report/sources');
  const rows = sources.passkeyCeremonyRows(ring());
  t.equal(rows.length, 7, 'B. seven of the eight rows are ceremonies');
  const one = rows[0];
  t.check(one.kind === 'ceremony' && one.ceremony === 'registration' &&
    one.outcome === 'refused' && one.errorCode === 'STS-AUTHN-0022' &&
    one.offeredFirst === 'ML-DSA-65' && one.postQuantumOffered === true &&
    one.postQuantum === false && one.attachment === 'platform' &&
    one.transports === 'internal' && one.durationMs === 4200 &&
    one.day === '2026-10-28' && one.timestamp === '2026-10-28T08:59:59.000Z',
    'B2. a #1108 row unfolds: offered first, post-quantum offered, the ' +
    'authenticator split, the duration', JSON.stringify(one));
  const old = rows[2];
  t.check(old.attachment === 'cross-platform' &&
    old.transports === 'usb,nfc' &&
    old.attestation === 'ES256; ES256 > ES256' &&
    old.postQuantum === false && old.durationMs === null &&
    old.application === '',
    'B3. a row from before #1108 reads the same way, with no duration',
    JSON.stringify(old));
  const narrowed = rows[4];
  t.check(narrowed.offered === 'ES256,RS256' &&
    narrowed.offerRule === 'learned: Safari 18 on iOS 18' &&
    narrowed.offeredFirst === 'ES256' &&
    narrowed.postQuantumOffered === false && one.offerRule === '',
    'B3-ii. a client rule after the offer\'s first bar (#1112) is its own ' +
    'column, and the names are read before it', JSON.stringify(narrowed));
  const mismatch = rows.filter(function (r) {
    return r.kind === 'algorithm-mismatch';
  })[0] || {};
  t.check(mismatch.algorithm === 'ES256' && mismatch.held === 'ML-DSA-65' &&
    mismatch.ceremony === '' && mismatch.postQuantum === false &&
    mismatch.client === 'Edge 141 on Windows 11',
    'B4. a mismatch row is its own kind: the classical algorithm that ' +
    'signed, the ML-DSA ones held, no ceremony', JSON.stringify(mismatch));
  const text = JSON.stringify(rows);
  t.check(text.indexOf('192.0.2.') < 0 && text.indexOf('SUMMARY') < 0 &&
    rows.every(function (r) {
      return JSON.stringify(Object.keys(r)) === JSON.stringify(FIELDS);
    }),
    'B5. every row carries the catalog\'s fields and no address or summary');
  log.debug('Leaving projection().');
}

async function readWith(events, document) {
  log.debug('Entering readWith().');
  const sources = require('../report/sources');
  const audit = require('../common/audit');
  const realFresh = audit.fresh;
  const realList = audit.list;
  audit.fresh = function () {
    return Promise.resolve();
  };
  audit.list = function () {
    return events;
  };
  try {
    const asked = ask(document);
    if (!asked.ok) {
      log.debug('Leaving readWith(). Refused.');
      return asked;
    }
    const answer = await sources.read(asked.plan, { startedMs: Date.now(),
      budgetMs: 5000, execution: 'sync' });
    log.debug('Leaving readWith().');
    return answer;
  } finally {
    audit.fresh = realFresh;
    audit.list = realList;
  }
}

function counts(answer, key) {
  log.debug('Entering counts().');
  log.debug('Leaving counts().');
  return ((answer && answer.rows) || []).map(function (row) {
    return row[key] + '=' + row.count;
  }).sort().join(';');
}

async function definitions(t) {
  log.debug('Entering definitions().');
  const src = new Catalog().source('passkeyCeremonies');
  const ready = (src && src.presets) || [];
  t.equal(ready.map(function (d) {
    return d.id;
  }).join(','), 'ml-dsa-registrations-failed-by-client,' +
    'ml-dsa-asked-classical-made-by-client,' +
    'classical-sign-ins-by-ml-dsa-holders',
  'C. the three predefined queries');
  for (const d of ready) {
    const asked = ask(d.document);
    t.check(asked.ok && !!d.name,
      'C2. "' + d.name + '" is a valid query document',
      asked.description);
  }
  const byId = {};
  ready.forEach(function (d) {
    byId[d.id] = d.document;
  });
  const failed = await readWith(ring(),
    byId['ml-dsa-registrations-failed-by-client']);
  t.equal(counts(failed, 'client'), 'Chrome 141 on macOS 15=2',
    'C3. ML-DSA registrations that failed, by client: the two Chrome ' +
    'ones, not the classical-only one', JSON.stringify(failed));
  const classical = await readWith(ring(),
    byId['ml-dsa-asked-classical-made-by-client']);
  t.equal(counts(classical, 'client'), 'Firefox 144 on Linux=1',
    'C4. asked for ML-DSA and made a classical passkey: the Firefox one ' +
    '(a row from before #1108), not the ML-DSA one made',
    JSON.stringify(classical));
  const mismatch = await readWith(ring(),
    byId['classical-sign-ins-by-ml-dsa-holders']);
  t.equal(counts(mismatch, 'client'), 'Edge 141 on Windows 11=1',
    'C5. classical sign-ins by ML-DSA holders: the mismatch row alone, not ' +
    'its ceremony', JSON.stringify(mismatch));
  const slow = await readWith(ring(), { source: 'passkeyCeremonies',
    select: ['actor', 'algorithm', 'durationMs'],
    where: { op: 'gt', field: 'durationMs', value: 500 },
    orderBy: [{ field: 'durationMs', dir: 'desc' }], limit: 10 });
  t.equal(((slow && slow.rows) || []).map(function (r) {
    return r.actor + ':' + r.durationMs;
  }).join(','), 'p1:4200,p4:900',
    'C6. durations filter and sort as numbers', JSON.stringify(slow));
  log.debug('Leaving definitions().');
}

async function realPath(t) {
  log.debug('Entering realPath().');
  const ceremonies = require('../authn/webauthn_ceremonies');
  const sources = require('../report/sources');
  const who = 'rpc-' + require('crypto').randomBytes(3).toString('hex');
  const req = { headers: { 'user-agent': 'Mozilla/5.0 (X11; Linux ' +
    'x86_64; rv:144.0) Gecko/20100101 Firefox/144.0' } };
  ceremonies.record({ ceremony: 'registration', door: 'portal',
    username: who, role: 'primary', lane: 'pqc', outcome: 'refused',
    errorCode: 'STS-AUTHN-0022', offered: [-49, -7], req: req,
    issuedAt: Date.now() - 2500,
    posted: { error: 'NotSupportedError',
              authenticatorAttachment: 'cross-platform',
              response: { transports: ['usb'] } } });
  ceremonies.algorithmMismatch({ username: who, used: 'ES256',
    held: ['ES256', 'ML-DSA-44'], door: 'sign-in', req: req });
  const asked = ask({ source: 'passkeyCeremonies',
    select: ['kind', 'client', 'clientError', 'offeredFirst',
      'postQuantumOffered', 'attachment', 'transports', 'durationMs', 'held',
      'algorithm'],
    where: { op: 'eq', field: 'actor', value: who }, limit: 10 });
  const answer = asked.ok ? await sources.read(asked.plan,
    { startedMs: Date.now(), budgetMs: 5000, execution: 'sync' }) : asked;
  const rows = (answer && answer.rows) || [];
  const reg = rows.filter(function (r) {
    return r.kind === 'ceremony';
  })[0] || {};
  const mis = rows.filter(function (r) {
    return r.kind === 'algorithm-mismatch';
  })[0] || {};
  t.check(rows.length === 2 && reg.clientError === 'NotSupportedError' &&
    reg.client === 'Firefox 144 on Linux' && reg.offeredFirst ===
    'ML-DSA-65' && reg.postQuantumOffered === true &&
    reg.attachment === 'cross-platform' && reg.transports === 'usb' &&
    reg.durationMs >= 2500 && mis.held === 'ML-DSA-44' &&
    mis.algorithm === 'ES256',
    'D. rows the ceremony module writes reach the source through the ' +
    'audit ring', JSON.stringify(answer));
  log.debug('Leaving realPath().');
}

function published(t) {
  log.debug('Entering published().');
  const api = require('../report/report_api');
  const OpenApi = require('../report/openapi');
  const ReportRuntime = require('../report/web_report_pages');
  const cat = new Catalog();
  const view = api.publicSource(cat.source('passkeyCeremonies'));
  t.check(Array.isArray(view.presets) && view.presets.length === 3 &&
    view.presets[0].document.source === 'passkeyCeremonies',
    'E. the catalog view publishes the source\'s predefined queries');
  const spec = OpenApi.document(cat);
  const schemas = (spec.components && spec.components.schemas) || {};
  t.check(!!(schemas.Source && schemas.Source.properties.presets),
    'E2. the OpenAPI document describes them');
  const query = view.presets[1].document;
  t.equal((ReportRuntime.whereLeaves(query.where) || []).length, 5,
    'E3. a flat and with boolean comparisons is drawn as filter rows');
  const html = ReportRuntime.queryFormHtml({
    text: function (key) {
      return key;
    }
  }, cat.list().map(function (src) {
    return api.publicSource(src);
  }), query);
  t.check(html.indexOf('value="passkeyCeremonies" selected') >= 0 &&
    html.indexOf('<option value="false" selected>') >= 0 &&
    html.indexOf('<option value="success" selected>') >= 0,
    'E4. the query form fills from a predefined query', html.slice(0, 400));
  log.debug('Leaving published().');
}

module.exports = {
  name: 'report_passkey_ceremonies',
  describe: 'the passkeyCeremonies report source over the WebAuthn ' +
    'ceremony audit rows, and its predefined queries (#1107)',
  run: async function (t) {
    log.debug('Entering run().');
    catalog(t);
    projection(t);
    await definitions(t);
    await realPath(t);
    published(t);
    log.debug('Leaving run().');
  }
};
