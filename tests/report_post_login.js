// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: report_post_login.js
//
// ---------------------------------------------------------------------------
// POST-LOGIN PROGRESS IN THE REPORTS APPLICATION (#1110).
//
// `post_login.progress` (#1096) kept, per person and activity, the first
// invitation, the snooze, the asks, the skips and completion, and nothing
// read it back. This file holds the source that does, in process:
//
//   A. The catalog: the `postLoginProgress` source, its fields, the one-word
//      `progress` and the three predefined queries — each a document the
//      validator accepts and the New Query form can draw.
//   B. The rows, read through a real `PostLogin` over a Map and a clock this
//      file moves: a person asked, one who skipped twice, one past the
//      allotted time, one done, one only mailed by a started activity
//      (#1111's fields), and a row written before #1110 whose profile is
//      asked of the policy.
//   C. The predefined queries run against those rows.
//   D. The walk stops at the limit: `eachProgressAsync()` and
//      `realms.map()`'s `scanAsync()` both end on a `false`.
//   E. The API publishes the presets, and the page draws them.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const Catalog = require('../report/catalog');
const Limits = require('../report/limits');
const Query = require('../report/query');

const log = require('bunyan').createLogger({ name: 'report_post_login',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.parse('2026-10-01T00:00:00.000Z');

const limits = Limits.fixed({ syncMaxRows: 1000, asyncMaxRows: 5000,
                              pdfMaxRows: 100 });

function ask(document) {
  log.debug("Entering ask().");
  const query = new Query({ catalog: new Catalog(), limits: limits });
  const result = query.validate(document);
  log.debug("Leaving ask().");
  return result;
}

function catalogChecks(t) {
  log.debug("Entering catalogChecks().");
  const catalog = new Catalog();
  const src = catalog.source('postLoginProgress');
  if (!t.check(!!src, 'postLoginProgress is a source')) {
    log.debug("Leaving catalogChecks(). No source.");
    return;
  }
  const ids = src.fields.map(function (f) {
    return f.id;
  });
  ['username', 'activity', 'profile', 'role', 'progress', 'invitedAt',
   'snoozedUntil', 'asks', 'skips', 'done', 'doneAt', 'deadline',
   'graceEnded', 'askedBy', 'mailedBy', 'mails', 'firstMailedAt',
   'lastMailedAt']
    .forEach(function (id) {
      t.check(ids.indexOf(id) >= 0, 'postLoginProgress has ' + id);
    });
  t.equal(src.anchored, undefined,
    'it reads the progress store, not the directory: not anchored');
  t.equal(JSON.stringify(catalog.field('postLoginProgress',
    'progress').values),
    JSON.stringify(['done', 'past-grace', 'snoozed', 'asked', 'mailed']),
    'progress is one of five words');
  t.check(catalog.field('postLoginProgress', 'progress').group,
    'a count may group by progress');
  const presets = src.presets || [];
  t.equal(presets.map(function (p) {
    return p.id;
  }).join(','), 'progress-by-activity,past-grace-period,skipped-most',
    'the three predefined queries');
  presets.forEach(function (p) {
    const asked = ask(p.document);
    t.equal(asked.ok, true, p.id + ' validates', asked.description);
    const doc = p.document;
    t.check(!doc.where || (doc.where.op !== 'and' && doc.where.op !== 'or'),
      p.id + ' has at most one filter leaf, so the form can draw it');
    t.check(!doc.groupBy || doc.groupBy.length <= 1,
      p.id + ' groups by at most one field');
    t.check(!doc.orderBy || doc.orderBy.length <= 1,
      p.id + ' orders by at most one field');
  });
  t.equal(catalog.preset('postLoginProgress', 'nope'), null,
    'an unknown preset is null');
  const copy = catalog.preset('postLoginProgress', 'skipped-most');
  copy.document.limit = 1;
  t.equal(catalog.preset('postLoginProgress', 'skipped-most').document.limit,
    100, 'a preset handed out is a copy');
  log.debug("Leaving catalogChecks().");
}

// A real PostLogin over a Map and a clock this file moves.
function progressDouble() {
  log.debug("Entering progressDouble().");
  const PostLogin = require('../common/post_login').PostLogin;
  const helpers = require('../common/helpers');
  const clock = { now: T0 };
  const store = new Map();
  const instance = new PostLogin({ log: helpers.log, credentials: {},
    passkeyPolicy: {}, postLoginPolicy: {}, webauthnPolicy: {},
    progress: store, now: function () {
      return clock.now;
    } });
  log.debug("Leaving progressDouble().");
  return { instance: instance, clock: clock, store: store };
}

function due(extra) {
  log.debug("Entering due().");
  const out = Object.assign({ activity: 'pqc-passkey-migration',
    role: 'primary', reason: 'classical', required: false,
    enforceable: true, method: 'upgrade', fallback: 'none', snoozeDays: 7,
    graceDays: 30, invitedAt: 0, deadline: 0, profile: 'staff',
    askedBy: 'policy' },
  extra || {});
  log.debug("Leaving due().");
  return out;
}

async function rowsOf(sources, document) {
  log.debug("Entering rowsOf().");
  const asked = ask(document);
  if (!asked.ok) {
    log.debug("Leaving rowsOf(). Refused.");
    return { ok: false, description: asked.description };
  }
  const answer = await sources.read(asked.plan, { startedMs: Date.now(),
    budgetMs: 5000, execution: 'sync' });
  log.debug("Leaving rowsOf().");
  return answer;
}

async function rowChecks(t) {
  log.debug("Entering rowChecks().");
  const sources = require('../report/sources');
  const built = progressDouble();
  const pl = built.instance;
  // ada: asked once, today.
  pl.noteAsked('ada', due());
  // bob: asked and skipped twice.
  pl.noteAsked('bob', due({ role: 'mfa', askedBy: 'pla-9' }));
  pl.noteSkipped('bob', due({ role: 'mfa', askedBy: 'pla-9' }));
  pl.noteSkipped('bob', due({ role: 'mfa', askedBy: 'pla-9' }));
  // cy: asked forty days ago, never did it: past a thirty-day grace.
  built.clock.now = T0 - 40 * DAY;
  pl.noteAsked('cy', due());
  // dee: asked forty days ago and did it.
  pl.noteAsked('dee', due());
  built.clock.now = T0 - 10 * DAY;
  pl.noteDone('dee', due());
  // eve: only mailed by a started activity (#1111), twice.
  built.clock.now = T0 - 3 * DAY;
  pl.noteMailed('eve', due(), 'pla-1');
  built.clock.now = T0 - 1 * DAY;
  pl.noteMailed('eve', due(), 'pla-1');
  // old: a row written before #1110 — no profile, no grace recorded.
  built.store.set('old|pqc-passkey-migration',
    { invitedAt: T0 - 2 * DAY, asks: 1, skips: 0, doneAt: 0,
      snoozedUntil: 0 });
  built.clock.now = T0;
  sources.installPostLogin(built.instance);
  try {
    const all = await rowsOf(sources, { source: 'postLoginProgress',
      select: ['username', 'activity', 'profile', 'role', 'progress',
        'invitedAt', 'asks', 'skips', 'done', 'deadline', 'graceEnded',
        'askedBy', 'mailedBy', 'mails', 'firstMailedAt', 'lastMailedAt'],
      orderBy: [{ field: 'username', dir: 'asc' }], limit: 50 });
    t.equal(all.ok, true, 'the source answers', all.description);
    const by = {};
    (all.rows || []).forEach(function (r) {
      by[r.username] = r;
    });
    t.equal(Object.keys(by).join(','), 'ada,bob,cy,dee,eve,old',
      'one row per person asked or mailed');
    t.equal(by.ada && by.ada.progress, 'asked', 'ada is asked');
    t.equal(by.ada && by.ada.profile, 'staff',
      'the profile is the one recorded with the row');
    t.equal(by.ada && by.ada.invitedAt, new Date(T0).toISOString(),
      'the first invitation');
    t.equal(by.ada && by.ada.deadline,
      new Date(T0 + 30 * DAY).toISOString(),
      'the deadline is graceDays from the first invitation');
    t.equal(by.bob && by.bob.skips, 2, 'bob skipped twice');
    t.equal(by.ada && by.ada.askedBy, 'policy',
      'askedBy: the policy asked ada (#1126)');
    t.equal(by.bob && by.bob.askedBy, 'pla-9',
      'and a started activity asked bob');
    t.equal(by.eve && by.eve.askedBy, '',
      'a person only mailed was asked by nobody');
    t.equal(by.bob && by.bob.role, 'mfa', 'in the role he was asked in');
    t.equal(by.bob && by.bob.progress, 'snoozed', 'and is put off');
    t.equal(by.cy && by.cy.graceEnded, true, 'cy is past the allotted time');
    t.equal(by.cy && by.cy.progress, 'past-grace', 'and says so in a word');
    t.equal(by.dee && by.dee.done, true, 'dee did it');
    t.equal(by.dee && by.dee.graceEnded, false,
      'done is never past its grace');
    t.equal(by.dee && by.dee.progress, 'done', 'done is the first word');
    t.equal(by.eve && by.eve.progress, 'mailed',
      'a person only mailed is mailed');
    t.equal(by.eve && by.eve.invitedAt, null,
      'a mail is not an invitation');
    t.equal(by.eve && by.eve.mails, 2, 'two mails went');
    t.equal(by.eve && by.eve.mailedBy, 'pla-1',
      'from the started activity');
    t.equal(by.eve && by.eve.firstMailedAt,
      new Date(T0 - 3 * DAY).toISOString(), 'the first mail');
    t.equal(by.eve && by.eve.lastMailedAt,
      new Date(T0 - 1 * DAY).toISOString(), 'the last mail');
    t.equal(by.old && by.old.profile, 'default',
      'a row written before #1110 takes the profile that reaches the ' +
      'person now');

    // C. The predefined queries.
    const catalog = new Catalog();
    const byActivity = await rowsOf(sources, catalog.preset(
      'postLoginProgress', 'progress-by-activity').document);
    const counts = {};
    (byActivity.rows || []).forEach(function (r) {
      counts[r.progress] = r.count;
    });
    t.equal(JSON.stringify(counts), JSON.stringify({ asked: 2, done: 1,
      mailed: 1, 'past-grace': 1, snoozed: 1 }),
      'progress by activity counts each word', JSON.stringify(byActivity));
    const past = await rowsOf(sources, catalog.preset('postLoginProgress',
      'past-grace-period').document);
    t.equal((past.rows || []).map(function (r) {
      return r.username;
    }).join(','), 'cy', 'people past their grace period: cy alone');
    const skipped = await rowsOf(sources, catalog.preset('postLoginProgress',
      'skipped-most').document);
    t.equal((skipped.rows || []).map(function (r) {
      return r.username + ':' + r.skips;
    }).join(','), 'bob:2', 'people who skipped most: bob, twice');

    // D. An unordered read stops at its limit: the walk is ended, not
    // finished.
    let offered = 0;
    const counting = {
      eachProgressAsync: function (fn) {
        return built.instance.eachProgressAsync(function (entry) {
          offered += 1;
          return fn(entry);
        });
      },
      graceOf: function (row, days) {
        return built.instance.graceOf(row, days);
      }
    };
    sources.installPostLogin(counting);
    const two = await rowsOf(sources, { source: 'postLoginProgress',
      select: ['username'], limit: 2 });
    t.equal(two.ok && two.rows.length, 2, 'a limit of two answers two');
    t.check(offered <= 3, 'and the walk stopped there (' + offered +
      ' offered of six)');
  } finally {
    sources.installPostLogin(null);
  }
  log.debug("Leaving rowChecks().");
}

async function scanStops(t) {
  log.debug("Entering scanStops().");
  const realms = require('../common/realms');
  const store = realms.map({});
  ['a', 'b', 'c', 'd'].forEach(function (k) {
    store.set(k, { k: k });
  });
  const seen = [];
  await store.scanAsync(function (value, key) {
    seen.push(key);
    return seen.length < 2 ? undefined : false;
  });
  t.equal(seen.length, 2, 'scanAsync ends on false');
  const all = [];
  await store.scanAsync(function (value, key) {
    all.push(key);
  });
  t.equal(all.length, 4, 'and walks everything otherwise');
  log.debug("Leaving scanStops().");
}

function published(t) {
  log.debug("Entering published().");
  const api = require('../report/report_api');
  const OpenApi = require('../report/openapi');
  const catalog = new Catalog();
  const pub = api.publicSource(catalog.source('postLoginProgress'));
  t.equal((pub.presets || []).length, 3, 'the API publishes the presets');
  t.equal(api.publicSource(catalog.source('users')).presets.length, 0,
    'and an empty list for a source with none');
  const spec = OpenApi.document(catalog);
  t.check(!!spec.components.schemas.Source.properties.presets,
    'the OpenAPI Source schema describes presets');
  t.check(spec.components.schemas.Source.properties.id.enum
    .indexOf('postLoginProgress') >= 0, 'and names the source');
  log.debug("Leaving published().");
}

function drawn(t) {
  log.debug("Entering drawn().");
  const fs = require('fs');
  const path = require('path');
  const messages = require('../common/web_messages');
  const ReportRuntime = require('../report/web_report_pages');
  const own = JSON.parse(fs.readFileSync(path.join(__dirname, '..',
    'common', 'locales', 'report', 'en.json'), 'utf8'));
  const flat = {};
  Object.keys(own).forEach(function (key) {
    flat['report.' + key] = own[key];
  });
  const tr = messages.WebTranslator.fromData({ catalogs: { en: flat },
    negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                  direction: 'ltr', matched: true } });
  const catalog = new Catalog();
  const sources = catalog.list().map(function (src) {
    return { id: src.id, fields: src.fields, anchored: src.anchored === true,
      retention: src.retention };
  });
  const doc = catalog.preset('postLoginProgress',
    'progress-by-activity').document;
  const html = ReportRuntime.queryFormHtml(tr, sources, doc);
  t.check(html.indexOf('<option value="postLoginProgress" selected>') >= 0,
    'the form opens on the preset\'s source');
  t.check(/name="groupByQuery" checked/.test(html),
    'with its group ticked');
  t.check(html.indexOf('<option value="progress" selected>') >= 0,
    'on progress');
  ['presets', 'presetsNote', 'presetFrom'].forEach(function (key) {
    t.check(typeof own[key] === 'string' && own[key].length > 0,
      'the report catalog has ' + key);
  });
  log.debug("Leaving drawn().");
}

async function run(t) {
  log.debug("Entering run().");
  catalogChecks(t);
  await rowChecks(t);
  await scanStops(t);
  published(t);
  drawn(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_post_login',
  describe: 'the post-login progress source in /report (#1110): fields, ' +
    'the one-word progress, the predefined queries, a walk that stops at ' +
    'its limit, and the presets published and drawn',
  run: run
};
