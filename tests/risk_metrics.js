'use strict';
//
// File: risk_metrics.js
//
// ===========================================================================
// MONITORING → RISK SCORING (#62, 2026-09-22): the scoring system measured.
// In a child process, against the memory risk store, with assessments
// written straight into it:
//
//   A. THE WINDOW COUNTS: by level, signal, door, decision, phase, country
//      and score band, the people assessed, and what people said — an
//      assessment older than the window left out, another realm's never in.
//   B. THE SIGNALS: every signal with its factor beside how often it fired.
//   C. THE SERIES adds up to the total, a column per bucket the window asks
//      for; an unknown window is 24h.
//   D. THE STANDINGS: people at each level now.
//   E. THIS PROCESS: counts of its own, apart from the store's.
//   F. THE PAGE: the timeline, the level bars in the level's colour, the
//      signals table and the process table, with no script.
//
// The postgres driver's SQL is held to the same answers by
// `tests/vendored/sts_admin_risk.js` in the modes that have a database.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_metrics',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.RM_ROOT;
  const OUT = process.env.RM_OUT;
  const fs = require('fs');
  const findings = [];
  const t = {
    check: function (ok, what, detail) {
      findings.push({ ok: !!ok, what: what,
                      detail: detail === undefined ? '' : String(detail) });
    }
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const riskStore = require(ROOT + '/risk/risk_store');
    const riskAdmin = require(ROOT + '/admin-ui/risk_admin');
    const admin = require(ROOT + '/admin-ui/admin');

    const now = Date.now();
    const DAY = 86400000;
    let n = 0;
    const record = function (realm, fields) {
      n++;
      return riskStore.recordAssessment(Object.assign({
        realm: realm, id: 'rm-' + n, at: now - 60000, phase: 'sign-in',
        door: 'password', subject: 'urn:uuid:rm-' + (n % 4),
        decision: 'permit', level: 'LOW', score: 0.005, signals: [],
        bot: false, country: 'NZ', feedback: '' }, fields), false);
    };
    await record('default', { level: 'HIGH', score: 0.4,
      signals: [{ signal: 'tor-exit' }, { signal: 'new-device' }],
      decision: 'deny', country: 'DE', feedback: 'denied' });
    await record('default', { level: 'HIGH', score: 2,
      signals: [{ signal: 'tor-exit' }], decision: 'observe:deny',
      door: 'webauthn', bot: true });
    await record('default', { level: 'MEDIUM', score: 0.05,
      signals: [{ signal: 'new-device' }], decision: 'step-up',
      phase: 'session', feedback: 'confirmed' });
    await record('default', {});
    await record('default', { score: 0.0005 });
    await record('default', {});
    // Outside a seven-day window, and in another realm.
    await record('default', { at: now - 8 * DAY });
    await record('rm-other', { level: 'HIGH', score: 5 });

    // --- A. the window counts ------------------------------------------------
    const week = await riskAdmin.metricsView({ window: '7d' });
    const a = week.assessments;
    t.check(a.total === 6 && a.byLevel.HIGH === 2 && a.byLevel.MEDIUM === 1 &&
            a.byLevel.LOW === 3,
            'A1. the window counts six assessments by level, the old one and ' +
            'the other realm\'s left out', JSON.stringify(a.byLevel));
    t.check(a.byDoor.password === 5 && a.byDoor.webauthn === 1 &&
            a.byDecision.deny === 1 && a.byDecision['observe:deny'] === 1 &&
            a.byDecision['step-up'] === 1 && a.byDecision.permit === 3 &&
            a.byPhase.session === 1 && a.byCountry.DE === 1 &&
            a.byCountry.NZ === 5 && a.bots === 1,
            'A2. by door, decision, phase and country, and the automated ' +
            'clients', JSON.stringify(a));
    t.check(a.byBand['< 0.001'] === 1 && a.byBand['0.001 – 0.01'] === 2 &&
            a.byBand['0.01 – 0.1'] === 1 && a.byBand['0.1 – 1'] === 1 &&
            a.byBand['≥ 1'] === 1,
            'A3. the scores in decades', JSON.stringify(a.byBand));
    t.check(a.feedback.denied === 1 && a.feedback.confirmed === 1 &&
            a.subjects === 4 && Math.abs(a.maxScore - 2) < 1e-9,
            'A4. what people said, the people assessed, and the highest ' +
            'score', JSON.stringify([a.feedback, a.subjects, a.maxScore]));
    const month = await riskAdmin.metricsView({ window: '30d' });
    t.check(month.assessments.total === 7 && month.bucketMs === DAY,
            'A5. thirty days takes the old one in, a column a day',
            month.assessments.total + ' ' + month.bucketMs);

    // --- B. the signals ------------------------------------------------------
    const tor = week.signals.filter(function (s) {
      return s.signal === 'tor-exit';
    })[0] || {};
    const device = week.signals.filter(function (s) {
      return s.signal === 'new-device';
    })[0] || {};
    t.check(tor.fired === 2 && tor.factor === 5 && device.fired === 2 &&
            week.signals.every(function (s) {
              return typeof s.factor === 'number' &&
                     typeof s.fired === 'number';
            }),
            'B1. every signal with its factor and how often it fired',
            JSON.stringify([tor, device]));

    // --- C. the series -------------------------------------------------------
    const day = await riskAdmin.metricsView({ window: 'forever' });
    const sum = day.assessments.series.reduce(function (s, b) {
      return s + b.total;
    }, 0);
    t.check(day.window === '24h' && day.bucketMs === 3600000 && sum === 6 &&
            day.assessments.series.every(function (b) {
              return b.at % 3600000 === 0;
            }),
            'C1. an unknown window is 24h, a column an hour, and the series ' +
            'adds up to the total', JSON.stringify(day.assessments.series));

    // --- D. the standings ----------------------------------------------------
    await riskStore.upsertSubject({ realm: 'default', subject: 'urn:uuid:a',
      score: 0.4, level: 'HIGH', reason: 'tor-exit', lastAssessment: 'rm-1',
      updatedAt: now }, false);
    await riskStore.upsertSubject({ realm: 'default', subject: 'urn:uuid:b',
      score: 0.005, level: 'LOW', reason: 'the model',
      lastAssessment: 'rm-4', updatedAt: now }, false);
    const after = await riskAdmin.metricsView({});
    t.check(after.standings.HIGH === 1 && after.standings.LOW === 1,
            'D1. the people at each level now',
            JSON.stringify(after.standings));

    // --- E. this process -----------------------------------------------------
    const p = after.process;
    t.check(typeof p.assessed === 'number' && typeof p.failed === 'number' &&
            p.durationMs && typeof p.durationMs.p95 === 'number' &&
            p.reactions && p.rescore && p.since <= Date.now() &&
            after.database === false,
            'E1. this process\'s own counts, apart from the store\'s, and ' +
            'the store named', JSON.stringify(p));

    // --- F. the page ---------------------------------------------------------
    const res = { statusCode: 200, headers: {}, body: '',
      status: function (c) { this.statusCode = c; return this; },
      set: function (k, v) { this.headers[String(k).toLowerCase()] = v;
                             return this; },
      setHeader: function (k, v) { this.headers[String(k).toLowerCase()] = v; },
      getHeader: function (k) { return this.headers[String(k).toLowerCase()]; },
      type: function () { return this; },
      send: function (b) { this.body = String(b); return this; },
      end: function (b) { this.body = String(b || ''); return this; } };
    let html = '';
    const original = admin.respond;
    try {
      admin.respond = function (req, r, json, title, active, inner) {
        html = inner;
      };
      await new Promise(function (resolve) {
        const app = { get: function (p2, h) {
          if (p2 === riskAdmin.METRICS_PAGE) {
            Promise.resolve(h({ query: { window: '7d' }, headers: {} }, res))
              .then(function () { setTimeout(resolve, 200); });
          }
        }, post: function () {} };
        riskAdmin.registerRoutes(app);
      });
    } finally {
      admin.respond = original;
    }
    t.check(/id="risk-timeline"/.test(html) &&
            /id="risk-by-level"/.test(html) &&
            /background:#d93025/.test(html) &&
            /id="risk-signals"/.test(html) &&
            /id="risk-process"/.test(html) &&
            /id="risk-feedback"/.test(html) && !/<script/i.test(html),
            'F1. the page draws the timeline, the level bars in the level\'s ' +
            'colour, the signals and this process, with no script',
            html.slice(0, 400));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'risk-metrics-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RM_ROOT: ROOT, RM_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_metrics',
  describe: 'Monitoring → Risk Scoring (#62): a window\'s assessments ' +
            'counted by level, signal, door, decision, phase, country and ' +
            'score band, what people said, each signal beside its factor, a ' +
            'series that adds up, standings, this process\'s own counts, and ' +
            'the page drawn without a script',
  run: run
};
