'use strict';
//
// File: risk_user_badge.js
//
// ===========================================================================
// A PERSON'S CURRENT RISK ON THEIR DIRECTORY → USERS PAGE (#62, 2026-09-22).
// rcbj asked for it "large and colorful". In process, against the memory
// risk store, with standings written straight into it:
//
//   A. NEVER ASSESSED: the page draws the grey UNKNOWN badge and says why;
//      the API answers `risk: null`.
//   B. ASSESSED: the level is drawn large in its colour — HIGH red, MEDIUM
//      amber, LOW green — with the score, the level it came from and what
//      moved it; the API answers the same standing.
//   C. THE LINK goes to Monitoring → Risk narrowed to this person, and that
//      page's view model narrows its assessments to them.
//
// In a child process, because it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_user_badge',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.RB_ROOT;
  const OUT = process.env.RB_OUT;
  const findings = [];
  const t = {
    check: function (ok, what, detail) {
      findings.push({ ok: !!ok, what: what,
                      detail: detail === undefined ? '' : String(detail) });
    }
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const admin = require(ROOT + '/admin-ui/admin');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const stats = require(ROOT + '/common/admin_stats');
    const helpers = require(ROOT + '/common/helpers');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const riskStore = require(ROOT + '/risk/risk_store');
    const riskAdmin = require(ROOT + '/admin-ui/risk_admin');

    const NAME = 'rb-dana';
    ldap.createUser(NAME, { invent: false });
    stats.recordAuthentication({ presented: NAME, protocol: 'test',
                                 method: 'a probe' });
    const sub = String(helpers.subjectForName(NAME));
    const draw = async function () {
      const req = { query: { user: NAME }, headers: {}, cookies: {},
                    method: 'GET', path: '/admin/users', url: '/admin/users' };
      const risk = await adminViews.riskFor(req.query);
      return { page: admin.usersView(req, risk),
               json: adminViews.userDetailJson(req, NAME, risk) };
    };
    const jsonOf = function (view) {
      const j = view.json;
      return typeof j === 'function' ? j() : j;
    };

    // --- A. never assessed ---------------------------------------------------
    const none = await draw();
    t.check(/class="risk-badge"/.test(none.page.inner) &&
            /background:#dadce0/.test(none.page.inner) &&
            />UNKNOWN</.test(none.page.inner) &&
            /has not been assessed/.test(none.page.inner),
            'A1. a person never assessed gets the grey UNKNOWN badge, which ' +
            'says why');
    t.check(jsonOf(none.json).risk === null,
            'A2. and the API answers risk: null',
            JSON.stringify(jsonOf(none.json).risk));

    // --- B. assessed -------------------------------------------------------
    const at = Date.now();
    await riskStore.upsertSubject({ realm: 'default', subject: sub,
      score: 0.12, level: 'LOW', reason: 'the model', lastAssessment: 'a-1',
      updatedAt: at - 60000 }, false);
    const low = await draw();
    t.check(/background:#188038/.test(low.page.inner) &&
            />LOW</.test(low.page.inner),
            'B1. LOW is drawn in green');
    await riskStore.upsertSubject({ realm: 'default', subject: sub,
      score: 0.91, level: 'HIGH', reason: 'tor-exit, new-country',
      lastAssessment: 'a-2', updatedAt: at }, false);
    const high = await draw();
    const badge = (/<div class="risk-badge"[\s\S]*?<\/div><\/div>/
      .exec(high.page.inner) || [''])[0];
    t.check(/background:#d93025/.test(badge) && />HIGH</.test(badge) &&
            /font-size:3em/.test(badge) && /score 0\.910/.test(badge) &&
            /was LOW/.test(badge) && /tor-exit, new-country/.test(badge),
            'B2. HIGH is drawn large in red, with the score, the level it ' +
            'came from and what moved it', badge);
    t.check(high.page.inner.indexOf('class="risk-badge"') <
            high.page.inner.indexOf('class="tiles"'),
            'B3. the badge is the first thing on the page');
    const risk = jsonOf(high.json).risk || {};
    t.check(risk.level === 'HIGH' && risk.previousLevel === 'LOW' &&
            risk.score === 0.91 && risk.subject === sub &&
            risk.reason === 'tor-exit, new-country',
            'B4. the API answers the same standing', JSON.stringify(risk));
    await riskStore.upsertSubject({ realm: 'default', subject: sub,
      score: 0.5, level: 'MEDIUM', reason: 'new-asn', lastAssessment: 'a-3',
      updatedAt: at + 1 }, false);
    t.check(/background:#f9ab00/.test((await draw()).page.inner),
            'B5. MEDIUM is drawn in amber');

    // --- C. the link -------------------------------------------------------
    t.check(high.page.inner.indexOf('href="/admin/risk?subject=' +
                                    encodeURIComponent(sub)
                                      .replace(/&/g, '&amp;') +
                                    '#risk-assessments"') >= 0,
            'C1. the badge links to Monitoring → Risk narrowed to this person');
    const view = await riskAdmin.riskView({ subject: sub });
    t.check(Array.isArray(view.assessments.rows) &&
            view.assessments.rows.every(function (row) {
              return row.subject === sub;
            }),
            'C2. and that page narrows its assessments to them');
    // Without a standing read, no badge: nobody asked.
    const unread = admin.usersView({ query: { user: NAME }, headers: {},
      cookies: {}, method: 'GET', path: '/admin/users', url: '/admin/users' });
    t.check(!/class="risk-badge"/.test(unread.inner),
            'C3. a caller that read no standing draws no badge');
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'risk-user-badge-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RB_ROOT: ROOT, RB_OUT: out }),
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
  name: 'risk_user_badge',
  describe: 'a person\'s current risk on their Directory → Users page (#62): ' +
            'large and in colour by level, grey when never assessed, the ' +
            'same standing on /admin-api/users?user=, and a link to ' +
            'Monitoring → Risk narrowed to them',
  run: run
};
