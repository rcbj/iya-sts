'use strict';
//
// File: risk_realm_admin.js
//
// ===========================================================================
// A REALM ADMINISTRATOR ON THE RISK PAGES (#62, 2026-09-22; rcbj: "realm
// admins see /admin/risk"). Until then both pages were service pages.
//
//   A. THE GATE (`admin-ui/admin_scope.ts`): a realm administrator reaches
//      Monitoring → Risk and Risk Scoring, sees them in the navigation, and
//      is refused another realm by `?realm=`; of the actions, only their own
//      realm's operator allow and deny lists — never a service dataset, a
//      provider's terms, or another realm's list.
//   B. THE VIEW (`admin-ui/risk_admin.ts`): unnamed, the realm is the one
//      the page is drawn in; the realm-only view holds the realm's own
//      operator lists and no service dataset, no provider's terms and no
//      acceptance, and the scoring page no process counts.
//   C. THE PAGE drawn for them has no terms, no settings and an import form
//      pinned to their realm.
//
// In a child process, because it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_realm_admin',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.RR_ROOT;
  const OUT = process.env.RR_OUT;
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
    const realms = require(ROOT + '/common/realms');
    const scope = require(ROOT + '/admin-ui/admin_scope');
    const riskAdmin = require(ROOT + '/admin-ui/risk_admin');
    const admin = require(ROOT + '/admin-ui/admin');

    const REALM = 'rra-acme';
    realms.create({ id: REALM, name: 'Risk realm administrator' });
    const state = { authority: 'realm', identityRealm: REALM };
    const refused = function (pagePath, body, query) {
      return scope.refusalFor(state, pagePath, body || null, query || {});
    };

    // --- A. the gate -------------------------------------------------------
    t.check(!refused('/admin/risk') && !refused('/admin/risk-scoring') &&
            scope.pageVisible(state, '/admin/risk') &&
            scope.pageVisible(state, '/admin/risk-scoring'),
            'A1. a realm administrator reaches both risk pages and sees them ' +
            'in the navigation');
    t.check(!!refused('/admin/risk', null, { realm: 'default' }) &&
            !!refused('/admin/risk-scoring', null, { realm: 'other' }) &&
            !refused('/admin/risk', null, { realm: REALM }),
            'A2. ?realm= naming another realm is refused, their own is not');
    const deny = { action: 'import', dataset: 'iplist.operator-deny',
                   realm: REALM };
    t.check(!refused('/admin/risk', deny) &&
            !refused('/admin/risk', { action: 'rollback',
              dataset: 'iplist.operator-allow', realm: REALM }),
            'A3. their own realm\'s operator lists may be changed');
    const service = refused('/admin/risk', { action: 'import',
      dataset: 'geo.city', realm: '' });
    const terms = refused('/admin/risk', { action: 'accept-terms',
      provider: 'dbip' });
    const other = refused('/admin/risk', Object.assign({}, deny,
                                                       { realm: 'default' }));
    const unnamed = refused('/admin/risk', Object.assign({}, deny,
                                                         { realm: '' }));
    t.check(!!service && !!terms && !!other && !!unnamed &&
            [service, terms, other, unnamed].every(function (r) {
              return r.code === 'STS-ADMIN-0787';
            }),
            'A4. a service dataset, a provider\'s terms, another realm\'s ' +
            'list and an unnamed one are refused (STS-ADMIN-0787)',
            JSON.stringify([service, terms, other, unnamed]));
    t.check(!scope.refusalFor({ authority: 'service' }, '/admin/risk',
                              { action: 'accept-terms' }, {}),
            'A5. a service administrator is refused none of it');

    // --- B. the view -------------------------------------------------------
    const view = await realms.run(realms.get(REALM), function () {
      return riskAdmin.riskView({}, true);
    });
    t.check(view.realm === REALM && view.realmOnly === true &&
            view.datasets.length === 2 &&
            view.datasets.every(function (d) {
              return d.perRealm && d.realm === REALM;
            }) && view.providers.length === 0 &&
            view.acceptances.length === 0 && view.directory === '',
            'B1. unnamed, the realm is the one drawn in, and the realm-only ' +
            'view holds its two operator lists and nothing of the service\'s',
            JSON.stringify({ realm: view.realm, datasets: view.datasets.map(
              function (d) { return d.dataset; }) }));
    const full = await riskAdmin.riskView({});
    t.check(full.realm === 'default' && full.datasets.length > 2 &&
            full.providers.length > 0,
            'B2. a service administrator\'s view in the default realm has ' +
            'every dataset and every provider');
    const metrics = await realms.run(realms.get(REALM), function () {
      return riskAdmin.metricsView({}, true);
    });
    const serviceMetrics = await riskAdmin.metricsView({});
    t.check(metrics.realm === REALM && metrics.process === undefined &&
            !!serviceMetrics.process,
            'B3. the scoring page has no process counts for a realm ' +
            'administrator, and has them for a service one');

    // --- C. the page --------------------------------------------------------
    // The page asks `gateStateFor()` who is looking, and `mayWrite()`; both
    // are answered here as for a realm administrator holding Admin Write.
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const draw = async function (pagePath) {
      let html = '';
      const saved = { respond: admin.respond, mayWrite: admin.mayWrite,
                      gate: adminViews.gateStateFor };
      try {
        admin.respond = function (req, r, json, title, active, inner) {
          html = inner;
        };
        admin.mayWrite = function () {
          return true;
        };
        adminViews.gateStateFor = function () {
          return state;
        };
        let handler = null;
        riskAdmin.registerRoutes({ get: function (p2, h) {
          if (p2 === pagePath) {
            handler = h;
          }
        }, post: function () {} });
        realms.run(realms.get(REALM), function () {
          handler({ query: {}, headers: {} }, {});
        });
        for (let i = 0; i < 100 && !html; i++) {
          await new Promise(function (r) { setTimeout(r, 20); });
        }
      } finally {
        admin.respond = saved.respond;
        admin.mayWrite = saved.mayWrite;
        adminViews.gateStateFor = saved.gate;
      }
      return html;
    };
    const page = await draw(riskAdmin.PAGE);
    t.check(page.length > 0 && page.indexOf('Whose data, on what terms') < 0 &&
            page.indexOf('<h2>Settings</h2>') < 0 &&
            page.indexOf('id="risk-import-accept"') < 0 &&
            page.indexOf('<input type="hidden" name="realm" value="' + REALM +
                         '">') >= 0 &&
            page.indexOf('geo.city') < 0,
            'C1. their page has no terms, no settings and no service ' +
            'dataset, and its import form is pinned to their realm',
            page.slice(0, 300));
    const scoring = await draw(riskAdmin.METRICS_PAGE);
    t.check(scoring.length > 0 && scoring.indexOf('id="risk-process"') < 0 &&
            scoring.indexOf('id="risk-timeline"') >= 0,
            'C2. their scoring page has no process table',
            scoring.slice(0, 300));

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
  const out = path.join(os.tmpdir(), 'risk-realm-admin-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RR_ROOT: ROOT, RR_OUT: out }),
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
  name: 'risk_realm_admin',
  describe: 'a realm administrator on the risk pages (#62): both reached and ' +
            'listed, another realm refused, only their own realm\'s ' +
            'operator lists writable, a view of the realm\'s own with no ' +
            'service dataset, terms or process counts, and a page to match',
  run: run
};
