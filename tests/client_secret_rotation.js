'use strict';
//
// File: client_secret_rotation.js
//
// ===========================================================================
// CLIENT-SECRET ROTATION AND EXPIRY (#49 P5, 2026-09-22; rcbj's answer:
// enforce, notify administrators, rotate with an overlap).
//
//   A. ROTATE: `rotate-secret` (the console's and `/admin-api`'s one action)
//      mints a new secret and keeps the old one accepted until
//      oauth2.clientSecretOverlapS — both authenticate — where
//      `regenerate-secret` ends the old one at once.
//   B. THE OVERLAP ENDS: the daily sweep clears the previous secret once its
//      overlap has passed, and it stops authenticating.
//   C. EXPIRY: a secret past oauthClientSecretExpiresAt is REFUSED in product
//      mode (STS-OAUTH-0558) and accepted, and said so, in development.
//   D. THE WARNING: the sweep lists a secret expiring within
//      oauth2.clientSecretExpiryWarningDays and one that has expired, with an
//      audit row each; the job that runs it is registered.
//
// In a child process, with the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'client_secret_rotation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.CS_ROOT;
  const OUT = process.env.CS_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const applications = require(ROOT + '/common/applications');
    const clientAuth = require(ROOT + '/oauth-oidc/client_auth');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const scheduler = require(ROOT + '/cluster/scheduler');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const APP = 'cs-rotation-app';
    const S0 = 'cs-rotation-first-secret-0123456789';
    applications.createApplication({ identifier: APP, protocols: ['oauth2'],
      fields: { oauthClientId: APP, oauthClientSecret: S0,
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const check = function (presented) {
      const current = applications.clientConfigOf(APP) || {};
      return clientAuth.verify({ method: 'client_secret_basic',
        clientId: APP, presentedSecret: presented,
        clientSecret: current.client_secret });
    };

    // --- A. rotate ---------------------------------------------------------
    note((await check(S0)).ok, 'A0. the first secret authenticates');
    const rotated = actions.applicationsAction(
      { action: 'rotate-secret', application: APP }, [], {});
    const reply = rotated && rotated.then ? await rotated : rotated;
    const S1 = reply && reply.clientSecret;
    note(reply && reply.ok && S1 && S1 !== S0 && reply.overlapUntil > Date.now(),
         'A1. rotate-secret mints a new secret and says until when the old ' +
         'one works', JSON.stringify(reply && { ok: reply.ok,
           until: reply.overlapUntil }));
    const newOk = await check(S1);
    const oldOk = await check(S0);
    note(newOk.ok && oldOk.ok && oldOk.previousSecret === true,
         'A2. inside the overlap BOTH the new and the old secret authenticate',
         JSON.stringify({ newOk: newOk.ok, oldOk: oldOk.ok }));

    // --- B. the overlap ends ------------------------------------------------
    // Its end in the past, and no sweep yet: the TIME alone refuses it.
    applications.updateApplication(APP, { attribute:
      'oauthClientSecretPreviousUntil', mode: 'set',
      value: String(Date.now() - 1000) });
    const lapsed = await check(S0);
    note(!lapsed.ok && lapsed.errorCode === 'STS-OAUTH-0020',
         'B0. once the overlap has passed the old secret is refused, before ' +
         'any sweep has cleared it', JSON.stringify(lapsed));
    const overlapMs = Number(config.value('oauth2.clientSecretOverlapS')) *
                      1000;
    const swept = applications.sweepClientSecrets(Date.now() + overlapMs +
                                                  1000);
    note(swept.cleared.indexOf(APP) >= 0,
         'B1. past the overlap the sweep clears the previous secret',
         JSON.stringify(swept.cleared));
    const oldAfter = await check(S0);
    note(!oldAfter.ok && oldAfter.errorCode === 'STS-OAUTH-0020' &&
         (await check(S1)).ok,
         'B2. and the old secret stops authenticating; the new one goes on',
         JSON.stringify(oldAfter));
    const regen = applications.regenerateClientSecret(APP);
    const S2 = regen.clientSecret;
    note(!(await check(S1)).ok && (await check(S2)).ok,
         'B3. regenerate-secret still ends the old secret at once');

    // --- C. expiry -----------------------------------------------------------
    const past = Math.floor(Date.now() / 1000) - 60;
    applications.updateApplication(APP, { attribute:
      'oauthClientSecretExpiresAt', mode: 'set', value: String(past) });
    const devExpired = await check(S2);
    note(devExpired.ok,
         'C1. in DEVELOPMENT an expired secret is accepted (and logged)',
         JSON.stringify(devExpired));
    config.setOverride('global.mode', 'product');
    const prodExpired = await check(S2);
    config.clearOverride('global.mode');
    note(!prodExpired.ok && prodExpired.errorCode === 'STS-OAUTH-0558',
         'C2. in PRODUCT it is refused (STS-OAUTH-0558)',
         JSON.stringify(prodExpired));

    // --- D. the warning ----------------------------------------------------
    const OTHER = 'cs-rotation-soon';
    applications.createApplication({ identifier: OTHER, protocols: ['oauth2'],
      fields: { oauthClientId: OTHER, oauthClientSecret: 'cs-soon-secret',
                oauthClientSecretExpiresAt:
                  String(Math.floor(Date.now() / 1000) + 3600) } });
    const report = applications.sweepClientSecrets(Date.now());
    note(report.expired.indexOf(APP) >= 0 &&
         report.expiring.indexOf(OTHER) >= 0,
         'D1. the sweep lists the expired secret and the one expiring within ' +
         'the warning window', JSON.stringify(report));
    const rows = audit.list();
    note(rows.some(function (r) {
      return r.action === 'application.secret-expired' && r.target === APP;
    }) && rows.some(function (r) {
      return r.action === 'application.secret-expiring' && r.target === OTHER;
    }), 'D2. each with an audit row an administrator can find');
    const job = scheduler.job('oauth2.client-secret-expiry');
    note(job && job.scope === 'realm' && (job.kind || 'cluster') === 'cluster',
         'D3. and the daily job that runs the sweep is registered, per realm');

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'client-secret-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', CS_ROOT: ROOT, CS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'client_secret_rotation',
  describe: 'client-secret rotation with an overlap, the overlap ending, ' +
            'expiry refused in product and accepted in development, and the ' +
            'daily warning of secrets expiring and expired (#49 P5)',
  run: run
};
