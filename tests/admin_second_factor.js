'use strict';
//
// File: admin_second_factor.js
//
// ===========================================================================
// A SECOND FACTOR FOR ADMINISTRATORS, AS POLICY (#246, 2026-09-26).
//
// rcbj: "I want admin having MFA to be a policy decision that is defined
// under Directory->Policies in the default realm." The authentication
// policy's `requireSecondFactorForAdministrators` — `if-held`, `offer` (the
// default for now) or `always` — for anybody holding a console role. What
// this holds:
//
//   A. THE FIELD: its values and default, the save that refuses `always`
//      with no second-factor mechanism, and the sentence the page draws.
//   B. WHO: `credentials.mfaRequirementFor()` offers a second factor to an
//      administrator and to nobody else, requires it under `always`, and
//      only ever OFFERS it to the default realm's built-in administrator.
//   C. THE OFFER, over HTTP: the sign-in screen draws the set-up step with
//      an Ignore button, and Ignore signs the person in on their password.
//   D. `always`: no Ignore button, and an Ignore posted anyway is refused.
//   E. Somebody who is not an administrator is never offered one.
//   F. AT ELEVATED RISK (#226's console, never locked out): the offer is
//      made, recorded as STS-RISK-0039, and Ignore reaches the console.
//
// In a child process, because it loads the whole stack and changes settings
// and policies the rest of the in-process suite must not see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'admin_second_factor',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RD_ROOT;
  const OUT = process.env.RD_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function browser(port, userAgent) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({ 'user-agent': userAgent },
                                      o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const credentials = require(ROOT + '/common/credentials');
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const adminRbac = require(ROOT + '/admin-ui/admin_rbac');
    const riskDatasets = require(ROOT + '/risk/risk_datasets');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);
    const SECRET = 'admin-second-factor-secret-0123456789ab';
    const REDIRECT = 'https://rp.admin-mfa.example/cb';
    const CLIENT = 'asf-client';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const policyWith = function (fields) {
      const saved = authnPolicy.save('default',
        Object.assign({}, authnPolicy.DEFAULTS, fields));
      if (!saved.ok) {
        throw new Error('policy not saved: ' + JSON.stringify(saved.errors));
      }
    };
    const auditOf = function (action, actor) {
      return audit.list().filter(function (row) {
        return row.action === action && row.actor === actor;
      });
    };
    const pathOf = function (location) {
      const u = new URL(String(location || ''), 'http://127.0.0.1');
      return u.pathname + u.search;
    };
    // The password step of a sign-in to `start` (a path answering with a
    // redirect toward the sign-in screen), answered as `username`.
    const passwordStep = async function (b, start, username) {
      let at = await b.go('GET', start);
      for (let i = 0; i < 4 && at.status >= 300 && at.status < 400 &&
           !/\/authn\/login\?/.test(String(at.headers.location || ''));
           i++) {
        at = await b.go('GET', pathOf(at.headers.location));
      }
      const screen = pathOf(at.headers.location);
      const page = await b.go('GET', screen);
      return b.go('POST', screen.split('?')[0], {
        form: Object.assign(hiddenFields(page.text), {
          username: username, password: 'anything', action: 'login' }) });
    };
    const followTo = async function (b, first, pattern) {
      let at = first;
      for (let i = 0; i < 5 && at.status >= 300 && at.status < 400 &&
           !pattern.test(String(at.headers.location || '')); i++) {
        at = await b.go('GET', pathOf(at.headers.location));
      }
      return at;
    };
    const authorizeAt = '/oauth2/authorize?' + new URLSearchParams({
      client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
      scope: 'openid', state: 's', nonce: 'n' }).toString();
    const ignoreOf = function (html) {
      return /id="mfa-setup-ignore"/.test(html)
        ? (String(html).match(/name="mfa_id" value="([^"]+)"/) || [])[1] ||
          '' : '';
    };

    // --- A. the field -----------------------------------------------------
    const field = authnPolicy.FIELD_BY_KEY.requireSecondFactorForAdministrators;
    note(field && field.values.join(',') === 'if-held,offer,always' &&
         authnPolicy.DEFAULTS.requireSecondFactorForAdministrators === 'offer',
         'A1. the field is if-held, offer or always, and offer by default',
         JSON.stringify(field && field.values));
    const secondOff = {};
    Object.keys(authnPolicy.DEFAULTS).forEach(function (key) {
      if (/SecondFactor$/.test(key) && key.indexOf('require') !== 0) {
        secondOff[key] = false;
      }
    });
    const refused = authnPolicy.validate(Object.assign({},
      authnPolicy.DEFAULTS, secondOff,
      { requireSecondFactorForAdministrators: 'always' }));
    note(refused && (refused.problems || []).some(function (e) {
           return /administrators/.test(e);
         }),
         'A2. always with no second-factor mechanism accepted is refused',
         JSON.stringify(refused && refused.problems));
    note(authnPolicy.describe().some(function (line) {
      return /administrators who hold none are offered one/.test(line);
    }), 'A3. the page says what the default does');

    // --- B. who -------------------------------------------------------------
    ldap.createUser('asf-alice', { invent: false });
    ldap.createUser('asf-bob', { invent: false });
    adminRbac.grant('asf-alice', 'write', { via: 'test', actor: 'test' });
    // The built-in administrator, in the roster as a started service seeds
    // it: this stack binds no listener, so nothing seeded it.
    const builtIn = String(config.value('admin.bootstrapUsername') || '');
    if (builtIn) {
      ldap.createUser(builtIn, { invent: false });
      adminRbac.grant(builtIn, 'write', { via: 'test', actor: 'test' });
    }
    const alice = credentials.mfaRequirementFor('asf-alice');
    const bob = credentials.mfaRequirementFor('asf-bob');
    note(alice.offered && !alice.required && !bob.offered && !bob.required,
         'B1. offer: an administrator is offered a second factor, and ' +
         'somebody holding no console role is not',
         JSON.stringify({ alice: alice, bob: bob }));
    policyWith({ requireSecondFactorForAdministrators: 'always' });
    const aliceAlways = credentials.mfaRequirementFor('asf-alice');
    const builtInAlways = builtIn
      ? credentials.mfaRequirementFor(builtIn) : null;
    note(aliceAlways.required && aliceAlways.byAdministrator &&
         !aliceAlways.offered && builtInAlways &&
         builtInAlways.offered && !builtInAlways.required,
         'B2. always: an administrator must set one up, and the built-in ' +
         'administrator (' + builtIn + ') is only offered one',
         JSON.stringify({ alice: aliceAlways, builtIn: builtInAlways }));
    policyWith({ requireSecondFactorForAdministrators: 'if-held' });
    const aliceIfHeld = credentials.mfaRequirementFor('asf-alice');
    note(!aliceIfHeld.offered && !aliceIfHeld.required,
         'B3. if-held: an administrator is asked as everybody else is',
         JSON.stringify(aliceIfHeld));
    policyWith({});

    // --- C. the offer, over HTTP ------------------------------------------
    const b1 = browser(port, CHROME);
    const offeredPage = await passwordStep(b1, authorizeAt, 'asf-alice');
    const offerId = ignoreOf(offeredPage.text);
    note(offeredPage.status === 200 && !!offerId &&
         /Setting one up now is recommended/.test(offeredPage.text),
         'C1. an administrator with no second factor is shown the set-up ' +
         'step with an Ignore button', offeredPage.status + ' ' +
         offeredPage.text.slice(0, 160));
    const ignored = await b1.go('POST', '/authn/mfa-setup',
                                { form: { mfa_id: offerId,
                                          action: 'ignore' } });
    const landed = await followTo(b1, ignored,
                                  new RegExp('^' + REDIRECT.replace(
                                    /[.*+?^${}()|[\]\\/]/g, '\\$&')));
    note(String(landed.headers.location || '').indexOf(REDIRECT + '?code=') ===
           0 && auditOf('authn.mfa.enrolment.offered', 'asf-alice').length &&
         auditOf('authn.mfa.enrolment.declined', 'asf-alice').length,
         'C2. Ignore signs them in on their password, and the offer and ' +
         'the refusal of it are both on the audit log',
         ignored.status + ' ' + String(landed.headers.location || ''));

    // --- D. always ----------------------------------------------------------
    policyWith({ requireSecondFactorForAdministrators: 'always' });
    const b2 = browser(port, CHROME);
    const requiredPage = await passwordStep(b2, authorizeAt, 'asf-alice');
    const requiredId = (requiredPage.text.match(
      /name="mfa_id" value="([^"]+)"/) || [])[1] || '';
    const pushed = await b2.go('POST', '/authn/mfa-setup',
                               { form: { mfa_id: requiredId,
                                         action: 'ignore' } });
    note(requiredPage.status === 200 && !!requiredId &&
         !ignoreOf(requiredPage.text) && pushed.status === 400 &&
         /cannot be ignored/.test(pushed.text),
         'D1. always: the set-up step has no Ignore button, and an Ignore ' +
         'posted anyway is refused (STS-AUTHN-0270)',
         requiredPage.status + ' ' + pushed.status);
    policyWith({});

    // --- E. not an administrator -------------------------------------------
    const b3 = browser(port, CHROME);
    const bobAnswer = await passwordStep(b3, authorizeAt, 'asf-bob');
    note(bobAnswer.status >= 300 && bobAnswer.status < 400 &&
         !auditOf('authn.mfa.enrolment.offered', 'asf-bob').length,
         'E1. somebody holding no console role signs straight in',
         bobAnswer.status + ' ' + String(bobAnswer.headers.location || ''));

    // --- F. at elevated risk, at the console --------------------------------
    config.setOverride('risk.enforceInDevelopment', true);
    config.setOverride('risk.datasetShrinkLimitPercent', 100);
    const denied = await riskDatasets.importVersion({
      dataset: 'iplist.operator-deny', realm: 'default', format: 'ip-list',
      content: '127.0.0.1\n', version: 'asf-deny-1', source: 'upload' });
    ldap.createUser('asf-carl', { invent: false });
    adminRbac.grant('asf-carl', 'read', { via: 'test', actor: 'test' });
    const b4 = browser(port, CHROME);
    const riskyPage = await passwordStep(b4, '/admin', 'asf-carl');
    const riskyId = ignoreOf(riskyPage.text);
    const atRisk = auditOf('authn.mfa.enrolment.at-risk', 'asf-carl');
    let riskyDone = riskyId ? await b4.go('POST', '/authn/mfa-setup',
      { form: { mfa_id: riskyId, action: 'ignore' } }) : riskyPage;
    riskyDone = await followTo(b4, riskyDone, /\/admin\/callback\?/);
    note(denied && denied.ok && !!riskyId && atRisk.length === 1 &&
         atRisk[0].errorCode === 'STS-RISK-0039' &&
         /\/admin\/callback\?.*code=/.test(String(riskyDone.headers.location ||
                                                  '')),
         'F1. at HIGH the console still offers the second factor, the ' +
         'offer is recorded as made at elevated risk (STS-RISK-0039), and ' +
         'Ignore reaches the console',
         JSON.stringify({ deny: denied && denied.ok, offered: !!riskyId,
           atRisk: atRisk.length,
           at: String(riskyDone.headers.location || '').slice(0, 80),
           page: riskyPage.text.slice(0, 120) }));

    server.close();
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
  const out = path.join(os.tmpdir(), 'admin-second-factor-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', RD_ROOT: ROOT, RD_OUT: out }),
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
  name: 'admin_second_factor',
  describe: 'a second factor for administrators as authentication policy ' +
            '(#246): the field and its default, who is offered and who ' +
            'required, the Ignore button over HTTP, always without it, and ' +
            'the offer at elevated risk at the console',
  run: run
};
