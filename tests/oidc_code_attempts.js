// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/oidc_code_attempts.js
//
// ---------------------------------------------------------------------------
// AN OIDC AUTHORIZATION-CODE SIGN-IN ON THE ATTEMPTS TAB.
//
// The tab is the audit log. `application_authentications.js` writes the row
// itself. This one does not: it creates an application declared for the
// authorization-code flow, creates a person, and signs that person in through
// `/oauth2/authorize` and the sign-in screen. It then draws the console's
// application page — Directory → Applications → the application,
// Authentication attempts — the way the console's renderer draws it from
// `GET /admin-api/applications?application=`.
//
// Two applications, the same person:
//
//   1. The application this file creates (`oauth2` and `oidc`, grant
//      `authorization_code`, response type `code`, a public client).
//   2. `sts-admin-console`, the console's own client, which the service
//      seeds as that same flow. The page the console calls
//      Applications → Application → sts-admin-console.
//
// Each sign-in is a new browser. The code on the redirect is how the test
// knows the flow finished. The tab has to name the person, the application's
// client id (`application=` or `client_id=`) and the method. The password is
// not on the page. The console was not driven in a browser; the HTML is the
// console renderer's.
//
// THEN SINGLE SIGN-ON (2026-10-26). The first browser, still holding the
// session it signed in with, asks `/oauth2/authorize` for `sts-admin-console`
// and is answered with a code and no screen. No credential is presented, so
// until `authn.notePresented()` wrote `session.presented` that visit was on
// neither Authentication attempts tab. Both screen sign-ins write no such
// row — the return trip to `/oauth2/authorize` is the sign-in's own — and
// the single sign-on writes exactly one, on the console's tab and on the
// person's. Neither screen sign-in's trip back from the consent screen is one
// either. Last, a single sign-on into a second application of this file's
// kind, which asks for consent: the visit before the consent screen and the
// one after it are one act, and write one row.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'oidc_code_attempts',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const http = require('http');
  const crypto = require('crypto');
  const ROOT = process.env.RD_ROOT;
  const OUT = process.env.RD_OUT;
  const log = require('bunyan').createLogger({
    name: 'oidc_code_attempts_child',
    level: process.env.LOG_LEVEL || 'info' });
  const findings = [];

  /**
   * One finding the parent reads back.
   *
   * @param ok - whether it held
   * @param what - the sentence
   * @param detail - optional evidence, never the password
   */
  function note(ok, what, detail) {
    log.debug("Entering note().");
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    log.debug("Leaving note().");
  }

  /**
   * A location as a path on this process, host stripped.
   *
   * @param location - a URL or a path
   * @returns pathname and query
   */
  function pathOf(location) {
    log.debug("Entering pathOf().");
    const u = new URL(String(location || ''), 'http://127.0.0.1');
    log.debug("Leaving pathOf().");
    return u.pathname + u.search;
  }

  /**
   * Evidence with the password taken out, short enough to read.
   *
   * @param text - what a failure would print
   * @param secret - the password
   * @returns the text, cut
   */
  function safe(text, secret) {
    log.debug("Entering safe().");
    const out = String(text || '').split(secret).join('[password]')
      .slice(0, 600);
    log.debug("Leaving safe().");
    return out;
  }

  /**
   * GET one path, keeping the jar.
   *
   * @param port - the listen port
   * @param jar - cookie name to value
   * @param userAgent - the browser name
   * @param urlPath - the path
   * @returns `{ status, headers, text }`
   */
  function get(port, jar, userAgent, urlPath) {
    log.debug("Entering get().");
    return new Promise(function (resolve) {
      const headers = { 'user-agent': userAgent };
      if (Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      const req = http.request({ host: '127.0.0.1', port: port,
        path: pathOf(urlPath), method: 'GET', headers: headers },
      function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          const value = pair.slice(eq + 1);
          if (value === '') {
            delete jar[pair.slice(0, eq)];
          } else {
            jar[pair.slice(0, eq)] = value;
          }
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          log.debug("Leaving get(). " + res.statusCode);
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text });
        });
      });
      req.on('error', function (e) {
        log.debug("Caught in get(): " + ((e && e.message) || e));
        log.debug("Leaving get(). The request failed.");
        resolve({ status: 0, headers: {}, text: String(e && e.message) });
      });
      req.end();
    });
  }

  /**
   * The authorization-code sign-in, as a browser with no session.
   *
   * @param port - the listen port
   * @param screen - the sign-in helper
   * @param userAgent - the browser name
   * @param clientId - the OAuth client id
   * @param redirect - the registered redirect URI
   * @param username - the person
   * @param password - what the screen is given
   * @returns the last location, and the jar
   */
  async function signIn(port, screen, userAgent, clientId, redirect,
                        username, password) {
    log.debug("Entering signIn(). " + clientId);
    const jar = {};
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier)
      .digest('base64url');
    const start = '/oauth2/authorize?' + new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: redirect,
      scope: 'openid', state: 's', nonce: 'n',
      code_challenge: challenge, code_challenge_method: 'S256'
    }).toString();
    let at = await get(port, jar, userAgent, start);
    for (let i = 0; i < 4 && at.status >= 300 && at.status < 400 &&
         !/\/authn\/login\?/.test(String(at.headers.location || '')); i++) {
      at = await get(port, jar, userAgent, at.headers.location);
    }
    let step = await screen.follow({ port: port, jar: jar,
      userAgent: userAgent, at: pathOf(at.headers.location),
      fields: { username: username, password: password, action: 'login' } });
    if (step.next === 'mfa') {
      step = await screen.ignoreOffer({ port: port, jar: jar,
                                        userAgent: userAgent }, step);
    }
    let loc = String((step.headers && step.headers.location) ||
                     step.location || '');
    for (let i = 0; i < 6 && !/[?&]code=/.test(loc); i++) {
      if (!loc || /[?&]error=/.test(loc)) {
        break;
      }
      if (/\/oauth2\/consent/.test(loc)) {
        const allowed = await screen.answerConsent({ port: port, jar: jar,
          userAgent: userAgent, at: pathOf(loc) });
        loc = String((allowed.headers && allowed.headers.location) ||
                     allowed.location || '');
        continue;
      }
      const next = await get(port, jar, userAgent, loc);
      loc = String((next.headers && next.headers.location) || '');
      if (!(next.status >= 300 && next.status < 400)) {
        break;
      }
    }
    log.debug("Leaving signIn(). " + clientId);
    return { location: loc, next: step.next, errors: step.errors || [],
             status: step.status, jar: jar };
  }

  /**
   * An authorization request from a browser that already holds a session:
   * redirects and a consent screen are followed, the sign-in screen is not.
   *
   * @param port - the listen port
   * @param screen - the sign-in helper, for the consent screen
   * @param userAgent - the browser name
   * @param jar - the browser's cookies, holding its session
   * @param clientId - the OAuth client id
   * @param redirect - the registered redirect URI
   * @returns the last location, whether the sign-in screen was reached, and
   *   whether the consent screen was answered
   */
  async function authorizeOnSession(port, screen, userAgent, jar, clientId,
                                    redirect) {
    log.debug("Entering authorizeOnSession(). " + clientId);
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier)
      .digest('base64url');
    let loc = '/oauth2/authorize?' + new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: redirect,
      scope: 'openid', state: 's', nonce: 'n',
      code_challenge: challenge, code_challenge_method: 'S256'
    }).toString();
    let screened = false;
    let consented = false;
    for (let i = 0; i < 6 && !/[?&]code=/.test(loc); i++) {
      if (/\/authn\/login/.test(loc)) {
        screened = true;
        break;
      }
      if (/\/oauth2\/consent/.test(loc)) {
        const allowed = await screen.answerConsent({ port: port, jar: jar,
          userAgent: userAgent, at: pathOf(loc) });
        consented = true;
        loc = String((allowed.headers && allowed.headers.location) ||
                     allowed.location || '');
        continue;
      }
      const next = await get(port, jar, userAgent, loc);
      loc = String((next.headers && next.headers.location) || '');
      if (!(next.status >= 300 && next.status < 400)) {
        break;
      }
    }
    log.debug("Leaving authorizeOnSession(). " + clientId);
    return { location: loc, screened: screened, consented: consented };
  }

  /**
   * The person's `session.presented` rows in the audit log.
   *
   * @param audit - the audit log
   * @param username - the person
   * @returns those rows, newest first
   */
  async function presentedBy(audit, username) {
    log.debug("Entering presentedBy().");
    await audit.fresh();
    const rows = audit.list().filter(function (row) {
      return row.action === 'session.presented' && row.actor === username;
    });
    log.debug("Leaving presentedBy(). " + rows.length);
    return rows;
  }

  /**
   * The Authentication attempts panel of one application's console page.
   *
   * @param views - the admin views
   * @param page - the applications renderer
   * @param kit - the console kit
   * @param port - the listen port, for the request host
   * @param identifier - the application
   * @returns the drill-down and the panel's HTML
   */
  async function attemptsOf(views, page, kit, audit, port, identifier) {
    log.debug("Entering attemptsOf(). " + identifier);
    await audit.fresh();
    const json = views.applicationsJson({
      query: { application: identifier },
      headers: { host: '127.0.0.1:' + port },
      protocol: 'http',
      get: function () { return ''; }
    });
    const html = page.detail(kit.context({ application: identifier }), json);
    const at = html.indexOf('id="tab-authentications"');
    const next = at < 0 ? -1 : html.indexOf('id="tab-', at + 24);
    const tab = at < 0 ? '' : html.slice(at, next < 0 ? html.length : next);
    log.debug("Leaving attemptsOf(). " + identifier);
    return { json: json, tab: tab };
  }

  const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

  (async function () {
    log.debug("Entering the oidc code attempts child.");
    require(ROOT + '/common/protocol_stack');
    require(ROOT + '/common/i18n');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const views = require(ROOT + '/admin-core/admin_views');
    const page = require(ROOT + '/admin-ui/web_applications');
    const usersPage = require(ROOT + '/admin-ui/web_users');
    const kit = require(ROOT + '/admin-ui/web_kit');
    const screen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const tag = 'oidccode' + process.pid;
    const APP = tag + '-app';
    const REDIRECT = 'https://rp.' + tag + '.example/cb';
    const USER = tag + '-user';
    const PASSWORD = 's3cret-' + tag;
    const CONSOLE = 'sts-admin-console';

    const created = applications.createApplication({
      identifier: APP, protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: APP, oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthResponseType: ['code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'none' }
    });
    const person = ldap.createUser(USER, { invent: false });
    note(created && created.ok === true && person && person.ok !== false,
         '1. an OIDC authorization-code application and a user are created',
         JSON.stringify({ app: created && created.errors,
                          user: person && person.errors }));

    const signed = await signIn(port, screen, CHROME, APP, REDIRECT, USER,
                                 PASSWORD);
    const coded = /[?&]code=/.test(signed.location) &&
      signed.location.indexOf(REDIRECT) === 0;
    note(coded, '2. the user finishes the authorization-code sign-in',
         safe(signed.status + ' ' + signed.next + ' ' +
              (signed.errors || []).join('; ') + ' ' + signed.location,
              PASSWORD));

    const appPage = await attemptsOf(views, page, kit, audit, port, APP);
    const appEvents = (appPage.json.authenticationEvents || []).filter(
      function (row) {
        return row.action === 'authentication' && row.actor === USER;
      });
    const appDetail = (appEvents[0] && appEvents[0].detail) || {};
    note(coded && appPage.tab.indexOf('id="tab-authentications"') >= 0 &&
         appEvents.length >= 1 &&
         (appDetail.application === APP || appDetail.client_id === APP) &&
         appPage.tab.indexOf(USER) >= 0 &&
         (appPage.tab.indexOf('application=' + APP) >= 0 ||
          appPage.tab.indexOf('client_id=' + APP) >= 0) &&
         appPage.tab.indexOf('method=') >= 0 &&
         appPage.tab.indexOf('method=' + appDetail.method) >= 0 &&
         appPage.tab.indexOf('No authentication attempt naming this') < 0 &&
         appPage.tab.indexOf(PASSWORD) < 0 &&
         appPage.tab.indexOf('application=' + CONSOLE) < 0,
         '3. that application\'s Authentication attempts tab names the ' +
         'user, the client and the method',
         safe(JSON.stringify({ detail: appDetail,
                               tab: appPage.tab.slice(0, 400) }), PASSWORD));

    const consoleRow = applications.get(CONSOLE);
    const consoleCfg = applications.clientConfigOf(CONSOLE);
    const grants = [].concat((consoleRow && consoleRow.fields &&
                              consoleRow.fields.oauthGrantType) || []);
    const responses = [].concat((consoleRow && consoleRow.fields &&
                                 consoleRow.fields.oauthResponseType) || []);
    const consoleRedirect = (consoleCfg.redirect_uris || [])[0] || '';
    note(!!consoleRow && grants.indexOf('authorization_code') >= 0 &&
         (responses.length === 0 || responses.indexOf('code') >= 0) &&
         !!consoleRedirect,
         '4. sts-admin-console is the seeded authorization-code client',
         JSON.stringify({ grants: grants, responses: responses,
                          redirect: consoleRedirect }));

    const consoleSign = await signIn(port, screen, CHROME, CONSOLE,
                                      consoleRedirect, USER, PASSWORD);
    const consoleCoded = /[?&]code=/.test(consoleSign.location);
    note(consoleCoded,
         '5. the same user signs in to sts-admin-console that way',
         safe(consoleSign.status + ' ' + consoleSign.next + ' ' +
              (consoleSign.errors || []).join('; ') + ' ' +
              consoleSign.location, PASSWORD));

    const consolePage = await attemptsOf(views, page, kit, audit, port,
                                          CONSOLE);
    const consoleEvents = (consolePage.json.authenticationEvents || [])
      .filter(function (row) {
        return row.action === 'authentication' && row.actor === USER;
      });
    const consoleDetail = (consoleEvents[0] && consoleEvents[0].detail) ||
      {};
    note(consoleCoded &&
         consolePage.tab.indexOf('id="tab-authentications"') >= 0 &&
         consoleEvents.length >= 1 &&
         (consoleDetail.application === CONSOLE ||
          consoleDetail.client_id === CONSOLE) &&
         consolePage.tab.indexOf(USER) >= 0 &&
         (consolePage.tab.indexOf('application=' + CONSOLE) >= 0 ||
          consolePage.tab.indexOf('client_id=' + CONSOLE) >= 0) &&
         consolePage.tab.indexOf('method=') >= 0 &&
         consolePage.tab.indexOf('method=' + consoleDetail.method) >= 0 &&
         consolePage.tab.indexOf('No authentication attempt naming this') <
           0 &&
         consolePage.tab.indexOf(PASSWORD) < 0 &&
         consolePage.tab.indexOf('application=' + APP) < 0,
         '6. Applications → sts-admin-console → Authentication attempts ' +
         'lists that user',
         safe(JSON.stringify({ detail: consoleDetail,
                               tab: consolePage.tab.slice(0, 400) }),
              PASSWORD));

    const beforeSso = await presentedBy(audit, USER);
    note(beforeSso.length === 0,
         '7. neither screen sign-in wrote session.presented: the return ' +
         'trip to /oauth2/authorize is the sign-in\'s own',
         JSON.stringify(beforeSso.map(function (row) {
           return row.detail;
         })));

    const sso = await authorizeOnSession(port, screen, CHROME, signed.jar,
                                         CONSOLE, consoleRedirect);
    const ssoCoded = !sso.screened && /[?&]code=/.test(sso.location);
    note(coded && ssoCoded,
         '8. the first browser reaches sts-admin-console on the session ' +
         'it already holds, with no sign-in screen',
         sso.screened + ' ' + sso.location);

    const afterSso = await presentedBy(audit, USER);
    const presented = (afterSso[0] && afterSso[0].detail) || {};
    note(afterSso.length === 1 && presented.application === CONSOLE &&
         presented.method === 'existing session' &&
         afterSso[0].protocol === 'OAuth 2.0 / OIDC' && !!presented.sub &&
         !!presented.sessionId,
         '9. that single sign-on wrote one session.presented row naming ' +
         'sts-admin-console, the method and the session',
         JSON.stringify(afterSso.map(function (row) {
           return { protocol: row.protocol, detail: row.detail };
         })));

    const ssoPage = await attemptsOf(views, page, kit, audit, port, CONSOLE);
    const ssoEvents = (ssoPage.json.authenticationEvents || []).filter(
      function (row) {
        return row.action === 'session.presented' && row.actor === USER;
      });
    note(ssoEvents.length === 1 &&
         ssoPage.tab.indexOf('session.presented') >= 0 &&
         ssoPage.tab.indexOf('method=existing session') >= 0 &&
         ssoPage.tab.indexOf(PASSWORD) < 0,
         '10. Applications → sts-admin-console → Authentication attempts ' +
         'lists the single sign-on',
         safe(JSON.stringify({ events: ssoEvents.length,
                               tab: ssoPage.tab.slice(0, 600) }),
              PASSWORD));

    const userJson = views.usersJson({
      query: { user: USER },
      headers: { host: '127.0.0.1:' + port },
      protocol: 'http',
      get: function () { return ''; }
    });
    const userHtml = usersPage.detail(kit.context({ user: USER }), userJson);
    const userAt = userHtml.indexOf('id="utab-authentications"');
    const userNext = userAt < 0 ? -1 :
      userHtml.indexOf('id="utab-', userAt + 25);
    const userTab = userAt < 0 ? '' :
      userHtml.slice(userAt, userNext < 0 ? userHtml.length : userNext);
    const userEvents = (userJson.authenticationEvents || []).filter(
      function (row) {
        return row.action === 'session.presented';
      });
    note(userEvents.length === 1 &&
         userTab.indexOf('session.presented') >= 0 &&
         userTab.indexOf('method=existing session') >= 0 &&
         (userTab.indexOf('application=' + CONSOLE) >= 0) &&
         userTab.indexOf(PASSWORD) < 0,
         '11. the person\'s Authentication attempts tab lists the single ' +
         'sign-on to sts-admin-console',
         safe(JSON.stringify({ events: userEvents.length,
                               tab: userTab.slice(0, 600) }), PASSWORD));

    const APP2 = tag + '-consent';
    const REDIRECT2 = 'https://rp2.' + tag + '.example/cb';
    const created2 = applications.createApplication({
      identifier: APP2, protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: APP2, oauthRedirectUri: [REDIRECT2],
                oauthGrantType: ['authorization_code'],
                oauthResponseType: ['code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'none' }
    });
    const before2 = (await presentedBy(audit, USER)).length;
    const sso2 = await authorizeOnSession(port, screen, CHROME, signed.jar,
                                          APP2, REDIRECT2);
    const after2 = (await presentedBy(audit, USER)).filter(function (row) {
      return (row.detail || {}).application === APP2;
    });
    const total2 = (await presentedBy(audit, USER)).length;
    note(created2 && created2.ok === true && !sso2.screened &&
         sso2.consented && /[?&]code=/.test(sso2.location) &&
         after2.length === 1 &&
         total2 === before2 + 1,
         '12. a single sign-on through a consent screen writes one ' +
         'session.presented row, not one each way',
         JSON.stringify({ screened: sso2.screened, consented: sso2.consented,
                          location: sso2.location,
                          rows: after2.length, before: before2,
                          total: total2 }));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    log.debug("Leaving the oidc code attempts child.");
    process.exit(0);
  })().catch(function (e) {
    log.debug("Caught in the oidc code attempts child: " +
              ((e && e.message) || e));
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    try {
      fs.writeFileSync(OUT, JSON.stringify(findings));
    } catch (writeError) {
      log.debug("Caught in the oidc code attempts child: " +
                ((writeError && writeError.message) || writeError));
    }
    process.exit(0);
  });
}

/**
 * Runs the stack in a child and reports each finding.
 *
 * @param t - the harness
 */
function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(),
    'oidc-code-attempts-' + process.pid + '-' +
    require('crypto').randomBytes(8).toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', RD_ROOT: ROOT,
                                  RD_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
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

/**
 * The suite entry.
 *
 * @param t - the harness
 */
function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidc code attempts',
  describe: 'an OIDC authorization-code sign-in is on the application ' +
            'page\'s Authentication attempts tab, including ' +
            'sts-admin-console, and a single sign-on on an existing ' +
            'session is on that tab and the person\'s',
  run: run
};
