// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/authn_consent_api.js
// ===========================================================================
// THE OAUTH CONSENT SCREEN IS A PAGE OF THE SIGN-IN SURFACE OVER
// `/authn-api/consent` (#576).
//
// The whole stack in a child process, over HTTP on 127.0.0.1, a person
// signed in at the screen and a consent minted for them by
// `beginConsent()`, as the authorization endpoint mints one:
//
//   1. THE SHELL: `/oauth2/consent?consent=<id>` answers the shell document
//      — the sign-in bundle at `/oauth2/consent.js`, the card, the
//      `<noscript>`, no form — with a policy that keeps `frame-ancestors`;
//      the three checks refuse as they always did (400, `invalid_request`):
//      a malformed id, an unknown one, no session, another person's. The
//      script is served.
//   2. THE INDEX AND THE OPENAPI DOCUMENT name the view and the answer and
//      the page and control each mirrors.
//   3. THE VIEW: facts and no markup — the application, the scopes, the
//      RFC 9396 detail member by member, the limits and their rows, what was
//      already agreed, the request's parameters — and `csrf`, the token of
//      the cookie's session; refused to another person's session.
//   4. THE BINDING of an answer: JSON, an Origin of this service, the
//      token; a malformed id, an unknown field, a limit control under a
//      name the page never draws, and an action that is neither are
//      refused; no refusal carries an error code.
//   5. THE ANSWERS: a raised limit is refused and the consent kept; Allow
//      with a lowered limit names the authorization request to go back to,
//      records the consent and the lowered detail, and spends the record;
//      a replay is refused; Deny names the request with `consent_error=
//      access_denied` and records nothing.
//   6. THE ID IS NEVER IN AN AUDIT ROW.
//   7. THE OLD FORM POST IS GONE.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'authn_consent_api',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.CA_ROOT;
  const OUT = process.env.CA_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const authn = require(ROOT_DIR + '/authn/authn');
    const consentScreen = require(ROOT_DIR + '/oauth-oidc/consent_screen');
    const details = require(ROOT_DIR + '/oauth-oidc/authorization_details');
    const websecurity = require(ROOT_DIR + '/common/websecurity');
    const audit = require(ROOT_DIR + '/common/audit');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const codeFree = function (text) {
      return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ''));
    };
    const session = function (jar) {
      return String(jar.sts_session || '').split('.')[0];
    };
    // A person signed in at the screen, in a jar of their own.
    const signIn = async function (who) {
      const jar = {};
      const at = authn.beginAuthentication({ returnTo: '/ca/after',
        protocol: 'ca-probe', application: '' });
      const r = await screen.submit({ port: port, jar: jar, at: at,
        fields: { action: 'login', username: who, password: 'x' } });
      note(r.next === 'redirect' && !!jar.sts_session,
           '0. ' + who + ' signs in at the screen', r.text);
      return jar;
    };
    const RETURN = '/oauth2/authorize?client_id=ca-client&state=s1';
    const raw = [{ type: 'ca_payment', instructedAmount: '100.00',
                   limits: { amount: '100.00', currency: 'EUR', count: 5 } }];
    const begin = function (who) {
      return consentScreen.beginConsent({
        returnTo: RETURN, username: who, clientId: 'ca-client',
        clientName: 'CA <App>', protocol: 'OAuth 2.0 / OIDC',
        scopes: [{ scope: 'ca.read', permission: null },
                 { scope: 'https://ca.example/write',
                   permission: { name: 'write', description: '',
                                 identifier: 'https://ca.example/write',
                                 baseUri: 'https://ca.example' } }],
        already: [{ scope: 'openid', global: false, at: '' },
                  { scope: 'email', global: true }],
        authorizationDetails: [{ type: 'ca_payment', resource: 'ca-bank',
          resourceName: 'CA Bank', audience: 'https://bank.ca.example',
          description: 'Pay from your account',
          members: [{ name: 'instructedAmount', value: '100.00' }] }],
        rawAuthorizationDetails: raw, detailsDigest: 'ca-digest',
        uiLocales: 'fr',
        details: [{ label: 'client_id', value: 'ca-client' },
                  { label: 'redirect_uri', value: 'https://rp.example/cb' }]
      });
    };

    const alice = await signIn('ca-alice');
    const bob = await signIn('ca-bob');

    // --- 1. the shell ------------------------------------------------------
    let at = begin('ca-alice');
    let r = await screen.call({ port: port, jar: alice, method: 'GET',
                                path: at });
    const csp = String(r.headers['content-security-policy'] || '');
    note(/^\/oauth2\/consent\?consent=/.test(at) && r.status === 200 &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         r.text.indexOf('<script src="/oauth2/consent.js" defer></script>') >
           0 &&
         r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
         r.text.indexOf('<noscript>') > 0 && !/<form/.test(r.text) &&
         !/consent-allow/.test(r.text),
         '1a. /oauth2/consent answers the shell: the bundle, the card, the ' +
         'notice, and no form', r.status + ' ' + r.text.slice(0, 500));
    note(/frame-ancestors 'none'/.test(csp) &&
         /script-src 'self'(;|$)/.test(csp) &&
         /connect-src 'self'/.test(csp) && !/unsafe-inline/.test(csp),
         '1b. its policy keeps frame-ancestors and allows script and API ' +
         'from \'self\' only', csp);
    r = await screen.call({ port: port, jar: alice, method: 'GET',
                            path: '/oauth2/consent?consent=not*an*id' });
    note(r.status === 400 && r.json && r.json.error === 'invalid_request',
         '1c. a malformed id is refused as it always was', r.status);
    r = await screen.call({ port: port, jar: alice, method: 'GET',
      path: '/oauth2/consent?consent=AAAAAAAAAAAAAAAAAAAAAAAA' });
    note(r.status === 400 && /no consent waiting/i.test(r.text),
         '1d. an unknown id is refused as it always was', r.text);
    r = await screen.call({ port: port, jar: {}, method: 'GET', path: at });
    note(r.status === 400 && /Nobody is signed in/.test(r.text),
         '1e. a browser with no session is refused', r.text);
    r = await screen.call({ port: port, jar: bob, method: 'GET', path: at });
    note(r.status === 400 && /asked of .{0,2}ca-alice/.test(r.text),
         '1f. another person\'s session is refused', r.text);
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/oauth2/consent.js' });
    const signinJs = await screen.call({ port: port, jar: {}, method: 'GET',
                                         path: '/authn/signin.js' });
    note(r.status === 200 && /javascript/.test(r.headers['content-type']) &&
         r.text.length > 1000 && r.text === signinJs.text &&
         r.text.indexOf('was not built') < 0,
         '1g. the script is served: the sign-in surface\'s bundle', r.status +
         ' ' + r.text.length);

    // --- 2. the index and the document ---------------------------------
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn-api' });
    const ops = (r.json && r.json.operations) || [];
    const one = function (method, mirrors) {
      return ops.filter(function (op) {
        return op.method === method && op.mirrors === mirrors &&
          op.path === '/authn-api/consent/{id}';
      }).length === 1;
    };
    note(r.status === 200 && one('GET', 'GET /oauth2/consent') &&
         one('POST', 'POST /oauth2/consent'),
         '2a. the index names the view and the answer and what each mirrors',
         JSON.stringify(ops.filter(function (op) {
           return /consent/.test(op.path);
         })));
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn-api/openapi.json' });
    const doc = r.json && r.json.paths &&
      r.json.paths['/authn-api/consent/{id}'];
    note(r.status === 200 && doc && doc.get && doc.post &&
         doc.post.requestBody,
         '2b. the OpenAPI document carries both, with the body',
         JSON.stringify(doc || {}).slice(0, 300));

    // --- 3. the view ---------------------------------------------------------
    let opened = await screen.openConsent({ port: port, jar: alice, at: at });
    const v = opened.view || {};
    note(opened.shell.status === 200 && opened.status === 200 &&
         v.consent === true && v.username === 'ca-alice' &&
         v.client && v.client.id === 'ca-client' &&
         v.client.name === 'CA <App>' && v.scopes.length === 2 &&
         v.scopes[1].permission.identifier === 'https://ca.example/write' &&
         v.authorizationDetails[0].resource === 'CA Bank' &&
         v.authorizationDetails[0].members[0].value === '100.00' &&
         v.already.length === 2 && v.already[1].global === true &&
         v.attribute === 'oauthConsent' && v.details.length === 2,
         '3a. the view names the application, the scopes, the detail member ' +
         'by member, what was already agreed and the request\'s parameters',
         JSON.stringify(v).slice(0, 500));
    note(v.limits && v.limits.length === 1 && v.limits[0].r === 0 &&
         v.limits[0].limits.amount === '100.00' &&
         v.limits[0].rows.map(function (row) {
           return row.member;
         }).join(',') === 'amount,currency,count',
         '3b. and the limits a person may lower, with their rows',
         JSON.stringify(v.limits));
    note(!/<[a-z]/.test(JSON.stringify(Object.assign({}, v,
                                                     { client: null }))),
         '3c. the view is facts and no markup', JSON.stringify(v)
           .slice(0, 300));
    note(opened.csrf && opened.csrf === websecurity.tokenFor(session(alice)) &&
         opened.json.uiLocales === 'fr',
         '3d. csrf is the token of the cookie\'s session, and the request\'s ' +
         'ui_locales is beside the view', opened.csrf + ' ' +
         opened.json.uiLocales);
    const bobs = await screen.openConsent({ port: port, jar: bob, at: at });
    note(bobs.status === 400 && !bobs.view &&
         /asked of .{0,2}ca-alice/.test(bobs.text) && codeFree(bobs.text),
         '3e. the view is refused to another person\'s session', bobs.text);

    // --- 4. the binding ------------------------------------------------------
    const answerPath = '/authn-api/consent/' + opened.id;
    const tryAct = function (o) {
      return screen.act(Object.assign({ port: port, jar: alice,
        opened: opened, path: answerPath, body: { action: 'allow' } }, o));
    };
    r = await tryAct({ contentType: 'application/x-www-form-urlencoded',
                       body: 'action=allow' });
    note(r.status === 415 && codeFree(r.text),
         '4a. a body that is not JSON is refused (415)', r.status);
    r = await tryAct({ origin: null });
    note(r.status === 403, '4b. no Origin is refused (403)', r.status);
    r = await tryAct({ origin: 'https://evil.example' });
    note(r.status === 403, '4c. another origin is refused (403)', r.status);
    r = await tryAct({ csrf: '' });
    note(r.status === 403, '4d. no token is refused (403)', r.status);
    r = await tryAct({ csrf: websecurity.tokenFor(session(bob)) });
    note(r.status === 403 && codeFree(r.text),
         '4e. another session\'s token is refused (403)', r.status);
    r = await tryAct({ path: '/authn-api/consent/not*an*id' });
    note(r.status === 400, '4f. a malformed id is refused', r.status);
    r = await tryAct({ body: { action: 'allow', scope: 'everything' } });
    note(r.status === 400 && codeFree(r.text),
         '4g. a field the operation does not take is refused', r.text);
    r = await tryAct({ body: { action: 'allow', lim_t0r0_admin: '1' } });
    note(r.status === 400, '4h. a limit control the page never draws is ' +
         'refused', r.text);
    r = await tryAct({ body: { action: 'maybe' } });
    note(r.status === 400, '4i. an answer that is neither allow nor deny ' +
         'is refused', r.text);
    // Bound to Bob's own session (his token), so it reaches the check that
    // matters: whose session this is.
    r = await screen.act({ port: port, jar: bob, opened: bobs,
                           csrf: websecurity.tokenFor(session(bob)),
                           path: answerPath, body: { action: 'allow' } });
    note(r.status === 400 && /signed in as .{0,2}ca-bob/.test(r.text) &&
         codeFree(r.text),
         '4j. another person\'s answer is refused, and nothing recorded',
         r.text);

    // --- 5. the answers ------------------------------------------------------
    r = await screen.answerConsent({ port: port, jar: alice, at: at,
      opened: opened, limits: { lim_t0r0_amount: '200.00' } });
    note(r.apiStatus === 400 && r.next === 'refused' &&
         /may only be lowered/.test(r.errors.join(' ')) &&
         codeFree(r.text) && !!consentScreen.pendingFor(opened.id),
         '5a. a raised limit is refused, and the consent kept', r.text);
    r = await screen.answerConsent({ port: port, jar: alice, at: at,
      opened: opened, limits: { lim_t0r0_amount: '50.00',
                                lim_t0r0_count: '5' } });
    const allowed = details.consumeConsent('ca-alice', 'ca-client',
                                           'ca-digest');
    note(r.apiStatus === 200 && r.next === 'redirect' &&
         r.location === RETURN && !consentScreen.pendingFor(opened.id) &&
         allowed && allowed.lowered &&
         allowed.lowered[0].limits.amount === '50.00',
         '5b. Allow with a lowered limit names the authorization request, ' +
         'records the detail as lowered, and spends the record', r.text +
         ' ' + JSON.stringify(allowed));
    r = await screen.answerConsent({ port: port, jar: alice, at: at,
                                     opened: opened });
    note(r.apiStatus === 400 && /already been answered/.test(r.text),
         '5c. a replay is refused', r.text);
    at = begin('ca-alice');
    r = await screen.answerConsent({ port: port, jar: alice, at: at,
                                     decision: 'deny' });
    note(r.next === 'redirect' && r.location.indexOf(RETURN + '&') === 0 &&
         /consent_error=access_denied/.test(r.location),
         '5d. Deny names the request with consent_error=access_denied',
         r.location);
    const rows = audit.list();
    note(rows.some(function (row) {
      return row.action === 'consent.grant' && row.actor === 'ca-alice';
    }) && rows.some(function (row) {
      return row.action === 'consent.deny' && row.actor === 'ca-alice' &&
        row.errorCode === 'STS-OAUTH-0152';
    }), '5e. both are audited as the form\'s answers were');

    // --- 6. the id in the audit log ------------------------------------------
    const http6 = rows.filter(function (row) {
      return /\/authn-api\/consent\//.test(String(row.target || '')) ||
        /\/oauth2\/consent/.test(String(row.target || ''));
    });
    note(http6.length > 0 && http6.every(function (row) {
      return String(row.target).indexOf(opened.id) < 0;
    }), '6. an audit row names the operation and never the id',
         http6.slice(0, 3).map(function (row) {
           return row.target;
         }).join(' '));

    // --- 7. the old form post ------------------------------------------------
    at = begin('ca-alice');
    r = await screen.call({ port: port, jar: alice, method: 'POST',
      path: '/oauth2/consent', headers: { 'content-type':
        'application/x-www-form-urlencoded' },
      body: 'consent_id=' + encodeURIComponent(at.split('consent=')[1]) +
            '&action=allow' });
    note(r.status === 404 && !!consentScreen.pendingFor(
      decodeURIComponent(at.split('consent=')[1])),
         '7. POST /oauth2/consent is gone', r.status);

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ca-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  // THE OLD DEFAULT, SET EXPLICITLY (#751): `authn.multipleAccounts` is on
  // by default since 2026-10-20, and what this file holds is a browser
  // with ONE session — a sign-in's answer with no account ticket on it, a
  // change of person ending the session it replaced.
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  CA_ROOT: ROOT, CA_OUT: out,
                                  STS_AUTHN_MULTIPLE_ACCOUNTS: 'false' }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'authn_consent_api',
  describe: 'the OAuth consent screen is a page of the sign-in surface ' +
            'over /authn-api/consent: the shell and its three checks, the ' +
            'view, the CSRF binding, Allow with lowered limits and Deny, and ' +
            'the consent id never in an audit row (#576)',
  run: run
};
