// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/gnap_interact_api.js
// ===========================================================================
// GNAP'S INTERACTION PAGES ARE A STATIC SURFACE OVER `/gnap-api` (#578).
//
// The whole stack in a child process, over HTTP on 127.0.0.1, with grants
// waiting for interaction made in the store as the engine makes them:
//
//   1. THE SHELL: `/gnap/code` and the approval page answer the shell — the
//      bundle, the card, the `<noscript>`, no form — with a policy that
//      keeps `frame-ancestors`, and mint the `sts_session` arrival cookie.
//      The bundle is served.
//   2. THE INDEX lists the four operations and the page or control each
//      mirrors.
//   3. THE PROTOCOL'S ANSWERS ARE UNCHANGED: a start link answers its 303
//      to the approval page and works once; a spent or unknown link is a
//      400 page (now the shell carrying the refusal, no code in it); the
//      approval page sends a browser with no session to the sign-in screen;
//      a cancelled sign-in enacts the redirect finish with `hash` and
//      `interact_ref`, the hash RFC 9635 section 4.2.3's.
//   4. THE VIEW: facts and no words, and `csrf`; with no session it sends
//      the browser back to the page.
//   5. THE BINDING of an act: JSON, an Origin of this service, the token;
//      no refusal carries an error code; a malformed body and a limit
//      control this page does not draw are refused.
//   6. THE ANSWER: the rights left ticked approved, and `location` the
//      client's finish URI with the hash and interact_ref the 303 named; a
//      second answer refused; a denial with no finish answers the done
//      view; a cancelled sign-in with no finish is the shell carrying it.
//   7. THE USER CODE, case-folded and spent once, names the approval page.
//   8. THE OLD FORM POSTS ARE GONE.
//   9. THE COMPILED RENDERER draws the view the API answered.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'gnap_interact_api',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.GIA_ROOT;
  const OUT = process.env.GIA_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const store = require(ROOT_DIR + '/gnap/gnap_store');
    const grants = require(ROOT_DIR + '/gnap/gnap_grants');
    const interact = require(ROOT_DIR + '/gnap/gnap_interact');
    const applications = require(ROOT_DIR + '/common/applications');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const SUFFIX = crypto.randomBytes(3).toString('hex');
    const CLIENT = 'gia-client-' + SUFFIX;
    const FINISH = 'https://client.gia.test/cb';
    const codeFree = function (text) {
      return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ''));
    };
    ldap.createUser('gia-alice', { invent: false });
    applications.createApplication({ identifier: CLIENT,
      kind: 'gnap-client', protocols: ['gnap'], fields: {} });

    // A grant waiting for interaction, as `startInteraction()` leaves one:
    // a redirect start link, a user code, and the finish asked for.
    // `unstarted` leaves it as a start mode would find it; every other grant
    // has had its interaction started, as one the approval page is asked
    // about always has.
    const made = function (finish, unstarted) {
      const now = Math.floor(Date.now() / 1000);
      const grant = store.newGrant({
        as: 'default', grantEndpoint: ORIGIN + '/gnap',
        client: { identifier: CLIENT, key: null, proof: 'httpsig',
                  display: { name: 'GIA <client>', declared: ['name'] } },
        request: { tokens: [{ label: '', bearer: false, access: [
          'gia-ref-' + SUFFIX, { type: 'gia-type', actions: ['read'] }] }],
                   multiple: false, subject: null, interact: null },
        ro: null, decision: null, delivered: false, polls: 0,
        approval: 'pending', grantExpiresAt: now + 3600,
        subjectAuthorizedBy: null, finalization: null, requirement: null,
        ownerApproval: null });
      const rid = store.handle(18);
      const code = 'GIA' + crypto.randomBytes(3).toString('hex')
        .toUpperCase().replace(/[^A-Z2-9]/g, 'K');
      const interaction = {
        modes: { redirect: { id: rid, used: false },
                 user_code: { code: code, used: false } },
        finish: finish === undefined
          ? { method: 'redirect', uri: FINISH,
              nonce: 'gia-cn-' + SUFFIX } : finish,
        serverNonce: 'gia-sn-' + crypto.randomBytes(6).toString('hex'),
        expiresAt: now + 600, started: unstarted ? null : 'redirect',
        decided: false,
        decision: null, interactRef: null, approvalId: store.handle(18) };
      store.putInteraction('approve:' + interaction.approvalId, grant.id);
      store.putInteraction('redirect:' + rid, grant.id);
      store.putUserCode(code, grant.id);
      grant.interaction = interaction;
      grant.state = store.STATE.PENDING;
      grant.expiresAt = interaction.expiresAt;
      store.saveGrant(grant, 'made by the test');
      return { grant: grant, rid: rid, code: code,
               approve: '/gnap/approve/' + interaction.approvalId,
               api: '/gnap-api/approve/' + interaction.approvalId };
    };
    const get = function (jar, p, headers) {
      return screen.call({ port: port, jar: jar, method: 'GET', path: p,
                           headers: headers || {} });
    };
    const send = function (jar, p, body, o) {
      const opts = o || {};
      const headers = { accept: 'application/json',
        'content-type': opts.type || 'application/json' };
      if (opts.origin !== null) {
        headers.origin = opts.origin || ORIGIN;
      }
      if (opts.csrf) {
        headers['x-csrf-token'] = opts.csrf;
      }
      return screen.call({ port: port, jar: jar, method: 'POST', path: p,
        headers: headers,
        body: typeof body === 'string' ? body : JSON.stringify(body) });
    };
    const isShell = function (r) {
      return r.text.indexOf('<script src="/gnap/interaction.js" defer>' +
                            '</script>') > 0 &&
        r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
        r.text.indexOf('<noscript>') > 0 && !/<form/.test(r.text);
    };
    const stateOf = function (r) {
      const m = /data-sts-state="([^"]*)"/.exec(r.text);
      if (!m) {
        return null;
      }
      return JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&#39;/g, '\'')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&'));
    };

    // --- 1. the shell --------------------------------------------------------
    const codeJar = {};
    let r = await get(codeJar, '/gnap/code');
    const csp = String(r.headers['content-security-policy'] || '');
    note(r.status === 200 && isShell(r) && !stateOf(r) &&
         /no-store/.test(String(r.headers['cache-control'])),
         '1a. /gnap/code answers the shell: the bundle, the card, the ' +
         'notice, and no form', r.status + ' ' + r.text.slice(0, 600));
    note(/frame-ancestors 'none'/.test(csp) &&
         /script-src 'self'(;|$)/.test(csp) &&
         /connect-src 'self'/.test(csp) && !/unsafe-inline/.test(csp),
         '1b. its policy keeps frame-ancestors and allows script and API ' +
         'from \'self\' only', csp);
    note(!!codeJar.sts_session,
         '1c. and it mints the arrival cookie for a browser without one',
         JSON.stringify(Object.keys(codeJar)));
    r = await get({}, '/gnap/interaction.js');
    note(r.status === 200 && /javascript/.test(r.headers['content-type']) &&
         r.text.length > 1000 && r.text.indexOf('was not built') < 0,
         '1d. the bundle is served, built', r.status + ' ' + r.text.length);

    // --- 2. the index --------------------------------------------------------
    r = await get({}, '/gnap-api');
    const ops = (r.json && r.json.operations) || [];
    note(r.status === 200 && ['GET /gnap/code', 'POST /gnap/code',
      'GET /gnap/approve/{id}', 'POST /gnap/approve/{id}']
      .every(function (m) {
        return ops.filter(function (op) {
          return op.mirrors === m;
        }).length === 1;
      }) && JSON.stringify(interact.operations()) ===
        JSON.stringify(ops),
         '2. the index lists every operation and what each mirrors',
         JSON.stringify(ops));

    // --- 3. the protocol's answers -------------------------------------------
    const one = made(undefined, true);
    const jar = {};
    r = await get(jar, '/gnap/interact/' + one.rid);
    note(r.status === 303 && r.headers.location === one.approve &&
         /no-store/.test(String(r.headers['cache-control'])),
         '3a. a start link answers its 303 to the approval page, as before',
         r.status + ' ' + r.headers.location);
    r = await get(jar, '/gnap/interact/' + one.rid);
    const spent = stateOf(r);
    note(r.status === 400 && isShell(r) && spent &&
         spent.view.kind === 'problem' && codeFree(r.text),
         '3b. it works once: again, a 400 page — the shell carrying the ' +
         'refusal, and no error code in it', r.status + ' ' +
         JSON.stringify(spent));
    r = await get(jar, '/gnap/interact/nosuchlinkatall');
    note(r.status === 400 && stateOf(r) &&
         stateOf(r).view.kind === 'problem',
         '3c. an unknown link is the same 400 page', r.status);
    r = await get(jar, one.approve);
    note(r.status === 303 && /\/authn\/login\?authn=/.test(
      r.headers.location),
         '3d. the approval page sends a browser with no session to the ' +
         'sign-in screen', r.status + ' ' + r.headers.location);
    const signIn = r.headers.location;

    // A cancelled sign-in on another grant: the finish is enacted.
    const cancelled = made();
    r = await get({}, cancelled.approve + '?authn_error=access_denied');
    const back = r.status === 303 ? new URL(r.headers.location) : null;
    const cancelHash = back ? grants.interactionHash(
      cancelled.grant.interaction.finish.nonce,
      cancelled.grant.interaction.serverNonce,
      back.searchParams.get('interact_ref'), ORIGIN + '/gnap') : '';
    note(back && back.origin + back.pathname === FINISH &&
         back.searchParams.get('hash') === cancelHash &&
         store.getGrant(cancelled.grant.id).decision.approved === false,
         '3e. a cancelled sign-in enacts the redirect finish with hash and ' +
         'interact_ref (section 4.2.3), as before', r.status + ' ' +
         r.headers.location);

    // --- 4. the view ---------------------------------------------------------
    r = await get({}, one.api);
    note(r.status === 200 && r.json && r.json.next === 'page' &&
         r.json.location === one.approve,
         '4a. with no session the view sends the browser back to the page',
         r.status + ' ' + r.text.slice(0, 300));
    const signedIn = await screen.submit({ port: port, jar: jar, at: signIn,
      fields: { action: 'login', username: 'gia-alice', password: 'x' } });
    note(signedIn.next === 'redirect' &&
         signedIn.location.indexOf(one.approve) >= 0,
         '4b. the sign-in returns to the approval page',
         signedIn.next + ' ' + signedIn.location);
    r = await get(jar, one.approve);
    note(r.status === 200 && isShell(r) && !stateOf(r),
         '4c. signed in, the approval page is the shell, which fetches its ' +
         'view', r.status + ' ' + r.text.slice(0, 300));
    r = await get(jar, one.api);
    const view = r.json && r.json.view;
    const csrf = r.json && r.json.csrf;
    note(r.status === 200 && view && view.kind === 'approve' &&
         view.username === 'gia-alice' && view.client.identifier === CLIENT &&
         view.client.nameDeclared === true && !view.client.logo &&
         view.tokens[0].rights.map(function (x) {
           return x.field;
         }).join() === 't0r0,t0r1' &&
         view.tokens[0].rights[0].right.reference === 'gia-ref-' + SUFFIX &&
         view.tokens[0].rights[1].right.type === 'gia-type' &&
         view.finish.method === 'redirect' && !!csrf &&
         !/Allow access/.test(r.text),
         '4d. the view is facts and no words, with its csrf',
         r.text.slice(0, 600));

    // --- 5. the binding ------------------------------------------------------
    r = await send(jar, one.api, 'action=allow', {
      type: 'application/x-www-form-urlencoded', csrf: csrf });
    const notJson = r;
    r = await send(jar, one.api, { action: 'allow' }, { origin: null,
                                                       csrf: csrf });
    const noOrigin = r;
    r = await send(jar, one.api, { action: 'allow' },
                   { origin: 'https://evil.example', csrf: csrf });
    const otherOrigin = r;
    r = await send(jar, one.api, { action: 'allow' }, { csrf: 'nottoken' });
    const badToken = r;
    note(notJson.status === 415 && noOrigin.status === 403 &&
         otherOrigin.status === 403 && badToken.status === 403 &&
         [notJson, noOrigin, otherOrigin, badToken].every(function (x) {
           return x.json && x.json.ok === false && codeFree(x.text);
         }) && store.getGrant(one.grant.id).interaction.decided === false,
         '5a. an act needs JSON, an Origin of this service and the token; ' +
         'none of the refusals carries a code, and nothing is decided',
         [notJson, noOrigin, otherOrigin, badToken].map(function (x) {
           return x.status;
         }).join());
    r = await send(jar, one.api, { action: 'allow', extra: 'x' },
                   { csrf: csrf });
    const unknownField = r;
    r = await send(jar, one.api, { action: 'allow', lim_t0r0_amount: ['1',
      { x: 1 }] }, { csrf: csrf });
    note(unknownField.status === 400 && r.status === 400 &&
         codeFree(unknownField.text) && codeFree(r.text) &&
         store.getGrant(one.grant.id).interaction.decided === false,
         '5b. a field the act does not take, and a limit control it does ' +
         'not draw, are refused', unknownField.status + ' ' + r.status);

    // --- 6. the answer -------------------------------------------------------
    r = await send(jar, one.api, { action: 'allow', right: 't0r1' },
                   { csrf: csrf });
    const to = r.json && r.json.location ? new URL(r.json.location) : null;
    const after = store.getGrant(one.grant.id);
    const expected = to ? grants.interactionHash(
      one.grant.interaction.finish.nonce, one.grant.interaction.serverNonce,
      to.searchParams.get('interact_ref'), ORIGIN + '/gnap') : '';
    note(r.status === 200 && r.json.ok && r.json.next === 'redirect' && to &&
         to.origin + to.pathname === FINISH &&
         to.searchParams.get('hash') === expected &&
         to.searchParams.get('interact_ref') ===
           after.interaction.interactRef &&
         after.decision && after.decision.approved === true,
         '6a. Allow answers the client\'s finish URI with the hash and ' +
         'interact_ref section 4.2.3 defines, the address the 303 named',
         r.status + ' ' + r.text.slice(0, 400));
    const kept = JSON.stringify((after.decision && after.decision.tokens) ||
                                after.approved || null);
    note(kept.indexOf('gia-type') >= 0 &&
         kept.indexOf('gia-ref-' + SUFFIX) < 0,
         '6b. only the right left ticked is approved', kept.slice(0, 400));
    r = await send(jar, one.api, { action: 'allow', right: 't0r1' },
                   { csrf: csrf });
    note(r.status === 400 && r.json && r.json.ok === false &&
         r.json.view && r.json.view.kind === 'problem' && codeFree(r.text),
         '6c. a second answer is refused, with a view the page draws',
         r.status + ' ' + r.text.slice(0, 300));
    const quiet = made(null);
    r = await get(jar, quiet.api);
    const quietCsrf = r.json && r.json.csrf;
    r = await send(jar, quiet.api, { action: 'deny' }, { csrf: quietCsrf });
    note(r.status === 200 && r.json.next === 'done' &&
         r.json.view.kind === 'done' && r.json.view.approved === false &&
         r.json.view.pushed === null && !r.json.location,
         '6d. Deny with no finish method answers the done view',
         r.status + ' ' + r.text.slice(0, 300));
    const quietCancel = made(null);
    r = await get({}, quietCancel.approve + '?authn_error=access_denied');
    note(r.status === 200 && stateOf(r) && stateOf(r).view.kind === 'done' &&
         stateOf(r).view.approved === false,
         '6e. a cancelled sign-in with no finish is the shell carrying the ' +
         'done view', r.status + ' ' + r.text.slice(0, 300));

    // --- 7. the user code ----------------------------------------------------
    const coded = made(undefined, true);
    r = await get(codeJar, '/gnap-api/code');
    const codeCsrf = r.json && r.json.csrf;
    note(r.status === 200 && r.json.view.kind === 'code' && !!codeCsrf,
         '7a. the code page\'s view carries its csrf', r.text.slice(0, 200));
    const typed = coded.code.slice(0, 3).toLowerCase() + '-' +
                  coded.code.slice(3);
    r = await send(codeJar, '/gnap-api/code', { code: typed },
                   { csrf: codeCsrf });
    note(r.status === 200 && r.json.next === 'page' &&
         r.json.location === coded.approve &&
         store.getGrant(coded.grant.id).interaction.started === 'user_code',
         '7b. a code typed in either case, with a dash, names the approval ' +
         'page and starts the interaction', r.status + ' ' + r.text);
    r = await send(codeJar, '/gnap-api/code', { code: coded.code },
                   { csrf: codeCsrf });
    note(r.status === 400 && r.json.ok === false && codeFree(r.text),
         '7c. and it is spent: a second time it is refused',
         r.status + ' ' + r.text);
    r = await send(codeJar, '/gnap-api/code', { code: coded.code });
    note(r.status === 403, '7d. the code act is bound as every act is',
         r.status);

    // --- 8. the old form posts -----------------------------------------------
    r = await screen.call({ port: port, jar: jar, method: 'POST',
      path: '/gnap/code', headers: { 'content-type':
        'application/x-www-form-urlencoded' }, body: 'code=X' });
    const oldCode = r.status;
    r = await screen.call({ port: port, jar: jar, method: 'POST',
      path: quietCancel.approve, headers: { 'content-type':
        'application/x-www-form-urlencoded' }, body: 'action=allow' });
    note(oldCode === 404 && r.status === 404,
         '8. POST /gnap/code and POST /gnap/approve/{id} are gone',
         oldCode + ' ' + r.status);

    // --- 9. the compiled renderer draws the view -----------------------------
    const Pages = require(ROOT_DIR + '/gnap/web_gnap_interact_pages');
    const messages = require(ROOT_DIR + '/common/web_messages');
    const own = JSON.parse(fs.readFileSync(ROOT_DIR +
                                           '/common/locales/gnap/en.json'));
    const flat = {};
    Object.keys(own).forEach(function (k) {
      flat['gnap.' + k] = own[k];
    });
    const t = messages.WebTranslator.fromData({ catalogs: { en: flat },
      negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                    direction: 'ltr', matched: true } });
    const drawn = Pages.render(one.approve, view, { t: t, query: {} });
    note(/Allow access\?/.test(drawn) &&
         /name="right" value="t0r0" checked/.test(drawn) &&
         /name="right" value="t0r1" checked/.test(drawn) &&
         drawn.indexOf('action="' + one.approve + '"') > 0 &&
         /as it describes itself/.test(drawn),
         '9. the compiled renderer draws the approval page from the view ' +
         'the API answered', drawn.slice(0, 400));

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
  const out = path.join(os.tmpdir(), 'gia-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  GIA_ROOT: ROOT, GIA_OUT: out }),
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
  name: 'gnap_interact_api',
  describe: 'GNAP\'s interaction pages are a static surface over /gnap-api: ' +
            'the shell, the protocol\'s answers unchanged, the view, the ' +
            'CSRF binding, the answer and its finish, the user code (#578)',
  run: run
};
