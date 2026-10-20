// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/authn_api_wallet.js — THE WALLET SIGN-IN'S PAGES ARE ROUTES OF THE
// SIGN-IN SURFACE, AND ITS ACTS ARE `/authn-api/wallet` (#574).
//
// The whole stack in a child process on `tests/wallet_kit.js`'s in-process
// server:
//
//   1. THE INDEX AND THE OPENAPI DOCUMENT list the five wallet operations,
//      each with the page it is the door of, and the transaction's `state`
//      as a path parameter.
//   2. THE SHELLS: `/authn/wallet` and `/authn/wallet/wait` answer the
//      sign-in surface's document — its one script, the `<noscript>`, no
//      form, `frame-ancestors` kept — and mint the `sts_session` arrival
//      cookie; `/authn/wallet.js` and the old `POST /authn/wallet/dc-api`
//      are gone.
//   3. THE START VIEW creates nothing: no binding cookie and no
//      transaction; it answers what is being started and the CSRF token, or
//      the refusal a start would meet with its view.
//   4. THE BINDING of every act: JSON, an Origin of this service, the token
//      of the browser's session; a field the operation does not take is
//      refused; NO ANSWER CARRIES AN ERROR CODE.
//   5. THE FLOW: the start sets the binding cookie and names the wait
//      page; the wait view; the poll answers `wait` until the wallet
//      answers; then the sign-in, the session cookie set on THAT answer and
//      no earlier one, `next: redirect` back to the request; a second
//      collection refused.
//   6. THE BEARER IDS ARE NEVER RECORDED: the state in a path and the
//      pending id, step, state and response_code in a query are redacted in
//      every audit row and in the call log's path and query.
//   7. THE ENROLMENT AND THE SECOND FACTOR: an enrolment with no session is
//      refused, and a start naming a step nobody holds.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'authn_api_wallet',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    const m = w.m;
    try {
      await sections(w, note, m);
    } catch (e) {
      note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  // No answer here may carry an error code: codes are recorded, never sent.
  function codeFree(r) {
    return !/STS-[A-Z]+-\d{4}/.test(String(r.text || ''));
  }

  async function sections(w, note, m) {
    const audit = require(ROOT + '/common/audit');
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('aw-alice', { invent: false });
    });
    // The Client Identifier a sign-in signs under, the audience a holder
    // proves for: x509_hash's since 2026-10-12 (`w.signInAudience()`).
    const aud = await w.signInAudience();

    // ==================================================================
    // 1. THE INDEX AND THE OPENAPI DOCUMENT
    // ==================================================================
    const index = await w.request('GET', '/authn-api');
    const ops = ((index.json || {}).operations || []).filter(function (op) {
      return /^\/authn-api\/wallet/.test(op.path);
    });
    const byId = {};
    ops.forEach(function (op) {
      byId[op.operationId] = op;
    });
    note(ops.length === 5 &&
         byId.getWalletStart && byId.getWalletStart.method === 'GET' &&
         byId.getWalletStart.mirrors === 'GET /authn/wallet' &&
         byId.startWalletSignIn && byId.startWalletSignIn.method === 'POST' &&
         byId.getWalletWait &&
         byId.getWalletWait.path === '/authn-api/wallet/{state}' &&
         byId.getWalletWait.mirrors === 'GET /authn/wallet/wait' &&
         byId.walletStatus &&
         byId.walletStatus.path === '/authn-api/wallet/{state}/status' &&
         byId.answerWalletDcApi &&
         byId.answerWalletDcApi.path === '/authn-api/wallet/{state}/dc-api',
         '1a. the index lists the five wallet operations and the page each ' +
         'is the door of', JSON.stringify(ops.map(function (op) {
           return op.method + ' ' + op.path;
         })));
    const doc = (await w.request('GET', '/authn-api/openapi.json')).json || {};
    const statusOp = ((doc.paths || {})['/authn-api/wallet/{state}/status'] ||
                      {}).post || {};
    note(statusOp.operationId === 'walletStatus' &&
         (statusOp.parameters || []).some(function (p) {
           return p.name === 'state' && p.in === 'path';
         }) && !!statusOp.requestBody &&
         ((doc.paths || {})['/authn-api/wallet'] || {}).get &&
         ((doc.paths || {})['/authn-api/wallet'] || {}).post,
         '1b. the OpenAPI document has them, the state a path parameter and ' +
         'each act\'s body a schema', JSON.stringify(statusOp.parameters));

    // ==================================================================
    // 2. THE SHELLS
    // ==================================================================
    const shellWho = w.browser();
    const shellId = w.pendingSignIn();
    const shell = await w.request('GET', '/authn/wallet?authn=' + shellId,
                                  { browser: shellWho });
    const csp = String(shell.headers['content-security-policy'] || '');
    note(shell.status === 200 &&
         /<script src="\/authn\/signin\.js"/.test(shell.text) &&
         /<noscript>/.test(shell.text) && !/<form/.test(shell.text) &&
         /script-src 'self'/.test(csp) &&
         /frame-ancestors 'none'/.test(csp) &&
         !!shellWho.cookies.sts_session &&
         !shellWho.cookies.sts_wallet_binding,
         '2a. /authn/wallet answers the sign-in surface\'s shell, mints the ' +
         'arrival cookie and starts nothing', shell.status + ' ' + csp);
    const waitShell = await w.request('GET', '/authn/wallet/wait?authn=x&' +
                                      'state=y', { browser: w.browser() });
    note(waitShell.status === 200 &&
         /<script src="\/authn\/signin\.js"/.test(waitShell.text),
         '2b. /authn/wallet/wait answers the same shell', waitShell.status);
    const oldScript = await w.request('GET', '/authn/wallet.js');
    const oldForm = await w.request('POST', '/authn/wallet/dc-api',
                                    { form: { authn: 'x', state: 'y' } });
    note(oldScript.status === 404 && oldForm.status === 404,
         '2c. /authn/wallet.js and the form POST /authn/wallet/dc-api are ' +
         'gone', oldScript.status + ' ' + oldForm.status);

    // ==================================================================
    // 3. THE START VIEW CREATES NOTHING
    // ==================================================================
    const viewWho = w.browser();
    const viewId = w.pendingSignIn();
    await w.request('GET', '/authn/wallet?authn=' + viewId,
                    { browser: viewWho });
    const opened = await w.request('GET', '/authn-api/wallet?authn=' + viewId,
                                   { browser: viewWho });
    note(opened.status === 200 && opened.json &&
         opened.json.view && opened.json.view.wallet === 'start' &&
         opened.json.view.kind === 'wallet' &&
         typeof opened.json.csrf === 'string' && opened.json.csrf.length > 0 &&
         !viewWho.cookies.sts_wallet_binding &&
         !opened.setCookie.some(function (c) {
           return /^sts_wallet_binding=/.test(c);
         }),
         '3a. the start view answers what is being started and the CSRF ' +
         'token, and sets no binding cookie', opened.status);
    const nothing = await w.request('GET', '/authn-api/wallet?authn=' +
                                    'nothing-pending', { browser: viewWho });
    note(nothing.status === 400 && nothing.code === 'STS-VC-0053' &&
         nothing.json && nothing.json.next === 'refused' &&
         nothing.json.view && nothing.json.view.wallet === 'refused' &&
         codeFree(nothing),
         '3b. a start naming nothing pending is refused with a view, ' +
         'STS-VC-0053, and no code in the answer',
         nothing.status + ' ' + nothing.code);

    // ==================================================================
    // 4. THE BINDING OF AN ACT
    // ==================================================================
    const csrf = opened.json.csrf;
    const asForm = await w.request('POST', '/authn-api/wallet', {
      browser: viewWho, headers: { origin: w.origin, 'x-csrf-token': csrf },
      form: { authn: viewId } });
    note(asForm.status === 415 && asForm.code === 'STS-AUTHN-0325' &&
         codeFree(asForm),
         '4a. a form body is refused, STS-AUTHN-0325',
         asForm.status + ' ' + asForm.code);
    const noOrigin = await w.act(viewWho, '/authn-api/wallet',
                                 { authn: viewId },
                                 { origin: null, csrf: csrf });
    const foreign = await w.act(viewWho, '/authn-api/wallet',
                                { authn: viewId },
                                { origin: 'https://attacker.example',
                                  csrf: csrf });
    note(noOrigin.status === 403 && noOrigin.code === 'STS-AUTHN-0326' &&
         foreign.status === 403 && foreign.code === 'STS-AUTHN-0326',
         '4b. no Origin, or another site\'s, is refused, STS-AUTHN-0326',
         noOrigin.status + ' ' + foreign.status);
    const noToken = await w.act(viewWho, '/authn-api/wallet',
                                { authn: viewId }, { csrf: '' });
    const wrongToken = await w.act(viewWho, '/authn-api/wallet',
                                   { authn: viewId }, { csrf: 'x' + csrf });
    note(noToken.status === 403 && noToken.code === 'STS-AUTHN-0327' &&
         wrongToken.status === 403 && wrongToken.code === 'STS-AUTHN-0327' &&
         !viewWho.cookies.sts_wallet_binding,
         '4c. no CSRF token, or another browser\'s, is refused, ' +
         'STS-AUTHN-0327, and nothing is started',
         noToken.status + ' ' + wrongToken.status);
    const extra = await w.act(viewWho, '/authn-api/wallet',
                              { authn: viewId, returnTo: '/elsewhere' },
                              { csrf: csrf });
    note(extra.status === 400 && extra.code === 'STS-VC-0069' &&
         codeFree(extra),
         '4d. a field the operation does not take — a returnTo — is ' +
         'refused, STS-VC-0069', extra.status + ' ' + extra.code);

    // ==================================================================
    // 5. THE FLOW
    // ==================================================================
    const holder = w.holderKey();
    const issued = await w.issue('aw-alice', holder);
    note(!!issued.credential, '5a. a credential is issued to aw-alice',
         issued.error);
    const who = w.browser();
    const s = await w.start(who, w.pendingSignIn());
    const arrival = who.cookies.sts_session;
    note(s.started.status === 303 && !!who.cookies.sts_wallet_binding &&
         /^\/authn\/wallet\/wait\?authn=[^&]+&state=/.test(s.waitPath) &&
         !s.started.answer.setCookie.some(function (c) {
           return /^sts_session=/.test(c);
         }),
         '5b. the start sets the binding cookie, names the wait page, and ' +
         'sets no session cookie', s.started.status + ' ' + s.waitPath);
    note(s.waiting.status === 200 && s.view && s.view.wallet === 'wait' &&
         s.view.state === s.state && !!s.dcRequest && !!s.walletUrl &&
         s.view.pollSeconds > 0 && codeFree(s.waiting),
         '5c. the wait view carries the request, the same-device link and ' +
         'the poll\'s interval', s.waiting.status);
    const early = await w.collect(who, s);
    note(early.status === 200 && early.json && early.json.next === 'wait' &&
         early.json.expiresIn > 0 && who.cookies.sts_session === arrival,
         '5d. the poll answers wait while the wallet has not answered, and ' +
         'changes no session', early.status + ' ' + early.text);
    await w.respond(s, w.presentSdJwt(issued.credential, holder,
                                      s.requestObject.nonce, aud));
    const done = await w.collect(who, s);
    const session = w.sessionOf(who);
    note(done.status === 303 && done.headers.location === '/wsi/after' &&
         done.json.next === 'redirect' && w.sessionCookie(done) &&
         session && session.user.username === 'aw-alice' &&
         who.cookies.sts_session !== arrival,
         '5e. once the wallet has answered the poll signs the browser in: ' +
         'the session cookie on THAT answer, next: redirect back to the ' +
         'request', done.status + ' ' + done.text);
    await w.refreshCsrf(who);
    const again = await w.collect(who, s);
    note(again.status === 400 && again.code === 'STS-VC-0062' &&
         !w.sessionCookie(again) && codeFree(again),
         '5f. and a second collection is refused, STS-VC-0062',
         again.status + ' ' + again.code);

    // ==================================================================
    // 6. THE BEARER IDS ARE NEVER RECORDED
    // ==================================================================
    const rows = audit.list().filter(function (row) {
      return /\/authn-api\/wallet|\/authn\/wallet/.test(String(row.target ||
                                                               ''));
    });
    const leaked = rows.filter(function (row) {
      const text = JSON.stringify([row.target, row.summary,
                                   row.detail && row.detail.query]);
      return text.indexOf(s.state) >= 0 || text.indexOf(s.authn) >= 0;
    });
    note(rows.length > 0 && leaked.length === 0,
         '6a. no audit row of the wallet\'s pages or operations names the ' +
         'state or the pending id', rows.length + ' rows, ' +
         leaked.map(function (row) {
           return row.target;
         }).join(' '));
    note(audit.redactedPath('/authn-api/wallet/abc/status') ===
           '/authn-api/wallet/(redacted)/status' &&
         audit.redactedPath('/authn/wallet/wait?authn=a&state=b&mfa=c&' +
                            'response_code=d&qr=1') ===
           '/authn/wallet/wait?authn=(redacted)&state=(redacted)&' +
           'mfa=(redacted)&response_code=(redacted)&qr=1' &&
         JSON.stringify(audit.redactedQuery({ authn: 'a', qr: '1' })) ===
           JSON.stringify({ authn: '(redacted)', qr: '1' }),
         '6b. the call log\'s path and query carry none of them either');

    // ==================================================================
    // 7. THE ENROLMENT AND THE SECOND FACTOR
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.signInSelfIssued', 'true');
    });
    const enrolWho = w.browser();
    await w.request('GET', '/authn/wallet?siop=1&enrol=1',
                    { browser: enrolWho });
    const enrol = await w.request('GET', '/authn-api/wallet?siop=1&enrol=1',
                                  { browser: enrolWho });
    note(enrol.status === 403 && enrol.code === 'STS-VC-0093' &&
         enrol.json && enrol.json.view &&
         enrol.json.view.backKind === 'portal',
         '7a. an enrolment from a browser holding no sign-on session is ' +
         'refused, STS-VC-0093, back to the portal',
         enrol.status + ' ' + enrol.code);
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.signInSelfIssued');
    });
    const step = await w.start(w.browser(), null, { mfa: 'no-such-step' });
    note(step.started.status === 400 && step.started.code === 'STS-VC-0053',
         '7b. a start naming a second-factor step nobody holds is refused, ' +
         'STS-VC-0053', step.started.status + ' ' + step.started.code);
  }
}

async function run(t) {
  log.debug("Entering run().");
  // THE OLD DEFAULT, SET EXPLICITLY (#751): the poll's answer is held to a
  // redirect with no account ticket on it, a browser with one session.
  kit.inAChild(t, childMain, 'authn-api-wallet',
               { STS_AUTHN_MULTIPLE_ACCOUNTS: 'false' });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'the wallet sign-in over /authn-api (#574)',
  describe: 'the shells, the start view that creates nothing, the binding ' +
            'of every act, the poll that finishes the sign-in, and no ' +
            'bearer id in the audit log',
  run: run
};
