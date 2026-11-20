// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/logout_api.js
// ===========================================================================
// THE SIGN-OUT IS A STATIC SURFACE OVER `/authn-api/logout` (#577).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. THE SHELL: a browser's `GET /logout` answers the shell — the bundle,
//      the sign-out's stylesheet, the `<noscript>`, no form — with a policy
//      that keeps `frame-ancestors`; a browser with no session is still sent
//      to sign in; `?username=` (naming open in development) mints the
//      arrival cookie for a browser holding none. The bundle and the
//      stylesheet are served, the stylesheet being the rules the
//      server-drawn document carries inline.
//   2. THE INDEX AND THE OPENAPI DOCUMENT list both operations and the page
//      or form each mirrors.
//   3. THE VIEW: the inventory as facts, no credential in a row, and `csrf`
//      — the token of the cookie's session; a name, where naming is open;
//      a name refused (403) and nobody (401) where it is not.
//   4. THE BINDING of the act: JSON, an Origin of this service, the token,
//      a closed body.
//   5. A SIGN-OUT WITH NOTHING TO FAN OUT answers the result's view, and
//      clears the cookie where the browser's own session ended.
//   6. A SIGN-OUT THAT FANS OUT answers the signed-out document's form; the
//      document is the server-drawn page, with the fan-out `fanOutOf()`
//      draws — the function `/federation/slo` shares — and its policy;
//      refused without an Origin, from another, and with a result this
//      service did not make; it mints no cookie.
//   7. THE JSON DOOR at `GET|POST /logout` is unchanged, and a form posted
//      there ends nothing and is sent to the page.
//   8. No answer carries an error code.
//   9. ENDING ANOTHER SESSION NEEDS A RECENT SIGN-IN AT THIS DOOR TOO (#1521,
//      #1577), as at `POST /logout`: refused 403 with a `reauthenticate` view
//      naming where to sign in again, nothing ended; signing yourself out
//      everywhere is never asked; and after that sign-in the same act ends
//      the other session.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'logout_api',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.LA_ROOT;
  const OUT = process.env.LA_OUT;
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
    const config = require(ROOT_DIR + '/common/config');
    const websecurity = require(ROOT_DIR + '/common/websecurity');
    const logout = require(ROOT_DIR + '/logout/logout');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const origin = 'http://127.0.0.1:' + port;
    const codeFree = function (text) {
      return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ''));
    };
    const sessionIdOf = function (jar) {
      return String(jar.sts_session || '').split('.')[0];
    };
    // A person signed in at the screen, in a jar of their own.
    const signIn = async function (username) {
      const jar = {};
      const at = authn.beginAuthentication({ returnTo: '/logout',
        protocol: 'la-probe', application: '' });
      const r = await screen.submit({ port: port, jar: jar, at: at,
        fields: { action: 'login', username: username, password: 'right' } });
      return { jar: jar, next: r.next };
    };
    const get = function (jar, p, accept) {
      return screen.call({ port: port, jar: jar, method: 'GET', path: p,
        headers: accept ? { accept: accept } : {} });
    };
    const act = function (jar, body, o) {
      const opts = o || {};
      const headers = { accept: 'application/json',
        'content-type': opts.contentType || 'application/json' };
      if (opts.origin !== null) {
        headers.origin = opts.origin || origin;
      }
      if (opts.csrf) {
        headers['x-csrf-token'] = opts.csrf;
      }
      return screen.call({ port: port, jar: jar, method: 'POST',
        path: '/authn-api/logout', headers: headers,
        body: typeof body === 'string' ? body : JSON.stringify(body) });
    };

    // --- 1. the shell --------------------------------------------------------
    const ann = await signIn('la-ann');
    note(ann.next === 'redirect' && !!ann.jar.sts_session,
         '(la-ann signed in)', ann.next);
    let r = await get(ann.jar, '/logout');
    const csp = String(r.headers['content-security-policy'] || '');
    note(r.status === 200 &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         r.text.indexOf('<script src="/logout/signout.js" defer></script>') >
           0 &&
         r.text.indexOf('<link rel="stylesheet" href="/logout/signout.css">') >
           0 &&
         r.text.indexOf('<noscript>') > 0 && !/<form/.test(r.text) &&
         !/name="scope"/.test(r.text),
         '1a. a browser\'s GET /logout answers the shell: the bundle, the ' +
         'stylesheet, the notice, and no form', r.status + ' ' +
         r.text.slice(0, 600));
    note(/frame-ancestors 'none'/.test(csp) &&
         /script-src 'self'(;|$)/.test(csp) &&
         /connect-src 'self'/.test(csp) && !/unsafe-inline/.test(csp),
         '1b. its policy keeps frame-ancestors and allows script, style and ' +
         'API from \'self\' only', csp);
    r = await get({}, '/logout');
    note(r.status === 302 &&
         /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(String(r.headers.location || '')),
         '1c. a browser with no session is sent to sign in first, as it ' +
         'always was', r.status + ' ' + r.headers.location);
    const named = {};
    r = await get(named, '/logout?username=la-bob');
    note(r.status === 200 && !!named.sts_session,
         '1d. ?username= (open in development) answers the shell and mints ' +
         'the arrival cookie the act is bound to', r.status + ' ' +
         JSON.stringify(Object.keys(named)));
    r = await get({}, '/logout/signout.js');
    note(r.status === 200 && /javascript/.test(r.headers['content-type']) &&
         r.text.length > 1000 && r.text.indexOf('was not built') < 0,
         '1e. the bundle is served, built', r.status + ' ' + r.text.length);
    const css = await get({}, '/logout/signout.css');
    note(css.status === 200 && /text\/css/.test(css.headers['content-type']) &&
         css.text.indexOf('button.global{') >= 0 &&
         css.text.indexOf('details.sts-accounts{') >= 0,
         '1f. the stylesheet is served, with the account control\'s rules ' +
         '(#561)', css.status);

    // --- 2. the index and the document -------------------------------------
    r = await get({}, '/authn-api');
    const ops = (r.json && r.json.operations) || [];
    const one = function (m, action) {
      return ops.filter(function (op) {
        return op.mirrors === m && (!action || op.action === action);
      });
    };
    note(one('GET /logout').length === 1 &&
         one('GET /logout')[0].path === '/authn-api/logout' &&
         one('POST /logout', 'logout').length === 1 &&
         one('POST /logout')[0].method === 'POST',
         '2a. the index lists the view and the act, mirroring GET and POST ' +
         '/logout', JSON.stringify(one('POST /logout')));
    r = await get({}, '/authn-api/openapi.json');
    const doc = (r.json && r.json.paths && r.json.paths['/authn-api/logout']) ||
      {};
    note(!!doc.get && !!doc.post && !!doc.post.requestBody &&
         (doc.get.parameters || []).some(function (p) {
           return p.name === 'username';
         }),
         '2b. the OpenAPI document has both, the act\'s body and the view\'s ' +
         'username', JSON.stringify(Object.keys(doc)));

    // --- 3. the view --------------------------------------------------------
    r = await get(ann.jar, '/authn-api/logout', 'application/json');
    const view = (r.json && r.json.view) || {};
    const sessionFamily = (view.families || []).filter(function (f) {
      return f.id === 'session';
    })[0] || { rows: [] };
    const annSession = sessionIdOf(ann.jar);
    note(r.status === 200 && view.state === 'inventory' &&
         view.username === 'la-ann' && view.naming === 'open' &&
         sessionFamily.rows.some(function (row) {
           return row.id === 'session:' + annSession && row.terminable;
         }) && r.json.csrf === websecurity.tokenFor(annSession) &&
         codeFree(r.text),
         '3a. the view: the inventory as facts, the browser\'s own session ' +
         'among it, and the token of the cookie\'s session',
         r.status + ' ' + r.text.slice(0, 400));
    note(!/"secret"/.test(r.text),
         '3b. no row carries the credential behind it', '');
    r = await get(named, '/authn-api/logout?username=la-bob',
                  'application/json');
    note(r.status === 200 && r.json.view.username === 'la-bob' &&
         r.json.view.named === true &&
         r.json.csrf === websecurity.tokenFor(sessionIdOf(named)),
         '3c. a name, where naming is open, is whom the view is about',
         r.status + ' ' + r.text.slice(0, 200));
    config.setOverride('logout.anyUser', 'false');
    r = await get(ann.jar, '/authn-api/logout?username=la-bob',
                  'application/json');
    note(r.status === 403 && r.json.ok === false &&
         r.json.view.state === 'refused' &&
         /logout\.anyUser is off/.test((r.json.errors || []).join(' ')) &&
         codeFree(r.text),
         '3d. with naming closed, somebody else\'s name is refused (403), ' +
         'with the view the page draws the refusal on', r.text);
    r = await get(ann.jar, '/authn-api/logout?username=la-ann',
                  'application/json');
    note(r.status === 200 && r.json.view.username === 'la-ann',
         '3e. and the caller\'s own name is honoured', r.status);
    r = await get({}, '/authn-api/logout', 'application/json');
    note(r.status === 401 && r.json.view.state === 'nobody' &&
         codeFree(r.text),
         '3f. with no session and no name, nobody (401)', r.text);
    config.setOverride('logout.anyUser', 'true');

    // --- 4. the binding of the act -------------------------------------------
    const csrf = websecurity.tokenFor(annSession);
    r = await act(ann.jar, {}, { csrf: csrf, contentType:
                                 'application/x-www-form-urlencoded' });
    note(r.status === 415, '4a. a body that is not JSON is refused (415)',
         r.status);
    r = await act(ann.jar, {}, { csrf: csrf, origin: 'https://evil.example' });
    note(r.status === 403, '4b. another origin is refused (403)', r.status);
    r = await act(ann.jar, {}, { csrf: csrf, origin: null });
    note(r.status === 403, '4c. no Origin is refused (403)', r.status);
    r = await act(ann.jar, {}, {});
    note(r.status === 403, '4d. no token is refused (403)', r.status);
    r = await act(ann.jar, {}, { csrf: websecurity.tokenFor('another') });
    note(r.status === 403 && codeFree(r.text),
         '4e. another session\'s token is refused (403)', r.status);
    r = await act(ann.jar, { scope: 'global', admin: '1' }, { csrf: csrf });
    note(r.status === 400, '4f. a field the act does not take is refused',
         r.status);
    r = await act(ann.jar, { scope: 'Global' }, { csrf: csrf });
    note(r.status === 400 && codeFree(r.text),
         '4g. a scope outside the closed set is refused', r.text);
    note(!!authn.sessionById(annSession),
         '4h. and none of them ended anything', annSession);

    // --- 5. nothing to fan out: the result's view --------------------------
    r = await act(ann.jar, { scope: 'selected',
                             select: ['session:' + annSession] },
                  { csrf: csrf });
    const answer = r.json || {};
    note(r.status === 200 && answer.ok === true &&
         answer.next === 'signed-out' && !answer.form &&
         answer.view && answer.view.state === 'result' &&
         answer.view.scope === 'selected' &&
         answer.view.terminated.some(function (row) {
           return row.id === 'session:' + annSession;
         }) && answer.ownSessionEnded === true && codeFree(r.text),
         '5a. a sign-out with nothing to fan out answers the result\'s view',
         r.text.slice(0, 500));
    note(!ann.jar.sts_session && !authn.sessionById(annSession),
         '5b. the browser\'s own session ended, and its cookie was cleared ' +
         'on the answer', JSON.stringify(ann.jar));
    note(r.headers['clear-site-data'] === '"storage"',
         '5c. the answer tells the browser to drop storage, and not cookies ' +
         '(#1440)', r.headers['clear-site-data']);

    // --- 6. a sign-out that fans out: the signed-out document ---------------
    const cy = await signIn('la-cy');
    const cySession = sessionIdOf(cy.jar);
    const held = authn.sessionById(cySession);
    held.wsfedRealms = { 'urn:la:rp': 'https://rp.la.example/wsfed' };
    const cyCsrf = websecurity.tokenFor(cySession);
    r = await act(cy.jar, { scope: 'global' }, { csrf: cyCsrf });
    const fanned = r.json || {};
    note(r.status === 200 && fanned.next === 'signed-out' && !fanned.view &&
         fanned.form && fanned.form.method === 'POST' &&
         fanned.form.action === '/logout/signed-out' &&
         typeof fanned.form.fields.result === 'string' &&
         !cy.jar.sts_session,
         '6a. a sign-out that fans out answers the signed-out document\'s ' +
         'form, and clears the cookie', r.text.slice(0, 300));
    const postDoc = function (result, o) {
      const opts = o || {};
      const headers = { 'content-type': 'application/x-www-form-urlencoded' };
      if (opts.origin !== null) {
        headers.origin = opts.origin || origin;
      }
      if (opts.site) {
        headers['sec-fetch-site'] = opts.site;
      }
      return screen.call({ port: port, jar: opts.jar || {}, method: 'POST',
        path: '/logout/signed-out', headers: headers,
        body: new URLSearchParams(result === undefined ? {}
                                  : { result: result }).toString() });
    };
    const docJar = {};
    r = await postDoc(fanned.form.fields.result, { jar: docJar });
    const docCsp = String(r.headers['content-security-policy'] || '');
    const shared = logout.fanOutOf([{ cleanups: [{ realm: 'urn:la:rp',
      wreply: 'https://rp.la.example/wsfed',
      url: 'https://rp.la.example/wsfed?wa=wsignoutcleanup1.0' }] }]);
    note(r.status === 200 && /^<!doctype html>/.test(r.text) &&
         r.text.indexOf(shared.html) > 0 &&
         r.text.indexOf('<img src="https://rp.la.example/wsfed?wa=' +
                        'wsignoutcleanup1.0"') > 0 &&
         r.text.indexOf('<script') < 0,
         '6b. the signed-out document is the server-drawn page, its fan-out ' +
         'exactly what fanOutOf() — /federation/slo\'s too — draws, with ' +
         'no script', r.status + ' ' + r.text.slice(0, 300));
    note(/frame-ancestors 'none'/.test(docCsp) &&
         /img-src 'self' data: \*/.test(docCsp),
         '6c. its policy is the fan-out\'s, frame-ancestors kept', docCsp);
    note(r.text.indexOf('<style>' + css.text + '</style>') > 0,
         '6d. its inline rules are the static page\'s stylesheet, to the ' +
         'byte', '');
    note(!docJar.sts_session,
         '6e. and it mints no cookie for the browser it signed out',
         JSON.stringify(docJar));
    r = await postDoc(fanned.form.fields.result, { origin: null });
    note(r.status === 403 && codeFree(r.text) && r.text.indexOf('<img') < 0,
         '6f. posted with no Origin, it is refused (403)', r.status);
    r = await postDoc(fanned.form.fields.result,
                      { origin: 'https://evil.example' });
    note(r.status === 403, '6g. from another origin, refused (403)',
         r.status);
    // A browser's own form post: every page here is sent
    // `Referrer-Policy: no-referrer`, so the navigation carries
    // `Origin: null`, and Fetch Metadata says where it came from.
    r = await postDoc(fanned.form.fields.result,
                      { origin: 'null', site: 'same-origin' });
    note(r.status === 200 && r.text.indexOf(shared.html) > 0,
         '6g2. a navigation\'s null Origin, the browser saying it is ' +
         'same-origin, is drawn', r.status);
    r = await postDoc(fanned.form.fields.result,
                      { origin: 'null', site: 'cross-site' });
    note(r.status === 403, '6g3. and refused (403) where it says cross-site',
         r.status);
    const sealed = String(fanned.form.fields.result);
    const forged = sealed.slice(0, sealed.lastIndexOf('.') + 1) +
      'A'.repeat(43);
    r = await postDoc(forged);
    note(r.status === 400 && codeFree(r.text) && r.text.indexOf('<img') < 0,
         '6h. a result this service did not MAC is refused (400)', r.status);
    r = await postDoc(undefined);
    note(r.status === 400, '6i. no result at all is refused (400)',
         r.status);

    // --- 6j. a selected WS-Federation or SAML row tells the store ----------
    // (2026-11-15, found by #444's D12): forgetting a realm or a service
    // provider edits an object the session store holds and does not
    // journal, so the session is written back through noteSessionChanged()
    // as the oidc-rp row's forget always was. The calls are counted on the
    // module's facade, which logout.ts calls at the time of the act.
    const ed = await signIn('la-ed');
    const edSession = sessionIdOf(ed.jar);
    const edHeld = authn.sessionById(edSession);
    edHeld.wsfedRealms = { 'urn:la:ed': 'https://rp.la.example/wsfed-ed' };
    edHeld.saml2ServiceProviders = { 'urn:la:sp': {
      acs: 'https://sp.la.example/acs', idpEntityId: 'urn:la:idp',
      at: Date.now(), nameId: 'la-ed', nameIdFormat: '' } };
    authn.noteSessionChanged(edHeld);
    const noted = [];
    const realNote = authn.noteSessionChanged;
    authn.noteSessionChanged = function (one) {
      noted.push(one && one.id);
      return realNote.apply(this, arguments);
    };
    let edResult;
    try {
      edResult = logout.terminate(String((edHeld.user || {}).username ||
                                         'la-ed'),
        ['wsfed-rp:' + edSession + '|urn:la:ed',
         'saml2-sp:' + edSession + '|urn:la:sp'],
        { by: 'the logout_api test' });
    } finally {
      authn.noteSessionChanged = realNote;
    }
    const edAfter = authn.sessionById(edSession) || {};
    note(noted.filter(function (id) {
      return id === edSession;
    }).length >= 2 &&
         !Object.prototype.hasOwnProperty.call(edAfter.wsfedRealms || {},
                                                'urn:la:ed') &&
         !Object.prototype.hasOwnProperty.call(
           edAfter.saml2ServiceProviders || {}, 'urn:la:sp'),
         '6j. forgetting a WS-Federation realm and a SAML service provider ' +
         'writes the session back to the store, once for each',
         JSON.stringify({ noted: noted,
                          ended: ((edResult || {}).terminated || [])
                            .map(function (row) { return row.id; }) }));

    // --- 6k. a realm with several sign-out addresses: every one is told ----
    // (2026-11-15). A realm declaring two `wsfedSignOutUri` values is one
    // sign-in and two rows, `<sid>|<realm>` and `<sid>|<realm>|1` (#747).
    // Until this, the second row read its realm as `<realm>|1` and did
    // nothing while saying it had, and only the first address was ever sent
    // a cleanup. Ending either row now sends one to both and forgets the
    // realm once; the sibling row then reports it already forgotten.
    const applications = require(ROOT_DIR + '/common/applications');
    const TWO = 'urn:la:two';
    const OUTS = ['https://rp.la.example/out-a',
                  'https://rp.la.example/out-b?x=1'];
    const twoMade = applications.createApplication({ identifier: TWO,
      protocols: ['wsfed'],
      fields: { wsfedReplyUrl: ['https://rp.la.example/wsfed-two'],
                wsfedSignOutUri: OUTS } });
    const urlsOf = function (result) {
      return ((result || {}).cleanups || []).map(function (one) {
        return one.url;
      }).sort();
    };
    const wanted = [OUTS[0] + '?wa=wsignoutcleanup1.0',
                    OUTS[1] + '&wa=wsignoutcleanup1.0'].sort();
    // The second row on its own.
    const two = await signIn('la-two');
    const twoSession = sessionIdOf(two.jar);
    const twoHeld = authn.sessionById(twoSession);
    twoHeld.wsfedRealms = { [TWO]: 'https://rp.la.example/wsfed-two' };
    authn.noteSessionChanged(twoHeld);
    const twoUser = String((twoHeld.user || {}).username || 'la-two');
    const second = logout.terminate(twoUser,
      ['wsfed-rp:' + twoSession + '|' + TWO + '|1'],
      { by: 'the logout_api test' });
    const twoAfter = authn.sessionById(twoSession) || {};
    note(twoMade && twoMade.ok !== false &&
         JSON.stringify(urlsOf(second)) === JSON.stringify(wanted) &&
         !Object.prototype.hasOwnProperty.call(twoAfter.wsfedRealms || {},
                                                TWO),
         '6k. ending a realm\'s SECOND address row sends a cleanup to both ' +
         'its addresses and forgets the realm',
         JSON.stringify({ made: twoMade && twoMade.errors,
                          cleanups: urlsOf(second),
                          realms: Object.keys(twoAfter.wsfedRealms || {}) }));
    // Both rows together, as a sign-out of the session ends them.
    twoAfter.wsfedRealms = { [TWO]: 'https://rp.la.example/wsfed-two' };
    authn.noteSessionChanged(twoAfter);
    const both = logout.terminate(twoUser,
      ['wsfed-rp:' + twoSession + '|' + TWO,
       'wsfed-rp:' + twoSession + '|' + TWO + '|1'],
      { by: 'the logout_api test' });
    const bothRows = ((both || {}).terminated || []).filter(function (row) {
      return String(row.id).indexOf('wsfed-rp:') === 0;
    });
    note(JSON.stringify(urlsOf(both)) === JSON.stringify(wanted) &&
         bothRows.length === 2,
         '6k2. ending both rows sends each address exactly one cleanup, and ' +
         'both rows are ended',
         JSON.stringify({ cleanups: urlsOf(both),
                          ended: bothRows.map(function (row) {
                            return row.id;
                          }) }));

    // --- 7. the JSON door, and a form posted to /logout ---------------------
    const dee = await signIn('la-dee');
    const deeSession = sessionIdOf(dee.jar);
    r = await screen.call({ port: port, jar: dee.jar, method: 'POST',
      path: '/logout', headers: {
        'content-type': 'application/x-www-form-urlencoded' },
      body: 'scope=global' });
    note(r.status === 303 && r.headers.location === '/logout' &&
         !!authn.sessionById(deeSession),
         '7a. a form posted to /logout ends nothing and is sent to the ' +
         'page (303)', r.status + ' ' + r.headers.location);
    r = await get(dee.jar, '/logout', 'application/json');
    note(r.status === 200 && r.json && r.json.username === 'la-dee' &&
         Array.isArray(r.json.families),
         '7b. GET /logout asking for JSON answers the inventory as it did',
         r.status);
    r = await screen.call({ port: port, jar: dee.jar, method: 'POST',
      path: '/logout', headers: { 'content-type': 'application/json',
                                  accept: 'application/json' },
      body: JSON.stringify({ scope: 'global' }) });
    note(r.status === 200 && r.json && r.json.scope === 'global' &&
         r.json.ownSessionEnded === true && !authn.sessionById(deeSession) &&
         !dee.jar.sts_session,
         '7c. POST /logout with JSON signs out as it did', r.text.slice(0,
                                                                         300));
    r = await screen.call({ port: port, jar: {}, method: 'POST',
      path: '/logout', headers: { 'content-type': 'application/json',
                                  accept: 'application/json' },
      body: JSON.stringify({ scope: 'nowhere', username: 'la-x' }) });
    note(r.status === 400 && r.json && r.json.error === 'invalid_request',
         '7d. and its refusal of a body is JSON now, where it was a page',
         r.status + ' ' + r.text.slice(0, 200));

    // --- 8. the whole walk, as the page sends it ----------------------------
    const eve = await signIn('la-eve');
    const walked = await screen.signOut({ port: port, jar: eve.jar,
                                         fields: {} });
    note(walked.status === 200 && walked.act && walked.act.status === 200 &&
         walked.json && walked.json.view.scope === 'global' &&
         !eve.jar.sts_session,
         '8a. authn_screen.signOut() walks the page: shell, view, act',
         walked.status + ' ' + String(walked.text).slice(0, 200));

    // --- 9. ending another session needs a recent sign-in (#1577) ---------
    config.setOverride('account.recentAuthMinutes', '15');
    const fay = await signIn('la-fay');
    const fayOther = await signIn('la-fay');
    const faySession = sessionIdOf(fay.jar);
    const fayOtherSession = sessionIdOf(fayOther.jar);
    const stale = function (sid) {
      const one = authn.sessionById(sid);
      const old = Math.floor(Date.now() / 1000) - 7200;
      (one.events || []).forEach(function (event) {
        event.at = old;
      });
      one.authTime = old;
    };
    stale(faySession);
    const fayCsrf = websecurity.tokenFor(faySession);
    r = await act(fay.jar, { scope: 'selected',
                             select: ['session:' + fayOtherSession] },
                  { csrf: fayCsrf });
    const owed = r.json || {};
    note(r.status === 403 && owed.ok === false && owed.view &&
         owed.view.state === 'reauthenticate' &&
         /^\/authn\/login/.test(String(owed.view.signIn || '')) &&
         Array.isArray(owed.errors) && owed.errors.length === 1 &&
         codeFree(r.text),
         '9a. a stale sign-in ending another session is refused (403) with ' +
         'a view naming where to sign in again, and no code',
         r.status + ' ' + r.text.slice(0, 300));
    note(!!authn.sessionById(fayOtherSession) &&
         !!authn.sessionById(faySession) && !!fay.jar.sts_session,
         '9b. and nothing was ended', faySession + ' ' + fayOtherSession);
    r = await screen.call({ port: port, jar: fay.jar, method: 'POST',
      path: '/logout', headers: { 'content-type': 'application/json',
                                  accept: 'application/json' },
      body: JSON.stringify({ scope: 'selected',
                             select: ['session:' + fayOtherSession] }) });
    note(r.status === 403 && r.json &&
         r.json.error === 'reauthentication_required',
         '9c. the JSON door answers the same act the same way', r.status);
    const again = await screen.submit({ port: port, jar: fay.jar,
      at: owed.view.signIn,
      fields: { action: 'login', username: 'la-fay', password: 'right' } });
    note(again.next === 'redirect' && !!authn.sessionById(faySession),
         '9d. signing in again where the view said keeps the same session',
         again.next);
    r = await act(fay.jar, { scope: 'selected',
                             select: ['session:' + fayOtherSession] },
                  { csrf: websecurity.tokenFor(faySession) });
    note(r.status === 200 && r.json && r.json.ok === true &&
         !authn.sessionById(fayOtherSession) &&
         !!authn.sessionById(faySession),
         '9e. and then the same act ends the other session, and only it',
         r.status + ' ' + r.text.slice(0, 200));
    const gus = await signIn('la-gus');
    const gusSession = sessionIdOf(gus.jar);
    stale(gusSession);
    r = await act(gus.jar, { scope: 'global' },
                  { csrf: websecurity.tokenFor(gusSession) });
    note(r.status === 200 && r.json && r.json.ok === true &&
         !authn.sessionById(gusSession),
         '9f. signing yourself out everywhere is never asked', r.status);
    config.clearOverride('account.recentAuthMinutes');
    const pages = require(ROOT_DIR + '/logout/web_signout_pages');
    const drawn = pages.render('/logout', owed.view, { t: {
      html: function (key) {
        return '[' + key + ']';
      },
      text: function (key) {
        return key;
      } } });
    note(drawn.indexOf('[logout.reauthenticate.lead]') > 0 &&
         drawn.indexOf('[logout.reauthenticate.signIn]') > 0 &&
         drawn.indexOf('data-sts-navigate="1"') > 0 &&
         drawn.indexOf('href="' + String(owed.view.signIn)
           .replace(/&/g, '&amp;')) > 0,
         '9g. the page draws that view as a sentence and a link to sign in ' +
         'again, in the catalogs\' words', drawn.slice(0, 300));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
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
  const out = path.join(os.tmpdir(), 'la-' + process.pid + '-' + Date.now() +
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
                                  LA_ROOT: ROOT, LA_OUT: out }),
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
  name: 'logout_api',
  describe: 'the sign-out is a static surface over /authn-api/logout: the ' +
            'shell, the view, the CSRF binding, the act and its result, the ' +
            'signed-out document and its fan-out, and the JSON door ' +
            'unchanged (#577)',
  run: run
};
