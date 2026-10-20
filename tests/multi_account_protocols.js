// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: multi_account_protocols.js
//
// ===========================================================================
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER (#561): THE PROTOCOL SIGN-INS.
//
// `authn/CLAUDE.md`, *Several signed-in accounts in one browser*, is the
// design and `tests/multi_account_sessions.js` the contract of the set
// itself. This file is the plan's delivery step 3, over HTTP against the
// whole stack, with `authn.multipleAccounts` OFF and then ON:
//
//   OFF (today's behaviour, unchanged):
//   1. a second person signing in through SAML 2.0 ends the first; a
//      <Subject> naming the first changes nothing; no sts_accounts cookie;
//   2. IsPassive with no session is NoPassive with today's sentence;
//   3. Session Management's OP iframe script is byte for byte the script
//      before #561 (its SHA-256), and its cookie one state; no static
//      surface's shell carries `data-sts-accounts`, which ON every one
//      does — so a page asks for the account list only with the setting on.
//   ON:
//   4. SAML 2.0: ForceAuthn goes to a fresh sign-in, never the picker, and
//      adds the account; a request naming nobody goes to the picker; a
//      <Subject> NameID chooses its account silently, one naming nobody
//      here goes to the sign-in screen with the name filled in, and a
//      transient one is no hint; IsPassive with a choice to make is
//      NoPassive saying so, with the `account.ambiguous` row; IsPassive
//      with a <Subject> is answered;
//   5. SAML 1.1, which has no hint and no IsPassive: the picker;
//   6. WS-Federation: the picker, and `wfresh` a fresh sign-in instead;
//   7. Session Management: the cookie lists both accounts' browser states,
//      the script served is the list's, and it answers `unchanged` for
//      either account's `session_state` and `changed` once one is gone;
//   8. GNAP: the grant's `user` chooses its account; with none the picker,
//      and the account chosen there is the one the page's own API calls
//      act as.
//
// WHY A CHILD PROCESS: it serves the whole protocol stack on a loopback port
// (`tests/saml2_force_authn.js`'s reason).
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'multi_account_protocols',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The OP iframe's script as it was before #561, by its SHA-256: what a realm
// with `authn.multipleAccounts` off must still be served, byte for byte.
const SCRIPT_BEFORE_561 =
  '7b356d56cec3d3ed6acfcd4c18ce3a83c1b20ad43efc19809058cbbd498ddb0d';

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.MAP_ROOT;
  const OUT = process.env.MAP_OUT;
  const BEFORE = process.env.MAP_SCRIPT_SHA;
  const http = require('http');
  const zlib = require('zlib');
  const vm = require('vm');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const config = require(ROOT_DIR + '/common/config');
    const audit = require(ROOT_DIR + '/common/audit');
    const applications = require(ROOT_DIR + '/common/applications');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const authn = require(ROOT_DIR + '/authn/authn');
    const AccountSets = require(ROOT_DIR + '/authn/account_sets');
    const sm = require(ROOT_DIR + '/oauth-oidc/session_management');
    const store = require(ROOT_DIR + '/gnap/gnap_store');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const SUFFIX = crypto.randomBytes(3).toString('hex');
    const RP = 'https://rp.map.example';
    const REDIRECT = RP + '/cb';
    const ALICE = 'map-alice-' + SUFFIX;
    const BOB = 'map-bob-' + SUFFIX;
    const CAROL = 'map-carol-' + SUFFIX;
    config.setOverride('oauth2.consentRequired', false);
    applications.createApplication({ identifier: 'map-rp-' + SUFFIX,
      protocols: ['oauth2'],
      fields: { oauthClientId: 'map-rp-' + SUFFIX,
                oauthRedirectUri: [REDIRECT],
                oauthClientSecret: 'map-secret-0123456789abcdef0123456789',
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    const get = function (jar, p) {
      return screen.call({ port: port, jar: jar, method: 'GET',
                           path: p.replace(/^https?:\/\/[^/]+/, '') });
    };
    const json = function (jar, method, p, body, csrf) {
      return screen.call({ port: port, jar: jar, method: method,
        path: p.replace(/^https?:\/\/[^/]+/, ''),
        headers: Object.assign({ accept: 'application/json',
          'content-type': 'application/json', origin: ORIGIN },
          csrf ? { 'x-csrf-token': csrf } : {}),
        body: body === undefined ? undefined : JSON.stringify(body) });
    };
    const inRealm = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    const on = function (yes) {
      config.setOverride('authn.multipleAccounts', yes ? 'true' : 'false');
    };

    // --- SAML 2.0 ----------------------------------------------------------
    const authnRequest = function (o) {
      const subject = o.subject
        ? '<saml:Subject><saml:NameID' + (o.format
          ? ' Format="' + o.format + '"' : '') + '>' + o.subject +
          '</saml:NameID></saml:Subject>' : '';
      const xml = '<samlp:AuthnRequest ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_map' + crypto.randomBytes(8).toString('hex') + '" ' +
        'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
        'AssertionConsumerServiceURL="https://sp.map.test/acs"' +
        (o.force ? ' ForceAuthn="true"' : '') +
        (o.passive ? ' IsPassive="true"' : '') + '>' +
        '<saml:Issuer>urn:map:sp</saml:Issuer>' + subject +
        '</samlp:AuthnRequest>';
      return '/saml2/sso?SAMLRequest=' + encodeURIComponent(
        zlib.deflateRawSync(Buffer.from(xml)).toString('base64'));
    };
    const samlResponseOf = function (r) {
      const m = /name="SAMLResponse" value="([^"]+)"/.exec(r.text || '');
      if (!m) {
        return null;
      }
      const xml = Buffer.from(m[1], 'base64').toString('utf8');
      const codes = [];
      const re = /StatusCode Value="([^"]+)"/g;
      let one;
      while ((one = re.exec(xml))) {
        codes.push(one[1].split(':').pop());
      }
      const nameId = /NameID[^>]*>([^<]+)</.exec(xml);
      const message = /StatusMessage>([^<]*)</.exec(xml);
      return { codes: codes, nameId: nameId ? nameId[1] : '',
               message: message ? message[1] : '' };
    };
    // Walks a flow from `start`: signs in as `username` at a sign-in
    // screen, stops at the account picker, follows every other redirect.
    const drive = async function (jar, start, username) {
      let r = await get(jar, start);
      let screens = 0;
      let picker = '';
      let screenAt = '';
      for (let hop = 0; hop < 12; hop += 1) {
        const to = String((r.headers && r.headers.location) || '');
        if (r.status >= 300 && r.status < 400 && /\/authn\/accounts\?/
            .test(to)) {
          picker = to;
          break;
        }
        if (r.status >= 300 && r.status < 400 && /\/authn\/login\?authn=/
            .test(to)) {
          screens += 1;
          screenAt = to;
          if (!username) {
            break;
          }
          const answer = await screen.submit({ port: port, jar: jar,
            at: to, fields: { action: 'login', username: username,
                              password: 'x' } });
          r = { status: answer.status, headers: answer.headers,
                text: answer.text };
          continue;
        }
        if (r.status >= 300 && r.status < 400 && to) {
          if (to.indexOf('http') === 0 && to.indexOf(ORIGIN) !== 0) {
            break;
          }
          r = await get(jar, to);
          continue;
        }
        break;
      }
      return { final: r, screens: screens, picker: picker,
               screenAt: screenAt, saml: samlResponseOf(r) };
    };
    // Continues a flow from the picker as one of its signed-in accounts.
    const pick = async function (jar, at, username) {
      const id = decodeURIComponent(/[?&]authn=([^&]+)/.exec(at)[1]);
      await get(jar, at);
      const view = await json(jar, 'GET', '/authn-api/pending/' +
                              encodeURIComponent(id) + '/accounts');
      const accounts = (view.json && view.json.view &&
                        view.json.view.accounts) || [];
      const one = accounts.filter(function (a) {
        return a.username === username;
      })[0];
      const act = await json(jar, 'POST', '/authn-api/pending/' +
                             encodeURIComponent(id) + '/accounts/select',
                             { account: one ? one.key : 'nobody' },
                             view.json && view.json.csrf);
      return { view: view.json, act: act.json,
               location: String((act.json && act.json.location) || '') };
    };
    const liveFor = function (username) {
      return inRealm(function () {
        const out = [];
        authn.sessions.forEach(function (session, sid) {
          if (session && session.user &&
              session.user.username === username &&
              session.chosen !== false && !authn.sessionEnded(session)) {
            out.push(String(sid));
          }
        });
        return out;
      });
    };
    const ambiguousRows = function () {
      return inRealm(function () {
        return audit.list().filter(function (event) {
          return event.action === 'account.ambiguous' &&
            event.protocol === 'SAML 2.0';
        }).length;
      });
    };

    // =====================================================================
    // OFF
    // =====================================================================
    on(false);
    const off = {};
    let f = await drive(off, authnRequest({}), ALICE + '-off');
    note(f.saml && f.saml.codes[0] === 'Success' &&
         f.saml.nameId === ALICE + '-off' &&
         !off[AccountSets.cookieName()],
         '1a. off: a SAML 2.0 sign-in, and no sts_accounts cookie',
         JSON.stringify({ saml: f.saml, jar: Object.keys(off) }));
    f = await drive(off, authnRequest({ force: true }), BOB + '-off');
    note(f.saml && f.saml.nameId === BOB + '-off' && f.screens === 1 &&
         liveFor(ALICE + '-off').length === 0,
         '1b. off: a second person signing in (ForceAuthn) ENDED the first ' +
         'one\'s session, as it always did',
         JSON.stringify({ saml: f.saml, alice: liveFor(ALICE + '-off') }));
    f = await drive(off, authnRequest({ subject: ALICE + '-off' }), '');
    note(f.saml && f.saml.nameId === BOB + '-off' && f.screens === 0,
         '1c. off: a <Subject> naming the first person changes nothing: ' +
         'single sign-on as the session the cookie names',
         JSON.stringify(f.saml));
    f = await drive({}, authnRequest({ passive: true }), '');
    note(f.saml && f.saml.codes.indexOf('NoPassive') >= 0 &&
         f.saml.message === 'There is no browser session here, and ' +
           'IsPassive forbids asking for one.',
         '2. off: IsPassive with no session is NoPassive, today\'s sentence',
         JSON.stringify(f.saml));
    config.setOverride('oauth2.sessionManagement', 'true');
    let r = await get({}, sm.SCRIPT_PATH);
    note(r.status === 200 && crypto.createHash('sha256').update(r.text)
           .digest('hex') === BEFORE && r.text === sm.IFRAME_SCRIPT,
         '3. off: the OP iframe\'s script is byte for byte the one before ' +
         '#561', crypto.createHash('sha256').update(r.text).digest('hex'));

    // THE SHELLS SAY NOTHING with the setting off, so no runtime asks for
    // the account list (`WebAccounts.announced()`): the front door, the
    // portal, the console and a description page, as `ShellDocument` draws
    // them (`/logout` sends a browser with no session to sign in).
    const SHELLS = ['/', '/portal', '/admin', '/saml2'];
    const shells = async function () {
      const out = [];
      for (const one of SHELLS) {
        const got = await get({}, one);
        out.push({ path: one, status: got.status,
                   on: /<html[^>]* data-sts-accounts="on"/.test(got.text),
                   any: /data-sts-accounts/.test(got.text) });
      }
      return out;
    };
    let drawn = await shells();
    note(drawn.every(function (one) {
      return one.status === 200 && !one.any;
    }), '3b. off: no static surface\'s shell carries data-sts-accounts, ' +
        'so no page asks for the account list', JSON.stringify(drawn));

    // =====================================================================
    // ON
    // =====================================================================
    on(true);
    drawn = await shells();
    note(drawn.every(function (one) {
      return one.status === 200 && one.on;
    }), '3c. on: every static surface\'s shell says data-sts-accounts="on"',
        JSON.stringify(drawn));
    const jar = {};
    f = await drive(jar, authnRequest({}), ALICE);
    note(f.saml && f.saml.nameId === ALICE && !!jar[AccountSets.cookieName()],
         '4a. on: a SAML 2.0 sign-in as alice writes the account set\'s ' +
         'cookie', JSON.stringify({ saml: f.saml, jar: Object.keys(jar) }));
    f = await drive(jar, authnRequest({}), '');
    note(f.saml && f.saml.nameId === ALICE && f.screens === 0 && !f.picker,
         '4b. with one account, a plain request is single sign-on',
         JSON.stringify(f.saml));
    f = await drive(jar, authnRequest({ force: true }), BOB);
    note(f.saml && f.saml.nameId === BOB && f.screens === 1 && !f.picker,
         '4c. ForceAuthn goes to a FRESH sign-in, never the picker, and ' +
         'bob signs in', JSON.stringify({ screens: f.screens,
                                          picker: f.picker, saml: f.saml }));
    note(liveFor(ALICE).length === 1 && liveFor(BOB).length === 1,
         '4d. and both stay signed in: bob was added, alice not ended',
         JSON.stringify({ alice: liveFor(ALICE), bob: liveFor(BOB) }));
    f = await drive(jar, authnRequest({}), '');
    note(!!f.picker && !f.saml,
         '4e. a request that names nobody goes to the account picker',
         JSON.stringify({ picker: f.picker, status: f.final.status }));
    const picked = await pick(jar, f.picker, BOB);
    f = await drive(jar, picked.location, '');
    note(/sts_account=/.test(picked.location) && f.saml &&
         f.saml.nameId === BOB,
         '4f. choosing bob at the picker resumes the held request as bob',
         JSON.stringify({ location: picked.location, saml: f.saml }));
    f = await drive(jar, authnRequest({ subject: ALICE }), '');
    note(f.saml && f.saml.nameId === ALICE && f.screens === 0 && !f.picker,
         '4g. a <Subject> NameID naming alice chooses her silently',
         JSON.stringify(f.saml));
    f = await drive(jar, authnRequest({ subject: BOB }), '');
    note(f.saml && f.saml.nameId === BOB && !f.picker,
         '4h. and one naming bob chooses him', JSON.stringify(f.saml));
    f = await drive(jar, authnRequest({ subject: CAROL }), '');
    const carolRecord = f.screenAt ? inRealm(function () {
      return authn.pendingFor(decodeURIComponent(
        /[?&]authn=([^&]+)/.exec(f.screenAt)[1]));
    }) : null;
    note(!f.picker && !!f.screenAt && !f.saml && carolRecord &&
         carolRecord.hint === CAROL,
         '4i. a NameID naming nobody signed in here goes to the sign-in ' +
         'screen with that name filled in — never another account',
         JSON.stringify({ screen: f.screenAt, picker: f.picker,
                          hint: carolRecord && carolRecord.hint }));
    f = await drive(jar, authnRequest({
      subject: ALICE,
      format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' }), '');
    note(!!f.picker,
         '4j. a transient NameID names a session of another sign-in, not ' +
         'an account: no hint, so the picker', JSON.stringify(f.picker));
    const rowsBefore = ambiguousRows();
    f = await drive(jar, authnRequest({ passive: true }), '');
    note(f.saml && f.saml.codes.indexOf('NoPassive') >= 0 &&
         /signed in to 2 accounts/.test(f.saml.message) &&
         ambiguousRows() === rowsBefore + 1,
         '4k. IsPassive with a choice to make is NoPassive, saying so, with ' +
         'an account.ambiguous row', JSON.stringify({ saml: f.saml,
           rows: ambiguousRows() - rowsBefore }));
    f = await drive(jar, authnRequest({ passive: true, subject: ALICE }), '');
    note(f.saml && f.saml.codes[0] === 'Success' && f.saml.nameId === ALICE,
         '4l. IsPassive with a <Subject> naming alice is answered as alice',
         JSON.stringify(f.saml));

    // --- SAML 1.1 ----------------------------------------------------------
    f = await drive(jar, '/saml11/sso?providerId=urn%3Amap%3Asaml11&shire=' +
                    encodeURIComponent('https://rp11.map.test/acs') +
                    '&target=t-' + SUFFIX, '');
    note(!!f.picker,
         '5. SAML 1.1 (no hint, no IsPassive in the profile): the picker',
         JSON.stringify({ picker: f.picker, status: f.final.status,
                          location: f.final.headers &&
                            f.final.headers.location }));

    // --- WS-Federation -----------------------------------------------------
    const wsfed = '/wsfed?wa=wsignin1.0&wtrealm=' +
      encodeURIComponent('urn:map:wsfed:' + SUFFIX) + '&wreply=' +
      encodeURIComponent('https://wsfed.map.test/');
    f = await drive(jar, wsfed, '');
    note(!!f.picker, '6a. WS-Federation with nothing to choose by: the picker',
         JSON.stringify({ picker: f.picker, status: f.final.status }));
    f = await drive(jar, wsfed + '&wfresh=0', '');
    note(!f.picker && !!f.screenAt,
         '6b. wfresh asks for a fresh authentication: the sign-in screen, ' +
         'never the picker, whose choice the return trip (which drops ' +
         'wfresh) would answer however old',
         JSON.stringify({ picker: f.picker, screen: f.screenAt }));

    // --- Session Management -----------------------------------------------
    const authorize = function (extra) {
      return '/oauth2/authorize?' + new URLSearchParams(Object.assign({
        client_id: 'map-rp-' + SUFFIX, response_type: 'code',
        redirect_uri: REDIRECT, scope: 'openid',
        state: 's-' + crypto.randomBytes(4).toString('hex'),
        nonce: 'n-' + crypto.randomBytes(4).toString('hex')
      }, extra || {})).toString();
    };
    const paramsOf = function (res) {
      const loc = String((res && res.headers && res.headers.location) || '');
      const at = loc.indexOf('?');
      return loc.indexOf(REDIRECT) === 0 && at > 0
        ? new URLSearchParams(loc.slice(at + 1)) : new URLSearchParams();
    };
    f = await drive(jar, authorize({ login_hint: ALICE }), '');
    const aliceState = paramsOf(f.final).get('session_state') || '';
    const listed = String(jar[sm.COOKIE] || '').split('.');
    const holds = function (sessionState, browserState) {
      const salt = String(sessionState).split('.').pop();
      return stsCrypto.sessionStateHash('map-rp-' + SUFFIX, RP, browserState,
                                        salt) === sessionState;
    };
    note(!!aliceState && listed.length === 2 && listed.some(function (bs) {
      return holds(aliceState, bs);
    }), '7a. on: the browser-state cookie lists BOTH accounts\' states, ' +
         'and alice\'s session_state is over hers',
         JSON.stringify({ cookie: jar[sm.COOKIE], code:
                          paramsOf(f.final).get('code') }));
    f = await drive(jar, authorize({ login_hint: BOB }), '');
    const bobState = paramsOf(f.final).get('session_state') || '';
    r = await get({}, sm.SCRIPT_PATH);
    note(r.text === sm.IFRAME_SCRIPT_ACCOUNTS && r.text !== sm.IFRAME_SCRIPT,
         '7b. and the script served is the one that reads the list');
    const ask = async function (cookie, state) {
      const answers = [];
      let handler = null;
      const context = vm.createContext({
        window: { addEventListener: function (type, fn) {
          if (type === 'message') {
            handler = fn;
          }
        }, crypto: crypto.webcrypto },
        document: { cookie: cookie }, btoa: btoa, TextEncoder: TextEncoder,
        Uint8Array: Uint8Array, String: String });
      vm.runInContext(r.text, context);
      handler({ data: 'map-rp-' + SUFFIX + ' ' + state, origin: RP,
                source: { postMessage: function (text) {
                  answers.push(text);
                } } });
      for (let i = 0; i < 500 && !answers.length; i++) {
        await new Promise(function (done) { setTimeout(done, 10); });
      }
      return answers[0] || '(no answer)';
    };
    const cookieLine = sm.COOKIE + '=' + String(jar[sm.COOKIE] || '');
    const aOk = await ask(cookieLine, aliceState);
    const bOk = await ask(cookieLine, bobState);
    const aliceOnly = listed.filter(function (bs) {
      return holds(aliceState, bs);
    })[0] || '';
    const bobGone = await ask(sm.COOKIE + '=' + aliceOnly, bobState);
    note(aOk === 'unchanged' && bOk === 'unchanged' && bobGone === 'changed',
         '7c. the iframe answers unchanged to either account\'s relying ' +
         'party, and changed once that account\'s state is gone',
         JSON.stringify({ alice: aOk, bob: bOk, bobGone: bobGone }));
    config.clearOverride('oauth2.sessionManagement');

    // --- GNAP --------------------------------------------------------------
    const CLIENT = 'map-gnap-' + SUFFIX;
    applications.createApplication({ identifier: CLIENT, kind: 'gnap-client',
      protocols: ['gnap'], fields: {} });
    const grantFor = function (userHint) {
      return inRealm(function () {
        const now = Math.floor(Date.now() / 1000);
        const grant = store.newGrant({
          as: 'default', grantEndpoint: ORIGIN + '/gnap',
          client: { identifier: CLIENT, key: null, proof: 'httpsig',
                    display: { name: 'MAP client', declared: ['name'] } },
          request: { tokens: [{ label: '', bearer: false, access: [
            'map-ref-' + SUFFIX] }], multiple: false, subject: null,
                     interact: null },
          userHint: userHint || undefined,
          ro: null, decision: null, delivered: false, polls: 0,
          approval: 'pending', grantExpiresAt: now + 3600,
          subjectAuthorizedBy: null, finalization: null, requirement: null,
          ownerApproval: null });
        const interaction = {
          modes: {}, finish: null,
          serverNonce: 'map-sn-' + crypto.randomBytes(6).toString('hex'),
          expiresAt: now + 600, started: 'redirect', decided: false,
          decision: null, interactRef: null, approvalId: store.handle(18) };
        store.putInteraction('approve:' + interaction.approvalId, grant.id);
        grant.interaction = interaction;
        grant.state = store.STATE.PENDING;
        grant.expiresAt = interaction.expiresAt;
        store.saveGrant(grant, 'made by the test');
        return { id: grant.id,
                 page: '/gnap/approve/' + interaction.approvalId,
                 api: '/gnap-api/approve/' + interaction.approvalId };
      });
    };
    const grantRow = function (id) {
      return inRealm(function () {
        return store.getGrant ? store.getGrant(id) : null;
      });
    };
    const forAlice = grantFor(ALICE);
    r = await get(jar, forAlice.page);
    let v = await json(jar, 'GET', forAlice.api);
    note(r.status === 200 && v.json && v.json.view &&
         v.json.view.username === ALICE,
         '8a. GNAP: a grant whose user is alice is approved as alice, the ' +
         'page\'s own API call included', JSON.stringify({ status: r.status,
           view: v.json && v.json.view && v.json.view.username }));
    const anyone = grantFor('');
    f = await drive(jar, anyone.page, '');
    note(!!f.picker, '8b. a grant naming nobody: the account picker',
         JSON.stringify({ picker: f.picker, status: f.final.status }));
    const gp = await pick(jar, f.picker, BOB);
    r = await get(jar, gp.location);
    v = await json(jar, 'GET', anyone.api);
    const row = grantRow(anyone.id);
    note(r.status === 200 && v.json && v.json.view &&
         v.json.view.username === BOB &&
         (!row || (row.interaction && row.interaction.accountSid ===
                   liveFor(BOB)[0])),
         '8c. bob chosen at the picker: the page, and the page\'s own API ' +
         'call (which carries no ticket), act as bob',
         JSON.stringify({ status: r.status, view: v.json && v.json.view &&
           v.json.view.username, recorded: row && row.interaction &&
           row.interaction.accountSid }));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'multi-account-protocols-' +
                        process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|SAML|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', MAP_ROOT: ROOT,
                                  MAP_OUT: out,
                                  MAP_SCRIPT_SHA: SCRIPT_BEFORE_561 }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  if (t.check(Array.isArray(findings), 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'multi_account_protocols',
  describe: 'several signed-in accounts in one browser (#561), the protocol ' +
            'sign-ins: SAML 2.0 hints, ForceAuthn and IsPassive, SAML 1.1 ' +
            'and WS-Federation through the picker and wfresh, Session ' +
            'Management\'s list of browser states, GNAP\'s user hint and ' +
            'its page\'s calls — and with the setting off, today\'s ' +
            'behaviour',
  run: run
};
