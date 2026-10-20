// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: multi_account_logout.js
//
// ===========================================================================
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER (#561): SIGNING OUT.
//
// The plan's section 5, its delivery step 4, over HTTP against the whole
// stack (`logout/CLAUDE.md`, *Several accounts in one browser*):
//
//   OFF (today's behaviour, unchanged):
//   1. the sign-out's account step does not exist (400, STS-LOGOUT-0013),
//      the page's view is the inventory with no `account`, and
//      RP-Initiated Logout with no hint asks to confirm the one session as
//      it always did, then ends it and clears the cookie.
//   ON, a browser holding alice and bob:
//   2. `/logout` draws the account step rather than sending the browser to
//      sign in; its view lists both by key and never a sid; `login_hint`
//      preselects one; the JSON door answers 409 naming them;
//   3. choosing alice leads to her inventory, and her global sign-out ends
//      her sessions and leaves bob's: the default cookie (bob's) is kept,
//      and alice is remembered;
//   4. signing out the browser's DEFAULT clears the cookie and makes the
//      next live account the default;
//   5. an account no longer here is refused (409, STS-LOGOUT-0012), and
//      "every account in this browser" signs every one out;
//   6. RP-Initiated Logout: a verified id_token_hint whose sid is in this
//      browser's set ends THAT session; the same hint presented by another
//      browser ends nothing; with no hint the page asks which account and
//      ends the one chosen;
//   7. SAML 2.0 Single Logout over the front channel ends the session its
//      SessionIndex names in the set, not the default;
//   8. WS-Federation: wsignout1.0 asks which account when more than one
//      signed in to the realm and ends the one chosen; wsignoutcleanup1.0
//      ends every session of the set that signed in to it, asking nobody.
//
// WHY A CHILD PROCESS: the whole protocol stack on a loopback port.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'multi_account_logout',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.MAL_ROOT;
  const OUT = process.env.MAL_OUT;
  const http = require('http');
  const zlib = require('zlib');
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
    const applications = require(ROOT_DIR + '/common/applications');
    const authn = require(ROOT_DIR + '/authn/authn');
    const AccountSets = require(ROOT_DIR + '/authn/account_sets');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const SUFFIX = crypto.randomBytes(3).toString('hex');
    const CLIENT = 'mal-rp-' + SUFFIX;
    const SECRET = 'mal-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.mal.example/cb';
    const SP = 'urn:mal:sp:' + SUFFIX;
    const REALM = 'urn:mal:wsfed:' + SUFFIX;
    const name = function (who) {
      return 'mal-' + who + '-' + SUFFIX;
    };
    config.setOverride('oauth2.consentRequired', false);
    // `logout.anyUser` names somebody else by `username`; the browser's
    // own accounts are what is asked about here.
    config.setOverride('logout.anyUser', 'false');
    applications.createApplication({ identifier: CLIENT, protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthRedirectUri: [REDIRECT],
                oauthClientSecret: SECRET,
                oauthPostLogoutRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    const get = function (jar, p, accept) {
      return screen.call({ port: port, jar: jar, method: 'GET',
        path: p.replace(/^https?:\/\/[^/]+/, ''),
        headers: accept ? { accept: accept } : {} });
    };
    const json = function (jar, method, p, body, csrf) {
      return screen.call({ port: port, jar: jar, method: method,
        path: p.replace(/^https?:\/\/[^/]+/, ''),
        headers: Object.assign({ accept: 'application/json',
          'content-type': 'application/json', origin: ORIGIN },
          csrf ? { 'x-csrf-token': csrf } : {}),
        body: body === undefined ? undefined : JSON.stringify(body) });
    };
    const form = function (jar, p, fields) {
      return screen.call({ port: port, jar: jar, method: 'POST', path: p,
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   origin: ORIGIN },
        body: new URLSearchParams(fields).toString() });
    };
    const inRealm = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
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
    const defaultOf = function (jar) {
      return String(jar[authn.SESSION_COOKIE] || '').split('.')[0];
    };
    const authorize = function (extra) {
      return '/oauth2/authorize?' + new URLSearchParams(Object.assign({
        client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's-' + crypto.randomBytes(4).toString('hex'),
        nonce: 'n-' + crypto.randomBytes(4).toString('hex')
      }, extra || {})).toString();
    };
    // Follows a flow from `start`, signing in as `username` at a screen.
    const drive = async function (jar, start, username) {
      let r = await get(jar, start);
      for (let hop = 0; hop < 12; hop += 1) {
        const to = String((r.headers && r.headers.location) || '');
        if (r.status >= 300 && r.status < 400 && /\/authn\/login\?authn=/
            .test(to) && username) {
          const answer = await screen.submit({ port: port, jar: jar, at: to,
            fields: { action: 'login', username: username, password: 'x' } });
          r = { status: answer.status, headers: answer.headers,
                text: answer.text };
          continue;
        }
        if (r.status >= 300 && r.status < 400 && to &&
            (to.indexOf('http') !== 0 || to.indexOf(ORIGIN) === 0) &&
            !/\/authn\/(accounts|login)\?/.test(to)) {
          r = await get(jar, to);
          continue;
        }
        break;
      }
      return r;
    };
    // An OpenID Connect sign-in as `username` (a fresh one, prompt=login),
    // answering the ID Token the code is exchanged for.
    const oidcSignIn = async function (jar, username) {
      const r = await drive(jar, authorize({ prompt: 'login' }), username);
      const loc = String((r.headers && r.headers.location) || '');
      const code = loc.indexOf(REDIRECT) === 0
        ? new URLSearchParams(loc.slice(loc.indexOf('?') + 1)).get('code')
        : '';
      if (!code) {
        return '';
      }
      const t = await screen.call({ port: port, jar: {}, method: 'POST',
        path: '/oauth2/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   authorization: 'Basic ' + Buffer.from(CLIENT + ':' + SECRET)
                     .toString('base64') },
        body: new URLSearchParams({ grant_type: 'authorization_code',
                                    code: code, redirect_uri: REDIRECT })
          .toString() });
      return String((t.json && t.json.id_token) || '');
    };
    // The page's account step and the forms after it, as the runtime sends
    // them.
    const step = async function (jar, query) {
      await get(jar, '/logout' + (query || ''));
      return json(jar, 'GET', '/authn-api/logout' + (query || ''));
    };

    // =====================================================================
    // OFF
    // =====================================================================
    config.setOverride('authn.multipleAccounts', 'false');
    const off = {};
    await oidcSignIn(off, name('off'));
    let r = await json(off, 'GET', '/authn-api/logout/accounts');
    note(r.status === 400, '1a. off: the account step does not exist (400, ' +
         'STS-LOGOUT-0013)', r.status + ' ' + r.text.slice(0, 200));
    r = await step(off, '');
    note(r.status === 200 && r.json && r.json.view &&
         r.json.view.state === 'inventory' &&
         r.json.view.account === undefined,
         '1b. off: /logout\'s view is the inventory, with no account in it',
         JSON.stringify(r.json && r.json.view && { state: r.json.view.state,
           account: r.json.view.account }));
    r = await get(off, '/oauth2/logout');
    note(r.status === 200 && /name="confirm_for"/.test(r.text) &&
         !/sts_signout_account/.test(r.text),
         '1c. off: RP-Initiated Logout with no hint asks to confirm, as ' +
         'always, and offers no account choice', r.status);
    const confirmFor = (/name="confirm_for" value="([^"]*)"/.exec(r.text) ||
                        [])[1] || '';
    r = await form(off, '/oauth2/logout', { confirm: 'yes',
                                            confirm_for: confirmFor });
    note(liveFor(name('off')).length === 0 && !off[authn.SESSION_COOKIE],
         '1d. off: confirmed, the session ends and the cookie is cleared',
         JSON.stringify({ live: liveFor(name('off')),
                          jar: Object.keys(off) }));

    // =====================================================================
    // ON
    // =====================================================================
    config.setOverride('authn.multipleAccounts', 'true');
    const jar = {};
    await oidcSignIn(jar, name('alice'));
    await oidcSignIn(jar, name('bob'));
    note(liveFor(name('alice')).length === 1 &&
         liveFor(name('bob')).length === 1 &&
         defaultOf(jar) === liveFor(name('bob'))[0],
         '2a. on: alice and bob signed in to one browser, bob the default',
         JSON.stringify({ alice: liveFor(name('alice')),
                          bob: liveFor(name('bob')), dflt: defaultOf(jar) }));
    r = await get(jar, '/logout');
    note(r.status === 200 && /signout\.js/.test(r.text),
         '2b. /logout draws the page (the shell), not a sign-in',
         r.status + ' ' + (r.headers.location || ''));
    r = await json(jar, 'GET', '/authn-api/logout');
    const accounts = (r.json && r.json.view && r.json.view.accounts) || [];
    const keyOf = function (who) {
      return (accounts.filter(function (one) {
        return one.username === name(who);
      })[0] || {}).key || '';
    };
    note(r.json && r.json.view && r.json.view.state === 'accounts' &&
         accounts.length === 2 && !!keyOf('alice') && !!keyOf('bob') &&
         r.text.indexOf(liveFor(name('alice'))[0]) < 0 &&
         r.text.indexOf(liveFor(name('bob'))[0]) < 0,
         '2c. its view is the account step: both accounts by key, no sid',
         r.text.slice(0, 400));
    r = await json(jar, 'GET', '/authn-api/logout?login_hint=' +
                   encodeURIComponent(name('alice')));
    note(r.json && r.json.view && r.json.view.preselected === keyOf('alice'),
         '2d. login_hint preselects alice (the console\'s and the portal\'s ' +
         'tab account)', JSON.stringify(r.json && r.json.view &&
                                        r.json.view.preselected));
    r = await get(jar, '/logout', 'application/json');
    note(r.status === 409 && r.json &&
         r.json.error === 'account_choice_required' &&
         (r.json.accounts || []).length === 2,
         '2e. the JSON door answers 409 account_choice_required, naming ' +
         'the accounts', r.status + ' ' + r.text.slice(0, 200));
    const csrf = (await json(jar, 'GET', '/authn-api/logout')).json.csrf;
    r = await json(jar, 'POST', '/authn-api/logout/accounts',
                   { account: keyOf('alice') }, csrf);
    note(r.status === 200 && r.json && r.json.next === 'inventory' &&
         r.json.location === '/logout?account=' +
           encodeURIComponent(keyOf('alice')),
         '3a. choosing alice answers her sign-out page',
         r.status + ' ' + r.text.slice(0, 300));
    r = await step(jar, '?account=' + encodeURIComponent(keyOf('alice')));
    note(r.json && r.json.view && r.json.view.state === 'inventory' &&
         r.json.view.username === name('alice') &&
         r.json.view.account === keyOf('alice'),
         '3b. her inventory, carrying her account for the forms after it',
         JSON.stringify(r.json && r.json.view && {
           state: r.json.view.state, username: r.json.view.username,
           account: r.json.view.account }));
    const bobDefault = defaultOf(jar);
    r = await json(jar, 'POST', '/authn-api/logout',
                   { scope: 'global', username: name('alice'),
                     account: keyOf('alice') }, r.json.csrf);
    const set = function () {
      const value = String(jar[AccountSets.cookieName()] || '');
      return inRealm(function () {
        return value ? AccountSets.byId(value.split('.')[0]) : null;
      });
    };
    note(r.status === 200 && liveFor(name('alice')).length === 0 &&
         liveFor(name('bob')).length === 1 && defaultOf(jar) === bobDefault &&
         !!set() && !!set().remembered[keyOf('alice')],
         '3c. alice\'s global sign-out ended her session and left bob\'s; ' +
         'the cookie (bob\'s, the default) was kept, and alice is ' +
         'remembered', JSON.stringify({ status: r.status,
           alice: liveFor(name('alice')), bob: liveFor(name('bob')),
           dflt: defaultOf(jar), was: bobDefault }));
    // alice again, now the default; signing her out moves the default.
    await oidcSignIn(jar, name('alice'));
    const aliceSid = liveFor(name('alice'))[0];
    note(defaultOf(jar) === aliceSid, '4a. alice signed in again: she is ' +
         'the default', defaultOf(jar) + ' ' + aliceSid);
    let v = await step(jar, '?account=' + encodeURIComponent(keyOf('alice')));
    r = await json(jar, 'POST', '/authn-api/logout',
                   { scope: 'global', username: name('alice'),
                     account: keyOf('alice') }, v.json.csrf);
    note(liveFor(name('alice')).length === 0 &&
         defaultOf(jar) === liveFor(name('bob'))[0],
         '4b. signing the DEFAULT out cleared the cookie and made the next ' +
         'live account (bob) the default',
         JSON.stringify({ dflt: defaultOf(jar), bob: liveFor(name('bob')) }));
    await oidcSignIn(jar, name('carol'));
    v = await json(jar, 'GET', '/authn-api/logout');
    r = await json(jar, 'POST', '/authn-api/logout/accounts',
                   { account: keyOf('alice') }, v.json.csrf);
    note(r.status === 409 && r.json && r.json.view &&
         r.json.view.state === 'accounts',
         '5a. alice, no longer signed in here, is refused (409, ' +
         'STS-LOGOUT-0012) and the step drawn again', r.status);
    r = await json(jar, 'POST', '/authn-api/logout/accounts',
                   { account: 'all' }, v.json.csrf);
    note(r.status === 200 && r.json && r.json.next === 'signed-out' &&
         liveFor(name('bob')).length === 0 &&
         liveFor(name('carol')).length === 0 && !jar[authn.SESSION_COOKIE],
         '5b. every account in this browser: bob and carol both signed out, ' +
         'and the cookie cleared', JSON.stringify({ status: r.status,
           next: r.json && r.json.next, bob: liveFor(name('bob')),
           carol: liveFor(name('carol')), jar: Object.keys(jar) }));

    // --- RP-Initiated Logout -------------------------------------------------
    // An ID Token carries `sid` while back-channel (or front-channel) logout
    // is on; the hint's sid is what is asked about.
    config.setOverride('oauth2.backchannelLogout', 'true');
    const rp = {};
    const aliceHint = await oidcSignIn(rp, name('rp-alice'));
    await oidcSignIn(rp, name('rp-bob'));
    r = await get({}, '/oauth2/logout?id_token_hint=' +
                  encodeURIComponent(aliceHint));
    note(liveFor(name('rp-alice')).length === 1,
         '6a. alice\'s id_token_hint from ANOTHER browser ends nothing: a ' +
         'bare sid stays untrusted', r.status);
    r = await get(rp, '/oauth2/logout?id_token_hint=' +
                  encodeURIComponent(aliceHint) +
                  '&post_logout_redirect_uri=' + encodeURIComponent(REDIRECT));
    note(!!aliceHint && liveFor(name('rp-alice')).length === 0 &&
         liveFor(name('rp-bob')).length === 1,
         '6b. in this browser the hint\'s sid names alice\'s session in the ' +
         'set: that session ends, bob\'s does not',
         JSON.stringify({ status: r.status, alice: liveFor(name('rp-alice')),
                          bob: liveFor(name('rp-bob')) }));
    await oidcSignIn(rp, name('rp-alice'));
    r = await get(rp, '/oauth2/logout');
    const forms = r.text.split('<form').filter(function (one) {
      return /sts_signout_account/.test(one);
    });
    note(r.status === 200 && forms.length === 2,
         '6c. with no hint and two accounts, the page asks which (a form ' +
         'per account)', r.status + ' ' + forms.length);
    const bobForm = forms.filter(function (one) {
      return one.indexOf(name('rp-bob')) >= 0;
    })[0] || '';
    const fields = {};
    (bobForm.match(/<input type="hidden"[^>]*>/g) || []).forEach(
      function (tag) {
        const n = /name="([^"]+)"/.exec(tag);
        const value = /value="([^"]*)"/.exec(tag);
        if (n) {
          fields[n[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
        }
      });
    fields.confirm = 'yes';
    r = await form(rp, '/oauth2/logout', fields);
    note(liveFor(name('rp-bob')).length === 0 &&
         liveFor(name('rp-alice')).length === 1,
         '6d. choosing bob there ends bob\'s session and only his',
         JSON.stringify({ status: r.status, bob: liveFor(name('rp-bob')),
                          alice: liveFor(name('rp-alice')) }));

    // --- SAML 2.0 Single Logout ---------------------------------------------
    const samlSso = function (subject, force) {
      const xml = '<samlp:AuthnRequest ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_mal' + crypto.randomBytes(8).toString('hex') + '" ' +
        'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
        'AssertionConsumerServiceURL="https://sp.mal.test/acs"' +
        (force ? ' ForceAuthn="true"' : '') + '>' +
        '<saml:Issuer>' + SP + '</saml:Issuer>' + (subject
          ? '<saml:Subject><saml:NameID>' + subject +
            '</saml:NameID></saml:Subject>' : '') + '</samlp:AuthnRequest>';
      return '/saml2/sso?SAMLRequest=' + encodeURIComponent(
        zlib.deflateRawSync(Buffer.from(xml)).toString('base64'));
    };
    const slo = function (nameId, sessionIndex) {
      const xml = '<samlp:LogoutRequest ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_mals' + crypto.randomBytes(8).toString('hex') + '" ' +
        'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
        '<saml:Issuer>' + SP + '</saml:Issuer><saml:NameID>' + nameId +
        '</saml:NameID><samlp:SessionIndex>' + sessionIndex +
        '</samlp:SessionIndex></samlp:LogoutRequest>';
      return '/saml2/slo?SAMLRequest=' + encodeURIComponent(
        zlib.deflateRawSync(Buffer.from(xml)).toString('base64'));
    };
    const saml = {};
    await drive(saml, samlSso('', false), name('sp-bob'));
    await drive(saml, samlSso('', true), name('sp-alice'));
    const spAlice = liveFor(name('sp-alice'))[0];
    const spBob = liveFor(name('sp-bob'))[0];
    note(!!spAlice && !!spBob && defaultOf(saml) === spAlice,
         '7a. bob then alice signed in to one service provider; alice the ' +
         'default', JSON.stringify({ alice: spAlice, bob: spBob,
                                     dflt: defaultOf(saml) }));
    r = await get(saml, slo(name('sp-bob'), spBob));
    note(liveFor(name('sp-bob')).length === 0 &&
         liveFor(name('sp-alice')).length === 1 &&
         defaultOf(saml) === spAlice,
         '7b. a front-channel LogoutRequest whose SessionIndex is bob\'s ' +
         'ends bob\'s session in the set, not the default (alice\'s)',
         JSON.stringify({ status: r.status, bob: liveFor(name('sp-bob')),
                          alice: liveFor(name('sp-alice')),
                          dflt: defaultOf(saml) }));

    // --- WS-Federation ---------------------------------------------------
    const wsfedIn = '/wsfed?wa=wsignin1.0&wtrealm=' +
      encodeURIComponent(REALM) + '&wreply=' +
      encodeURIComponent('https://wsfed.mal.test/');
    const ws = {};
    await drive(ws, wsfedIn, name('ws-alice'));
    await drive(ws, wsfedIn + '&wfresh=0', name('ws-bob'));
    note(liveFor(name('ws-alice')).length === 1 &&
         liveFor(name('ws-bob')).length === 1,
         '8a. alice and bob both signed in to the relying party',
         JSON.stringify({ alice: liveFor(name('ws-alice')),
                          bob: liveFor(name('ws-bob')) }));
    r = await get(ws, '/wsfed?wa=wsignout1.0&wtrealm=' +
                  encodeURIComponent(REALM));
    const links = (r.text.match(/href="[^"]*sts_signout_account=[^"]*"/g) ||
                   []);
    note(r.status === 200 && links.length === 2 &&
         liveFor(name('ws-alice')).length === 1 &&
         liveFor(name('ws-bob')).length === 1,
         '8b. wsignout1.0 asks which account (two links) and ends nothing ' +
         'yet', r.status + ' ' + links.length);
    const bobKey = inRealm(function () {
      const one = authn.sessionById(liveFor(name('ws-bob'))[0]);
      return AccountSets.keyOf({ sub: one.user.sub,
                                 username: one.user.username });
    });
    const bobLink = links.filter(function (one) {
      return one.indexOf(encodeURIComponent(bobKey)) >= 0;
    })[0] || '';
    r = await get(ws, bobLink.replace(/^href="/, '').replace(/"$/, '')
                       .replace(/&amp;/g, '&'));
    note(liveFor(name('ws-bob')).length === 0 &&
         liveFor(name('ws-alice')).length === 1,
         '8c. following bob\'s link ends his session only',
         JSON.stringify({ status: r.status, bob: liveFor(name('ws-bob')),
                          alice: liveFor(name('ws-alice')) }));
    await drive(ws, wsfedIn + '&wfresh=0', name('ws-bob'));
    r = await get(ws, '/wsfed?wa=wsignoutcleanup1.0&wtrealm=' +
                  encodeURIComponent(REALM));
    note(r.status === 200 && liveFor(name('ws-bob')).length === 0 &&
         liveFor(name('ws-alice')).length === 0 &&
         !/sts_signout_account/.test(r.text),
         '8d. wsignoutcleanup1.0 asks nobody and ends every session of the ' +
         'set that signed in to the realm',
         JSON.stringify({ status: r.status, bob: liveFor(name('ws-bob')),
                          alice: liveFor(name('ws-alice')) }));

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
  const out = path.join(os.tmpdir(), 'multi-account-logout-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|SAML|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', MAL_ROOT: ROOT,
                                  MAL_OUT: out }),
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
  name: 'multi_account_logout',
  describe: 'several signed-in accounts in one browser (#561), signing out: ' +
            '/logout\'s account step, the default cookie moving, every ' +
            'account at once, RP-Initiated Logout by id_token_hint sid and ' +
            'by choice, SAML Single Logout by SessionIndex, WS-Federation\'s ' +
            'two sign-outs — and with the setting off, today\'s behaviour',
  run: run
};
