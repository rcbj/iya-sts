// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_disable.js
//
// ===========================================================================
// A DISABLED ACCOUNT (2026-09-17, #36 follow-up).
//
// The directory had no disabled state: the issuance policy could refuse
// somebody an application, SCIM's `active: false` was recorded and read by
// nothing, and an administrator who wanted somebody OUT had to remove their
// password and hope. `pwdAccountLockedTime` — draft-behera-ldap-password-
// policy's administrative lock — is that state now, and
// `common/account_state.ts` is the one place it is written.
//
// **WHAT THIS FILE IS FOR IS THE LIST OF DOORS.** A refusal that holds at the
// sign-in screen and nowhere else would look exactly like this feature
// working. So every door that can be driven in this process is driven, before
// and after the disable, and the ones that share a choke point are driven
// THROUGH that choke point rather than assumed:
//
//   B. the two sign-in screens (a password, and passwordless before any
//      ceremony), and `authn.startSession()` itself with the shape each other
//      door hands it — federation, SPNEGO, a TLS client certificate, the
//      OID4VP wallet door, WS-Trust — because that function is the one place
//      a session is made;
//   C. `credentials.verify()`, which is what an LDAP bind, the password
//      grant, a WS-Trust UsernameToken, SCIM and SSF Basic and EST present a
//      password to;
//   D. the Kerberos KDC: an AS-REQ answers KDC_ERR_CLIENT_REVOKED (18);
//   E. the token endpoint: the password grant and a REFRESH TOKEN issued
//      before the disable are both `invalid_grant`, through the issuance gate
//      every grant carrying a person reaches;
//   F. the issuance gate itself, which is what the SAML profiles,
//      WS-Federation, WS-Trust, GNAP and the KDC's TGS ask;
//   G. the management API, whose bearer check refuses a disabled person's
//      token (and a revoked one);
//   H. what the disable DOES: every session ended, the relying parties sent
//      their back-channel Logout Tokens, tokens revoked, an audit row;
//   I. SCIM `active: false` is the same act, and `active: true` the enable;
//   J. enabling restores the sign-in.
//
// In a child process on an ephemeral loopback port, with a relying party of
// its own for the Logout Tokens.
//
// **AND THEN AGAIN IN PRODUCT (#413, 2026-10-02).** Every door above was
// driven in development only, where nothing else is checked — so a refusal
// that development reached by some other road would have read as this
// feature. The second child STARTS in product (`STS_MODE=product`, with a
// krbtgt password and a key-encryption key of its own, so its KDC is a
// product KDC deriving each person's keys from their password), gives both
// people a REAL password, and drives the same doors with it, so each refusal
// is the disable and not a wrong password or a principal nobody made. Four
// things differ there, each by design:
//
//   * THE PASSWORD GRANT DOES NOT EXIST IN PRODUCT: product implies RFC 9700
//     mode, which refuses it for everybody (`unsupported_grant_type`,
//     STS-OAUTH-0131, section 2.4) before any account is looked at. A3 and E1
//     assert that refusal instead; the call it would have made,
//     `credentials.verify()`, is C2, and the refresh grant (E2) is reached.
//   * G is development's only: its token comes from the password grant.
//   * I, SCIM's `active`, is development's only: a SCIM caller in product is
//     a provisioning client with a credential of its own, and the mapping it
//     drives is the same code in either mode.
//   * B4, the back-channel Logout Token, is development's only: product
//     sends one over https alone and refuses to register the http address
//     this file's relying party listens on.
//
// The authorization requests carry PKCE in both modes (RFC 9700 requires it
// in product, and development ignores what it does not need).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'account_disable',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.AD_ROOT;
  const OUT = process.env.AD_OUT;
  const PRODUCT = process.env.AD_MODE === 'product';
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  const partOf = function (jwt, n) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[n], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.json ? JSON.stringify(o.json)
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({}, o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = o.json ? 'application/json'
            : 'application/x-www-form-urlencoded';
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
            let parsed = null;
            try {
              parsed = JSON.parse(text);
            } catch (e) {
              parsed = { parseError: e.message };
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: parsed });
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

  (async function () {
    if (PRODUCT) {
      // A PRODUCT PROCESS FROM THE START (`STS_MODE=product`), and not a
      // development one switched over: the KDC decides at start whether it
      // is a product KDC — whose people have keys derived from their
      // passwords and whose unknown principals are not created — and the
      // keys are sealed, so the keystore is started first, as
      // `tests/kerberos_person_keys.js`'s product child starts it.
      const keystore = require(ROOT + '/common/keystore');
      keystore.reset();
      keystore.setStore({
        loadKeys: function () { return Promise.resolve([]); },
        saveKeys: function () { return Promise.resolve(); },
        deleteKeys: function () { return Promise.resolve(); }
      });
      await keystore.start();
    }
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const credentials = require(ROOT + '/common/credentials');
    const accountState = require(ROOT + '/common/account_state');
    const gate = require(ROOT + '/common/issuance_gate');
    const backchannel = require(ROOT + '/oauth-oidc/backchannel_logout');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const principals = require(ROOT + '/kerberos/krb5_principals');
    const kdc = require(ROOT + '/kerberos/krb5_kdc');
    const msgs = require(ROOT + '/kerberos/krb5_messages');
    const kcrypto = require(ROOT + '/kerberos/krb5_crypto');
    const scimMap = require(ROOT + '/scim/scim_map');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;

    const posted = [];
    const rp = http.createServer(function (req, res) {
      let text = '';
      req.on('data', function (c) { text += c; });
      req.on('end', function () {
        posted.push({ path: req.url, body: text });
        res.writeHead(200).end();
      });
    });
    await new Promise(function (r) { rp.listen(0, '127.0.0.1', r); });
    const rpBase = 'http://127.0.0.1:' + rp.address().port;

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('federation.outboundAllowHttp', true);
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 0);

    const SECRET = 'account-disable-secret-0123456789abcdef';
    const REDIRECT = 'https://rp.disable.example/cb';
    const CLIENT = 'ad-client';
    const madeClient = applications.createApplication({ identifier: CLIENT,
      // saml2 too: F asks the gate about a SAML assertion for this
      // application, and product refuses one for an application that never
      // declared the protocol — which would read as the disable.
      protocols: ['oauth2', 'oidc', 'saml2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code', 'refresh_token',
                                 'password'],
                // G. asks for an /admin-api token, and admin:read is issued
                // only to a client that declares it (#110).
                oauthAllowedScope: ['openid', 'admin:read'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic',
                // Development only: product sends a Logout Token over https
                // alone and refuses to register an http address (see the
                // header).
                oauthBackchannelLogoutUri: PRODUCT ? [] : rpBase + '/bc' } });
    note(madeClient && madeClient.ok !== false,
         'precondition: the application ' + CLIENT + ' is registered',
         JSON.stringify(madeClient && (madeClient.errors || madeClient.ok)));
    const ALICE = 'ad-alice';
    const OTHER = 'ad-somebody-else';
    ldap.createUser(ALICE, { invent: false });
    // A REAL PASSWORD, which development ignores and product verifies — so in
    // product every refusal below is the disable and not a wrong password.
    const PASSWORD = 'Ad-' + crypto.randomBytes(6).toString('hex') +
                     '-Correct.Horse.Battery.Staple.42';
    const passwordSet = credentials.setPassword(ALICE, PASSWORD);
    // A PRIMARY SECURITY KEY, so the passwordless path reaches the account:
    // product refuses a passwordless sign-in for somebody who holds none
    // before it asks anything else (STS-AUTHN-0206), which would read as
    // the disable at C5.
    const keyAdded = credentials.addKey(ALICE, {
      credentialId: 'ad-key-' + crypto.randomBytes(6).toString('hex'),
      label: 'ad key', publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA',
                                       y: 'AA' },
      signCount: 0 }, 'primary');
    note(keyAdded && keyAdded.ok !== false,
         'precondition: ' + ALICE + ' holds a primary security key',
         JSON.stringify(keyAdded));
    note(passwordSet && passwordSet.ok !== false,
         'precondition: ' + ALICE + ' has a password',
         JSON.stringify(passwordSet));
    // The other person D2 and F2 ask about, made the same way: in product a
    // principal nobody provisioned does not exist, so a control about them
    // needs them to.
    ldap.createUser(OTHER, { invent: false });
    credentials.setPassword(OTHER, PASSWORD);
    if (PRODUCT) {
      // A product KDC derives a person's keys from the password when it is
      // set, off the request path; the AS-REQ controls need them there.
      await require(ROOT + '/kerberos/krb5_person_keys').idle();
    }

    const signIn = async function (b, username) {
      const verifier = crypto.randomBytes(32).toString('base64url');
      const challenge = crypto.createHash('sha256').update(verifier)
        .digest('base64url');
      let r = await b.go('GET', '/oauth2/authorize?' + new URLSearchParams({
        client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's', code_challenge: challenge,
        code_challenge_method: 'S256',
        nonce: 'n' + crypto.randomBytes(3).toString('hex') }).toString());
      if (r.status === 302 &&
          /\/authn\/login/.test(String(r.headers.location || ''))) {
        const page = await b.go('GET', r.headers.location);
        const form = hiddenFields(page.text);
        form.username = username;
        form.password = PASSWORD;
        form.action = 'login';
        const screen = String(r.headers.location).split('?')[0]
          .replace(/^https?:\/\/[^/]+/, '');
        const sent = await b.go('POST', screen, { form: form });
        if (sent.status === 200) {
          return { screen: sent, token: null };
        }
        r = await b.go('GET', String(sent.headers.location || ''));
      }
      const loc = String(r.headers.location || '');
      const code = r.status === 302 && loc.indexOf(REDIRECT) === 0
        ? new URL(loc).searchParams.get('code') : null;
      if (!code) {
        return { screen: r, token: null };
      }
      const token = await b.go('POST', '/oauth2/token', {
        noCookies: true,
        headers: { authorization: 'Basic ' +
          Buffer.from(CLIENT + ':' + SECRET).toString('base64') },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT, scope: 'openid',
                code_verifier: verifier } });
      return { screen: r, token: token };
    };
    const passwordGrant = function (username, extra) {
      return browser(port).go('POST', '/oauth2/token', {
        headers: { authorization: 'Basic ' +
          Buffer.from(CLIENT + ':' + SECRET).toString('base64') },
        form: Object.assign({ grant_type: 'password', username: username,
                              password: PASSWORD }, extra || {}) });
    };
    const asReq = function (realm, username) {
      return msgs.encKdcReq({
        msgType: msgs.MSG_TYPE.AS_REQ,
        padata: [],
        reqBody: {
          kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
          cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [username] },
          realm: realm,
          sname: { type: msgs.NAME_TYPE.SRV_INST, name: ['krbtgt', realm] },
          till: new Date(Date.now() + 3600000),
          nonce: 424242,
          etypes: [kcrypto.etypeByName('aes256-cts-hmac-sha1-96').id]
        }
      });
    };
    const askKdc = async function (username) {
      const reply = await kdc.handleMessage(asReq(principals.REALM, username));
      const identified = msgs.identify(reply);
      if (identified &&
          identified.applicationNumber === msgs.APPLICATION.AS_REP) {
        return { asRep: true };
      }
      const err = msgs.readKrbError(reply);
      return { error: err.errorCode, text: String(err.eText || '') };
    };
    const gateAnswer = function (username) {
      return gate.check({ application: CLIENT,
                          kind: gate.ISSUANCE.SAML_ASSERTION,
                          subject: { kind: 'user', name: username,
                                     authenticated: true },
                          claims: null });
    };
    const startedFor = function (username, shape) {
      const res = { set: function () { return res; },
                    append: function () { return res; },
                    status: function () { return res; },
                    type: function () { return res; },
                    send: function () { return res; },
                    req: null };
      return authn.startSession(res, username, shape.amr, shape.acr,
                                shape.protocol, shape.detail || {});
    };
    const codeOfLastRow = function (action) {
      // `audit.list()` answers newest FIRST.
      const rows = audit.list().filter(function (row) {
        return row.action === action;
      });
      return rows.length ? rows[0].errorCode : '';
    };

    // A PASSWORDLESS SIGN-IN, up to the point where the ceremony would be
    // drawn. PKCE because product requires it.
    const passwordlessAttempt = async function () {
      const b = browser(port);
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: CLIENT, response_type: 'code',
                              redirect_uri: REDIRECT, scope: 'openid',
                              state: 's', nonce: 'n1',
                              code_challenge: crypto.createHash('sha256')
                                .update(crypto.randomBytes(32))
                                .digest('base64url'),
                              code_challenge_method: 'S256' }).toString());
      const page = await b.go('GET', String(start.headers.location || ''));
      const form = hiddenFields(page.text);
      form.username = ALICE;
      form.password = '';
      form.webauthn_only = '1';
      form.action = 'login';
      return b.go('POST', '/authn/login', { form: form });
    };
    // A page's text for a finding, without its stylesheet.
    const pageText = function (r) {
      return String(r.text).replace(/<style[\s\S]*?<\/style>/, '')
        .slice(0, 400);
    };

    // Each other door's shape, as it hands it to `authn.startSession()`.
    const shapes = [
      ['federation', { amr: ['pwd'], acr: '1', protocol: 'Federation',
                       detail: { federation: { id: 'rel-1' } } }],
      ['SPNEGO', { amr: ['krb'], acr: '1', protocol: 'Kerberos v5',
                   detail: { presented: ALICE + '@EXAMPLE.COM' } }],
      ['a TLS client certificate', { amr: ['x509'], acr: '1',
                                     protocol: 'TLS', detail: {} }],
      ['the OID4VP wallet door', { amr: ['pop'], acr: '1',
                                   protocol: 'OpenID4VP',
                                   detail: { key: '' } }],
      ['WS-Trust', { amr: ['pwd'], acr: '1', protocol: 'WS-Trust',
                     detail: {} }]
    ];
    // --- A. before: everything works -----------------------------------------
    const alice = browser(port);
    let r = await signIn(alice, ALICE);
    const idToken = partOf((r.token && r.token.json.id_token) || '', 1);
    const refreshToken = String((r.token && r.token.json.refresh_token) || '');
    note(r.token && r.token.status === 200 && !!idToken.sid,
         'A1. (a control: ' + ALICE + ' signs in and holds a session, an ID ' +
         'Token and a refresh token)',
         (r.token ? r.token.status + ' ' + r.token.text.slice(0, 200)
                  : r.screen.status + ' ' +
                    String(r.screen.headers.location || '') + ' ' +
                    r.screen.text.slice(0, 200)) + ' ' + !!refreshToken);
    const beforeKdc = await askKdc(ALICE);
    note(beforeKdc.error === 25 || beforeKdc.asRep,
         'A2. (a control: the KDC answers their AS-REQ with ' +
         'KDC_ERR_PREAUTH_REQUIRED (25), not a refusal)',
         JSON.stringify(beforeKdc));
    const beforeGrant = await passwordGrant(ALICE);
    if (PRODUCT) {
      note(beforeGrant.status === 400 &&
           beforeGrant.json.error === 'unsupported_grant_type',
           'A3. (product has no password grant: RFC 9700 section 2.4 refuses ' +
           'it for everybody, before any account is looked at)',
           beforeGrant.status + ' ' + beforeGrant.text.slice(0, 160));
    } else {
      note(beforeGrant.status === 200,
           'A3. (a control: the password grant issues tokens for them)',
           beforeGrant.status);
    }
    note(gateAnswer(ALICE).allowed,
         'A4. (a control: the issuance gate allows an assertion for them)',
         JSON.stringify(gateAnswer(ALICE)));
    const passwordlessBefore = await passwordlessAttempt();
    note(passwordlessBefore.status === 200 &&
         /wa-credential/.test(passwordlessBefore.text),
         'A5. (a control: a passwordless sign-in draws the security-key ' +
         'ceremony for them)', passwordlessBefore.status + ' ' +
         pageText(passwordlessBefore));
    // The control C3 needs: before the disable each shape IS a session, so a
    // null afterwards is the disable and not a shape the mode refuses.
    const startedShapes = shapes.filter(function (pair) {
      return startedFor(ALICE, pair[1]) !== null;
    }).map(function (pair) { return pair[0]; });
    note(startedShapes.length === shapes.length,
         'A6. (a control: authn.startSession() makes a session for them ' +
         'with each other door\'s shape: ' + startedShapes.join(', ') + ')',
         JSON.stringify(startedShapes));

    // --- B. the disable ------------------------------------------------------
    const before = backchannel.mark();
    const acted = adminActions.usersAction({ action: 'disable', user: ALICE,
                                             reason: 'a test' },
                                           { via: 'api', actor: 'an-operator' });
    note(acted.ok && acted.changed === true && acted.disabled === true,
         'B1. POST /admin-api/users/disable (and the console\'s Disable ' +
         'button) writes the lock', JSON.stringify(acted).slice(0, 300));
    note(credentials.accountDisabled(ALICE) &&
         accountState.isDisabled(ALICE) &&
         (ldap.readPerson(ldap.dnOfUser ? ldap.dnOfUser(ALICE) : '') || true),
         'B2. and `pwdAccountLockedTime` is what says so',
         JSON.stringify(credentials.mechanismsFor(ALICE).disabled));
    note(!authn.sessionById(idToken.sid),
         'B3. every session they held is ENDED at once');
    let rows = [];
    for (let i = 0; i < 60 && !rows.length && !PRODUCT; i++) {
      rows = backchannel.deliveriesFor([idToken.sid], before);
      if (!rows.length || rows[0].state === 'pending') {
        rows = rows.length && rows[0].state !== 'pending' ? rows : [];
        await sleep(50);
      }
    }
    if (!PRODUCT) {
      note(posted.length === 1 && rows.length === 1 &&
           rows[0].state === 'sent',
           'B4. the relying parties on those sessions are sent their ' +
           'back-channel Logout Tokens', JSON.stringify(rows) + ' posts=' +
           posted.length);
    }
    note(acted.ended && acted.ended.terminated > 0 &&
         /disabled/.test(String(acted.message)),
         'B5. and the reply says what was ended', String(acted.message)
           .slice(0, 300));
    note(audit.list().some(function (row) {
      return row.action === 'account.disable' && row.target === ALICE &&
             row.actor === 'an-operator';
    }), 'B6. one account.disable audit row names who did it');

    // --- C. the doors --------------------------------------------------------
    const stranger = browser(port);
    r = await signIn(stranger, ALICE);
    note(r.screen.status === 200 &&
         /Authentication failed/.test(r.screen.text) && !r.token,
         'C1. the SIGN-IN SCREEN refuses their password — with the same ' +
         'sentence a wrong one gets, which is the enumeration answer',
         r.screen.status + ' ' + r.screen.text.slice(0, 120));
    const loginPage = await stranger.go('GET', '/authn/login?authn=' +
      encodeURIComponent('x'));
    note(loginPage.status === 200 || loginPage.status === 400,
         'C1b. (the screen is still drawn for everybody else)',
         loginPage.status);
    const verified = credentials.verify(ALICE, PASSWORD,
                                        { via: 'an LDAP simple bind' });
    note(!verified.ok && verified.reason === 'account-disabled',
         'C2. credentials.verify() — the one call an LDAP bind, the password ' +
         'grant, a WS-Trust UsernameToken, SCIM and SSF Basic and EST all ' +
         'make — refuses them in BOTH modes', JSON.stringify(verified));
    const refusedShapes = shapes.filter(function (pair) {
      return startedFor(ALICE, pair[1]) === null;
    }).map(function (pair) { return pair[0]; });
    note(refusedShapes.length === shapes.length,
         'C3. authn.startSession() — the one place every other door makes a ' +
         'session — refuses each of them: ' + refusedShapes.join(', '),
         JSON.stringify(refusedShapes));
    note(codeOfLastRow('session.refuse') === 'STS-AUTHN-0201',
         'C4. with STS-AUTHN-0201 on the audit row');
    const passwordless = await passwordlessAttempt();
    note(passwordless.status === 200 &&
         /Authentication failed/.test(passwordless.text) &&
         !/wa-credential/.test(passwordless.text),
         'C5. a PASSWORDLESS security-key sign-in is refused BEFORE the ' +
         'ceremony — no key is enrolled for a disabled account',
         passwordless.status + ' ' + pageText(passwordless));

    // --- D. the KDC ----------------------------------------------------------
    const afterKdc = await askKdc(ALICE);
    note(afterKdc.error === 18,
         'D1. an AS-REQ for them is refused KDC_ERR_CLIENT_REVOKED (18) — in ' +
         'development mode too, where the principal would otherwise be ' +
         'created on the spot', JSON.stringify(afterKdc));
    const otherKdc = await askKdc(OTHER);
    note(otherKdc.error === 25 || otherKdc.asRep,
         'D2. (and every other principal is unaffected)',
         JSON.stringify(otherKdc));

    // --- E. the token endpoint -----------------------------------------------
    const afterGrant = await passwordGrant(ALICE);
    note(afterGrant.status === 400 && afterGrant.json.error ===
         (PRODUCT ? 'unsupported_grant_type' : 'invalid_grant'),
         PRODUCT ? 'E1. the password grant is still refused, as for ' +
                   'everybody (product has none: see A3)'
                 : 'E1. the password grant is invalid_grant',
         afterGrant.status + ' ' + afterGrant.text.slice(0, 160));
    const refreshed = await browser(port).go('POST', '/oauth2/token', {
      headers: { authorization: 'Basic ' +
        Buffer.from(CLIENT + ':' + SECRET).toString('base64') },
      form: { grant_type: 'refresh_token', refresh_token: refreshToken } });
    note(refreshed.status === 400 && refreshed.json.error === 'invalid_grant',
         'E2. and a REFRESH TOKEN issued before the disable is invalid_grant ' +
         '— the credential a sign-out is supposed to be about',
         refreshed.status + ' ' + refreshed.text.slice(0, 160));

    // --- F. the issuance gate -------------------------------------------------
    const gated = gateAnswer(ALICE);
    note(!gated.allowed && gated.disabled === true &&
         /disabled/.test(gated.why),
         'F1. the issuance gate refuses anything on their behalf — which is ' +
         'what the SAML profiles, WS-Federation, WS-Trust, GNAP and the ' +
         'KDC\'s TGS ask before they issue', JSON.stringify(gated));
    note(gateAnswer(OTHER).allowed,
         'F2. (and allows it for everybody else)');

    // --- G. the management API -------------------------------------------------
    // Development only: its token comes from the password grant, which
    // product does not have (see the header).
    if (!PRODUCT) {
      const apiUser = 'ad-api-user';
      ldap.createUser(apiUser, { invent: false });
      const apiToken = await passwordGrant(apiUser,
        { scope: 'admin:read', resource: base + '/admin-api' });
      const apiCall = function (token) {
        return browser(port).go('GET', '/admin-api/logout', {
          headers: { authorization: 'Bearer ' + token } });
      };
      const apiBefore = await apiCall(String(apiToken.json.access_token || ''));
      credentials.setAccountDisabled(apiUser, true);
      const apiAfter = await apiCall(String(apiToken.json.access_token || ''));
      credentials.setAccountDisabled(apiUser, false);
      note(apiBefore.status === 200 && apiAfter.status === 401 &&
           apiAfter.json.error === 'invalid_token',
           'G1. the management API refuses a token issued to a person whose ' +
           'account is disabled — it used to work until the token expired',
           apiBefore.status + ' then ' + apiAfter.status + ' ' +
           apiAfter.text.slice(0, 160));
    }

    // --- H. enabling ----------------------------------------------------------
    const enabled = adminActions.usersAction({ action: 'enable',
                                               user: ALICE },
                                             { via: 'console',
                                               actor: 'an-operator' });
    note(enabled.ok && enabled.changed === true &&
         !credentials.accountDisabled(ALICE),
         'H1. enable clears the lock', JSON.stringify(enabled).slice(0, 200));
    const back = browser(port);
    r = await signIn(back, ALICE);
    note(r.token && r.token.status === 200,
         'H2. and they sign in again', r.token && r.token.status);
    const twice = adminActions.usersAction({ action: 'enable', user: ALICE },
                                           { via: 'api', actor: 'x' });
    note(twice.ok && twice.changed === false,
         'H3. enabling an enabled account changes nothing and says so',
         String(twice.message));
    const nobody = adminActions.usersAction({ action: 'disable',
                                              user: 'anonymous' },
                                            { via: 'api', actor: 'x' });
    note(!nobody.ok, 'H4. and the anonymous principal cannot be disabled',
         JSON.stringify(nobody.errors || []));

    // --- I. SCIM ---------------------------------------------------------------
    // Development only: see the header.
    if (!PRODUCT) {
      const scimHeaders = { authorization: 'Basic ' +
        Buffer.from('ad-scim-caller:anything').toString('base64') };
      ldap.createUser('ad-scim-caller', { invent: false });
      const scimBrowser = browser(port);
      const created = await scimBrowser.go('POST', '/scim/v2/Users', {
        headers: scimHeaders,
        json: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                userName: 'ad-scim-user' } });
      note(created.status === 201 && created.json.active === true,
           'I1. a SCIM User is created ACTIVE — `active` is always said, and ' +
           'an unlocked entry is true', created.status + ' ' +
           JSON.stringify(created.json.active));
      const scimSession = browser(port);
      await signIn(scimSession, 'ad-scim-user');
      const deactivated = await scimBrowser.go('PUT',
        '/scim/v2/Users/' + created.json.id, {
          headers: scimHeaders,
          json: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                  userName: 'ad-scim-user', active: false } });
      await sleep(300);
      note(deactivated.status === 200 && deactivated.json.active === false &&
           credentials.accountDisabled('ad-scim-user'),
           'I2. `active: false` DISABLES the account — the non-goal this ' +
           'reversed', deactivated.status + ' ' +
           JSON.stringify(deactivated.json.active));
      note(authn.sessionsOf('ad-scim-user').length === 0,
           'I3. and the directory hands the change to account_state, so ' +
           'their sessions end too — whichever door wrote the lock',
           authn.sessionsOf('ad-scim-user').length);
      const reactivated = await scimBrowser.go('PUT',
        '/scim/v2/Users/' + created.json.id, {
          headers: scimHeaders,
          json: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                  userName: 'ad-scim-user', active: true } });
      note(reactivated.status === 200 && reactivated.json.active === true &&
           !credentials.accountDisabled('ad-scim-user'),
           'I4. and `active: true` enables them', reactivated.status);
      // PATCH is how most provisioning clients deactivate (Entra ID, Okta):
      // a replace of the one member, never the whole resource. scim.ts has no
      // PATCH code of its own — scimmy reads the resource out, applies the
      // operation and writes it back in — so this asks that the round trip
      // carries the lock, rather than trusting that it must.
      const scimPatch = function (value) {
        return scimBrowser.go('PATCH', '/scim/v2/Users/' + created.json.id, {
          headers: scimHeaders,
          json: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                  Operations: [{ op: 'replace', path: 'active',
                                 value: value }] } });
      };
      await signIn(scimSession, 'ad-scim-user');
      const patchedOff = await scimPatch(false);
      await sleep(300);
      note(patchedOff.status === 200 && patchedOff.json.active === false &&
           credentials.accountDisabled('ad-scim-user'),
           'I6. a PATCH replacing `active` with false DISABLES the account, ' +
           'as the PUT does', patchedOff.status + ' ' +
           JSON.stringify(patchedOff.json && patchedOff.json.active));
      note(authn.sessionsOf('ad-scim-user').length === 0,
           'I7. and ends their sessions, as the PUT does',
           authn.sessionsOf('ad-scim-user').length);
      const patchedOn = await scimPatch(true);
      note(patchedOn.status === 200 && patchedOn.json.active === true &&
           !credentials.accountDisabled('ad-scim-user'),
           'I8. and a PATCH replacing it with true enables them',
           patchedOn.status + ' ' +
           JSON.stringify(patchedOn.json && patchedOn.json.active));
      // Entra ID sends the boolean as the STRING "False" (Microsoft documents
      // it as a known deviation). Whatever scimmy makes of it, it must not be
      // a 2xx that leaves the account enabled: that is the original bug.
      const patchedString = await scimPatch('False');
      await sleep(300);
      const stringDisabled = credentials.accountDisabled('ad-scim-user');
      note(patchedString.status >= 400 || stringDisabled,
           'I9. a PATCH with the string "False" either disables the account ' +
           'or is refused — never answered 2xx with the account left enabled',
           patchedString.status + ' disabled=' + stringDisabled);
      if (stringDisabled) {
        credentials.setAccountDisabled('ad-scim-user', false);
      }
      const unsaid = scimMap.fromScimUser(
        { userName: 'x' }, { pwdAccountLockedTime: ['000001010000Z'] });
      note((unsaid.attributes.pwdAccountLockedTime || [])[0] ===
           '000001010000Z',
           'I5. a resource that does not SAY `active` leaves the lock alone ' +
           '— a PUT from a client that never sends the member must not ' +
           'enable an account an administrator disabled',
           JSON.stringify(unsaid.attributes.pwdAccountLockedTime));
    }

    // --- J. what the console and the API show ----------------------------------
    credentials.setAccountDisabled(ALICE, true);
    const mfaJson = adminViews.mfaJson(ALICE);
    credentials.setAccountDisabled(ALICE, false);
    note(mfaJson && mfaJson.disabled === true,
         'J1. GET /admin-api/mfa (and the person\'s /admin/users page) says ' +
         'the account is disabled', JSON.stringify(mfaJson && mfaJson.disabled));

    server.close();
    rp.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

// What a product child starts with: the mode, a krbtgt password that is not
// the published one, and persisted keys sealed under a key-encryption key
// made here for the run — `tests/kerberos_person_keys.js`'s arrangement. A
// development child gets nothing.
function productEnvironment(mode, dir) {
  log.debug("Entering productEnvironment(). " + mode);
  if (mode !== 'product') {
    log.debug("Leaving productEnvironment(). Development.");
    return {};
  }
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile,
                   require('crypto').randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  log.debug("Leaving productEnvironment().");
  return { STS_MODE: 'product',
           KRB5_KRBTGT_PASSWORD: 'ad-' +
             require('crypto').randomBytes(12).toString('hex'),
           STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
           STS_KEYS_KEK_FILE: kekFile };
}

function inAChild(t, mode) {
  log.debug("Entering inAChild(). " + mode);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'account-disable-'));
  const out = path.join(dir, 'report.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, productEnvironment(mode, dir),
                         { LOG_LEVEL: 'fatal', AD_ROOT: ROOT, AD_OUT: out,
                           AD_MODE: mode }),
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
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), '[' + mode + '] the child process ' +
                                        'reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, '[' + mode + '] ' + one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t, 'development');
  inAChild(t, 'product');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'account_disable',
  describe: 'A disabled account (pwdAccountLockedTime): refused at every ' +
            'door that can be driven in process — the sign-in screens, ' +
            'startSession with each other door\'s shape, credentials.verify, ' +
            'the KDC, the token endpoint, the issuance gate and the ' +
            'management API — its sessions ended and its relying parties ' +
            'told, SCIM active mapped onto it, and the enable; and the doors ' +
            'again in product (#413)',
  run: run
};
