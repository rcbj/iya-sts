// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_wallet.js
//
// ---------------------------------------------------------------------------
// `/portal/wallet`: A CREDENTIAL ABOUT YOURSELF, INTO YOUR OWN WALLET (#589).
//
//   A. THE QR CODE THE BROWSER DRAWS (`portal/web_qr.ts`) is the `qrcode`
//      package's, module for module: every error correction level, every
//      mask, lengths from one byte to the versions an offer reaches. An
//      encoder that is wrong draws a picture that scans as nothing.
//   B. In a child process with the whole stack, a person signed in as the
//      static portal signs in (`tests/vendored/portal_signin.js`):
//        1. `GET /account-api/credentials/offerable` lists the issuer's
//           configurations, with the metadata's names;
//        2. `POST /account-api/credentials/offers` makes a pre-authorized
//           offer FOR THE CALLER — the code's record names them — with the
//           Transaction Code, by value and by reference, and the offer is
//           session-presented on the sign-on session the token was issued on
//           (CAEP, naming OpenID4VCI);
//        3. the code and the Transaction Code redeem at the token endpoint
//           for a token about the caller;
//        4. a body naming somebody else still offers for the caller (the
//           person is the token's), an unknown configuration is refused
//           (STS-PORTAL-0589), no token is refused (401), and a token
//           without `account:manage` gets nothing;
//        5. THE RENDERER ROUND TRIP: the POST's view drawn by the portal's
//           own bundle carries the QR code, the Transaction Code and the
//           open-in-wallet link with the offer by value.
//
// A child process for `account_api.js`'s reason: the stack is built once,
// with a composition root.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'portal_wallet',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PW_ROOT;
  const OUT = process.env.PW_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function brief(r) {
    return r ? r.status + ' ' + String(r.text || '').slice(0, 300) : 'none';
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const http = require('http');
    const app = require(ROOT_DIR + '/common/app');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const offers = require(ROOT_DIR + '/oid4vc/vc_offers');
    const authn = require(ROOT_DIR + '/authn/authn');
    const signin = require(ROOT_DIR + '/tests/vendored/portal_signin');

    const stamp = String(process.pid);
    const ALICE = 'pw-alice-' + stamp;
    const MALLORY = 'pw-mallory-' + stamp;
    const PASSWORD = 'Portal-Wallet-' + stamp + '-Passw0rd!';
    [ALICE, MALLORY].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      credentials.setPassword(name, PASSWORD);
    });

    // THE PRESENTATIONS, as CAEP's observer is told them: the facade is
    // read at the call, so wrapping it here sees every one.
    const presented = [];
    const notePresented = authn.notePresented;
    authn.notePresented = function (session, via, req) {
      presented.push({ via: via, id: session && session.id,
                       user: session && session.user &&
                             session.user.username });
      return notePresented(session, via, req);
    };

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const base = 'http://127.0.0.1:' + server.address().port;

    const alice = await signin.signInToThePortal(base, ALICE, null,
                                                 { password: PASSWORD });
    note(!!alice.token, 'alice signs in as the static portal does');

    // --- 1. what may be offered ------------------------------------------
    const offerable = await alice.page('/portal/wallet');
    const configs = (offerable.json && offerable.json.configurations) || [];
    const identity = configs.filter(function (one) {
      return one.id === 'IdentityCredential';
    })[0];
    note(offerable.status === 200 && identity &&
         identity.name === 'Identity Credential' &&
         identity.format === 'dc+sd-jwt' &&
         JSON.stringify(offerable.json.modes) ===
           JSON.stringify(['cross-device', 'deferred']),
         '1. GET /account-api/credentials/offerable lists the issuer\'s ' +
         'configurations, named as its metadata names them, and the two ' +
         'pre-authorized modes', brief(offerable));

    // --- 2. an offer for the caller ----------------------------------------
    const before = presented.length;
    const made = await alice.act('/portal/wallet',
      { configuration: 'IdentityCredential', mode: 'cross-device' });
    const offer = (made.json && made.json.offer) || {};
    const grant = ((offer.credentialOffer || {}).grants || {})[
      'urn:ietf:params:oauth:grant-type:pre-authorized_code'] || {};
    const code = grant['pre-authorized_code'] || '';
    const record = code ? offers.preAuthorizedCodes.get(code) : null;
    note(made.status === 200 && made.json.ok && code && record &&
         record.user && record.user.username === ALICE,
         '2a. POST /account-api/credentials/offers makes a pre-authorized ' +
         'offer whose code names the caller', brief(made));
    note(/^\d{4,}$/.test(String(offer.txCode || '')) && record &&
         record.txCode === offer.txCode &&
         JSON.stringify(offer.credentialOffer).indexOf(offer.txCode) < 0,
         '2b. it answers the Transaction Code, which is the code\'s, and ' +
         'is not in the offer', String(offer.txCode));
    const byRef = offer.byReference || {};
    note(/^openid-credential-offer:\/\/\?credential_offer=/.test(
           String((offer.byValue || {}).offerUri)) &&
         /^openid-credential-offer:\/\/\?credential_offer_uri=/.test(
           String(byRef.offerUri)) &&
         /\/oid4vci\/credential-offer\//.test(
           String(byRef.credentialOfferUri)) &&
         !isNaN(Date.parse(offer.expiresAt)),
         '2c. the offer comes by value and by reference, with its expiry',
         JSON.stringify(offer).slice(0, 400));
    const fetched = await fetch(byRef.credentialOfferUri);
    const fetchedJson = await fetched.json().catch(function () {
      return null;
    });
    note(fetched.status === 200 && fetchedJson &&
         JSON.stringify(fetchedJson) ===
           JSON.stringify(offer.credentialOffer),
         '2d. the reference serves the same offer', fetched.status);
    const mine = presented.slice(before);
    note(mine.length === 1 && mine[0].via === 'OpenID4VCI' &&
         mine[0].user === ALICE && mine[0].id,
         '2e. the offer is session-presented, naming OpenID4VCI, on the ' +
         'sign-on session the portal\'s token was issued on',
         JSON.stringify(mine));

    // --- 3. it redeems for a token about the caller -------------------------
    const tokenAnswer = await fetch(base + '/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code, tx_code: offer.txCode }).toString() });
    const redeemed = await tokenAnswer.json().catch(function () {
      return {};
    });
    let claims = {};
    try {
      claims = JSON.parse(Buffer.from(String(redeemed.access_token)
        .split('.')[1], 'base64url').toString('utf8'));
    } catch (e) {
      // No token to read: the note below says so with the status.
      claims = { unreadable: (e && e.message) || String(e) };
    }
    note(tokenAnswer.status === 200 && claims.username === ALICE,
         '3. the code and the Transaction Code redeem for a token about ' +
         'the caller', tokenAnswer.status + ' ' +
         JSON.stringify(claims).slice(0, 300));

    // --- 4. the refusals -----------------------------------------------------
    const mallory = await signin.signInToThePortal(base, MALLORY, null,
                                                   { password: PASSWORD });
    const named = await mallory.act('/portal/wallet',
      { configuration: 'IdentityCredential', mode: 'deferred',
        user: ALICE, username: ALICE, sub: 'urn:uuid:not-mallory' });
    const namedOffer = (named.json && named.json.offer) || {};
    const namedCode = (((namedOffer.credentialOffer || {}).grants || {})[
      'urn:ietf:params:oauth:grant-type:pre-authorized_code'] || {})[
      'pre-authorized_code'];
    const namedRecord = namedCode ? offers.preAuthorizedCodes.get(namedCode)
                                  : null;
    note(named.status >= 400 ||
         (namedRecord && namedRecord.user &&
          namedRecord.user.username === MALLORY && namedRecord.deferred),
         '4a. A BODY NAMING ALICE STILL OFFERS FOR MALLORY: the person is ' +
         'the token\'s', brief(named));
    const unknown = await alice.act('/portal/wallet',
      { configuration: 'NoSuchCredential', mode: 'cross-device' });
    note(unknown.status === 400 && unknown.json && unknown.json.ok === false &&
         unknown.json.view && unknown.json.view.configurations,
         '4b. an unknown configuration is refused, with the page\'s view',
         brief(unknown));
    const badMode = await alice.act('/portal/wallet',
      { configuration: 'IdentityCredential', mode: 'same-device' });
    note(badMode.status === 400,
         '4c. a same-device offer is not this page\'s to make',
         brief(badMode));
    const bare = await fetch(base + '/account-api/credentials/offers', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configuration: 'IdentityCredential',
                             mode: 'cross-device' }) });
    note(bare.status === 401, '4d. no token: 401', bare.status);
    let narrow = null;
    let narrowRefused = '';
    try {
      const openidOnly = await signin.signInToThePortal(base, MALLORY, null,
        { password: PASSWORD, scope: 'openid' });
      narrow = await openidOnly.api('POST', '/account-api/credentials/offers',
        { configuration: 'IdentityCredential', mode: 'cross-device' });
    } catch (e) {
      narrowRefused = (e && e.message) || String(e);
    }
    note(narrowRefused || (narrow && narrow.status === 403),
         '4e. a token without account:manage makes no offer',
         narrowRefused ? 'refused at sign-in: ' + narrowRefused.slice(0, 200)
                       : brief(narrow));

    // --- 5. the renderer round trip ------------------------------------------
    const table = signin.portalBundle();
    const me = await alice.api('GET', '/account-api/me');
    const t = table.messages.WebTranslator.fromData(me.json.locale);
    const html = table.render('/portal/wallet', made.json.view, {
      t: t, query: {}, prefix: '', origin: base, me: me.json,
      locale: me.json.locale, version: me.json.version,
      here: '/portal/wallet' });
    const decoded = html.replace(/&amp;/g, '&');
    note(/<svg[^>]*id="offer_qr"/.test(html) &&
         decoded.indexOf('id="tx_code">' + offer.txCode + '<') >= 0 &&
         decoded.indexOf('id="open_in_wallet" href="' +
                         offer.byValue.offerUri + '"') >= 0 &&
         /<form method="post" action="\/portal\/wallet">/.test(html) &&
         !/portalWallet\./.test(html),
         '5a. the POST\'s view draws the QR code, the Transaction Code and ' +
         'the open-in-wallet link, in the person\'s language',
         html.slice(0, 400));
    const page = await alice.draw('/portal/wallet');
    note(page.status === 200 && /id="wallet-make"/.test(page.html) &&
         !/id="offer_qr"/.test(page.html),
         '5b. the page drawn from its GET offers the form and no offer',
         page.status + ' ' + page.html.slice(0, 200));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

// A. The encoder against the `qrcode` package, for every level and mask.
function qrMatchesTheReference(t) {
  log.debug("Entering qrMatchesTheReference().");
  const WebQr = require('../common/web_qr');
  const QRCode = require('qrcode');
  const lengths = [1, 14, 15, 40, 100, 130, 200, 400, 900, 1500, 2300];
  let compared = 0;
  const wrong = [];
  ['L', 'M', 'Q', 'H'].forEach(function (level) {
    lengths.forEach(function (length) {
      let text = '';
      for (let i = 0; i < length; i++) {
        text += String.fromCharCode(33 + (i * 7) % 90);
      }
      if (length === 40) {
        // Beyond ASCII: byte mode carries UTF-8.
        text = 'openid-credential-offer://?x=héllo ✓ 日 ' +
               '😀';
      }
      for (let mask = 0; mask < 8; mask++) {
        let reference = null;
        try {
          reference = QRCode.create([{ data: text, mode: 'byte' }],
            { errorCorrectionLevel: level, maskPattern: mask });
        } catch (e) {
          // Past version 40 at this level: neither can draw it.
          log.debug("Caught in qrMatchesTheReference(): " +
                    ((e && e.message) || e));
          continue;
        }
        const mine = WebQr.matrix(text, level, mask);
        compared += 1;
        let differ = mine.version !== reference.version ? -1 : 0;
        for (let y = 0; differ === 0 && y < mine.size; y++) {
          for (let x = 0; x < mine.size; x++) {
            if (!!reference.modules.get(y, x) !== mine.modules[y][x]) {
              differ += 1;
            }
          }
        }
        if (differ !== 0) {
          wrong.push(level + '/' + length + '/mask ' + mask + ': ' + differ);
        }
      }
    });
  });
  t.check(compared > 300 && !wrong.length,
          'A. the browser\'s QR encoder draws exactly what the qrcode ' +
          'package draws, for every level and mask (' + compared + ')',
          wrong.slice(0, 10).join('; '));
  const svg = WebQr.svg('openid-credential-offer://?credential_offer_uri=' +
                        'https%3A%2F%2Fsts.example%2Foid4vci%2F' +
                        'credential-offer%2Fabc', { id: 'q', label: 'a"b' });
  t.check(/^<svg [^>]*id="q"[^>]*aria-label="a&quot;b"/.test(svg) &&
          /<path d="M/.test(svg) && !/<script/i.test(svg),
          'A. the SVG is inline markup, its attributes escaped',
          svg.slice(0, 200));
  log.debug("Leaving qrMatchesTheReference().");
}

async function run(t) {
  log.debug("Entering run().");
  qrMatchesTheReference(t);
  const out = path.join(os.tmpdir(), 'pw-' + process.pid + '-' + Date.now() +
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
                                  PW_ROOT: ROOT, PW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'portal_wallet',
  describe: '/portal/wallet: a pre-authorized Credential Offer for the ' +
            'caller\'s own wallet over /account-api, the QR code the ' +
            'browser draws, and the page drawn from the answer (#589)',
  run: run
};
