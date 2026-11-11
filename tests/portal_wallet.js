// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_wallet.js
//
// ---------------------------------------------------------------------------
// `/portal/wallet`: A CREDENTIAL ABOUT YOURSELF, INTO YOUR OWN WALLET (#589).
//
//   A. THE QR CODE THE BROWSER DRAWS (`common/web_qr.ts`) is the `qrcode`
//      package's, module for module: every error correction level, every
//      mask, lengths from one byte to the versions an offer reaches. An
//      encoder that is wrong draws a picture that scans as nothing.
//   B. In a child process with the whole stack, a person signed in as the
//      static portal signs in (`tests/protocol/portal_signin.js`):
//        1. `GET /account-api/credentials/offerable` lists the issuer's
//           configurations, with the metadata's names;
//        2. `POST /account-api/credentials/offers` makes a pre-authorized
//           offer FOR THE CALLER — the code's record names them — with the
//           Transaction Code, by value and by reference, and the offer is
//           session-presented on the sign-on session the token was issued on
//           (CAEP, naming OpenID4VCI);
//        3. the code and the Transaction Code redeem at the token endpoint
//           for a token about the caller — and (#666) the code names the
//           offer's session, on whose risk the token request is judged:
//           a HIGH standing held for the person does not refuse an offer
//           made on a clean session, and still refuses one made on none;
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
    const signin = require(ROOT_DIR + '/tests/protocol/portal_signin');

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
    // The record keeps the Transaction Code's DIGEST and never the code
    // (#614), so "which is the code's" is the digest of the answer.
    note(/^\d{4,}$/.test(String(offer.txCode || '')) && record &&
         record.txCodeDigest ===
           require(ROOT_DIR + '/common/crypto').credentialDigest(
             offer.txCode) &&
         record.txCode === undefined &&
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
    // A WALLET APP IS HANDED THE OFFER BY ITS SCHEME, AND NO WEB WALLET IS
    // OFFERED BY DEFAULT (2026-10-12): `oid4vci.walletUrl` is empty.
    note((offer.byValue || {}).walletUrl === '' && byRef.walletUrl === '',
         '2c-ii. no web wallet link is offered where none is configured',
         JSON.stringify([(offer.byValue || {}).walletUrl, byRef.walletUrl]));
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
    note(record && mine.length === 1 && record.sessionId === mine[0].id,
         '2f. the code records the sign-on session the offer was made on ' +
         '(#666), the one it is judged on at the token endpoint',
         JSON.stringify([record && record.sessionId, mine[0] && mine[0].id]));
    const config = require(ROOT_DIR + '/common/config');
    config.setOverride('oid4vci.walletInvocation', 'haip-vci');
    const haip = await alice.act('/portal/wallet',
      { configuration: 'IdentityCredential', mode: 'cross-device' });
    config.clearOverride('oid4vci.walletInvocation');
    const haipOffer = (haip.json && haip.json.offer) || {};
    note(/^haip-vci:\/\/\?credential_offer=/.test(
           String((haipOffer.byValue || {}).offerUri)) &&
         /^haip-vci:\/\/\?credential_offer_uri=/.test(
           String((haipOffer.byReference || {}).offerUri)),
         '2c-iii. oid4vci.walletInvocation=haip-vci hands it over under ' +
         'haip-vci:// (OpenID4VC HAIP 1.0 section 4.2)',
         String((haipOffer.byValue || {}).offerUri).slice(0, 40));
    const asMeta = await fetch(base +
      '/.well-known/oauth-authorization-server');
    const asJson = await asMeta.json().catch(function () {
      return {};
    });
    note(asJson['pre-authorized_grant_anonymous_access_supported'] === true,
         '2c-iv. the authorization server says a wallet may redeem the ' +
         'code naming no client (OpenID4VCI 1.0 section 12.3), which is ' +
         'how it is redeemed below', String(
           asJson['pre-authorized_grant_anonymous_access_supported']));

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

    // --- 3b. judged on the offer's session, not a held standing (#666) ------
    // The issue's sequence, for a person of its own: a sign-in refused on
    // risk left them HIGH in one request worker, their next sign-in was
    // clean, and the offer was made on it. Here the clean sign-in comes
    // first and the HIGH is held after it — what that worker still held —
    // with enforcement OFF while it is assessed, so the risk-response
    // reaction is only observed and the session lives. Then the token
    // request, enforced, is judged on the OFFER'S session.
    const riskEngine = require(ROOT_DIR + '/risk/risk_engine');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const BOB = 'pw-bob-' + stamp;
    ldap.createUser(BOB, { invent: false });
    credentials.setPassword(BOB, PASSWORD);
    const bob = await signin.signInToThePortal(base, BOB, null,
                                               { password: PASSWORD });
    await riskEngine.assess({ realm: 'default',
      subject: helpers.subjectForName(BOB), username: BOB,
      sessionId: '', door: 'a test', userAgent: 'curl/8.5.0',
      context: { address: '192.0.2.10', uaFingerprint: 'fp-666' } });
    const heldHigh = riskEngine.standingOf('default', BOB);
    config.setOverride('risk.enforceInDevelopment', true);
    const again = await bob.act('/portal/wallet',
      { configuration: 'IdentityCredential', mode: 'cross-device' });
    const againOffer = (again.json && again.json.offer) || {};
    const againCode = (((againOffer.credentialOffer || {}).grants || {})[
      'urn:ietf:params:oauth:grant-type:pre-authorized_code'] || {})[
      'pre-authorized_code'] || '';
    const againRecord = againCode ?
      offers.preAuthorizedCodes.get(againCode) : null;
    const offerSession = againRecord ?
      authn.sessionById(againRecord.sessionId) : null;
    const redeemAgain = await fetch(base + '/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': againCode, tx_code: againOffer.txCode })
        .toString() });
    const redeemAgainText = await redeemAgain.text();
    note(heldHigh && heldHigh.level === 'HIGH' && offerSession &&
         offerSession.risk && offerSession.risk.level !== 'HIGH' &&
         redeemAgain.status === 200,
         '3b. with a HIGH standing held for the person, an offer made on ' +
         'a session that is not HIGH still redeems: the token request is ' +
         'judged on the offer\'s session (#666)',
         JSON.stringify([heldHigh && heldHigh.level,
                         offerSession && offerSession.risk &&
                         offerSession.risk.level, redeemAgain.status,
                         redeemAgainText.slice(0, 200)]));
    // And with no session behind the offer, the standing still decides.
    const orphan = offers.makeOffer({ protocol: 'http',
      get: function () {
        return '127.0.0.1';
      }, headers: {} }, { configurationIds: ['IdentityCredential'],
      mode: 'cross-device', user: againRecord && againRecord.user });
    const orphanRedeem = await fetch(base + '/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': orphan.built.preAuthorizedCode,
        tx_code: orphan.built.txCode }).toString() });
    const orphanJson = await orphanRedeem.json().catch(function () {
      return {};
    });
    note(orphanRedeem.status === 400 && orphanJson.error === 'access_denied',
         '3c. an offer made on no session is still judged on the ' +
         'person\'s standing, and HIGH refuses it',
         orphanRedeem.status + ' ' + JSON.stringify(orphanJson));
    config.clearOverride('risk.enforceInDevelopment');

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
         /id="wallet-no-app"/.test(html) &&
         !/id="open_in_web_wallet"/.test(html) &&
         !/portalWallet\./.test(html),
         '5a. the POST\'s view draws the QR code, the Transaction Code, ' +
         'the open-in-wallet link and what to do when nothing opens — and ' +
         'no web wallet link — in the person\'s language',
         html.slice(0, 400));
    const withWeb = JSON.parse(JSON.stringify(made.json.view));
    withWeb.offer.byValue = Object.assign({}, withWeb.offer.byValue,
      { walletUrl: 'http://wallet.example/credential-offer?x=1' });
    const webHtml = table.render('/portal/wallet', withWeb, {
      t: t, query: {}, prefix: '', origin: base, me: me.json,
      locale: me.json.locale, version: me.json.version,
      here: '/portal/wallet' });
    note(new RegExp('<a [^>]*id="open_in_web_wallet" target="_blank" ' +
                    'rel="noopener" href="http://wallet\\.example/' +
                    'credential-offer\\?x=1"')
           .test(webHtml.replace(/&amp;/g, '&')),
         '5a-ii. a configured web wallet\'s link opens in a new tab',
         webHtml.slice(webHtml.indexOf('open_in_wallet'),
                       webHtml.indexOf('open_in_wallet') + 400));
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
