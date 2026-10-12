// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: vc_demo_api.js
// ===========================================================================
// THE OPENID4VC DEMONSTRATION AS A STATIC SURFACE OVER `/vc-demo-api` (#582).
//
// The demonstration issuer's and verifier's five pages answer one shell
// since #582, and the browser draws them from `/vc-demo-api`. What is held:
//
//   1. THE SHELLS: each page answers the same document, `no-store`, its
//      script `/issuer/demo.js` under `script-src 'self'` with
//      `frame-ancestors` kept, a `<noscript>` and nothing else — no offer, no
//      code, no request in it; the two start pages give a browser arriving
//      without one the `sts_session` cookie their acts are bound to.
//   2. A GET CREATES NOTHING: the start pages' views check their query (a
//      bad one refused with the page's code) and mint no offer, code, state
//      or request; the issuer's and the bar door's views are their facts.
//   3. EVERY ACT IS BOUND as `/authn-api`'s are: not JSON (STS-VC-0116),
//      another origin (0117), no CSRF token (0118) — refused before
//      anything is minted, and no answer carries a code.
//   4. THE OFFER: on this device the act's `location` is the wallet link
//      `makeOffer()` makes — the `openid-credential-offer` query, by value
//      or by reference, whose `/oid4vci/credential-offer/{id}` still serves
//      the offer as it did; for another device the QR page's view carries
//      the `openid-credential-offer://` URI with the same query as the
//      wallet link, and the Transaction Code the pre-authorized code holds.
//   5. THE START: on this device `location` is the wallet with the request,
//      whose `request_uri` serves the signed Request Object as before; for
//      another device the view's `openid4vp://` URI carries the wallet
//      link's query, and the state the page polls.
//   6. THE CLOSING PAGE'S VIEW: nothing yet for an unknown or unanswered
//      state, the verdict once there is one, and never a wallet sign-in's.
//   7. A PRODUCT REALM is served none of it (#585).
// ===========================================================================

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'vc_demo_api',
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

  function queryOf(url) {
    const out = {};
    new URL(url).searchParams.forEach(function (value, name) {
      out[name] = value;
    });
    return out;
  }

  async function sections(w, note, m) {
    const minted = function () {
      return w.inRealm(function () {
        return [m.offers.preAuthorizedCodes.size, m.offers.issuerStates.size,
                m.offers.credentialOffers.size,
                m.verifier.recentVerifications(1000).total].join(',');
      });
    };

    // ==================================================================
    // 1. THE SHELLS
    // ==================================================================
    const pages = ['/issuer', '/issuer/offer?mode=cross-device',
                   '/oid4vp/verifier', '/oid4vp/start?mode=cross-device',
                   '/oid4vp/done?state=nothing'];
    const before = await minted();
    for (const p of pages) {
      const r = await w.request('GET', p, { browser: w.browser() });
      const csp = String(r.headers['content-security-policy'] || '');
      note(r.status === 200 && /^text\/html/.test(r.headers['content-type']) &&
           /no-store/.test(String(r.headers['cache-control'])) &&
           /<script src="\/issuer\/demo\.js" defer><\/script>/.test(r.text) &&
           /<noscript>/.test(r.text) &&
           /<link rel="stylesheet" href="\/web\/card\.css">/.test(r.text) &&
           /script-src 'self'/.test(csp) && /frame-ancestors/.test(csp) &&
           !/unsafe-inline/.test(csp.replace(/style-src[^;]*;?/, '')) &&
           !/tx_code|openid-credential-offer|openid4vp:|<img/.test(r.text),
           '1a. ' + p + ' answers the static surface\'s shell, and nothing ' +
           'of an offer or a request', r.status + ' ' + csp.slice(0, 160));
      const arrival = (r.setCookie || []).some(function (c) {
        return /^sts_session=[^;]+/.test(c);
      });
      const isStart = /\/issuer\/offer|\/oid4vp\/start/.test(p);
      note(arrival === isStart, '1b. ' + p + (isStart
        ? ' gives a browser without one the cookie its act is bound to'
        : ' mints no cookie'), String(arrival));
    }
    const script = await w.request('GET', '/issuer/demo.js');
    note(script.status === 200 &&
         /javascript/.test(String(script.headers['content-type'])),
         '1c. the surface\'s script is served', script.status + ' ' +
         script.headers['content-type']);
    note(await minted() === before, '1d. loading the five shells minted ' +
         'nothing', before);

    // ==================================================================
    // 2. A GET CREATES NOTHING
    // ==================================================================
    const index = await w.request('GET', '/vc-demo-api');
    const ops = ((index.json || {}).operations || []).map(function (op) {
      return op.method + ' ' + op.path + ' ' + (op.mirrors || '');
    });
    note(index.status === 200 && ops.indexOf('POST /vc-demo-api/offer ' +
         'POST /issuer/offer') >= 0 && ops.indexOf('POST /vc-demo-api/start ' +
         'POST /oid4vp/start') >= 0 && ops.indexOf('GET /vc-demo-api/done ' +
         'GET /oid4vp/done') >= 0,
         '2a. the index lists each operation with the page it mirrors',
         ops.join(' | '));
    const issuerView = await w.request('GET', '/vc-demo-api/issuer');
    const iv = (issuerView.json || {}).view || {};
    note(issuerView.status === 200 && iv.kind === 'issuer' &&
         iv.configurationId === m.vcConfigs.VCI_CONFIG_ID &&
         iv.issuer === w.base && typeof iv.wallet === 'string',
         '2b. the issuer\'s page is its facts: the configuration, the ' +
         'wallet and the issuer', JSON.stringify(iv));
    const verifierView = await w.request('GET',
      '/vc-demo-api/verifier?format=jwt_vc_json');
    const vv = (verifierView.json || {}).view || {};
    note(verifierView.status === 200 && vv.kind === 'verifier' &&
         vv.format === 'jwt_vc_json' && vv.askingFor === 'jwt_vc_json' &&
         Array.isArray(vv.claims) &&
         vv.responseUri === w.base + '/oid4vp/response',
         '2c. the bar door\'s view: the format named, what it asks for, ' +
         'where the wallet posts', JSON.stringify(vv).slice(0, 300));
    const visitor = w.browser();
    await w.request('GET', '/issuer/offer?mode=cross-device',
                    { browser: visitor });
    const offerView = await w.request('GET',
      '/vc-demo-api/offer?mode=cross-device', { browser: visitor });
    const startView = await w.request('GET',
      '/vc-demo-api/start?mode=cross-device', { browser: visitor });
    note(offerView.status === 200 && offerView.json.view.kind ===
         'offerStart' && /^[A-Za-z0-9_-]{20,}$/.test(offerView.json.csrf) &&
         startView.status === 200 && startView.json.view.kind ===
         'presentStart' && startView.json.view.mode === 'cross-device' &&
         startView.json.csrf === offerView.json.csrf &&
         await minted() === before,
         '2d. the start pages\' views answer the CSRF token of the ' +
         'browser\'s cookie, and mint nothing', await minted());
    const badOffer = await w.request('GET', '/vc-demo-api/offer?mode=bogus');
    const badStart = await w.request('GET',
      '/vc-demo-api/start?format=no-such');
    note(badOffer.status === 400 && badOffer.code === 'STS-VC-0025' &&
         badOffer.json && badOffer.json.ok === false && codeFree(badOffer) &&
         badStart.status === 400 && badStart.code === 'STS-VC-0032' &&
         codeFree(badStart),
         '2e. a bad query is refused by the view, with the page\'s code, ' +
         'recorded and not sent', badOffer.code + ' ' + badStart.code);

    // ==================================================================
    // 3. EVERY ACT IS BOUND
    // ==================================================================
    const csrf = offerView.json.csrf;
    const notJson = await w.request('POST', '/vc-demo-api/offer', {
      browser: visitor, form: { mode: 'cross-device' },
      headers: { origin: w.origin, 'x-csrf-token': csrf } });
    const elsewhere = await w.act(visitor, '/vc-demo-api/offer',
      { mode: 'cross-device' }, { origin: 'https://evil.example', csrf: csrf });
    const noToken = await w.act(visitor, '/vc-demo-api/start',
      { mode: 'cross-device' }, { csrf: '' });
    const otherToken = await w.act(w.browser(), '/vc-demo-api/start',
      { mode: 'cross-device' }, { csrf: csrf });
    note(notJson.status === 415 && notJson.code === 'STS-VC-0116' &&
         elsewhere.status === 403 && elsewhere.code === 'STS-VC-0117' &&
         noToken.status === 403 && noToken.code === 'STS-VC-0118' &&
         otherToken.status === 403 && otherToken.code === 'STS-VC-0118' &&
         [notJson, elsewhere, noToken, otherToken].every(codeFree) &&
         await minted() === before,
         '3a. an act not JSON, from another origin, or without this ' +
         'browser\'s token is refused, and nothing is minted',
         [notJson.code, elsewhere.code, noToken.code, otherToken.code]
           .join(','));

    // ==================================================================
    // 4. THE OFFER
    // ==================================================================
    const wallet = await w.inRealm(function () {
      return m.offers.configuredWalletUrl();
    });
    const same = await w.demoStart('/issuer/offer');
    const sameAt = String(same.headers.location || '');
    const sameOffer = sameAt.indexOf(wallet + '?credential_offer=') === 0
      ? JSON.parse(queryOf(sameAt).credential_offer) : null;
    const issuerState = sameOffer && sameOffer.grants &&
      sameOffer.grants.authorization_code &&
      sameOffer.grants.authorization_code.issuer_state;
    note(same.status === 302 && sameOffer &&
         sameOffer.credential_issuer === w.base &&
         JSON.stringify(sameOffer.credential_configuration_ids) ===
           JSON.stringify([m.vcConfigs.VCI_CONFIG_ID]) &&
         !!issuerState && await w.inRealm(function () {
           return m.offers.issuerStates.has(issuerState);
         }),
         '4a. on this device the act names the wallet with the offer by ' +
         'value, an issuer_state held for it — the address the 302 named',
         same.status + ' ' + sameAt.slice(0, 200));
    const byRef = await w.demoStart('/issuer/offer?by=reference');
    const refAt = String(byRef.headers.location || '');
    const refUri = refAt ? queryOf(refAt).credential_offer_uri || '' : '';
    const served = refUri ? await w.request('GET', w.pathOf(refUri)) : null;
    note(byRef.status === 302 &&
         refAt.indexOf(wallet + '?credential_offer_uri=') === 0 &&
         refUri.indexOf(w.base + '/oid4vci/credential-offer/') === 0 &&
         served && served.status === 200 &&
         /^application\/json/.test(served.headers['content-type']) &&
         /no-store/.test(String(served.headers['cache-control'])) &&
         served.json && served.json.credential_issuer === w.base,
         '4b. by reference: the wallet is handed credential_offer_uri, which ' +
         'serves the offer as it always did', refAt.slice(0, 200) + ' ' +
         (served ? served.status : ''));
    const cross = await w.demoStart('/issuer/offer?mode=cross-device');
    const cv = cross.json && cross.json.view || {};
    const crossOffer = /^openid-credential-offer:\/\/\?credential_offer=/
      .test(String(cv.offerUri))
      ? JSON.parse(decodeURIComponent(String(cv.offerUri)
          .slice('openid-credential-offer://?credential_offer='.length)))
      : null;
    const preAuth = crossOffer && ((crossOffer.grants || {})[
      'urn:ietf:params:oauth:grant-type:pre-authorized_code'] || {});
    const held = preAuth && preAuth['pre-authorized_code']
      ? await w.inRealm(function () {
        return m.offers.preAuthorizedCodes.get(preAuth['pre-authorized_code']);
      }) : null;
    note(cross.status === 200 && cv.kind === 'offer' &&
         cv.mode === 'cross-device' &&
         String(cv.walletUrl).indexOf(wallet + '?') === 0 &&
         String(cv.walletUrl).slice(wallet.length + 1) ===
           String(cv.offerUri).slice('openid-credential-offer://?'.length) &&
         held && held.txCode === cv.txCode && /^\d+$/.test(cv.txCode) &&
         held.deferred === false &&
         String(cv.offerUri).indexOf(cv.txCode) < 0,
         '4c. for another device the QR view carries the ' +
         'openid-credential-offer URI with the wallet link\'s query, and ' +
         'the Transaction Code the code holds — which the offer does not',
         JSON.stringify(cv).slice(0, 300));
    const deferred = await w.demoStart('/issuer/offer?mode=deferred');
    const dv = deferred.json && deferred.json.view || {};
    note(deferred.status === 200 && dv.kind === 'offer' &&
         dv.mode === 'deferred',
         '4d. a deferred offer (H.3) is the QR view too', JSON.stringify(dv)
           .slice(0, 160));

    // ==================================================================
    // 5. THE START
    // ==================================================================
    const vpWallet = await w.inRealm(function () {
      return m.verifier.vpWalletFor(w.fakeReq(''), '');
    });
    const start = await w.demoStart('/oid4vp/start?by=reference');
    const startAt = String(start.headers.location || '');
    const startQuery = startAt ? queryOf(startAt) : {};
    const object = startQuery.request_uri
      ? await w.request('GET', w.pathOf(startQuery.request_uri)) : null;
    const ro = object && object.status === 200 ? w.decode(object.text) : null;
    note(start.status === 302 &&
         startAt.indexOf(String(vpWallet.url) + '?') === 0 &&
         !!startQuery.client_id && object && object.status === 200 &&
         /oauth-authz-req\+jwt/.test(object.headers['content-type']) &&
         ro && ro.response_mode === 'direct_post' &&
         ro.response_uri === w.base + '/oid4vp/response',
         '5a. on this device the act names the wallet with client_id and ' +
         'request_uri, which serves the signed Request Object as before',
         start.status + ' ' + startAt.slice(0, 200));
    const vpCross = await w.demoStart('/oid4vp/start?mode=cross-device');
    const rv = vpCross.json && vpCross.json.view || {};
    const rq = /^openid4vp:\/\/\?/.test(String(rv.requestUri))
      ? queryOf('https://x.invalid/?' +
                String(rv.requestUri).slice('openid4vp://?'.length)) : {};
    note(vpCross.status === 200 && rv.kind === 'request' &&
         String(rv.walletUrl).indexOf(String(vpWallet.url) + '?') === 0 &&
         String(rv.walletUrl).split('?')[1] ===
           String(rv.requestUri).slice('openid4vp://?'.length) &&
         rq.state === rv.state && rv.pollSeconds > 0,
         '5b. for another device the view carries the openid4vp:// URI with ' +
         'the wallet link\'s query, and the state the page polls',
         JSON.stringify(rv).slice(0, 300));

    // ==================================================================
    // 6. THE CLOSING PAGE'S VIEW
    // ==================================================================
    const unknown = await w.request('GET', '/vc-demo-api/done?state=nope');
    const waiting = await w.request('GET', '/vc-demo-api/done?state=' +
                                    encodeURIComponent(rv.state));
    note(unknown.status === 200 && unknown.json.view.received === false &&
         waiting.status === 200 && waiting.json.view.received === false,
         '6a. an unknown or unanswered state is "nothing yet"',
         unknown.status + ' ' + waiting.status);
    await w.inRealm(function () {
      const tx = m.verifier.transactionFor(rv.state);
      tx.verdict = { ok: false, at: new Date().toISOString(), checks: [],
                     claims: { given_name: 'Ada', address: { c: 'US' } },
                     requested: ['given_name'] };
      m.verifier.saveTransaction(tx);
    });
    const decided = await w.request('GET', '/vc-demo-api/done?state=' +
                                    encodeURIComponent(rv.state));
    const dd = (decided.json || {}).view || {};
    note(decided.status === 200 && dd.received === true &&
         dd.accepted === false &&
         JSON.stringify(dd.claims) === JSON.stringify([
           { name: 'given_name', value: 'Ada' },
           { name: 'address', value: '{"c":"US"}' }]) &&
         JSON.stringify(dd.requested) === '["given_name"]',
         '6b. once decided, the verdict, the claims as text and what was ' +
         'asked for', JSON.stringify(dd));
    await w.inRealm(function () {
      const tx = m.verifier.transactionFor(rv.state);
      tx.signIn = { authnId: 'x', completePath: '/authn/wallet/wait' };
      m.verifier.saveTransaction(tx);
    });
    const signIn = await w.request('GET', '/vc-demo-api/done?state=' +
                                   encodeURIComponent(rv.state));
    note(signIn.status === 200 && signIn.json.view.received === false,
         '6c. a wallet sign-in\'s transaction is never this page\'s',
         JSON.stringify(signIn.json));

    // ==================================================================
    // 7. A PRODUCT REALM IS SERVED NONE OF IT
    // ==================================================================
    await w.inRealm(function () {
      m.realms.create({ id: 'vcdemoprod', name: 'vcdemoprod',
                        overrides: { 'global.mode': 'product' } });
    });
    const unrouted = [];
    for (const p of ['/issuer', '/issuer/offer', '/oid4vp/verifier',
                     '/oid4vp/start', '/oid4vp/done', '/issuer/demo.js',
                     '/vc-demo-api', '/vc-demo-api/offer',
                     '/vc-demo-api/start', '/vc-demo-api/done']) {
      const r = await w.request('GET', '/realm/vcdemoprod' + p);
      if (!(r.status === 404 && /Cannot GET/.test(r.text))) {
        unrouted.push(p + ' ' + r.status);
      }
    }
    const posted = await w.request('POST', '/realm/vcdemoprod/vc-demo-api/' +
                                   'offer', { json: {} });
    note(unrouted.length === 0 && posted.status === 404 &&
         /Cannot POST/.test(posted.text),
         '7a. a product realm answers every page, the script and the API as ' +
         'unrouted paths', unrouted.join(', ') || 'all unrouted');
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'vc-demo-api');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'the OpenID4VC demonstration over /vc-demo-api (#582)',
  describe: 'the shells, the views that mint nothing, the binding of every ' +
            'act, the offer and the request a wallet is handed unchanged, ' +
            'the closing page\'s view, and nothing in a product realm',
  run: run
};
