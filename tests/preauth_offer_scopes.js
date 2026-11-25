// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: preauth_offer_scopes.js
//
// ===========================================================================
// A PRE-AUTHORIZED CODE REDEEMED BY A WALLET THAT NAMES NO CLIENT KEEPS THE
// OFFER'S CREDENTIAL SCOPES, IN PRODUCT (#2169).
//
// Since #2114 (#1589) a product-mode client that declares no scopes is
// issued `openid` alone, and `tokenSet()`'s narrowing judged the ABSENT
// client of an anonymous pre-authorized redemption (OpenID4VCI 1.0 section
// 6.1; this server advertises it, section 12.3) as such a client. The
// token lost its credential scope, `vc_issued.ts`'s `subjectFromToken()`
// filed the credential under nobody, and `/portal/wallet` listed nothing
// the wallet had just been issued (`sts_oid4vc_wallet.js`,
// `sts_eudi_wallet_portal.js`). rcbj: "Obey the spec. Allowances must be
// made to achieve that." In a child process with the whole stack, in
// product mode:
//
//   1. an offer redeemed naming no client is issued a token carrying the
//      offered configuration's scope, and the credential issued on it is
//      written to the issued register under the person;
//   2. the scope comes from the OFFER: an offer for one configuration does
//      not carry another's, and a scope the offer did not name is still
//      taken off at `tokenSet()`;
//   3. a wallet that NAMES a client is that client: one declaring nothing
//      is still narrowed, and its token carries no credential scope.
// ===========================================================================

const nodeCrypto = require('crypto');
const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'preauth_offer_scopes',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = nodeCrypto.randomBytes(4).toString('hex');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const STAMP = process.env.POS_STAMP;
  const walletKit = require(ROOT + '/tests/wallet_kit');
  const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

  walletKit.boot().then(async function (w) {
    try {
      await sections(w);
    } catch (e) {
      w.note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    try {
      w.m.config.clearOverride('global.mode');
    } catch (e) {
      // Never set: the failure above already says why.
      w.note(true, 'cleanup', e && e.message);
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  async function sections(w) {
    const m = w.m;
    const note = w.note;
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const configs = m.vcConfigs.VCI_CONFIGS;
    const SD = 'IdentityCredential';
    const sdScope = configs[SD].scope;
    // Another configuration with a scope of its own, for section 2.
    const otherId = Object.keys(configs).filter(function (id) {
      return id !== SD && configs[id].scope &&
             configs[id].scope !== sdScope;
    })[0];
    const otherScope = otherId ? configs[otherId].scope : '';
    const PERSON = 'pos-holder-' + STAMP;
    m.ldap.createUser(PERSON, { invent: false });
    const subject = m.helpers.subjectForName(PERSON);

    // A clientless redemption of a fresh offer for `configId`.
    async function redeem(configId, named) {
      const built = await m.realms.run(w.DEFAULT, function () {
        return m.offers.buildCredentialOffer(w.fakeReq(''), [configId],
          'cross-device', { user: m.helpers.userFor(PERSON) });
      });
      const got = await w.request('POST', '/oauth2/token',
        { form: Object.assign({ grant_type: PRE_AUTH,
          'pre-authorized_code': built.preAuthorizedCode,
          tx_code: built.txCode }, named || {}) });
      const token = got.json && got.json.access_token;
      return { status: got.status, text: got.text, token: token,
               claims: token ? w.decode(token) : {} };
    }
    const words = function (scope) {
      return String(scope || '').split(/\s+/).filter(Boolean);
    };

    m.config.setOverride('global.mode', 'product');

    // --- 1. no client named: the offer's scope, and the register row -----
    const first = await redeem(SD);
    note(first.status === 200 &&
         words(first.claims.scope).indexOf(sdScope) >= 0,
         '1a. PRODUCT: a pre-authorized code redeemed naming no client is ' +
         'issued the offered configuration\'s scope (' + sdScope + ')',
         first.status + ' ' + JSON.stringify(first.claims.scope) + ' ' +
         String(first.text).slice(0, 200));
    const before = m.issued.issuancesForSubject(subject).length;
    const issued = first.token
      ? await w.issue(PERSON, w.holderKey('ES256'),
                      { token: first.token, configId: SD })
      : { error: 'no token' };
    const after = m.issued.issuancesForSubject(subject).length;
    note(!!issued.credential && after === before + 1,
         '1b. and the credential issued on it is written to the issued ' +
         'register under the person, which is what /portal/wallet lists',
         JSON.stringify([before, after, issued.error || 'issued']));

    // --- 2. the scope is the offer's, never more ---------------------------
    if (otherId) {
      note(first.status === 200 &&
           words(first.claims.scope).indexOf(otherScope) < 0,
           '2a. an offer for ' + SD + ' does not carry ' + otherId + '\'s ' +
           'scope (' + otherScope + ')', JSON.stringify(first.claims.scope));
    }
    let set = null;
    let threw = '';
    try {
      set = await m.realms.run(w.DEFAULT, function () {
        return oauth2.tokenSet(w.base, {
          request: w.fakeReq(''), user: m.helpers.userFor(PERSON),
          client_id: '', grant: 'pre-authorized code', withRefresh: false,
          scope: sdScope + ' profile' + (otherScope ? ' ' + otherScope : ''),
          offer_scopes: [sdScope] });
      });
    } catch (e) {
      threw = (e && (e.stack || e.message)) || String(e);
    }
    const kept = words(set && set.scope);
    note(set && kept.indexOf(sdScope) >= 0 && kept.indexOf('profile') < 0 &&
         (!otherScope || kept.indexOf(otherScope) < 0),
         '2b. at tokenSet(), a scope the offer did not name is still taken ' +
         'off; the offer\'s is kept', JSON.stringify(set && set.scope) +
         ' ' + threw.slice(0, 400));

    // --- 3. a wallet that names a client is that client --------------------
    w.provision();
    const named = await redeem(SD, w.client);
    note((named.status === 200 &&
          words(named.claims.scope).indexOf(sdScope) < 0) ||
         (named.status === 400 && /invalid_scope/.test(named.text)),
         '3. a wallet naming a client that declares nothing is still ' +
         'narrowed by that declaration: no ' + sdScope,
         named.status + ' ' + JSON.stringify(named.claims.scope) + ' ' +
         String(named.text).slice(0, 200));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'preauth-offer-scopes', { POS_STAMP: STAMP });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'preauth_offer_scopes',
  describe: 'OpenID4VCI (#2169): in product, a pre-authorized code ' +
            'redeemed naming no client keeps the offer\'s credential ' +
            'scopes and its credential is registered, a scope the offer ' +
            'did not name is still taken off, and a named client is still ' +
            'judged by its declaration',
  run: run
};
