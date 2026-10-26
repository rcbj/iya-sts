// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_wallet_signing_alg.js
//
// ===========================================================================
// /portal/wallet's CHOICE OF THE ALGORITHM A CREDENTIAL IS SIGNED WITH
// (rcbj, 2026-10-16).
//
//   1. `GET /account-api/credentials/offerable` names each configuration's
//      `signingAlgs`, the configured one first and the default: every JOSE
//      algorithm for dc+sd-jwt (post-quantum ones included), the configured
//      one and RS256 for the DID-named one, bbs-2023 for ldp_vc — and the
//      metadata's `credential_signing_alg_values_supported` says the same;
//   2. an offer choosing ES256, and one choosing ML-DSA-44, redeemed as a
//      wallet does it, is issued a credential signed with that algorithm,
//      and one choosing nothing with the configured one;
//   3. an algorithm the configuration does not allow is refused
//      (STS-PORTAL-0592), for a JOSE and for the DID-named configuration;
//   4. the page draws one list, the first configuration's options shown and
//      its default selected, the others hidden and disabled;
//   5. the runtime's `wireDependentSelects()` follows the configuration
//      radios: picking the ldp_vc one shows bbs-2023 alone and selects it.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'portal_wallet_signing_alg',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    try {
      await sections(w, note, w.m);
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

  function brief(r) {
    return r ? r.status + ' ' + String(r.text || '').slice(0, 300) : 'none';
  }

  async function sections(w, note, m) {
    const credentials = require(ROOT + '/common/credentials');
    const signin = require(ROOT + '/tests/protocol/portal_signin');
    const PortalRuntime = require(ROOT + '/portal/web_portal_runtime');
    const stamp = String(process.pid);
    const ALICE = 'pwa-alice-' + stamp;
    const PASSWORD = 'Portal-Wallet-Alg-' + stamp + '-Passw0rd!';
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser(ALICE, { invent: false });
      credentials.setPassword(ALICE, PASSWORD);
    });
    const alice = await signin.signInToThePortal(w.base, ALICE, null,
                                                 { password: PASSWORD });
    const configured = await w.inRealm(function () {
      return String(m.config.value('oid4vci.credentialSigningAlgorithm'));
    });

    // --- 1. the lists --------------------------------------------------------
    const view = await alice.page('/portal/wallet');
    const rows = (view.json && view.json.configurations) || [];
    const byId = {};
    rows.forEach(function (r) {
      byId[r.id] = r;
    });
    const algsOf = function (id) {
      return ((byId[id] && byId[id].signingAlgs) || []).map(function (a) {
        return a.alg;
      });
    };
    const sd = algsOf('IdentityCredential');
    const did = algsOf('IdentityCredentialDid');
    const ldp = algsOf('IdentityCredentialLdpVc');
    const mldsa = (byId.IdentityCredential.signingAlgs || [])
      .filter(function (a) {
        return a.alg === 'ML-DSA-44';
      })[0] || {};
    note(sd[0] === configured &&
         byId.IdentityCredential.defaultSigningAlg === configured &&
         sd.indexOf('ES256') > 0 && sd.indexOf('ML-DSA-44') > 0 &&
         sd.indexOf('SLH-DSA-SHA2-128s') > 0 &&
         sd.indexOf('ML-DSA-44-ES256') > 0 && sd.indexOf('HS256') < 0 &&
         /draft/.test(String(mldsa.spec)) &&
         JSON.stringify(ldp) === JSON.stringify(['bbs-2023']) &&
         did[0] === configured && did.indexOf('RS256') >= 0 &&
         did.length === (configured === 'RS256' ? 1 : 2),
         '1a. each configuration names its algorithms, the configured one ' +
         'first: every JOSE one (PQC drafts named as drafts), the DID-named ' +
         'one\'s two keys, and bbs-2023 for ldp_vc',
         JSON.stringify({ configured: configured, sd: sd.length, did: did,
                          ldp: ldp, mldsa: mldsa }));
    const meta = await w.request('GET',
                                 '/.well-known/openid-credential-issuer');
    const supported = (meta.json &&
                       meta.json.credential_configurations_supported) || {};
    note(JSON.stringify((supported.IdentityCredential || {})
           .credential_signing_alg_values_supported) === JSON.stringify(sd) &&
         JSON.stringify((supported.IdentityCredentialDid || {})
           .credential_signing_alg_values_supported) === JSON.stringify(did),
         '1b. the metadata\'s credential_signing_alg_values_supported is the ' +
         'same list', brief(meta));

    // --- 2. issued with the algorithm chosen -------------------------------
    const issuedWith = async function (signingAlg) {
      const fields = { configuration: 'IdentityCredential',
                       mode: 'cross-device' };
      if (signingAlg !== undefined) {
        fields.signingAlg = signingAlg;
      }
      const made = await alice.act('/portal/wallet', fields);
      const offer = (made.json && made.json.offer) || {};
      const grant = ((offer.credentialOffer || {}).grants || {})[
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'] || {};
      const token = await w.request('POST', '/oauth2/token', {
        form: Object.assign({
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': grant['pre-authorized_code'],
          tx_code: offer.txCode }, w.client) });
      const accessToken = token.json && token.json.access_token;
      if (!accessToken) {
        return { error: 'offer ' + brief(made) + ' token ' + brief(token) };
      }
      const got = await w.issue(ALICE, w.holderKey(), { token: accessToken });
      if (!got.credential) {
        return { error: got.error };
      }
      const header = JSON.parse(Buffer.from(
        String(got.credential).split('~')[0].split('.')[0], 'base64url')
        .toString('utf8'));
      return { offerAlg: offer.signingAlg, alg: header.alg };
    };
    const es = await issuedWith('ES256');
    note(es.alg === 'ES256' && es.offerAlg === 'ES256',
         '2a. an offer choosing ES256 is issued a credential signed ES256',
         JSON.stringify(es));
    const pq = await issuedWith('ML-DSA-44');
    note(pq.alg === 'ML-DSA-44',
         '2b. one choosing ML-DSA-44 is issued a post-quantum credential',
         JSON.stringify(pq));
    const plain = await issuedWith(undefined);
    note(plain.alg === configured && plain.offerAlg === configured,
         '2c. one choosing nothing is signed with the configured algorithm',
         JSON.stringify(plain));

    // --- 3. refused ----------------------------------------------------------
    const hs = await alice.act('/portal/wallet',
      { configuration: 'IdentityCredential', mode: 'cross-device',
        signingAlg: 'HS256' });
    const notDid = configured === 'ES384' ? 'ES256' : 'ES384';
    const didAsk = await alice.act('/portal/wallet',
      { configuration: 'IdentityCredentialDid', mode: 'cross-device',
        signingAlg: notDid });
    note(hs.status === 400 && hs.json.ok === false &&
         didAsk.status === 400 && didAsk.json.ok === false,
         '3. an algorithm the configuration does not allow is refused, for ' +
         'dc+sd-jwt (HS256) and for the DID-named one (' + notDid + ')',
         brief(hs) + ' / ' + brief(didAsk));

    // --- 4. the page ---------------------------------------------------------
    const drawn = await alice.draw('/portal/wallet');
    const html = drawn.html;
    const optionOf = function (alg) {
      const at = html.indexOf('<option value="' + alg + '"');
      return at < 0 ? '' : html.slice(at, html.indexOf('>', at) + 1);
    };
    note(/<select id="wallet-alg" name="signingAlg" data-depends-on="configuration">/
           .test(html) &&
         html.split('name="signingAlg"').length === 2 &&
         / selected>$/.test(optionOf(configured)) &&
         / hidden disabled/.test(optionOf('bbs-2023')) &&
         !/hidden/.test(optionOf('ML-DSA-44')) &&
         /data-for="[^"]*IdentityCredentialLdpVc/.test(optionOf('bbs-2023')),
         '4. one list: the first configuration\'s algorithms shown and its ' +
         'default selected, ldp_vc\'s bbs-2023 hidden and disabled',
         JSON.stringify({ configured: optionOf(configured),
                          bbs: optionOf('bbs-2023') }));

    // --- 5. the runtime follows the radios ---------------------------------
    const option = function (value, forIds, defaultFor) {
      const attrs = { 'data-for': forIds, 'data-default-for': defaultFor };
      return { value: value, hidden: false, disabled: false,
               getAttribute: function (n) {
                 return attrs[n];
               } };
    };
    const select = { value: 'RS256',
      options: [option('RS256', 'a b', 'a'), option('ES256', 'a', ''),
                option('bbs-2023', 'c', 'c')],
      getAttribute: function () {
        return 'configuration';
      } };
    const listeners = [];
    const radio = function (value) {
      return { value: value, checked: false,
               addEventListener: function (kind, fn) {
                 listeners.push({ value: value, fn: fn, radio: this });
               } };
    };
    const radios = [radio('a'), radio('b'), radio('c')];
    PortalRuntime.wireDependentSelects({ querySelectorAll: function (q) {
      return /^select/.test(q) ? [select] : radios;
    } });
    const pick = function (value) {
      listeners.forEach(function (l) {
        l.radio.checked = l.value === value;
        l.fn();
      });
    };
    pick('c');
    const onC = { value: select.value,
                  shown: select.options.filter(function (o) {
                    return !o.hidden && !o.disabled;
                  }).map(function (o) {
                    return o.value;
                  }) };
    pick('b');
    note(onC.value === 'bbs-2023' &&
         JSON.stringify(onC.shown) === JSON.stringify(['bbs-2023']) &&
         select.options[1].disabled === true &&
         select.options[0].disabled === false,
         '5. picking another configuration shows only its algorithms and ' +
         'selects its default', JSON.stringify(onC));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'portal-wallet-signing-alg');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_wallet_signing_alg',
  describe: '/portal/wallet\'s choice of the algorithm a credential is ' +
            'signed with: each configuration\'s list, the credential issued ' +
            'with the choice (ML-DSA-44 included), refusals, the drawn list ' +
            'and the runtime that follows the configuration radios',
  run: run
};
