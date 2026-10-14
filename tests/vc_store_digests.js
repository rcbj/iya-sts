// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/vc_store_digests.js
//
// ===========================================================================
// THE OPENID4VC AND SHARED SIGNALS STORES KEEP DIGESTS, NOT CREDENTIALS
// (#614).
//
// Every store below is a declared `realms.map({ persist })`: journalled,
// replicated into every request worker and node, and sealed into
// `sts_minted` in product mode. #614 has each keep `crypto.credentialDigest()`
// of a bearer value it only looks up, spends or compares — or drop a whole
// token nothing read back — and this file is how a regression is caught:
// for each store it drives the flow that writes it, over real HTTP where
// there is one, and then reads the STORE ITSELF and asserts the raw value
// is not in it, neither as a key nor anywhere in a row's JSON. A flow that
// still works after the change is the other half: a lookup that forgot to
// hash would find nothing, and the flow would fail.
//
//   1. pre-authorized codes: keyed by the code's digest, the Transaction
//      Code kept as `txCodeDigest` (never `txCode`), and a right and a
//      wrong tx_code still told apart at the token endpoint;
//   2. issuer states and offers by reference: keyed by digests, and the
//      offer still served at its `credential_offer_uri`;
//   3. c_nonces: keyed by `vc_issuer.nonceKey()`, and a credential issued
//      against one;
//   4. notification ids: no access token on the row;
//   5. deferred transactions: keyed by the transaction_id's digest, no
//      access token on the row, and the credential still collected;
//   6. an OpenID4VP verdict: `presentationDigest` and the verified claims,
//      never the presentation;
//   7. the SSF receivers' inbox: `tokenDigest`, the header and the claims,
//      never the SET, and the described row the pages draw says the same.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason: the whole
// stack is loaded and settings are flipped (`tests/wallet_kit.js`).
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');
const log = require('bunyan').createLogger({ name: 'vc_store_digests',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
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

  // Every key and every row of a digest-keyed facade, in the ambient realm.
  function rowsOf(facade) {
    const out = [];
    facade.forEachDigest(function (value, key) {
      out.push({ key: key, value: value });
    });
    return out;
  }

  // Every key and every row of a plain declared store.
  function plainRowsOf(store) {
    const out = [];
    store.forEach(function (value, key) {
      out.push({ key: key, value: value });
    });
    return out;
  }

  // Whether a raw value appears anywhere in a store: as a key, or as a
  // substring of any row's JSON.
  function holds(rows, raw) {
    const needle = String(raw);
    return rows.some(function (one) {
      return String(one.key) === needle ||
             JSON.stringify(one.value).indexOf(needle) >= 0;
    });
  }

  async function sections(w, note, m) {
    const digest = m.stsCrypto.credentialDigest;
    const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('dg-alice', { invent: false });
    });

    // ==================================================================
    // 1. PRE-AUTHORIZED CODES AND THE TRANSACTION CODE
    // ==================================================================
    const built = await w.inRealm(function () {
      return m.offers.buildCredentialOffer(w.fakeReq(''),
        ['IdentityCredential'], 'cross-device',
        { user: m.helpers.userFor('dg-alice') });
    });
    const codeRows = await w.inRealm(function () {
      return rowsOf(m.offers.preAuthorizedCodes);
    });
    const codeRow = codeRows.filter(function (one) {
      return one.key === digest(built.preAuthorizedCode);
    })[0];
    note(built.preAuthorizedCode && codeRow &&
         !holds(codeRows, built.preAuthorizedCode),
         '1a. a pre-authorized code is stored under its digest, and the ' +
         'code is nowhere in the store',
         JSON.stringify(codeRows.map(function (one) {
           return one.key;
         })));
    note(codeRow && codeRow.value.txCode === undefined &&
         codeRow.value.txCodeDigest === digest(built.txCode),
         '1b. the Transaction Code is kept as txCodeDigest, never as txCode',
         JSON.stringify(codeRow && Object.keys(codeRow.value)));
    const wrongTx = built.txCode === '11111' ? '22222' : '11111';
    const wrong = await w.request('POST', '/oauth2/token', {
      form: Object.assign({ grant_type: PRE_AUTH,
        'pre-authorized_code': built.preAuthorizedCode, tx_code: wrongTx },
      w.client) });
    const right = await w.request('POST', '/oauth2/token', {
      form: Object.assign({ grant_type: PRE_AUTH,
        'pre-authorized_code': built.preAuthorizedCode,
        tx_code: built.txCode }, w.client) });
    note(wrong.status === 400 && /not correct/.test(wrong.text) &&
         right.status === 200 && right.json && right.json.access_token,
         '1c. the token endpoint still finds the code by the digest of the ' +
         'one presented, refuses a wrong tx_code and redeems the right one',
         wrong.status + ' ' + wrong.text.slice(0, 160) + ' | ' +
         right.status + ' ' + right.text.slice(0, 160));
    const afterRedeem = await w.inRealm(function () {
      return m.offers.preAuthorizedCodes.get(built.preAuthorizedCode);
    });
    note(!afterRedeem, '1d. and the redeemed code is gone from the store');

    // ==================================================================
    // 2. ISSUER STATES AND OFFERS BY REFERENCE
    // ==================================================================
    const sameDevice = await w.inRealm(function () {
      return m.offers.makeOffer(w.fakeReq(''),
        { configurationIds: ['IdentityCredential'], mode: 'same-device',
          byReference: true, wallet: '' });
    });
    const issuerState = sameDevice.built.issuerState;
    const stateRows = await w.inRealm(function () {
      return rowsOf(m.offers.issuerStates);
    });
    note(issuerState && stateRows.some(function (one) {
      return one.key === digest(issuerState);
    }) && !holds(stateRows, issuerState) &&
         await w.inRealm(function () {
           return m.offers.issuerStates.has(issuerState);
         }),
         '2a. an issuer_state is stored under its digest and found by the ' +
         'value the wallet hands back', issuerState);
    const offerUri = sameDevice.byReference &&
                     sameDevice.byReference.credentialOfferUri;
    const offerId = offerUri ? offerUri.split('/').pop() : '';
    const offerRows = await w.inRealm(function () {
      return rowsOf(m.offers.credentialOffers);
    });
    note(offerId && offerRows.some(function (one) {
      return one.key === digest(offerId);
    }) && !offerRows.some(function (one) {
      return one.key === offerId;
    }),
         '2b. an offer by reference is stored under the digest of its id',
         offerId);
    const fetched = offerUri ? await w.request('GET', w.pathOf(offerUri))
                             : { status: 0, text: '' };
    note(fetched.status === 200 && fetched.json &&
         fetched.json.grants && fetched.json.grants.authorization_code &&
         fetched.json.grants.authorization_code.issuer_state === issuerState,
         '2c. and is still served at its credential_offer_uri, whole — the ' +
         'documented exception (OpenID4VCI section 4.1.3)',
         fetched.status + ' ' + fetched.text.slice(0, 200));

    // ==================================================================
    // 3 AND 4. A c_nonce, AND THE NOTIFICATION ROW
    // ==================================================================
    const nonce = await w.request('POST', '/oid4vci/nonce', { form: {} });
    const cNonce = nonce.json && nonce.json.c_nonce;
    const nonceRows = await w.inRealm(function () {
      return plainRowsOf(m.issuer.vciNonces);
    });
    note(cNonce && nonceRows.some(function (one) {
      return one.key === m.issuer.nonceKey(cNonce);
    }) && !holds(nonceRows, cNonce),
         '3a. a c_nonce is stored under vc_issuer.nonceKey(), its digest, ' +
         'and the nonce is nowhere in the store', cNonce);
    const holder = w.holderKey();
    const issued = await w.issue('dg-alice', holder);
    note(issued.credential && !issued.error,
         '3b. and a credential is issued against a nonce the proof quotes ' +
         '— found by its digest', issued.error || '');
    const notificationId = issued.response && issued.response.json &&
                           issued.response.json.notification_id;
    const notificationRows = await w.inRealm(function () {
      return plainRowsOf(m.issuer.notificationIds);
    });
    const notificationRow = notificationRows.filter(function (one) {
      return one.key === notificationId;
    })[0];
    note(notificationRow && notificationRow.value.accessToken === undefined &&
         issued.accessToken && !holds(notificationRows, issued.accessToken),
         '4a. a notification row carries no access token, and the token is ' +
         'nowhere in the store',
         JSON.stringify(notificationRow && Object.keys(notificationRow.value)));

    // ==================================================================
    // 5. DEFERRED TRANSACTIONS
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vci.deferredReadyMs', 0);
    });
    const deferredOffer = await w.inRealm(function () {
      return m.offers.buildCredentialOffer(w.fakeReq(''),
        ['IdentityCredential'], 'deferred',
        { user: m.helpers.userFor('dg-alice') });
    });
    const deferredToken = await w.request('POST', '/oauth2/token', {
      form: Object.assign({ grant_type: PRE_AUTH,
        'pre-authorized_code': deferredOffer.preAuthorizedCode,
        tx_code: deferredOffer.txCode }, w.client) });
    const token = deferredToken.json && deferredToken.json.access_token;
    const pending = token ? await w.issue('dg-alice', w.holderKey(),
                                          { token: token }) : {};
    const answered = pending.response || { status: 0, json: null };
    const transactionId = answered.json && answered.json.transaction_id;
    const txRows = await w.inRealm(function () {
      return rowsOf(m.offers.deferredTransactions);
    });
    const txRow = txRows.filter(function (one) {
      return one.key === digest(transactionId);
    })[0];
    note(answered.status === 202 && transactionId && txRow &&
         !holds(txRows, transactionId),
         '5a. a deferred transaction is stored under the digest of its ' +
         'transaction_id, and the id is nowhere in the store',
         answered.status + ' ' + String(transactionId));
    note(txRow && txRow.value.accessToken === undefined &&
         !holds(txRows, token),
         '5b. and the row carries no access token, and the token is ' +
         'nowhere in the store',
         JSON.stringify(txRow && Object.keys(txRow.value)));
    const collected = transactionId ? await w.request('POST',
      '/oid4vci/deferred_credential', {
        headers: { authorization: 'Bearer ' + token },
        json: { transaction_id: transactionId } }) : { status: 0, text: '' };
    note(collected.status === 200 && collected.json &&
         Array.isArray(collected.json.credentials),
         '5c. and the credential is collected by the transaction_id the ' +
         'wallet presents', collected.status + ' ' +
         collected.text.slice(0, 200));
    await w.inRealm(function () {
      m.config.clearOverride('oid4vci.deferredReadyMs');
    });

    // ==================================================================
    // 6. AN OPENID4VP VERDICT
    // ==================================================================
    const started = await w.verificationStart('by=reference');
    const barUrl = started.headers.location
      ? new URL(started.headers.location) : null;
    const barRo = barUrl ? w.decode((await w.request('GET',
      w.pathOf(barUrl.searchParams.get('request_uri')))).text) : null;
    let presentation = '';
    let answer = { status: 0, text: '' };
    if (barRo && issued.credential) {
      await w.inRealm(function () {
        m.config.setOverride('oid4vp.claims', '');
        const tx = m.verifier.transactionFor(barRo.state);
        tx.requested = [];
        m.verifier.saveTransaction(tx);
      });
      presentation = w.presentSdJwt(issued.credential, holder, barRo.nonce,
                                    barRo.client_id);
      answer = await w.request('POST', '/oid4vp/response', {
        form: { state: barRo.state,
                vp_token: w.vpToken('dc+sd-jwt', presentation) } });
      await w.inRealm(function () {
        m.config.clearOverride('oid4vp.claims');
      });
    }
    const outcome = barRo ? await w.inRealm(function () {
      return m.verifier.verificationOutcome(barRo.state);
    }) : null;
    const verdict = (outcome && outcome.verdict) || {};
    const kbJwt = presentation.split('~').pop();
    note(answer.status === 200 && verdict.ok === true &&
         verdict.presentation === undefined &&
         verdict.presentationDigest === digest(presentation),
         '6a. an accepted presentation\'s verdict names it by ' +
         'presentationDigest and never carries it',
         answer.status + ' ' + JSON.stringify(Object.keys(verdict)));
    const stored = barRo ? await w.inRealm(function () {
      return JSON.stringify(m.verifier.transactionFor(barRo.state) || {});
    }) : '';
    note(stored && kbJwt && stored.indexOf(kbJwt) < 0 &&
         stored.indexOf(presentation) < 0 &&
         verdict.claims && typeof verdict.claims === 'object',
         '6b. the transaction holds neither the presentation nor its Key ' +
         'Binding JWT, and keeps the verified claims', stored.slice(0, 300));

    // ==================================================================
    // 7. THE SSF RECEIVERS' INBOX
    // ==================================================================
    // Delivered the way `tests/ssf_receivers.js` delivers one: a real signed
    // SET handed to `accept()` with the stream's own authorization header —
    // the loopback push itself is that file's to hold.
    const receivers = require(ROOT + '/ssf/ssf_receivers');
    const events = require(ROOT + '/ssf/ssf_events');
    let set = '';
    const pushed = await w.inRealm(function () {
      receivers.seedStreams();
      const stream = receivers.streamFor(receivers.ADMIN);
      if (!stream) {
        return { status: 0, why: 'no seeded stream' };
      }
      set = events.signSetSync(events.buildSet({
        issuer: stream.iss,
        audience: receivers.surfaceOf(receivers.ADMIN).audience,
        uri: events.CAEP_EVENT_URIS[0],
        payload: { event_timestamp: Math.floor(Date.now() / 1000) },
        subject: { format: 'opaque', id: 'dg-subject' } }));
      return receivers.accept(receivers.ADMIN, {
        headers: { authorization: stream.delivery.authorization_header,
                   'content-type': 'application/secevent+jwt' },
        body: set });
    });
    const inbox = await w.inRealm(function () {
      return receivers.listFor(receivers.ADMIN, {});
    });
    const entry = inbox.filter(function (one) {
      return one && one.tokenDigest === digest(set);
    })[0];
    note(pushed.status === 202 && set && entry &&
         entry.token === undefined && entry.claims && entry.header &&
         JSON.stringify(inbox).indexOf(set) < 0,
         '7a. a received SET is kept as its tokenDigest, header and claims, ' +
         'never the SET', JSON.stringify(pushed).slice(0, 300) +
         ' | ' + JSON.stringify(entry && Object.keys(entry)));
    const described = await w.inRealm(function () {
      return receivers.view(receivers.ADMIN, {});
    });
    const row = (described.received || []).filter(function (one) {
      return one.tokenDigest === digest(set);
    })[0];
    note(row && row.token === undefined,
         '7b. and the row the pages and /admin-api draw names it by ' +
         'tokenDigest, with no token', JSON.stringify(row || {}).slice(0, 300));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'vc-store-digests');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_store_digests',
  describe: 'the OpenID4VC stores and the SSF receivers\' inbox keep ' +
            'digests of the codes, nonces, ids, presentations and SETs ' +
            'they only look up — never the values (#614)',
  run: run
};
