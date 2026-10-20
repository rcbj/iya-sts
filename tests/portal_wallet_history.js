// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_wallet_history.js
//
// ===========================================================================
// /portal/wallet's HISTORY OF THE CREDENTIALS ISSUED TO THE PERSON, AND
// REMOVE (#661, rcbj 2026-10-16).
//
// A credential is issued as a wallet does it (`wallet_kit.js`), and then,
// through the account API the static portal uses:
//   1. `GET /account-api/credentials/offerable` lists it in `issued`: valid,
//      removable, nothing reported by the wallet yet;
//   2. the wallet's `credential_deleted` sent to the Notification Endpoint
//      (OpenID4VCI 1.0 section 11) with the Credential Response's
//      `notification_id` is shown on it, and revokes nothing;
//   3. another person naming its id is refused (STS-PORTAL-0591), and the
//      credential stays valid — the subject is the token's (OWASP A01);
//   4. its holder's Remove revokes it: `removed`, no longer removable, its
//      status-list entry INVALID, its issued-register row revoked, refused
//      at sign-in, and the audit row names the holder;
//   5. Remove again is answered as done;
//   6. the page draws the history, a Remove form for a credential that is
//      still good and none for one removed, and the note that the wallet's
//      copy must be deleted in the wallet;
//   7. the history is paged twenty at a time with the portal's own pager
//      (`kit.pageNav()`), a page past the end is the last, and a form on
//      page 2 carries it, so its answer is page 2.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'portal_wallet_history',
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
    const audit = require(ROOT + '/common/audit');
    const signin = require(ROOT + '/tests/vendored/portal_signin');
    const stamp = String(process.pid);
    const ALICE = 'pwh-alice-' + stamp;
    const MALLORY = 'pwh-mallory-' + stamp;
    const PASSWORD = 'Portal-Wallet-History-' + stamp + '-Passw0rd!';
    await w.inRealm(function () {
      w.provision();
      [ALICE, MALLORY].forEach(function (name) {
        m.ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });
    });
    const alice = await signin.signInToThePortal(w.base, ALICE, null,
                                                 { password: PASSWORD });
    const mallory = await signin.signInToThePortal(w.base, MALLORY, null,
                                                   { password: PASSWORD });
    note(!!alice.token && !!mallory.token,
         'precondition: alice and mallory sign in to the portal');

    const holder = w.holderKey();
    const got = await w.issue(ALICE, holder);
    const notificationId = got.response && got.response.json &&
                           got.response.json.notification_id;
    note(!!got.credential && !!notificationId,
         'precondition: a credential is issued to alice, with a ' +
         'notification_id', got.error || '');
    const subject = await w.inRealm(function () {
      return m.helpers.subjectForName(ALICE);
    });
    const row = await w.inRealm(function () {
      return m.issued.rowsForSubject(subject)[0] || null;
    });
    const recorded = row && row.credentials && row.credentials[0];

    // --- 1. listed ---------------------------------------------------------
    const first = await alice.page('/portal/wallet');
    const issued = (first.json && first.json.issued) || [];
    const one = issued[0] || {};
    note(first.status === 200 && issued.length === 1 &&
         one.configurationId === 'IdentityCredential' &&
         one.format === 'dc+sd-jwt' && one.status === 'valid' &&
         one.removable === true && one.walletEvent === '' &&
         /^[A-Za-z0-9_-]{22}$/.test(String(one.id || '')),
         '1. the credential is in issued: valid, removable, nothing ' +
         'reported by the wallet', brief(first));

    // --- 2. the wallet's report -------------------------------------------
    const told = await w.request('POST', '/oid4vci/notification', {
      headers: { authorization: 'Bearer ' + got.accessToken },
      json: { notification_id: notificationId,
              event: 'credential_deleted' } });
    const afterTold = await alice.page('/portal/wallet');
    const toldOne = ((afterTold.json && afterTold.json.issued) || [])[0] || {};
    note(told.status === 204 && toldOne.walletEvent === 'credential_deleted' &&
         !!toldOne.walletEventAt && toldOne.status === 'valid',
         '2. the wallet\'s credential_deleted is shown on it, and revokes ' +
         'nothing', told.status + ' ' + JSON.stringify(toldOne));

    // --- 3. somebody else's id ---------------------------------------------
    const stolen = await mallory.act('/portal/remove-wallet-credential',
                                     { id: one.id });
    const stillAlice = await alice.page('/portal/wallet');
    const stillOne = ((stillAlice.json && stillAlice.json.issued) || [])[0] ||
                     {};
    note(stolen.status === 400 && stolen.json && stolen.json.ok === false &&
         stillOne.status === 'valid' &&
         audit.list().some(function (r) {
           return r.action === 'portal.vc.remove' && r.actor === MALLORY &&
                  r.errorCode === 'STS-PORTAL-0591';
         }),
         '3. mallory naming alice\'s credential is refused ' +
         '(STS-PORTAL-0591), and it stays valid', brief(stolen));

    // --- 4. removed by its holder ------------------------------------------
    const removed = await alice.act('/portal/remove-wallet-credential',
                                    { id: one.id });
    const removedOne = ((removed.json && removed.json.view &&
                         removed.json.view.issued) || [])[0] || {};
    note(removed.status === 200 && removed.json.ok === true &&
         /wallet/i.test(String(removed.json.message || '')) &&
         removedOne.status === 'removed' && removedOne.removable === false &&
         !!removedOne.removedAt,
         '4a. alice\'s Remove answers the view with the credential removed',
         brief(removed));
    const after = await w.inRealm(function () {
      const r = m.issued.rowByKey(row && row.key);
      return {
        status: recorded && recorded.statusKey
          ? m.status.statusOf(recorded.statusKey) : -1,
        revoked: !!(recorded && recorded.artifactKey &&
                    m.stats.artifactRevokedByKey(recorded.artifactKey)),
        reason: r ? m.issued.disownedReason(r, r.credentials) : ''
      };
    });
    note(after.status === m.status.INVALID && after.revoked &&
         /holder removed it/.test(after.reason),
         '4b. its status-list entry is INVALID, its issued-register row ' +
         'revoked, and sign-in refuses it', JSON.stringify(after));
    const row4 = audit.list().filter(function (r) {
      return r.action === 'portal.vc.remove' && r.outcome === 'success';
    })[0];
    note(row4 && row4.actor === ALICE && row4.target === ALICE,
         '4c. the audit row names alice as the actor',
         JSON.stringify(row4 || null));

    // --- 5. again ----------------------------------------------------------
    const again = await alice.act('/portal/remove-wallet-credential',
                                  { id: one.id });
    note(again.status === 200 && again.json.ok === true,
         '5. removing it again is answered as done', brief(again));

    // --- 6. the page -------------------------------------------------------
    const drawn = await alice.draw('/portal/wallet');
    note(drawn.status === 200 && /id="wallet-issued"/.test(drawn.html) &&
         /id="wallet-remove-note"/.test(drawn.html) &&
         drawn.html.indexOf('data-issuance="' + one.id + '"') > 0 &&
         drawn.html.indexOf('action="/portal/remove-wallet-credential"') < 0,
         '6a. the page draws the history and the note, and no Remove for a ' +
         'removed credential', drawn.html.slice(0, 300));
    const fresh = await w.issue(ALICE, w.holderKey());
    const redrawn = await alice.draw('/portal/wallet');
    note(!!fresh.credential &&
         /<form method="post" action="\/portal\/remove-wallet-credential">/
           .test(redrawn.html) &&
         (redrawn.json.issued || []).length === 2 &&
         redrawn.json.issued[0].status === 'valid',
         '6b. a new credential, newest first, has its Remove form',
         fresh.error || JSON.stringify(redrawn.json.issued || []));

    // --- 7. paged ----------------------------------------------------------
    // Two so far; nineteen more makes twenty-one, one past a page. Each is
    // issued a millisecond apart at least, so "newest first" is an order.
    let failed = '';
    for (let i = 0; i < 19 && !failed; i++) {
      const more = await w.issue(ALICE, w.holderKey());
      failed = more.error || '';
    }
    const p1 = await alice.page('/portal/wallet');
    const p2 = await alice.page('/portal/wallet', { page: 2 });
    const past = await alice.page('/portal/wallet', { page: 9 });
    const paging1 = (p1.json && p1.json.paging) || {};
    const paging2 = (p2.json && p2.json.paging) || {};
    const oldest = ((p2.json && p2.json.issued) || [])[0] || {};
    note(!failed && (p1.json.issued || []).length === 20 &&
         paging1.page === 1 && paging1.pages === 2 && paging1.per === 20 &&
         paging1.total === 21 &&
         (p2.json.issued || []).length === 1 && paging2.page === 2 &&
         oldest.id === one.id && oldest.status === 'removed' &&
         past.json.paging && past.json.paging.page === 2,
         '7a. twenty to a page, newest first: the oldest, removed, is alone ' +
         'on page 2, and a page past the end is the last',
         failed || JSON.stringify({ p1: paging1, p2: paging2,
                                    oldest: oldest.id === one.id }));
    const pagedHtml = await alice.draw('/portal/wallet', { page: 2 });
    const firstHtml = await alice.draw('/portal/wallet');
    note(/id="pager-page"/.test(firstHtml.html) &&
         firstHtml.html.indexOf('href="/portal/wallet?page=2"') > 0 &&
         /id="pager-page"/.test(pagedHtml.html) &&
         /<input type="hidden" name="page" value="2">/.test(pagedHtml.html) &&
         !/name="page"/.test(firstHtml.html),
         '7b. the portal\'s pager is drawn under the history, and the ' +
         'forms on page 2 carry it', pagedHtml.html.slice(0, 300));
    const onTwo = (p1.json.issued || [])[19] || {};
    const removedOnTwo = await alice.act('/portal/remove-wallet-credential',
                                         { id: onTwo.id, page: '2' });
    const view2 = (removedOnTwo.json && removedOnTwo.json.view) || {};
    note(removedOnTwo.status === 200 && view2.paging &&
         view2.paging.page === 2 && (view2.issued || []).length === 1,
         '7c. a Remove sent from page 2 answers page 2',
         brief(removedOnTwo));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'portal-wallet-history');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_wallet_history',
  describe: '/portal/wallet\'s history of the credentials issued to the ' +
            'person, the wallet\'s notification shown on it, and Remove: ' +
            'revoked here, refused for anyone else, and the wallet\'s copy ' +
            'left for the person to delete',
  run: run
};
