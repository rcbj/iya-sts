// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_wallet_batch.js
//
// ===========================================================================
// /portal/wallet's ISSUANCES AND THEIR BATCH COPIES (#670, rcbj 2026-10-17).
//
// With batch issuance on (`oid4vci.batchSize`, 4) a wallet sends four
// proofs and is given four credentials, each bound to a different key of
// its own. The register keeps them as four rows — a JOSE row is keyed by
// its credential — that share the Credential Response's `notification_id`,
// and the page lists them as ONE issuance with its copies. In a child
// (`wallet_kit.js`), through the account API the static portal uses:
//   1. a batch of four is one entry of `issued` with four `copies`, "Copy n
//      of 4", each copy's `keyThumbprint` the RFC 7638 thumbprint of the
//      proof key it was issued for, computed here, in the proofs' order;
//   2. the wallet's notification with the response's `notification_id`
//      reaches every copy, not only the first row's;
//   3. the page draws the batching note with the batch size, one issuance
//      row and four copy rows in a fold, each key shortened with the whole
//      thumbprint as its tooltip — and at a batch size of one, no note;
//   4. another person naming the issuance's id or a copy's is refused
//      (STS-PORTAL-0591) and all four stay valid;
//   5. Remove on one copy revokes exactly that copy's status-list entry and
//      register row and leaves the other three valid; the issuance is
//      `mixed`, three valid and one removed;
//   6. Remove on the issuance revokes the other three: all four INVALID,
//      every one refused at sign-in, one audit row for the act;
//   7. a page counts issuances, not copies;
//   8. a DID-bound (`ldp_vc`) batch keeps each copy's holder `did:jwk`.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'portal_wallet_batch',
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

  // RFC 7638 section 3, written here rather than borrowed from the service:
  // the required members of the key type, in lexicographic order, no
  // whitespace, SHA-256, base64url.
  function thumbprint(jwk) {
    const members = { EC: ['crv', 'kty', 'x', 'y'], OKP: ['crv', 'kty', 'x'],
                      RSA: ['e', 'kty', 'n'] }[jwk.kty];
    const json = '{' + members.map(function (m) {
      return JSON.stringify(m) + ':' + JSON.stringify(jwk[m]);
    }).join(',') + '}';
    return require('crypto').createHash('sha256').update(json, 'utf8')
      .digest('base64url');
  }

  async function sections(w, note, m) {
    const credentials = require(ROOT + '/common/credentials');
    const audit = require(ROOT + '/common/audit');
    const signin = require(ROOT + '/tests/protocol/portal_signin');
    const stamp = String(process.pid);
    const ALICE = 'pwb-alice-' + stamp;
    const MALLORY = 'pwb-mallory-' + stamp;
    const BOB = 'pwb-bob-' + stamp;
    const PASSWORD = 'Portal-Wallet-Batch-' + stamp + '-Passw0rd!';
    await w.inRealm(function () {
      w.provision();
      [ALICE, MALLORY, BOB].forEach(function (name) {
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
    const batchSize = await w.inRealm(function () {
      return Number(m.vcConfigs.vciBatchSize());
    });
    note(batchSize === 4, 'precondition: oid4vci.batchSize is 4',
         String(batchSize));

    const holders = [w.holderKey(), w.holderKey(), w.holderKey(),
                     w.holderKey()];
    const got = await w.issue(ALICE, holders[0], { holders: holders });
    const notificationId = got.response && got.response.json &&
                           got.response.json.notification_id;
    note(!!got.credentials && got.credentials.length === 4 &&
         !!notificationId,
         'precondition: one Credential Response carries four credentials ' +
         'and one notification_id', got.error || '');
    const subject = await w.inRealm(function () {
      return m.helpers.subjectForName(ALICE);
    });
    const rows = await w.inRealm(function () {
      return m.issued.rowsForSubject(subject);
    });
    note(rows.length === 4, 'precondition: the register keeps the batch as ' +
         'four rows, one per credential', String(rows.length));

    // --- 1. one issuance, four copies -------------------------------------
    const first = await alice.page('/portal/wallet');
    const issued = (first.json && first.json.issued) || [];
    const one = issued[0] || {};
    const copies = one.copies || [];
    note(first.status === 200 && first.json.batchSize === 4 &&
         issued.length === 1 && copies.length === 4 &&
         one.status === 'valid' && one.removable === true &&
         one.counts && one.counts.valid === 4 &&
         copies.every(function (c, i) {
           return c.position === i + 1 && c.of === 4 &&
                  c.status === 'valid' && c.removable === true &&
                  /^[A-Za-z0-9_-]{22}$/.test(c.id) && c.id !== one.id &&
                  /^\d+$/.test(String(c.statusIndex));
         }) &&
         new Set(copies.map(function (c) {
           return c.statusIndex;
         })).size === 4,
         '1a. a batch of four is ONE issuance with four copies, each valid ' +
         'with a status-list entry of its own', brief(first));
    const wanted = holders.map(function (h) {
      return thumbprint(h.jwk);
    });
    note(copies.length === 4 && copies.every(function (c, i) {
      return c.keyThumbprint === wanted[i];
    }) && new Set(wanted).size === 4,
         '1b. each copy\'s key is the RFC 7638 thumbprint of the proof key it ' +
         'was issued for, in the order of the proofs',
         JSON.stringify({ got: copies.map(function (c) {
           return c.keyThumbprint;
         }), wanted: wanted }));

    // --- 2. the wallet's report reaches every copy -------------------------
    const told = await w.request('POST', '/oid4vci/notification', {
      headers: { authorization: 'Bearer ' + got.accessToken },
      json: { notification_id: notificationId,
              event: 'credential_accepted' } });
    const afterTold = await alice.page('/portal/wallet');
    const toldOne = ((afterTold.json && afterTold.json.issued) || [])[0] || {};
    note(told.status === 204 && toldOne.walletEvent === 'credential_accepted' &&
         (toldOne.copies || []).length === 4 &&
         toldOne.copies.every(function (c) {
           return c.walletEvent === 'credential_accepted';
         }),
         '2. the wallet\'s notification is recorded on all four copies',
         told.status + ' ' + JSON.stringify(toldOne.copies || []));

    // --- 3. the page, and the note -----------------------------------------
    const drawn = await alice.draw('/portal/wallet');
    const html = String(drawn.html || '');
    const copyRows = html.match(/<tr data-credential="/g) || [];
    note(drawn.status === 200 && /id="wallet-batch-note"/.test(html) &&
         /given 4 copies/.test(html) &&
         (html.match(/<tr data-issuance="/g) || []).length === 1 &&
         copyRows.length === 4 && /<details><summary>4 copies<\/summary>/
           .test(html) &&
         html.indexOf('Copy 2 of 4') > 0 &&
         html.indexOf('<code title="' + wanted[1] + '">' +
                      wanted[1].slice(0, 12) + '&hellip;</code>') > 0 &&
         html.indexOf('>Remove all copies<') > 0 &&
         (html.match(/>Remove this copy</g) || []).length === 4,
         '3a. the page says batching is on with the batch size, and draws ' +
         'one row for the issuance and its four copies in a fold, each key ' +
         'shortened with the whole thumbprint as its tooltip',
         html.slice(html.indexOf('id="wallet-issued"'),
                    html.indexOf('id="wallet-issued"') + 1500));
    await w.inRealm(function () {
      m.config.setOverride('oid4vci.batchSize', 1);
    });
    const single = await alice.draw('/portal/wallet');
    await w.inRealm(function () {
      m.config.clearOverride('oid4vci.batchSize');
    });
    note(single.status === 200 && single.json.batchSize === 1 &&
         !/id="wallet-batch-note"/.test(String(single.html || '')) &&
         /id="wallet-issued"/.test(String(single.html || '')),
         '3b. at a batch size of one the page says nothing about batching',
         String(single.html || '').slice(0, 300));

    // --- 4. somebody else's ids --------------------------------------------
    const stolenAll = await mallory.act('/portal/remove-wallet-credential',
                                        { id: one.id });
    const stolenOne = await mallory.act('/portal/remove-wallet-credential',
                                        { id: copies[0].id });
    const still = await alice.page('/portal/wallet');
    const stillOne = ((still.json && still.json.issued) || [])[0] || {};
    note(stolenAll.status === 400 && stolenOne.status === 400 &&
         stillOne.status === 'valid' && stillOne.counts &&
         stillOne.counts.valid === 4 &&
         audit.list().filter(function (r) {
           return r.action === 'portal.vc.remove' && r.actor === MALLORY &&
                  r.errorCode === 'STS-PORTAL-0591';
         }).length === 2,
         '4. mallory naming alice\'s issuance or one of its copies is ' +
         'refused (STS-PORTAL-0591), and all four stay valid',
         brief(stolenAll) + ' / ' + brief(stolenOne));

    // The register's view of each copy, in the proofs' order: its
    // status-list entry, its issued-register mark, and why sign-in refuses
    // it. Each JOSE copy is a row of its own, found by its key and read
    // again so the state is current.
    function states() {
      return w.inRealm(function () {
        return wanted.map(function (jkt) {
          const meta = rows.filter(function (r) {
            return r.jkt === jkt;
          })[0];
          const row = meta ? m.issued.rowByKey(meta.key) : null;
          const c = row && row.credentials[0];
          return {
            status: c ? m.status.statusOf(c.statusKey) : -1,
            revoked: !!(c && c.artifactKey &&
                        m.stats.artifactRevokedByKey(c.artifactKey)),
            reason: row ? m.issued.disownedReason(row, [c]) : 'no row'
          };
        });
      });
    }

    // --- 5. remove one copy ------------------------------------------------
    const removedOne = await alice.act('/portal/remove-wallet-credential',
                                       { id: copies[1].id });
    const afterOne = await states();
    const viewOne = ((removedOne.json && removedOne.json.view &&
                      removedOne.json.view.issued) || [])[0] || {};
    note(removedOne.status === 200 && removedOne.json.ok === true &&
         removedOne.json.scope === 'copy' && removedOne.json.removed === 1 &&
         /other copies/.test(String(removedOne.json.message || '')),
         '5a. Remove on copy 2 answers that one copy was removed',
         brief(removedOne));
    note(afterOne[1].status === m.status.INVALID && afterOne[1].revoked &&
         /holder removed it/.test(afterOne[1].reason) &&
         [0, 2, 3].every(function (i) {
           return afterOne[i].status === m.status.VALID &&
                  !afterOne[i].revoked && afterOne[i].reason === '';
         }),
         '5b. exactly that copy\'s status-list entry is INVALID, its ' +
         'register row revoked and sign-in refuses it; the other three are ' +
         'valid', JSON.stringify(afterOne));
    note(viewOne.status === 'mixed' && viewOne.counts &&
         viewOne.counts.valid === 3 && viewOne.counts.removed === 1 &&
         viewOne.removable === true && viewOne.copies &&
         viewOne.copies[1].status === 'removed' &&
         viewOne.copies[1].removable === false &&
         viewOne.copies[0].status === 'valid',
         '5c. the issuance is mixed: three valid, one removed',
         JSON.stringify(viewOne));
    const mixedHtml = String((await alice.draw('/portal/wallet')).html || '');
    note(mixedHtml.indexOf('3 of 4: Valid') > 0 &&
         mixedHtml.indexOf('1 of 4: Removed by you') > 0 &&
         (mixedHtml.match(/>Remove this copy</g) || []).length === 3,
         '5d. the page says how many copies are in each state, and offers ' +
         'Remove only on the three still good', mixedHtml.slice(0, 200));

    // --- 6. remove every copy ----------------------------------------------
    const before = audit.list().filter(function (r) {
      return r.action === 'portal.vc.remove' && r.actor === ALICE;
    }).length;
    const removedAll = await alice.act('/portal/remove-wallet-credential',
                                       { id: one.id });
    const afterAll = await states();
    const viewAll = ((removedAll.json && removedAll.json.view &&
                      removedAll.json.view.issued) || [])[0] || {};
    const rowsAfter = audit.list().filter(function (r) {
      return r.action === 'portal.vc.remove' && r.actor === ALICE;
    });
    const act = rowsAfter.filter(function (r) {
      return r.detail && r.detail.scope === 'issuance';
    });
    note(removedAll.status === 200 && removedAll.json.scope === 'issuance' &&
         removedAll.json.removed === 3 &&
         /Every copy/.test(String(removedAll.json.message || '')) &&
         afterAll.every(function (s) {
           return s.status === m.status.INVALID && s.revoked &&
                  /holder removed it/.test(s.reason);
         }) &&
         viewAll.status === 'removed' && viewAll.removable === false &&
         rowsAfter.length === before + 1 && act.length === 1 &&
         act[0].detail.removed === 3 && act[0].detail.copies === 4,
         '6. Remove on the issuance revokes the other three: all four ' +
         'INVALID and refused at sign-in, in one audited act',
         JSON.stringify({ audit: [before, rowsAfter.length], act: act,
                          after: afterAll, view: viewAll.status }));
    const again = await alice.act('/portal/remove-wallet-credential',
                                  { id: one.id });
    note(again.status === 200 && again.json.ok === true &&
         again.json.removed === 0,
         '6b. removing it again is answered as done', brief(again));

    // --- 7. a page counts issuances ----------------------------------------
    // One issuance of four so far; nineteen of one make twenty issuances of
    // twenty-three credentials — one page. One more is twenty-one: two.
    let failed = '';
    for (let i = 0; i < 19 && !failed; i++) {
      const more = await w.issue(ALICE, w.holderKey());
      failed = more.error || '';
    }
    const p20 = await alice.page('/portal/wallet');
    const paging20 = (p20.json && p20.json.paging) || {};
    const more = await w.issue(ALICE, w.holderKey());
    const p21 = await alice.page('/portal/wallet', { page: 2 });
    const paging21 = (p21.json && p21.json.paging) || {};
    const lastPage = (p21.json && p21.json.issued) || [];
    note(!failed && !more.error && paging20.total === 20 &&
         paging20.pages === 1 && (p20.json.issued || []).length === 20 &&
         paging21.total === 21 && paging21.pages === 2 &&
         lastPage.length === 1 && lastPage[0].id === one.id &&
         (lastPage[0].copies || []).length === 4,
         '7. a page counts issuances: twenty of twenty-three credentials ' +
         'fit one page, and the twenty-first moves the batch, all four ' +
         'copies, to page 2',
         failed || more.error || JSON.stringify({ p20: paging20,
                                                  p21: paging21 }));

    // --- 8. a DID-bound batch ----------------------------------------------
    const bobs = [w.holderKey(), w.holderKey()];
    const ldp = await w.issue(BOB, bobs[0], { holders: bobs,
                                              format: 'ldp_vc' });
    const bobSub = await w.inRealm(function () {
      return m.helpers.subjectForName(BOB);
    });
    const bobIssued = await w.inRealm(function () {
      return m.issued.issuancesForSubject(bobSub);
    });
    const dids = await w.inRealm(function () {
      return bobs.map(function (h) {
        return m.di.didJwkOf(h.jwk);
      });
    });
    const bobCopies = (bobIssued[0] && bobIssued[0].copies) || [];
    note(!ldp.error && bobIssued.length === 1 && bobCopies.length === 2 &&
         bobCopies.every(function (c, i) {
           return c.holderDid === dids[i] &&
                  c.keyThumbprint === thumbprint(bobs[i].jwk);
         }),
         '8. an ldp_vc batch of two is one issuance whose copies keep their ' +
         'holder\'s did:jwk and key thumbprint',
         ldp.error || JSON.stringify(bobCopies));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'portal-wallet-batch');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_wallet_batch',
  describe: '/portal/wallet\'s batch copies: one issuance with its copies, ' +
            'each told apart by the key it is bound to, the batching note, ' +
            'and Remove for one copy or every copy',
  run: run
};
