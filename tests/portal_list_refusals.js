// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_list_refusals.js
//
// ===========================================================================
// TWO PORTAL LISTS THAT READ AS EMPTY WHEN THEY HAD NOTHING TO SAY
// (2026-10-20). In process, each page's class over its own dependencies:
//
//   1. `/portal/self-issued`: a person the directory holds no entry for is
//      REFUSED (STS-PORTAL-0616, 404, audited) rather than answered "none
//      enrolled"; a person with an entry and nothing enrolled still gets the
//      empty list, and one with something enrolled gets it;
//   2. `/portal/wallet`: a token whose `sub` and person do not name each
//      other is refused (STS-PORTAL-0617, 403, audited) for the history, an
//      offer and a Remove, before anything is read or written by that
//      subject; agreement in EITHER direction passes — the subject is the
//      person's entry's, or the subject's entry is filed under that name
//      (the legacy `urn:sts:user:` form, a name the directory folds) — and a
//      process with no directory refuses nothing; agreeing, with nothing
//      indexed, is still the empty history;
//   3. both pages, handed the refusal as their view, draw no list at all.
//
// That no LEGITIMATE caller is refused is held end to end by the wallet's
// own jobs (`portal_wallet.js`, `portal_wallet_history.js`,
// `portal_wallet_batch.js`), whose people sign in to the portal in a realm
// and read their history through the same operation.
// ===========================================================================

const PortalSelfIssued =
  require('../portal/portal_self_issued').PortalSelfIssued;
const PortalWallet = require('../portal/portal_wallet').PortalWallet;
const log = require('bunyan').createLogger({ name: 'portal_list_refusals',
  level: process.env.LOG_LEVEL || 'info' });

const quiet = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// The account API's helpers, recording what each operation answered.
function context() {
  log.debug("Entering context().");
  const ctx = {
    BASE: '/account-api', PORTAL: '/portal',
    audits: [],
    audit: { record: function (row) {
      ctx.audits.push(row);
    } },
    refuse: function (res, status, code, errors, extra) {
      res.sent = Object.assign({ status: status, code: code, ok: false,
                                 errors: [].concat(errors) }, extra || {});
      return res.sent;
    },
    json: function (res, status, body) {
      res.sent = Object.assign({ status: status }, body);
      return res.sent;
    },
    translatorFor: function () {
      return { text: function (key) {
        return key;
      } };
    }
  };
  log.debug("Leaving context().");
  return ctx;
}

function operation(page, ctx, id) {
  return page.accountOperations(ctx).filter(function (one) {
    return one.operationId === id;
  })[0];
}

const ALICE = 'pl-alice';
const ALICE_SUB = 'urn:uuid:aaaaaaaa-1111-2222-3333-444444444444';
const BOB = 'pl-bob';
const BOB_SUB = 'urn:uuid:bbbbbbbb-1111-2222-3333-444444444444';

function selfIssuedSections(t) {
  log.debug("Entering selfIssuedSections().");
  const held = { 'pl-alice': [], 'pl-carol': [
    { subject: 'did:jwk:abc', label: 'phone', by: 'pl-carol', proof: 'wallet',
      enrolledAt: '2026-10-20T00:00:00Z' }] };
  const page = new PortalSelfIssued({
    log: quiet,
    config: { value: function () {
      return false;
    } },
    siop: { PROOF_ADMIN: 'admin', list: function (name) {
      return Object.prototype.hasOwnProperty.call(held, name)
        ? held[name] : null;
    } }
  });
  const ctx = context();
  const get = operation(page, ctx, 'getSelfIssued');
  const answer = function (name) {
    const res = {};
    get.handler({}, res, { username: name, sub: 'urn:uuid:x' },
                { query: {} });
    return res.sent;
  };
  const nobody = answer('pl-nobody');
  t.check(nobody.status === 404 && nobody.code === 'STS-PORTAL-0616' &&
          nobody.ok === false && !nobody.subjects &&
          ctx.audits.some(function (row) {
            return row.errorCode === 'STS-PORTAL-0616' &&
              row.actor === 'pl-nobody' && row.outcome === 'failure';
          }),
          '1a. no entry for the person: refused, 404 STS-PORTAL-0616, ' +
          'audited, and no list', JSON.stringify(nobody));
  const none = answer(ALICE);
  t.check(none.status === 200 && Array.isArray(none.subjects) &&
          none.subjects.length === 0,
          '1b. an entry with nothing enrolled: the empty list, as before',
          JSON.stringify(none));
  const some = answer('pl-carol');
  t.check(some.status === 200 && some.subjects.length === 1 &&
          some.subjects[0].subject === 'did:jwk:abc',
          '1c. an entry with a subject enrolled: listed',
          JSON.stringify(some));
  log.debug("Leaving selfIssuedSections().");
}

function wallet(directory, asked) {
  log.debug("Entering wallet().");
  const page = new PortalWallet({
    log: quiet,
    userFor: function (name) {
      return { username: name };
    },
    hasSubjectResolver: function () {
      return directory !== null;
    },
    nameForSubject: function (sub) {
      if (/^urn:sts:user:/.test(sub)) {
        return sub.slice('urn:sts:user:'.length);
      }
      return (directory && directory.byUuid[sub]) || '';
    },
    subjectForName: function (name) {
      return (directory && directory.byName[String(name).toLowerCase()]) ||
        '';
    },
    loadOffers: function () {
      return { offerTtlMs: function () {
        return 600000;
      }, configuredWalletUrl: function () {
        return '';
      }, makeOffer: function () {
        asked.push('makeOffer');
        throw new Error('no offer is made in this test');
      } };
    },
    loadConfigs: function () {
      return { vciConfigIds: function () {
        return [];
      }, vciSigningAlgsFor: function () {
        return [];
      }, vciBatchSize: function () {
        return 1;
      } };
    },
    loadIssuer: function () {
      return { vciMetadata: function () {
        return { credential_configurations_supported: {} };
      } };
    },
    loadIssued: function () {
      return { issuancesForSubject: function (sub) {
        asked.push('history:' + sub);
        return [];
      }, removeForSubject: function (sub) {
        asked.push('remove:' + sub);
        return { ok: false, error: 'nothing' };
      } };
    }
  });
  log.debug("Leaving wallet().");
  return page;
}

function walletSections(t) {
  log.debug("Entering walletSections().");
  // The directory: alice's entry is filed as `pl-alice`, bob's as `pl-bob`.
  const directory = {
    byUuid: { [ALICE_SUB]: ALICE, [BOB_SUB]: BOB },
    byName: { 'pl-alice': ALICE_SUB, 'pl-bob': BOB_SUB }
  };
  const asked = [];
  const page = wallet(directory, asked);
  const ctx = context();
  const get = operation(page, ctx, 'getOfferableCredentials');
  const offer = operation(page, ctx, 'createCredentialOffer');
  const remove = operation(page, ctx, 'removeIssuedCredential');
  const history = function (caller) {
    const res = {};
    get.handler({}, res, caller, { query: {} });
    return res.sent;
  };

  // 2a. bob's subject on a token naming alice: somebody else's history.
  const crossed = { username: ALICE, sub: BOB_SUB };
  const seen = history(crossed);
  const offered = {};
  offer.handler({}, offered, crossed,
                { body: { configuration: 'X', mode: 'cross-device' } });
  const removed = {};
  remove.handler({}, removed, crossed, { body: { id: 'abc' } });
  t.check(seen.status === 403 && seen.code === 'STS-PORTAL-0617' &&
          !seen.issued && offered.sent.code === 'STS-PORTAL-0617' &&
          removed.sent.code === 'STS-PORTAL-0617' && asked.length === 0 &&
          ['portal.vc.view', 'portal.vc.offer', 'portal.vc.remove']
            .every(function (action) {
              return ctx.audits.some(function (row) {
                return row.action === action &&
                  row.errorCode === 'STS-PORTAL-0617';
              });
            }),
          '2a. another person\'s subject: the history, an offer and a ' +
          'Remove are refused (403 STS-PORTAL-0617, audited) and nothing ' +
          'is read or written by that subject',
          JSON.stringify({ seen: seen, asked: asked }));

  // 2b. a subject no entry carries: nobody's history.
  const orphan = history({ username: ALICE,
                           sub: 'urn:uuid:cccccccc-0000-0000-0000-0000000' +
                                '00000' });
  const unnamed = history({ username: ALICE, sub: '' });
  t.check(orphan.code === 'STS-PORTAL-0617' &&
          unnamed.code === 'STS-PORTAL-0617' && asked.length === 0,
          '2b. a subject no entry carries, or none at all: refused',
          JSON.stringify({ orphan: orphan, unnamed: unnamed }));

  // 2c. agreement in either direction.
  const own = history({ username: ALICE, sub: ALICE_SUB });
  const upper = history({ username: ALICE, sub: ALICE_SUB.toUpperCase() });
  const legacy = history({ username: ALICE, sub: 'urn:sts:user:' + ALICE });
  const folded = history({ username: 'PL-Alice', sub: ALICE_SUB });
  t.check([own, upper, legacy, folded].every(function (one) {
    return one.status === 200 && Array.isArray(one.issued) &&
      one.issued.length === 0 && one.paging.total === 0;
  }) && asked.filter(function (one) {
    return one.indexOf('history:') === 0;
  }).length === 4,
          '2c. the person\'s own subject (in any case), the legacy form ' +
          'naming them, and a name the directory folds all pass, and with ' +
          'nothing indexed the history is the empty list, as before',
          JSON.stringify({ own: own.status, upper: upper.status,
                           legacy: legacy.status, folded: folded.status,
                           asked: asked }));

  // 2d. no directory in the process: nothing to compare, nothing refused.
  const loose = wallet(null, []);
  const looseRes = {};
  operation(loose, context(), 'getOfferableCredentials').handler(
    {}, looseRes, { username: ALICE, sub: BOB_SUB }, { query: {} });
  t.check(looseRes.sent.status === 200,
          '2d. a process with no directory refuses nothing',
          JSON.stringify(looseRes.sent));
  log.debug("Leaving walletSections().");
}

function renderSections(t) {
  log.debug("Entering renderSections().");
  const tr = { html: function (key) {
    return '[' + key + ']';
  }, date: function (x) {
    return String(x);
  } };
  const SelfIssuedPages = require('../portal/web_self_issued');
  const WalletPages = require('../portal/web_wallet');
  const refused = { ok: false, errors: ['why'] };
  const selfHtml = SelfIssuedPages.render(refused, { t: tr, query: {} });
  const walletHtml = WalletPages.render(refused, { t: tr, query: {} });
  t.check(selfHtml.indexOf('portalSelfIssued.heading') >= 0 &&
          selfHtml.indexOf('siop-none') < 0 &&
          selfHtml.indexOf('siop-off') < 0 &&
          walletHtml.indexOf('portalWallet.heading') >= 0 &&
          walletHtml.indexOf('wallet-none') < 0 &&
          walletHtml.indexOf('<form') < 0,
          '3. handed a refusal, both pages draw their heading and no list ' +
          '(no "none" that would read as an answer)',
          selfHtml + ' | ' + walletHtml);
  // 3b. A LONG SUBJECT STAYS IN ITS CARD (2026-10-20, rcbj on 8081): a
  // did:jwk is two hundred characters with no space, and the table pushed
  // far past the card. The table is a heading-row `grid`, and a value in a
  // cell may break anywhere.
  const listed = SelfIssuedPages.render({ enabled: true, subjects: [
    { subject: 'did:jwk:' + 'eyJ'.repeat(70), proof: 'wallet' }] },
    { t: tr, query: {} });
  const style = require('../portal/web_portal_kit').STYLE;
  t.check(/<table class="grid">/.test(listed) &&
          style.indexOf('td code{overflow-wrap:anywhere}') >= 0,
          '3b. the self-issued list is a grid table and a long value in a ' +
          'cell wraps instead of widening the table',
          listed.slice(0, 300));
  log.debug("Leaving renderSections().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== 1. /portal/self-issued ===');
  selfIssuedSections(t);
  t.log.info('=== 2. /portal/wallet ===');
  walletSections(t);
  t.log.info('=== 3. the pages, refused, and a long subject ===');
  renderSections(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_list_refusals',
  describe: '/portal/self-issued refuses a person with no entry ' +
            '(STS-PORTAL-0616) and /portal/wallet a token whose sub and ' +
            'person disagree (STS-PORTAL-0617), instead of an empty list; ' +
            'the empty lists that are answers stay',
  run: run
};
