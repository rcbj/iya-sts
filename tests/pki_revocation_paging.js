// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/pki_revocation_paging.js — PROTOCOLS → PKI PAGES EACH AUTHORITY'S
// LISTS AND DOES PER-ROW WORK FOR THE PAGE ONLY (#370, 2026-09-30).
//
// The revocation pane listed every certificate each authority had signed,
// each with a Revoke form, and every revoked serial with no certificate left
// — lists that every issue and every rotation make longer. #352's rule is
// *page before per-row work*, and each claim here is a COUNT against a
// population much larger than a page, never a time:
//
//   A. The model: with 5,000 issued certificates and 1,200 revocations on one
//      authority, the page holds 5 issued rows and 5 orphans, with the
//      totals and the paging beside them; `describeEntry()` runs for the
//      rows of the page only; `issuedHere()` — a rebuild of the issued list —
//      is never called; `issuedList()` and `listFor()` once per authority.
//   B. The revocation state on each row of the page is the register's:
//      revoked, held, or good, and a page past the end is the last page.
//   C. Each authority pages on its own parameter, and `per` is shared — and
//      can shorten a list below five, never lengthen it past five
//      (2026-09-30).
//   D. The pane draws the page's rows, a pager and a search box per list,
//      and every Revoke form carries `back` and the list it is in.
//   E. Each list's search narrows it before it is paged, on a parameter of
//      its own, and leaves the other lists alone (2026-09-30).
//
// The revocation register and the tree are stand-ins handed to a PkiAdmin of
// this file's own, because what is counted is what the page asks of them;
// everything else is the service's own.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realRevocation = require('../common/pki_revocation');
const pkiAdminModule = require('../admin-ui/pki_admin');

// The console's renderers draw in English here because common/i18n.ts
// installs node's default translator (#539); without it they draw keys.
require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'pki_revocation_paging',
  level: process.env.LOG_LEVEL || 'info' });

const ISSUED = 5000;
const REVOKED_ISSUED = 400;
const ORPHANS = 800;
const PER = 5;

function hex(n) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return (0x100000 + n).toString(16);
}

// Two authorities: `jose` with the big lists, `root` with a few rows, so that
// one authority's page parameter can be seen not to move the other.
function register() {
  log.debug("Entering register().");
  const calls = { issuedList: 0, listFor: 0, describeEntry: 0,
                  issuedHere: 0 };
  const issued = { jose: [], root: [] };
  const revoked = { jose: [], root: [] };
  for (let i = 0; i < ISSUED; i++) {
    issued.jose.push({ serialHex: hex(i), subject: 'CN=leaf ' +
                         String(i).padStart(5, '0'),
                       notAfter: '2030-01-01T00:00:00Z', kind: 'leaf',
                       label: '', expired: false });
  }
  for (let i = 0; i < REVOKED_ISSUED; i++) {
    revoked.jose.push({ serialHex: hex(i * 7 % ISSUED),
                        revokedAt: '2026-09-30T00:00:00Z',
                        reason: i % 5 === 0 ? 'certificateHold' : 'superseded',
                        reasonCode: i % 5 === 0 ? 6 : 4, subject: '' });
  }
  for (let i = 0; i < ORPHANS; i++) {
    revoked.jose.push({ serialHex: 'ff' + hex(i),
                        revokedAt: '2026-09-29T00:00:00Z',
                        reason: 'superseded', reasonCode: 4,
                        subject: 'CN=gone ' + i });
  }
  for (let i = 0; i < 3; i++) {
    issued.root.push({ serialHex: 'aa' + i, subject: 'CN=ca ' + i,
                       notAfter: '2030-01-01T00:00:00Z',
                       kind: 'intermediate-ca', label: '', expired: false });
  }
  const stub = Object.assign({}, realRevocation, {
    authorities: function () {
      return [
        { scope: '*process', ca: 'root', label: 'Root CA',
          tier: { subject: 'CN=Root', notAfter: '2040-01-01T00:00:00Z' } },
        { scope: '', ca: 'jose', label: 'JOSE Issuing CA',
          tier: { subject: 'CN=JOSE', notAfter: '2030-01-01T00:00:00Z' } }
      ];
    },
    distributionPoints: function () {
      return { http: 'http://x/crl', ldap: 'ldap://x/crl',
               ocsp: 'http://x/ocsp', caIssuers: 'http://x/ca', dn: 'cn=x' };
    },
    scopeSegment: function (scope) {
      return scope === '*process' ? 'process' : 'default';
    },
    issuedList: function (scope, ca) {
      calls.issuedList++;
      return issued[ca].slice();
    },
    listFor: function (scope, ca) {
      calls.listFor++;
      return revoked[ca].slice();
    },
    describeEntry: function (one) {
      calls.describeEntry++;
      return realRevocation.describeEntry(one);
    },
    issuedHere: function () {
      calls.issuedHere++;
      return false;
    }
  });
  log.debug("Leaving register().");
  return { stub: stub, calls: calls, issued: issued, revoked: revoked };
}

function adminWith(stub) {
  log.debug("Entering adminWith().");
  const deps = pkiAdminModule.PkiAdmin.defaultDeps();
  deps.pkiRevocation = stub;
  deps.pki = Object.assign({}, deps.pki, { PROCESS_SCOPE: '*process' });
  log.debug("Leaving adminWith().");
  return new pkiAdminModule.PkiAdmin(deps);
}

async function run(t) {
  log.debug("Entering run().");
  const r = register();
  const admin = adminWith(r.stub);

  t.log.info('=== A. the model holds one page, and per-row work is the ' +
             'page\'s ===');
  const model = admin['revocationModel']({});
  const jose = model.authorities.filter(function (one) {
    return one.ca === 'jose';
  })[0];
  t.check(!!jose, 'the big authority is in the model');
  t.equal(jose.issued.length, PER, 'its issued list is one page');
  t.equal(jose.issuedTotal, ISSUED, 'with the whole count beside it');
  t.equal(jose.revokedNotIssued.length, PER, 'its orphans are one page');
  t.equal(jose.revokedNotIssuedTotal, ORPHANS, 'with their whole count');
  t.equal(jose.revokedTotal, REVOKED_ISSUED + ORPHANS,
          'and the whole revocation count');
  t.equal(model.totalRevoked, REVOKED_ISSUED + ORPHANS,
          'the model\'s total counts every authority\'s whole list');
  // `param` and `noun` since #446: the paging control is drawn from this
  // answer in the static console, and needs the parameter that moves the
  // list and the noun its rows are counted in.
  t.equal(JSON.stringify(jose.issuedPaging),
          JSON.stringify({ page: 1, pages: ISSUED / PER, perPage: PER,
                           firstRow: 1, lastRow: PER, total: ISSUED,
                           param: 'ca-default-jose-issuedPage',
                           noun: 'certificates' }),
          'issuedPaging says what the page holds, and what moves it');
  t.equal(jose.orphansPaging.total, ORPHANS, 'orphansPaging too');
  t.check(r.calls.describeEntry <= 2 * PER,
          'describeEntry() ran for the rows of the page only, not the ' +
          (REVOKED_ISSUED + ORPHANS) + ' revocations',
          String(r.calls.describeEntry));
  t.equal(r.calls.issuedHere, 0,
          'issuedHere() — a rebuild of the issued list — was not called');
  t.equal(r.calls.issuedList, 2, 'issuedList() once per authority');
  t.equal(r.calls.listFor, 2, 'listFor() once per authority');
  t.check(!Object.prototype.propertyIsEnumerable.call(jose, 'pagingRaw'),
          'the renderer\'s paging objects are not published');

  t.log.info('=== B. each row\'s state is the register\'s ===');
  const bySerial = {};
  r.revoked.jose.forEach(function (entry) {
    bySerial[entry.serialHex] = entry;
  });
  const wrong = jose.issued.filter(function (row) {
    const entry = bySerial[row.serialHex] || null;
    return row.revoked !== !!entry ||
      row.held !== (!!entry && entry.reason === 'certificateHold') ||
      (entry && row.revokedReason !== entry.reason);
  });
  t.equal(wrong.length, 0, 'every row on the page says what the register ' +
          'says about its serial');
  t.check(jose.issued.some(function (row) { return row.revoked; }) &&
          jose.issued.some(function (row) { return !row.revoked; }),
          'the page holds revoked and good rows alike');
  const describedOnPage = jose.revoked.every(function (entry) {
    return jose.issued.some(function (row) {
      return row.revoked && row.serialHex === entry.serialHex;
    });
  });
  t.check(describedOnPage && jose.revoked.length ===
          jose.issued.filter(function (row) { return row.revoked; }).length,
          '`revoked` is the page\'s revocations, described');
  const last = admin['revocationModel'](
    { 'ca-default-jose-issuedPage': '9999' });
  const lastJose = last.authorities.filter(function (one) {
    return one.ca === 'jose';
  })[0];
  t.equal(lastJose.issuedPaging.page, ISSUED / PER,
          'a page past the end is the last page');
  t.equal(lastJose.issued[lastJose.issued.length - 1].serialHex,
          r.issued.jose[ISSUED - 1].serialHex,
          'and it ends at the last certificate');

  t.log.info('=== C. one parameter per list, `per` shared ===');
  const moved = admin['revocationModel']({ 'ca-default-jose-issuedPage': '3',
                                           per: '3' });
  const movedJose = moved.authorities.filter(function (one) {
    return one.ca === 'jose';
  })[0];
  const movedRoot = moved.authorities.filter(function (one) {
    return one.ca === 'root';
  })[0];
  t.equal(movedJose.issuedPaging.page, 3, 'the jose list moved to page 3');
  t.equal(movedJose.issued[0].serialHex, r.issued.jose[6].serialHex,
          'and page 3 of 3 starts at the 7th certificate');
  t.equal(movedJose.orphansPaging.page, 1,
          'its orphans list stayed on page 1');
  t.equal(movedRoot.issuedPaging.page, 1, 'the root list stayed on page 1');
  t.equal(movedRoot.issuedPaging.perPage, 3, 'per is shared by every list');
  const longer = admin['revocationModel']({ per: '50' });
  t.check(longer.authorities.every(function (one) {
    return one.issuedPaging.perPage === PER &&
      one.orphansPaging.perPage === PER && one.issued.length <= PER;
  }), 'a `per` above five is held to five on every list');

  // The list view is the page's renderer's since #446 (`admin-ui/web_pki.ts`).
  const PkiPage = require('../admin-ui/web_pki');
  t.log.info('=== D. the pane and the way back ===');
  const query = { 'ca-default-jose-issuedPage': '2', personsPage: '4',
                  'ca-bogus': '7', 'evil-issuedPage': '2' };
  const view = PkiPage.keyPairListView(query);
  t.check(view['ca-default-jose-issuedPage'] === '2' &&
          view.personsPage === '4' && !('ca-bogus' in view) &&
          !('evil-issuedPage' in view),
          'the list view carries the authority lists\' parameters and no ' +
          'name this file does not write', JSON.stringify(view));
  const json = { revocation: admin['revocationModel'](query) };
  // Drawn by the renderer from the model passed through JSON (#446).
  const html = PkiPage.revocationPane(JSON.parse(JSON.stringify(json)), view,
    require('../admin-ui/web_kit').context({}, true).t);
  const revokeForms =
    (html.match(/name="action" value="revoke-certificate"/g) || []).length;
  const releaseForms = (html.match(/name="action" value="release-hold"/g) ||
                        []).length;
  const joseModel = json.revocation.authorities.filter(function (one) {
    return one.ca === 'jose';
  })[0];
  const expectedForms = joseModel.issued.filter(function (row) {
    return !row.revoked;
  }).length + 3;
  t.equal(revokeForms, expectedForms,
          'a Revoke form for each unrevoked row on the page, and no more');
  t.equal(releaseForms, joseModel.issued.filter(function (row) {
    return row.held;
  }).length, 'a Release form for each held row on the page');
  t.check(html.indexOf('id="list-ca-default-jose-issuedPage"') >= 0 &&
          html.indexOf('id="list-ca-default-jose-orphansPage"') >= 0,
          'each of the big authority\'s lists has a pager');
  t.check(html.indexOf('ca-default-jose-issuedPage=3') >= 0,
          'the pager links to the next page of that list');
  t.check(html.indexOf('id="find-ca-default-jose-issuedq"') >= 0 &&
          html.indexOf('id="find-ca-default-jose-orphansq"') >= 0 &&
          html.indexOf('id="find-ca-process-root-issuedq"') >= 0,
          'every list has a search box, the one-page list as well');
  t.check(/name="list" value="ca-default-jose-issuedq"/.test(html) &&
          /name="back" value="\?[^"]*ca-default-jose-issuedPage=2/.test(html),
          'every form carries the list it is in and the page it is on');
  // Where a revoke sent the browser back to went with the server-rendered
  // console (#446): the static console stays on the page it was on.

  t.log.info('=== E. each list searched before it is paged ===');
  const searched = admin['revocationModel'](
    { 'ca-default-jose-issuedq': 'LEAF 0012',
      'ca-default-jose-orphansq': 'gone 79', 'ca-default-jose-orphansPage': '3',
      'ca-process-root-issuedPage': '1' });
  const sJose = searched.authorities.filter(function (one) {
    return one.ca === 'jose';
  })[0];
  const sRoot = searched.authorities.filter(function (one) {
    return one.ca === 'root';
  })[0];
  t.equal(sJose.issuedPaging.total, 10,
          'a case-insensitive substring of the subject matched ten of ' +
          ISSUED);
  t.equal(sJose.issuedPaging.pages, 2, 'two pages of five');
  t.check(sJose.issued.every(function (row) {
    return /^CN=leaf 0012\d$/.test(row.subject);
  }), 'and the page holds only matches');
  t.equal(sJose.issuedTotal, ISSUED, 'the whole count is still beside it');
  t.equal(sJose.issuedSearch, 'LEAF 0012', 'the reply echoes the search');
  t.equal(sJose.orphansPaging.total, 11,
          'the orphans are searched on their own parameter (79, 790–799)');
  t.equal(sJose.orphansPaging.page, 3, 'and page 3 of three is the last');
  t.equal(sRoot.issuedPaging.total, 3, 'the other authority is not narrowed');
  t.equal(sRoot.issuedSearch, null, 'and says so');
  const bySerialHex = admin['revocationModel'](
    { 'ca-default-jose-issuedq': hex(4321) });
  t.equal(bySerialHex.authorities.filter(function (one) {
    return one.ca === 'jose';
  })[0].issued[0].serialHex, hex(4321), 'a serial finds its certificate');
  const nothing = { revocation: admin['revocationModel'](
    { 'ca-default-jose-issuedq': 'no such thing' }) };
  const nothingView = PkiPage.keyPairListView(
    { 'ca-default-jose-issuedq': 'no such thing',
      'ca-default-jose-issuedPage': '4', personsPage: '2' });
  const nothingHtml = PkiPage.revocationPane(
    JSON.parse(JSON.stringify(nothing)), nothingView,
    require('../admin-ui/web_kit').context({}, true).t);
  t.check(nothingHtml.indexOf('matches the search above') >= 0,
          'a search that matches nothing says so');
  const form = (nothingHtml.match(
    /<form method="get" id="find-ca-default-jose-issuedq"[\s\S]*?<\/form>/) ||
    [''])[0];
  t.check(form.indexOf('value="no such thing"') >= 0 &&
          form.indexOf('name="personsPage" value="2"') >= 0 &&
          form.indexOf('name="ca-default-jose-issuedPage"') < 0,
          'the box re-shows its term, carries the other lists\' state and ' +
          'starts its own list at page 1', form);
  t.check(PkiPage.keyPairListView(
    { 'ca-default-jose-issuedq': 'x'.repeat(201) })[
    'ca-default-jose-issuedq'] === undefined,
          'a search longer than any field is not carried');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_revocation_paging',
  describe: '#370: Protocols → PKI pages each authority\'s issued and ' +
            'revoked lists and does per-row work for the page only',
  run: run
};
