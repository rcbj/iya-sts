// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/oauth_lists_paging.js
//
// ---------------------------------------------------------------------------
// FOUR OAUTH 2.0 / OIDC PAGES, THEIR LISTS PAGED (#313's sweep, 2026-10-12).
//
// `/admin/grants`, `/admin/claim-providers`, `/admin/commands` and
// `/admin/deliveries` drew every row they had — or, worse, cut the list at
// 500, 100 or 200 rows with nothing to say a row was missing. Each is drawn
// from its `/admin-api` answer, and each answer now pages its lists, so this
// file holds the four views to:
//
//   1. ONE PAGE OF EACH LIST, with the whole list still counted.
//   2. EACH PARAMETER MOVING ONLY ITS OWN LIST, `per` sizing them all.
//   3. A PAGE PAST THE END CLAMPED to the last.
//   4. A SEARCH NARROWING BEFORE THE PAGE (`grantq`, `linkq`).
//   5. NO SILENT CUT: past the old limits every row is reachable, and a
//      walk of every page reads each row once.
//
// In process, over each API class built with stand-ins for the register it
// reads: filling a realm with 600 command deliveries over HTTP would be 600
// relying parties' worth of traffic. The paging is the console's own
// (`admin_views.pagedRows()`), as on every other page.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const helpers = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const adminViews = require('../admin-core/admin_views');
const grantsApi = require('../oauth-oidc/grant_management_api');
const claimsApi = require('../oauth-oidc/claims_providers_api');
const commandsApi = require('../oauth-oidc/provider_commands_api');

const log = require('bunyan').createLogger({ name: 'oauth_lists_paging',
  level: process.env.LOG_LEVEL || 'info' });

function rowsOf(n, make) {
  log.debug("Entering rowsOf().");
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(make(i));
  }
  log.debug("Leaving rowsOf().");
  return out;
}

function baseDeps(extra) {
  log.debug("Entering baseDeps().");
  log.debug("Leaving baseDeps().");
  return Object.assign({ log: helpers.log, parseBody: helpers.parseBody,
    baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes,
    loadViews: function () {
      return adminViews;
    } }, extra);
}

// Every page of one list, by asking for each in turn until the last.
function walk(view, query, list, param) {
  log.debug("Entering walk().");
  const seen = [];
  for (let page = 1; page <= 100; page++) {
    const asked = Object.assign({}, query);
    asked[param] = String(page);
    const one = view(asked);
    seen.push.apply(seen, one.rows);
    if (page >= one.paging.pages) {
      break;
    }
  }
  log.debug("Leaving walk().");
  return seen;
}

function distinct(ids) {
  return ids.filter(function (id, i) {
    return ids.indexOf(id) === i;
  }).length;
}

function grants(t) {
  log.debug("Entering grants().");
  const all = rowsOf(37, function (i) {
    return { grantId: 'g-' + i, clientId: 'client-' + (i % 4),
             subject: 'urn:uuid:person-' + i, scopes: [], generation: 1,
             tokens: 0 };
  });
  const api = new grantsApi.GrantManagementApi(baseDeps({
    loadGrants: function () {
      return { list: function (clientId) {
        return all.filter(function (g) {
          return !clientId || g.clientId === clientId;
        });
      } };
    } }));
  const first = api.grantsView({ per: '10' });
  t.check(first.grants.length === 10 && first.total === 37 &&
          first.matched === 37 && first.paging.grants.pages === 4 &&
          first.paging.grants.param === 'grantsPage',
          'grants 1. one page of ten, on grantsPage, the total whole',
          JSON.stringify(first.paging.grants));
  const past = api.grantsView({ per: '10', grantsPage: '9' });
  t.check(past.paging.grants.page === 4 && past.grants.length === 7,
          'grants 3. a page past the end is the last page', '');
  const searched = api.grantsView({ per: '10', grantq: 'CLIENT-1' });
  // client-1 is every fourth grant from the second: nine of thirty-seven.
  t.check(searched.matched === 9 && searched.total === 37 &&
          searched.filter.q === 'CLIENT-1' &&
          searched.grants.every(function (g) {
            return g.clientId === 'client-1';
          }),
          'grants 4. grantq narrows before the page, case-insensitively',
          JSON.stringify({ matched: searched.matched }));
  const seen = walk(function (q) {
    const v = api.grantsView(q);
    return { rows: v.grants.map(function (g) {
      return g.grantId;
    }), paging: v.paging.grants };
  }, { per: '6' }, 'grants', 'grantsPage');
  t.check(seen.length === 37 && distinct(seen) === 37,
          'grants 5. walking every page reads every grant once', '');
  log.debug("Leaving grants().");
}

function claimProviders(t) {
  log.debug("Entering claimProviders().");
  const view = { callbackPath: '/oauth2/claims-callback',
    providers: rowsOf(12, function (i) {
      return { id: 'p' + i, claims: [] };
    }),
    links: rowsOf(29, function (i) {
      return { username: 'person' + i, provider: 'p' + (i % 3),
               sub: 'there-' + i };
    }) };
  const api = new claimsApi.ClaimsProvidersApi(baseDeps({
    loadProviders: function () {
      return { view: function () {
        return JSON.parse(JSON.stringify(view));
      } };
    } }));
  const first = api.pagedView({ per: '5' });
  t.check(first.providers.length === 5 && first.links.length === 5 &&
          first.counts.providers === 12 && first.counts.links === 29 &&
          first.paging.providers.param === 'providersPage' &&
          first.paging.links.param === 'linksPage',
          'claim providers 1. one page of each list, both counted whole',
          JSON.stringify(first.paging));
  const moved = api.pagedView({ per: '5', linksPage: '3' });
  t.check(moved.paging.links.page === 3 &&
          moved.paging.providers.page === 1 &&
          moved.links[0].username === 'person10',
          'claim providers 2. linksPage moves the links and not the ' +
          'providers', '');
  const searched = api.pagedView({ per: '5', linkq: 'p2' });
  t.check(searched.matched.links === 9 && searched.counts.links === 29 &&
          searched.paging.providers.total === 12,
          'claim providers 4. linkq narrows the links and not the providers',
          JSON.stringify(searched.matched));
  log.debug("Leaving claimProviders().");
}

function commands(t) {
  log.debug("Entering commands().");
  // Past every old cut: 500 accounts and deliveries, 100 runs.
  const report = {
    enabled: true, automatic: false, issuer: 'https://op.example',
    clients: rowsOf(14, function (i) {
      return { clientId: 'rp-' + i };
    }),
    accounts: rowsOf(612, function (i) {
      return { clientId: 'rp-0', sub: 'acct-' + i };
    }),
    runs: rowsOf(130, function (i) {
      return { id: 'run-' + i };
    }),
    deliveries: rowsOf(540, function (i) {
      return { id: 'd-' + i, state: 'dead' };
    }),
    counts: { pending: 0, sent: 0, dead: 540 },
    accountCommands: [], tenantCommands: [] };
  const kinds = [
    { id: 'backchannel-logout', rows: rowsOf(230, function (i) {
      return { id: 'b-' + i };
    }) },
    { id: 'provider-commands', rows: rowsOf(3, function (i) {
      return { id: 'c-' + i };
    }) }];
  const api = new commandsApi.ProviderCommandsApi(baseDeps({
    loadCommands: function () {
      return { report: function () {
        return JSON.parse(JSON.stringify(report));
      } };
    },
    loadOutbound: function () {
      return { KINDS: ['backchannel-logout', 'provider-commands'],
        kindReport: function () {
          return { kinds: JSON.parse(JSON.stringify(kinds)),
                   states: ['pending', 'sent', 'dead'] };
        } };
    } }));
  const first = api.commandsView({ per: '50' });
  t.check(first.accounts.length === 50 && first.runs.length === 50 &&
          first.deliveries.length === 50 && first.clients.length === 14 &&
          first.listCounts.accounts === 612 &&
          first.listCounts.runs === 130 &&
          first.listCounts.deliveries === 540 &&
          first.clientIds.length === 14,
          'commands 1. one page of each of the four, counted whole',
          JSON.stringify(first.listCounts));
  const moved = api.commandsView({ per: '50', runsPage: '2' });
  t.check(moved.paging.runs.page === 2 && moved.paging.accounts.page === 1 &&
          moved.paging.deliveries.page === 1 &&
          moved.runs[0].id === 'run-50',
          'commands 2. runsPage moves the runs and nothing else', '');
  const last = api.commandsView({ per: '50', accountsPage: '99' });
  t.check(last.paging.accounts.page === 13 && last.accounts.length === 12 &&
          last.accounts[11].sub === 'acct-611',
          'commands 3+5. the last page is reachable, past the old 500 cut',
          JSON.stringify(last.paging.accounts));
  const deliveries = api.deliveriesView({ per: '50' });
  const logout = deliveries.kinds[0];
  t.check(logout.rows.length === 50 && logout.matched === 230 &&
          logout.paging.param === 'backchannelLogoutPage' &&
          deliveries.kinds[1].paging.param === 'providerCommandsPage',
          'deliveries 1. each kind one page, on a parameter of its own',
          JSON.stringify(logout.paging));
  const kindMoved = api.deliveriesView({ per: '50',
                                         backchannelLogoutPage: '5' });
  t.check(kindMoved.kinds[0].paging.page === 5 &&
          kindMoved.kinds[0].rows[29].id === 'b-229' &&
          kindMoved.kinds[1].paging.page === 1,
          'deliveries 2+5. one kind\'s page moves only it, past the old ' +
          '200 cut', '');
  const seen = walk(function (q) {
    const k = api.deliveriesView(q).kinds[0];
    return { rows: k.rows.map(function (r) {
      return r.id;
    }), paging: k.paging };
  }, { per: '40' }, 'kinds', 'backchannelLogoutPage');
  t.check(seen.length === 230 && distinct(seen) === 230,
          'deliveries 5. walking every page reads every delivery once', '');
  log.debug("Leaving commands().");
}

function run(t) {
  log.debug("Entering run().");
  grants(t);
  claimProviders(t);
  commands(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oauth lists paging',
  describe: 'Grants, Claims Providers, OpenID Provider Commands and ' +
            'Outbound deliveries: every list one page through the API the ' +
            'console draws from, each pager its own, clamped, searched and ' +
            'walked past the old silent cuts',
  run: run
};
