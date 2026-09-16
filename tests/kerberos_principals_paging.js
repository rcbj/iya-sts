'use strict';

// ===========================================================================
// tests/kerberos_principals_paging.js — THE TWO LISTS ON
// /admin/kerberos/principals PAGE ON THEIR OWN PARAMETERS (2026-09-13).
//
// `adminViews.kerberosPrincipalsJson()` handed `pagedRows()` a `param` option,
// and `pagingOf()` reads no such option — it builds the parameter from `name`.
// So both lists read the bare `?page=`, while the page's links wrote
// `peoplePage` and `servicesPage`: every next, previous and numbered link
// reloaded page 1, and each link's own "page 2 of 3" line said otherwise
// because the console route re-attached the right name to the nav. Nothing
// errored and every assertion anybody had written passed, because a first
// page is what a working pager shows too.
//
// Three claims:
//   1. `?servicesPage=2` moves the services list and not the people list, and
//      `?peoplePage=2` the reverse — the paging objects AND the rows.
//   2. A bare `?page=` moves neither, which is what tells this fix from one
//      that made both lists follow one parameter.
//   3. The page draws the second page's principals when its own link is
//      followed, and every link it draws names a parameter the view reads.
//
// In process because it needs more than one page of each list, and a real
// service principal is a random key sealed on a directory entry: the two list
// functions are replaced for the length of the file and put back in a
// `finally`. The page's handler is called below the console gate with a
// request carrying only a query, as `pki_key_pair_paging.js` does.
// ===========================================================================

delete process.env.CONFIG_FILE;

const krb5PersonKeys = require('../kerberos/krb5_person_keys');
const adminViews = require('../admin-core/admin_views');
const app = require('../common/app');
// Registers `/admin/kerberos/principals` and starts nothing.
// Loading a module registers nothing since #50's R1; the composition root
// (`common/protocol_stack.ts`) does, so a test that loads one module
// registers its routes itself.
require('../admin-ui/admin').registerRoutes(app);

const log = require('bunyan').createLogger({
  name: 'kerberos_principals_paging',
  level: process.env.LOG_LEVEL || 'info' });

const PEOPLE = [0, 1, 2, 3, 4].map(function (n) {
  return { username: 'kpp-person-' + n,
           principal: 'kpp-person-' + n + '@EXAMPLE.COM',
           kvno: 2, etypes: [], retained: [], derivedAt: '', derivedOn: 'set',
           sealed: false, current: true };
});
const SERVICES = [0, 1, 2, 3, 4, 5, 6].map(function (n) {
  return { principal: 'HTTP/kpp-service-' + n + '@EXAMPLE.COM',
           spn: 'HTTP/kpp-service-' + n, kvno: 3, etypes: [], retained: [],
           createdAt: '', rotatedAt: '', sealed: false, held: true };
});

function names(rows, key) {
  log.debug("Entering names().");
  log.debug("Leaving names().");
  return rows.map(function (one) {
    return one[key];
  }).join(',');
}

function pageHandler() {
  log.debug("Entering pageHandler().");
  const layer = (app._router.stack || []).filter(function (one) {
    return one.route && one.route.path === '/admin/kerberos/principals' &&
           one.route.methods.get;
  })[0];
  log.debug("Leaving pageHandler(). " + (layer ? "Found." : "Not found."));
  return layer ? layer.route.stack[0].handle : null;
}

function drawPage(query) {
  log.debug("Entering drawPage().");
  let body = '';
  const res = {
    set: function () {
      return this;
    },
    status: function () {
      return this;
    },
    type: function () {
      return this;
    },
    send: function (text) {
      body = String(text);
      return this;
    },
    get: function () {
      return undefined;
    },
    getHeader: function () {
      return undefined;
    },
    setHeader: function () {
      return undefined;
    },
    locals: {}
  };
  const req = { query: query, headers: {}, method: 'GET', cookies: {},
                url: '/admin/kerberos/principals',
                originalUrl: '/admin/kerberos/principals',
                path: '/admin/kerberos/principals',
                get: function () {
                  return '';
                } };
  pageHandler()(req, res, function (e) {
    log.debug("The Kerberos principals handler called next(): " +
              ((e && e.message) || e));
  });
  log.debug("Leaving drawPage(). " + body.length + " character(s).");
  return body;
}

function runBody(t) {
  log.debug("Entering runBody().");
  // -------------------------------------------------------------------------
  t.log.info('=== 1. each list moves on its own parameter ===');
  const services2 = adminViews.kerberosPrincipalsJson({
    query: { per: '3', servicesPage: '2' } });
  t.equal(services2.servicesPaging.page, 2,
          '`servicesPage=2` puts the services list on page 2');
  t.equal(names(services2.services, 'spn'),
          'HTTP/kpp-service-3,HTTP/kpp-service-4,HTTP/kpp-service-5',
          'and the services it returns are rows 4–6');
  t.equal(services2.peoplePaging.page, 1,
          'while the people list stays on page 1');
  t.equal(names(services2.people, 'username'),
          'kpp-person-0,kpp-person-1,kpp-person-2',
          'with its first three people');

  const people2 = adminViews.kerberosPrincipalsJson({
    query: { per: '3', peoplePage: '2' } });
  t.equal(people2.peoplePaging.page, 2,
          '`peoplePage=2` puts the people list on page 2');
  t.equal(names(people2.people, 'username'), 'kpp-person-3,kpp-person-4',
          'and the people it returns are the last two');
  t.equal(people2.servicesPaging.page, 1,
          'while the services list stays on page 1');

  // -------------------------------------------------------------------------
  t.log.info('=== 2. a bare page moves neither ===');
  const bare = adminViews.kerberosPrincipalsJson({
    query: { per: '3', page: '2' } });
  t.check(bare.peoplePaging.page === 1 && bare.servicesPaging.page === 1,
          'a bare `page=2` moves NEITHER list — neither reads it',
          'people ' + bare.peoplePaging.page + ', services ' +
          bare.servicesPaging.page);

  // -------------------------------------------------------------------------
  t.log.info('=== 3. the page follows its own links ===');
  t.check(typeof pageHandler() === 'function',
          'GET /admin/kerberos/principals is registered');
  const first = drawPage({ per: '3' });
  const links = first.match(
    /href="\/admin\/kerberos\/principals\?[^"#]*#list-[a-zA-Z]+"/g) || [];
  t.check(links.length > 0 && links.every(function (href) {
    return /(peoplePage|servicesPage)=\d+/.test(href) &&
           !/[?&]page=/.test(href);
  }), 'every paging link names `peoplePage` or `servicesPage`, which the ' +
      'view reads', links.slice(0, 3).join(' '));
  t.check(first.indexOf('HTTP/kpp-service-0') >= 0 &&
          first.indexOf('HTTP/kpp-service-3') < 0,
          'page 1 draws the first services and not the fourth');
  const second = drawPage({ per: '3', servicesPage: '2' });
  t.check(second.indexOf('HTTP/kpp-service-3') >= 0 &&
          second.indexOf('HTTP/kpp-service-0') < 0,
          'following the services link draws rows 4–6 instead of page 1 again');
  t.check(second.indexOf('kpp-person-0') >= 0,
          'and the people table beside it is still on its first page');
  // The row buttons are drawn only for Admin Write, which a request with no
  // session does not hold, so what is checked is the other carrier: the
  // PEOPLE table's links on this page must keep the services position.
  const peopleLinks = second.match(
    /href="\/admin\/kerberos\/principals\?[^"#]*peoplePage=\d+[^"#]*#/g) || [];
  t.check(peopleLinks.length > 0 && peopleLinks.every(function (href) {
    return href.indexOf('servicesPage=2') >= 0;
  }), 'every People link on that page keeps `servicesPage=2`',
      peopleLinks.slice(0, 2).join(' '));
  log.debug("Leaving runBody().");
}

function run(t) {
  log.debug("Entering run().");
  const listPeople = krb5PersonKeys.listPeople;
  const listServices = krb5PersonKeys.listServices;
  krb5PersonKeys.listPeople = function () {
    return PEOPLE.slice();
  };
  krb5PersonKeys.listServices = function () {
    return SERVICES.slice();
  };
  try {
    runBody(t);
  } finally {
    krb5PersonKeys.listPeople = listPeople;
    krb5PersonKeys.listServices = listServices;
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_principals_paging',
  describe: 'The people and service principal lists on ' +
            '/admin/kerberos/principals page on peoplePage and servicesPage, ' +
            'which the page\'s own links write.',
  run: run
};
