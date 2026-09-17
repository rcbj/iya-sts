'use strict';

// ===========================================================================
// tests/pki_key_pair_paging.js — THE APPLICATIONS AND PEOPLE TABLES ON
// /admin/pki ARE PAGED (2026-09-13).
//
// Both tables drew every row they had. They page now, separately, on
// `issuedPage` and `personsPage` with one shared `per`, and four things
// about that are claims no amount of reading the page confirms:
//
//   1. THE TWO LISTS PAGE INDEPENDENTLY. A single `page` would have `next ›`
//      under People silently advancing Applications, and the markup looks the
//      same either way — so the test asks for page 2 of one and page 1 of the
//      other and checks which rows each table drew.
//   2. THE JSON CARRIES BOTH LISTS WHOLE, WITH THE PAGING BESIDE THEM.
//      `sts_jwt_bearer_grant.js` looks its client up in `issued` by
//      identifier; a reply holding one page would answer "not there" about an
//      application on page two.
//   3. EVERY PAGING LINK CARRIES BOTH TABLES' STATE, and every Take-off button
//      carries it as `back` — a link that dropped `personsPage` would reset the
//      table the reader was not touching.
//   4. THE REDIRECT A TAKE-OFF ANSWERS WITH IS REBUILT, NOT ECHOED. It is a
//      `Location` header made out of a request body; the page numbers survive
//      and anything else in `back` does not.
//
// In process because the page is behind the console gate and a sign-in is not
// what is under test: the route's own handler is called with a request that
// carries only a query. It creates applications and people in the default
// realm and removes every one of them, and the certificate authority it finds
// is the one it leaves (`tests/person_credentials.js` argues why).
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const applications = require('../common/applications');
const personAssertions = require('../common/person_assertions');
// Fills the directory slots the registry and the person register read through.
// It registers HTTP views and binds nothing.
const ldap = require('../ldap/ldap_server');
// Registers `/admin/pki` and starts nothing.
const pkiAdmin = require('../admin-ui/pki_admin');
const app = require('../common/app');
// Loading a module registers nothing since #50's R1; the composition root
// (`common/protocol_stack.ts`) does, so a test that loads one module
// registers its routes itself.
pkiAdmin.registerRoutes(app);

const log = require('bunyan').createLogger({ name: 'pki_key_pair_paging',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const APPS = [0, 1, 2, 3, 4].map(function (n) {
  return 'pkp-app-' + RUN + '-' + n;
});
const PEOPLE = [0, 1, 2].map(function (n) {
  return 'pkp-person-' + RUN + '-' + n;
});

// The GET /admin/pki handler as the router holds it, below the gate.
function pageHandler() {
  log.debug("Entering pageHandler().");
  const layer = (app._router.stack || []).filter(function (one) {
    return one.route && one.route.path === '/admin/pki' &&
           one.route.methods.get;
  })[0];
  log.debug("Leaving pageHandler(). " + (layer ? "Found." : "Not found."));
  return layer ? layer.route.stack[0].handle : null;
}

// The page's HTML for a query. Nothing in a query of this shape opens the
// certificate dialog, so the handler answers synchronously.
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
                url: '/admin/pki', originalUrl: '/admin/pki',
                path: '/admin/pki',
                get: function () {
                  return '';
                } };
  pageHandler()(req, res, function (e) {
    log.debug("The PKI page handler called next(): " + ((e && e.message) || e));
  });
  log.debug("Leaving drawPage(). " + body.length + " character(s).");
  return body;
}

// The markup between one heading id and the next thing named.
function between(body, fromId, toText) {
  log.debug("Entering between().");
  const start = body.indexOf('id="' + fromId + '"');
  const end = start < 0 ? -1 : body.indexOf(toText, start);
  log.debug("Leaving between().");
  return start < 0 ? '' : body.slice(start, end < 0 ? undefined : end);
}

function namesIn(markup, names) {
  log.debug("Entering namesIn().");
  log.debug("Leaving namesIn().");
  return names.filter(function (name) {
    return markup.indexOf('>' + name + '</a>') >= 0;
  });
}

async function runBody(t) {
  log.debug("Entering runBody().");
  t.check(typeof pageHandler() === 'function',
          'GET /admin/pki is registered and its handler can be reached');
  const built = pki.hasChain() ? { ok: true } : await pki.start({});
  t.check(built.ok, 'a certificate authority exists to issue people\'s key ' +
          'pairs from', (built.errors || []).join(' '));

  // A key pair on every application, so every row in the Applications table
  // has a Take-off button whose `back` can be checked. P-256, because five
  // RSA generations would be most of this file's run time.
  for (const [n, id] of APPS.entries()) {
    const made = applications.createApplication({
      identifier: id, protocols: ['oauth2'],
      fields: { oauthAssertionIssuer: 'https://pkp-' + RUN + '-' + n +
                                      '.example' } });
    t.check(made.ok, 'application ' + id + ' is created',
            ((made && made.errors) || []).join(' '));
    const issued = await pkiAdmin.pkiAction({
      action: 'issue', purpose: 'jwt', identifier: id,
      leafKeyAlg: 'ec-p256' });
    t.check(issued.ok, 'a key pair is issued to ' + id,
            ((issued && issued.errors) || []).join(' '));
  }
  for (const name of PEOPLE) {
    ldap.createUser(name, {});
    // `keyAlg`, the management API's spelling, where the applications above
    // use the console's `leafKeyAlg`: both must reach the issue. Until
    // 2026-09-16 `keyAlg` was accepted and ignored, and the leaf came out in
    // the Issuing CA's algorithm.
    const issued = await pkiAdmin.pkiAction({
      action: 'issue', target: 'person', purpose: 'jwt', identifier: name,
      keyAlg: 'ec-p256' });
    t.check(issued.ok, 'a key pair is issued to ' + name,
            ((issued && issued.errors) || []).join(' '));
    t.check(/^A ec-p256 /.test(String(issued && issued.why)),
            'in the ec-p256 the API spelling asked for',
            String(issued && issued.why).slice(0, 80));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== 1. the JSON: both lists whole, the paging beside them ===');
  const whole = pkiAdmin.pkiView({ query: {} });
  const ours = whole.issued.filter(function (one) {
    return APPS.indexOf(one.identifier) >= 0;
  });
  t.equal(ours.length, APPS.length,
          'every application created is in `issued` with no query');
  const json = pkiAdmin.pkiView({ query: { per: '2',
                                           issuedPage: '2' } });
  t.equal(json.issued.length, whole.issued.length,
          '`issued` is WHOLE whatever page was asked for — a reader looking ' +
          'an application up by identifier must not miss one on page two');
  t.equal(json.persons.length, whole.persons.length,
          'and so is `persons`');
  t.equal(json.issuedPaging.page, 2, '`issuedPaging` reports page 2');
  t.equal(json.issuedPaging.perPage, 2, 'at the `per` that was asked for');
  t.equal(json.issuedPaging.total, json.issued.length,
          'and counts the whole list');
  t.equal(json.personsPaging.page, 1,
          '`personsPaging` is on page 1 — `issuedPage` did not move it');
  t.equal(json.personsPaging.total, json.persons.length,
          'and counts people, one per member of `persons`');
  t.equal(whole.issuedPaging.perPage, 25,
          'with no `per`, a table shows twenty-five rows');

  // -------------------------------------------------------------------------
  t.log.info('=== 2. the page: each table draws its own slice ===');
  const perPage = 2;
  const appPage = 2;
  const peopleIndex = json.persons.map(function (one) {
    return one.username;
  });
  // The page of People that holds the first person this file made, so the
  // test knows which names must be drawn there and which must not.
  const personPage = Math.floor(peopleIndex.indexOf(PEOPLE[0]) / perPage) + 1;
  const query = { per: String(perPage), issuedPage: String(appPage),
                  personsPage: String(personPage) };
  const body = drawPage(query);
  t.check(body.indexOf('<table') >= 0, 'the page is drawn',
          body.slice(0, 200));
  const appsMarkup = between(body, 'pki-applications',
                             'Issue a signing key pair to a person');
  const peopleMarkup = between(body, 'pki-people', 'Revoking a certificate');

  const expectedApps = json.issued.slice((appPage - 1) * perPage,
                                         appPage * perPage)
    .map(function (one) {
      return one.identifier;
    });
  const drawnApps = namesIn(appsMarkup, whole.issued.map(function (one) {
    return one.identifier;
  }));
  t.equal(drawnApps.join(','), expectedApps.join(','),
          'the Applications table draws exactly rows ' +
          ((appPage - 1) * perPage + 1) + '–' + appPage * perPage);

  const expectedPeople = peopleIndex.slice((personPage - 1) * perPage,
                                           personPage * perPage);
  const drawnPeople = namesIn(peopleMarkup, peopleIndex);
  t.equal(drawnPeople.join(','), expectedPeople.join(','),
          'the People table draws exactly page ' + personPage +
          ' of people, whatever page Applications is on');

  t.check(/id="list-issuedPage"/.test(appsMarkup),
          'the Applications table has a paging control of its own');
  t.check(/id="list-personsPage"/.test(peopleMarkup) ||
          json.personsPaging.pages === 1,
          'and so does People, where it has more than one page');
  const appLinks = appsMarkup.match(/href="\/admin\/pki\?[^"#]*#list-/g) || [];
  t.check(appLinks.length > 0 && appLinks.every(function (href) {
    return href.indexOf('personsPage=' + personPage) >= 0 &&
           href.indexOf('per=' + perPage) >= 0;
  }), 'every Applications paging link carries People\'s page and the ' +
      'shared `per`', appLinks.slice(0, 2).join(' '));
  t.equal((body.match(/id="per"/g) || []).length, 1,
          'the rows-per-table control is drawn once, and its id is unique');

  const expectedBack = 'name="back" value="?per=' + perPage +
                       '&amp;issuedPage=' + appPage +
                       '&amp;personsPage=' + personPage + '"';
  [['Applications', appsMarkup], ['People', peopleMarkup]]
    .forEach(function (pair) {
      const buttons = (pair[1].match(/Take this key pair off/g) || []).length;
      const backs = pair[1].match(/name="back" value="[^"]*"/g) || [];
      t.check(buttons > 0 && backs.length === buttons &&
              backs.every(function (one) {
                return one === expectedBack;
              }),
              'every Take-off button in the ' + pair[0] + ' table carries ' +
              'both tables\' state as `back`',
              buttons + ' button(s): ' + backs.slice(0, 2).join(' '));
    });

  const clamped = pkiAdmin.pkiView({ query: { per: '2',
                                              issuedPage: '9999' } });
  t.equal(clamped.issuedPaging.page, clamped.issuedPaging.pages,
          'a page past the end is the last page, not an empty table');

  // -------------------------------------------------------------------------
  t.log.info('=== 3. where a Take-off button sends the browser ===');
  t.equal(pkiAdmin.returnTo({ action: 'revoke', target: 'person',
                              identifier: PEOPLE[0],
                              back: '?per=2&personsPage=3&issuedPage=2' }),
          '/admin/pki?per=2&issuedPage=2&personsPage=3#pki-people',
          'a person\'s Take-off lands on the same pages, at the People table');
  t.equal(pkiAdmin.returnTo({ action: 'revoke', identifier: APPS[0],
                              back: '?issuedPage=4' }),
          '/admin/pki?issuedPage=4#pki-applications',
          'an application\'s lands at the Applications table');
  t.equal(pkiAdmin.returnTo({ action: 'revoke', identifier: APPS[0],
                              back: '?next=//evil.example&per=x&' +
                                    'issuedPage=2%0d%0aSet-Cookie:a' }),
          '/admin/pki#pki-applications',
          'anything in `back` that is not a page number is dropped — the ' +
          'destination is rebuilt, never echoed');
  t.equal(pkiAdmin.returnTo({ action: 'build' }), '/admin/pki',
          'a control that carries no `back` gets the bare page, as before');
  log.debug("Leaving runBody().");
}

function heldAuthority() {
  log.debug("Entering heldAuthority().");
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(before) {
  log.debug("Entering restoreAuthority().");
  if (!before.chain && pki.hasChain()) {
    pki.clearChain(undefined);
  }
  if (!before.root && keystore.pkiFor(pki.SERVICE_SCOPE)) {
    keystore.attachPki(pki.SERVICE_SCOPE, null);
  }
  log.debug("Leaving restoreAuthority().");
}

function removeWhatWasMade() {
  log.debug("Entering removeWhatWasMade().");
  APPS.forEach(function (id) {
    if (applications.get(id)) {
      applications.deleteApplication(id);
    }
  });
  PEOPLE.forEach(function (name) {
    personAssertions.PURPOSE_IDS.forEach(function (purpose) {
      personAssertions.clear(name, purpose);
    });
    const found = ldap.objectFor(name);
    if (found && found.entry) {
      ldap.deletePerson(found.entry.dn);
    }
  });
  log.debug("Leaving removeWhatWasMade().");
}

async function run(t) {
  log.debug("Entering run().");
  const before = heldAuthority();
  try {
    await runBody(t);
  } finally {
    removeWhatWasMade();
    restoreAuthority(before);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_key_pair_paging',
  describe: 'The Applications and People tables on /admin/pki page ' +
            'separately on one `per`, the JSON keeps both lists whole with ' +
            'the paging beside them, and a Take-off button returns to the ' +
            'page it was pressed on.',
  run: run
};
