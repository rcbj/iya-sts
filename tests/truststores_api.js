// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: truststores_api.js
//
// ===========================================================================
// THE NAMED TRUSTSTORES' MANAGEMENT API AND CONSOLE TABS (#2118 phase 4).
//
// `GET /admin-api/truststores` and `POST /admin-api/truststores/:action`
// (`mgmt-api/admin_api.ts`, `admin-core/admin_actions.ts`'s
// `namedTruststoresAction()`, `admin-core/admin_views.ts`'s
// `namedTruststoresJson()`), driven through the route table's own handlers
// in process, with the real directory installed (`ldap/ldap_server`), so
// every answer also passes the closed response model the API holds it to.
// `tests/truststores.js` holds the engine (`common/truststores.ts`); this
// holds the two doors onto it and the page that draws them.
//
//   A. THE TABLE: the GET and the seven actions, each an operation of the
//      document, and the console's forms resolving by tab — the Truststores
//      tab's `add` to `/admin-api/truststores/add`, the page's own `add`
//      still to `/admin-api/pki/trust/add`.
//   B. A NAMED TRUSTSTORE'S LIFE in a realm this file creates: create, the
//      name refusals, add (a leaf refused by name), the view, show with and
//      without PEM, remove, delete — each refusal with the engine's code.
//   C. ASSIGNMENT: assign as a string and as a list, the kind, fixed and
//      empty refusals, delete refused while assigned, unassign back to the
//      default, and a service-wide use case refused from a realm.
//   D. AUDIT: every write a row naming truststores and fingerprints, and no
//      row carrying certificate text.
//   E. REALM CONFINEMENT: another realm does not see, and cannot delete, a
//      realm's truststore; a service-wide truststore is seen read-only.
//   F. THE SYSTEM TRUSTSTORE in the view: node's store, no PEM, sorted.
//   G. AN UNKNOWN ACTION names the seven (STS-ADMIN-0956).
//   H. THE PAGE: the three tabs, the forms naming their tabs, the filter,
//      and nothing writable for a reader without Admin Write.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'truststores_api',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const audit = require('../common/audit');
const kit = require('./tools/trust_kit');
const stsCrypto = require('../common/crypto');

const BASE = '/admin-api/truststores';
const ACTION_ROUTE = BASE + '/:action';
const PAGE = '/admin/pki/trust';

// The handler of one row of the route table.
function handlerFor(routes, method, route) {
  log.debug("Entering handlerFor().");
  const found = (routes || []).filter(function (entry) {
    return entry.method === method &&
      String(entry.route || entry.path || '') === route;
  })[0];
  log.debug("Leaving handlerFor(). " + (found ? "found." : "missing."));
  return found || null;
}

// A response the handlers can answer into, recording the status, the body
// and the code marked on it.
function responseFor(req) {
  log.debug("Entering responseFor().");
  const captured = { status: 0, text: '' };
  const res = {
    req: req,
    locals: { apiCaller: { kind: 'person', name: 'tsapi-admin',
                           sub: 'tsapi-admin',
                           clientId: 'sts-admin-console' } },
    status: function status(code) {
      log.debug("Entering status().");
      captured.status = code;
      log.debug("Leaving status().");
      return res;
    },
    type: function type() {
      log.debug("Entering type().");
      log.debug("Leaving type().");
      return res;
    },
    set: function set() {
      log.debug("Entering set().");
      log.debug("Leaving set().");
      return res;
    },
    setHeader: function setHeader() {
      log.debug("Entering setHeader().");
      log.debug("Leaving setHeader().");
      return res;
    },
    send: function send(text) {
      log.debug("Entering send().");
      captured.text = String(text || '');
      log.debug("Leaving send().");
      return res;
    }
  };
  log.debug("Leaving responseFor().");
  return { res: res, captured: captured };
}

// One call to a row's handler in a realm, settled.
async function call(routes, realmId, method, action, payload) {
  log.debug("Entering call(). " + method + " " + action);
  const row = handlerFor(routes, method, method === 'GET' ? BASE :
                                         ACTION_ROUTE);
  if (!row) {
    log.debug("Leaving call(). No row.");
    return { status: 0, body: {}, code: '' };
  }
  const req = {
    method: method, params: { action: action }, query: {},
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload || {}), path: ''
  };
  const built = responseFor(req);
  await realms.run(realmId, async function () {
    const answered = row.handler(req, built.res);
    if (answered && typeof answered.then === 'function') {
      await answered;
    }
    // An add verifies each certificate's signature off the event loop, so
    // the answer is waited for by the clock, up to thirty seconds.
    for (let i = 0; i < 3000 && !built.captured.status; i++) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 10);
      });
    }
  });
  let body = {};
  try {
    body = JSON.parse(built.captured.text || '{}');
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    body = { raw: built.captured.text };
  }
  log.debug("Leaving call(). " + built.captured.status);
  return { status: built.captured.status, body: body,
           code: errorCodes.codeOf(built.res) || '' };
}

// The audit rows written since a sequence number. The audit log is PER
// REALM, so a realm's rows are read in that realm.
function rowsSince(seq, realmId) {
  log.debug("Entering rowsSince().");
  const listed = realmId ? realms.run(realmId, function () {
    return audit.list();
  }) : audit.list();
  const rows = listed.filter(function (row) {
    return (Number(row.seq) || 0) > seq &&
      row.action === 'admin.pki.truststore.change';
  });
  log.debug("Leaving rowsSince(). " + rows.length);
  return rows;
}

function lastSeq() {
  log.debug("Entering lastSeq().");
  let top = 0;
  audit.list().forEach(function (row) {
    top = Math.max(top, Number(row.seq) || 0);
  });
  log.debug("Leaving lastSeq(). " + top);
  return top;
}

// The console's English, for the page: its own namespace and the kit's.
function translator() {
  log.debug("Entering translator().");
  const webMessages = require('../common/web_messages');
  const flat = {};
  ['consolePkiTrust', 'consoleKit'].forEach(function (ns) {
    const english = JSON.parse(fs.readFileSync(path.join(__dirname,
      '../common/locales/' + ns + '/en.json'), 'utf8'));
    Object.keys(english).forEach(function (key) {
      flat[ns + '.' + key] = english[key];
    });
  });
  log.debug("Leaving translator().");
  return webMessages.WebTranslator.fromData({
    negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                  direction: 'ltr', matched: true },
    catalogs: { en: flat } });
}

module.exports = {
  name: 'truststores_api',
  describe: 'named truststores: GET /admin-api/truststores, its seven ' +
            'actions, their refusals, audit and realm confinement, and the ' +
            'three tabs of /admin/pki/trust',
  run: async function (t) {
    // The real directory, so the engine stores what the API writes.
    require('../ldap/ldap_server');
    const adminApi = require('../mgmt-api/admin_api');
    const adminViews = require('../admin-core/admin_views');
    const WebForms = require('../admin-ui/web_forms');
    const webKit = require('../admin-ui/web_kit');
    const PkiTrustPage = require('../admin-ui/web_pki_trust');
    const routes = adminApi.ROUTES;
    const stamp = process.pid + '-' + Date.now().toString(36);
    const realmA = 'tsapi-a-' + stamp;
    const realmB = 'tsapi-b-' + stamp;
    const shared = 'tsapi-shared-' + process.pid;
    const made = [];
    try {
      [realmA, realmB].forEach(function (id) {
        realms.create({ id: id, name: id, domain: id + '.example.net' });
        made.push(id);
      });

      // A. THE TABLE.
      t.log.info('A. the table');
      const getRow = handlerFor(routes, 'GET', BASE);
      const actRow = handlerFor(routes, 'POST', ACTION_ROUTE);
      t.check(!!getRow && getRow.operationId === 'getTruststores' &&
              getRow.mirrors === 'GET ' + PAGE,
              'A1. the GET is getTruststores and mirrors the page');
      t.equal(((actRow && actRow.actions) || []).map(function (one) {
        return one.action;
      }).join(','), 'show,create,delete,add,remove,assign,unassign',
              'A2. the seven actions');
      const paths = require('../mgmt-api/admin_api_spec').AdminApiSpec
        .merged().paths;
      t.check(!!(paths[BASE] && paths[BASE].get) &&
              ((actRow && actRow.actions) || []).every(function (one) {
                const op = paths[BASE + '/' + one.action];
                return op && op.post &&
                  op.post.operationId === one.operationId;
              }), 'A3. every operation is in the document');
      const index = [];
      routes.forEach(function (row) {
        if (row.actions) {
          row.actions.forEach(function (one) {
            index.push({ method: 'POST', mirrors: row.mirrors,
                         path: String(row.route).replace(':action',
                                                         one.action) });
          });
          return;
        }
        index.push({ method: row.method, mirrors: row.mirrors,
                     path: row.path || row.route });
      });
      const table = WebForms.table(index);
      t.equal([
        WebForms.resolve(table, PAGE + '#pki-trust-tab-truststores', 'add'),
        WebForms.resolve(table, PAGE + '#pki-trust-tab-truststores',
                         'remove'),
        WebForms.resolve(table, PAGE + '#pki-trust-tab-truststores',
                         'create'),
        WebForms.resolve(table, PAGE + '#pki-trust-tab-usecases', 'assign'),
        WebForms.resolve(table, PAGE + '#pki-trust-tab-usecases',
                         'unassign'),
        WebForms.resolve(table, PAGE, 'add'),
        WebForms.resolve(table, PAGE, 'remove')].join(' '),
      BASE + '/add ' + BASE + '/remove ' + BASE + '/create ' + BASE +
        '/assign ' + BASE + '/unassign /admin-api/pki/trust/add ' +
        '/admin-api/pki/trust/remove',
      'A4. a tab\'s form resolves to /truststores, the page\'s own to ' +
        '/pki/trust');

      // B. A NAMED TRUSTSTORE'S LIFE.
      t.log.info('B. a named truststore');
      const root = await kit.mint({ cn: 'tsapi root', ca: true });
      const issuing = await kit.mint({ cn: 'tsapi issuing', ca: true,
                                       pathLen: 0, issuer: root });
      const leaf = await kit.mint({ cn: 'tsapi leaf', issuer: root });
      const before = lastSeq();
      const created = await call(routes, realmA, 'POST', 'create',
        { name: 'partners', description: 'our partners' });
      t.check(created.status === 200 && created.body.ok === true &&
              created.body.name === 'partners',
              'B1. a truststore is created', JSON.stringify(created.body));
      const twice = await call(routes, realmA, 'POST', 'create',
                               { name: 'partners' });
      t.check(twice.status === 400 && twice.code === 'STS-PKI-0305' &&
              Array.isArray(twice.body.errors) && !('code' in twice.body),
              'B2. a second of the name is refused, its code recorded and ' +
              'not sent', twice.code + ' ' + JSON.stringify(twice.body));
      const badName = await call(routes, realmA, 'POST', 'create',
                                 { name: 'system' });
      t.check(badName.status === 400 && badName.code === 'STS-PKI-0305',
              'B3. a built-in name is refused (STS-PKI-0305)', badName.code);
      const added = await call(routes, realmA, 'POST', 'add', {
        name: 'partners', certificates: [leaf.pem, root.pem, issuing.pem] });
      t.check(added.status === 200 && added.body.added.length === 2 &&
              added.body.refused.length === 1 &&
              added.body.added.every(function (one) {
                return !('pem' in one) && /^[0-9A-F]{64}$/.test(
                  one.fingerprint256);
              }), 'B4. the anchor and intermediate are added, the leaf ' +
              'refused by name, no PEM sent back',
              JSON.stringify(added.body).slice(0, 400));
      const nowhere = await call(routes, realmA, 'POST', 'add',
                                 { name: 'nowhere', certificates: root.pem });
      t.check(nowhere.status === 400 && nowhere.code === 'STS-PKI-0301',
              'B5. a truststore that does not exist takes nothing ' +
              '(STS-PKI-0301)', nowhere.code);
      const garbage = await call(routes, realmA, 'POST', 'add',
                                 { name: 'partners', certificates: 'x' });
      t.check(garbage.status === 400 && garbage.code === 'STS-PKI-0238',
              'B6. no PEM given is refused whole (STS-PKI-0238)',
              garbage.code);
      const viewA = await call(routes, realmA, 'GET', '', null);
      const partners = (viewA.body.stores || []).filter(function (one) {
        return one.name === 'partners';
      })[0];
      t.check(viewA.status === 200 && viewA.body.realm === realmA &&
              !!partners && partners.kind === 'named' &&
              partners.scope === 'realm' && partners.readOnly === false &&
              partners.anchors === 1 && partners.intermediates === 1 &&
              (partners.certificates || []).length === 2 &&
              partners.certificates.every(function (one) {
                return !('pem' in one);
              }) && viewA.body.limits.installed === true,
              'B7. the view lists it with its certificates, without PEM',
              JSON.stringify(partners || viewA.body).slice(0, 400));
      const shown = await call(routes, realmA, 'POST', 'show',
                               { name: 'partners' });
      t.check(shown.status === 200 &&
              shown.body.truststore.certificates.length === 2 &&
              shown.body.truststore.certificates.every(function (one) {
                return /BEGIN CERTIFICATE/.test(one.pem);
              }), 'B8. show answers each certificate with its PEM');
      const shownBare = await call(routes, realmA, 'POST', 'show',
                                   { name: 'partners', withPem: false });
      t.check(shownBare.status === 200 &&
              shownBare.body.truststore.certificates.every(function (one) {
                return !('pem' in one);
              }), 'B9. show with withPem false leaves PEM out');
      const ghost = await call(routes, realmA, 'POST', 'show',
                               { name: 'ghost' });
      t.check(ghost.status === 400 && ghost.code === 'STS-PKI-0301',
              'B10. show of a name nothing holds is refused', ghost.code);

      // C. ASSIGNMENT.
      t.log.info('C. assignment');
      const assigned = await call(routes, realmA, 'POST', 'assign',
        { useCase: 'saml-signer', truststores: 'partners, signers' });
      t.check(assigned.status === 200 &&
              assigned.body.names.join(',') === 'partners,signers',
              'C1. a list given as one string is assigned, in order',
              JSON.stringify(assigned.body));
      const viewA2 = await call(routes, realmA, 'GET', '', null);
      const saml = (viewA2.body.useCases || []).filter(function (one) {
        return one.id === 'saml-signer';
      })[0];
      const partners2 = (viewA2.body.stores || []).filter(function (one) {
        return one.name === 'partners';
      })[0];
      t.check(!!saml && saml.assigned === true &&
              partners2.usedBy.indexOf('saml-signer') >= 0,
              'C2. the view shows the assignment, and who trusts the store');
      const inUse = await call(routes, realmA, 'POST', 'delete',
                               { name: 'partners' });
      t.check(inUse.status === 400 && inUse.code === 'STS-PKI-0307',
              'C3. a truststore a use case trusts is not deleted', inUse.code);
      const fromRealm = await call(routes, realmA, 'POST', 'assign',
        { useCase: 'outbound-smtp', truststores: ['system'] });
      t.check(fromRealm.status === 400 && fromRealm.code === 'STS-PKI-0302',
              'C4. a service-wide use case is not assigned from a realm',
              fromRealm.code);
      const fixed = await call(routes, realmA, 'POST', 'assign',
        { useCase: 'cell-peer', truststores: ['partners'] });
      const unknown = await call(routes, realmA, 'POST', 'assign',
        { useCase: 'no-such-use', truststores: ['partners'] });
      const empty = await call(routes, realmA, 'POST', 'assign',
        { useCase: 'saml-signer', truststores: ' , ' });
      const kind = await call(routes, realmA, 'POST', 'assign',
        { useCase: 'spiffe-svid', truststores: ['partners'] });
      t.check(fixed.code === 'STS-PKI-0303' &&
              unknown.code === 'STS-PKI-0303' &&
              empty.code === 'STS-PKI-0303' && kind.code === 'STS-PKI-0304' &&
              [fixed, unknown, empty, kind].every(function (one) {
                return one.status === 400;
              }), 'C5. fixed, unknown, empty and wrong-kind assignments ' +
              'are refused with the engine\'s codes',
              [fixed.code, unknown.code, empty.code, kind.code].join(' '));
      t.check(empty.status === 400 && (await call(routes, realmA, 'GET', '',
        null)).body.useCases.filter(function (one) {
        return one.id === 'saml-signer';
      })[0].assigned === true,
              'C6. an empty list clears nothing: it is refused, not an ' +
              'unassign');
      const unassigned = await call(routes, realmA, 'POST', 'unassign',
                                    { useCase: 'saml-signer' });
      t.check(unassigned.status === 200 &&
              unassigned.body.names.join(',') === saml.defaults.join(','),
              'C7. unassign returns the use case to its default',
              JSON.stringify(unassigned.body));
      const fp = partners.certificates.filter(function (one) {
        return one.kind === 'intermediate';
      })[0].fingerprint256;
      const colons = fp.match(/.{2}/g).join(':').toLowerCase();
      const removed = await call(routes, realmA, 'POST', 'remove',
                                 { name: 'partners', fingerprint: colons });
      const again = await call(routes, realmA, 'POST', 'remove',
                               { name: 'partners', fingerprint: fp });
      t.check(removed.status === 200 && removed.body.fingerprint === fp &&
              again.status === 400 && again.code === 'STS-PKI-0301',
              'C8. a certificate is removed under the other spelling, and ' +
              'once', JSON.stringify([removed.body, again.code]));

      // E. REALM CONFINEMENT (before the delete, so there is a store to
      // confine).
      t.log.info('E. realm confinement');
      const viewB = await call(routes, realmB, 'GET', '', null);
      t.check(viewB.status === 200 && viewB.body.realm === realmB &&
              !(viewB.body.stores || []).some(function (one) {
                return one.name === 'partners';
              }), 'E1. another realm does not see the realm\'s truststore');
      const fromB = await call(routes, realmB, 'POST', 'delete',
                               { name: 'partners' });
      const addFromB = await call(routes, realmB, 'POST', 'add',
                                  { name: 'partners',
                                    certificates: issuing.pem });
      t.check(fromB.status === 400 && fromB.code === 'STS-PKI-0301' &&
              addFromB.status === 400 && addFromB.code === 'STS-PKI-0301',
              'E2. nor can it delete it or add to it',
              fromB.code + ' ' + addFromB.code);
      const deleted = await call(routes, realmA, 'POST', 'delete',
                                 { name: 'partners' });
      t.check(deleted.status === 200 && deleted.body.ok === true,
              'B11. unassigned, the truststore is deleted');
      const madeShared = await call(routes, realms.DEFAULT_ID, 'POST',
        'create', { name: shared, description: 'shared' });
      const smtp = await call(routes, realms.DEFAULT_ID, 'POST', 'assign',
        { useCase: 'outbound-smtp', truststores: ['system', shared] });
      const viewB2 = await call(routes, realmB, 'GET', '', null);
      const seen = (viewB2.body.stores || []).filter(function (one) {
        return one.name === shared;
      })[0];
      t.check(madeShared.status === 200 && smtp.status === 200 && !!seen &&
              seen.scope === 'service' && seen.readOnly === true &&
              seen.usedBy.indexOf('outbound-smtp') >= 0,
              'E3. a default-realm truststore is service-wide, assigned to ' +
              'a service-wide use case, and read-only from a realm',
              JSON.stringify(seen || smtp.body).slice(0, 300));
      const sharedFromB = await call(routes, realmB, 'POST', 'delete',
                                     { name: shared });
      t.check(sharedFromB.status === 400 &&
              sharedFromB.code === 'STS-PKI-0301',
              'E4. a realm cannot delete a service-wide truststore',
              sharedFromB.code);
      const unSmtp = await call(routes, realms.DEFAULT_ID, 'POST',
                                'unassign', { useCase: 'outbound-smtp' });
      const goneShared = await call(routes, realms.DEFAULT_ID, 'POST',
                                    'delete', { name: shared });
      t.check(unSmtp.status === 200 && goneShared.status === 200,
              'E5. the default realm unassigns and deletes it');

      // D. AUDIT.
      t.log.info('D. audit');
      // Realm A is this file's own, so all of its rows are; the default
      // realm's are those written since this file began.
      const rows = rowsSince(0, realmA).concat(rowsSince(before));
      const actions = rows.map(function (row) {
        return row.detail && row.detail.action;
      });
      ['create', 'add', 'assign', 'unassign', 'remove', 'delete']
        .forEach(function (one) {
          t.check(actions.indexOf(one) >= 0, 'D1. ' + one + ' is audited');
        });
      t.check(rows.every(function (row) {
        return !/BEGIN CERTIFICATE|MII[A-Za-z0-9+/]{20}/.test(
          JSON.stringify(row));
      }), 'D2. no audit row carries certificate text');
      const addRow = rows.filter(function (row) {
        return row.detail && row.detail.action === 'add' &&
          row.target === realmA;
      })[0];
      t.check(!!addRow && addRow.actor === 'tsapi-admin' &&
              addRow.detail.name === 'partners' &&
              addRow.detail.count === 2 &&
              String(addRow.detail.fingerprints).split(' ').length === 2,
              'D3. the add row names the actor, the truststore and the ' +
              'fingerprints', JSON.stringify(addRow || {}).slice(0, 300));
      t.check(rows.length === 10,
              'D4. one row per write that was made, none for a refusal ' +
              '(' + rows.length + ')');

      // F. THE SYSTEM TRUSTSTORE.
      t.log.info('F. the system truststore');
      const system = viewA.body.system;
      const subjects = system.certificates.map(function (one) {
        return one.subject;
      });
      const sorted = subjects.slice().sort(function (a, b) {
        return String(a).localeCompare(String(b));
      });
      const size = Buffer.byteLength(JSON.stringify(viewA.body));
      t.check(system.count > 0 &&
              system.count === system.certificates.length &&
              system.certificates.every(function (one) {
                return !('pem' in one) && one.subject &&
                  /^[0-9A-F]{64}$/.test(one.fingerprint256);
              }) && subjects.join('\n') === sorted.join('\n'),
              'F1. node\'s store, ' + system.count + ' certificates, ' +
              'described without PEM and sorted by subject');
      t.check(size < 200000, 'F2. the whole view is ' + size + ' bytes');
      const systemRow = viewA.body.stores.filter(function (one) {
        return one.name === 'system';
      })[0];
      t.check(systemRow && systemRow.anchors === system.count &&
              systemRow.readOnly === true,
              'F3. the system row counts what the tab lists');
      const fingerprintOf = function (pem) {
        log.debug("Entering fingerprintOf().");
        log.debug("Leaving fingerprintOf().");
        return String(stsCrypto.parseCertificate(pem).fingerprint256)
          .replace(/:/g, '');
      };
      t.check(fingerprintOf(root.pem).length === 64,
              'F4. the fingerprint spelling is upper hex without colons');

      // G. AN UNKNOWN ACTION.
      t.log.info('G. unknown action');
      const odd = await call(routes, realmA, 'POST', 'frobnicate', {});
      t.check(odd.status === 400 && odd.code === 'STS-ADMIN-0956' &&
              /The seven are: show, create, delete, add, remove, assign, unassign\./
                .test(String((odd.body.errors || [])[0])),
              'G1. an unknown action names the seven (STS-ADMIN-0956)',
              JSON.stringify(odd.body));

      // H. THE PAGE.
      t.log.info('H. the page');
      const tr = translator();
      const pkiView = realms.run(realmA, function () {
        return adminViews.pkiTrustJson({ query: {} });
      });
      const json = Object.assign({}, pkiView, { truststores: viewA.body });
      const html = PkiTrustPage.render(json,
                                       webKit.context({}, true, tr));
      ['truststores', 'usecases', 'system'].forEach(function (tab) {
        t.check(html.indexOf('data-tab="' + tab + '"') >= 0,
                'H1. the ' + tab + ' tab is drawn');
      });
      t.check(html.indexOf('action="' + PAGE +
                           '#pki-trust-tab-truststores"') >= 0 &&
              html.indexOf('action="' + PAGE +
                           '#pki-trust-tab-usecases"') >= 0 &&
              html.indexOf('name="action" value="create"') >= 0 &&
              html.indexOf('name="action" value="assign"') >= 0,
              'H2. the forms post from their tabs');
      t.check(!/consolePkiTrust\./.test(html),
              'H3. every string is in the catalog');
      const one = system.certificates[0];
      const filtered = PkiTrustPage.render(json, webKit.context(
        { systemq: one.fingerprint256.slice(0, 20) }, true, tr));
      const rowsDrawn = (filtered.match(/<tr><td>[^<]*<\/td><td class="sub">/g)
        || []).length;
      t.check(filtered.indexOf(one.fingerprint256) >= 0 &&
              /certificates match/.test(filtered) && rowsDrawn >= 1 &&
              rowsDrawn < system.count,
              'H4. the filter keeps the matching certificates (' +
              rowsDrawn + ')');
      const reader = PkiTrustPage.render(json,
                                         webKit.context({}, false, tr));
      t.check(reader.indexOf('value="create"') < 0 &&
              reader.indexOf('value="assign"') < 0 &&
              reader.indexOf('value="unassign"') < 0,
              'H5. a reader without Admin Write gets no truststore control');
    } finally {
      made.forEach(function (id) {
        try {
          realms.remove(id);
        } catch (e) {
          log.debug("Caught in run(): " + ((e && e.message) || e));
        }
      });
    }
  }
};
