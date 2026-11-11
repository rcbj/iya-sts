// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_action_actor.js
//
// ===========================================================================
// EVERY ADMIN ACTION IS TOLD WHO IS ACTING, NEVER BY ITS REQUEST BODY (rcbj
// on #1579, 2026-11-11).
//
// Until #1579 `AdminApi.nameActor()` wrote the verified token's subject into
// a JSON body's `actor` member after the schema had passed, and the actions
// of `admin-core/admin_actions.ts` read `body.actor` for their audit rows.
// Since #1579 each `/admin-api` handler hands its action the subject in the
// action's context argument (`{ via, actor }`), `nameActor()` is gone, and
// no action reads a member the Management API model does not declare.
//
// One act of each family that took its actor from the body, called through
// its `/admin-api` handler in process, as `admin_api_nominated_actor.js`
// calls the users and policies handlers: the request carries no `actor` at
// all, `res.locals.apiCaller` is the gate's verified subject, and the rows
// the act writes must name that subject. In process no HTTP row is written,
// so a row naming the subject after the call is the action's own.
//
//   1. groups       create                     (the directory's row)
//   2. roles        create-role                (roles.create)
//   3. permissions  set-permission-base and
//                   define-permission          (the registry's update)
//   4. applications add-owner                  (application.add-owner)
//   5. consent      grant-global-consent       (the registry's update)
//   6. saml2        upload-metadata            (the registry's update)
//   7. logout       retry-backchannel          (the actor handed to
//                                               `backchannel.retry()`,
//                                               observed by a stand-in, as
//                                               a real dead delivery needs a
//                                               client that refused one)
//
// `users` and `policies` are `admin_api_nominated_actor.js`'s, the group
// create over HTTP is `admin_api_actor.js`'s, and the branding removal is
// `branding_api.js`'s F2.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');

const log = require('bunyan').createLogger({
  name: 'admin_api_action_actor',
  level: process.env.LOG_LEVEL || 'info' });

const ldap = require('../ldap/ldap_server');
const audit = require('../common/audit');
const applications = require('../common/applications');
const backchannel = require('../oauth-oidc/backchannel_logout');
const adminApi = require('../mgmt-api/admin_api');

// The subject the gate would have taken off a person token. No directory
// username, so no other row names it by accident.
const SUBJECT = 'aaa1579-subject';

function handlerFor(routes, route) {
  log.debug("Entering handlerFor().");
  const found = (routes || []).filter(function (entry) {
    return entry.method === 'POST' &&
      String(entry.path || entry.route || '') === route;
  })[0];
  log.debug("Leaving handlerFor(). " + (found ? "found." : "missing."));
  return found ? found.handler : null;
}

// The locals the gate writes for a person token. No Accept-Language, so
// sendJson does not translate the answer.
function responseFor(req) {
  log.debug("Entering responseFor().");
  const captured = { status: 0, text: '' };
  const res = {
    req: req,
    locals: {
      apiCaller: {
        kind: 'person',
        name: SUBJECT,
        sub: SUBJECT,
        clientId: 'sts-admin-console'
      }
    },
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

function parsed(captured) {
  log.debug("Entering parsed().");
  let body = {};
  try {
    body = JSON.parse(captured.text || '{}');
  } catch (e) {
    log.debug("Caught in parsed(): " + ((e && e.message) || e));
    body = { parseError: String((e && e.message) || e),
             raw: captured.text };
  }
  log.debug("Leaving parsed().");
  return { status: captured.status, body: body };
}

// One call to a handler, settled. A handler that answers later (a promise
// it returns, or one it starts and does not return) is waited for until it
// has sent.
async function callHandler(route, action, payload) {
  log.debug("Entering callHandler(). " + route + " " + action);
  const handler = handlerFor(adminApi.ROUTES, route);
  if (typeof handler !== 'function') {
    log.debug("Leaving callHandler(). No handler.");
    return { status: 0, body: { errors: ['no handler for ' + route] } };
  }
  const req = {
    method: 'POST',
    params: { action: action },
    query: {},
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    path: ''
  };
  const built = responseFor(req);
  const answered = handler(req, built.res);
  if (answered && typeof answered.then === 'function') {
    await answered;
  }
  for (let i = 0; i < 100 && !built.captured.status; i++) {
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  const out = parsed(built.captured);
  log.debug("Leaving callHandler(). " + out.status);
  return out;
}

// The highest sequence number written so far, and the rows written after
// it that name the subject.
function lastSeq() {
  log.debug("Entering lastSeq().");
  let top = 0;
  audit.list().forEach(function (row) {
    top = Math.max(top, Number(row.seq) || 0);
  });
  log.debug("Leaving lastSeq(). " + top);
  return top;
}

function namedSince(seq) {
  log.debug("Entering namedSince().");
  const rows = audit.list().filter(function (row) {
    return (Number(row.seq) || 0) > seq && row.actor === SUBJECT;
  });
  log.debug("Leaving namedSince(). " + rows.length);
  return rows;
}

// One act through its handler: it succeeds, and a row it wrote names the
// subject.
async function act(t, label, route, action, payload) {
  log.debug("Entering act(). " + label);
  const before = lastSeq();
  const got = await callHandler(route, action, payload);
  const rows = namedSince(before);
  t.check(got.status === 200 && got.body && got.body.ok === true &&
          rows.length > 0,
          label + ': the act succeeds and a row it wrote names the token ' +
          'subject',
          JSON.stringify({ status: got.status,
                           errors: got.body && got.body.errors,
                           named: rows.map(function (row) {
                             return row.action;
                           }) }).slice(0, 600));
  log.debug("Leaving act(). " + label);
  return got;
}

function samlEntity(entityId) {
  log.debug("Entering samlEntity().");
  const md = 'urn:oasis:names:tc:SAML:2.0:metadata';
  log.debug("Leaving samlEntity().");
  return '<md:EntityDescriptor xmlns:md="' + md + '" entityID="' +
    entityId + '"><md:SPSSODescriptor protocolSupportEnumeration="' +
    'urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService ' +
    'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' +
    'https://aaa-sp.test/acs" index="0"/></md:SPSSODescriptor>' +
    '</md:EntityDescriptor>';
}

async function run(t) {
  log.debug("Entering run().");
  const stamp = crypto.randomBytes(4).toString('hex');
  const person = 'aaa1579u' + stamp;
  const app = 'aaa1579-app-' + stamp;
  const sp = 'https://aaa1579-sp-' + stamp + '.test/sp';

  const made = ldap.createUser(person, {});
  const created = applications.createApplication({ identifier: app,
    protocols: ['oauth2'], fields: { oauthClientId: app } });
  t.check(made && made.ok !== false && created && created.ok !== false,
          'the person and the application the acts name exist',
          JSON.stringify({ person: made && (made.errors || made.dn),
                           app: created && created.errors }));

  // 1. groups
  await act(t, '1. groups create', '/admin-api/groups/:action', 'create',
            { group: 'aaa1579-g-' + stamp });
  // 2. roles
  await act(t, '2. roles create-role', '/admin-api/roles/:action',
            'create-role', { role: 'aaa1579-r-' + stamp });
  // 3. permissions: the base first (a permission is named by it), then
  // the permission. Both write a row of the registry's.
  await act(t, '3a. permissions set-permission-base',
            '/admin-api/permissions/:action', 'set-permission-base',
            { resource: app, baseUri: 'https://aaa1579.test/' });
  await act(t, '3b. permissions define-permission',
            '/admin-api/permissions/:action', 'define-permission',
            { resource: app, name: 'read', description: 'Read it' });
  // 4. applications
  await act(t, '4. applications add-owner',
            '/admin-api/applications/:action', 'add-owner',
            { application: app, owner: person });
  // 5. consent
  await act(t, '5. consent grant-global-consent',
            '/admin-api/consent/:action', 'grant-global-consent',
            { client: app, scope: 'profile' });
  // 6. saml2: registered first (that act names nobody: the registry's
  // create row takes no actor), then its metadata uploaded.
  const registered = await callHandler('/admin-api/saml2/:action',
                                       'register', { sp: sp });
  t.check(registered.status === 200 && registered.body.ok === true,
          '6a. the SAML 2.0 service provider is registered',
          JSON.stringify(registered.body && registered.body.errors));
  await act(t, '6b. saml2 upload-metadata', '/admin-api/saml2/:action',
            'upload-metadata', { sp: sp, document: samlEntity(sp) });

  // 7. logout: the stand-in records the actor it was handed.
  const realRetry = backchannel.retry;
  let handed = null;
  backchannel.retry = function retry(id, actor) {
    log.debug("Entering the stand-in retry().");
    handed = { id: id, actor: actor };
    log.debug("Leaving the stand-in retry().");
    return { ok: true, row: { id: id }, message: 'queued again' };
  };
  try {
    const retried = await callHandler('/admin-api/logout/:action',
      'retry-backchannel', { delivery: 'aaa1579-delivery-' + stamp });
    t.check(retried.status === 200 && retried.body.ok === true &&
            !!handed && handed.actor === SUBJECT,
            '7. logout retry-backchannel hands the token subject to the ' +
            'retry, for the row it writes',
            JSON.stringify({ status: retried.status, handed: handed,
                             errors: retried.body && retried.body.errors }));
  } finally {
    backchannel.retry = realRetry;
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_action_actor',
  describe: 'every admin action a management API handler calls is handed ' +
            'the token subject for its audit rows, never through its body ' +
            '(#1579)',
  run: run
};
