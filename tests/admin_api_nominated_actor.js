// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_nominated_actor.js
//
// ===========================================================================
// A NAME THE BODY SUPPLIES IS NOT THE AUDIT ACTOR (#966).
//
// `POST /admin-api/users/:action` already passes the verified token's
// subject as `context.actor`. `set-password`, and the three rows a create
// writes when it sets a credential, recorded `body.actor` and ignored that
// subject. `POST /admin-api/policies/:action` passed no actor, and
// `policiesAction` then read `body.actor`, so a passkey-policy save —
// `recoveryAssurance` and `adminEnrolment` included — recorded whoever the
// body named.
//
// The write is the same write: it still takes the route's scope and stays
// in the ambient realm. Only the row's actor changes.
//
// IN PROCESS, THROUGH THE HANDLERS. Both request schemas are closed
// (`additionalProperties: false`), so a JSON body carrying `actor` is
// refused (STS-API-0009) before the action — `tests/admin_api_actor.js`
// holds that for a group create — and `nameActor` then forces a JSON
// body's `actor` to the token subject. The hole is the action recording
// `body.actor` when `context.actor` and `body.actor` differ. Calling the
// handler is how this file produces that: the schema and `nameActor` never
// run.
//
// THE TOKEN SUBJECT is `res.locals.apiCaller`, which is what the gate
// writes once it has allowed the call and what `callerNameOf` reads. For a
// person that name is `username || preferred_username || sub`, the claims
// `tests/admin_api_actor.js` puts on a minted person token
// (`client_id: sts-admin-console`). Setting the locals to that shape is
// the subject. Minting a JWT and driving HTTP would meet the schema's
// refusal before any row was written.
//
// The named passkey profile selects an application id nobody has, and is
// reset before this file returns, so the default profile other tests read
// is left as they found it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');

const log = require('bunyan').createLogger({
  name: 'admin_api_nominated_actor',
  level: process.env.LOG_LEVEL || 'info' });

const ldap = require('../ldap/ldap_server');
const audit = require('../common/audit');
const passkeyPolicy = require('../common/passkey_policy');
const adminApi = require('../mgmt-api/admin_api');

// The subject the gate would have taken off a person token, and the name
// the body nominates instead. Neither is a directory username.
const SUBJECT = 'aa966-subject';
const NOMINATED = 'aa966-nominated';

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
function responseFor(req, subject) {
  log.debug("Entering responseFor().");
  const captured = { status: 0, text: '' };
  const res = {
    req: req,
    locals: {
      apiCaller: {
        kind: 'person',
        name: subject,
        sub: subject,
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

function callHandler(handler, action, payload, subject) {
  log.debug("Entering callHandler(). action=" + action);
  const req = {
    method: 'POST',
    params: { action: action },
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    path: ''
  };
  const built = responseFor(req, subject);
  let answered;
  try {
    answered = handler(req, built.res);
  } catch (e) {
    log.debug("Caught in callHandler(): " + ((e && e.message) || e));
    log.debug("Leaving callHandler(). The handler threw.");
    throw e;
  }
  if (answered && typeof answered.then === 'function') {
    log.debug("Leaving callHandler(). When the handler settles.");
    return answered.then(function () {
      return parsed(built.captured);
    }, function (e) {
      log.debug("Caught in callHandler(): " + ((e && e.message) || e));
      throw e;
    });
  }
  const out = parsed(built.captured);
  log.debug("Leaving callHandler().");
  return out;
}

// `audit.list()` is newest first. `matches` keeps the row this act wrote.
function newest(action, matches) {
  log.debug("Entering newest().");
  const row = audit.list().filter(function (one) {
    return one.action === action && matches(one);
  })[0] || null;
  log.debug("Leaving newest(). " + (row ? "a row." : "none."));
  return row;
}

function passkeyBody(profile, stamp, actor) {
  log.debug("Entering passkeyBody().");
  const fields = Object.assign({}, passkeyPolicy.DEFAULTS, {
    profile: profile,
    selectApplications: ['aa966-nobody-' + stamp],
    recoveryAssurance: 'not-weaker',
    adminEnrolment: 'on'
  });
  if (actor !== undefined) {
    fields.actor = actor;
  }
  log.debug("Leaving passkeyBody().");
  return fields;
}

async function run(t) {
  log.debug("Entering run().");
  const users = handlerFor(adminApi.ROUTES, '/admin-api/users/:action');
  const policies = handlerFor(adminApi.ROUTES,
                              '/admin-api/policies/:action');
  const stamp = crypto.randomBytes(4).toString('hex');
  const user = 'aa966u' + stamp;
  const profile = 'aa966p' + stamp;
  try {
    t.check(typeof users === 'function' && typeof policies === 'function',
            'the users and policies action handlers are registered',
            'users ' + typeof users + ', policies ' + typeof policies);
    if (typeof users === 'function' && typeof policies === 'function') {
      const made = ldap.createUser(user, {});
      t.check(made && made.ok !== false,
              'the person whose password is set exists',
              JSON.stringify(made && (made.errors || made.dn || made)));

      const nominated = await callHandler(users, 'set-password',
        { user: user, generate: true, actor: NOMINATED }, SUBJECT);
      t.check(nominated.status === 200 && nominated.body &&
              nominated.body.ok === true,
              'set-password with a body actor naming somebody else succeeds',
              JSON.stringify({ status: nominated.status,
                               errors: nominated.body &&
                                       nominated.body.errors }));
      const setRow = newest('password.set', function (row) {
        return row.target === user;
      });
      t.equal(setRow && setRow.actor, SUBJECT,
              'that set-password row records the token subject');

      const omitted = await callHandler(users, 'set-password',
        { user: user, generate: true }, SUBJECT);
      t.check(omitted.status === 200 && omitted.body &&
              omitted.body.ok === true,
              'set-password that omits actor succeeds',
              JSON.stringify({ status: omitted.status,
                               errors: omitted.body &&
                                       omitted.body.errors }));
      const omittedRow = newest('password.set', function (row) {
        return row.target === user && row.seq !== (setRow && setRow.seq);
      });
      t.equal(omittedRow && omittedRow.actor, SUBJECT,
              'a set-password body that omits actor still records the ' +
              'token subject');

      const saved = await callHandler(policies, 'save-passkey-policy',
        passkeyBody(profile, stamp, NOMINATED), SUBJECT);
      t.check(saved.status === 200 && saved.body && saved.body.ok === true,
              'a passkey-policy save with a body actor naming somebody ' +
              'else succeeds',
              JSON.stringify({ status: saved.status,
                               errors: saved.body && saved.body.errors }));
      const saveRow = newest('admin.passkey-policy.change', function (row) {
        return String(row.summary || '').indexOf('"' + profile + '"') >= 0;
      });
      t.equal(saveRow && saveRow.actor, SUBJECT,
              'that passkey-policy row records the token subject');

      const againBody = passkeyBody(profile, stamp);
      againBody.recoveryAssurance = 'operator-only';
      const again = await callHandler(policies, 'save-passkey-policy',
                                      againBody, SUBJECT);
      t.check(again.status === 200 && again.body && again.body.ok === true,
              'a passkey-policy save that omits actor succeeds',
              JSON.stringify({ status: again.status,
                               errors: again.body && again.body.errors }));
      const againRow = newest('admin.passkey-policy.change', function (row) {
        return String(row.summary || '').indexOf('"' + profile + '"') >= 0 &&
          row.seq !== (saveRow && saveRow.seq);
      });
      t.equal(againRow && againRow.actor, SUBJECT,
              'a passkey-policy body that omits actor still records the ' +
              'token subject');
    }
  } finally {
    if (typeof policies === 'function') {
      try {
        const cleared = await callHandler(policies, 'reset-passkey-policy',
          { profile: profile }, SUBJECT);
        t.check(cleared.body && cleared.body.ok === true,
                'the named passkey profile is reset',
                JSON.stringify(cleared.body && cleared.body.errors));
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
        t.bad('resetting the named passkey profile threw',
              (e && e.message) || String(e));
      }
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_nominated_actor',
  describe: 'a management API set-password and passkey-policy save record ' +
            'the token subject, including when the body names somebody ' +
            'else (#966)',
  run: run
};
