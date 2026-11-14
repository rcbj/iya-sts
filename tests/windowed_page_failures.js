// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: windowed_page_failures.js
//
// ===========================================================================
// A WINDOWED DEVICES OR ROLES PAGE THAT FAILED IS ANSWERED AS WHAT FAILED
// (#359, the review of #692).
//
// `GET /admin-api/ldap/devices` and `GET /admin-api/rbac` became promises in
// a windowed process, and their first handlers answered EVERY rejection as
// 503 `temporarily_unavailable` under STS-LDAP-0139 — so a bug in drawing the
// page read as "the store is down, try again shortly", forever. This holds,
// for both operations, with the page builder stood in for:
//
//   1. a store that could not be read — the bridge's timeout (STS-LDAP-0130)
//      and refusal (0131), the request's spent budget (0175) and an
//      asynchronous question the store did not answer (0139) — is a 503
//      with Retry-After, under that code;
//   2. anything else is a 500 `server_error`: under its own code when it
//      carries one, under STS-LDAP-0176 when it carries none, and with no
//      Retry-After.
//
// In process: the handlers are the routes this process wired.
// ===========================================================================

const log = require('bunyan').createLogger({
  name: 'windowed_page_failures', level: process.env.LOG_LEVEL || 'info' });

delete process.env.CONFIG_FILE;

// A response that records what the handler sent.
function fakeResponse() {
  log.debug("Entering fakeResponse().");
  const headers = {};
  let done = null;
  const sent = new Promise(function (resolve) {
    done = resolve;
  });
  const res = {
    statusCode: 200,
    locals: {},
    headers: headers,
    sent: sent,
    body: '',
    setHeader: function (name, value) {
      headers[String(name).toLowerCase()] = String(value);
    },
    getHeader: function (name) {
      return headers[String(name).toLowerCase()];
    },
    status: function (code) {
      res.statusCode = code;
      return res;
    },
    type: function () {
      return res;
    },
    set: function (name, value) {
      res.setHeader(name, value);
      return res;
    },
    send: function (body) {
      res.body = String(body);
      done();
      return res;
    },
    end: function (body) {
      res.body = String(body || '');
      done();
      return res;
    },
    json: function (body) {
      res.body = JSON.stringify(body);
      done();
      return res;
    }
  };
  log.debug("Leaving fakeResponse().");
  return res;
}

// The GET handler of one management-API path.
function handlerOf(routes, path) {
  log.debug("Entering handlerOf(). " + path);
  const entry = routes.filter(function (one) {
    return one.method === 'GET' && (one.path === path || one.route === path);
  })[0];
  log.debug("Leaving handlerOf().");
  return entry ? entry.handler : null;
}

async function run(t) {
  log.debug("Entering run().");
  const adminApi = require('../mgmt-api/admin_api');
  const adminViews = require('../admin-core/admin_views');
  const errorCodes = require('../common/error_codes');
  const routes = adminApi.ROUTES;
  const pages = [
    { path: '/admin-api/ldap/devices', member: 'directoryPageJson' },
    { path: '/admin-api/rbac', member: 'rbacListJson' }
  ];
  const coded = function (message, code) {
    const e = new Error(message);
    if (code) {
      errorCodes.mark(e, code);
    }
    return e;
  };
  const cases = [
    { why: 'the bridge timed out', error: coded('slow', 'STS-LDAP-0130'),
      status: 503, code: 'STS-LDAP-0130' },
    { why: 'the bridge was refused', error: coded('no', 'STS-LDAP-0131'),
      status: 503, code: 'STS-LDAP-0131' },
    { why: 'an asynchronous question went unanswered',
      error: coded('gone', 'STS-LDAP-0139'), status: 503,
      code: 'STS-LDAP-0139' },
    { why: 'the request\'s budget was spent',
      error: coded('spent', 'STS-LDAP-0175'), status: 503,
      code: 'STS-LDAP-0175' },
    { why: 'a bug with no code', error: new TypeError('x is undefined'),
      status: 500, code: 'STS-LDAP-0176' },
    { why: 'a failure with a code of its own',
      error: coded('policy', 'STS-API-0014'), status: 500,
      code: 'STS-API-0014' }
  ];
  for (const page of pages) {
    const handler = handlerOf(routes, page.path);
    t.check(typeof handler === 'function',
            page.path + ' has a GET handler');
    if (typeof handler !== 'function') {
      continue;
    }
    const original = adminViews[page.member];
    try {
      for (const one of cases) {
        adminViews[page.member] = function () {
          return Promise.reject(one.error);
        };
        const res = fakeResponse();
        handler({ query: {}, headers: {}, method: 'GET', url: page.path },
                res);
        await res.sent;
        const body = JSON.parse(res.body || '{}');
        const retry = res.getHeader('retry-after');
        t.check(res.statusCode === one.status &&
                errorCodes.codeOf(res) === one.code &&
                (one.status === 503
                  ? body.error === 'temporarily_unavailable' && retry === '5'
                  : body.error === 'server_error' && !retry),
                page.path + ': ' + one.why + ' is ' + one.status +
                ' under ' + one.code,
                JSON.stringify({ status: res.statusCode,
                                 code: errorCodes.codeOf(res),
                                 retry: retry, body: body }));
      }
    } finally {
      adminViews[page.member] = original;
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'windowed_page_failures',
  describe: 'a windowed devices or roles page answers 503 only for a store ' +
            'it could not read, and 500 under its own code (or ' +
            'STS-LDAP-0176) for anything else (#359)',
  run: run
};
