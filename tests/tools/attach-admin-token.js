// ===========================================================================
// tests/tools/attach-admin-token.js — PRESENT THE MANAGEMENT API'S TOKEN.
//
// `/admin-api` requires an OAuth 2.0 access token since 2026-09-09.
// Twenty-three jobs drive that API and NOT ONE OF THEM SHARES AN HTTP HELPER —
// each builds its own `fetch` or `https.request` — so making them all
// authenticate is either twenty-three edits that say the same thing, or one
// place that says it once. This is that place: `run-report.js` preloads it into
// every job with `--require`, and it adds the header to management-API calls
// that do not already carry one.
//
// **WHY A PRELOAD RATHER THAN A SHARED CLIENT.** A shared client is the right
// answer for a suite being written today, and adopting one across twenty-three
// files that each have their own conventions is a large change with no test
// behind it — every one of those files would be touched for a reason that has
// nothing to do with what it asserts. This shim leaves the jobs about what they
// test, and there is exactly one thing to read to know how they authenticate.
//
// **IT IS DELIBERATELY NARROW.** It attaches the token to `/admin-api` and
// nothing else, and it never replaces an Authorization header a job set itself
// — several jobs authenticate AS somebody on purpose (SCIM's six schemes, the
// XACML gate's four callers, a token this job just minted), and a shim that
// overwrote those would silently rewrite the thing under test.
//
// A job that wants to drive `/admin-api` UNAUTHENTICATED — to assert the
// refusal — sends `Authorization: none`, which this leaves alone and the
// service reads as a malformed credential.
// ===========================================================================

'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'attach-admin-token',
  level: process.env.LOG_LEVEL || 'info' });

const TOKEN = process.env.STS_ADMIN_API_TOKEN || '';

if (TOKEN) {
  const http = require('http');
  const https = require('https');

  // `/admin-api` in any realm: app.js leaves the `/realm/<id>` prefix on the
  // URL a client sends, so both shapes have to match.
  const WANTED = /^(?:\/realm\/[^/]+)?\/admin-api(?:\/|$|\?)/;

  function wants(pathname) {
    log.debug("Entering wants().");
    log.debug("Leaving wants().");
    return WANTED.test(String(pathname || ''));
  }

  function hasAuth(headers) {
    log.debug("Entering hasAuth().");
    if (!headers) {
      log.debug("Leaving hasAuth().");
      return false;
    }
    if (typeof headers.get === 'function') {
      log.debug("Leaving hasAuth().");
      return !!headers.get('authorization');
    }
    log.debug("Leaving hasAuth().");
    return Object.keys(headers).some(function (k) {
      return k.toLowerCase() === 'authorization';
    });
  }

  // ---- global fetch, which is what most of the jobs use --------------------
  if (typeof globalThis.fetch === 'function') {
    const realFetch = globalThis.fetch;
    globalThis.fetch = function (input, init) {
      log.debug("Entering fetch().");
      const url = typeof input === 'string' ? input
        : (input && input.url) || String(input);
      let path = '';
      try {
        path = new URL(url).pathname + (new URL(url).search || '');
      }
      catch (e) {
        log.debug("Caught in fetch(): " + ((e && e.message) || e));
        path = String(url);
      }
      if (!wants(path)) {
        log.debug("Leaving fetch().");
        return realFetch.apply(this, arguments);
      }
      const options = Object.assign({}, init || {});
      const headers = Object.assign({}, (options.headers || {}));
      if (!hasAuth(init && init.headers) && !hasAuth(headers) &&
          !(typeof input === 'object' && input && hasAuth(input.headers))) {
        headers.authorization = 'Bearer ' + TOKEN;
      }
      options.headers = headers;
      log.debug("Leaving fetch().");
      return realFetch.call(this, input, options);
    };
  }

  // ---- http/https.request, for the jobs that build their own ---------------
  [http, https].forEach(function (mod) {
    const real = mod.request;
    mod.request = function (a, b, c) {
      log.debug("Entering request().");
      let options = null;
      if (typeof a === 'string' || a instanceof URL) {
        options = (b && typeof b === 'object') ? b : null;
      } else if (a && typeof a === 'object') {
        options = a;
      }
      let path = '';
      if (typeof a === 'string') {
        try {
          path = new URL(a).pathname;
        } catch (e) {
          log.debug("Caught in request(): " + ((e && e.message) || e));
          path = a;
        }
      } else if (a instanceof URL) {
        path = a.pathname;
      } else if (options) {
        path = options.path || '';
      }
      if (options && wants(path) && !hasAuth(options.headers)) {
        options.headers = Object.assign({}, options.headers || {},
                                        { authorization: 'Bearer ' + TOKEN });
      }
      log.debug("Leaving request().");
      return real.apply(this, arguments);
    };
  });
}
