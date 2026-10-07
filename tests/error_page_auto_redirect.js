// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/error_page_auto_redirect.js — THE AUTHORIZATION ERROR PAGE'S TIMED
// CONTINUE (#317).
//
// The page shown instead of redirecting an error to a client (RFC 9700
// section 4.11.2, `sendRedirectInterstitial()`) continues by itself only when
// an operator sets `oauth2.errorPageAutoRedirectS` above 0:
//   1. by default there is no refresh and no "automatically" sentence;
//   2. set, a meta refresh names the link's own target and the seconds, and
//      the page says so;
//   3. the form_post variant never has one — a POST needs a script.
// ===========================================================================
'use strict';
const config = require('../common/config');
const oauth2 = require('../oauth-oidc/oauth2');
const log = require('bunyan').createLogger({ name: 'error_page_auto_redirect',
  level: process.env.LOG_LEVEL || 'info' });

// A response that keeps what the page sends.
function fakeResponse() {
  log.debug("Entering fakeResponse().");
  const res = {
    statusCode: 0, body: '', headers: {},
    status: function (code) {
      res.statusCode = code;
      return res;
    },
    type: function () {
      return res;
    },
    set: function (name, value) {
      res.headers[name] = value;
      return res;
    },
    send: function (body) {
      res.body = String(body);
      return res;
    }
  };
  log.debug("Leaving fakeResponse().");
  return res;
}

// The page for one error, as a person not signed in would get it.
function render(form) {
  log.debug("Entering render().");
  const res = fakeResponse();
  oauth2.sendRedirectInterstitial(res, {
    error: 'invalid_request', description: 'something was wrong',
    why: 'because', clientId: 'a-client',
    redirectUri: 'https://rp.example/cb', state: 's1',
    target: 'https://rp.example/cb?error=invalid_request&state=s1',
    form: form ? { error: 'invalid_request', state: 's1' } : undefined
  });
  log.debug("Leaving render().");
  return res.body;
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== 1. off by default ===');
  const plain = render(false);
  t.check(plain.indexOf('http-equiv="refresh"') < 0 &&
          plain.indexOf('automatically in') < 0 &&
          plain.indexOf('Continue to https://rp.example/cb') >= 0,
          '1. the default page has its link and no timed continue');

  t.log.info('=== 2. set to five seconds ===');
  config.setOverride('oauth2.errorPageAutoRedirectS', 5);
  try {
    const timed = render(false);
    t.check(timed.indexOf('<meta http-equiv="refresh" content="5;url=' +
                          'https://rp.example/cb?error=invalid_request' +
                          '&amp;state=s1">') >= 0,
            '2a. the refresh names the link\'s own target and the seconds');
    t.check(timed.indexOf('sent there automatically in 5 seconds') >= 0 &&
            timed.indexOf('<script') < 0,
            '2b. the page says when, and still carries no script');

    t.log.info('=== 3. form_post keeps its button ===');
    const posted = render(true);
    t.check(posted.indexOf('http-equiv="refresh"') < 0 &&
            posted.indexOf('<form method="post"') >= 0,
            '3. the form_post page never continues by itself');
  } finally {
    config.clearOverride('oauth2.errorPageAutoRedirectS');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'error_page_auto_redirect',
  describe: 'The authorization error page\'s optional timed continue ' +
            '(#317): off by default, a meta refresh when set, never for ' +
            'form_post',
  run: run
};
