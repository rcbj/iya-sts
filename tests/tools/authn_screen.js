// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/authn_screen.js
//
// ===========================================================================
// THE SIGN-IN SCREEN OVER `/authn-api`, FOR AN IN-PROCESS TEST (#571).
//
// `tests/vendored/authn_signin.js` is the protocol jobs' helper; this is
// the same walk for a test that runs the stack in a child process and talks
// to it over `http` on 127.0.0.1, with its own cookie jar — a plain object,
// name to value, which this reads and writes in place, as each test's own
// `browser()` keeps one.
//
// The screen was a form until #571: GET drew it, POST answered a 303 or a
// page. Now the shell's GET mints the arrival cookie, the view answers the
// CSRF token, and the act answers the next step as JSON. `submit()` does all
// three and answers what a test needs to go on:
//
//   { status, json, next, location, errors, view, text, headers }
//
// with `status` 303 and `headers.location` the answer's `location` where it
// names one (`redirect`, `mfa`, `password-change`) — read as the 303 the
// form was answered with, which a browser follows with a GET either way —
// and the API's own status otherwise.
// ===========================================================================

const http = require('http');
const log = require('bunyan').createLogger({ name: 'authn_screen',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * One request to the in-process service, keeping the jar.
 *
 * @param {object} o - `port`, `jar`, `userAgent`, `method`, `path`,
 *   `headers`, `body`; `ca`, for a service on TLS — every function here
 *   passes it through
 * @returns {Promise<object>} `{ status, headers, text, json }`
 */
function call(o) {
  log.debug("Entering call(). " + o.method);
  return new Promise(function (resolve, reject) {
    const headers = Object.assign({ 'user-agent': o.userAgent ||
                                      'authn-screen/1.0' }, o.headers || {});
    const jar = o.jar || {};
    if (Object.keys(jar).length) {
      headers.cookie = Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    const body = o.body === undefined ? '' : String(o.body);
    if (o.method !== 'GET') {
      headers['content-length'] = Buffer.byteLength(body);
    }
    // A service on TLS (`ca`, the PEM its certificate chains to) is asked
    // over https, verified against that anchor.
    const transport = o.ca ? require('https') : http;
    const req = transport.request({ host: '127.0.0.1', port: o.port,
      ca: o.ca || undefined,
      path: String(o.path).replace(/^https?:\/\/[^/]+/, ''),
      method: o.method, headers: headers }, function (res) {
      let text = '';
      (res.headers['set-cookie'] || []).forEach(function (line) {
        const pair = line.split(';')[0];
        const eq = pair.indexOf('=');
        const value = pair.slice(eq + 1);
        if (value === '') {
          delete jar[pair.slice(0, eq)];
        } else {
          jar[pair.slice(0, eq)] = value;
        }
      });
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in call(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the text.
          json = null;
        }
        log.debug("Leaving call(). " + res.statusCode);
        resolve({ status: res.statusCode, headers: res.headers, text: text,
                  json: json });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

/**
 * The screen's address split into its path, its prefix and its id.
 *
 * @param {string} at - `/realm/x/authn/login?authn=…`, a URL, or a path to
 *   `/authn/password-change?change=…`
 * @returns {object} `{ prefix, id, page }`
 */
function parse(at) {
  log.debug("Entering parse().");
  const url = new URL(String(at), 'http://here.invalid');
  const m = /^(.*?)\/authn\/(login|select-idp|password-change)$/
    .exec(url.pathname);
  log.debug("Leaving parse().");
  return { prefix: m ? m[1] : '', page: m ? m[2] : 'login',
           id: url.searchParams.get('authn') ||
               url.searchParams.get('change') || '' };
}

/**
 * Opens the screen as its page does: the shell, then the view.
 *
 * @param {object} o - `port`, `jar`, `userAgent`, `at` (the screen's
 *   address)
 * @returns {Promise<object>} `{ status, shell, json, view, csrf, prefix,
 *   id }`
 */
async function open(o) {
  log.debug("Entering open().");
  const where = parse(o.at);
  const shellPath = o.at.replace(/^https?:\/\/[^/]+/, '');
  const shell = await call({ port: o.port, ca: o.ca, jar: o.jar,
                             userAgent: o.userAgent, method: 'GET',
                             path: shellPath });
  const viewPath = where.prefix + (where.page === 'password-change'
    ? '/authn-api/password-change/' + encodeURIComponent(where.id)
    : '/authn-api/pending/' + encodeURIComponent(where.id) +
      (where.page === 'select-idp' ? '/partners' : ''));
  const view = await call({ port: o.port, ca: o.ca, jar: o.jar,
                            userAgent: o.userAgent, method: 'GET',
                            path: viewPath,
                            headers: { accept: 'application/json' } });
  log.debug("Leaving open(). " + view.status);
  return { status: view.status, shell: shell, json: view.json,
           view: view.json && view.json.view,
           csrf: (view.json && view.json.csrf) || '',
           prefix: where.prefix, id: where.id, page: where.page };
}

// The operation each of the screen's buttons is.
const OPERATIONS = {
  login: 'password', cancel: 'cancel', anonymous: 'anonymous',
  'email-code': 'email', 'email-link': 'email', passkey: 'passkey'
};

/**
 * Sends an act, bound as the page binds it.
 *
 * @param {object} o - `port`, `jar`, `userAgent`, `opened` (an `open()`
 *   answer), `path` (under the prefix), `body`; `origin`, `contentType`,
 *   `csrf` to send something else
 * @returns {Promise<object>} the answer
 */
async function act(o) {
  log.debug("Entering act().");
  const headers = { accept: 'application/json',
    'content-type': o.contentType || 'application/json' };
  if (o.origin !== null) {
    headers.origin = o.origin ||
      (o.ca ? 'https' : 'http') + '://127.0.0.1:' + o.port;
  }
  const csrf = o.csrf === undefined ? o.opened.csrf : o.csrf;
  if (csrf) {
    headers['x-csrf-token'] = csrf;
  }
  const r = await call({ port: o.port, ca: o.ca, jar: o.jar, userAgent: o.userAgent,
    method: 'POST', path: o.opened.prefix + o.path, headers: headers,
    body: typeof o.body === 'string' ? o.body : JSON.stringify(o.body || {})
  });
  const j = r.json || {};
  const goes = !!j.location && ['redirect', 'mfa', 'password-change']
    .indexOf(j.next) >= 0;
  log.debug("Leaving act(). " + r.status + " " + j.next);
  return { status: goes ? 303 : r.status, apiStatus: r.status,
           json: r.json, text: r.text, next: String(j.next || ''),
           location: String(j.location || ''), errors: j.errors || [],
           step: j.step || '', id: j.id || '', form: j.form || null,
           headers: Object.assign({}, r.headers,
                                  goes ? { location: j.location } : {}) };
}

/**
 * The JSON body of an act from the form's fields.
 *
 * @param {string} action - the button
 * @param {object} f - the fields
 * @returns {object} the body
 */
function bodyFor(action, f) {
  log.debug("Entering bodyFor(). " + action);
  const flag = function (v) {
    return ['1', 'true', 'on', 'yes', true].indexOf(v) >= 0 ? '1'
                                                            : undefined;
  };
  const fields = f || {};
  let out = {};
  if (action === 'login') {
    out = { username: fields.username, password: fields.password,
            use_webauthn: flag(fields.use_webauthn),
            webauthn_only: flag(fields.webauthn_only),
            remember_browser: flag(fields.remember_browser),
            device_fp: fields.device_fp || undefined };
  } else if (action === 'anonymous') {
    out = { remember_browser: flag(fields.remember_browser),
            device_fp: fields.device_fp || undefined };
  } else if (action === 'email-code' || action === 'email-link') {
    out = { username: fields.username,
            kind: action === 'email-link' ? 'link' : 'code',
            remember_browser: flag(fields.remember_browser),
            device_fp: fields.device_fp || undefined };
  } else if (action === 'passkey') {
    out = { credential: fields.passkey_credential || fields.credential,
            remember_browser: flag(fields.remember_browser),
            device_fp: fields.device_fp || undefined };
  }
  Object.keys(out).forEach(function (k) {
    if (out[k] === undefined) {
      delete out[k];
    }
  });
  log.debug("Leaving bodyFor().");
  return out;
}

/**
 * Submits the screen: opens it (shell and view) and sends the act its
 * button is.
 *
 * @param {object} o - `port`, `jar`, `userAgent`, `at` (the screen's
 *   address), `fields` (the form's, `action` among them); `opened`, an
 *   `open()` answer already in hand
 * @returns {Promise<object>} the answer, with `view` and `opened`
 */
async function submit(o) {
  log.debug("Entering submit().");
  const opened = o.opened || await open(o);
  const action = String((o.fields && o.fields.action) || 'login');
  if (!opened.view) {
    log.debug("Leaving submit(). No view.");
    return { status: opened.status, json: opened.json, next: 'no-view',
             location: '', errors: (opened.json && opened.json.errors) || [],
             text: JSON.stringify(opened.json), headers: {}, view: null,
             opened: opened };
  }
  const answer = await act({ port: o.port, ca: o.ca, jar: o.jar,
    userAgent: o.userAgent, opened: opened,
    path: '/authn-api/pending/' + encodeURIComponent(opened.id) + '/' +
          OPERATIONS[action],
    body: bodyFor(action, o.fields) });
  answer.view = opened.view;
  answer.opened = opened;
  log.debug("Leaving submit(). " + answer.next);
  return answer;
}

/**
 * Changes the password a sign-in waits on, as that page does.
 *
 * @param {object} o - `port`, `jar`, `userAgent`, `at` (the page's
 *   address), `fields` (`new_password`, `confirm_password`)
 * @returns {Promise<object>} the answer
 */
async function changePassword(o) {
  log.debug("Entering changePassword().");
  const opened = await open(o);
  const answer = await act({ port: o.port, ca: o.ca, jar: o.jar,
    userAgent: o.userAgent, opened: opened,
    path: '/authn-api/password-change/' + encodeURIComponent(opened.id),
    body: { new_password: o.fields.new_password,
            confirm_password: o.fields.confirm_password } });
  answer.view = opened.view;
  log.debug("Leaving changePassword(). " + answer.next);
  return answer;
}

/**
 * Arms the screen's usernameless passkey ceremony, as its page does when
 * the button is pressed or the autofill starts (#474, `…/passkey/options`).
 *
 * @param {object} o - `port`, `jar`, `userAgent`, `opened`
 * @returns {Promise<object>} the answer, `challenge`, `rpId` and `options`
 *   beside it where the ceremony was armed
 */
async function passkeyOptions(o) {
  log.debug("Entering passkeyOptions().");
  const answer = await act({ port: o.port, ca: o.ca, jar: o.jar,
    userAgent: o.userAgent, opened: o.opened,
    path: '/authn-api/pending/' + encodeURIComponent(o.opened.id) +
          '/passkey/options', body: {} });
  const j = answer.json || {};
  answer.challenge = String(j.challenge || '');
  answer.rpId = String(j.rpId || '');
  answer.options = j.options || null;
  log.debug("Leaving passkeyOptions(). " + answer.apiStatus);
  return answer;
}

/**
 * Submits the screen and, where the act names a page of its own — a second
 * factor's, the set-up step's, the forced password change's — opens that
 * page with a GET, as the screen's runtime sends the browser there. The
 * page is what the form's POST used to answer with; a `redirect` stays
 * `submit()`'s 303-shaped answer, and a refusal its JSON one.
 *
 * @param {object} o - as `submit()`
 * @returns {Promise<object>} the page `{ status, headers, text, json,
 *   answer }`, or `submit()`'s answer
 */
async function follow(o) {
  log.debug("Entering follow().");
  const answer = await submit(o);
  if (answer.next !== 'mfa' && answer.next !== 'password-change') {
    log.debug("Leaving follow(). " + answer.next);
    return answer;
  }
  const page = await call({ port: o.port, ca: o.ca, jar: o.jar,
                            userAgent: o.userAgent, method: 'GET',
                            path: answer.location });
  page.answer = answer;
  log.debug("Leaving follow(). The step's page.");
  return page;
}

module.exports = {
  call: call,
  open: open,
  act: act,
  submit: submit,
  follow: follow,
  passkeyOptions: passkeyOptions,
  changePassword: changePassword,
  bodyFor: bodyFor
};
