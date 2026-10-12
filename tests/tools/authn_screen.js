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
//
// And the OAuth consent screen (#576), a page of the same surface:
// `openConsent()` and `answerConsent()`.
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
    // NO User-Agent of its own: a name like `authn-screen/1.0` is an
    // automated client to risk scoring (`isbot`), which product refuses —
    // a test's own browser sends its User-Agent, or none, as before #571.
    const headers = Object.assign({}, o.userAgent
      ? { 'user-agent': o.userAgent } : {}, o.headers || {});
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
  const r = await call({ port: o.port, ca: o.ca, jar: o.jar,
    userAgent: o.userAgent,
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

// THE STEPS AFTER THE SCREEN (#572, #573): each page's path, and the name
// `GET /authn-api/mfa/{id}?page=` gives it.
const STEP_PAGES = {
  '/authn/totp': 'totp', '/authn/webauthn': 'webauthn',
  '/authn/backup-code': 'backup-code', '/authn/password-factor': 'password',
  '/authn/mfa-setup': 'setup', '/authn/email-code': 'email-code',
  '/authn/email-link': 'email-link', '/authn/email-link/open': 'email-link-open'
};

/**
 * A step's address split into its prefix, its page and its query.
 *
 * @param {string} at - `/realm/x/authn/totp?mfa=…`, or a URL
 * @returns {object} `{ prefix, path, page, id, key, t }`, `page` '' where
 *   the address is not a step's
 */
function stepOf(at) {
  log.debug("Entering stepOf().");
  const url = new URL(String(at), 'http://here.invalid');
  const path = Object.keys(STEP_PAGES).sort(function (x, y) {
    return y.length - x.length;
  }).filter(function (one) {
    return url.pathname.endsWith(one);
  })[0] || url.pathname;
  const prefix = STEP_PAGES[path]
    ? url.pathname.slice(0, url.pathname.length - path.length) : '';
  log.debug("Leaving stepOf().");
  return { prefix: prefix, path: path, page: STEP_PAGES[path] || '',
           id: url.searchParams.get('mfa') || '',
           key: url.searchParams.get('key') || '',
           t: url.searchParams.get('t') || '' };
}

/**
 * Opens a step's page as the sign-in surface does (#572, #573): the shell,
 * then `GET /authn-api/mfa/{id}?page=`.
 *
 * @param {object} o - `port`, `ca`, `jar`, `userAgent`, `at` (the step's
 *   address, as an act's `location` named it); `page`, another page of the
 *   same step
 * @returns {Promise<object>} `{ status, shell, json, view, csrf, prefix, id,
 *   page, key, t, text }`
 */
async function openStep(o) {
  log.debug("Entering openStep().");
  const where = stepOf(o.at);
  const page = o.page || where.page;
  const shell = await call({ port: o.port, ca: o.ca, jar: o.jar,
                             userAgent: o.userAgent, method: 'GET',
                             path: String(o.at).replace(/^https?:\/\/[^/]+/,
                                                         '') });
  const view = await call({ port: o.port, ca: o.ca, jar: o.jar,
    userAgent: o.userAgent, method: 'GET',
    path: where.prefix + '/authn-api/mfa/' + encodeURIComponent(where.id) +
          '?page=' + page + (where.key ? '&key=' +
                             encodeURIComponent(where.key) : ''),
    headers: { accept: 'application/json' } });
  log.debug("Leaving openStep(). " + view.status);
  return { status: view.status, shell: shell, json: view.json,
           view: view.json && view.json.view, text: view.text,
           csrf: (view.json && view.json.csrf) || '',
           prefix: where.prefix, id: where.id, page: page, key: where.key,
           t: where.t, at: o.at };
}

/**
 * Sends a step's act, bound as its page binds it (#572, #573).
 *
 * @param {object} o - `port`, `ca`, `jar`, `userAgent`, `opened` (an
 *   `openStep()` answer), `op` (`totp`, `backup-code`, `password`,
 *   `webauthn/options`, `webauthn`, `setup/totp`, `setup/confirm`,
 *   `setup/webauthn`, `skip`, `email/send`, `email/code`,
 *   `email-link/open`), `body`; `origin`, `contentType`, `csrf` to send
 *   something else
 * @returns {Promise<object>} the answer, as `act()`'s
 */
async function stepAct(o) {
  log.debug("Entering stepAct(). " + o.op);
  const answer = await act(Object.assign({}, o, {
    path: '/authn-api/mfa/' + encodeURIComponent(o.opened.id) + '/' + o.op }));
  log.debug("Leaving stepAct(). " + answer.apiStatus + " " + answer.next);
  return answer;
}

/**
 * Submits the screen and, where the act names a step's page of its own —
 * a second factor's, the set-up step's (#572), an emailed factor's (#573),
 * the forced password change's — opens it as the surface does: a step's
 * view (`openStep()`), or the password change's (`open()`). A `redirect`
 * stays `submit()`'s 303-shaped answer, and a refusal its JSON one.
 *
 * @param {object} o - as `submit()`
 * @returns {Promise<object>} the opened page with `answer`, or `submit()`'s
 *   answer
 */
async function follow(o) {
  log.debug("Entering follow().");
  const answer = await submit(o);
  if (answer.next !== 'mfa' && answer.next !== 'password-change') {
    log.debug("Leaving follow(). " + answer.next);
    return answer;
  }
  const page = answer.next === 'mfa'
    ? await openStep({ port: o.port, ca: o.ca, jar: o.jar,
                       userAgent: o.userAgent, at: answer.location })
    : await open({ port: o.port, ca: o.ca, jar: o.jar,
                   userAgent: o.userAgent, at: answer.location });
  page.answer = answer;
  log.debug("Leaving follow(). The step's page.");
  return page;
}

/**
 * Where an answer names a step, opens it; where that step is an OFFERED
 * set-up (#246), presses Ignore, as a person who only wants to sign in on a
 * password does. Any other answer as it is.
 *
 * @param {object} o - `port`, `ca`, `jar`, `userAgent`
 * @param {object} answer - an act's answer
 * @returns {Promise<object>} the Ignore's answer, or `answer`
 */
async function ignoreOffer(o, answer) {
  log.debug("Entering ignoreOffer().");
  if (!(answer.next === 'mfa' && answer.step === 'enrol')) {
    log.debug("Leaving ignoreOffer(). " + answer.next);
    return answer;
  }
  const opened = await openStep(Object.assign({}, o,
                                              { at: answer.location }));
  if (!(opened.view && opened.view.setup && opened.view.setup.optional)) {
    log.debug("Leaving ignoreOffer(). A required set-up step.");
    answer.opened = opened;
    return answer;
  }
  const ignored = await stepAct(Object.assign({}, o, { opened: opened,
                                                       op: 'skip', body: {} }));
  ignored.ignored = true;
  log.debug("Leaving ignoreOffer(). Ignored.");
  return ignored;
}

/**
 * A step's passkey ceremony, its authenticator the test's own: arms it
 * (`webauthn/options`), hands the options to `make` — which answers the
 * credential's JSON form, or a promise of it — and sends the result.
 *
 * @param {object} o - `port`, `ca`, `jar`, `userAgent`, `opened` (the
 *   passkey page, `openStep()`), `key` (a chosen passkey, #534)
 * @param {Function} make - `(ceremony) => credential`
 * @returns {Promise<object>} `{ armed, answer }`
 */
async function passkeyStep(o, make) {
  log.debug("Entering passkeyStep().");
  const armed = await stepAct(Object.assign({}, o, { op: 'webauthn/options',
    body: o.key ? { key: o.key } : {} }));
  if (!armed.json || !armed.json.ok) {
    log.debug("Leaving passkeyStep(). Not armed.");
    return { armed: armed, answer: armed };
  }
  const credential = await make(armed.json);
  const answer = await stepAct(Object.assign({}, o, { op: 'webauthn',
    body: { credential: typeof credential === 'string'
      ? credential : JSON.stringify(credential) } }));
  log.debug("Leaving passkeyStep(). " + answer.next);
  return { armed: armed, answer: answer };
}

// THE OAUTH CONSENT SCREEN (#576): `/oauth2/consent?consent=<id>` answers
// the sign-in surface's shell, the page is drawn from `GET
// /authn-api/consent/{id}`, and Allow or Deny goes to `POST
// /authn-api/consent/{id}`, bound as every act of the surface.

/**
 * The consent screen's address split into its prefix and its id.
 *
 * @param {string} at - `/realm/x/oauth2/consent?consent=…`, or a URL
 * @returns {object} `{ prefix, id }`
 */
function consentOf(at) {
  log.debug("Entering consentOf().");
  const url = new URL(String(at), 'http://here.invalid');
  const m = /^(.*?)\/oauth2\/consent$/.exec(url.pathname);
  log.debug("Leaving consentOf().");
  return { prefix: m ? m[1] : '',
           id: url.searchParams.get('consent') || '' };
}

/**
 * Opens the consent screen as its page does: the shell, then the view.
 *
 * @param {object} o - `port`, `ca`, `jar`, `userAgent`, `at` (the screen's
 *   address, as the authorization endpoint's redirect named it)
 * @returns {Promise<object>} `{ status, shell, json, view, csrf, prefix,
 *   id, text }`
 */
async function openConsent(o) {
  log.debug("Entering openConsent().");
  const where = consentOf(o.at);
  const shell = await call({ port: o.port, ca: o.ca, jar: o.jar,
                             userAgent: o.userAgent, method: 'GET',
                             path: String(o.at).replace(/^https?:\/\/[^/]+/,
                                                         '') });
  const view = await call({ port: o.port, ca: o.ca, jar: o.jar,
    userAgent: o.userAgent, method: 'GET',
    path: where.prefix + '/authn-api/consent/' +
          encodeURIComponent(where.id),
    headers: { accept: 'application/json' } });
  log.debug("Leaving openConsent(). " + view.status);
  return { status: view.status, shell: shell, json: view.json,
           view: view.json && view.json.view, text: view.text,
           csrf: (view.json && view.json.csrf) || '',
           prefix: where.prefix, id: where.id, at: o.at };
}

/**
 * Answers the consent screen as its page does: opens it, then sends Allow
 * or Deny with any limit a test lowered. The answer is `act()`'s — a 303
 * with `headers.location` the authorization request to go back to, read as
 * the form's answer was.
 *
 * @param {object} o - `port`, `ca`, `jar`, `userAgent`, `at`; `decision`,
 *   `allow` (the default) or `deny`; `limits`, the controls' values by
 *   name (`lim_t0r0_amount`); `opened`, an `openConsent()` answer in hand
 * @returns {Promise<object>} the answer, `opened` beside it
 */
async function answerConsent(o) {
  log.debug("Entering answerConsent().");
  const opened = o.opened || await openConsent(o);
  const answer = await act(Object.assign({}, o, { opened: opened,
    path: '/authn-api/consent/' + encodeURIComponent(opened.id),
    body: Object.assign({}, o.limits || {},
                        { action: o.decision === 'deny' ? 'deny'
                                                        : 'allow' }) }));
  answer.opened = opened;
  answer.view = opened.view;
  log.debug("Leaving answerConsent(). " + answer.apiStatus + " " +
            answer.next);
  return answer;
}

module.exports = {
  consentOf: consentOf,
  openConsent: openConsent,
  answerConsent: answerConsent,
  call: call,
  open: open,
  act: act,
  submit: submit,
  follow: follow,
  STEP_PAGES: STEP_PAGES,
  stepOf: stepOf,
  openStep: openStep,
  stepAct: stepAct,
  ignoreOffer: ignoreOffer,
  passkeyStep: passkeyStep,
  passkeyOptions: passkeyOptions,
  changePassword: changePassword,
  bodyFor: bodyFor
};
