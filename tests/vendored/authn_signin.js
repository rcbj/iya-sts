// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: authn_signin.js
//
// ===========================================================================
// SIGNING IN AT THE SIGN-IN SCREEN, OVER `/authn-api`, AS ITS PAGE DOES
// (#571, 2026-10-12).
//
// **THIS IS A HELPER AND NOT A JOB**, and it is OURS (`MANIFEST.js`'s
// LOCAL_HELPERS). Every job that signs somebody in at `/authn/login` signs
// in through it — rcbj's decision on #571 — so the screen's protocol is
// written down once, the way `console_signin.js` writes the console's.
//
// ---------------------------------------------------------------------------
// WHAT CHANGED AT #571, AND SO WHAT THIS DOES.
//
// The screen was a form: `GET /authn/login?authn=<id>` drew it with a hidden
// `authn_id` and `csrf_token`, and `POST /authn/login` answered a 303 back
// to the caller, or a page — the screen again, a second factor's, the
// forced password change's. Since #571 the screen is a static surface:
//
//   GET  /authn/login?authn=<id>               the shell; it mints the
//                                              sts_session arrival cookie
//                                              where the browser has none
//   GET  /authn-api/pending/<id>               { view, csrf }
//   POST /authn-api/pending/<id>/<operation>   JSON, Origin, X-CSRF-Token
//        -> { ok, next: 'redirect' | 'mfa' | 'password-change' |
//             'home-cell', location, step, id, form }
//        -> { ok: false, next: 'refused', errors }
//
// So this does what the page does: the shell (for its cookie), the view
// (for the token), and the act, with the cookies kept between them.
//
// ---------------------------------------------------------------------------
// WHAT IT ANSWERS: `submit()` takes the FORM's fields as the jobs wrote them
// before — `action` (`login`, `cancel`, `anonymous`, `email-code`,
// `email-link`, `passkey`), `username`, `password`, `use_webauthn`,
// `webauthn_only`, `remember_browser`, `device_fp`, `passkey_credential` —
// and answers:
//
//   { status, json, next, location, step, id, errors, view, csrf,
//     cookie, setCookies, headers }
//
// `location` ABSOLUTE (on the base's origin) for `redirect`, `mfa` and
// `password-change`; `cookie` the request's cookie header with every
// cookie both requests set folded in; `headers` a `get()`/`getSetCookie()`
// pair over the same, so a job's own jar `keep()`s the answer as it kept a
// fetch response. A job follows `location` with a GET, as a browser follows
// the 303 the form was answered with: a second factor's page is still
// server-drawn (#572) and answers its HTML there.
// ===========================================================================

const log = require("bunyan").createLogger({ name: "authn_signin",
  level: process.env.LOG_LEVEL || "info" });

/**
 * The pending sign-in's id in a screen address, or the id itself.
 *
 * @param {string} where - `/authn/login?authn=…`, an absolute URL, or an id
 * @returns {string} the id
 */
function pendingIdOf(where) {
  log.debug("Entering pendingIdOf().");
  const text = String(where || "");
  const m = text.match(/[?&](?:authn|change)=([^&#]+)/);
  log.debug("Leaving pendingIdOf().");
  return m ? decodeURIComponent(m[1]) : text;
}

/**
 * A cookie header with set-cookie lines folded in; an emptied value
 * removes the cookie, as a browser does.
 *
 * @param {string} header - the cookie header so far
 * @param {string[]} setCookies - `Set-Cookie` lines
 * @returns {string} the cookie header
 */
function foldCookies(header, setCookies) {
  log.debug("Entering foldCookies().");
  const held = {};
  const order = [];
  String(header || "").split(/;\s*/).forEach(function (pair) {
    const at = pair.indexOf("=");
    if (at > 0) {
      const name = pair.slice(0, at).trim();
      if (!(name in held)) {
        order.push(name);
      }
      held[name] = pair.slice(at + 1);
    }
  });
  (setCookies || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1);
    if (value === "") {
      delete held[name];
      return;
    }
    if (!(name in held)) {
      order.push(name);
    }
    held[name] = value;
  });
  log.debug("Leaving foldCookies().");
  return order.filter(function (name) {
    return name in held;
  }).map(function (name) {
    return name + "=" + held[name];
  }).join("; ");
}

/**
 * The set-cookie lines of a fetch response.
 *
 * @param {object} res - the response
 * @returns {string[]} the lines
 */
function setCookiesOf(res) {
  log.debug("Entering setCookiesOf().");
  log.debug("Leaving setCookiesOf().");
  return res.headers.getSetCookie ? res.headers.getSetCookie() : [];
}

/**
 * The service's base without a trailing slash, and its origin.
 *
 * @param {string} base - the base URL, a realm's prefix included
 * @returns {{base: string, origin: string}} both
 */
function baseOf(base) {
  log.debug("Entering baseOf().");
  const b = String(base || "").replace(/\/+$/, "");
  log.debug("Leaving baseOf().");
  return { base: b, origin: new URL(b).origin };
}

/**
 * Opens the screen as the page does: the shell (for the arrival cookie a
 * browser without one is given) and the view (for the CSRF token).
 *
 * @param {string} base - the service's base, a realm's prefix included
 * @param {string} where - the screen's address or the pending id
 * @param {object} [options] - `cookie`, the request's cookie header;
 *   `page`, `select-idp` or `password-change` for those pages' views
 * @returns {Promise<object>} `{ status, json, view, csrf, cookie,
 *   setCookies, shellStatus }`
 */
async function screen(base, where, options) {
  log.debug("Entering screen().");
  const opts = options || {};
  const b = baseOf(base);
  const id = pendingIdOf(where);
  const page = opts.page || "login";
  const shellPath = page === "password-change"
    ? "/authn/password-change?change=" : (page === "select-idp"
      ? "/authn/select-idp?authn=" : "/authn/login?authn=");
  let cookie = String(opts.cookie || "");
  const setCookies = [];
  const shell = await fetch(b.base + shellPath + encodeURIComponent(id),
    { redirect: "manual", headers: cookie ? { cookie: cookie } : {} });
  setCookiesOf(shell).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookies);
  await shell.text();
  const viewPath = page === "password-change"
    ? "/authn-api/password-change/" + encodeURIComponent(id)
    : "/authn-api/pending/" + encodeURIComponent(id) +
      (page === "select-idp" ? "/partners" : "");
  const res = await fetch(b.base + viewPath, {
    headers: Object.assign({ accept: "application/json" },
                           cookie ? { cookie: cookie } : {}) });
  setCookiesOf(res).forEach(function (one) {
    setCookies.push(one);
  });
  cookie = foldCookies(cookie, setCookiesOf(res));
  const json = await res.json().catch(function (e) {
    log.debug("Caught in screen(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status.
    return null;
  });
  log.debug("Leaving screen(). " + res.status);
  return { status: res.status, shellStatus: shell.status, json: json,
           view: json && json.view, csrf: (json && json.csrf) || "",
           cookie: cookie, setCookies: setCookies, id: id };
}

/**
 * Sends one act to the sign-in API, bound as the page binds it.
 *
 * @param {string} base - the service's base
 * @param {string} path - the operation's path under the base, its id
 *   filled (`/authn-api/pending/<id>/password`)
 * @param {object} body - the act's JSON
 * @param {object} options - `cookie`, `csrf`; `origin` and `contentType` to
 *   send something else (a refusal test)
 * @returns {Promise<object>} the answer, as `submit()` describes it
 */
async function act(base, path, body, options) {
  // The id is a bearer capability: not logged.
  log.debug("Entering act(). " +
            String(path).replace(/\/(pending|password-change)\/[^/]+/,
                                 "/$1/(id)"));
  const opts = options || {};
  const b = baseOf(base);
  const headers = { accept: "application/json",
                    "content-type": opts.contentType || "application/json" };
  if (opts.origin !== null) {
    headers.origin = opts.origin || b.origin;
  }
  if (opts.csrf) {
    headers["x-csrf-token"] = opts.csrf;
  }
  if (opts.cookie) {
    headers.cookie = opts.cookie;
  }
  const res = await fetch(b.base + path, { method: "POST",
    redirect: "manual", headers: headers,
    body: typeof body === "string" ? body : JSON.stringify(body || {}) });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in act(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the status and the text.
    json = null;
  }
  const answer = answerOf(b, res, json, text, opts.cookie,
                          opts.setCookies || []);
  log.debug("Leaving act(). " + res.status + " " + answer.next);
  return answer;
}

/**
 * The answer a job reads, from an act's response.
 *
 * @param {object} b - `baseOf()`'s answer
 * @param {object} res - the fetch response
 * @param {object|null} json - its JSON
 * @param {string} text - its text
 * @param {string} cookie - the cookie header the act was sent with
 * @param {string[]} earlier - set-cookie lines of the requests before it
 * @returns {object} the answer
 */
function answerOf(b, res, json, text, cookie, earlier) {
  log.debug("Entering answerOf().");
  const own = setCookiesOf(res);
  const all = (earlier || []).concat(own);
  const j = json || {};
  const location = j.location
    ? new URL(String(j.location), b.origin).toString() : "";
  log.debug("Leaving answerOf().");
  return {
    status: res.status, json: json, text: text,
    ok: !!j.ok, next: String(j.next || (json ? "" : "not-json")),
    location: location, step: j.step || "", id: j.id || "",
    form: j.form || null, errors: j.errors || [],
    cookie: foldCookies(cookie, own), setCookies: all,
    headers: {
      get: function (name) {
        const n = String(name).toLowerCase();
        if (n === "location") {
          return location || null;
        }
        if (n === "set-cookie") {
          return all.length ? all.join(", ") : null;
        }
        return res.headers.get(name);
      },
      getSetCookie: function () {
        return all.slice();
      }
    }
  };
}

// The operation each of the form's buttons is, and the body it takes.
const OPERATIONS = {
  login: "password", cancel: "cancel", anonymous: "anonymous",
  "email-code": "email", "email-link": "email", passkey: "passkey"
};

/**
 * The JSON body of an act, from the form's fields as a job wrote them.
 *
 * @param {string} action - the button
 * @param {object} fields - the form's fields
 * @returns {object} the body
 */
function bodyFor(action, fields) {
  log.debug("Entering bodyFor(). " + action);
  const f = fields || {};
  const flag = function (v) {
    return ["1", "true", "on", "yes", true].indexOf(v) >= 0 ? "1"
                                                            : undefined;
  };
  let out = {};
  if (action === "login") {
    out = { username: f.username, password: f.password,
            use_webauthn: flag(f.use_webauthn),
            webauthn_only: flag(f.webauthn_only),
            remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  } else if (action === "anonymous") {
    out = { remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  } else if (action === "email-code" || action === "email-link") {
    out = { username: f.username,
            kind: action === "email-link" ? "link" : "code",
            remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
  } else if (action === "passkey") {
    out = { credential: f.passkey_credential || f.credential,
            remember_browser: flag(f.remember_browser),
            device_fp: f.device_fp || undefined };
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
 * Submits the sign-in screen as its page does: opens it (shell and view),
 * then sends the act the form's `action` is.
 *
 * @param {string} base - the service's base, a realm's prefix included
 * @param {string} where - the screen's address, or the pending id
 * @param {object} fields - the form's fields, `action` among them
 *   (`login` where left out)
 * @param {object} [options] - `cookie`; `screen`, a `screen()` answer
 *   already in hand
 * @returns {Promise<object>} the answer, with the view it was sent from
 */
async function submit(base, where, fields, options) {
  log.debug("Entering submit().");
  const opts = options || {};
  const action = String((fields && fields.action) || "login");
  const opened = opts.screen || await screen(base, where,
                                             { cookie: opts.cookie });
  if (!opened.view) {
    log.debug("Leaving submit(). No view: " + opened.status);
    return Object.assign({ status: opened.status, json: opened.json,
      ok: false, next: "no-view", location: "", errors:
        (opened.json && opened.json.errors) || [], view: null, csrf: "",
      cookie: opened.cookie, setCookies: opened.setCookies,
      headers: {
        get: function () {
          return null;
        },
        getSetCookie: function () {
          return opened.setCookies;
        }
      }
    });
  }
  const op = OPERATIONS[action];
  if (!op) {
    throw new Error("authn_signin: the sign-in screen has no button " +
                    action);
  }
  const answer = await act(base, "/authn-api/pending/" +
    encodeURIComponent(opened.id) + "/" + op, bodyFor(action, fields),
    { cookie: opened.cookie, csrf: opened.csrf,
      setCookies: opened.setCookies });
  answer.view = opened.view;
  answer.csrf = opened.csrf;
  log.debug("Leaving submit(). " + answer.next);
  return answer;
}

/**
 * Arms a passkey ceremony with no username on a pending sign-in.
 *
 * @param {string} base - the service's base
 * @param {object} opened - a `screen()` answer
 * @returns {Promise<object>} `{ status, json }`: `challenge`, `rpId`,
 *   `options`
 */
async function passkeyOptions(base, opened) {
  log.debug("Entering passkeyOptions().");
  const answer = await act(base, "/authn-api/pending/" +
    encodeURIComponent(opened.id) + "/passkey/options", {},
    { cookie: opened.cookie, csrf: opened.csrf });
  log.debug("Leaving passkeyOptions().");
  return answer;
}

/**
 * Changes the password a sign-in is waiting on, as the forced change's
 * page does.
 *
 * @param {string} base - the service's base
 * @param {string} where - the page's address or the step's id
 * @param {object} fields - `new_password`, `confirm_password`
 * @param {object} [options] - `cookie`
 * @returns {Promise<object>} the answer
 */
async function changePassword(base, where, fields, options) {
  log.debug("Entering changePassword().");
  const opts = options || {};
  const opened = await screen(base, where, { cookie: opts.cookie,
                                             page: "password-change" });
  const answer = await act(base, "/authn-api/password-change/" +
    encodeURIComponent(opened.id), {
      new_password: fields.new_password,
      confirm_password: fields.confirm_password },
    { cookie: opened.cookie, csrf: opened.csrf,
      setCookies: opened.setCookies });
  answer.view = opened.view;
  log.debug("Leaving changePassword(). " + answer.next);
  return answer;
}

module.exports = {
  pendingIdOf: pendingIdOf,
  foldCookies: foldCookies,
  screen: screen,
  act: act,
  submit: submit,
  passkeyOptions: passkeyOptions,
  changePassword: changePassword,
  bodyFor: bodyFor
};
