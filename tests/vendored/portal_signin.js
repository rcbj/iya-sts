// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
// File: portal_signin.js
// ===========================================================================
// SIGNING IN AS THE STATIC USER PORTAL, OVER HTTP, AND ASKING WHAT ITS PAGES
// ASK (#568, 2026-10-12).
//
// **THIS IS A HELPER AND NOT A JOB**, and it is OURS (`MANIFEST.js`'s
// LOCAL_HELPERS). It has no assertions of its own beyond the ones that say
// the flow did not happen.
//
// Since #568 the portal is a static page: every `/portal/*` path answers the
// same document, and the page signs in IN THE BROWSER as the public client
// `sts-user-portal` — the code flow with PKCE S256, `resource` the realm's
// `/account-api`, a token that is always DPoP-bound — and draws each page
// from its `/account-api` operation's answer. So a job signs in the same way
// and asks the same operations, as `console_signin.js` does for the console:
//
//   GET  /portal                                -> the shell (registers the
//                                                  realm's /portal/callback)
//   GET  /oauth2/authorize?…code_challenge…     -> 302 /authn/login?authn=…
//   POST /authn/login                           -> 303 back to authorize
//   GET  /oauth2/authorize                      -> 302 /portal/callback?code=…
//   POST /oauth2/token (DPoP)                   -> a DPoP-bound access token
//
// THE CLIENT IT ANSWERS:
//   * `page(path, query)` — the GET operation that mirrors a portal page,
//     asked with the page's query: the page's view.
//   * `draw(path, query)` — that view drawn by the portal's own renderers
//     (`portal/portal.bundle.js`), `{ status, json, html }`.
//   * `act(path, fields)` — the POST operation that mirrors the form at
//     `path`, sent its fields as JSON.
//   * `api(method, path, body)` — any `/account-api` path, as the portal.
//   * `refresh()` — the refresh grant with the same DPoP key.
//   * `cookie` — the sign-on session's cookie the walk set, for a job that
//     also needs the person's browser session.
//
// `nobody(method, path, body)` (a module function) calls an operation that
// takes no token — an activation or reset link's — as the portal does for a
// page drawn for nobody.
//
// THE PERSON: `options.password` signs in an account that exists with that
// password; otherwise the account is created first through `/admin-api`
// (the run's preload attaches its credential), with a random password this
// process holds — `console_signin.js`'s `ensureConsoleAccount()`.
// ===========================================================================

const assert = require("assert");
const signin = require("./console_signin.js");

const log = require("bunyan").createLogger({ name: "portal_signin",
  level: process.env.STS_LOG_LEVEL || "info" });

// A DESKTOP BROWSER'S USER-AGENT on every request, as the portal's own
// requests carry one: product mode's risk scoring (#62) refuses a first
// sign-in from an agent that reads as a bot, and the jobs that walked the
// portal with a browser of their own sent this string before #568.
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A P-256 key per sign-in and the RFC 9449 proof it signs — the console
// helper's, written once more here so the two helpers do not share state.
function dpopKey() {
  log.debug("Entering dpopKey().");
  const crypto = require("crypto");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const state = { nonce: "" };
  log.debug("Leaving dpopKey().");
  return {
    publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    keepNonce: function (response) {
      const nonce = response.headers.get("dpop-nonce");
      if (nonce) {
        state.nonce = nonce;
      }
    },
    proof: function (method, url, accessToken) {
      const header = { typ: "dpop+jwt", alg: "ES256", jwk: this.publicJwk };
      const claims = { jti: b64u(crypto.randomBytes(16)),
                       htm: String(method).toUpperCase(),
                       htu: String(url).replace(/[?#].*$/, ""),
                       iat: Math.floor(Date.now() / 1000) };
      if (accessToken) {
        claims.ath = b64u(crypto.createHash("sha256").update(accessToken)
          .digest());
      }
      if (state.nonce) {
        claims.nonce = state.nonce;
      }
      const input = b64u(JSON.stringify(header)) + "." +
                    b64u(JSON.stringify(claims));
      const signature = crypto.sign("sha256", Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
      return input + "." + b64u(signature);
    }
  };
}

// THE PORTAL'S RENDERERS, as a browser loads them: `portal/portal.bundle.js`,
// the image build's esbuild output of `web_portal_pages.ts`, run in a context
// with no require, process or Buffer. Loaded once.
let bundle = null;
function portalBundle() {
  log.debug("Entering portalBundle().");
  if (!bundle) {
    const fs = require("fs");
    const path = require("path");
    const vm = require("vm");
    const file = path.join(__dirname, "..", "..", "portal",
                           "portal.bundle.js");
    const code = fs.readFileSync(file, "utf8");
    bundle = vm.runInContext(code + "\n;StsPortal;",
      vm.createContext({ URLSearchParams: URLSearchParams, Intl: Intl }),
      { filename: "portal.bundle.js" });
  }
  log.debug("Leaving portalBundle().");
  return bundle;
}

// The account API's index, once per base: which operation mirrors which
// portal page or form.
const indexes = {};
async function operationsOf(base) {
  log.debug("Entering operationsOf().");
  if (!indexes[base]) {
    const r = await fetch(base + "/account-api",
                          { headers: { accept: "application/json" } });
    const json = await r.json().catch(function () {
      return null;
    });
    assert.ok(r.status === 200 && json && Array.isArray(json.operations),
      "GET " + base + "/account-api should answer the index of " +
      "operations; it answered " + r.status);
    indexes[base] = json.operations;
  }
  log.debug("Leaving operationsOf().");
  return indexes[base];
}

// The operation that mirrors `METHOD path`.
async function mirroring(base, method, path) {
  log.debug("Entering mirroring().");
  const wanted = method + " " + path;
  const row = (await operationsOf(base)).filter(function (op) {
    return op.mirrors === wanted;
  })[0];
  assert.ok(row, "no /account-api operation mirrors " + wanted);
  log.debug("Leaving mirroring().");
  return row;
}

// AN OPERATION THAT TAKES NO TOKEN, as the portal calls one for a page drawn
// for nobody: `{ status, json, text, headers }`.
async function nobody(base, method, path, body) {
  log.debug("Entering nobody().");
  const url = /^https?:/.test(path) ? path : base + path;
  const init = { method: method, headers: { accept: "application/json",
                                            "User-Agent": AGENT } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in nobody(): " + ((e && e.message) || e));
    // Not JSON: answered as its text.
    json = null;
  }
  log.debug("Leaving nobody().");
  return { status: r.status, json: json, text: text, headers: r.headers };
}

// `base` is the service's base URL (a realm's prefix included for a realm);
// `user` the name to sign in as; `log2` optional; `options.password` the
// password of an account that exists, `options.cookie` a sign-on session
// already held (no password typed: single sign-on answers the flow), and
// `options.acrValues` / `options.prompt` for a step-up.
async function signInToThePortal(base, user, log2, options) {
  log.debug("Entering signInToThePortal().");
  const say = (log2 && log2.info) ? log2.info.bind(log2) : function () {};
  const opts = options || {};
  const cookies = signin.jar();
  const crypto = require("crypto");
  const key = dpopKey();
  if (opts.cookie) {
    String(opts.cookie).split(/;\s*/).forEach(function (pair) {
      const name = pair.split("=")[0];
      if (name) {
        cookies.keep({ headers: { getSetCookie: function () {
          return [pair];
        } } });
      }
    });
  }

  function fromLocation(location) {
    return new URL(String(location || ""), base).toString();
  }

  async function fetchKeeping(url, init) {
    const sent = Object.assign({ redirect: "manual" }, init || {});
    sent.headers = Object.assign({ cookie: cookies.header(),
                                   "User-Agent": AGENT },
                                 sent.headers || {});
    const r = await fetch(url, sent);
    cookies.keep(r);
    return r;
  }

  const password = opts.cookie ? "" : (opts.password ||
    await signin.ensureConsoleAccount(base, user, say));

  // THE SHELL FIRST, as a browser opens the portal: serving it registers
  // this realm's `/portal/callback` on the seeded portal client.
  const shell = await fetchKeeping(base + "/portal?realm=default");
  assert.ok(shell.status === 200,
    "GET " + base + "/portal should answer the portal's shell; it answered " +
    shell.status);

  const verifier = b64u(crypto.randomBytes(32));
  const state = b64u(crypto.randomBytes(16));
  const redirectUri = base + "/portal/callback";
  const resource = base + "/account-api";
  const params = {
    response_type: "code", client_id: "sts-user-portal",
    redirect_uri: redirectUri, scope: "openid account:manage",
    state: state, code_challenge: b64u(crypto.createHash("sha256")
      .update(verifier).digest()),
    code_challenge_method: "S256", resource: resource };
  if (opts.prompt) {
    params.prompt = opts.prompt;
  }
  if (opts.acrValues) {
    params.acr_values = opts.acrValues;
  }
  let at = await fetchKeeping(base + "/oauth2/authorize?" +
                              new URLSearchParams(params).toString());
  let location = at.headers.get("location") || "";
  const authn = (location.match(/[?&]authn=([^&]+)/) || [])[1];
  if (authn) {
    assert.ok(password, "the portal's authorization request asked for a " +
      "sign-in, and this walk was given a session rather than a password");
    const screen = await fetchKeeping(fromLocation(location));
    const screenHtml = await screen.text();
    const csrf =
      (screenHtml.match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
    at = await fetchKeeping(fromLocation(location).split("?")[0], {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "authn_id=" + encodeURIComponent(authn) +
            "&username=" + encodeURIComponent(user) +
            "&password=" + encodeURIComponent(password) +
            "&action=login" +
            (csrf ? "&csrf_token=" + encodeURIComponent(csrf) : "")
    });
    // A SECOND FACTOR OFFERED (#246) is ignored, as the console helper does.
    if (at.status === 200) {
      const offered = await at.text();
      const setupId = /id="mfa-setup-ignore"/.test(offered)
        ? (offered.match(/name="mfa_id" value="([^"]+)"/) || [])[1] || ""
        : "";
      assert.ok(setupId, "signing in at /authn/login answered 200 and no " +
        "Ignore button: " + offered.slice(0, 300));
      at = await fetchKeeping(base + "/authn/mfa-setup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "mfa_id=" + encodeURIComponent(setupId) + "&action=ignore"
      });
    }
    location = at.headers.get("location") || "";
  }
  for (let i = 0; i < 5 && !/\/portal\/callback\?/.test(location) &&
       (at.status === 302 || at.status === 303); i++) {
    at = await fetchKeeping(fromLocation(location));
    location = at.headers.get("location") || "";
  }
  const back = new URL(fromLocation(location));
  const code = back.searchParams.get("code");
  assert.ok(/\/portal\/callback$/.test(back.pathname) && code &&
            back.searchParams.get("state") === state,
    "the authorization endpoint should answer the portal's callback with a " +
    "code and the state it was sent; it answered " + at.status + " to \"" +
    location + "\"");

  const tokenUrl = base + "/oauth2/token";
  async function tokenRequest(form) {
    log.debug("Entering tokenRequest().");
    let answer = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const r = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded",
                   "User-Agent": AGENT,
                   dpop: key.proof("POST", tokenUrl, "") },
        body: new URLSearchParams(form).toString() });
      key.keepNonce(r);
      answer = { status: r.status, json: await r.json().catch(function () {
        return {};
      }) };
      if (!(r.status === 400 && answer.json.error === "use_dpop_nonce")) {
        break;
      }
    }
    log.debug("Leaving tokenRequest().");
    return answer;
  }
  const issued = await tokenRequest({
    grant_type: "authorization_code", code: code, redirect_uri: redirectUri,
    client_id: "sts-user-portal", code_verifier: verifier,
    resource: resource });
  assert.ok(issued.status === 200 && issued.json.access_token &&
            /^dpop$/i.test(String(issued.json.token_type || "")),
    "the portal's code should redeem for a DPoP-bound access token; the " +
    "token endpoint answered " + issued.status + " " +
    JSON.stringify(issued.json).slice(0, 300));
  let token = issued.json.access_token;
  let refreshToken = issued.json.refresh_token || "";

  async function refresh() {
    log.debug("Entering refresh().");
    const answer = await tokenRequest({
      grant_type: "refresh_token", refresh_token: refreshToken,
      client_id: "sts-user-portal", resource: resource });
    if (answer.status === 200 && answer.json.access_token) {
      token = answer.json.access_token;
      refreshToken = answer.json.refresh_token || refreshToken;
    }
    log.debug("Leaving refresh().");
    return answer;
  }

  async function api(method, path, body) {
    log.debug("Entering api().");
    const url = /^https?:/.test(path) ? path : base + path;
    let answer = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers = { authorization: "DPoP " + token,
                        dpop: key.proof(method, url, token),
                        accept: "application/json", "User-Agent": AGENT };
      const init = { method: method, headers: headers };
      if (body !== undefined) {
        headers["content-type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      const r = await fetch(url, init);
      key.keepNonce(r);
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in api(): " + ((e && e.message) || e));
        // Not JSON: answered as its text.
        json = null;
      }
      answer = { status: r.status, json: json, text: text,
                 headers: r.headers };
      const challenge = String(r.headers.get("www-authenticate") || "");
      if (r.status === 401 && /invalid_token/.test(challenge) &&
          refreshToken && attempt === 0) {
        const renewed = await refresh();
        if (renewed.status === 200) {
          continue;
        }
      }
      if (!(r.status === 401 && /use_dpop_nonce/.test(challenge))) {
        break;
      }
    }
    log.debug("Leaving api().");
    return answer;
  }

  say("[portal] signed in as " + user + " as the static portal: PKCE, a " +
      "DPoP-bound token for " + resource + ".");
  log.debug("Leaving signInToThePortal().");
  return {
    user: user,
    password: password,
    base: base,
    get token() {
      return token;
    },
    get refreshToken() {
      return refreshToken;
    },
    cookie: cookies.header(),
    api: api,
    refresh: refresh,
    key: key,
    // The page's view: the GET operation that mirrors it, with its query.
    page: async function (path, query) {
      const row = await mirroring(base, "GET", path);
      const qs = new URLSearchParams(query || {}).toString();
      return api("GET", row.path + (qs ? "?" + qs : ""));
    },
    // The page drawn by the portal's own renderers, in the reader's
    // language: `{ status, json, html }`.
    draw: async function (path, query) {
      const answer = await this.page(path, query);
      if (this.me === undefined) {
        const me = await api("GET", "/account-api/me");
        this.me = me.json;
      }
      const table = portalBundle();
      const t = table.messages
        ? table.messages.WebTranslator.fromData(this.me && this.me.locale)
        : null;
      const view = answer.json && answer.json.view ? answer.json.view
                                                  : answer.json;
      const html = answer.status === 200 && view
        ? table.render(path, view, { t: t, query: query || {}, prefix: "",
                                     origin: base, me: this.me }) : "";
      return { status: answer.status, json: answer.json, html: html };
    },
    // The form at `path`, sent to the operation that mirrors it.
    act: async function (path, fields) {
      const row = await mirroring(base, "POST", path);
      return api("POST", row.path, Object.assign({}, fields || {}));
    }
  };
}

module.exports = { signInToThePortal: signInToThePortal, nobody: nobody,
                   operationsOf: operationsOf, portalBundle: portalBundle };
