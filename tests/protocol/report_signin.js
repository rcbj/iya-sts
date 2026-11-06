// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
// File: report_signin.js
// ===========================================================================
// SIGNING IN AS THE REPORTING APPLICATION'S PUBLIC CLIENT (#1299).
//
// **A HELPER AND NOT A JOB**, and it is OURS (MANIFEST.js's LOCAL_HELPERS).
// There is no packaged report-api sign-in — report-api is otherwise tested
// only in process — so the Schemathesis auth proxy needs one to obtain a
// DPoP-bound `report:use report:admin` token for `sts-report`. It is the same
// code flow `portal_signin.js` and `console_signin.js` drive, for the report
// client and resource: PKCE S256, pushed authorization where the realm
// requires it (RFC 9700 / OAuth 2.1), JARM where it offers nothing else, the
// sign-in screen over `/authn-api`, a consent screen if one is shown, and a
// DPoP-bound token redeemed with a nonce retry.
//
// The PERSON must already exist with `options.password` and hold the report
// roles (the fuzz run creates and grants through `/admin-api` first); this
// helper only signs that account in. It returns `{ token, key, refresh }`:
// the proxy signs a fresh proof per forwarded request with `key.proof()`.
//
// REDIRECT URI: the seeded `sts-report` client registers
// `rebaseTo(base, 'report') + '/report/callback'`, which is `base +
// '/report/callback'` wherever the reporting application shares the main
// listener (the test stack's case). A deployment that gives the report app a
// listener of its own would need that listener's base here.
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const signin = require("./console_signin.js");
const authnSignin = require("./authn_signin");
const fixtures = require("./oauth_fixtures");

const log = require("bunyan").createLogger({ name: "report_signin",
  level: process.env.STS_LOG_LEVEL || "info" });

// A desktop browser's User-Agent, as portal_signin.js sends: product mode's
// risk scoring refuses a first sign-in from an agent that reads as a bot.
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const CLIENT = "sts-report";
// The report scopes, beside the identity scopes the client declares; the
// token is audienced to `/report-api` by `resource`.
const SCOPE = "openid report:use report:admin";

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A P-256 DPoP key with the same shape console_signin.js's exposes, so the
// proxy signs the same way for every surface: `proof(method, url, token)` and
// `keepNonce(response)`.
function dpopKey() {
  log.debug("Entering dpopKey().");
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

// A Location against the service base, so a relative redirect resolves.
function fromLocation(base, location) {
  log.debug("Entering fromLocation().");
  log.debug("Leaving fromLocation().");
  return new URL(String(location || ""), base + "/").toString();
}

// A repeated parameter (resource) as the runtime sends it; URLSearchParams of
// an object would join an array into one value.
function formOf(fields) {
  log.debug("Entering formOf().");
  const form = new URLSearchParams();
  Object.keys(fields).forEach(function (name) {
    [].concat(fields[name]).forEach(function (one) {
      form.append(name, String(one));
    });
  });
  log.debug("Leaving formOf().");
  return form.toString();
}

/**
 * Signs the report person in and returns a DPoP-bound report token.
 *
 * @param {string} base - the realm's base URL (with any realm prefix)
 * @param {string} user - the person's username
 * @param {function} [log2] - a say(message) sink; defaults to the logger
 * @param {object} [options] - `password` (required), `consent`
 * @returns {Promise<object>} `{ get token, get refreshToken, key, refresh }`
 */
async function signInToReport(base, user, log2, options) {
  log.debug("Entering signInToReport().");
  const opts = options || {};
  const password = opts.password;
  assert.ok(password, "report_signin needs the report person's password");
  const say = typeof log2 === "function" ? log2 : function () {};
  const cookies = signin.jar();
  const key = dpopKey();
  const pkce = fixtures.pkce();
  const resource = base + "/report-api";
  const redirectUri = base + "/report/callback";
  const state = b64u(crypto.randomBytes(16));
  const nonce = b64u(crypto.randomBytes(16));
  // The body of the last refusal a hop answered (status >= 400), for the
  // diagnostic: a 400 at the authorization endpoint carries the OAuth error
  // (invalid_request / invalid_scope / unauthorized_client …) that says WHY,
  // which the assertion alone (status and Location) cannot.
  let lastRefusal = "";

  async function fetchKeeping(url) {
    log.debug("Entering fetchKeeping().");
    const r = await fetch(url, { redirect: "manual",
      headers: { "User-Agent": AGENT, cookie: cookies.header() } });
    // keep() reads the fetch Response's own headers.getSetCookie(); the jar
    // from console_signin.js takes the response itself, not a {setCookies}.
    cookies.keep(r);
    if (r.status >= 400) {
      // Read a clone so the caller still has the body if it wants it.
      lastRefusal = await r.clone().text().then(function (text) {
        return (r.status + " at " + url + ": " + String(text)).slice(0, 500);
      }, function () {
        return r.status + " at " + url;
      });
    }
    log.debug("Leaving fetchKeeping().");
    return r;
  }

  const params = { response_type: "code", client_id: CLIENT,
    redirect_uri: redirectUri, scope: SCOPE,
    code_challenge: pkce.challenge, code_challenge_method: "S256",
    resource: resource, state: state, nonce: nonce };

  // The realm's metadata decides pushed authorization and JARM, exactly as
  // portal_signin.js reads it.
  const meta = await fetch(base +
    "/.well-known/oauth-authorization-server",
    { headers: { "User-Agent": AGENT } })
    .then(function (r) {
      return r.status === 200 ? r.json() : {};
    }, function () {
      return {};
    });
  let authorizeUrl = base + "/oauth2/authorize?" + formOf(params);
  const modes = meta.response_modes_supported;
  if (Array.isArray(modes) && modes.indexOf("query") < 0 &&
      (modes.indexOf("jwt") >= 0 || modes.indexOf("query.jwt") >= 0)) {
    params.response_mode = modes.indexOf("jwt") >= 0 ? "jwt" : "query.jwt";
    authorizeUrl = base + "/oauth2/authorize?" + formOf(params);
  }
  if (meta.require_pushed_authorization_requests === true) {
    const parUrl = String(meta.pushed_authorization_request_endpoint ||
                          base + "/oauth2/par");
    let pushed = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const r = await fetch(parUrl, { method: "POST", headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": AGENT, dpop: key.proof("POST", parUrl, "") },
        body: formOf(params) });
      key.keepNonce(r);
      pushed = { status: r.status, json: await r.json().catch(function () {
        return {};
      }) };
      if (!(r.status === 400 && pushed.json.error === "use_dpop_nonce")) {
        break;
      }
    }
    assert.ok(pushed.status === 201 && pushed.json.request_uri,
      "pushing the report client's authorization request answered " +
      pushed.status + " " + JSON.stringify(pushed.json).slice(0, 300));
    authorizeUrl = base + "/oauth2/authorize?" + new URLSearchParams({
      client_id: CLIENT, request_uri: pushed.json.request_uri }).toString();
  }

  let at = await fetchKeeping(authorizeUrl);
  let location = at.headers.get("location") || "";
  const authn = (location.match(/[?&]authn=([^&]+)/) || [])[1];
  // The body of a refusal at a hop fetchKeeping did not make, for the
  // diagnostic: the sign-in and consent steps go through authn_signin (not
  // fetchKeeping), so without this a 400 there left `lastRefusal` empty and the
  // final assertion blamed the authorization endpoint for a refusal the
  // sign-in step answered (#1299: the admin-api cell changed `fuzzer`'s
  // password, so the sign-in answered STS-AUTHN-0054 and this said "the
  // authorization endpoint … answered 400").
  function noteStepRefusal(where, answer) {
    if (!answer || Number(answer.status) < 400) {
      return;
    }
    const detail = typeof answer.text === "string" && answer.text
      ? answer.text
      : JSON.stringify(answer.json || {});
    lastRefusal = (answer.status + " at " + where + ": " + String(detail))
      .slice(0, 500);
  }

  if (authn) {
    const signedIn = await authnSignin.signIn(base,
      fromLocation(base, location),
      { action: "login", username: user, password: password },
      { cookie: cookies.header() });
    cookies.keep(signedIn);
    noteStepRefusal("the sign-in step", signedIn);
    at = authnSignin.responseLike(signedIn);
    location = at.headers.get("location") || "";
  }

  let guard = 0;
  while (guard < 8 && !/\/report\/callback\?/.test(location)) {
    guard += 1;
    if ((at.status === 302 || at.status === 303) &&
        authnSignin.isConsent(location) && opts.consent !== false) {
      const answered = await authnSignin.consentFor(
        fromLocation(base, location), cookies.header());
      cookies.keep(answered);
      noteStepRefusal("the consent step", answered);
      at = authnSignin.responseLike(answered);
    } else if (at.status === 200) {
      break;
    } else if (at.status === 302 || at.status === 303) {
      at = await fetchKeeping(fromLocation(base, location));
    } else {
      break;
    }
    location = at.headers.get("location") || "";
  }

  const back = new URL(fromLocation(base, location));
  if (back.searchParams.get("response")) {
    const parts = String(back.searchParams.get("response")).split(".");
    let jarm = {};
    try {
      jarm = JSON.parse(Buffer.from(parts[1] || "", "base64url")
        .toString("utf8") || "{}");
    } catch (e) {
      log.debug("Caught in signInToReport() reading JARM: " +
                ((e && e.message) || e));
      jarm = {};
    }
    ["code", "state", "error", "error_description"].forEach(function (name) {
      if (jarm[name] !== undefined) {
        back.searchParams.set(name, String(jarm[name]));
      }
    });
  }
  const code = back.searchParams.get("code");
  assert.ok(/\/report\/callback$/.test(back.pathname) && code &&
            back.searchParams.get("state") === state,
    "the authorization endpoint should answer the report callback with a " +
    "code and the state; it answered " + at.status + " to \"" + location +
    "\"" + (lastRefusal ? " [last refusal: " + lastRefusal + "]" : ""));

  const tokenUrl = base + "/oauth2/token";
  async function tokenRequest(form) {
    log.debug("Entering tokenRequest().");
    let answer = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const r = await fetch(tokenUrl, { method: "POST", headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": AGENT, dpop: key.proof("POST", tokenUrl, "") },
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

  const issued = await tokenRequest({ grant_type: "authorization_code",
    code: code, redirect_uri: redirectUri, client_id: CLIENT,
    code_verifier: pkce.verifier, resource: resource });
  assert.ok(issued.status === 200 && issued.json.access_token &&
            /^dpop$/i.test(String(issued.json.token_type || "")),
    "the report code should redeem for a DPoP-bound access token; the token " +
    "endpoint answered " + issued.status + " " +
    JSON.stringify(issued.json).slice(0, 300));
  let token = issued.json.access_token;
  let refreshToken = issued.json.refresh_token || "";

  async function refresh() {
    log.debug("Entering refresh().");
    if (!refreshToken) {
      log.debug("Leaving refresh(). No refresh token.");
      return token;
    }
    const again = await tokenRequest({ grant_type: "refresh_token",
      refresh_token: refreshToken, client_id: CLIENT, resource: resource });
    if (again.status === 200 && again.json.access_token) {
      token = again.json.access_token;
      refreshToken = again.json.refresh_token || refreshToken;
    }
    log.debug("Leaving refresh().");
    return token;
  }

  say("[report] signed in as " + user + " as " + CLIENT + ": a DPoP-bound " +
      "token for " + resource + ".");
  log.debug("Leaving signInToReport().");
  return {
    user: user,
    get token() {
      return token;
    },
    get refreshToken() {
      return refreshToken;
    },
    key: key,
    refresh: refresh
  };
}

module.exports = { signInToReport: signInToReport };
