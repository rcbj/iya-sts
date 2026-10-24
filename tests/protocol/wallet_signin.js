// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: wallet_signin.js
//
// ===========================================================================
// SIGNING IN WITH A WALLET, OVER `/authn-api/wallet`, AS ITS PAGES DO
// (#574, 2026-10-12).
//
// **THIS IS A HELPER AND NOT A JOB**, and it is OURS (`MANIFEST.js`'s
// LOCAL_HELPERS), beside `authn_signin.js`, which writes the sign-in
// screen's protocol down once the same way.
//
// ---------------------------------------------------------------------------
// WHAT CHANGED AT #574, AND SO WHAT THIS DOES.
//
// `GET /authn/wallet?authn=<id>` made the transaction, set the binding
// cookie and answered a 303 to the wait page; the wait page was a server
// page that finished the sign-in when asked again (with the wallet's
// `response_code` on a same-device return), and the Digital Credentials
// API answer was a form POST to `/authn/wallet/dc-api`. Since #574 both
// pages are routes of the static sign-in surface:
//
//   GET  /authn/wallet?authn=<id>            the shell (the arrival cookie)
//   GET  /authn-api/wallet?authn=<id>        { view, csrf } — creates nothing
//   POST /authn-api/wallet                   the start: the binding cookie,
//                                            { next: 'wait', state, go }
//   GET  /authn-api/wallet/<state>           the wait page's view
//   POST /authn-api/wallet/<state>/status    the collection: { next: 'wait' }
//                                            or the sign-in's answer
//   POST /authn-api/wallet/<state>/dc-api    the Digital Credentials API's
//
// every POST JSON, with this service's Origin and the X-CSRF-Token the
// view answered. A JOB'S BROWSER is its own jar: anything with `header()`
// (the cookie header) and `take(response)` (keeps a fetch response's
// cookies), which every job here already has; the token is kept on it as
// `csrf`.
//
// An act's answer is read as the page it replaced was read (`formLike()`):
// one naming an address — `redirect`, `mfa`, a start's wait page — is the
// 303 it was, `location` absolute on the base's origin.
// ===========================================================================

const log = require("bunyan").createLogger({ name: "wallet_signin",
  level: process.env.LOG_LEVEL || "info" });

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
 * One request in a job's browser.
 *
 * @param {object|null} who - the jar, or null for a party with no cookies
 * @param {string} method - the method
 * @param {string} url - the absolute URL
 * @param {object} [opts] - `json`, `headers`
 * @returns {Promise<object>} `{ status, headers, text, json, setCookie }`
 */
async function call(who, method, url, opts) {
  // A wallet's transaction state is a bearer capability: not logged.
  log.debug("Entering call(). " + method + " " +
            String(url).replace(/\/wallet\/[^/?]+/, "/wallet/(state)")
              .replace(/\?.*$/, ""));
  const o = opts || {};
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  let body;
  if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header && who.header()) {
    headers.cookie = who.header();
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  const setCookie = who && who.take ? who.take(r) :
    (typeof r.headers.getSetCookie === "function" ?
      r.headers.getSetCookie() : []);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // A page (a shell), not JSON: the caller reads the text.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, headers: r.headers, text: text, json: json,
           setCookie: setCookie || [] };
}

/**
 * An act's answer read as the page it replaced: an address it names is the
 * 303 it was.
 *
 * @param {object} b - `baseOf()`'s answer
 * @param {object} r - `call()`'s answer
 * @returns {object} the answer, with `status`, `location` and `answer`
 */
function formLike(b, r) {
  log.debug("Entering formLike().");
  const j = r.json || {};
  const where = j.location || (j.ok && j.go ? b.base + j.go : "");
  log.debug("Leaving formLike().");
  if (j.ok && where) {
    return Object.assign({}, r, { status: 303, answer: r,
      location: new URL(where, b.origin).toString() });
  }
  return Object.assign({}, r, { location: "", answer: r });
}

/**
 * Sends an act, bound as the page binds it.
 *
 * @param {string} base - the service's base
 * @param {object|null} who - the jar
 * @param {string} path - the operation's path under the base
 * @param {object} body - the JSON
 * @param {object} [opts] - `origin` (null for none), `csrf`
 * @returns {Promise<object>} the answer, `formLike()`'s reading
 */
async function act(base, who, path, body, opts) {
  log.debug("Entering act().");
  const o = opts || {};
  const b = baseOf(base);
  const headers = {};
  if (o.origin !== null) {
    headers.origin = o.origin || b.origin;
  }
  const csrf = o.csrf !== undefined ? o.csrf : (who && who.csrf) || "";
  if (csrf) {
    headers["x-csrf-token"] = csrf;
  }
  const r = await call(who, "POST", b.base + path,
                       { json: body, headers: headers });
  log.debug("Leaving act(). " + r.status);
  return formLike(b, r);
}

/**
 * The start page as it is opened: its shell (the arrival cookie) and its
 * view (the CSRF token, kept on the jar). Creates nothing.
 *
 * @param {string} base - the service's base
 * @param {object} who - the jar
 * @param {object} query - `authn` or `mfa`, and `siop`, `enrol`
 * @returns {Promise<object>} `{ shell, opened }`
 */
async function open(base, who, query) {
  log.debug("Entering open().");
  const b = baseOf(base);
  const q = new URLSearchParams(query || {}).toString();
  const shell = await call(who, "GET", b.base + "/authn/wallet?" + q);
  const opened = await call(who, "GET", b.base + "/authn-api/wallet?" + q);
  if (opened.json && opened.json.csrf) {
    who.csrf = opened.json.csrf;
  }
  log.debug("Leaving open(). " + opened.status);
  return { shell: shell, opened: opened };
}

/**
 * Starts a wallet sign-in as the start page does, and reads the wait
 * page's view.
 *
 * @param {string} base - the service's base
 * @param {object} who - the jar
 * @param {object} query - `authn` or `mfa`, and `siop`, `enrol`
 * @returns {Promise<object>} `{ door, opened, state, waitUrl, waiting,
 *   view, walletUrl, requestUri, authn, mfa, enrol }` — `door` read as the
 *   303 the start used to answer, or the refusal at its status
 */
async function start(base, who, query) {
  log.debug("Entering start().");
  const b = baseOf(base);
  const first = await open(base, who, query);
  if (first.opened.status !== 200) {
    log.debug("Leaving start(). The start view refused.");
    return { door: formLike(b, first.opened), opened: first.opened,
             shell: first.shell };
  }
  const door = await act(base, who, "/authn-api/wallet", query || {});
  const out = { door: door, opened: first.opened, shell: first.shell };
  if (door.status !== 303) {
    log.debug("Leaving start(). The start refused.");
    return out;
  }
  out.state = door.answer.json.state;
  out.waitUrl = door.location;
  const u = new URL(out.waitUrl);
  out.authn = u.searchParams.get("authn") || "";
  out.mfa = u.searchParams.get("mfa") || "";
  out.enrol = u.searchParams.get("enrol") || "";
  out.waiting = await view(base, who, out.state);
  out.view = (out.waiting.json && out.waiting.json.view) || null;
  out.walletUrl = out.view && out.view.sameDevice
    ? new URL(out.view.sameDevice) : null;
  out.requestUri = out.walletUrl
    ? out.walletUrl.searchParams.get("request_uri") || "" : "";
  log.debug("Leaving start().");
  return out;
}

/**
 * The wait page's view.
 *
 * @param {string} base - the service's base
 * @param {object|null} who - the jar
 * @param {string} state - the transaction
 * @returns {Promise<object>} `call()`'s answer
 */
async function view(base, who, state) {
  log.debug("Entering view().");
  const b = baseOf(base);
  const r = await call(who, "GET", b.base + "/authn-api/wallet/" +
                       encodeURIComponent(state));
  log.debug("Leaving view(). " + r.status);
  return r;
}

/**
 * The transaction a wait-page address names — a start's, or the one a
 * wallet sends the person back to with its `response_code`.
 *
 * @param {string} url - the wait page's address
 * @returns {object} `{ state, authn, mfa, enrol, responseCode }`
 */
function fromWaitUrl(url) {
  log.debug("Entering fromWaitUrl().");
  const u = new URL(String(url), "http://x");
  log.debug("Leaving fromWaitUrl().");
  return { state: u.searchParams.get("state") || "",
           authn: u.searchParams.get("authn") || "",
           mfa: u.searchParams.get("mfa") || "",
           enrol: u.searchParams.get("enrol") || "",
           responseCode: u.searchParams.has("response_code")
             ? u.searchParams.get("response_code") : undefined };
}

/**
 * The ids an act on a transaction names beside it.
 *
 * @param {object} s - `start()`'s or `fromWaitUrl()`'s answer
 * @returns {object} the body's members
 */
function idsOf(s) {
  log.debug("Entering idsOf().");
  const out = { authn: s.authn };
  if (s.mfa) {
    out.mfa = s.mfa;
  }
  if (s.enrol) {
    out.enrol = "1";
  }
  log.debug("Leaving idsOf().");
  return out;
}

/**
 * Collects the sign-in as the wait page does (`POST …/status`): `wait`
 * until the wallet has answered, then the sign-in's answer. A wait-page
 * address the wallet sent the person back to carries its `response_code`;
 * `opts.responseCode` overrides it.
 *
 * @param {string} base - the service's base
 * @param {object|null} who - the jar
 * @param {object|string} s - `start()`'s answer, or a wait-page address
 * @param {object} [opts] - `responseCode`, `origin`, `csrf`
 * @returns {Promise<object>} `formLike()`'s reading
 */
async function collect(base, who, s, opts) {
  log.debug("Entering collect().");
  const o = opts || {};
  const t = typeof s === "string" ? fromWaitUrl(s) : s;
  const body = idsOf(t);
  const code = o.responseCode !== undefined ? o.responseCode
                                             : t.responseCode;
  if (code !== undefined) {
    body.response_code = code;
  }
  const r = await act(base, who, "/authn-api/wallet/" +
                      encodeURIComponent(t.state) + "/status", body, o);
  log.debug("Leaving collect(). " + r.status);
  return r;
}

/**
 * Sends a Digital Credentials API answer as the wait page does.
 *
 * @param {string} base - the service's base
 * @param {object|null} who - the jar
 * @param {object} s - `start()`'s answer
 * @param {string} response - the DigitalCredential, as JSON text
 * @param {object} [opts] - `origin`, `csrf`
 * @returns {Promise<object>} `formLike()`'s reading
 */
async function answerDcApi(base, who, s, response, opts) {
  log.debug("Entering answerDcApi().");
  const r = await act(base, who, "/authn-api/wallet/" +
                      encodeURIComponent(s.state) + "/dc-api",
                      Object.assign(idsOf(s), { response: response }),
                      opts);
  log.debug("Leaving answerDcApi(). " + r.status);
  return r;
}

/**
 * A CSRF token for a jar whose session changed under it — a sign-in
 * replaces the arrival session, and the token is the session's: the start
 * view for any pending sign-in answers the token of the cookie the jar holds
 * now, even where it refuses the start.
 *
 * @param {string} base - the service's base
 * @param {object} who - the jar
 * @param {string} authnId - a pending sign-in's id
 * @returns {Promise<string>} the token
 */
async function refreshCsrf(base, who, authnId) {
  log.debug("Entering refreshCsrf().");
  const opened = (await open(base, who, { authn: authnId })).opened;
  log.debug("Leaving refreshCsrf(). " + opened.status);
  return (opened.json && opened.json.csrf) || "";
}

// ---------------------------------------------------------------------------
// THE WALLET'S ANSWER UNDER THE REQUEST'S RESPONSE MODE (2026-10-12). A
// sign-in asks for `direct_post.jwt` by default (`oid4vp.signInResponseMode`,
// OpenID4VC HAIP 1.0 section 5.1), and a HAIP wallet then sends ONE form
// field, `response`: a JWE (OpenID4VP 1.0 section 8.3) to the P-256
// `ECDH-ES` key the request offers in `client_metadata.jwks`, A128GCM,
// whose plaintext is the answer's other fields. Written here with node's
// crypto rather than taken from the service — RFC 7518 section 4.6's direct
// key agreement and Concat KDF — so the service's decryption is held to an
// encryption it did not write. `direct_post` is the fields as they are.
// ---------------------------------------------------------------------------

/**
 * ECDH-ES with A128GCM, compact serialisation (RFC 7516, RFC 7518 4.6).
 *
 * @param {string} plaintext - the payload
 * @param {object} jwk - the recipient's public P-256 JWK
 * @returns {string} the compact JWE
 */
function encryptEcdhEs(plaintext, jwk) {
  log.debug("Entering encryptEcdhEs().");
  const crypto = require("crypto");
  const ephemeral = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const epk = ephemeral.publicKey.export({ format: "jwk" });
  const z = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: crypto.createPublicKey({ key: { kty: "EC", crv: jwk.crv,
                                               x: jwk.x, y: jwk.y },
                                        format: "jwk" }) });
  const enc = "A128GCM";
  const lenPrefixed = function (buf) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length);
    return Buffer.concat([len, buf]);
  };
  const keyBits = Buffer.alloc(4);
  keyBits.writeUInt32BE(128);
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1);
  const otherInfo = Buffer.concat([lenPrefixed(Buffer.from(enc)),
                                   lenPrefixed(Buffer.alloc(0)),
                                   lenPrefixed(Buffer.alloc(0)), keyBits]);
  const cek = crypto.createHash("sha256")
    .update(Buffer.concat([counter, z, otherInfo])).digest().subarray(0, 16);
  const header = { alg: "ECDH-ES", enc: enc,
                   epk: { kty: "EC", crv: epk.crv, x: epk.x, y: epk.y } };
  if (jwk.kid) {
    header.kid = jwk.kid;
  }
  const protectedB64 = Buffer.from(JSON.stringify(header))
    .toString("base64url");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-128-gcm", cek, iv);
  cipher.setAAD(Buffer.from(protectedB64, "ascii"));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")),
                           cipher.final()]);
  const tag = cipher.getAuthTag();
  log.debug("Leaving encryptEcdhEs().");
  return [protectedB64, "", iv.toString("base64url"),
          ct.toString("base64url"), tag.toString("base64url")].join(".");
}

/**
 * What a wallet posts to the Response URI for `fields` under the request's
 * response mode: the fields for `direct_post`, `{ response }` for
 * `direct_post.jwt` (`opts.plain` sends the fields whatever was asked).
 * A `vp_token` given as JSON text is the object it encodes inside the JWE.
 *
 * @param {object} requestObject - the decoded Request Object
 * @param {object} fields - the answer's fields, `state` among them
 * @param {object} [opts] - `plain`
 * @returns {object} the form
 */
function answerForm(requestObject, fields, opts) {
  log.debug("Entering answerForm().");
  const o = opts || {};
  const ro = requestObject || {};
  if (ro.response_mode !== "direct_post.jwt" || o.plain) {
    log.debug("Leaving answerForm(). In the clear.");
    return fields;
  }
  const payload = Object.assign({}, fields);
  delete payload.state;
  if (typeof payload.vp_token === "string") {
    try {
      payload.vp_token = JSON.parse(payload.vp_token);
    } catch (e) {
      log.debug("Caught in answerForm(): " + ((e && e.message) || e));
      // A malformed vp_token sent on purpose travels as it is.
    }
  }
  const key = (((ro.client_metadata || {}).jwks || {}).keys || [])
    .find(function (k) {
      return k.alg === "ECDH-ES" && k.crv === "P-256";
    });
  if (!key) {
    log.debug("Leaving answerForm(). No ECDH-ES key was offered.");
    throw new Error("the request asked for direct_post.jwt and offered no " +
                    "P-256 ECDH-ES key");
  }
  log.debug("Leaving answerForm(). Encrypted.");
  return { response: encryptEcdhEs(JSON.stringify(payload), key) };
}

module.exports = {
  encryptEcdhEs: encryptEcdhEs,
  answerForm: answerForm,
  baseOf: baseOf,
  call: call,
  act: act,
  open: open,
  start: start,
  view: view,
  collect: collect,
  answerDcApi: answerDcApi,
  fromWaitUrl: fromWaitUrl,
  refreshCsrf: refreshCsrf,
  formLike: formLike
};
