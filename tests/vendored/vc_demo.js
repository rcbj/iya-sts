// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: vc_demo.js
//
// ===========================================================================
// THE OPENID4VC DEMONSTRATION'S PAGES OVER `/vc-demo-api`, AS THEIR RUNTIME
// DRIVES THEM (#582, 2026-10-12).
//
// **THIS IS A HELPER AND NOT A JOB**, and it is OURS (`MANIFEST.js`'s
// LOCAL_HELPERS), beside `wallet_signin.js`.
//
// `GET /issuer/offer` and `GET /oid4vp/start` made an offer or a request
// and answered a 302 to the wallet, or a page drawing the QR code; the
// closing page `/oid4vp/done` was a page this service drew. Since #582 the
// five pages are a static surface's shells, drawn in the browser from
// `/vc-demo-api`:
//
//   GET  /issuer/offer?…              the shell (the arrival cookie);
//                                     creates nothing
//   GET  /vc-demo-api/offer?…         { view, csrf }, the query checked
//   POST /vc-demo-api/offer           the act: { location } (the wallet, on
//                                     this device) or { view } (the QR page:
//                                     offerUri, walletUrl, txCode)
//   …and the same for /oid4vp/start at /vc-demo-api/start (the QR page's
//   view: requestUri, walletUrl, state), and
//   GET  /vc-demo-api/done?state=…    the closing page's view
//
// every POST JSON, with this service's Origin and the X-CSRF-Token the view
// answered. A JOB'S BROWSER is a jar — a plain object, cookie name to value
// — which this reads and writes in place; `{}` for a fresh one.
//
// An act's answer is read as the page it replaced was read: a `location`
// is the 302 it was (`status` 302, `location` the same bytes the 302
// named); anything else keeps its status, with `view` and `json`.
// ===========================================================================

const log = require("bunyan").createLogger({ name: "vc_demo",
  level: process.env.LOG_LEVEL || "info" });

/**
 * One request in a job's browser, keeping the jar.
 *
 * @param {object} jar - cookie name to value, read and written in place
 * @param {string} method - the method
 * @param {string} url - the absolute URL
 * @param {object} [opts] - `json`, `headers`
 * @returns {Promise<object>} `{ status, headers, text, json, setCookie }`
 */
async function call(jar, method, url, opts) {
  // A transaction's state and an offer's code are bearer values: the query
  // is not logged.
  log.debug("Entering call(). " + method + " " +
            String(url).replace(/\?.*$/, ""));
  const o = opts || {};
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  let body;
  if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  const cookie = Object.keys(jar || {}).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
  if (cookie) {
    headers.cookie = cookie;
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  const setCookie = typeof r.headers.getSetCookie === "function"
    ? r.headers.getSetCookie() : [];
  setCookie.forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0 || !jar) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Max-Age=0/i.test(String(line))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // A page, not JSON: `text` is what the caller reads.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, headers: r.headers, text: text, json: json,
           setCookie: setCookie };
}

/**
 * Opens a start page as its runtime does, and sends its act.
 *
 * @param {object} jar - the browser's jar
 * @param {string} base - the service's base, a realm's prefix included
 * @param {string} page - `/issuer/offer` or `/oid4vp/start`
 * @param {string} op - its API path, `/vc-demo-api/offer` or `/start`
 * @param {object} query - the page's query, name to value
 * @returns {Promise<object>} `{ status, location, view, json, text, shell }`
 */
async function startPage(jar, base, page, op, query) {
  log.debug("Entering startPage(). " + page);
  const b = String(base || "").replace(/\/+$/, "");
  const qs = new URLSearchParams(query || {}).toString();
  const q = qs ? "?" + qs : "";
  const shell = await call(jar, "GET", b + page + q,
                           { headers: { accept: "text/html" } });
  const opened = await call(jar, "GET", b + op + q);
  if (opened.status !== 200 || !opened.json || !opened.json.ok) {
    log.debug("Leaving startPage(). The view was refused.");
    return { status: opened.status, location: "", view: null,
             json: opened.json, text: opened.text, shell: shell };
  }
  const body = {};
  Object.keys(query || {}).forEach(function (name) {
    body[name] = String(query[name]);
  });
  const r = await call(jar, "POST", b + op, { json: body,
    headers: { origin: new URL(b).origin,
               "x-csrf-token": String(opened.json.csrf || "") } });
  const j = r.json || {};
  const goes = r.status === 200 && j.ok && typeof j.location === "string";
  log.debug("Leaving startPage(). " + r.status);
  return { status: goes ? 302 : r.status, apiStatus: r.status,
           location: goes ? j.location : "", view: j.view || null,
           json: r.json, text: r.text, shell: shell };
}

/**
 * The demonstration issuer's offer page, `/issuer/offer?<query>`.
 *
 * @param {object} jar - the browser's jar
 * @param {string} base - the service's base
 * @param {object} query - `mode`, `by`, `wallet`,
 *   `credential_configuration_ids`
 * @returns {Promise<object>} the answer, read as the page's
 */
function offer(jar, base, query) {
  log.debug("Entering offer().");
  log.debug("Leaving offer().");
  return startPage(jar, base, "/issuer/offer", "/vc-demo-api/offer", query);
}

/**
 * The bar door's start page, `/oid4vp/start?<query>`.
 *
 * @param {object} jar - the browser's jar
 * @param {string} base - the service's base
 * @param {object} query - `format`, `by`, `mode`, `client_id_prefix`, …
 * @returns {Promise<object>} the answer, read as the page's
 */
function start(jar, base, query) {
  log.debug("Entering start().");
  log.debug("Leaving start().");
  return startPage(jar, base, "/oid4vp/start", "/vc-demo-api/start", query);
}

/**
 * The closing page's view for a state.
 *
 * @param {object} jar - the browser's jar
 * @param {string} base - the service's base
 * @param {string} state - the request's state
 * @returns {Promise<object>} `{ status, view, json }`
 */
async function done(jar, base, state) {
  log.debug("Entering done().");
  const r = await call(jar, "GET", String(base || "").replace(/\/+$/, "") +
                       "/vc-demo-api/done?state=" +
                       encodeURIComponent(String(state || "")));
  log.debug("Leaving done(). " + r.status);
  return { status: r.status, view: (r.json && r.json.view) || null,
           json: r.json };
}

module.exports = {
  offer: offer,
  start: start,
  done: done,
  call: call
};
