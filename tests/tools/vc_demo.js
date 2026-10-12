// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/vc_demo.js
//
// ===========================================================================
// THE OPENID4VC DEMONSTRATION'S START PAGES OVER `/vc-demo-api`, FOR AN
// IN-PROCESS TEST (#582).
//
// `GET /issuer/offer` and `GET /oid4vp/start` made an offer or a request
// and answered a 302 to the wallet, or a page with the QR code. Since #582
// they are a static surface's shells: the shell's GET mints the arrival
// cookie and creates nothing, the view answers the CSRF token, and the act
// is `POST /vc-demo-api/offer` or `/start`, answering `location` (the
// address the 302 named) or the QR page's `view`. `offer()` and `start()`
// do all three, through `authn_screen.js`'s `call()` with the test's jar,
// and answer what a test reads:
//
//   { status, location, view, json, shell, opened }
//
// with `status` 302 and `location` where the act named the wallet — read
// as the 302 the page answered — and the API's status otherwise.
// ===========================================================================

const screen = require('./authn_screen');
const log = require('bunyan').createLogger({ name: 'vc_demo',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * A query object as a query string, '' for none.
 *
 * @param {object} query - name → value
 * @returns {string} `?…` or ''
 */
function qs(query) {
  log.debug("Entering qs().");
  const text = new URLSearchParams(query || {}).toString();
  log.debug("Leaving qs().");
  return text ? '?' + text : '';
}

/**
 * Opens a start page as its runtime does, and sends its act.
 *
 * @param {object} o - `port`, `jar`, `ca`, `prefix` (a realm's, '' for the
 *   default), `query`; `origin` to send another
 * @param {string} page - `/issuer/offer` or `/oid4vp/start`
 * @param {string} op - the API's path for it, `/vc-demo-api/offer` or
 *   `/start`
 * @returns {Promise<object>} the answer, read as the page's
 */
async function startPage(o, page, op) {
  log.debug("Entering startPage(). " + page);
  const prefix = o.prefix || '';
  const jar = o.jar || {};
  const shell = await screen.call({ port: o.port, ca: o.ca, jar: jar,
    method: 'GET', path: prefix + page + qs(o.query) });
  const opened = await screen.call({ port: o.port, ca: o.ca, jar: jar,
    method: 'GET', path: prefix + op + qs(o.query),
    headers: { accept: 'application/json' } });
  if (opened.status !== 200 || !opened.json || !opened.json.ok) {
    log.debug("Leaving startPage(). The view was refused.");
    return { status: opened.status, location: '', view: null,
             json: opened.json, shell: shell, opened: opened };
  }
  const body = {};
  Object.keys(o.query || {}).forEach(function (name) {
    body[name] = String(o.query[name]);
  });
  const headers = { accept: 'application/json',
                    'content-type': 'application/json',
                    origin: o.origin ||
                      (o.ca ? 'https' : 'http') + '://127.0.0.1:' + o.port,
                    'x-csrf-token': String(opened.json.csrf || '') };
  const r = await screen.call({ port: o.port, ca: o.ca, jar: jar,
    method: 'POST', path: prefix + op, headers: headers,
    body: JSON.stringify(body) });
  const j = r.json || {};
  const goes = r.status === 200 && j.ok && typeof j.location === 'string';
  log.debug("Leaving startPage(). " + r.status);
  return { status: goes ? 302 : r.status, apiStatus: r.status,
           location: goes ? j.location : '',
           headers: goes ? { location: j.location } : r.headers,
           view: j.view || null, json: r.json, text: r.text,
           shell: shell, opened: opened };
}

/**
 * The demonstration issuer's offer: `/issuer/offer` with `o.query`.
 *
 * @param {object} o - see `startPage()`
 * @returns {Promise<object>} the answer
 */
function offer(o) {
  log.debug("Entering offer().");
  log.debug("Leaving offer().");
  return startPage(o, '/issuer/offer', '/vc-demo-api/offer');
}

/**
 * The bar door's start: `/oid4vp/start` with `o.query`.
 *
 * @param {object} o - see `startPage()`
 * @returns {Promise<object>} the answer
 */
function start(o) {
  log.debug("Entering start().");
  log.debug("Leaving start().");
  return startPage(o, '/oid4vp/start', '/vc-demo-api/start');
}

/**
 * The closing page's view for a state.
 *
 * @param {object} o - `port`, `jar`, `ca`, `prefix`, `state`
 * @returns {Promise<object>} `{ status, json, view }`
 */
async function done(o) {
  log.debug("Entering done().");
  const r = await screen.call({ port: o.port, ca: o.ca, jar: o.jar || {},
    method: 'GET', path: (o.prefix || '') + '/vc-demo-api/done?state=' +
      encodeURIComponent(String(o.state || '')),
    headers: { accept: 'application/json' } });
  log.debug("Leaving done(). " + r.status);
  return { status: r.status, json: r.json,
           view: (r.json && r.json.view) || null };
}

module.exports = {
  offer: offer,
  start: start,
  done: done,
  startPage: startPage
};
