// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/web_round_trip.js
// ===========================================================================
// THE RENDERER ROUND TRIP, FOR EVERY STATIC SURFACE (#570, 2026-10-12).
//
// A static surface draws a page in the browser from what its API answered,
// with the same `web_` renderer this process can run. Two things can go
// wrong between the two, and each has cost something once:
//
//   * THE VIEW DOES NOT SURVIVE THE WIRE: a Date, a Map, an `undefined`
//     member, a function — something the renderer read in this process that
//     JSON drops or changes. So the view goes through
//     `JSON.parse(JSON.stringify())` before the browser's renderer sees it,
//     exactly as a `fetch()` would hand it over.
//   * THE BUNDLE IS NOT THE SOURCE: esbuild's output of the same modules,
//     run where there is no `require`, `process`, `module` or `Buffer` — a
//     stand-in for a browser — has to draw the same bytes.
//
// `tests/console_web_bundle.js` grew both checks for the console (#446) and
// the portal's jobs the second (#568). This is the one copy, which they and
// every later surface use: `loadBundle()` runs a renderers-only bundle in a
// sandbox, and `roundTrip()` compares one page drawn by this process from the
// view with the same page drawn by the bundle from the view after the wire.
// `tests/tools/web_surfaces.js` is the registry a new surface adds itself to,
// and `tests/web_surfaces.js` runs it.
//
// A LIBRARY FOR TESTS: no test of its own. It logs at `debug` as every
// module here does, through a bunyan logger of its own (it is called from
// inside the child processes those tests start, which have no other).
// ===========================================================================

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const log = require('bunyan').createLogger({ name: 'web_round_trip',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * Runs a renderers-only bundle in a context with no `require`, `process`,
 * `module` or `Buffer`, and answers its global.
 *
 * @param {string} file - the bundle's path
 * @param {string} globalName - the global its IIFE assigns (`StsConsole`)
 * @returns {{ value: any, code: string, problem: string }} the global (null
 *   where it could not be had), the bundle's text, and why not
 */
function loadBundle(file, globalName) {
  log.debug("Entering loadBundle(). " + file);
  let code = '';
  try {
    code = fs.readFileSync(file, 'utf8');
  } catch (e) {
    log.debug("Caught in loadBundle(): " + ((e && e.message) || e));
    log.debug("Leaving loadBundle(). Not built.");
    return { value: null, code: '',
             problem: 'not built: ' + String((e && e.message) || e) };
  }
  try {
    const sandbox = vm.createContext({});
    const value = vm.runInContext(code + '\n;' + globalName + ';', sandbox,
                                  { filename: path.basename(file) });
    log.debug("Leaving loadBundle().");
    return { value: value || null, code: code,
             problem: value ? '' : globalName + ' is not defined' };
  } catch (e) {
    // What a browser would have thrown loading it: the finding says so.
    log.debug("Caught in loadBundle(): " + ((e && e.message) || e));
    log.debug("Leaving loadBundle(). It did not run.");
    return { value: null, code: code,
             problem: String((e && e.message) || e) };
  }
}

/**
 * A view as a browser receives it: through JSON.
 *
 * @param {any} view - the view
 * @returns {any} the view after the wire
 */
function throughJson(view) {
  log.debug("Entering throughJson().");
  log.debug("Leaving throughJson().");
  return view === undefined ? undefined : JSON.parse(JSON.stringify(view));
}

/**
 * Where two strings first differ, with a little of each, for a finding.
 *
 * @param {string} a - one
 * @param {string} b - the other
 * @returns {string} '' where they are equal
 */
function firstDifference(a, b) {
  log.debug("Entering firstDifference().");
  if (a === b) {
    log.debug("Leaving firstDifference(). Equal.");
    return '';
  }
  const x = String(a);
  const y = String(b);
  let i = 0;
  while (i < x.length && i < y.length && x[i] === y[i]) {
    i += 1;
  }
  log.debug("Leaving firstDifference(). At " + i + ".");
  return 'at ' + i + ' of ' + x.length + '/' + y.length + ': ' +
    JSON.stringify(x.slice(Math.max(0, i - 40), i + 60)) + ' against ' +
    JSON.stringify(y.slice(Math.max(0, i - 40), i + 60));
}

/**
 * Draws one page both ways and compares the bytes.
 *
 * @param {object} one - `{ label, view, ctx, node, browser }`: `node` and
 *   `browser` are `(view, ctx) => html`, the first this process's renderer
 *   and the second the bundle's
 * @returns {{ ok: boolean, label: string, detail: string }} the finding
 */
function roundTrip(one) {
  log.debug("Entering roundTrip(). " + one.label);
  let mine = null;
  let theirs = null;
  try {
    mine = one.node(one.view, one.ctx);
    theirs = one.browser(throughJson(one.view), one.ctx);
  } catch (e) {
    // A renderer that throws is a finding, with its stack.
    log.debug("Caught in roundTrip(): " + ((e && e.message) || e));
    log.debug("Leaving roundTrip(). It threw.");
    return { ok: false, label: one.label,
             detail: 'threw: ' + String((e && e.stack) || e).slice(0, 600) };
  }
  const ok = typeof mine === 'string' && mine.length > 0 && mine === theirs;
  log.debug("Leaving roundTrip(). " + (ok ? 'Equal.' : 'Different.'));
  return { ok: ok, label: one.label,
           detail: ok ? String(mine.length) + ' characters'
                      : firstDifference(mine, theirs) };
}

module.exports = { loadBundle: loadBundle, throughJson: throughJson,
                   firstDifference: firstDifference, roundTrip: roundTrip };
