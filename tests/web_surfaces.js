// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/web_surfaces.js
// ===========================================================================
// EVERY STATIC SURFACE IS BUILT, RUNS WHERE A BROWSER DOES, AND DRAWS WHAT
// THIS PROCESS DRAWS (#570, 2026-10-12).
//
// Reads `tests/tools/web_surfaces.js`, the table every static surface adds
// its row to, and for each row asks:
//
//   A. THE BUILD: the renderers' bundle and the runtime were written, the
//      runtime's `.br` and `.gz` beside it, and `build-typescript.sh` has a
//      `bundle_surface` line naming the row's page table, bundle and runtime
//      — so a surface that is in the table and not in the build, or built
//      under another name, fails here rather than serving a placeholder.
//   B. THE BUNDLE runs with no `require`, `process`, `module` or `Buffer`,
//      calls no `require()` of its own, and answers a page table whose every
//      row has a path and a renderer, and a `render(path, view, ctx)`.
//   C. THE ROUND TRIP: every case a row lists, drawn by the bundle from its
//      view after `JSON.parse(JSON.stringify())`, is to the byte what this
//      process's compiled page module draws from the view itself
//      (`tests/tools/web_round_trip.js`). A row whose pages need the whole
//      stack and a person names the test that holds them instead (`heldBy`),
//      and that test must exist.
//   D. THE HARNESS ITSELF finds what it exists to find: a view member JSON
//      changes, and a renderer that throws.
//
// The bundles are written by an image build only (#50), so this runs in the
// tests image (`./docker-npm-test.sh`), as every in-process test does.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');
const harness = require('./tools/web_round_trip');
const SURFACES = require('./tools/web_surfaces');

const log = bunyan.createLogger({ name: 'web_surfaces',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * Says whether a file exists and has something in it.
 *
 * @param {string} rel - its path under the root
 * @returns {boolean} whether it does
 */
function built(rel) {
  log.debug("Entering built(). " + rel);
  let size = 0;
  try {
    size = fs.statSync(path.join(ROOT, rel)).size;
  } catch (e) {
    log.debug("Caught in built(): " + ((e && e.message) || e));
    size = 0;
  }
  log.debug("Leaving built(). " + size);
  return size > 0;
}

/**
 * Runs the checks.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const script = fs.readFileSync(path.join(ROOT, 'build-typescript.sh'),
                                 'utf8');
  // Each `bundle_surface` call, joined across its continuation lines.
  const calls = script.replace(/\\\n\s*/g, ' ').split('\n')
    .filter(function (line) {
      return /^bundle_surface\s/.test(line);
    });
  // --- D. the harness itself ---------------------------------------------
  // What the round trip exists to catch, caught: a renderer that reads a
  // member JSON changes (a Date) draws something else after the wire, and
  // one that throws is a finding with its reason, not a crash.
  const draw = function (view) {
    return '<p>' + (view.when instanceof Date ? 'a date' : 'text') + ' ' +
      String(view.n) + '</p>';
  };
  const same = harness.roundTrip({ label: 'plain', view: { n: 1 }, ctx: {},
                                   node: draw, browser: draw });
  const lost = harness.roundTrip({ label: 'a Date', ctx: {},
    view: { n: 1, when: new Date(0) }, node: draw, browser: draw });
  const threw = harness.roundTrip({ label: 'throws', view: {}, ctx: {},
    node: draw, browser: function () {
      throw new Error('no such member');
    } });
  t.check(same.ok && !lost.ok && /at 3 /.test(lost.detail) && !threw.ok &&
          /no such member/.test(threw.detail),
          'D1. the harness passes a view that survives the wire and finds ' +
          'one that does not, and a renderer that throws',
          JSON.stringify([same, lost, threw]).slice(0, 600));
  t.check(SURFACES.length >= 2, 'the table lists the surfaces',
          SURFACES.map(function (one) {
            return one.name;
          }).join(', '));
  for (const row of SURFACES) {
    t.log.info('=== ' + row.name + ' ===');
    // --- A. the build -------------------------------------------------------
    const named = calls.filter(function (line) {
      return line.indexOf(' ' + row.pages + ' ') > 0 &&
        line.indexOf(' ' + row.global + ' ') > 0 &&
        line.indexOf(' ' + row.bundle + ' ') > 0 &&
        / (\S+)$/.exec(line.trim())[1] === row.runtime;
    });
    t.check(named.length === 1,
            'A1. build-typescript.sh bundles ' + row.name + ' as the table ' +
            'says', calls.join(' | '));
    t.check(built(row.bundle) && built(row.runtime),
            'A2. the image build wrote ' + row.bundle + ' and ' + row.runtime);
    t.check(built(row.runtime + '.br') && built(row.runtime + '.gz'),
            'A3. and the runtime\'s brotli and gzip beside it');
    // --- B. the bundle --------------------------------------------------
    const loaded = harness.loadBundle(path.join(ROOT, row.bundle),
                                      row.global);
    const pages = loaded.value && loaded.value.PAGES;
    const rows = Array.isArray(pages) ? pages : [];
    t.check(!!loaded.value && rows.length > 0 &&
            typeof loaded.value.render === 'function',
            'B1. ' + row.bundle + ' runs with no require, process, module ' +
            'or Buffer, and answers a page table', loaded.problem);
    const bad = rows.filter(function (one) {
      return !one || typeof one.path !== 'string' ||
        typeof one.render !== 'function';
    });
    t.check(bad.length === 0 && !/\brequire\(/.test(loaded.code),
            'B2. every row has a path and a renderer, and the bundle calls ' +
            'no require() of its own',
            JSON.stringify(bad.slice(0, 3)) +
            ((/\brequire\([^)]*\)/.exec(loaded.code) || [''])[0]));
    // --- C. the round trip ----------------------------------------------
    if (row.heldBy) {
      t.check(fs.existsSync(path.join(ROOT, row.heldBy)),
              'C0. ' + row.name + '\'s pages are drawn from their API\'s ' +
              'answers by ' + row.heldBy);
      continue;
    }
    const mine = require(path.join(ROOT, row.pages.replace(/\.ts$/, '')));
    const cases = typeof row.cases === 'function' ? await row.cases(ROOT)
                                                  : [];
    t.check(cases.length > 0, 'C1. ' + row.name + ' lists cases to draw');
    cases.forEach(function (one) {
      const found = harness.roundTrip({
        label: one.label, view: one.view, ctx: one.ctx,
        node: function (view, ctx) {
          return mine.render(one.path, view, ctx);
        },
        browser: function (view, ctx) {
          return loaded.value ? loaded.value.render(one.path, view, ctx)
                              : null;
        }
      });
      t.check(found.ok, 'C2. ' + row.name + ': ' + found.label + ' is one ' +
              'page in this process and in the bundle', found.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'web_surfaces',
  describe: 'every static surface in tests/tools/web_surfaces.js is built, ' +
            'runs where a browser does, and draws from a view after the ' +
            'wire what this process draws (#570)',
  run: run
};
