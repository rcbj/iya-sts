// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/store_double.js
//
// ===========================================================================
// A DATABASE DOUBLE, PUT WHERE THE SERVICE DIALS ITS STORE (#326).
//
// Every connection this service makes to PostgreSQL is made by
// `persistence/knex_store.js` since #326, so that module is the seam a test
// replaces — not `pg`, which only Knex loads now. The doubles the tests
// already write are `pg`-shaped (a `Pool` with `on`, `connect`, `query`,
// `end`, and a `Client` with `on`, `connect`, `query`, `release`,
// `removeListener`, `end`), because the layer hands the driver exactly that
// shape; this puts a layer in the require cache that builds them:
//
//   * `openPool(settings, options)` is `new Pool(settings + options)`, with
//     `stats()` and `dedicated()` added where the double has none — a
//     dedicated connection is `new Client(...)` with the same options, as the
//     real one is dialled by the pool's own Knex instance;
//   * `openConnection(settings)` is `new Client(settings)`;
//   * everything else (`timedOutWaiting()`) is the real layer's.
//
// The driver requires the layer inside `create()`, as it required `pg`, so
// a double installed around `create()` is the one that driver holds for
// its life. `install()` answers the function that puts the previous entry
// back.
// ===========================================================================

const path = require('path');

const log = require('bunyan').createLogger({ name: 'store_double',
  level: process.env.LOG_LEVEL || 'info' });

const LAYER = require.resolve(path.join(__dirname, '..', '..', 'persistence',
                                        'knex_store'));

// The real layer, read before any double can be in the cache.
const REAL = require(LAYER);

/**
 * A layer whose pools and connections are the given doubles.
 *
 * @param fakes - `{ Pool, Client }`, `pg`-shaped constructors
 * @returns the layer's exports
 */
function layerOver(fakes) {
  log.debug("Entering layerOver().");
  function adapted(pool, settings) {
    if (typeof pool.stats !== 'function') {
      pool.stats = function () {
        return { total: 0, idle: 0, waiting: 0, max: settings.max };
      };
    }
    if (typeof pool.dedicated !== 'function') {
      pool.dedicated = function () {
        return new fakes.Client(settings);
      };
    }
    return pool;
  }
  log.debug("Leaving layerOver().");
  return Object.assign({}, REAL, {
    openPool: function (settings, options) {
      const merged = Object.assign({}, settings || {}, options || {});
      return adapted(new fakes.Pool(merged), merged);
    },
    openConnection: function (settings) {
      return new fakes.Client(Object.assign({}, settings || {}));
    }
  });
}

/**
 * Puts a layer over `fakes` in the require cache.
 *
 * @param fakes - `{ Pool, Client }`
 * @returns a function that puts back what was there
 */
function install(fakes) {
  log.debug("Entering install().");
  const previous = require.cache[LAYER];
  require.cache[LAYER] = /** @type {any} */ ({
    id: LAYER, filename: LAYER, loaded: true, exports: layerOver(fakes) });
  log.debug("Leaving install().");
  return function restore() {
    log.debug("Entering restore().");
    if (previous) {
      require.cache[LAYER] = previous;
    } else {
      delete require.cache[LAYER];
    }
    log.debug("Leaving restore().");
  };
}

module.exports = { install: install, LAYER: LAYER };
