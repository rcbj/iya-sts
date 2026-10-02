// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/sealed_settings.js
//
// ===========================================================================
// A SECRET SETTING IS SEALED WHERE IT IS WRITTEN DOWN (#222, 2026-10-01).
//
// A setting changed while the service runs is saved — the service-wide ones
// in `sts_appconfig`, a realm's in `sts_realms.overrides` — and most of them
// are not secrets. The ones marked `secret: true` in `common/config.js` are;
// of those, the only one that is also changeable while running (and so ever
// saved) is `scim.digestPassword`, the HTTP Digest password every SCIM
// username shares. It was written in the clear, beside the other settings.
//
// **SEALED AT THE DRIVER'S DOOR AND NOWHERE ELSE.** `persistence.js` saves
// settings as a DELTA against a shadow of what it last wrote, comparing
// values; a sealed value is a fresh ciphertext every time, so sealing before
// the comparison would make every flush a change. So the values this module
// sees are plaintext on the way in, and it seals them in a COPY handed to the
// driver; on the way out of the driver it opens them. Every reader of a
// setting — the in-memory configuration, the console, `/admin-api/config` —
// sees what it always saw.
//
// **WHERE NOTHING DURABLE SEALS, NOTHING IS SEALED** (development mode, or a
// key that dies with the process): a value sealed under such a key would be
// garbage at the next start. The label is `setting-secret`, and the value is
// sealed under the realm's data key for that class (`''` for the service's).
// A value read back that does not open is dropped with STS-STORE-0071 rather
// than handed to the service as ciphertext: the setting falls back to its
// configured default, which an operator can see and set again.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-sealed-settings' });

const LABEL = 'setting-secret';

// The keys of the settings sealed at rest: secret AND saved.
let secretKeys = null;

function secretSettingKeys() {
  log.debug("Entering secretSettingKeys().");
  if (!secretKeys) {
    secretKeys = new Set(config.SETTINGS.filter(function (row) {
      return !!row.secret && !!row.runtime;
    }).map(function (row) {
      return row.key;
    }));
  }
  log.debug("Leaving secretSettingKeys().");
  return secretKeys;
}

function keystore() {
  log.debug("Entering keystore().");
  log.debug("Leaving keystore().");
  return require('../common/keystore');
}

// Whether values written now are sealed: a durable key-encryption key.
function sealing() {
  log.debug("Entering sealing().");
  const ks = keystore();
  log.debug("Leaving sealing().");
  return ks.persists() && ks.sealed();
}

// A copy of a `{ key: raw }` map with every secret setting's value sealed.
function sealMap(map, realmId) {
  log.debug("Entering sealMap().");
  const out = {};
  const keys = secretSettingKeys();
  const seal = sealing();
  Object.keys(map || {}).forEach(function (key) {
    const value = map[key];
    if (seal && keys.has(key) && typeof value === 'string' && value !== '' &&
        !require('../common/crypto').isEncryptedWithKek(value)) {
      out[key] = keystore().seal(value, LABEL, undefined,
                                 { realm: realmId || '' });
    } else {
      out[key] = value;
    }
  });
  log.debug("Leaving sealMap().");
  return out;
}

// A copy of a `{ key: raw }` map with every sealed value opened. A value that
// does not open is left out (see the header).
function openMap(map, where) {
  log.debug("Entering openMap().");
  if (!map || typeof map !== 'object') {
    log.debug("Leaving openMap(). Nothing.");
    return map;
  }
  const out = {};
  const crypto = require('../common/crypto');
  Object.keys(map).forEach(function (key) {
    const value = map[key];
    if (typeof value === 'string' && crypto.isEncryptedWithKek(value)) {
      const opened = keystore().open(value, LABEL);
      if (opened === null || opened === undefined) {
        log.error(errorCodes.tag('STS-STORE-0071') + 'persistence: the ' +
                  'saved value of ' + key + ' (' + where + ') is sealed and ' +
                  'did not open; it is ignored, and the setting has its ' +
                  'configured value until it is set again.');
        return;
      }
      out[key] = opened;
    } else {
      out[key] = value;
    }
  });
  log.debug("Leaving openMap().");
  return out;
}

/**
 * Wraps a persistence driver's four settings methods so that secret settings
 * are sealed on the way in and opened on the way out. The driver is changed
 * in place and returned.
 *
 * @param driver - the driver `persistence.js` opened
 * @returns the same driver
 */
function wrap(driver) {
  log.debug("Entering wrap().");
  if (!driver || driver.__sealedSettings) {
    log.debug("Leaving wrap(). Nothing to do.");
    return driver;
  }
  const saveOverrides = driver.saveOverrides;
  const loadOverrides = driver.loadOverrides;
  const saveRealms = driver.saveRealms;
  const loadRealms = driver.loadRealms;
  if (typeof saveOverrides === 'function') {
    driver.saveOverrides = function (map, delta) {
      log.debug("Entering sealed saveOverrides().");
      const sealedDelta = delta
        ? Object.assign({}, delta, { set: sealMap(delta.set, ''),
                                     live: sealMap(delta.live, '') })
        : delta;
      log.debug("Leaving sealed saveOverrides().");
      return saveOverrides.call(driver, sealMap(map, ''), sealedDelta);
    };
  }
  if (typeof loadOverrides === 'function') {
    driver.loadOverrides = function () {
      log.debug("Entering sealed loadOverrides().");
      log.debug("Leaving sealed loadOverrides().");
      return Promise.resolve(loadOverrides.apply(driver, arguments))
        .then(function (saved) {
          return saved ? openMap(saved, 'the service settings') : saved;
        });
    };
  }
  if (typeof saveRealms === 'function') {
    driver.saveRealms = function (rows, delta) {
      log.debug("Entering sealed saveRealms().");
      const sealRow = function (row) {
        return row ? Object.assign({}, row, {
          overrides: sealMap(row.overrides, row.id) }) : row;
      };
      const sealedDelta = delta && Array.isArray(delta.upserts)
        ? Object.assign({}, delta, {
          upserts: delta.upserts.map(function (one) {
            return Object.assign({}, one, {
              row: sealRow(one.row),
              set: sealMap(one.set, one.row && one.row.id) });
          }) })
        : delta;
      log.debug("Leaving sealed saveRealms().");
      return saveRealms.call(driver, (rows || []).map(sealRow), sealedDelta);
    };
  }
  if (typeof loadRealms === 'function') {
    driver.loadRealms = function () {
      log.debug("Entering sealed loadRealms().");
      log.debug("Leaving sealed loadRealms().");
      return Promise.resolve(loadRealms.apply(driver, arguments))
        .then(function (rows) {
          return Array.isArray(rows) ? rows.map(function (row) {
            return row ? Object.assign({}, row, {
              overrides: openMap(row.overrides || {}, 'the realm "' +
                                 row.id + '"') }) : row;
          }) : rows;
        });
    };
  }
  Object.defineProperty(driver, '__sealedSettings', { value: true });
  log.debug("Leaving wrap().");
  return driver;
}

module.exports = {
  wrap: wrap,
  LABEL: LABEL,
  secretSettingKeys: secretSettingKeys,
  sealMap: sealMap,
  openMap: openMap
};
