// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
// ---------------------------------------------------------------------------
// SEALED KEY ROWS, READ AND WRITTEN WITHOUT THE KEYSTORE (#391).
//
// A test that seeds a store with a key or certificate-authority row before a
// keystore starts, or reads what a keystore wrote, needs the row's DATA
// ENCRYPTION KEY: since #391 a row is sealed under a DEK, and the DEK is in a
// `dek:<scope>:<realm>` row of its own, wrapped under the key-encryption key.
//
// This is a SECOND READER AND WRITER of that format, written from
// `common/CLAUDE.md`'s description of it rather than from `keystore.js`, so a
// test that seeds through it and reads back through the keystore (or the
// reverse) holds the format to its description. It lives in `tools/`
// because `run.js` would otherwise run it as a test.
// ---------------------------------------------------------------------------
const crypto = require('../../common/crypto');
const log = require('bunyan').createLogger({ name: 'sealed_rows',
  level: process.env.LOG_LEVEL || 'info' });

function wrapAad(id, scope, realm, cls) {
  log.debug("Entering wrapAad().");
  log.debug("Leaving wrapAad().");
  return 'sts dek v1|' + id + '|' + scope + '|' + realm + '|' + cls;
}

/**
 * Seals text as a keystore row of a realm, adding the service scope's data
 * encryption key for that realm and class to the store where it holds none.
 *
 * @param store - a fake store: `{ rows: Map }`
 * @param kek - the key-encryption key
 * @param realm - the realm (or certificate-authority scope) the row is for
 * @param label - the row's class: `signing-keys` or `pki-hierarchy`
 * @param text - the plaintext
 * @returns the sealed row
 */
function sealRowIn(store, kek, realm, label, text) {
  log.debug("Entering sealRowIn().");
  const realmId = String(realm || '') || 'default';
  const rowKey = 'dek:service:' + realmId;
  const row = store.rows.has(rowKey) ? JSON.parse(store.rows.get(rowKey))
    : { v: 1, scope: 'service', realm: realmId, deks: [] };
  let one = row.deks.filter(function (d) {
    return d.cls === label && d.status !== 'retired';
  })[0];
  let key = null;
  if (one) {
    key = crypto.unwrapDek(kek, one.wrapped,
                           wrapAad(one.id, 'service', realmId, label));
  } else {
    key = crypto.generateDek();
    const id = crypto.generateDekId();
    one = { id: id, cls: label, createdAt: Date.now(), status: 'active',
            wrapped: crypto.wrapDek(kek, key,
                                    wrapAad(id, 'service', realmId, label)) };
    row.deks.push(one);
    store.rows.set(rowKey, JSON.stringify(row));
  }
  log.debug("Leaving sealRowIn().");
  return crypto.encryptWithDek(one.id, key, String(text), label);
}

/**
 * Opens a sealed row, finding its data encryption key in any of the stores'
 * data-key rows.
 *
 * @param stores - fake stores to look in
 * @param kek - the key-encryption key
 * @param cipher - the sealed row
 * @returns the plaintext
 */
function openRowIn(stores, kek, cipher) {
  log.debug("Entering openRowIn().");
  const id = crypto.dekIdOf(cipher);
  for (const store of stores) {
    for (const pair of store.rows.entries()) {
      if (pair[0].indexOf('dek:') !== 0) {
        continue;
      }
      const row = JSON.parse(pair[1]);
      const one = row.deks.filter(function (d) {
        return d.id === id;
      })[0];
      if (one) {
        const key = crypto.unwrapDek(kek, one.wrapped,
                                     wrapAad(id, row.scope, row.realm,
                                             one.cls));
        log.debug("Leaving openRowIn().");
        return crypto.decryptWithDek(key, cipher);
      }
    }
  }
  log.debug("Leaving openRowIn(). No data key.");
  throw new Error('no store holds the data encryption key "' + id + '"');
}

module.exports = { sealRowIn: sealRowIn, openRowIn: openRowIn };
