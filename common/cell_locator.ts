// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_locator.ts
//
// ---------------------------------------------------------------------------
// WHICH CELL MINTED AN ARTIFACT (#98 D10, 2026-09-28).
//
// A code, a request_uri, a device code, a token's `jti` or a SAML artifact is
// minted in the cell that ran the flow — and very often presented at another:
// a relying party's server resolves the public name to the cell nearest IT,
// not to the one nearest the browser. The receiving cell has to find the
// minting cell without a round trip anywhere, and without anything a client
// can read saying where that is.
//
// **THE LOCATOR IS A KEYED TAG, APPENDED.** `stamp(value)` appends twelve
// base64url characters — the first 72 bits of an HMAC of the minting cell's
// id under the service key-encryption key, which every cell holds and nobody
// else does (`keystore.keyedDigest()`). `locate(value)` tries each cell's tag
// against the end of the value. Three properties follow, each the reason for
// the shape:
//
//   * **Nothing readable names a cell.** Without the key a tag is noise; the
//     one thing an outsider can see is that two artifacts share a suffix,
//     which says they came from the same place and not which place.
//   * **No separator.** The stamped value is still base64url of the length a
//     validation rule already allows (plus twelve), so no pattern anywhere in
//     the service has to learn a new character. A random value that happens
//     to end in a cell's tag is a 2^-72 event per cell.
//   * **Single-cell mode stamps nothing**, and `locate()` answers ''.
//
// A tag is cached per cell id: the key does not change while a process runs.
//
// A LIBRARY: no route. The keystore is required lazily, because this module
// is reached from `app.js`'s placement middleware, above everything.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('./cells');

const log = bunyan.createLogger({ name: 'sts-cell-locator' });

// Twelve base64url characters: 72 bits of the HMAC.
const TAG_LENGTH = 12;

/**
 * Stamps and reads the keyed tag that says which cell minted an artifact.
 */
class CellLocator {
  private readonly tags = new Map<string, string>();

  /**
   * Builds the locator. It holds no tag until one is asked for.
   */
  constructor() {
    log.debug("Entering CellLocator.constructor().");
    log.debug("Leaving CellLocator.constructor().");
  }

  /**
   * The tag of one cell, or '' where there is no key to make it with.
   *
   * @param cellId - the cell
   * @returns twelve base64url characters, or ''
   */
  tagOf(cellId: string): string {
    log.debug("Entering CellLocator.tagOf().");
    const id = String(cellId || '');
    const held = this.tags.get(id);
    if (held) {
      log.debug("Leaving CellLocator.tagOf(). Cached.");
      return held;
    }
    const keystore = require('./keystore');
    const digest = keystore.keyedDigest('cell-locator', id);
    if (!digest) {
      log.debug("Leaving CellLocator.tagOf(). No key.");
      return '';
    }
    const tag = String(digest).slice(0, TAG_LENGTH);
    this.tags.set(id, tag);
    log.debug("Leaving CellLocator.tagOf().");
    return tag;
  }

  /**
   * Appends this cell's tag to a freshly minted value. In single-cell mode,
   * or with no key, the value is returned as it is.
   *
   * @param value - the minted value (base64url)
   * @returns the stamped value
   */
  stamp(value: string): string {
    log.debug("Entering CellLocator.stamp().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellLocator.stamp(). Single-cell.");
      return String(value);
    }
    const tag = this.tagOf(cells.id());
    log.debug("Leaving CellLocator.stamp().");
    return String(value) + tag;
  }

  /**
   * Finds the cell that minted a value.
   *
   * @param value - a value `stamp()` may have produced
   * @returns the cell id, or '' when it carries no known cell's tag (or in
   *   single-cell mode)
   */
  locate(value: string): string {
    log.debug("Entering CellLocator.locate().");
    const text = String(value || '');
    if (!cells.isMulti() || text.length <= TAG_LENGTH) {
      log.debug("Leaving CellLocator.locate(). Nothing to read.");
      return '';
    }
    const tail = text.slice(-TAG_LENGTH);
    const found = cells.all().filter((one) => this.tagOf(one.id) === tail)[0];
    log.debug("Leaving CellLocator.locate(). " +
              (found ? found.id : 'none'));
    return found ? found.id : '';
  }

  /**
   * Tells whether a value was minted in ANOTHER cell, and which.
   *
   * @param value - a value `stamp()` may have produced
   * @returns the other cell's id, or '' when it is this cell's, unstamped,
   *   or the service is single-cell
   */
  elsewhere(value: string): string {
    log.debug("Entering CellLocator.elsewhere().");
    const at = this.locate(value);
    log.debug("Leaving CellLocator.elsewhere().");
    return at && at !== cells.id() ? at : '';
  }

  /**
   * Forgets the cached tags; for the tests, which change the key.
   */
  reset(): void {
    log.debug("Entering CellLocator.reset().");
    this.tags.clear();
    log.debug("Leaving CellLocator.reset().");
  }
}

const locator = new CellLocator();

/**
 * Which cell minted an artifact (#98 D10): a keyed tag appended when it is
 * minted and read when it is presented. A library: no route.
 * @namespace
 */
export = {
  CellLocator: CellLocator,
  TAG_LENGTH: TAG_LENGTH,
  tagOf: (cellId: string): string => locator.tagOf(cellId),
  stamp: (value: string): string => locator.stamp(value),
  locate: (value: string): string => locator.locate(value),
  elsewhere: (value: string): string => locator.elsewhere(value),
  reset: (): void => locator.reset()
};
