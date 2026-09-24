'use strict';
//
// File: page_pointer.ts
//
// ===========================================================================
// THE `next` / `from` POINTER OF A PAGED FEDERATION LISTING (#135, #136,
// 2026-09-24).
//
// The Extended Subordinate Listing (draft 03) and the Entity Collection
// Endpoint (draft 01) page the same way: a response that stops short carries
// `next`, an OPAQUE pointer, and the next request hands it back as `from`.
// Both drafts say what an unknown pointer gets — HTTP 404 with
// `page_not_found` — so "unknown" needs a meaning, and this file is it:
//
//   * **A POINTER NAMES THE FIRST ENTITY OF THE NEXT PAGE**, by its Entity
//     Identifier, which is the ordering key of both endpoints (each draft
//     leaves the key to the implementation and asks only that it be
//     CONSISTENT). A page resumes at the first entity whose identifier is not
//     before the named one, so an entity removed between two pages does not
//     break the walk — draft 03's "changes in pages yet to be fetched will be
//     reflected" — and one added before the pointer is simply not seen.
//
//   * **A POINTER IS MACED**, under the `oidfed-page` secret every node shares
//     (`cluster/cluster_secrets.ts`), over the realm, the endpoint and the
//     identifier. So a pointer is KNOWN exactly when this service made it —
//     for this realm and this endpoint — and anything else, however
//     plausible, is `page_not_found`. Without the MAC the check would be
//     "does it decode", and a caller could start a page anywhere by writing
//     the identifier in: harmless, but not what the drafts mean by a pointer
//     the server knows.
//
// The MAC is `crypto.js`'s `deriveSharedCredential()` — a keyed HMAC-SHA256
// with a separator between the parts — and the comparison its
// `constantTimeEquals()`: no cryptography is written here.
//
// A LIBRARY OF STATIC METHODS. It holds nothing.
// ===========================================================================

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import clusterSecrets = require('../cluster/cluster_secrets');

type Json = any;

const log = helpers.log;

const SECRET = 'oidfed-page';
const LABEL = 'oidfed-page-pointer';

class PagePointer {
  // Base64url of UTF-8 text, and back ('' for anything that is not).
  private static toB64u(text: string): string {
    log.debug("Entering PagePointer.toB64u().");
    log.debug("Leaving PagePointer.toB64u().");
    return Buffer.from(text, 'utf8').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  private static fromB64u(text: string): string {
    log.debug("Entering PagePointer.fromB64u().");
    if (!/^[A-Za-z0-9_-]*$/.test(text)) {
      log.debug("Leaving PagePointer.fromB64u(). Not base64url.");
      return '';
    }
    log.debug("Leaving PagePointer.fromB64u().");
    return Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('utf8');
  }

  // The MAC over the parts of a pointer.
  private static mac(realmId: string, endpoint: string, key: string): string {
    log.debug("Entering PagePointer.mac().");
    const out = stsCrypto.deriveSharedCredential(
      clusterSecrets.text(SECRET), LABEL, realmId, endpoint, key);
    log.debug("Leaving PagePointer.mac().");
    return out;
  }

  // The pointer to the page that starts at `key`, for `endpoint` in the
  // realm `realmId`.
  static encode(realmId: string, endpoint: string, key: string): string {
    log.debug("Entering PagePointer.encode(). " + endpoint);
    const out = PagePointer.toB64u(String(key)) + '.' +
                PagePointer.mac(String(realmId), endpoint, String(key));
    log.debug("Leaving PagePointer.encode().");
    return out;
  }

  // The key a pointer names, or null when this service did not make it for
  // this realm and endpoint (`page_not_found`).
  static decode(realmId: string, endpoint: string,
                pointer: Json): string | null {
    log.debug("Entering PagePointer.decode(). " + endpoint);
    const text = String(pointer === undefined || pointer === null ? ''
                                                                  : pointer);
    const dot = text.indexOf('.');
    if (dot <= 0 || dot !== text.lastIndexOf('.') || text.length > 4096) {
      log.debug("Leaving PagePointer.decode(). Not a pointer.");
      return null;
    }
    const key = PagePointer.fromB64u(text.slice(0, dot));
    if (!key) {
      log.debug("Leaving PagePointer.decode(). No key in it.");
      return null;
    }
    const expected = PagePointer.mac(String(realmId), endpoint, key);
    if (!stsCrypto.constantTimeEquals(expected, text.slice(dot + 1))) {
      log.debug("Leaving PagePointer.decode(). Not ours.");
      return null;
    }
    log.debug("Leaving PagePointer.decode().");
    return key;
  }

  // -------------------------------------------------------------------------
  // ONE PAGE of `items` (already filtered, and sorted by `keyOf`): from the
  // entity `from` names, at most `limit`, and the pointer to the rest.
  // `{ ok, page, next }`, or `{ ok: false }` for a pointer this service did
  // not make.
  // -------------------------------------------------------------------------
  static page<T>(items: T[], keyOf: (item: T) => string, realmId: string,
                 endpoint: string, from: Json, limit: number): Json {
    log.debug("Entering PagePointer.page(). " + items.length);
    let start = 0;
    if (from !== undefined && from !== null && from !== '') {
      const key = PagePointer.decode(realmId, endpoint, from);
      if (key === null) {
        log.debug("Leaving PagePointer.page(). Unknown pointer.");
        return { ok: false };
      }
      start = items.length;
      for (let i = 0; i < items.length; i++) {
        if (keyOf(items[i]) >= key) {
          start = i;
          break;
        }
      }
    }
    const page = items.slice(start, start + limit);
    const rest = start + limit < items.length;
    log.debug("Leaving PagePointer.page(). " + page.length);
    return { ok: true, page: page,
             next: rest ? PagePointer.encode(realmId, endpoint,
                                             keyOf(items[start + limit]))
                        : undefined };
  }
}

export = PagePointer;
