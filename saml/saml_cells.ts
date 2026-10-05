// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml_cells.ts
//
// ---------------------------------------------------------------------------
// WHERE A SAML BACK-CHANNEL REQUEST IS ANSWERED, IN A SERVICE DEPLOYED AS
// CELLS (#98 D10, 2026-09-28).
//
// Both SOAP endpoints of both profiles — `/saml2/ars`, `/saml2/aa` and
// `/saml11/responder` — are called by a service provider's SERVER, which
// resolves the public name to the cell nearest IT. What they ask about lives
// in one cell: an artifact where it was minted, a session where it is held.
// This library is how each handler finds that cell before it authenticates,
// counts or spends anything, and `common/cell_placement.ts`'s
// `relayToCell()` sends the whole request there.
//
// **AN ARTIFACT CARRIES ITS CELL INSIDE ITS HANDLE.** The two artifact
// layouts are fixed — a service provider decodes them by length and reads
// SourceID to find the issuer — so no tag can be appended to one. The last
// four bytes of the 20-byte MessageHandle (2.0) or AssertionHandle (1.1) are
// the minting cell's short keyed tag instead (`cell_locator.ts`'s
// `stampBytes()`, which argues the length and what a shorter tag is weaker
// at); sixteen random bytes remain, the floor saml-bindings-2.0-os section
// 3.6.4 sets. `stampHandle()` and `artifactCell()` are the two halves.
//
// **A QUERY IS ANSWERED WHERE THE SESSION THAT GAVE THE NameID IS HELD.**
// Neither attribute authority answers about a PERSON: each answers about the
// subject of a live session that gave the asking party exactly that NameID
// (`saml2ServiceProviders[sp].nameId`, `saml11RelyingParties[rp].nameId`).
// That is what makes a transient or persistent NameID answerable at all, and
// it is also why the person's home cell is the wrong question: a transient
// NameID maps to nobody outside the session that minted it, a persistent one
// is a keyed derivation no index is kept for, and a session may be held away
// from home where the transfer policy lets it (D4). So the handler looks here
// first, and only when no session here matches asks every peer
// (`saml-session-holder`) and relays to the first that holds one. A NameID no
// cell holds a session for is refused where it arrived, as it always was.
//
// A LIBRARY: no route. It registers its one inter-cell operation at load,
// which binds and dials nothing (`common/cell_channel.ts` keeps a map).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import cells = require('../common/cells');
import cellLocator = require('../common/cell_locator');

const log = helpers.log;

// The inter-cell operation a query's handler asks every peer.
const HOLDER_OP = 'saml-session-holder';
// The length of an artifact's handle, in both profiles.
const HANDLE_BYTES = 20;

/**
 * A question put to a cell: does it hold a live session that gave `party`
 * the NameID `nameId`, in `profile`?
 */
interface HolderQuestion {
  realm: string;
  profile: string;
  party: string;
  nameId: string;
}

/**
 * Where a SAML back-channel request is answered in a service deployed as
 * cells: the artifact handle's tag, and the cell holding a query's session.
 */
class SamlCells {
  /**
   * Stamps this cell's tag into a freshly drawn artifact handle. In
   * single-cell mode the handle is returned as it is.
   *
   * @param handle - twenty random bytes
   * @returns the handle to put in the artifact
   */
  static stampHandle(handle: Buffer): Buffer {
    log.debug("Entering SamlCells.stampHandle().");
    log.debug("Leaving SamlCells.stampHandle().");
    return cellLocator.stampBytes(handle, cellLocator.SAML_HANDLE_TAG_BYTES);
  }

  /**
   * The OTHER cell that minted an artifact, read from its handle.
   *
   * @param artifact - the artifact as it travels (base64)
   * @param length - the artifact's length in bytes: 44 for SAML 2.0, 42 for
   *   SAML 1.1
   * @returns the cell id, or '' when it is this cell's, unreadable, or the
   *   service is single-cell
   */
  static artifactCell(artifact: string, length: number): string {
    log.debug("Entering SamlCells.artifactCell().");
    if (!cells.isMulti()) {
      log.debug("Leaving SamlCells.artifactCell(). Single-cell.");
      return '';
    }
    const bytes = Buffer.from(String(artifact || '').trim(), 'base64');
    if (bytes.length !== length) {
      log.debug("Leaving SamlCells.artifactCell(). Not an artifact.");
      return '';
    }
    const at = cellLocator.elsewhereBytes(bytes.subarray(length -
                                                         HANDLE_BYTES),
                                          cellLocator.SAML_HANDLE_TAG_BYTES);
    log.debug("Leaving SamlCells.artifactCell(). " + (at || 'here'));
    return at;
  }

  // The live sessions HERE that gave `party` the NameID `nameId`.
  private static holds(question: HolderQuestion): boolean {
    log.debug("Entering SamlCells.holds().");
    const authn = require('../authn/authn');
    const field = question.profile === 'saml11' ? 'saml11RelyingParties'
                                                : 'saml2ServiceProviders';
    const found = question.nameId ? authn.sessionsMatching(function (s: any) {
      const there = (s && s[field] || {})[question.party];
      return !!there && there.nameId === question.nameId &&
             !authn.sessionEnded(s);
    }) : [];
    log.debug("Leaving SamlCells.holds(). " + found.length);
    return found.length > 0;
  }

  /**
   * Answers another cell's `saml-session-holder` question.
   *
   * @param body - `{ realm, profile, party, nameId }`
   * @returns `{ holds }`
   * @throws an Error for an unknown realm
   */
  static answer(body: any): { holds: boolean } {
    log.debug("Entering SamlCells.answer().");
    const realmId = String((body && body.realm) || '');
    const realm = realmId ? realms.get(realmId)
                          : realms.get(realms.DEFAULT_ID);
    if (!realm) {
      log.debug("Leaving SamlCells.answer(). No realm.");
      throw new Error('no such realm');
    }
    const question: HolderQuestion = {
      realm: realmId, profile: String(body.profile || ''),
      party: String(body.party || ''), nameId: String(body.nameId || '')
    };
    let holds = false;
    realms.run(realm, function () {
      holds = SamlCells.holds(question);
    });
    log.debug("Leaving SamlCells.answer(). " + holds);
    return { holds: holds };
  }

  /**
   * Finds the OTHER cell holding the live session a query names, when no
   * session here does.
   *
   * @param req - the request (a relayed one is never placed again)
   * @param profile - 'saml2' or 'saml11'
   * @param party - the asking service provider or relying party
   * @param nameId - the NameID the query names
   * @returns a promise of the cell id, or '' to answer here
   */
  static sessionHolder(req: any, profile: string, party: string,
                       nameId: string): Promise<string> {
    log.debug("Entering SamlCells.sessionHolder().");
    const question: HolderQuestion = {
      realm: realms.currentId(), profile: profile, party: String(party || ''),
      nameId: String(nameId || '')
    };
    if (!cells.isMulti() || (req && req.stsCellRelay) || !question.nameId ||
        !question.party || SamlCells.holds(question)) {
      log.debug("Leaving SamlCells.sessionHolder(). Here.");
      return Promise.resolve('');
    }
    const channel = require('../common/cell_channel');
    const asks = cells.peers().map(function (peer) {
      return channel.call(peer.id, HOLDER_OP, question)
        .then(function (answer: any) {
          return answer && answer.holds ? peer.id : '';
        }, function (err: any) {
          log.warn(errorCodes.tag('STS-CELL-0121') + 'saml: cell "' +
                   peer.id + '" could not be asked whether it holds the ' +
                   'session a ' + profile + ' query names (' +
                   ((err && err.message) || err) + '); the query is ' +
                   'answered without it.');
          return '';
        });
    });
    log.debug("Leaving SamlCells.sessionHolder(). Asking " + asks.length +
              " peer(s).");
    return Promise.all(asks).then(function (found: string[]) {
      return found.filter(Boolean)[0] || '';
    });
  }
}

require('../common/cell_channel').registerOp(HOLDER_OP, function (body: any) {
  return SamlCells.answer(body);
});

/**
 * Where a SAML back-channel request is answered in a service deployed as
 * cells (#98 D10). A library: no route.
 * @namespace
 */
export = {
  SamlCells: SamlCells,
  HOLDER_OP: HOLDER_OP,
  stampHandle: SamlCells.stampHandle,
  artifactCell: SamlCells.artifactCell,
  sessionHolder: SamlCells.sessionHolder,
  answer: SamlCells.answer
};
