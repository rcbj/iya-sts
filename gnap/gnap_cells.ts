// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: gnap_cells.ts
//
// ---------------------------------------------------------------------------
// WHICH CELL SERVES A GNAP REQUEST (#98 D9, D10, 2026-09-28).
//
// In a service deployed as cells (`common/cells.ts`) every GNAP store is the
// CELL's (`persistence/tiers.js`): a grant, its continuation, its interaction
// handles, its user codes, the access tokens it issued and the client
// instances registered on the way are held by the cell that minted them. A
// client, a resource server or a browser reaches whichever cell DNS chose, so
// every GNAP door first asks where its request belongs — and a request that
// belongs elsewhere is relayed WHOLE (`common/cell_channel.ts`), before any
// key proof is verified, any signature nonce or interaction handle is spent,
// or anything is counted: the owning cell spends them, once.
//
// HOW EACH REQUEST FINDS ITS CELL, door by door:
//
//   POST /gnap (the grant request, section 2), in this order:
//     1. a `client` that is an instance identifier (section 2.3.1) this cell
//        does not hold → the cell whose tag it carries: the instance's key
//        is held there;
//     2. an `existing_access_token` (RFC 9767 section 4, a resource server
//        deriving a token) → the cell that holds that token;
//     3. a `user` naming a reference or an opaque subject identifier this
//        cell does not hold → the cell that does (the other cells are asked);
//     4. a `user` naming a PERSON — a subject identifier, an ID Token's
//        `preferred_username` or `sub`, a SAML assertion's NameID, read here
//        WITHOUT verifying anything — → that person's HOME cell, because the
//        grant, its consent and the tokens about them are the person's and
//        belong where they are homed (D1, D4). The owning cell verifies the
//        assertion; this one only decides where it is verified.
//     Otherwise the grant is served where it arrives, and the resource owner
//     it is for is found later, at the interaction (below). When two rules
//     name different cells the FIRST wins: an instance's key exists in one
//     cell only, and a grant cannot be verified anywhere else.
//   /gnap/continue/{grant} (section 5): the grant's cell, by the tag on its
//     id — or, for a grant that MOVED (below), the cell it moved to.
//   /gnap/interact/{id}, /gnap/app/{id}, /gnap/approve/{id} (section 4): the
//     edge sends a pinned browser to its pinned cell and any other to the
//     handle's cell. A browser pinned to a cell that does not hold the grant
//     — the person signed in at home (D9) — PULLS the grant there (below).
//   /gnap/code (sections 4.1.2 and 4.1.3): a user code is typed by a person
//     from a list of 31 characters and carries no tag; a code this cell does
//     not hold is asked of the other cells, and the request relayed to the
//     one that holds it.
//   /gnap/token/{handle} (section 6): the edge, by the handle's tag.
//   /gnap/rs/resource, /gnap/introspect (RFC 9767 section 3.3): the cell that
//     holds the access token. A `jwt-signed` token's `jti` carries the tag
//     and is read without verifying; the other four formats hide it (an
//     encrypted JWT, a macaroon, a biscuit, a ZCAP), so a token this cell
//     does not hold is asked of the other cells by the digest of its value —
//     never the value itself.
//   /gnap/resource (RFC 9767 section 3.4): a `resource_server` that is an
//     instance identifier this cell does not hold → its cell. The resource
//     set itself is the global tier's.
//
// **A GRANT MOVES ONCE, BEFORE IT HAS ISSUED ANYTHING.** A grant is made in
// the cell the client reached, before anybody knows who will approve it. When
// the resource owner turns out to be homed elsewhere, the sign-in screen pins
// their browser there and sends it back to `/gnap/approve/…` (`authn.ts`'s
// restart, D9) — and the pinned cell holds nothing of the grant. It PULLS it
// (`gnap-surrender-grant`): the minting cell hands over the grant and the
// rows that find it, forgets them, and tells every other cell where it went
// (`gnap-grant-moved`), so that the client's next continuation — which still
// names the grant by its old id, and may reach any cell — is relayed to the
// grant's new cell in one hop from wherever it lands. A grant that has issued
// a token is not moved: its tokens, management handles and the consent they
// rest on stay where they were minted, and a browser pinned elsewhere is told
// the request is not waiting there.
//
// **SINGLE-CELL MODE DOES NOTHING HERE**: every method answers "serve it
// here" before it reads anything, and no operation is ever called.
//
// A LIBRARY: no route. It registers its three inter-cell operations when it
// is loaded, as `oauth-oidc/par.ts` does; the channel is required where it
// is used, as `common/cell_placement.ts` requires it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import realms = require('../common/realms');
import cells = require('../common/cells');
import cellLocator = require('../common/cell_locator');
import cellPlacement = require('../common/cell_placement');
import errorCodes = require('../common/error_codes');
import store = require('./gnap_store');
import proof = require('./gnap_proof');

const log = helpers.log;

// A moved grant's forwarding row lives this long past the grant's own expiry,
// so a client polling a grant that has just expired is told so by the cell
// that holds it rather than by one that has forgotten it moved.
const MOVED_GRACE_S = 600;
// The most forwarding rows a realm keeps; a move is one per traveller's
// grant, and a row past its time is never answered.
const MOVED_CAP = 5000;

// Where a grant went, per realm: the grant id and each of its interaction
// handles → `{ cell, until }`. Persisted, so every node of this cell knows
// it; cell-tier (`persistence/tiers.js`).
const movedGrants = realms.map({ persist: 'gnap.movedGrants', retain: 'age' });

// What the other cells are asked to locate.
type LocateKind = 'token' | 'user-code' | 'user-ref';

/**
 * Where a GNAP request is served in a service deployed as cells, and the
 * three inter-cell operations that answer it.
 */
class GnapCells {
  /**
   * Builds the placement. It holds nothing; the forwarding rows are a store.
   */
  constructor() {
    log.debug("Entering GnapCells.constructor().");
    log.debug("Leaving GnapCells.constructor().");
  }

  // True when nothing is to be placed: single-cell mode, or a request another
  // cell relayed here (one hop — `cell_channel.ts`).
  static stays(req: any): boolean {
    log.debug("Entering GnapCells.stays().");
    log.debug("Leaving GnapCells.stays().");
    return !cells.isMulti() || !!(req && req.stsCellRelay);
  }

  // Relays a request to a cell found by a store rather than by a tag, with
  // the body exactly as it arrived (`cell_placement.ts`'s serialisedBody()
  // prefers the bytes the proof covers).
  private relayTo(req: any, res: any, cellId: string, reason: string): true {
    log.debug("Entering GnapCells.relayTo(). " + cellId);
    require('../common/cell_channel').relay(req, res, cellId, {
      reason: reason, body: cellPlacement.serialisedBody(req) });
    log.debug("Leaving GnapCells.relayTo().");
    return true;
  }

  // -------------------------------------------------------------------------
  // THE FORWARDING ROWS.
  // -------------------------------------------------------------------------
  // The cell a grant or interaction handle moved to, or '' when it did not
  // (or the row has run out).
  private movedTo(key: string): string {
    log.debug("Entering GnapCells.movedTo().");
    const row = key ? movedGrants.get(key) : null;
    if (!row) {
      log.debug("Leaving GnapCells.movedTo(). Not moved.");
      return '';
    }
    if (Number(row.until) <= helpers.nowSec()) {
      movedGrants.delete(key);
      log.debug("Leaving GnapCells.movedTo(). Run out.");
      return '';
    }
    log.debug("Leaving GnapCells.movedTo(). " + row.cell);
    return String(row.cell || '');
  }

  // Writes the forwarding rows of one move, in the current realm. A bound at
  // the insert, not a sweep: rows past their time go first, then the oldest.
  private recordMove(keys: string[], cellId: string, until: number): void {
    log.debug("Entering GnapCells.recordMove(). " + keys.length + " key(s)");
    const now = helpers.nowSec();
    let held = 0;
    const live: Array<{ key: string; until: number }> = [];
    movedGrants.forEach(function (row: any, key: string) {
      held += 1;
      if (!row || Number(row.until) <= now) {
        movedGrants.delete(key);
      } else {
        live.push({ key: key, until: Number(row.until) });
      }
    });
    if (held + keys.length > MOVED_CAP) {
      live.sort(function (a, b) {
        return a.until - b.until;
      }).slice(0, Math.max(0, live.length + keys.length - MOVED_CAP))
        .forEach(function (one) {
          movedGrants.delete(one.key);
        });
    }
    keys.forEach(function (key) {
      movedGrants.set(key, { cell: cellId, until: until });
    });
    log.debug("Leaving GnapCells.recordMove().");
  }

  // -------------------------------------------------------------------------
  // ASKING THE OTHER CELLS what carries no tag. Every peer is asked at once;
  // the first in the cell map's order that holds it answers. A peer that
  // cannot be reached is logged and counted as not holding it, so the
  // request is served here and refused as unknown — the same answer a
  // stranger's value gets.
  // -------------------------------------------------------------------------
  private askPeers(kind: LocateKind, value: string): Promise<string> {
    log.debug("Entering GnapCells.askPeers(). kind=" + kind);
    const channel = require('../common/cell_channel');
    const realm = realms.currentId();
    const peers = cells.peers();
    log.debug("Leaving GnapCells.askPeers(). " + peers.length + " peer(s)");
    return Promise.all(peers.map(function (peer: any) {
      return channel.call(peer.id, 'gnap-locate', { realm: realm, kind: kind,
                                                    value: value })
        .then(function (answer: any) {
          return answer && answer.held ? String(peer.id) : '';
        }, function (err: any) {
          log.warn(errorCodes.tag('STS-CELL-0163') + 'gnap: cell "' +
                   peer.id + '" could not be asked whether it holds a ' +
                   kind + ' (' + ((err && err.message) || err) + '); the ' +
                   'request is served here as if nobody did.');
          return '';
        });
    })).then(function (found: string[]) {
      return found.filter(function (one) {
        return one;
      })[0] || '';
    });
  }

  // -------------------------------------------------------------------------
  // THE DOORS. Each answers a promise of true when it relayed the request,
  // and the route must then stop.
  // -------------------------------------------------------------------------
  /**
   * Places a grant request (`POST /gnap`, `POST /{as}/gnap`). See the header
   * for the order of the rules.
   *
   * @param req - the request, its body read
   * @param res - the response
   * @returns a promise of true when the request was relayed
   */
  async placeGrantRequest(req: any, res: any): Promise<boolean> {
    log.debug("Entering GnapCells.placeGrantRequest().");
    if (GnapCells.stays(req)) {
      log.debug("Leaving GnapCells.placeGrantRequest(). Here.");
      return false;
    }
    const body: any = proof.readBody(req);
    const json = body && body.ok ? body.json : null;
    if (!json || typeof json !== 'object') {
      // Refused here, as it would be anywhere.
      log.debug("Leaving GnapCells.placeGrantRequest(). No document.");
      return false;
    }
    // 1. A client instance's key is held where the instance was registered.
    if (typeof json.client === 'string' && !store.instanceById(json.client) &&
        cellPlacement.relayIfElsewhere(req, res, json.client,
                                       'gnap:instance')) {
      log.debug("Leaving GnapCells.placeGrantRequest(). An instance.");
      return true;
    }
    // 2. RFC 9767 section 4: the token being derived from.
    if (typeof json.existing_access_token === 'string' &&
        await this.placeToken(req, res, json.existing_access_token,
                              'gnap:derive')) {
      log.debug("Leaving GnapCells.placeGrantRequest(). A derivation.");
      return true;
    }
    const user = json.user;
    if (!user) {
      log.debug("Leaving GnapCells.placeGrantRequest(). Here.");
      return false;
    }
    // 3. A reference this service handed out (section 2.4.1), or an opaque
    // subject identifier (the same record, `gnap_subject.ts`).
    const refs = GnapCells.userReferences(user).filter(function (ref) {
      return !store.userByRef(ref);
    });
    for (let i = 0; i < refs.length; i++) {
      const holder = await this.askPeers('user-ref', store.digest(refs[i]));
      if (holder) {
        log.debug("Leaving GnapCells.placeGrantRequest(). A user reference.");
        return this.relayTo(req, res, holder, 'gnap:user-reference');
      }
    }
    // 4. A person, at home.
    const hint = GnapCells.subjectHint(user);
    const relayed = hint
      ? await cellPlacement.relayToHome(req, res, realms.currentId(),
                                        hint.kind, hint.value, 'gnap:user')
      : false;
    log.debug("Leaving GnapCells.placeGrantRequest(). " +
              (relayed ? 'At home.' : 'Here.'));
    return relayed;
  }

  /**
   * Places a continuation request (`/gnap/continue/{grant}`).
   *
   * @param req - the request
   * @param res - the response
   * @param grantId - the grant named by the URI
   * @returns a promise of true when the request was answered (relayed, or
   *   refused because it cannot be relayed again)
   */
  async placeContinuation(req: any, res: any,
                          grantId: string): Promise<boolean> {
    log.debug("Entering GnapCells.placeContinuation().");
    if (!cells.isMulti() || store.getGrant(grantId)) {
      log.debug("Leaving GnapCells.placeContinuation(). Here.");
      return false;
    }
    const moved = this.movedTo(grantId);
    if (moved && moved !== cells.id() && cells.get(moved)) {
      if (req.stsCellRelay) {
        // A THIRD CELL relayed it here by the id's tag before it heard of
        // the move. One hop is all a relay gets, so the client is asked to
        // try again: by then every cell has been told (`gnap-grant-moved`).
        errorCodes.mark(res, 'STS-CELL-0160');
        res.status(503).set('retry-after', '5').set('Cache-Control',
                                                     'no-store')
           .type('application/json')
           .send(JSON.stringify({ error: { code: 'too_fast',
             description: 'This grant request has just moved to another ' +
             'region of this service; try again shortly.' } }));
        log.debug("Leaving GnapCells.placeContinuation(). Moved; relayed " +
                  "once already.");
        return true;
      }
      log.debug("Leaving GnapCells.placeContinuation(). Moved.");
      return this.relayTo(req, res, moved, 'gnap:continue-moved');
    }
    if (req.stsCellRelay) {
      log.debug("Leaving GnapCells.placeContinuation(). Relayed here.");
      return false;
    }
    const relayed = cellPlacement.relayIfElsewhere(req, res, grantId,
                                                   'gnap:continue');
    log.debug("Leaving GnapCells.placeContinuation(). " +
              (relayed ? 'Relayed.' : 'Here.'));
    return relayed;
  }

  /**
   * Places a browser at an interaction handle (`/gnap/interact/{id}`,
   * `/gnap/app/{id}`, `/gnap/approve/{id}`): a grant this cell does not hold
   * is pulled here from the cell that minted it, or the request relayed to
   * the cell it moved to.
   *
   * @param req - the request
   * @param res - the response
   * @param key - the interaction key: `approve:`, `redirect:` or `app:`
   *   followed by the handle
   * @returns a promise of true when the request was relayed
   */
  async placeInteraction(req: any, res: any, key: string): Promise<boolean> {
    log.debug("Entering GnapCells.placeInteraction(). " +
              key.split(':')[0]);
    if (!cells.isMulti() || store.grantByInteraction(key)) {
      log.debug("Leaving GnapCells.placeInteraction(). Here.");
      return false;
    }
    const moved = this.movedTo(key);
    if (moved && moved !== cells.id() && cells.get(moved)) {
      if (req.stsCellRelay) {
        // Pinned to a cell that is not where the grant went: this cell
        // cannot send it on, and answers as for a handle it does not hold.
        log.debug("Leaving GnapCells.placeInteraction(). Moved; relayed " +
                  "once already.");
        return false;
      }
      log.debug("Leaving GnapCells.placeInteraction(). Moved.");
      return this.relayTo(req, res, moved, 'gnap:interaction-moved');
    }
    const handle = key.slice(key.indexOf(':') + 1);
    const minted = cellLocator.elsewhere(handle);
    if (!minted || !cells.get(minted)) {
      log.debug("Leaving GnapCells.placeInteraction(). Nobody holds it.");
      return false;
    }
    // THE BROWSER IS PINNED HERE (or a pinned browser was relayed here): the
    // person signs in, and is homed, where they are pinned. The grant comes
    // to them.
    await this.pull(minted, key);
    log.debug("Leaving GnapCells.placeInteraction(). Pulled.");
    return false;
  }

  // Asks the minting cell for a grant waiting at an interaction handle, and
  // adopts what it hands over. Nothing is thrown: a grant not handed over is
  // answered as a handle this cell does not hold.
  private pull(cellId: string, key: string): Promise<void> {
    log.debug("Entering GnapCells.pull(). from " + cellId);
    const realm = realms.currentId();
    log.debug("Leaving GnapCells.pull().");
    return require('../common/cell_channel').call(cellId,
      'gnap-surrender-grant', { realm: realm, key: key, to: cells.id() })
      .then(function (answer: any) {
        if (!answer || !answer.bundle) {
          log.warn(errorCodes.tag('STS-CELL-0161') + 'gnap: cell "' +
                   cellId + '" did not hand over the grant waiting at an ' +
                   'interaction handle (' + String((answer && answer.why) ||
                                                   'no answer') + '); the ' +
                   'browser pinned here is told nothing is waiting.');
          return;
        }
        store.importGrant(answer.bundle);
        log.info('gnap: a grant waiting for its resource owner was handed ' +
                 'over from cell "' + cellId + '", where the browser signing ' +
                 'in is pinned here (#98 D9).');
      }, function (err: any) {
        log.error(errorCodes.tag('STS-CELL-0162') + 'gnap: the grant ' +
                  'waiting at an interaction handle could not be fetched ' +
                  'from cell "' + cellId + '": ' +
                  ((err && err.message) || err) + '. The browser pinned ' +
                  'here is told nothing is waiting.');
      });
  }

  /**
   * Places a user code entered at `/gnap/code`. Called after the attempt is
   * counted: a code carries no tag, so the other cells are asked, and the
   * count here is what keeps a guesser from making every cell answer.
   *
   * @param req - the request, its form read
   * @param res - the response
   * @param code - the normalised code
   * @returns a promise of true when the request was relayed
   */
  async placeUserCode(req: any, res: any, code: string): Promise<boolean> {
    log.debug("Entering GnapCells.placeUserCode().");
    if (GnapCells.stays(req) || !code || store.grantByUserCode(code)) {
      log.debug("Leaving GnapCells.placeUserCode(). Here.");
      return false;
    }
    const holder = await this.askPeers('user-code', code);
    log.debug("Leaving GnapCells.placeUserCode(). " + (holder || 'here'));
    return holder ? this.relayTo(req, res, holder, 'gnap:user-code') : false;
  }

  /**
   * Places a request that presents an access token: at the demonstration
   * resource server (in `Authorization`), at introspection (in the body) and
   * as a token to derive from.
   *
   * @param req - the request
   * @param res - the response
   * @param value - the token's value
   * @param reason - what it is, for the log
   * @returns a promise of true when the request was relayed
   */
  async placeToken(req: any, res: any, value: string,
                   reason: string): Promise<boolean> {
    log.debug("Entering GnapCells.placeToken().");
    if (GnapCells.stays(req) || !value || store.tokenByValue(value)) {
      log.debug("Leaving GnapCells.placeToken(). Here.");
      return false;
    }
    const jti = GnapCells.jwsJti(value);
    if (jti && cellPlacement.relayIfElsewhere(req, res, jti, reason)) {
      log.debug("Leaving GnapCells.placeToken(). By its jti.");
      return true;
    }
    const holder = await this.askPeers('token', store.digest(value));
    log.debug("Leaving GnapCells.placeToken(). " + (holder || 'here'));
    return holder ? this.relayTo(req, res, holder, reason) : false;
  }

  /**
   * Places an introspection request (RFC 9767 section 3.3): the cell holding
   * the token, and failing that the one holding the resource server's
   * instance. The token wins: it is what the answer is about.
   *
   * @param req - the request, its body read
   * @param res - the response
   * @returns a promise of true when the request was relayed
   */
  async placeIntrospection(req: any, res: any): Promise<boolean> {
    log.debug("Entering GnapCells.placeIntrospection().");
    if (GnapCells.stays(req)) {
      log.debug("Leaving GnapCells.placeIntrospection(). Here.");
      return false;
    }
    const body: any = proof.readBody(req);
    const token = body && body.ok && body.json ? body.json.access_token
                                               : null;
    if (typeof token === 'string' &&
        await this.placeToken(req, res, token, 'gnap:introspect')) {
      log.debug("Leaving GnapCells.placeIntrospection(). By the token.");
      return true;
    }
    const relayed = this.placeResourceServer(req, res);
    log.debug("Leaving GnapCells.placeIntrospection().");
    return relayed;
  }

  /**
   * Places a resource server's request (registration, introspection) by the
   * instance identifier it presents itself with, when it presents one.
   *
   * @param req - the request, its body read
   * @param res - the response
   * @returns true when the request was relayed
   */
  placeResourceServer(req: any, res: any): boolean {
    log.debug("Entering GnapCells.placeResourceServer().");
    if (GnapCells.stays(req)) {
      log.debug("Leaving GnapCells.placeResourceServer(). Here.");
      return false;
    }
    const body: any = proof.readBody(req);
    const member = body && body.ok && body.json ? body.json.resource_server
                                                : null;
    const relayed = typeof member === 'string' &&
      !store.instanceById(member) &&
      cellPlacement.relayIfElsewhere(req, res, member, 'gnap:rs-instance');
    log.debug("Leaving GnapCells.placeResourceServer(). " +
              (relayed ? 'Relayed.' : 'Here.'));
    return relayed;
  }

  // -------------------------------------------------------------------------
  // READING A REQUEST WITHOUT VERIFYING IT. What is read decides only WHERE
  // the request is verified; the cell it names verifies it.
  // -------------------------------------------------------------------------
  // A `jwt-signed` token's `jti`, or '' for any other format.
  static jwsJti(value: string): string {
    log.debug("Entering GnapCells.jwsJti().");
    const parts = String(value || '').split('.');
    if (parts.length !== 3) {
      log.debug("Leaving GnapCells.jwsJti(). Not a JWS.");
      return '';
    }
    try {
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url')
        .toString('utf8'));
      log.debug("Leaving GnapCells.jwsJti().");
      return String((claims && claims.jti) || '');
    } catch (e) {
      log.debug("Caught in GnapCells.jwsJti(): " + ((e && e.message) || e));
      log.debug("Leaving GnapCells.jwsJti(). Unreadable.");
      return '';
    }
  }

  // The references a `user` member names: itself when it is a string
  // (section 2.4.1), and every opaque subject identifier in it.
  static userReferences(user: any): string[] {
    log.debug("Entering GnapCells.userReferences().");
    if (typeof user === 'string') {
      log.debug("Leaving GnapCells.userReferences(). A reference.");
      return [user];
    }
    const out: string[] = [];
    const walk = function (subId: any): void {
      if (!subId || typeof subId !== 'object') {
        return;
      }
      if (subId.format === 'opaque' && typeof subId.id === 'string') {
        out.push(subId.id);
      }
      if (subId.format === 'aliases' && Array.isArray(subId.identifiers)) {
        subId.identifiers.forEach(walk);
      }
    };
    (Array.isArray(user && user.sub_ids) ? user.sub_ids : []).forEach(walk);
    log.debug("Leaving GnapCells.userReferences(). " + out.length);
    return out;
  }

  // The routing index's key for a subject string: an entryUUID for
  // `urn:uuid:…`, a login name for the legacy `urn:sts:user:…`.
  static hintOfSubject(subject: string): { kind: string;
                                            value: string } | null {
    log.debug("Entering GnapCells.hintOfSubject().");
    const text = String(subject || '');
    const uuid = /^urn:uuid:([0-9a-fA-F-]{36})$/.exec(text);
    if (uuid) {
      log.debug("Leaving GnapCells.hintOfSubject(). An entryUUID.");
      return { kind: 'uuid', value: uuid[1].toLowerCase() };
    }
    const legacy = /^urn:sts:user:(.+)$/.exec(text);
    log.debug("Leaving GnapCells.hintOfSubject().");
    return legacy ? { kind: 'name', value: legacy[1] } : null;
  }

  // The person a `user` member names, as `gnap_subject.ts`'s resolveUser()
  // would find them — the first subject identifier, then the first
  // assertion — without verifying anything. Null when it names nobody this
  // service could route.
  static subjectHint(user: any): { kind: string; value: string } | null {
    log.debug("Entering GnapCells.subjectHint().");
    if (!user || typeof user !== 'object') {
      log.debug("Leaving GnapCells.subjectHint(). No member.");
      return null;
    }
    const ofSubId = function (subId: any): { kind: string;
                                              value: string } | null {
      if (!subId || typeof subId !== 'object') {
        return null;
      }
      if (subId.format === 'iss_sub') {
        return GnapCells.hintOfSubject(subId.sub);
      }
      if (subId.format === 'uri') {
        return GnapCells.hintOfSubject(subId.uri);
      }
      if (subId.format === 'account') {
        const m = /^acct:([^@]+)@/.exec(String(subId.uri || ''));
        return m ? { kind: 'name', value: m[1] } : null;
      }
      if (subId.format === 'email') {
        const local = String(subId.email || '').split('@')[0];
        return local ? { kind: 'name', value: local } : null;
      }
      if (subId.format === 'aliases' && Array.isArray(subId.identifiers)) {
        for (let i = 0; i < subId.identifiers.length; i++) {
          const inner = ofSubId(subId.identifiers[i]);
          if (inner) {
            return inner;
          }
        }
      }
      return null;
    };
    const subIds = Array.isArray(user.sub_ids) ? user.sub_ids : [];
    for (let i = 0; i < subIds.length; i++) {
      const found = ofSubId(subIds[i]);
      if (found) {
        log.debug("Leaving GnapCells.subjectHint(). A subject identifier.");
        return found;
      }
    }
    const assertions = Array.isArray(user.assertions) ? user.assertions : [];
    for (let i = 0; i < assertions.length; i++) {
      const found = GnapCells.hintOfAssertion(assertions[i]);
      if (found) {
        log.debug("Leaving GnapCells.subjectHint(). An assertion.");
        return found;
      }
    }
    log.debug("Leaving GnapCells.subjectHint(). Nobody.");
    return null;
  }

  // An ID Token's `preferred_username` or `sub`, or a SAML assertion's
  // NameID — the two formats `gnap_subject.ts` accepts, read the way it reads
  // them once they verify.
  static hintOfAssertion(assertion: any): { kind: string;
                                             value: string } | null {
    log.debug("Entering GnapCells.hintOfAssertion().");
    const value = String((assertion && assertion.value) || '');
    try {
      if (assertion && assertion.format === 'id_token') {
        const parts = value.split('.');
        const claims = parts.length === 3
          ? JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
          : null;
        log.debug("Leaving GnapCells.hintOfAssertion(). An ID Token.");
        if (!claims) {
          return null;
        }
        return claims.preferred_username
          ? { kind: 'name', value: String(claims.preferred_username) }
          : GnapCells.hintOfSubject(String(claims.sub || ''));
      }
      if (assertion && assertion.format === 'saml2') {
        const xml = Buffer.from(value, 'base64url').toString('utf8');
        const m = xml.match(/<(?:[A-Za-z0-9]+:)?NameID\b[^>]*>([^<]+)<\/(?:[A-Za-z0-9]+:)?NameID>/);
        log.debug("Leaving GnapCells.hintOfAssertion(). A SAML assertion.");
        return m ? { kind: 'name', value: m[1].trim() } : null;
      }
    } catch (e) {
      log.debug("Caught in GnapCells.hintOfAssertion(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapCells.hintOfAssertion(). Unreadable.");
      return null;
    }
    log.debug("Leaving GnapCells.hintOfAssertion(). Another format.");
    return null;
  }

  // -------------------------------------------------------------------------
  // THE INTER-CELL OPERATIONS, answered for another cell. Each runs in the
  // realm the caller names, and throws for a realm this service does not
  // have (the channel answers the caller 500, STS-CELL-0036).
  // -------------------------------------------------------------------------
  private static inRealm<T>(realmId: unknown, fn: () => T): T {
    log.debug("Entering GnapCells.inRealm().");
    const id = String(realmId || '');
    const realm = realms.get(id) || (id ? null : realms.get(realms.DEFAULT_ID));
    if (!realm) {
      log.debug("Leaving GnapCells.inRealm(). No such realm.");
      throw new Error(errorCodes.tag('STS-CELL-0165') + 'gnap: no realm "' +
                      id + '" here.');
    }
    let out: T;
    realms.run(realm, function () {
      out = fn();
    });
    log.debug("Leaving GnapCells.inRealm().");
    return out;
  }

  /**
   * `gnap-locate`: whether this cell holds an access token (by the digest of
   * its value), a live user code, or a user reference (by its digest).
   *
   * @param body - `{ realm, kind, value }`
   * @returns `{ held }`
   */
  locate(body: any): { held: boolean } {
    log.debug("Entering GnapCells.locate().");
    const kind = String((body && body.kind) || '');
    const value = String((body && body.value) || '');
    const held = GnapCells.inRealm(body && body.realm, function () {
      if (!value) {
        return false;
      }
      if (kind === 'token') {
        return store.holdsTokenDigest(value);
      }
      if (kind === 'user-code') {
        return !!store.grantByUserCode(value);
      }
      if (kind === 'user-ref') {
        return store.holdsUserRefDigest(value);
      }
      throw new Error(errorCodes.tag('STS-CELL-0165') + 'gnap: nothing ' +
                      'called "' + kind + '" is located between cells.');
    });
    log.debug("Leaving GnapCells.locate(). " + held);
    return { held: held };
  }

  /**
   * `gnap-surrender-grant`: hands a grant waiting at an interaction handle to
   * the cell the resource owner's browser is pinned to, and forgets it here.
   *
   * @param body - `{ realm, key, to }`
   * @returns a promise of `{ bundle }`, or `{ why }` when it is not handed
   *   over
   */
  surrender(body: any): Promise<any> {
    log.debug("Entering GnapCells.surrender().");
    const self = this;
    const to = String((body && body.to) || '');
    const key = String((body && body.key) || '');
    if (!to || to === cells.id() || !cells.get(to) ||
        !/^(approve|redirect|app):/.test(key)) {
      log.debug("Leaving GnapCells.surrender(). Malformed.");
      return Promise.reject(new Error(errorCodes.tag('STS-CELL-0165') +
        'gnap: a grant can be handed only to another cell of this service, ' +
        'by an interaction handle.'));
    }
    const out: any = GnapCells.inRealm(body.realm, function () {
      const grant = store.grantByInteraction(key);
      if (!grant) {
        return { why: 'no grant waits at that handle here' };
      }
      if ((grant.tokens && grant.tokens.length) || !grant.interaction ||
          grant.state !== store.STATE.PENDING) {
        return { why: 'the grant is not waiting for its resource owner, or ' +
                      'has issued tokens, which stay where they were minted' };
      }
      const bundle = store.exportGrant(grant);
      store.forgetGrant(bundle);
      const keys = [grant.id].concat(Object.keys(bundle.interactions));
      const until = Math.max(Number(grant.expiresAt) || 0,
                             helpers.nowSec()) + MOVED_GRACE_S;
      self.recordMove(keys, to, until);
      return { bundle: bundle, keys: keys, until: until };
    });
    if (!out.bundle) {
      log.debug("Leaving GnapCells.surrender(). Not handed over.");
      return Promise.resolve({ why: out.why });
    }
    log.info('gnap: a grant waiting for its resource owner was handed to ' +
             'cell "' + to + '", where the browser signing in is pinned ' +
             '(#98 D9); its continuation is forwarded there.');
    // EVERY OTHER CELL IS TOLD, so a continuation reaching any of them is
    // sent to the new cell in one hop. Not awaited by the pinned cell's
    // answer: a cell that has not heard relays by the id's tag to this
    // cell, which forwards.
    const channel = require('../common/cell_channel');
    const realm = String(body.realm || '');
    cells.peers().filter(function (peer: any) {
      return peer.id !== to;
    }).forEach(function (peer: any) {
      channel.call(peer.id, 'gnap-grant-moved', { realm: realm,
                                                  keys: out.keys, to: to,
                                                  until: out.until })
        .then(null, function (err: any) {
          log.warn(errorCodes.tag('STS-CELL-0164') + 'gnap: cell "' +
                   peer.id + '" could not be told a grant moved to cell "' +
                   to + '" (' + ((err && err.message) || err) + '); a ' +
                   'continuation it receives goes to this cell by the ' +
                   'grant\'s tag and is forwarded from here.');
        });
    });
    log.debug("Leaving GnapCells.surrender(). Handed over.");
    return Promise.resolve({ bundle: out.bundle });
  }

  /**
   * `gnap-grant-moved`: records where a grant another cell handed over went.
   *
   * @param body - `{ realm, keys, to, until }`
   * @returns `{ recorded }`
   */
  moved(body: any): { recorded: boolean } {
    log.debug("Entering GnapCells.moved().");
    const self = this;
    const to = String((body && body.to) || '');
    const keys = Array.isArray(body && body.keys)
      ? body.keys.map(String).slice(0, 16) : [];
    const until = Number(body && body.until) || 0;
    if (!to || !cells.get(to) || !keys.length || until <= helpers.nowSec()) {
      log.debug("Leaving GnapCells.moved(). Nothing to record.");
      return { recorded: false };
    }
    if (to === cells.id()) {
      // This cell holds it now; nothing to forward.
      log.debug("Leaving GnapCells.moved(). It is here.");
      return { recorded: false };
    }
    GnapCells.inRealm(body.realm, function () {
      self.recordMove(keys, to, until);
    });
    log.debug("Leaving GnapCells.moved().");
    return { recorded: true };
  }
}

const gnapCells = new GnapCells();

// The three questions another cell asks this one (#98 fan-out). Registered
// when this module is loaded, as `oauth-oidc/par.ts` registers its own; the
// channel is a library and registering binds nothing.
const channelForOps = require('../common/cell_channel');
channelForOps.registerOp('gnap-locate', function (body: any) {
  return gnapCells.locate(body);
});
channelForOps.registerOp('gnap-surrender-grant', function (body: any) {
  return gnapCells.surrender(body);
});
channelForOps.registerOp('gnap-grant-moved', function (body: any) {
  return gnapCells.moved(body);
});

/**
 * Where a GNAP request is served in a service deployed as cells (#98): the
 * placement of each door, and the operations the other cells ask.
 * @namespace
 */
export = {
  GnapCells: GnapCells,
  stays: GnapCells.stays,
  placeGrantRequest: (req: any, res: any): Promise<boolean> =>
    gnapCells.placeGrantRequest(req, res),
  placeContinuation: (req: any, res: any, grantId: string): Promise<boolean> =>
    gnapCells.placeContinuation(req, res, grantId),
  placeInteraction: (req: any, res: any, key: string): Promise<boolean> =>
    gnapCells.placeInteraction(req, res, key),
  placeUserCode: (req: any, res: any, code: string): Promise<boolean> =>
    gnapCells.placeUserCode(req, res, code),
  placeToken: (req: any, res: any, value: string,
               reason: string): Promise<boolean> =>
    gnapCells.placeToken(req, res, value, reason),
  placeIntrospection: (req: any, res: any): Promise<boolean> =>
    gnapCells.placeIntrospection(req, res),
  placeResourceServer: (req: any, res: any): boolean =>
    gnapCells.placeResourceServer(req, res),
  locate: (body: any) => gnapCells.locate(body),
  surrender: (body: any): Promise<any> => gnapCells.surrender(body),
  moved: (body: any) => gnapCells.moved(body),
  subjectHint: GnapCells.subjectHint,
  userReferences: GnapCells.userReferences,
  jwsJti: GnapCells.jwsJti
};
