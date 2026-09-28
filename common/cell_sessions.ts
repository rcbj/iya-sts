// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_sessions.ts
//
// ---------------------------------------------------------------------------
// A SESSION HELD AWAY FROM ITS PERSON'S HOME (#98 D4, D6, D9, 2026-09-28).
//
// A traveller authenticates at home (D9's restart), and every request of
// theirs is then relayed there — slower, and lawful under the strict default.
// Where the transfer policy PERMITS the session to be held in the cell the
// traveller is actually reaching (`cell_transfer.ts`'s `holdDecision()`,
// asked of the issuance policy), this module moves it there:
//
//   * **EXPORT, at home.** A request relayed FROM another cell, carrying a
//     session of a person homed here, is the moment: the session and a
//     PROJECTION of the person are COPIED to that cell (`adopt-session`), the
//     browser's pin is moved there on this very response, and home records
//     the export so it can reach that cell again. Home keeps its own copy —
//     the portal, which manages the person's entry, is always served at home
//     and is relayed there with the same cookie.
//   * **THE PROJECTION** is the person's entry with every credential taken
//     out (passwords, second-factor secrets, private keys, one-time tokens —
//     `credentialFree()`), and `memberOf` set to the groups home says they
//     are in. It is held in a minted store sealed under the visiting cell's
//     own key (`cells.projections`, cell tier), for as long as the session
//     may live, and put into every process's in-memory directory WITHOUT
//     becoming a directory row there (`persistence.materializeEntry()`), so
//     every protocol module reads the person as it always has. It never
//     answers "is this person homed here" (`isProjected()`), so a sign-in
//     or step-up for them still restarts at home.
//   * **A WRITE TO IT GOES HOME.** A consent recorded, a profile value a flow
//     sets: the tiered driver never writes a projected entry and hands the
//     change here, which sends the changed attributes home
//     (`projection-write`). A credential attribute in such a change is
//     refused at home.
//   * **HOME IS AUTHORITATIVE (D6).** A change to the person at home — a
//     disable, a password change, a sign-out everywhere — is pushed to every
//     cell that holds an export (`revoke-subject`, or `refresh-projection`
//     for a change that ends nothing), and the visiting cell ALSO asks home
//     (`subject-state`) before a refresh, a token exchange or whenever the
//     last answer is older than `cells.subjectCheckS`. Home unreachable is
//     fail-closed unless `cells.homeUnreachable` says otherwise.
//
// **WHAT A SESSION CARRIES ACROSS IS MINIMISED**: its identity, its
// authentication events' method, level, time and door, and none of their
// context — no address, no user agent, no fingerprint, no credential id. The
// context stays in the risk history at home, where it was recorded.
//
// A LIBRARY with no route. It registers its operations on the inter-cell
// channel, its hooks on the tiered driver, and a middleware `app.js`
// installs. Everything beyond the leaves is required lazily.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('./config');
import realms = require('./realms');
import cells = require('./cells');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-sessions' });

// A projection's origin marker, which the tiered driver reads.
const PROJECTION_ORIGIN = 'projection';
// Attribute names that are credentials, or one-time material, and never
// leave home. A pattern AND a list: the pattern catches a credential added
// later under a name nobody thought to list, which is the direction to fail.
const CREDENTIAL_PATTERN =
  /password|privatekey|secret|token|credential|backupcodes|eabkey|challenge|krb5key|otp|webauthn|pwdhistory/i;
const CREDENTIAL_ATTRIBUTES = ['userpassword', 'stswebauthncredential',
  'ststotpcredential', 'stsbackupcodes', 'stsactivationtoken',
  'stsactivationexpires', 'stspasswordresettoken', 'stspasswordresetexpires',
  'stsmailverifytoken', 'stsmailverifyexpires', 'stsassertionprivatekey',
  'stssamlassertionprivatekey', 'stsenrolledprivatekey', 'stsacmeeabkey',
  'stsscepchallenge', 'stsapppassword'];

// realm id -> uuid -> the projection held here.
const projections = realms.map({
  persist: 'cells.projections',
  reconcile: {
    // A projection another process of this cell stored: put it into this
    // process's directory too. A reconciler that throws applies nothing.
    restore: function (key: string, value: any, held: any, realmId: string) {
      log.debug("Entering the projection restore reconciler.");
      CellSessions.materialize(realmId, value);
      log.debug("Leaving the projection restore reconciler.");
      return value;
    },
    remove: function (key: string, held: any, realmId: string) {
      log.debug("Entering the projection remove reconciler.");
      if (held) {
        CellSessions.dematerialize(realmId, held);
      }
      log.debug("Leaving the projection remove reconciler.");
      return true;
    }
  }
});

// realm id -> uuid -> { cells: { <cell>: { at } }, pwdChangedTime } at home.
const exports_ = realms.map({ persist: 'cells.exports' });

// `${realm}|${uuid}` -> { at, state }: home's last answer, in this process.
const confirmed = new Map<string, { at: number; state: string }>();

/**
 * Sessions held away from their person's home: export, the projection,
 * writes sent home, and home's authority over both.
 */
class CellSessions {
  /**
   * Builds the module's state. Registers nothing until `install()`.
   */
  constructor() {
    log.debug("Entering CellSessions.constructor().");
    log.debug("Leaving CellSessions.constructor().");
  }

  // -------------------------------------------------------------------------
  // THE PROJECTION.
  // -------------------------------------------------------------------------
  /**
   * An entry's attributes with every credential removed.
   *
   * @param attrs - the attributes
   * @returns a copy without credential attributes
   */
  static credentialFree(attrs: Record<string, any>): Record<string, any> {
    log.debug("Entering CellSessions.credentialFree().");
    const out: Record<string, any> = {};
    Object.keys(attrs || {}).forEach(function (name) {
      const lower = name.toLowerCase();
      if (CREDENTIAL_ATTRIBUTES.indexOf(lower) >= 0 ||
          CREDENTIAL_PATTERN.test(lower)) {
        return;
      }
      out[name] = attrs[name];
    });
    log.debug("Leaving CellSessions.credentialFree().");
    return out;
  }

  private static uuidOf(attrs: Record<string, any>): string {
    log.debug("Entering CellSessions.uuidOf().");
    const key = Object.keys(attrs || {}).filter(function (one) {
      return one.toLowerCase() === 'entryuuid';
    })[0];
    const v = key ? attrs[key] : '';
    log.debug("Leaving CellSessions.uuidOf().");
    return String(Array.isArray(v) ? v[0] || '' : v || '').toLowerCase();
  }

  private static keyOf(dn: string): string {
    log.debug("Entering CellSessions.keyOf().");
    log.debug("Leaving CellSessions.keyOf().");
    return String(dn || '').trim().split(',').map(function (p) {
      return p.trim().toLowerCase();
    }).join(',');
  }

  /**
   * Puts a projection into this process's directory.
   *
   * @param realmId - the realm
   * @param projection - `{ dn, attributes, home }`
   */
  static materialize(realmId: string, projection: any): void {
    log.debug("Entering CellSessions.materialize().");
    if (!projection || !projection.dn) {
      log.debug("Leaving CellSessions.materialize(). Nothing.");
      return;
    }
    const persistence = require('../persistence/persistence');
    persistence.materializeEntry(realmId, CellSessions.keyOf(projection.dn), {
      dn: projection.dn,
      attributes: projection.attributes || {},
      origin: PROJECTION_ORIGIN + ':' + String(projection.home || '')
    });
    log.debug("Leaving CellSessions.materialize().");
  }

  /**
   * Takes a projection out of this process's directory.
   *
   * @param realmId - the realm
   * @param projection - `{ dn }`
   */
  static dematerialize(realmId: string, projection: any): void {
    log.debug("Entering CellSessions.dematerialize().");
    if (!projection || !projection.dn) {
      log.debug("Leaving CellSessions.dematerialize(). Nothing.");
      return;
    }
    require('../persistence/persistence').dematerializeEntry(
      realmId, CellSessions.keyOf(projection.dn));
    log.debug("Leaving CellSessions.dematerialize().");
  }

  /**
   * Tells whether a person is held here only as a projection — and so is NOT
   * homed here, whatever the directory says.
   *
   * @param realmId - the realm
   * @param kind - 'name' or 'uuid'
   * @param value - the login name or the entryUUID
   * @returns true for a projected person
   */
  isProjected(realmId: string, kind: string, value: string): boolean {
    log.debug("Entering CellSessions.isProjected().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellSessions.isProjected(). Single-cell.");
      return false;
    }
    const wanted = String(value || '').trim().toLowerCase();
    let found = false;
    projections.realmMap(realmId || realms.DEFAULT_ID).forEach(
      function (p: any, uuid: string) {
        if (found) {
          return;
        }
        found = kind === 'uuid' ? uuid === wanted.replace(/^urn:uuid:/, '')
                                : String(p.name || '') === wanted;
      });
    log.debug("Leaving CellSessions.isProjected(). " + found);
    return found;
  }

  /**
   * Builds the projection of a person homed here.
   *
   * @param username - their login name
   * @returns `{ dn, name, uuid, attributes, home }`, or null when they are
   *   not homed here
   */
  projectionOf(username: string): any {
    log.debug("Entering CellSessions.projectionOf().");
    const ldap = require('../ldap/ldap_server');
    const entry = ldap.existingUserEntry(username);
    if (!entry || String(entry.origin || '').indexOf(PROJECTION_ORIGIN) === 0) {
      log.debug("Leaving CellSessions.projectionOf(). Not homed here.");
      return null;
    }
    const attrs = CellSessions.credentialFree(entry.attributes || {});
    const groups = ldap.groupsOfUser(username);
    const memberOf = ((groups && groups.groups) || []).map(function (g: any) {
      return String(g.dn);
    });
    if (memberOf.length) {
      attrs.memberof = memberOf;
    }
    log.debug("Leaving CellSessions.projectionOf().");
    return {
      dn: String(entry.dn), name: String(username).toLowerCase(),
      uuid: CellSessions.uuidOf(entry.attributes || {}),
      attributes: attrs, home: cells.id()
    };
  }

  // -------------------------------------------------------------------------
  // EXPORT, AT HOME: the middleware `app.js` installs below the barrier, in
  // the process that serves the request.
  // -------------------------------------------------------------------------
  /**
   * The middleware that exports a session to the cell a relayed request
   * came from, when the transfer policy permits holding it there.
   *
   * @returns an express middleware
   */
  middleware(): (req: any, res: any, next: () => void) => void {
    log.debug("Entering CellSessions.middleware().");
    const self = this;
    log.debug("Leaving CellSessions.middleware().");
    return function cellSessionExport(req: any, res: any, next: () => void) {
      // A HOT PATH: the pair is logged only where something is decided.
      if (!cells.isMulti()) {
        next();
        return;
      }
      // A SESSION HELD HERE FOR A PERSON HOMED ELSEWHERE is confirmed with
      // home whenever the last answer is older than cells.subjectCheckS
      // (D6); one home refuses is ended here, and the request goes on as a
      // request with no session — which, for a sign-in, restarts at home.
      if (!req.stsCellRelay && projections.size) {
        self.recheckProjected(req).then(function () {
          next();
        }, function (err: any) {
          log.debug("Caught in cellSessionExport(): " +
                    ((err && err.message) || err));
          next();
        });
        return;
      }
      if (!req.stsCellRelay || !req.stsCellRelay.from) {
        next();
        return;
      }
      log.debug("Entering cellSessionExport().");
      self.maybeExport(req, res).then(function () {
        log.debug("Leaving cellSessionExport().");
        next();
      }, function (err: any) {
        log.warn(errorCodes.tag('STS-CELL-0052') + 'cells: a session could ' +
                 'not be exported to cell "' + req.stsCellRelay.from + '" (' +
                 ((err && err.message) || err) + '); it stays here and the ' +
                 'browser stays pinned here.');
        log.debug("Leaving cellSessionExport(). Not exported.");
        next();
      });
    };
  }

  // The periodic confirmation of a projected session in use.
  private async recheckProjected(req: any): Promise<void> {
    log.debug("Entering CellSessions.recheckProjected().");
    const authn = require('../authn/authn');
    const session = authn.sessionOf(req);
    const username = session && session.user
      ? String(session.user.username || '') : '';
    if (username && this.isProjected(realms.currentId(), 'name', username)) {
      await this.confirmSubject(realms.currentId(), username, false);
    }
    log.debug("Leaving CellSessions.recheckProjected().");
  }

  private async maybeExport(req: any, res: any): Promise<void> {
    log.debug("Entering CellSessions.maybeExport().");
    const to = String(req.stsCellRelay.from);
    // THE PORTAL STAYS AT HOME: it manages the person's own entry, which only
    // home holds, and a portal request another cell relays here is served
    // from home's copy of the session rather than being a reason to move it.
    if (/^\/portal(\/|$)/.test(String(req.path || ''))) {
      log.debug("Leaving CellSessions.maybeExport(). The portal.");
      return;
    }
    const authn = require('../authn/authn');
    const session = authn.sessionOf(req);
    const username = session && session.authenticated !== false &&
      session.user ? String(session.user.username || '') : '';
    if (!username) {
      log.debug("Leaving CellSessions.maybeExport(). No session.");
      return;
    }
    const projection = this.projectionOf(username);
    if (!projection || !projection.uuid) {
      log.debug("Leaving CellSessions.maybeExport(). Not homed here.");
      return;
    }
    const realmId = realms.currentId();
    const already = exports_.realmMap(realmId).get(projection.uuid);
    if (already && already.cells && already.cells[to] &&
        already.cells[to].sid === String(session.id)) {
      log.debug("Leaving CellSessions.maybeExport(). Already there.");
      return;
    }
    let decision: { allowed: boolean; why: string } = {
      allowed: false, why: 'no transfer decision is available' };
    try {
      decision = require('./cell_transfer').holdDecision({
        realm: realmId, subject: 'urn:uuid:' + projection.uuid,
        homeCell: cells.id(), servingCell: to });
    } catch (e) {
      log.debug("Caught in CellSessions.maybeExport(): " +
                ((e && e.message) || e));
    }
    if (!decision.allowed) {
      log.debug("Leaving CellSessions.maybeExport(). Not permitted: " +
                decision.why);
      return;
    }
    const lifetime = Math.max(60000,
                              Number(config.value('authn.sessionLifetimeS')) *
                              1000 || 28800000);
    const carried = Object.assign({}, session, {
      // Minimised — see the header.
      events: (session.events || []).map(function (e: any) {
        return { at: e.at, amr: e.amr, acr: e.acr, via: e.via };
      }),
      exportedFrom: cells.id()
    });
    await require('./cell_channel').call(to, 'adopt-session', {
      realm: realmId, session: carried,
      projection: Object.assign({}, projection,
                                { expiresAt: Date.now() + lifetime })
    });
    const held = exports_.realmMap(realmId).get(projection.uuid) ||
      { cells: {}, pwdChangedTime: '' };
    held.cells[to] = { at: Date.now(), sid: String(session.id) };
    held.name = projection.name;
    held.pwdChangedTime = CellSessions.pwdChangedTimeOf(username);
    exports_.realmMap(realmId).set(projection.uuid, held);
    // A COPY, NOT A MOVE: home keeps its session, which is what serves a
    // portal request the other cell relays here, and what a revocation made
    // here ends along with the export. The browser is pinned to the other
    // cell, so this copy answers only what that cell sends home.
    require('./cell_placement').setAffinity(req, res, realmId, to);
    log.info('cells: a session of a person homed here was exported to cell "' +
             to + '", which the transfer policy permits (' + decision.why +
             '); the browser is pinned there.');
    log.debug("Leaving CellSessions.maybeExport(). Exported.");
  }

  private static pwdChangedTimeOf(username: string): string {
    log.debug("Entering CellSessions.pwdChangedTimeOf().");
    const entry = require('../ldap/ldap_server').existingUserEntry(username);
    const v = entry && entry.attributes ? entry.attributes.pwdchangedtime : '';
    log.debug("Leaving CellSessions.pwdChangedTimeOf().");
    return String(Array.isArray(v) ? v[0] || '' : v || '');
  }

  // -------------------------------------------------------------------------
  // THE OPERATIONS, registered on the inter-cell channel by install().
  // -------------------------------------------------------------------------
  private opAdoptSession(body: any, ctx: { peer: string }): any {
    log.debug("Entering CellSessions.opAdoptSession().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    const p = body.projection;
    const s = body.session;
    if (!realm || !p || !p.uuid || !p.dn || !s || !s.id) {
      log.debug("Leaving CellSessions.opAdoptSession(). Malformed.");
      throw new Error('a malformed session export');
    }
    if (String(p.home || '') !== ctx.peer) {
      log.debug("Leaving CellSessions.opAdoptSession(). Not its home.");
      throw new Error('a projection may only be sent by its home cell');
    }
    realms.run(realm, function () {
      const projected = Object.assign({}, p, {
        attributes: CellSessions.credentialFree(p.attributes || {}) });
      projections.set(String(p.uuid), projected);
      CellSessions.materialize(realm.id || '', projected);
      require('../authn/authn').sessions.set(String(s.id), s);
    });
    confirmed.set(String(body.realm || '') + '|' + p.uuid,
                  { at: Date.now(), state: 'active' });
    log.info('cells: a session of a person homed in cell "' + ctx.peer +
             '" is held here now, with a credential-free projection.');
    log.debug("Leaving CellSessions.opAdoptSession().");
    return { adopted: true };
  }

  private opRevokeSubject(body: any, ctx: { peer: string }): any {
    log.debug("Entering CellSessions.opRevokeSubject().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    const uuid = String(body.uuid || '').toLowerCase();
    if (!realm || !uuid) {
      log.debug("Leaving CellSessions.opRevokeSubject(). Malformed.");
      throw new Error('a malformed revocation');
    }
    let ended = 0;
    realms.run(realm, function () {
      const held = projections.get(uuid);
      if (!held || String(held.home || '') !== ctx.peer) {
        return;
      }
      ended = CellSessions.endHere(String(held.name || ''),
                                   String(body.reason || 'revoked at home'));
      projections.delete(uuid);
      CellSessions.dematerialize(realm.id || '', held);
    });
    confirmed.delete(String(body.realm || '') + '|' + uuid);
    log.debug("Leaving CellSessions.opRevokeSubject(). " + ended);
    return { ended: ended };
  }

  // Everything this cell holds for a person, ended the one way this
  // service ends everything for an identity (`logout/logout.ts`).
  private static endHere(name: string, why: string): number {
    log.debug("Entering CellSessions.endHere().");
    let ended = 0;
    try {
      // A global sign-out of the identity, initiated by POLICY in CAEP's
      // words (#239): home said so. `why` is logged, not sent anywhere.
      const result = require('../logout/logout').terminate(name, null,
        { by: 'cells', initiatingEntity: 'policy' });
      ended = ((result && result.done) || []).length;
      log.info('cells: ended ' + ended + ' thing(s) held here for a person ' +
               'homed elsewhere: ' + why + '.');
    } catch (e) {
      log.warn(errorCodes.tag('STS-CELL-0053') + 'cells: what this cell ' +
               'held for a person homed elsewhere could not be ended: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving CellSessions.endHere().");
    return ended;
  }

  private opRefreshProjection(body: any, ctx: { peer: string }): any {
    log.debug("Entering CellSessions.opRefreshProjection().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    const p = body.projection;
    if (!realm || !p || !p.uuid) {
      log.debug("Leaving CellSessions.opRefreshProjection(). Malformed.");
      throw new Error('a malformed projection');
    }
    let refreshed = false;
    realms.run(realm, function () {
      const held = projections.get(String(p.uuid));
      if (!held || String(held.home || '') !== ctx.peer) {
        return;
      }
      const next = Object.assign({}, held, {
        attributes: CellSessions.credentialFree(p.attributes || {}) });
      projections.set(String(p.uuid), next);
      CellSessions.materialize(realm.id || '', next);
      refreshed = true;
    });
    log.debug("Leaving CellSessions.opRefreshProjection().");
    return { refreshed: refreshed };
  }

  private opSubjectState(body: any): any {
    log.debug("Entering CellSessions.opSubjectState().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    if (!realm) {
      log.debug("Leaving CellSessions.opSubjectState(). No realm.");
      return { state: 'missing' };
    }
    let state = 'missing';
    realms.run(realm, function () {
      const entry = require('../ldap/ldap_server')
        .entryByUuid(String(body.uuid || ''));
      if (!entry || String(entry.origin || '')
            .indexOf(PROJECTION_ORIGIN) === 0) {
        return;
      }
      const locked = entry.attributes && entry.attributes.pwdaccountlockedtime;
      state = locked && [].concat(locked).length ? 'disabled' : 'active';
    });
    log.debug("Leaving CellSessions.opSubjectState(). " + state);
    return { state: state };
  }

  // A change made in another cell to a person homed here. Only attributes
  // that are not credentials, and never the entry's name or its entryUUID.
  private opProjectionWrite(body: any, ctx: { peer: string }): any {
    log.debug("Entering CellSessions.opProjectionWrite().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    const set = body.set || {};
    if (!realm || !body.uuid || typeof set !== 'object') {
      log.debug("Leaving CellSessions.opProjectionWrite(). Malformed.");
      throw new Error('a malformed projection write');
    }
    const refused = Object.keys(set).filter(function (name) {
      const lower = name.toLowerCase();
      return CREDENTIAL_ATTRIBUTES.indexOf(lower) >= 0 ||
        CREDENTIAL_PATTERN.test(lower) || lower === 'entryuuid' ||
        lower === 'uid' || lower === 'memberof' || lower === 'objectclass';
    });
    if (refused.length) {
      log.warn(errorCodes.tag('STS-CELL-0054') + 'cells: cell "' + ctx.peer +
               '" sent a change to ' + refused.join(', ') + ' of a person ' +
               'homed here, which no other cell may write; refused.');
      log.debug("Leaving CellSessions.opProjectionWrite(). Refused.");
      throw new Error('attributes no other cell may write: ' +
                      refused.join(', '));
    }
    let written = false;
    realms.run(realm, function () {
      const ldap = require('../ldap/ldap_server');
      const entry = ldap.entryByUuid(String(body.uuid));
      if (!entry || String(entry.origin || '')
            .indexOf(PROJECTION_ORIGIN) === 0) {
        return;
      }
      const attrs = Object.assign({}, entry.attributes || {});
      Object.keys(set).forEach(function (name) {
        const lower = name.toLowerCase();
        if (set[name] === null) {
          delete attrs[lower];
        } else {
          attrs[lower] = [].concat(set[name]).map(String);
        }
      });
      const answer = ldap.writePerson(entry.dn, attrs, {});
      written = !!(answer && answer.ok);
    });
    log.debug("Leaving CellSessions.opProjectionWrite(). " + written);
    return { written: written };
  }

  // -------------------------------------------------------------------------
  // THE TIERED DRIVER'S HOOKS.
  // -------------------------------------------------------------------------
  // At the visiting cell: a flush found a projected entry changed. The
  // attributes that differ from what was projected are sent home.
  private projectionWrite(realmId: string, key: string, entry: any,
                          base: any): void {
    log.debug("Entering CellSessions.projectionWrite().");
    const home = String((entry && entry.origin) || '').split(':')[1] || '';
    const before = base ? (typeof base === 'string' ? JSON.parse(base) : base)
                        : null;
    const now = (entry && entry.attributes) || {};
    const was = (before && before.attributes) || {};
    const set: Record<string, any> = {};
    Object.keys(now).forEach(function (name) {
      if (JSON.stringify(now[name]) !== JSON.stringify(was[name])) {
        set[name] = now[name];
      }
    });
    Object.keys(was).forEach(function (name) {
      if (!(name in now)) {
        set[name] = null;
      }
    });
    delete set.memberof;
    const uuid = CellSessions.uuidOf(now) || CellSessions.uuidOf(was);
    if (!home || !uuid || !Object.keys(set).length) {
      log.debug("Leaving CellSessions.projectionWrite(). Nothing to send.");
      return;
    }
    require('./cell_channel').call(home, 'projection-write',
                                   { realm: realmId, uuid: uuid, set: set })
      .catch(function (err: any) {
        log.warn(errorCodes.tag('STS-CELL-0050') + 'cells: a change to a ' +
                 'person homed in cell "' + home + '" could not be sent ' +
                 'there (' + ((err && err.message) || err) + '); it is held ' +
                 'here only until the session ends.');
      });
    log.debug("Leaving CellSessions.projectionWrite().");
  }

  // At home: a person homed here was written. The cells holding a projection
  // of them are told — revoked if they were disabled or their password
  // changed, refreshed otherwise.
  private personWritten(realmId: string, key: string, entry: any): void {
    log.debug("Entering CellSessions.personWritten().");
    const attrs = (entry && entry.attributes) || {};
    const uuid = CellSessions.uuidOf(attrs);
    const held = uuid ? exports_.realmMap(realmId).get(uuid) : null;
    if (!held || !held.cells || !Object.keys(held.cells).length) {
      log.debug("Leaving CellSessions.personWritten(). No export.");
      return;
    }
    const lockedKey = Object.keys(attrs).filter(function (n) {
      return n.toLowerCase() === 'pwdaccountlockedtime';
    })[0];
    const changedKey = Object.keys(attrs).filter(function (n) {
      return n.toLowerCase() === 'pwdchangedtime';
    })[0];
    const locked = lockedKey && [].concat(attrs[lockedKey]).length > 0;
    const changed = changedKey ? String([].concat(attrs[changedKey])[0] || '')
                               : '';
    if (locked || (changed && changed !== String(held.pwdChangedTime || ''))) {
      this.revokeExports(realmId, uuid, locked ? 'the account was disabled'
                                               : 'the password was changed');
      log.debug("Leaving CellSessions.personWritten(). Revoked.");
      return;
    }
    const projection = this.projectionOf(String(held.name || ''));
    Object.keys(held.cells).forEach(function (cellId) {
      try {
        require('./cell_deliveries').deliver(cellId, 'refresh-projection',
                                             { realm: realmId,
                                               projection: projection });
      } catch (err) {
        log.warn(errorCodes.tag('STS-CELL-0051') + 'cells: a changed ' +
                 'projection for cell "' + cellId + '" could not be queued (' +
                 ((err && err.message) || err) + '); it asks home on its ' +
                 'next check.');
      }
    });
    log.debug("Leaving CellSessions.personWritten(). Refreshed.");
  }

  /**
   * Pushes a revocation of everything held for a person homed here to every
   * cell holding an export of them, and forgets the exports.
   *
   * @param realmId - the realm
   * @param uuid - the person's entryUUID
   * @param why - the reason, for the other cells' audit
   */
  revokeExports(realmId: string, uuid: string, why: string): void {
    log.debug("Entering CellSessions.revokeExports().");
    const held = exports_.realmMap(realmId).get(String(uuid));
    if (!held || !held.cells) {
      log.debug("Leaving CellSessions.revokeExports(). None.");
      return;
    }
    // DURABLY (`cell_deliveries.ts`): a cell that is down now is told when
    // it is back, and until then its own check against home
    // (`cells.subjectCheckS`) is the bound.
    Object.keys(held.cells).forEach(function (cellId) {
      try {
        require('./cell_deliveries').deliver(cellId, 'revoke-subject',
                                             { realm: realmId, uuid: uuid,
                                               reason: why });
      } catch (err) {
        log.warn(errorCodes.tag('STS-CELL-0055') + 'cells: a revocation for ' +
                 'cell "' + cellId + '" could not be queued (' +
                 ((err && err.message) || err) + '); it finds out at its ' +
                 'next check against home (cells.subjectCheckS).');
      }
    });
    exports_.realmMap(realmId).delete(String(uuid));
    log.debug("Leaving CellSessions.revokeExports().");
  }

  /**
   * Everything for a person was ended here — a sign-out everywhere — and so
   * it must be ended in every cell holding an export of them.
   *
   * @param realmId - the realm
   * @param username - the person
   */
  subjectTerminated(realmId: string, username: string): void {
    log.debug("Entering CellSessions.subjectTerminated().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellSessions.subjectTerminated(). Single-cell.");
      return;
    }
    const projection = this.projectionOf(username);
    if (projection && projection.uuid) {
      this.revokeExports(realmId, projection.uuid, 'signed out everywhere');
    }
    log.debug("Leaving CellSessions.subjectTerminated().");
  }

  // -------------------------------------------------------------------------
  // HOME'S AUTHORITY, ASKED AT THE VISITING CELL (D6).
  // -------------------------------------------------------------------------
  /**
   * Asks home whether a projected person may still be issued anything.
   * A person homed here, or single-cell mode, is always confirmed.
   *
   * @param realmId - the realm
   * @param username - the person
   * @param force - ask even inside `cells.subjectCheckS`
   * @returns a promise of `{ ok, why }`
   */
  async confirmSubject(realmId: string, username: string,
                       force?: boolean): Promise<{ ok: boolean; why: string }> {
    log.debug("Entering CellSessions.confirmSubject().");
    if (!cells.isMulti() || !this.isProjected(realmId, 'name', username)) {
      log.debug("Leaving CellSessions.confirmSubject(). Not projected.");
      return { ok: true, why: '' };
    }
    let held: any = null;
    projections.realmMap(realmId || realms.DEFAULT_ID).forEach(
      function (p: any) {
        if (!held && String(p.name || '') ===
            String(username || '').toLowerCase()) {
          held = p;
        }
      });
    if (!held) {
      log.debug("Leaving CellSessions.confirmSubject(). Gone.");
      return { ok: false, why: 'the person is no longer held here' };
    }
    const cacheKey = String(realmId || '') + '|' + held.uuid;
    const last = confirmed.get(cacheKey);
    const maxAgeMs = Math.max(0, Number(config.value('cells.subjectCheckS')) ||
                              0) * 1000;
    if (!force && last && last.state === 'active' &&
        Date.now() - last.at < maxAgeMs) {
      log.debug("Leaving CellSessions.confirmSubject(). Recently confirmed.");
      return { ok: true, why: '' };
    }
    try {
      const answer = await require('./cell_channel').call(
        String(held.home), 'subject-state',
        { realm: realmId, uuid: held.uuid });
      const state = String((answer && answer.state) || 'missing');
      confirmed.set(cacheKey, { at: Date.now(), state: state });
      if (state !== 'active') {
        realms.run(realms.get(realmId) || realms.get(realms.DEFAULT_ID),
          function () {
            CellSessions.endHere(String(held.name), 'home says ' + state);
            projections.delete(String(held.uuid));
            CellSessions.dematerialize(realmId, held);
          });
        log.debug("Leaving CellSessions.confirmSubject(). " + state);
        return { ok: false, why: 'the person\'s home cell says the account ' +
                                 'is ' + state };
      }
      log.debug("Leaving CellSessions.confirmSubject(). Confirmed.");
      return { ok: true, why: '' };
    } catch (err) {
      const open = String(config.value('cells.homeUnreachable')) ===
        'fail-open';
      const graceMs = Math.max(0,
                               Number(config.value('cells.failOpenGraceS')) ||
                               0) * 1000;
      if (open && last && last.state === 'active' &&
          Date.now() - last.at < graceMs) {
        log.warn(errorCodes.tag('STS-CELL-0056') + 'cells: the home cell of ' +
                 'a projected person could not be reached (' +
                 ((err && err.message) || err) + ') and ' +
                 'cells.homeUnreachable is fail-open: the last confirmation ' +
                 'is used.');
        log.debug("Leaving CellSessions.confirmSubject(). Fail-open.");
        return { ok: true, why: '' };
      }
      log.warn(errorCodes.tag('STS-CELL-0056') + 'cells: the home cell of a ' +
               'projected person could not be reached (' +
               ((err && err.message) || err) + '); refused, fail-closed.');
      log.debug("Leaving CellSessions.confirmSubject(). Fail-closed.");
      return { ok: false, why: 'the person\'s home region cannot be reached ' +
                               'to confirm the account' };
    }
  }

  /**
   * What `/admin/cells` shows: the projections held here and the exports
   * made from here, counted per realm.
   *
   * @returns `{ projections, exports }`
   */
  status(): { projections: number; exports: number } {
    log.debug("Entering CellSessions.status().");
    let p = 0;
    let x = 0;
    const ids = [realms.DEFAULT_ID].concat(realms.list().map(function (r: any) {
      return String(r.id);
    }));
    ids.forEach(function (id: string) {
      p += projections.realmMap(id).size;
      x += exports_.realmMap(id).size;
    });
    log.debug("Leaving CellSessions.status().");
    return { projections: p, exports: x };
  }

  /**
   * Registers the operations and the driver's hooks. Called once, when the
   * composition root builds the stack; a no-op in single-cell mode.
   */
  install(): void {
    log.debug("Entering CellSessions.install().");
    const self = this;
    const channel = require('./cell_channel');
    channel.registerOp('adopt-session', function (b: any, c: any) {
      return self.opAdoptSession(b, c);
    });
    channel.registerOp('revoke-subject', function (b: any, c: any) {
      return self.opRevokeSubject(b, c);
    });
    channel.registerOp('refresh-projection', function (b: any, c: any) {
      return self.opRefreshProjection(b, c);
    });
    channel.registerOp('subject-state', function (b: any) {
      return self.opSubjectState(b);
    });
    channel.registerOp('projection-write', function (b: any, c: any) {
      return self.opProjectionWrite(b, c);
    });
    log.debug("Leaving CellSessions.install().");
  }

  /**
   * The tiered driver's hook: a projected entry changed here (`persistence.js`
   * installs a forwarder to this when it opens a tiered store).
   *
   * @param realmId - the realm
   * @param key - the normalised DN
   * @param entry - the entry as it is now
   * @param base - what was last projected, a JSON string or object
   */
  onProjectionWrite(realmId: string, key: string, entry: any,
                    base: any): void {
    log.debug("Entering CellSessions.onProjectionWrite().");
    this.projectionWrite(realmId, key, entry, base);
    log.debug("Leaving CellSessions.onProjectionWrite().");
  }

  /**
   * The tiered driver's hook: a person homed here was written.
   *
   * @param realmId - the realm
   * @param key - the normalised DN
   * @param entry - the entry as written
   */
  onPersonWritten(realmId: string, key: string, entry: any): void {
    log.debug("Entering CellSessions.onPersonWritten().");
    this.personWritten(realmId, key, entry);
    log.debug("Leaving CellSessions.onPersonWritten().");
  }
}

const sessions = new CellSessions();

/**
 * Sessions held away from their person's home (#98 D4, D6, D9). A library:
 * no route.
 * @namespace
 */
export = {
  CellSessions: CellSessions,
  PROJECTION_ORIGIN: PROJECTION_ORIGIN,
  credentialFree: CellSessions.credentialFree,
  install: (): void => sessions.install(),
  onProjectionWrite: (r: string, k: string, e: any, b: any): void =>
    sessions.onProjectionWrite(r, k, e, b),
  onPersonWritten: (r: string, k: string, e: any): void =>
    sessions.onPersonWritten(r, k, e),
  middleware: () => sessions.middleware(),
  isProjected: (realmId: string, kind: string, value: string): boolean =>
    sessions.isProjected(realmId, kind, value),
  projectionOf: (username: string) => sessions.projectionOf(username),
  confirmSubject: (realmId: string, username: string, force?: boolean) =>
    sessions.confirmSubject(realmId, username, force),
  revokeExports: (realmId: string, uuid: string, why: string): void =>
    sessions.revokeExports(realmId, uuid, why),
  subjectTerminated: (realmId: string, username: string): void =>
    sessions.subjectTerminated(realmId, username),
  status: () => sessions.status()
};
