// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: scim_cells.ts
//
// ---------------------------------------------------------------------------
// WHICH CELL ANSWERS A SCIM REQUEST (#98 D1, D10, D11, 2026-09-28).
//
// A person is homed in one cell and their entry exists only there
// (`common/cells.ts`). SCIM writes and reads PEOPLE, so a SCIM request that
// names somebody has to be answered where they are homed, and this module
// says where that is — asked by `scim.ts`'s `handle()` BEFORE the caller is
// authenticated, because a Digest nonce count and a HOBA signature are spent
// where they are checked, and the cell that owns the request is the one that
// must spend them (`common/cell_placement.ts`, *the handler helpers*).
//
// **WHAT DECIDES, PER OPERATION:**
//
//   * `GET|PUT|PATCH|DELETE /Users/{id}` — the id is the person's
//     `entryUUID` (`CLAUDE.md`, *The `id` is the entry's `entryUUID`*), and
//     the global routing index has a row for it: relayed to the home cell. A
//     DN presented as an id (the pre-2026-09-14 spelling) is routed by its RDN
//     value, which is the login name the index also keys.
//   * `POST /Users` — a NEW person, whose home is `cells.homeFor()`: the cell
//     the resource names in this service's User extension
//     (`urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User:homeCell`,
//     below), else the realm's `cells.homeCell`, else the cell the request
//     reached. A named cell that does not exist or is outside the realm's
//     jurisdictions is refused (`STS-CELL-0140`) rather than placed somewhere
//     else — a person silently homed where nobody asked is the one outcome a
//     residency rule cannot have. Another cell: the create is relayed there
//     whole, and THAT cell claims the login name in the routing index before
//     it writes (`ingressRefusal()`, `STS-CELL-0142` when the name is homed
//     elsewhere). The claim is made by the cell that creates, not the one
//     that relays, so a relay that fails leaves no claim behind naming a cell
//     that never made the person.
//   * `POST|PUT|PATCH /Groups…` naming members — a group's DEFINITION is
//     global and its person MEMBERSHIP is resident (`persistence/tiers.js`),
//     so a write that adds or removes people is a write in their home cell.
//     Members homed in one other cell: relayed there. Members homed in more
//     than one cell: REFUSED (`STS-CELL-0143`) — one request is answered by
//     one cell, and splitting it would answer the client with one cell's
//     result for a write half of which happened somewhere else. The client
//     sends one request per cell's members (a PATCH `add` per cell is the
//     natural shape). A PUT at a cell replaces THAT cell's share of the
//     membership and the global definition; the other cells' shares stand.
//   * `POST /Bulk` — every operation is placed as it would be on its own
//     (a `bulkId:` reference to a create in the same request is placed with
//     that create). All in one other cell: the whole request is relayed
//     there. Spanning cells: the whole request is REFUSED (`STS-CELL-0144`)
//     before any operation runs. RFC 7644 section 3.7 lets a service
//     provider fail a BulkRequest as a whole, and answering one with some
//     operations performed in another region by a different request would
//     break section 3.7.3's promise that `bulkId` references resolve inside
//     one request; splitting and merging responses is the alternative this
//     refuses to build.
//   * `GET /Users`, `GET /Groups`, `.search` — the SERVING cell's residents
//     (D11). RFC 7644 section 3.4.2 defines the query parameters of a list and
//     leaves no room for "in another region": an extra parameter would be a
//     vocabulary no SCIM client sends. The cross-cell door is the console's
//     and `/admin-api`'s `?cell=` selector, which is placed at the edge.
//   * `/Me` with a bearer token is placed at the EDGE (the token names the
//     cell that minted it — `cell_placement.ts`'s `bearer` row); with HTTP
//     Basic it is routed here by the user name the credential carries.
//   * `POST /.well-known/hoba/register` names its person by `username`:
//     relayed to their home, and a NEW name to where a new person is homed.
//
// **A REQUEST THAT ARRIVED RELAYED IS NEVER RELAYED AGAIN** (one hop,
// `cell_channel.ts`); anything it names that is not here is then answered
// here, the way an unknown person always was — and a create is refused at the
// ingress rather than made in a cell that is not its home.
//
// **SINGLE-CELL MODE PLACES NOTHING**: `place()` answers "here" before it
// reads anything, and the extension attribute is accepted and ignored.
//
// A LIBRARY: no route. `scim.ts` asks it.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('../common/cells');
import cellRouting = require('../common/cell_routing');
import cellPlacement = require('../common/cell_placement');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-scim-cells' });

// This service's own User extension (`scim_map.ts`'s IYA_STS_USER_SCHEMA),
// written out rather than required: this module is a leaf the tests load
// without the SCIM stack.
const USER_EXTENSION =
  'urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User';
// The member of that extension naming the cell a new person is homed in.
const HOME_CELL = 'homeCell';
// A SCIM id: an entryUUID, bare or as a URN.
const UUID_SHAPED =
  /^(?:urn:uuid:)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A person as the routing index keys them: an entryUUID or a login name.
 */
interface PersonKey {
  kind: 'uuid' | 'name';
  value: string;
}

/**
 * What `place()` decided when it did not relay: served here, or refused with
 * a SCIM error `scim.ts` sends.
 */
interface Placement {
  relayed: boolean;
  refusal?: { status: number; scimType: string | null; detail: string;
              code: string };
}

/**
 * Where a SCIM request is answered in a service deployed as cells.
 */
class ScimCells {
  /**
   * Builds the placement. It holds nothing.
   */
  constructor() {
    log.debug("Entering ScimCells.constructor().");
    log.debug("Leaving ScimCells.constructor().");
  }

  /**
   * The home cell a User resource names in this service's extension.
   *
   * @param resource - the resource as sent (or as scimmy coerced it)
   * @returns the cell id, or ''
   */
  static homeCellAsked(resource: any): string {
    log.debug("Entering ScimCells.homeCellAsked().");
    const extension = resource && typeof resource === 'object'
      ? resource[USER_EXTENSION] : null;
    const value = extension && typeof extension === 'object'
      ? extension[HOME_CELL] : undefined;
    log.debug("Leaving ScimCells.homeCellAsked().");
    return typeof value === 'string' ? value.trim() : '';
  }

  /**
   * How the routing index keys the person a SCIM id names.
   *
   * @param id - an entryUUID (bare or `urn:uuid:`) or, from a client that
   *   stored one before 2026-09-14, a DN
   * @returns the key, or null for anything else (a `bulkId:` reference)
   */
  static personKey(id: unknown): PersonKey | null {
    log.debug("Entering ScimCells.personKey().");
    const text = String(id == null ? '' : id).trim();
    if (UUID_SHAPED.test(text)) {
      log.debug("Leaving ScimCells.personKey(). A UUID.");
      return { kind: 'uuid',
               value: text.toLowerCase().replace(/^urn:uuid:/, '') };
    }
    const rdn = /^[A-Za-z][A-Za-z0-9-]*=([^,+]+)(?:[,+]|$)/.exec(text);
    if (rdn && text.indexOf(',') > 0) {
      log.debug("Leaving ScimCells.personKey(). A DN.");
      return { kind: 'name', value: rdn[1].replace(/\\(.)/g, '$1').trim() };
    }
    log.debug("Leaving ScimCells.personKey(). Nothing to route by.");
    return null;
  }

  /**
   * The member ids a Group write names: `members[].value` of a resource, and
   * of a PatchOp every operation's value and every `members[value eq "…"]`
   * path.
   *
   * @param body - the parsed body
   * @returns the ids, possibly none
   */
  static memberIds(body: any): string[] {
    log.debug("Entering ScimCells.memberIds().");
    const out: string[] = [];
    const take = function (members: any) {
      log.debug("Entering take().");
      (Array.isArray(members) ? members : [members]).forEach(function (m) {
        if (m && typeof m === 'object' && m.value !== undefined) {
          out.push(String(m.value));
        }
      });
      log.debug("Leaving take().");
    };
    if (body && typeof body === 'object') {
      take(body.members);
      const ops = Array.isArray(body.Operations) ? body.Operations : [];
      ops.forEach(function (op: any) {
        if (!op || typeof op !== 'object') {
          return;
        }
        const path = String(op.path || '');
        const named = /value\s+eq\s+"([^"]+)"/i.exec(path);
        if (named) {
          out.push(named[1]);
        }
        if (/^members$/i.test(path)) {
          take(op.value);
        } else if (!path && op.value && typeof op.value === 'object') {
          take(op.value.members);
        }
      });
    }
    log.debug("Leaving ScimCells.memberIds(). " + out.length);
    return out;
  }

  // The body, parsed, or null. Never throws: a body that is not JSON is
  // refused by the handler in its own words, at the cell that serves it.
  private static parsed(req: any): any {
    log.debug("Entering ScimCells.parsed().");
    const raw = typeof req.body === 'string' ? req.body
      : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
    let out: any = null;
    try {
      out = raw.trim() ? JSON.parse(raw) : null;
    } catch (e) {
      log.debug("Caught in ScimCells.parsed(): " + ((e && e.message) || e));
      out = null;
    }
    log.debug("Leaving ScimCells.parsed().");
    return out;
  }

  // The home of one person key: this cell's id, another's, or '' for a
  // person nobody knows.
  private homeOfKey(realmId: string, key: PersonKey | null): Promise<string> {
    log.debug("Entering ScimCells.homeOfKey().");
    log.debug("Leaving ScimCells.homeOfKey().");
    return key ? cellRouting.homeOf(realmId, key.kind, key.value)
               : Promise.resolve('');
  }

  // The cells a list of member ids is homed in, this one included; unknown
  // members are left out.
  private async cellsOfMembers(realmId: string,
                               ids: string[]): Promise<string[]> {
    log.debug("Entering ScimCells.cellsOfMembers().");
    const homes = await Promise.all(ids.map((id) =>
      this.homeOfKey(realmId, ScimCells.personKey(id))));
    const out = homes.filter(function (h, i, all) {
      return !!h && all.indexOf(h) === i;
    });
    log.debug("Leaving ScimCells.cellsOfMembers(). " + out.join(','));
    return out;
  }

  // The cell a create of a new User is homed in, or a refusal.
  private static createHome(resource: any): { cell?: string;
                                              error?: string } {
    log.debug("Entering ScimCells.createHome().");
    const home: any = cells.homeFor(ScimCells.homeCellAsked(resource));
    log.debug("Leaving ScimCells.createHome().");
    return home.error ? { error: String(home.error) }
                      : { cell: String(home.cell || '') };
  }

  // The cells ONE operation belongs to — a User or Group path, a method and
  // its data, which is what a request and a Bulk operation both are. An
  // array of the cells it touches (possibly none: served wherever), or a
  // refusal.
  private async cellsOf(realmId: string, type: string, method: string,
                        id: string, body: any):
      Promise<{ cells: string[]; refusal?: Placement['refusal'] }> {
    log.debug("Entering ScimCells.cellsOf(). " + method + " " + type);
    const m = method.toUpperCase();
    if (type === 'User' && m === 'POST' && !id) {
      const home = ScimCells.createHome(body);
      if (home.error) {
        log.debug("Leaving ScimCells.cellsOf(). The home is refused.");
        return { cells: [], refusal: { status: 400, scimType: 'invalidValue',
          code: 'STS-CELL-0140',
          detail: 'This person cannot be homed where asked: ' + home.error +
                  '. The home cell is ' + USER_EXTENSION + ':' + HOME_CELL +
                  ', or the realm\'s default when that is not sent.' } };
      }
      log.debug("Leaving ScimCells.cellsOf(). A create.");
      return { cells: [home.cell as string] };
    }
    if (type === 'User' && id) {
      const home = await this.homeOfKey(realmId, ScimCells.personKey(id));
      log.debug("Leaving ScimCells.cellsOf(). A person.");
      return { cells: home ? [home] : [] };
    }
    if (type === 'Group' && m !== 'GET' && m !== 'DELETE') {
      const found = await this.cellsOfMembers(realmId,
                                              ScimCells.memberIds(body));
      log.debug("Leaving ScimCells.cellsOf(). A group's members.");
      return { cells: found };
    }
    log.debug("Leaving ScimCells.cellsOf(). Anywhere.");
    return { cells: [] };
  }

  // Every operation of a BulkRequest, placed. A `bulkId:` reference is
  // placed with the create it names, which `cellsOf()` already placed.
  private async cellsOfBulk(realmId: string, body: any):
      Promise<{ cells: string[]; refusal?: Placement['refusal'] }> {
    log.debug("Entering ScimCells.cellsOfBulk().");
    const ops = body && Array.isArray(body.Operations) ? body.Operations : [];
    const all: string[] = [];
    for (const op of ops) {
      if (!op || typeof op !== 'object') {
        continue;
      }
      const path = String(op.path || '');
      const m = /^\/(Users|Groups)(?:\/([^/?]+))?/.exec(path);
      if (!m) {
        continue;
      }
      const type = m[1] === 'Users' ? 'User' : 'Group';
      const id = m[2] ? decodeURIComponent(m[2]) : '';
      const one = await this.cellsOf(realmId, type, String(op.method || ''),
                                     /^bulkId:/.test(id) ? '' : id,
                                     op.data);
      if (one.refusal) {
        log.debug("Leaving ScimCells.cellsOfBulk(). An operation refused.");
        return one;
      }
      one.cells.forEach(function (c) {
        if (all.indexOf(c) < 0) {
          all.push(c);
        }
      });
    }
    log.debug("Leaving ScimCells.cellsOfBulk(). " + all.join(','));
    return { cells: all };
  }

  /**
   * Decides which cell answers a SCIM request and relays it there when that
   * is another cell. Called before the caller is authenticated.
   *
   * @param req - the request, its body read as text
   * @param res - the response
   * @param info - `{ operation, resourceType }` as `scim.ts` names the route
   * @param realmId - the realm
   * @returns a promise of `{ relayed }`, with a `refusal` to send when the
   *   request cannot be placed
   */
  async place(req: any, res: any, info: { operation: string;
                                          resourceType: string },
              realmId: string): Promise<Placement> {
    log.debug("Entering ScimCells.place(). " + info.operation + " " +
              info.resourceType);
    if (!cells.isMulti() || req.stsCellRelay) {
      log.debug("Leaving ScimCells.place(). Here.");
      return { relayed: false };
    }
    const here = cells.id();
    const id = req.params && req.params.id ? String(req.params.id) : '';
    // /Me over HTTP Basic: the user name in the credential. A bearer token
    // was placed at the edge by the cell that minted it.
    if (info.resourceType === 'Self') {
      const basic = /^Basic\s+(\S+)$/i.exec(
        String((req.headers && req.headers.authorization) || '').trim());
      const user = basic ? Buffer.from(basic[1], 'base64').toString('utf8')
        .split(':')[0] : '';
      const relayed = user
        ? await cellPlacement.relayToHome(req, res, realmId, 'name', user,
                                          'scim-me')
        : false;
      log.debug("Leaving ScimCells.place(). /Me.");
      return { relayed: relayed };
    }
    // A single person by id: the placement helper's own lookup.
    if (info.resourceType === 'User' && id) {
      const key = ScimCells.personKey(id);
      const relayed = key
        ? await cellPlacement.relayToHome(req, res, realmId, key.kind,
                                          key.value, 'scim-' + info.operation)
        : false;
      log.debug("Leaving ScimCells.place(). A person by id.");
      return { relayed: relayed };
    }
    let placed: { cells: string[]; refusal?: Placement['refusal'] };
    if (info.resourceType === 'Bulk') {
      placed = await this.cellsOfBulk(realmId, ScimCells.parsed(req));
    } else if ((info.resourceType === 'User' ||
                info.resourceType === 'Group') &&
               ['create', 'replace', 'modify'].indexOf(info.operation) >= 0) {
      placed = await this.cellsOf(realmId, info.resourceType,
                                  String(req.method || ''), id,
                                  ScimCells.parsed(req));
    } else {
      log.debug("Leaving ScimCells.place(). Served here (D11).");
      return { relayed: false };
    }
    if (placed.refusal) {
      log.debug("Leaving ScimCells.place(). Refused.");
      return { relayed: false, refusal: placed.refusal };
    }
    if (placed.cells.length > 1) {
      const bulk = info.resourceType === 'Bulk';
      log.info('scim: a ' + (bulk ? 'BulkRequest' : 'Group write') +
               ' names people homed in cells ' + placed.cells.join(', ') +
               ' and is refused whole (#98).');
      log.debug("Leaving ScimCells.place(). Spans cells.");
      return { relayed: false, refusal: { status: 400,
        scimType: 'invalidValue',
        code: bulk ? 'STS-CELL-0144' : 'STS-CELL-0143',
        detail: bulk
          ? 'The operations of this BulkRequest belong to people homed in ' +
            'different regions of this service, and one BulkRequest is ' +
            'performed in one region. Nothing was done. Send one ' +
            'BulkRequest per region\'s people.'
          : 'This Group write names members homed in different regions of ' +
            'this service, and a group\'s membership is written where each ' +
            'member is homed. Nothing was changed. Send one request per ' +
            'region\'s members.' } };
    }
    const target = placed.cells[0] || '';
    if (!target || target === here || !cells.get(target)) {
      log.debug("Leaving ScimCells.place(). Here.");
      return { relayed: false };
    }
    await require('../common/cell_channel').relay(req, res, target, {
      reason: 'scim-' + info.operation,
      body: cellPlacement.serialisedBody(req)
    });
    log.debug("Leaving ScimCells.place(). Relayed to " + target + ".");
    return { relayed: true };
  }

  /**
   * The check a User ingress makes at the cell that writes: a create is
   * homed here and its login name is claimed in the routing index first; an
   * update does not ask to move the person.
   *
   * @param data - the resource being written
   * @param isCreate - whether it is a create
   * @param realmId - the realm
   * @returns a promise of null, or a refusal `{ status, scimType, detail,
   *   code }`
   */
  async ingressRefusal(data: any, isCreate: boolean,
                       realmId: string): Promise<Placement['refusal'] | null> {
    log.debug("Entering ScimCells.ingressRefusal().");
    if (!cells.isMulti()) {
      log.debug("Leaving ScimCells.ingressRefusal(). Single-cell.");
      return null;
    }
    const here = cells.id();
    const asked = ScimCells.homeCellAsked(data);
    if (!isCreate) {
      // RE-HOMING IS AN ADMINISTRATOR'S ACT (#98 §4), copying the entry and
      // deleting it, audited at both ends — not a member a provisioning
      // client can PUT. Naming the cell the person is already in is fine.
      if (asked && asked !== here) {
        log.debug("Leaving ScimCells.ingressRefusal(). A re-home.");
        return { status: 400, scimType: 'mutability', code: 'STS-CELL-0145',
          detail: USER_EXTENSION + ':' + HOME_CELL + ' names another ' +
                  'region, and a person is moved between regions only by ' +
                  'an administrator\'s re-homing, never by a SCIM write. ' +
                  'Nothing was changed.' };
      }
      log.debug("Leaving ScimCells.ingressRefusal(). An update.");
      return null;
    }
    const home = ScimCells.createHome(data);
    if (home.error) {
      log.debug("Leaving ScimCells.ingressRefusal(). Home refused.");
      return { status: 400, scimType: 'invalidValue', code: 'STS-CELL-0140',
        detail: 'This person cannot be homed where asked: ' + home.error +
                '.' };
    }
    if (home.cell !== here) {
      // A create placed here anyway: it arrived relayed from a cell whose
      // settings disagree with this one's, or inside a BulkRequest that
      // arrived relayed. Refused rather than made in the wrong region.
      log.debug("Leaving ScimCells.ingressRefusal(). Not its home.");
      return { status: 400, scimType: 'invalidValue', code: 'STS-CELL-0141',
        detail: 'This person is homed in region "' + home.cell + '", and ' +
                'the request was answered by another. Nothing was created; ' +
                'send it again.' };
    }
    const name = String((data && data.userName) || '').trim();
    let claimed: { ok: boolean; cell?: string };
    try {
      claimed = await cellRouting.claimName(realmId, name, here);
    } catch (e) {
      log.error(errorCodes.tag('STS-CELL-0146') + 'scim: the routing index ' +
                'could not be asked to claim a login name: ' +
                ((e && e.message) || e) + '. The create is refused.');
      log.debug("Leaving ScimCells.ingressRefusal(). The index failed.");
      return { status: 500, scimType: null, code: 'STS-CELL-0146',
        detail: 'The login name could not be reserved just now; nothing ' +
                'was created. Try again.' };
    }
    if (!claimed.ok) {
      log.debug("Leaving ScimCells.ingressRefusal(). Homed elsewhere.");
      return { status: 409, scimType: 'uniqueness', code: 'STS-CELL-0142',
        detail: 'A person called "' + name + '" already exists in this ' +
                'realm, in another region of this service. Nothing was ' +
                'created.' };
    }
    log.debug("Leaving ScimCells.ingressRefusal(). Claimed.");
    return null;
  }

  /**
   * Places a HOBA key registration, which names its person by `username`:
   * at their home, or — for a name nobody holds — where a new person is
   * homed.
   *
   * @param req - the request, its body parsed or text
   * @param res - the response
   * @param realmId - the realm
   * @param username - the name the registration is for
   * @returns a promise of true when the request was relayed
   */
  async placeHobaRegistration(req: any, res: any, realmId: string,
                              username: string): Promise<boolean> {
    log.debug("Entering ScimCells.placeHobaRegistration().");
    if (!cells.isMulti() || req.stsCellRelay || !username) {
      log.debug("Leaving ScimCells.placeHobaRegistration(). Here.");
      return false;
    }
    const home = await cellRouting.homeOf(realmId, 'name', username);
    const target = home || String((ScimCells.createHome(null).cell) || '');
    if (!target || target === cells.id() || !cells.get(target)) {
      log.debug("Leaving ScimCells.placeHobaRegistration(). Here.");
      return false;
    }
    await require('../common/cell_channel').relay(req, res, target, {
      reason: 'hoba-register', body: cellPlacement.serialisedBody(req)
    });
    log.debug("Leaving ScimCells.placeHobaRegistration(). Relayed.");
    return true;
  }
}

const scimCells = new ScimCells();

/**
 * Where a SCIM request is answered in a service deployed as cells (#98): the
 * placement `scim.ts` asks before it authenticates, the check a User ingress
 * makes before it writes, and the extension member naming a new person's
 * home. A library: no route.
 * @namespace
 */
export = {
  ScimCells: ScimCells,
  USER_EXTENSION: USER_EXTENSION,
  HOME_CELL: HOME_CELL,
  homeCellAsked: ScimCells.homeCellAsked,
  personKey: ScimCells.personKey,
  memberIds: ScimCells.memberIds,
  place: (req: any, res: any, info: { operation: string;
                                      resourceType: string },
          realmId: string) => scimCells.place(req, res, info, realmId),
  ingressRefusal: (data: any, isCreate: boolean, realmId: string) =>
    scimCells.ingressRefusal(data, isCreate, realmId),
  placeHobaRegistration: (req: any, res: any, realmId: string,
                          username: string) =>
    scimCells.placeHobaRegistration(req, res, realmId, username)
};
