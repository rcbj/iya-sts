// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_rehome.ts
//
// ---------------------------------------------------------------------------
// MOVING A PERSON'S HOME TO ANOTHER CELL (#98 §8.8, 2026-09-28).
//
// A person's home changes only by an ADMINISTRATOR'S ACT, made at the cell
// that holds them now: never by where they sign in, never by a request. The
// act, in the order that keeps them one person throughout:
//
//   1. **The target is checked**: a cell this service has, in a jurisdiction
//      the realm may place people in (`cells.homeFor()`), and not this one.
//   2. **Everything they hold is ended**, here and in every cell holding an
//      export of their session (`logout.terminate()`, which fans out through
//      `cell_sessions.subjectTerminated()`): a session minted against the old
//      home's entry must not outlive the move.
//   3. **The entry goes whole**, over the inter-cell channel
//      (`adopt-person`): every attribute, their devices, and the groups they
//      are in. A value sealed here — a TOTP secret, a recovery-code vault, a
//      private key — is OPENED here and sealed again at the target under ITS
//      cell key, since a value sealed under this cell's key opens nowhere
//      else (`keystore.seal(…, 'cell')`). This is the one act that sends a
//      person's credentials between cells, over mutual TLS, and it is the act
//      a residency move is: the data now lives there.
//   4. **The entryUUID is carried**, because it is the person's `sub`
//      everywhere (`ldap_server.adoptEntry()`); `putEntry()` would mint a new
//      one and orphan every token and link that names them.
//   5. **The routing index is moved** (`routeMove()`, only while it still
//      names this cell) — the index is the one place a name is claimed.
//   6. **They are taken out of this cell**: their devices, their group
//      memberships (`dropMemberships()`), their entry. The index rows were
//      moved first, so the delete releases nothing.
//
// A step that fails before (5) leaves them here, ended but whole; a failure
// after it is logged with what is left to do, because the person is already
// homed at the target and the leftovers here are a copy the target's index
// no longer points at.
//
// A LIBRARY: no route. `admin-ui/cells_admin.ts` draws the act and
// `mgmt-api/admin_api.ts` answers it (rule 7).
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import realms = require('./realms');
import cells = require('./cells');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-rehome' });

// Where a value this service sealed begins, whichever key sealed it.
const SEALED_PREFIX = '$aesgcm$';

/**
 * Moves a person's home to another cell, and takes a person another cell
 * sends.
 */
class CellRehome {
  /**
   * Builds the mover. It holds nothing.
   */
  constructor() {
    log.debug("Entering CellRehome.constructor().");
    log.debug("Leaving CellRehome.constructor().");
  }

  private static lower(attrs: Record<string, any>): Record<string, string[]> {
    log.debug("Entering CellRehome.lower().");
    const out: Record<string, string[]> = {};
    Object.keys(attrs || {}).forEach(function (name) {
      const v = attrs[name];
      out[name.toLowerCase()] = (Array.isArray(v) ? v : [v]).map(String);
    });
    log.debug("Leaving CellRehome.lower().");
    return out;
  }

  private static normDn(dn: string): string {
    log.debug("Entering CellRehome.normDn().");
    log.debug("Leaving CellRehome.normDn().");
    return String(dn || '').trim().split(',').map(function (p) {
      return p.trim().toLowerCase();
    }).join(',');
  }

  // Every sealed value opened, and the names of the attributes that held
  // one; null when any will not open (the move then stops before anything).
  private static opened(attrs: Record<string, string[]>):
      { attrs: Record<string, string[]>; sealed: string[] } | null {
    log.debug("Entering CellRehome.opened().");
    const keystore = require('./keystore');
    const out: Record<string, string[]> = {};
    const sealed: string[] = [];
    let unopened = false;
    Object.keys(attrs).forEach(function (name) {
      out[name] = attrs[name].map(function (value) {
        if (value.indexOf(SEALED_PREFIX) !== 0) {
          return value;
        }
        const plain = keystore.open(value, 'rehome');
        if (plain === null || plain === undefined) {
          unopened = true;
          return value;
        }
        if (sealed.indexOf(name) < 0) {
          sealed.push(name);
        }
        return String(plain);
      });
    });
    log.debug("Leaving CellRehome.opened(). " + (unopened ? 'Unopened.'
                                                           : 'Opened.'));
    return unopened ? null : { attrs: out, sealed: sealed };
  }

  /**
   * Moves a person homed here to another cell.
   *
   * @param realmId - the realm (ambient during the call)
   * @param username - the person's login name
   * @param target - the cell to move them to
   * @param actor - who did it, for the audit rows
   * @returns a promise of `{ ok: true, target }` or `{ ok: false, why,
   *   code }`
   */
  async rehome(realmId: string, username: string, target: string,
               actor: string): Promise<{ ok: boolean; why?: string;
                                         code?: string; target?: string }> {
    log.debug("Entering CellRehome.rehome(). " + username + " -> " + target);
    const refuse = (code: string, why: string) => {
      log.debug("Leaving CellRehome.rehome(). " + code);
      return { ok: false, code: code, why: why };
    };
    if (!cells.isMulti()) {
      return refuse('STS-CELL-0045', 'this service is not deployed as cells');
    }
    const home = cells.homeFor(String(target || ''));
    if ('error' in home) {
      return refuse('STS-CELL-0045', home.error);
    }
    if (home.cell === cells.id()) {
      return refuse('STS-CELL-0045', 'the person is already homed in this ' +
                                     'cell');
    }
    const ldap = require('../ldap/ldap_server');
    const entry = ldap.existingUserEntry(username);
    if (!entry || String(entry.origin || '').indexOf('projection') === 0) {
      return refuse('STS-CELL-0045', '"' + username + '" is not homed in ' +
                                     'this cell');
    }
    const attrs = CellRehome.lower(entry.attributes || {});
    const uuid = String((attrs.entryuuid || [])[0] || '').toLowerCase();
    const personKey = CellRehome.normDn(entry.dn);
    // Their devices: entries under ou=devices that this person owns.
    const devices: Array<{ dn: string; attributes: Record<string,
                                                          string[]> }> = [];
    ldap.entries.realmMap(realmId).forEach(function (stored: any) {
      const a = CellRehome.lower(stored.attributes || {});
      const kind = String((a.stsdeviceownerkind || ['person'])[0]);
      if (kind === 'person' && (a.owner || []).some(function (o) {
        return CellRehome.normDn(o) === personKey;
      })) {
        devices.push({ dn: String(stored.dn), attributes: a });
      }
    });
    const groups = ((ldap.groupsOfUser(username) || {}).groups || [])
      .filter(function (g: any) {
        return (g.via || []).length > 0;
      })
      .map(function (g: any) {
        return String(g.dn);
      });
    const openedEntry = CellRehome.opened(attrs);
    const openedDevices = devices.map(function (d) {
      return { dn: d.dn, opened: CellRehome.opened(d.attributes) };
    });
    if (!openedEntry || openedDevices.some(function (d) {
      return !d.opened;
    })) {
      return refuse('STS-CELL-0046', 'a value sealed on the entry will not ' +
                                     'open in this cell, so it cannot be ' +
                                     'moved');
    }
    // (2) End everything they hold, here and in every export.
    try {
      require('../logout/logout').terminate(username, null,
        { by: actor || 'administrator', initiatingEntity: 'admin' });
    } catch (e) {
      log.warn(errorCodes.tag('STS-CELL-0047') + 'cells: what "' + username +
               '" held could not all be ended before the move: ' +
               ((e && e.message) || e));
    }
    // (3) The entry, whole, to the target.
    try {
      await require('./cell_channel').call(home.cell, 'adopt-person', {
        realm: realmId, dn: String(entry.dn), attributes: openedEntry.attrs,
        sealed: openedEntry.sealed,
        devices: openedDevices.map(function (d) {
          return { dn: d.dn, attributes: d.opened.attrs,
                   sealed: d.opened.sealed };
        }),
        groups: groups
      });
    } catch (err) {
      return refuse('STS-CELL-0047', 'cell "' + home.cell + '" did not take ' +
                    'the person: ' + ((err && err.message) || err));
    }
    // (5) The index, while it still names this cell.
    const persistence = require('../persistence/persistence');
    const driver = persistence.currentDriver();
    const routing = require('./cell_routing');
    try {
      if (driver && driver.tiered) {
        const name = String(username).trim().toLowerCase();
        await driver.routeMove(realmId, 'name',
                               routing.digest(realmId, 'name', name),
                               cells.id(), home.cell);
        if (uuid) {
          await driver.routeMove(realmId, 'uuid',
                                 routing.digest(realmId, 'uuid', uuid),
                                 cells.id(), home.cell);
        }
      }
    } catch (err) {
      log.error(errorCodes.tag('STS-CELL-0047') + 'cells: "' + username +
                '" was taken by cell "' + home.cell + '" and the routing ' +
                'index could not be moved: ' + ((err && err.message) || err) +
                '. The entry is left here until it can be.');
      return refuse('STS-CELL-0047', 'the routing index could not be moved');
    }
    // (6) Out of this cell.
    ldap.dropMemberships(entry.dn);
    // QUIETLY: the device moved rather than went — its certificates stay
    // valid and it signals nothing (`devices.remove()`'s `quiet`).
    devices.forEach(function (d) {
      try {
        require('./devices').remove(String((d.attributes.cn || [''])[0]),
                                    undefined, actor || 'administrator',
                                    { quiet: true });
      } catch (e) {
        log.warn(errorCodes.tag('STS-CELL-0047') + 'cells: a device of the ' +
                 'moved person was left here: ' + ((e && e.message) || e));
      }
    });
    const gone = ldap.deletePerson(entry.dn);
    if (!gone || !gone.ok) {
      log.error(errorCodes.tag('STS-CELL-0047') + 'cells: "' + username +
                '" is homed in cell "' + home.cell + '" now and the entry ' +
                'here could not be deleted (' +
                ((gone && gone.reason) || 'unknown') + '); delete it.');
    }
    require('./audit').record({
      category: 'directory', action: 'cells.rehome', actor: actor || '',
      outcome: 'success', subject: username,
      summary: 'a person was re-homed to another cell',
      detail: { to: home.cell, devices: devices.length,
                groups: groups.length }
    });
    log.info('cells: "' + username + '" is homed in cell "' + home.cell +
             '" now (' + devices.length + ' device(s), ' + groups.length +
             ' group membership(s)).');
    log.debug("Leaving CellRehome.rehome(). Moved.");
    return { ok: true, target: home.cell };
  }

  // The receiving half: `adopt-person`. Every value that was sealed at the
  // sending cell is sealed here again under THIS cell's key.
  private opAdoptPerson(body: any, ctx: { peer: string }): any {
    log.debug("Entering CellRehome.opAdoptPerson().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    if (!realm || !body.dn || !body.attributes) {
      log.debug("Leaving CellRehome.opAdoptPerson(). Malformed.");
      throw new Error('a malformed re-homing');
    }
    const keystore = require('./keystore');
    const reseal = function (attrs: Record<string, string[]>,
                             sealed: string[]): Record<string, string[]> {
      const out: Record<string, string[]> = {};
      Object.keys(attrs || {}).forEach(function (name) {
        out[name] = (attrs[name] || []).map(function (value) {
          if ((sealed || []).indexOf(name) < 0 || !keystore.persists()) {
            return String(value);
          }
          const again = keystore.seal(String(value), 'rehomed', 'cell');
          if (!again) {
            throw new Error('a value could not be sealed here');
          }
          return again;
        });
      });
      return out;
    };
    realms.run(realm, function () {
      const ldap = require('../ldap/ldap_server');
      if (ldap.existingUserEntry(String((body.attributes.uid || [''])[0]))) {
        throw new Error('a person of that name is already here');
      }
      ldap.adoptEntry(String(body.dn), reseal(body.attributes, body.sealed),
                      'rehomed');
      (body.devices || []).forEach(function (d: any) {
        ldap.adoptEntry(String(d.dn), reseal(d.attributes, d.sealed),
                        'rehomed');
      });
      (body.groups || []).forEach(function (groupDn: string) {
        const added = ldap.addGroupMember(groupDn, String(body.dn),
                                          { actor: 'cell ' + ctx.peer,
                                            channel: 'cells' });
        if (!added || !added.ok) {
          log.warn(errorCodes.tag('STS-CELL-0048') + 'cells: a re-homed ' +
                   'person could not be put back in ' + groupDn + '.');
        }
      });
    });
    log.info('cells: a person was re-homed here from cell "' + ctx.peer +
             '".');
    log.debug("Leaving CellRehome.opAdoptPerson().");
    return { adopted: true };
  }

  /**
   * Registers `adopt-person` on the inter-cell channel.
   */
  install(): void {
    log.debug("Entering CellRehome.install().");
    const self = this;
    require('./cell_channel').registerOp('adopt-person',
      function (b: any, c: any) {
        return self.opAdoptPerson(b, c);
      });
    log.debug("Leaving CellRehome.install().");
  }
}

const rehome = new CellRehome();

/**
 * Moving a person's home to another cell (#98). A library: no route.
 * @namespace
 */
export = {
  CellRehome: CellRehome,
  install: (): void => rehome.install(),
  rehome: (realmId: string, username: string, target: string,
           actor: string) => rehome.rehome(realmId, username, target, actor)
};
