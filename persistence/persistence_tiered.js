// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence_tiered.js
//
// ---------------------------------------------------------------------------
// ONE STORE OVER TWO DATABASES (#98, 2026-09-28).
//
// A cell of a service deployed as cells keeps its store in two places
// (`persistence/CLAUDE.md`, *Tiers*, and `tiers.js`): the GLOBAL tier's
// database — one writer for the whole service, read here from this cell's
// replica — and the CELL's own. This driver is the one the rest of the
// service sees: it has the postgres driver's whole interface and sends each
// call to the database that holds what it is about. Nothing above it knows
// there are two.
//
// **THE ROUTING, IN ONE PARAGRAPH.** Realms, settings, signing keys and the
// certificate authorities, the shared cluster secrets, the used-assertion
// history and the routing index are GLOBAL. The directory is split entry by
// entry (`tiers.directoryTierOf()`), a group into two halves. A minted row
// goes where its store's handle says (`tiers.mintedTierOf()`), and the
// expiry purge deletes it from that same database. Everything
// else — the cluster's membership, leases, claims and counters, risk
// scoring, the change log this process's barrier waits on — is the CELL's,
// because a cell is the cluster (#46) and the global tier is not.
//
// **TWO CHANGE LOGS AND TWO FOLLOWERS.** Each database logs its own writes
// in its own `sts_changes`, in the transaction that made them, exactly as a
// single store does. `persistence.js` follows the cell's with the module's
// own replication instance through THIS driver and the global's with a
// second instance (`createReplication('global')`) straight on the global
// driver. The appliers both call reach back through this driver, which is
// what sends a row read to the right database whichever log pointed at it.
//
// **WHAT IS NOT ATOMIC ACROSS THE TWO**, said rather than discovered: a
// directory flush that touches both tiers is two transactions, the global one
// first. A crash between them leaves the global half written and the cell
// half not; the shadow in `persistence.js` is advanced only on success, so
// the next flush writes the missing half. A global write is NOT fenced by the
// cell's membership (the global database has no membership of this cell's
// nodes, and a cell that lost its path to the global writer must not exit for
// it): the rows it writes are configuration merged row by row, as they were
// before cells.
//
// **THE ROUTING INDEX IS KEPT HERE**, at the one place every person's entry
// passes on its way to the store: a person written for the first time claims
// their login name and their entryUUID in `sts_cell_routing` (as keyed
// digests — see the table); a person deleted releases both. A claim refused
// because another cell holds the name is reported (STS-CELL-0020) and the
// entry is still written here — refusing a flush would lose every other
// change in it, and the creation paths ask the index BEFORE they create
// (`cell_routing.ts`), so this is the race that check could not close.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');
const tiers = require('./tiers');
const errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-persistence-tiered' });

// The driver methods that belong to the GLOBAL tier outright.
const GLOBAL_METHODS = [
  'loadRealms', 'saveRealms', 'loadOverrides', 'saveOverrides',
  'loadKeys', 'saveKeys', 'deleteKeys', 'loadKey', 'mergeKeys',
  'ensureSharedSecret',
  // THE USED-ASSERTION HISTORY IS GLOBAL (#98): an RFC 7523 or 7522
  // assertion is accepted once EVER (rule 3ae), and every cell answers on
  // the same public name — a history per cell would accept it once per cell.
  'claimUsedAssertion', 'settleUsedAssertion', 'findUsedAssertion',
  'listUsedAssertions', 'purgeUsedAssertions', 'removeUsedAssertions',
  'saveUsedAssertions',
  'routeClaim', 'routeLookup', 'routeRelease', 'routeMove', 'routeCounts',
  'routeRowsOf', 'routeRemoveRealm', 'replicaLagMs'
];

// The methods that go to BOTH databases, whose answers are combined below.
const BOTH_METHODS = ['open', 'close', 'loadDirectory', 'saveDirectory',
                      'readEntry', 'loadMinted', 'saveMinted', 'readMinted',
                      'readMintedMany', 'purgeMinted', 'purgeExpiredMinted',
                      'purgeTombstones',
                      'changeRowsWritten', 'adoptOrigin', 'renewOrigin',
                      'releaseOrigin', 'setOriginLost',
                      // What is sealed under a data encryption key (#391):
                      // counted and re-sealed in both databases.
                      'countSealed', 'countAllSealed', 'resealSealed',
                      // The directory's data-key index (#623), in both.
                      'indexSealed'];

// The login name of a person's entry: the `uid` RDN of its DN, which is how
// this directory names a person, or its `uid` attribute.
function loginNameOf(dnKey, attrs) {
  log.debug("Entering loginNameOf().");
  const first = String(dnKey || '').split(',')[0].trim();
  let name = '';
  if (first.toLowerCase().indexOf('uid=') === 0) {
    name = first.slice(4);
  } else {
    const key = Object.keys(attrs || {}).filter(function (one) {
      return one.toLowerCase() === 'uid';
    })[0];
    const value = key ? attrs[key] : '';
    name = String(Array.isArray(value) ? value[0] || '' : value || '');
  }
  log.debug("Leaving loginNameOf().");
  return name.trim().toLowerCase();
}

// Every live name a person answers to (#644): the filing name, each
// stsPseudonym, and a username the caller resolved them by. A pending
// verification address is not a name. One list, so the flush, a re-home
// and the single-cell conversion cannot drift.
function liveNamesOf(dnKey, attrs, username) {
  log.debug("Entering liveNamesOf().");
  const out = [];
  const add = function (value) {
    const key = String(value == null ? '' : value).trim().toLowerCase();
    if (key && out.indexOf(key) === -1) {
      out.push(key);
    }
  };
  add(loginNameOf(dnKey, attrs));
  const bag = attrs || {};
  Object.keys(bag).forEach(function (name) {
    if (String(name).toLowerCase() !== 'stspseudonym') {
      return;
    }
    const value = bag[name];
    const list = Array.isArray(value) ? value : [value];
    list.forEach(add);
  });
  add(username);
  log.debug("Leaving liveNamesOf().");
  return out;
}

// A DN as the directory keys it (`ldap_server.js` normalizeDn()): each RDN
// trimmed and lower-cased. The driver compares a loaded entry's DN with the
// keys the flush hands it, so the two must be spelt the same way.
function normDn(value) {
  log.debug("Entering normDn().");
  log.debug("Leaving normDn().");
  return String(value == null ? '' : value).trim().split(',')
    .map(function (part) {
      return part.trim().toLowerCase();
    }).join(',');
}

// A person's entryUUID, whatever the attribute's case.
function uuidOf(attrs) {
  log.debug("Entering uuidOf().");
  const key = Object.keys(attrs || {}).filter(function (one) {
    return one.toLowerCase() === 'entryuuid';
  })[0];
  const value = key ? attrs[key] : '';
  log.debug("Leaving uuidOf().");
  return String(Array.isArray(value) ? value[0] || '' : value || '')
    .trim().toLowerCase();
}

/**
 * Builds the store of one cell over its two databases.
 *
 * @param options - `global` (the global tier's postgres driver), `cell` (this
 *   cell's), `cellId` (this cell's id, written in the routing index), and
 *   `digest(realmId, kind, value)` (a keyed digest for the index, or null
 *   when there is no key to make one with)
 * @returns a driver with the postgres driver's interface
 */
function create(options) {
  log.debug("Entering create().");
  const globalDriver = options.global;
  const cellDriver = options.cell;
  const cellId = String(options.cellId || '');
  const digest = typeof options.digest === 'function' ? options.digest
                                                        : function () {
                                                          return null;
                                                        };
  if (!globalDriver || !cellDriver) {
    throw new Error(errorCodes.tag('STS-CELL-0002') + 'the tiered store ' +
                    'needs both the global driver and the cell\'s.');
  }

  // realm + '\n' + dnKey -> { name, uuid } of every person this process has
  // written or loaded, so a delete (which carries only the DN) can release
  // the entryUUID's index row, and so a person written again does not claim
  // again — one global write per person, not one per modification.
  const indexed = new Map();
  let conflicts = 0;
  let lastConflict = '';
  // WHAT `common/cell_sessions.ts` IS TOLD (#98 D4): a write to a PROJECTED
  // entry, which is sent home and never written here, and a person homed here
  // written, which may have to reach the cells holding a projection of them.
  // Installed late, by that module, because it is built long after this
  // driver; until then a projected row is still never written here.
  let cellHooks = { projectionWrite: null, personWritten: null };
  let projectionWrites = 0;

  function idOf(realm, key) {
    log.debug("Entering idOf().");
    log.debug("Leaving idOf().");
    return String(realm) + '\n' + String(key);
  }

  // ---------------------------------------------------------------------
  // THE DIRECTORY, SPLIT. Upserts and deletes go to the tier their DN is in;
  // a group becomes a global row (its definition and non-person members)
  // and a cell row (its person members), and a cell half with no members
  // is a delete of the cell row, since a group whose resident members all
  // left leaves nothing of itself in this cell.
  // ---------------------------------------------------------------------
  function splitChange(change) {
    log.debug("Entering splitChange().");
    const toGlobal = { upserts: [], deletes: [],
                       removedRealms: change.removedRealms || [] };
    const toCell = { upserts: [], deletes: [],
                     removedRealms: change.removedRealms || [] };
    const groups = new Map();
    const projected = [];
    (change.upserts || []).forEach(function (row) {
      const attrs = (row.entry && row.entry.attributes) || {};
      // A PROJECTED PERSON IS NEVER WRITTEN HERE (#98): their home holds the
      // entry, and a change made here to the copy is sent there.
      if (String((row.entry && row.entry.origin) || '')
            .indexOf('projection') === 0) {
        projected.push(row);
        return;
      }
      const tier = tiers.directoryTierOf(row.key, attrs);
      if (tier === 'global') {
        toGlobal.upserts.push(row);
        return;
      }
      if (tier === 'cell') {
        toCell.upserts.push(row);
        return;
      }
      const halves = tiers.splitGroup(attrs);
      const baseEntry = row.base !== undefined && row.base
        ? JSON.parse(row.base) : null;
      const baseHalves = baseEntry
        ? tiers.splitGroup(baseEntry.attributes || {}) : null;
      const half = function (which) {
        const out = Object.assign({}, row, {
          entry: Object.assign({}, row.entry, { attributes: halves[which] })
        });
        if (row.base !== undefined) {
          out.base = baseEntry
            ? JSON.stringify(Object.assign({}, baseEntry,
                                           { attributes: baseHalves[which] }))
            : row.base;
          // A CELL HALF THAT WAS NEVER STORED HAS NO BASE (2026-09-28,
          // tests/protocol/sts_cells_console.js). A group whose base held no
          // person resident here had no cell row at all — an empty half is
          // DELETED, below — so handing the driver the base entry with an
          // empty attribute map told its merge "this row existed and is gone
          // from the store now": `mergeEntry(base, mine, null)` answers
          // `deleted`, the insert was skipped, and the outcome put the group
          // back WITHOUT the member. So the first resident member of any
          // group in a cell — a console role granted at cell B — was dropped
          // on the very flush that should have written it. No stored half is
          // a base of null: `mine` is inserted, and a half another process in
          // this cell inserted meanwhile is merged over an empty base.
          if (which === 'cell' && baseHalves &&
              !Object.keys(baseHalves.cell).length) {
            out.base = null;
          }
        }
        return out;
      };
      toGlobal.upserts.push(half('global'));
      if (Object.keys(halves.cell).length) {
        toCell.upserts.push(half('cell'));
      } else {
        toCell.deletes.push({ realm: row.realm, key: row.key });
      }
      groups.set(idOf(row.realm, row.key), { row: row, halves: halves });
    });
    (change.deletes || []).forEach(function (row) {
      const tier = tiers.directoryTierOf(row.key, {});
      if (tier !== 'cell') {
        toGlobal.deletes.push(row);
      }
      // A group's cell half goes with it, and a device's tier is not known
      // from its DN alone — so every non-global delete, and every group's,
      // is sent to the cell as well. Deleting a row that is not there is
      // nothing.
      if (tier !== 'global' || tiers.isGroupDn(row.key) ||
          String(row.key).toLowerCase().indexOf('ou=devices,') >= 0) {
        toCell.deletes.push(row);
      }
    });
    // THE CREATES' CLAIMS (#628) go with the half of the tier each claim is
    // kept in, which commits after the global half — so a claim is never
    // given back before the entry it guarded is in the store.
    const releasing = splitReleases(change.releaseClaims);
    toGlobal.releaseClaims = releasing.global;
    toCell.releaseClaims = releasing.cell;
    log.debug("Leaving splitChange().");
    return { toGlobal: toGlobal, toCell: toCell, groups: groups,
             projected: projected };
  }

  // Claim rows (`{ scope, realm, key, reservation }`), by the tier their
  // scope is claimed in (`tiers.claimTierOf()`).
  function splitReleases(rows) {
    log.debug("Entering splitReleases().");
    const out = { global: [], cell: [] };
    (rows || []).forEach(function (row) {
      out[tiers.claimTierOf(row.scope) === 'global' ? 'global' : 'cell']
        .push(row);
    });
    log.debug("Leaving splitReleases().");
    return out;
  }

  // The outcomes of the two halves of a group, as one outcome about the
  // whole group — what `persistence.js` puts back into the live directory.
  function joinOutcomes(split, globalOut, cellOut) {
    log.debug("Entering joinOutcomes().");
    const out = [];
    const byKey = function (list) {
      const m = new Map();
      (list || []).forEach(function (one) {
        m.set(idOf(one.realm, one.key), one);
      });
      return m;
    };
    const g = byKey(globalOut);
    const c = byKey(cellOut);
    g.forEach(function (one, id) {
      if (!split.groups.has(id)) {
        out.push(one);
      }
    });
    c.forEach(function (one, id) {
      if (!split.groups.has(id)) {
        out.push(one);
      }
    });
    split.groups.forEach(function (group, id) {
      const og = g.get(id);
      const oc = c.get(id);
      if (!og && !oc) {
        return;
      }
      if (og && og.outcome === 'deleted') {
        out.push(og);
        return;
      }
      const globalEntry = og ? og.entry
        : Object.assign({}, group.row.entry,
                        { attributes: group.halves.global });
      const cellAttrs = oc ? (oc.outcome === 'deleted' ? {}
                              : (oc.entry && oc.entry.attributes) || {})
        : group.halves.cell;
      out.push({
        realm: group.row.realm, key: group.row.key,
        outcome: og && og.outcome === 'theirs' &&
                 (!oc || oc.outcome === 'theirs') ? 'theirs' : 'merged',
        entry: Object.assign({}, globalEntry, {
          attributes: tiers.joinGroup(globalEntry.attributes || {},
                                      cellAttrs)
        })
      });
    });
    log.debug("Leaving joinOutcomes(). " + out.length);
    return out;
  }

  // ---------------------------------------------------------------------
  // THE INDEX, KEPT AT THE FLUSH. A person upserted here claims every live
  // name and the entryUUID; a person deleted releases the set this process
  // remembered. A pseudonym added or removed is a change of that set, so an
  // upsert whose only difference is a name is not skipped (#644). Every
  // step is best-effort: a failed claim is retried at the next write of
  // that person (it is not recorded as indexed), and a failed release
  // leaves a row that names this cell for a person it no longer holds.
  // ---------------------------------------------------------------------
  function indexPeople(change) {
    log.debug("Entering indexPeople().");
    /** @type {Promise<any>} */
    let chain = Promise.resolve();
    // Names an upsert in THIS flush successfully asked to claim, including
    // one this cell already held (`claimed` false). A rename writes the new
    // DN and deletes the old in one change; the delete must not release a
    // name the upsert just kept.
    const claimedNow = [];
    (change.upserts || []).forEach(function (row) {
      if (!tiers.isPersonDn(row.key)) {
        return;
      }
      const id = idOf(row.realm, row.key);
      const attrs = (row.entry && row.entry.attributes) || {};
      const names = liveNamesOf(row.key, attrs);
      const uuid = uuidOf(attrs);
      const was = indexed.get(id);
      const previous = was
        ? (was.names || (was.name ? [was.name] : [])) : [];
      if (was && was.uuid === uuid &&
          previous.join('\n') === names.join('\n')) {
        return;
      }
      const nameRows = names.map(function (name) {
        return { name: name, digest: digest(row.realm, 'name', name) };
      }).filter(function (one) {
        return !!one.digest;
      });
      const uuidDigest = uuid ? digest(row.realm, 'uuid', uuid) : null;
      if (!nameRows.length && !uuidDigest) {
        return;
      }
      chain = chain.then(function () {
        const claims = [];
        nameRows.forEach(function (one) {
          claims.push(globalDriver.routeClaim(row.realm, 'name', one.digest,
                                              cellId));
        });
        if (uuidDigest) {
          claims.push(globalDriver.routeClaim(row.realm, 'uuid', uuidDigest,
                                              cellId));
        }
        return Promise.all(claims).then(function (answers) {
          const elsewhere = answers.filter(function (one) {
            return one && one.cell && one.cell !== cellId;
          });
          nameRows.forEach(function (one, i) {
            const answer = answers[i];
            const ours = !answer || !answer.cell || answer.cell === cellId;
            if (ours && claimedNow.indexOf(one.name) === -1) {
              claimedNow.push(one.name);
            }
          });
          // A RE-HOMED PERSON IS NOT A CONFLICT (2026-09-28,
          // tests/protocol/sts_cells_rehome.js): `adopt-person` writes them
          // here BEFORE the sending cell moves their index rows
          // (common/cell_rehome.ts, steps 3 and 5), so a flush that lands in
          // between finds them claimed by the cell they are leaving. That
          // was logged as STS-CELL-0020 and counted as a conflict on every
          // move that raced its own flush. The index moves to this cell a
          // moment later and the next write of the entry claims it; a move
          // whose index never follows is the sender's STS-CELL-0047.
          if (elsewhere.length &&
              String((row.entry && row.entry.origin) || '') === 'rehomed') {
            log.info('cells: realm "' + row.realm + '": a person re-homed ' +
                     'here is still indexed in cell "' + elsewhere[0].cell +
                     '", which is moving the index to this one.');
            return;
          }
          if (elsewhere.length) {
            conflicts += 1;
            lastConflict = 'realm "' + row.realm + '": a person with this ' +
              'login name or entryUUID is already homed in cell "' +
              elsewhere[0].cell + '"';
            log.error(errorCodes.tag('STS-CELL-0020') + 'cells: ' +
                      lastConflict + ', and one was written in this cell ' +
                      'too. The creation raced the index check; the entry ' +
                      'here will not be found by sign-in routing.');
            return;
          }
          indexed.set(id, { names: names, uuid: uuid });
          const drop = previous.filter(function (name) {
            return names.indexOf(name) === -1 &&
              claimedNow.indexOf(name) === -1;
          });
          return Promise.all(drop.map(function (name) {
            const made = digest(row.realm, 'name', name);
            return made
              ? globalDriver.routeRelease(row.realm, 'name', made, cellId)
              : null;
          }));
        });
      });
    });
    (change.deletes || []).forEach(function (row) {
      if (!tiers.isPersonDn(row.key)) {
        return;
      }
      const id = idOf(row.realm, row.key);
      const was = indexed.get(id);
      const remembered = was
        ? (was.names || (was.name ? [was.name] : []))
        : [loginNameOf(row.key, {})];
      const uuidDigest = was && was.uuid
        ? digest(row.realm, 'uuid', was.uuid) : null;
      indexed.delete(id);
      chain = chain.then(function () {
        const releases = [];
        remembered.forEach(function (name) {
          if (!name || claimedNow.indexOf(name) !== -1) {
            return;
          }
          const made = digest(row.realm, 'name', name);
          if (made) {
            releases.push(globalDriver.routeRelease(row.realm, 'name',
                                                    made, cellId));
          }
        });
        if (uuidDigest) {
          releases.push(globalDriver.routeRelease(row.realm, 'uuid',
                                                  uuidDigest, cellId));
        }
        return Promise.all(releases);
      });
    });
    (change.removedRealms || []).forEach(function (realmId) {
      chain = chain.then(function () {
        return globalDriver.routeRemoveRealm(realmId);
      });
    });
    log.debug("Leaving indexPeople().");
    return chain.catch(function (err) {
      log.warn(errorCodes.tag('STS-CELL-0021') + 'cells: the routing ' +
               'index could not be updated (' + ((err && err.message) || err) +
               '); it is retried at the next write of the same person.');
    });
  }

  // The two hooks, after a flush landed. Neither is awaited — each owns its
  // own retries and its own failures (`cell_sessions.ts`), and a flush must
  // not wait on another region.
  function tellCellHooks(split) {
    log.debug("Entering tellCellHooks().");
    if (typeof cellHooks.projectionWrite === 'function') {
      split.projected.forEach(function (row) {
        projectionWrites += 1;
        try {
          cellHooks.projectionWrite(row.realm, row.key, row.entry, row.base);
        } catch (e) {
          log.warn(errorCodes.tag('STS-CELL-0050') + 'cells: a write to a ' +
                   'projected entry could not be sent home: ' +
                   ((e && e.message) || e));
        }
      });
    }
    if (typeof cellHooks.personWritten === 'function') {
      (split.toCell.upserts || []).forEach(function (row) {
        if (!tiers.isPersonDn(row.key)) {
          return;
        }
        try {
          cellHooks.personWritten(row.realm, row.key, row.entry);
        } catch (e) {
          log.warn(errorCodes.tag('STS-CELL-0051') + 'cells: the cells ' +
                   'holding a projection of a changed person could not be ' +
                   'told: ' + ((e && e.message) || e));
        }
      });
    }
    log.debug("Leaving tellCellHooks().");
  }

  // Every person a load or read brought in, recorded as already indexed —
  // they were claimed when they were created, in this cell or before a
  // restart of it.
  function noteLoaded(realmId, entries) {
    log.debug("Entering noteLoaded().");
    (entries || []).forEach(function (entry) {
      const key = normDn(entry.dn);
      if (!tiers.isPersonDn(key)) {
        return;
      }
      const attrs = entry.attributes || {};
      const names = liveNamesOf(key, attrs);
      const uuid = uuidOf(attrs);
      // The digests are made when they are needed, not here: a load runs
      // before the keystore holds the key they are made under. Recording
      // does not claim (#644).
      indexed.set(idOf(realmId, key), { names: names, uuid: uuid });
    });
    log.debug("Leaving noteLoaded().");
  }

  // The minted rows of one list, split by their store's tier.
  function byHandleTier(list) {
    log.debug("Entering byHandleTier().");
    const out = { global: [], cell: [] };
    (list || []).forEach(function (one) {
      let tier = 'cell';
      try {
        tier = tiers.mintedTierOf(one.handle);
      } catch (e) {
        // Unclassified: kept where it was made. `tests/cell_tiers.js` is
        // what refuses an unclassified store, at build time.
        log.debug("Caught in byHandleTier(): " + ((e && e.message) || e));
      }
      out[tier].push(one);
    });
    log.debug("Leaving byHandleTier().");
    return out;
  }

  function tierOfHandle(handle) {
    log.debug("Entering tierOfHandle().");
    let tier = 'cell';
    try {
      tier = tiers.mintedTierOf(handle);
    } catch (e) {
      log.debug("Caught in tierOfHandle(): " + ((e && e.message) || e));
    }
    log.debug("Leaving tierOfHandle().");
    return tier === 'global' ? globalDriver : cellDriver;
  }

  // ---------------------------------------------------------------------
  // THE DRIVER. Every function the cell driver has, bound to it — the cell
  // is the default because the cluster and everything not named above is
  // the cell's — and then the global and the combined ones over the top.
  // ---------------------------------------------------------------------
  const driver = /** @type {any} */ ({ name: 'postgres', tiered: true });
  Object.keys(cellDriver).forEach(function (key) {
    if (typeof cellDriver[key] === 'function' &&
        BOTH_METHODS.indexOf(key) < 0) {
      driver[key] = cellDriver[key].bind(cellDriver);
    }
  });
  GLOBAL_METHODS.forEach(function (key) {
    if (typeof globalDriver[key] === 'function') {
      driver[key] = globalDriver[key].bind(globalDriver);
    }
  });

  // A CLAIM GOES WHERE ITS SCOPE SAYS (`tiers.claimTierOf()`): a global
  // scheduler job's run is claimed in the global tier, so one cell runs it.
  ['claimOnce', 'releaseClaim', 'claimHeld'].forEach(function (key) {
    driver[key] = function (scope) {
      log.debug("Entering tiered " + key + "().");
      const target = tiers.claimTierOf(scope) === 'global' ? globalDriver
                                                           : cellDriver;
      log.debug("Leaving tiered " + key + "().");
      return target[key].apply(target, arguments);
    };
  });
  // SEVERAL CLAIMS, AND SEVERAL RELEASES, IN ONE STATEMENT (#628): a claim
  // set goes to the tier of its FIRST row's scope — a caller claims one kind
  // of thing at a time, and a directory create's DN and username are both
  // cell scopes — and release rows are split by their own.
  driver.claimMany = function (rows) {
    log.debug("Entering tiered claimMany().");
    const first = (rows || [])[0] || {};
    const target = tiers.claimTierOf(first.scope) === 'global' ? globalDriver
                                                                : cellDriver;
    log.debug("Leaving tiered claimMany().");
    return target.claimMany.apply(target, arguments);
  };
  driver.releaseClaims = function (rows) {
    log.debug("Entering tiered releaseClaims().");
    const split = splitReleases(rows);
    log.debug("Leaving tiered releaseClaims().");
    return Promise.all([globalDriver.releaseClaims(split.global),
                        cellDriver.releaseClaims(split.cell)])
      .then(function (both) {
        return (Number(both[0]) || 0) + (Number(both[1]) || 0);
      });
  };
  driver.purgeClaims = function () {
    log.debug("Entering tiered purgeClaims().");
    log.debug("Leaving tiered purgeClaims().");
    return Promise.all([globalDriver.purgeClaims(),
                        cellDriver.purgeClaims()]).then(function (both) {
      return (Number(both[0]) || 0) + (Number(both[1]) || 0);
    });
  };

  driver.open = function () {
    log.debug("Entering tiered open().");
    log.debug("Leaving tiered open().");
    return globalDriver.open().then(function () {
      return cellDriver.open();
    });
  };

  driver.close = function () {
    log.debug("Entering tiered close().");
    log.debug("Leaving tiered close().");
    return Promise.all([
      cellDriver.close().catch(function (e) {
        log.debug("Caught in tiered close(): " + ((e && e.message) || e));
      }),
      globalDriver.close().catch(function (e) {
        log.debug("Caught in tiered close(): " + ((e && e.message) || e));
      })
    ]).then(function () {
      return undefined;
    });
  };

  // A directory load: the global rows, then the cell's; a group's cell half
  // is joined into its global half and never restored on its own.
  driver.loadDirectory = function () {
    log.debug("Entering tiered loadDirectory().");
    log.debug("Leaving tiered loadDirectory().");
    return Promise.all([globalDriver.loadDirectory(),
                        cellDriver.loadDirectory()]).then(function (both) {
      const fromGlobal = both[0] || {};
      const fromCell = both[1] || {};
      const out = {};
      Object.keys(fromGlobal).forEach(function (realmId) {
        out[realmId] = (fromGlobal[realmId] || []).slice();
      });
      let orphans = 0;
      Object.keys(fromCell).forEach(function (realmId) {
        const list = out[realmId] || (out[realmId] = []);
        const at = new Map();
        list.forEach(function (entry, i) {
          at.set(normDn(entry.dn), i);
        });
        (fromCell[realmId] || []).forEach(function (entry) {
          const dnKey = normDn(entry.dn);
          if (!tiers.isGroupDn(dnKey)) {
            list.push(entry);
            return;
          }
          const i = at.get(dnKey);
          if (i === undefined) {
            orphans += 1;
            return;
          }
          list[i] = Object.assign({}, list[i], {
            attributes: tiers.joinGroup(list[i].attributes || {},
                                        entry.attributes || {})
          });
        });
        noteLoaded(realmId, fromCell[realmId]);
      });
      if (orphans) {
        log.warn(errorCodes.tag('STS-CELL-0022') + 'cells: ' + orphans +
                 ' group membership row(s) in this cell belong to a group ' +
                 'the global tier no longer has; they are not restored.');
      }
      return Object.keys(out).length ? out : null;
    });
  };

  driver.saveDirectory = function (change) {
    log.debug("Entering tiered saveDirectory().");
    const split = splitChange(change);
    log.debug("Leaving tiered saveDirectory().");
    // THE GLOBAL HALF FIRST: a group's definition before its members, and a
    // failure there leaves the cell untouched for the retry.
    return globalDriver.saveDirectory(split.toGlobal).then(function (g) {
      return cellDriver.saveDirectory(split.toCell).then(function (c) {
        return indexPeople(split.toCell).then(function () {
          tellCellHooks(split);
          return { outcomes: joinOutcomes(split, g && g.outcomes,
                                          c && c.outcomes) };
        });
      });
    });
  };

  driver.readEntry = function (realmId, dnKey) {
    log.debug("Entering tiered readEntry().");
    const tier = tiers.directoryTierOf(dnKey, {});
    if (tier === 'global' && String(dnKey).toLowerCase()
          .indexOf('ou=devices,') < 0) {
      log.debug("Leaving tiered readEntry(). Global.");
      return globalDriver.readEntry(realmId, dnKey);
    }
    if (tier === 'cell') {
      log.debug("Leaving tiered readEntry(). Cell.");
      return cellDriver.readEntry(realmId, dnKey);
    }
    log.debug("Leaving tiered readEntry(). Both.");
    return Promise.all([globalDriver.readEntry(realmId, dnKey),
                        cellDriver.readEntry(realmId, dnKey)])
      .then(function (both) {
        const g = both[0];
        const c = both[1];
        if (!tiers.isGroupDn(String(dnKey).toLowerCase())) {
          // A device: whichever tier holds it.
          return g || c || null;
        }
        if (!g) {
          return null;
        }
        return Object.assign({}, g, {
          entry: Object.assign({}, g.entry, {
            attributes: tiers.joinGroup((g.entry && g.entry.attributes) ||
                                        {}, (c && c.entry &&
                                             c.entry.attributes) || {})
          })
        });
      });
  };

  // The FILTER is passed to both tiers (#333 made the postgres driver refuse
  // a read that does not say which realms and which instant it wants; the
  // tiered driver dropped it, and every node of a cell refused to start).
  driver.loadMinted = function (filter) {
    log.debug("Entering tiered loadMinted().");
    log.debug("Leaving tiered loadMinted().");
    return Promise.all([globalDriver.loadMinted(filter),
                        cellDriver.loadMinted(filter)])
      .then(function (both) {
        const g = byHandleTier(both[0]).global;
        const c = byHandleTier(both[1]).cell;
        return g.concat(c);
      });
  };

  driver.saveMinted = function (upserts, deletes) {
    log.debug("Entering tiered saveMinted().");
    const up = byHandleTier(upserts);
    const down = byHandleTier(deletes);
    log.debug("Leaving tiered saveMinted().");
    const run = function (target, u, d) {
      return u.length || d.length ? target.saveMinted(u, d)
                                  : Promise.resolve({ refused: [],
                                                      merged: [] });
    };
    return run(globalDriver, up.global, down.global).then(function (g) {
      return run(cellDriver, up.cell, down.cell).then(function (c) {
        return {
          refused: ((g && g.refused) || []).concat((c && c.refused) || []),
          merged: ((g && g.merged) || []).concat((c && c.merged) || [])
        };
      });
    });
  };

  driver.readMinted = function (handle, realmId, key) {
    log.debug("Entering tiered readMinted().");
    log.debug("Leaving tiered readMinted().");
    return tierOfHandle(handle).readMinted(handle, realmId, key);
  };

  // An on-demand store's console questions (#820): the store's own tier,
  // as a read of one of its rows is. A tier whose driver has no such door
  // answers as it would have — a refusal the caller reads as unread.
  driver.mintedQuery = function (name, args) {
    log.debug("Entering tiered mintedQuery(). " + name);
    const target = tierOfHandle(Array.isArray(args) ? args[0] : '');
    log.debug("Leaving tiered mintedQuery().");
    return typeof target.mintedQuery === 'function'
      ? target.mintedQuery(name, args)
      : Promise.reject(new Error('no on-demand query on this tier'));
  };

  driver.readMintedMany = function (refs) {
    log.debug("Entering tiered readMintedMany().");
    const split = byHandleTier(refs);
    log.debug("Leaving tiered readMintedMany().");
    return Promise.all([
      split.global.length ? globalDriver.readMintedMany(split.global) : [],
      split.cell.length ? cellDriver.readMintedMany(split.cell) : []
    ]).then(function (both) {
      return (both[0] || []).concat(both[1] || []);
    });
  };

  driver.purgeMinted = function (beforeMs, handles) {
    log.debug("Entering tiered purgeMinted().");
    log.debug("Leaving tiered purgeMinted().");
    return Promise.all([globalDriver.purgeMinted(beforeMs, handles),
                        cellDriver.purgeMinted(beforeMs, handles)])
      .then(function (both) {
        return (Number(both[0]) || 0) + (Number(both[1]) || 0);
      });
  };

  // THE EXPIRY PURGE RUNS IN BOTH DATABASES (#360). An unlisted method is
  // the cell driver's, so this one deleted only this cell's rows: a global
  // store's expired rows (dpop.seenJtis, the status lists) stayed in the
  // global table, refused wherever they were read and never deleted.
  // 'expired' names no handle — each database deletes its own rows — and
  // 'stale' names the short-lived stores, handed to the tier that holds
  // each one.
  //
  // 'ORPHAN' ASKS THE GLOBAL REGISTRY, NOT EACH DATABASE'S OWN. The realms
  // are a global table (`loadRealms` is a GLOBAL method and the conversion
  // moves `sts_realms` there), so a cell's `sts_realms` is empty or the
  // snapshot the conversion left. Judged against it, every cell row of a
  // realm made since then was an orphan, and a session or token of that
  // realm was deleted an hour after it was written. The global list is read
  // first and handed to the tier(s) asked; when it cannot be read nothing is
  // purged, because deleting on a guess is the failure this guards.
  //
  // `options.tier` NAMES ONE DATABASE (#695), and the expiry purge jobs
  // always name one (`persistence_minted.js`): 'cell' for this cell's job,
  // 'global' for the one cell that wins the global run claim. Then the
  // `limit` and the count are that database's alone. Without it both are
  // asked — each with the WHOLE limit, so the sum may be up to twice it,
  // which is why a caller that batches must name a tier — and they are
  // SETTLED SEPARATELY: one database failing does not hide what the other
  // deleted, which rides on the rejection as `removed`, with `tier` naming
  // the database (or databases) that failed.
  function purgeTier(which, kind, options) {
    log.debug("Entering purgeTier(). " + which + " " + kind);
    const target = which === 'global' ? globalDriver : cellDriver;
    log.debug("Leaving purgeTier().");
    return Promise.resolve().then(function () {
      return target.purgeExpiredMinted(kind, options);
    });
  }

  function settleTiers(asked) {
    log.debug("Entering settleTiers(). " + asked.length);
    log.debug("Leaving settleTiers().");
    return Promise.allSettled(asked.map(function (one) {
      return purgeTier(one.tier, one.kind, one.options);
    })).then(function (results) {
      let removed = 0;
      const failed = [];
      let first = null;
      results.forEach(function (r, i) {
        if (r.status === 'fulfilled') {
          removed += Number(r.value) || 0;
          return;
        }
        failed.push(asked[i].tier);
        first = first || r.reason;
      });
      if (!failed.length) {
        return removed;
      }
      const err = /** @type {any} */ (new Error('the ' +
        failed.join(' and ') + ' tier\'s expiry purge failed: ' +
        String((first && first.message) || first).replace(/\.+$/, '')));
      err.removed = removed;
      err.tier = failed.join(',');
      throw err;
    });
  }

  driver.purgeExpiredMinted = function (kind, options) {
    log.debug("Entering tiered purgeExpiredMinted().");
    const o = Object.assign({}, options || {});
    const only = o.tier === 'global' || o.tier === 'cell' ? o.tier : '';
    delete o.tier;
    const which = only ? [only] : ['global', 'cell'];
    let forTier = function (tier) {
      log.debug("Entering forTier(). " + tier);
      log.debug("Leaving forTier().");
      return o;
    };
    if (kind === 'stale') {
      const listed = Array.isArray(o.handles) ? o.handles : [];
      const split = byHandleTier(listed.map(function (handle) {
        return { handle: handle };
      }));
      forTier = function (tier) {
        log.debug("Entering forTier(), stale. " + tier);
        log.debug("Leaving forTier().");
        return Object.assign({}, o, {
          handles: split[tier].map(function (one) {
            return one.handle;
          })
        });
      };
    }
    const ask = function (realmsSeen) {
      log.debug("Entering ask().");
      log.debug("Leaving ask().");
      return settleTiers(which.map(function (tier) {
        const opts = forTier(tier);
        return { tier: tier, kind: kind,
                 options: realmsSeen
                   ? Object.assign({}, opts, { realms: realmsSeen })
                   : opts };
      }));
    };
    if (kind === 'orphan') {
      log.debug("Leaving tiered purgeExpiredMinted(). Orphans, against " +
                "the global realms.");
      return globalDriver.loadRealms().then(function (rows) {
        return ask((rows || []).map(function (row) {
          return String(row.id);
        }));
      });
    }
    log.debug("Leaving tiered purgeExpiredMinted().");
    return ask(null);
  };

  driver.purgeTombstones = function (beforeMs) {
    log.debug("Entering tiered purgeTombstones().");
    log.debug("Leaving tiered purgeTombstones().");
    return Promise.all([globalDriver.purgeTombstones(beforeMs),
                        cellDriver.purgeTombstones(beforeMs)])
      .then(function (both) {
        return (Number(both[0]) || 0) + (Number(both[1]) || 0);
      });
  };

  // WHAT IS SEALED UNDER A DATA ENCRYPTION KEY (#391 P2), in BOTH tiers:
  // a person's rows are in the cell's database and the keys and realms in
  // the global one, and a DEK may be destroyed only when neither holds a
  // value under it.
  driver.countSealed = function (dekIds) {
    log.debug("Entering tiered countSealed().");
    log.debug("Leaving tiered countSealed().");
    return Promise.all([globalDriver.countSealed(dekIds),
                        cellDriver.countSealed(dekIds)]).then(function (both) {
      const out = {};
      both.forEach(function (one) {
        Object.keys(one || {}).forEach(function (id) {
          out[id] = (out[id] || 0) + (Number(one[id]) || 0);
        });
      });
      return out;
    });
  };
  driver.countAllSealed = function () {
    log.debug("Entering tiered countAllSealed().");
    log.debug("Leaving tiered countAllSealed().");
    return Promise.all([globalDriver.countAllSealed(),
                        cellDriver.countAllSealed()]).then(function (both) {
      const out = {};
      both.forEach(function (one) {
        Object.keys(one || {}).forEach(function (id) {
          out[id] = (out[id] || 0) + (Number(one[id]) || 0);
        });
      });
      return out;
    });
  };
  // The data-key index caught up in BOTH databases (#623), each with the
  // whole budget, one after the other; `remaining` while either has more.
  driver.indexSealed = function (options) {
    log.debug("Entering tiered indexSealed().");
    log.debug("Leaving tiered indexSealed().");
    return globalDriver.indexSealed(options).then(function (first) {
      return cellDriver.indexSealed(options).then(function (second) {
        return { indexed: (Number(first && first.indexed) || 0) +
                          (Number(second && second.indexed) || 0),
                 remaining: !!((first && first.remaining) ||
                               (second && second.remaining)) };
      });
    });
  };
  // The `grantinggroup` key backfill (#1311) in BOTH databases, each walked
  // and marked by itself, one after the other, each with the whole budget;
  // complete only when both are. Every cell's leader walks the global tier
  // too until its mark is written: the writes are compare-and-set and any
  // cursor names a finished prefix, so two walkers cost time, never keys.
  driver.indexGrantingKeys = function (options) {
    log.debug("Entering tiered indexGrantingKeys().");
    const backfill = require('./granting_index_backfill');
    const each = function (one, what) {
      log.debug("Entering each().");
      log.debug("Leaving each().");
      return typeof one.indexGrantingKeys === 'function'
        ? one.indexGrantingKeys(Object.assign({}, options || {},
                                              { what: what }))
        : Promise.resolve({ complete: true, already: true });
    };
    log.debug("Leaving tiered indexGrantingKeys().");
    return each(globalDriver, 'the global tier').then(function (first) {
      return each(cellDriver, 'this cell\'s database')
        .then(function (second) {
          return backfill.combined(first, second);
        });
    });
  };
  driver.resealSealed = function (dekIds, reseal, options) {
    log.debug("Entering tiered resealSealed().");
    log.debug("Leaving tiered resealSealed().");
    return globalDriver.resealSealed(dekIds, reseal, options)
      .then(function (first) {
        return cellDriver.resealSealed(dekIds, reseal, options)
          .then(function (second) {
            const out = { changed: [] };
            [first, second].forEach(function (one) {
              Object.keys(one || {}).forEach(function (k) {
                if (k === 'changed') {
                  out.changed = out.changed.concat(one.changed || []);
                  return;
                }
                out[k] = (out[k] || 0) + (Number(one[k]) || 0);
              });
            });
            return out;
          });
      });
  };
  driver.changeRowsWritten = function () {
    log.debug("Entering tiered changeRowsWritten().");
    log.debug("Leaving tiered changeRowsWritten().");
    return (Number(globalDriver.changeRowsWritten()) || 0) +
           (Number(cellDriver.changeRowsWritten()) || 0);
  };

  // THE ORIGIN IS TAKEN IN BOTH DATABASES: each stamps this process's writes
  // on its own change log, and a follower skips its own rows by it. The
  // cell's answer is the one reported; the global claim is taken under the
  // same stable name.
  driver.adoptOrigin = function (opts) {
    log.debug("Entering tiered adoptOrigin().");
    log.debug("Leaving tiered adoptOrigin().");
    return cellDriver.adoptOrigin(opts).then(function (fromCell) {
      return globalDriver.adoptOrigin(opts).then(function () {
        return fromCell;
      });
    });
  };

  driver.renewOrigin = function (ttlMs) {
    log.debug("Entering tiered renewOrigin().");
    log.debug("Leaving tiered renewOrigin().");
    return Promise.all([cellDriver.renewOrigin(ttlMs),
                        globalDriver.renewOrigin(ttlMs)])
      .then(function (both) {
        // Losing the GLOBAL origin is not losing this process's right to
        // write its cell: it is reported by the global driver's own fence.
        return both[0];
      });
  };

  driver.releaseOrigin = function () {
    log.debug("Entering tiered releaseOrigin().");
    log.debug("Leaving tiered releaseOrigin().");
    return Promise.all([cellDriver.releaseOrigin(),
                        globalDriver.releaseOrigin()]).then(function (both) {
      return both[0];
    });
  };

  driver.setOriginLost = function (fn) {
    log.debug("Entering tiered setOriginLost().");
    cellDriver.setOriginLost(fn);
    globalDriver.setOriginLost(fn);
    log.debug("Leaving tiered setOriginLost().");
  };

  // The two drivers themselves, for the global follower and `/admin/cells`.
  driver.globalDriver = function () {
    log.debug("Entering tiered globalDriver().");
    log.debug("Leaving tiered globalDriver().");
    return globalDriver;
  };
  driver.cellDriver = function () {
    log.debug("Entering tiered cellDriver().");
    log.debug("Leaving tiered cellDriver().");
    return cellDriver;
  };
  driver.routingStatus = function () {
    log.debug("Entering tiered routingStatus().");
    log.debug("Leaving tiered routingStatus().");
    return { indexed: indexed.size, conflicts: conflicts,
             lastConflict: lastConflict || null,
             projectionWrites: projectionWrites };
  };
  // Installed by `common/cell_sessions.ts` (#98 D4).
  driver.setCellHooks = function (hooks) {
    log.debug("Entering tiered setCellHooks().");
    cellHooks = {
      projectionWrite: hooks && typeof hooks.projectionWrite === 'function'
        ? hooks.projectionWrite : null,
      personWritten: hooks && typeof hooks.personWritten === 'function'
        ? hooks.personWritten : null
    };
    log.debug("Leaving tiered setCellHooks().");
  };

  log.debug("Leaving create().");
  return driver;
}

/**
 * The store of one cell over the global tier's database and its own (#98).
 * A driver: no route.
 * @namespace
 */
module.exports = {
  create: create,
  GLOBAL_METHODS: GLOBAL_METHODS,
  BOTH_METHODS: BOTH_METHODS,
  // How the flush names a person in the routing index, for the one-time
  // conversion of a single-cell store (`cell_convert.js`), whose backfill
  // must write exactly the rows `indexPeople()` would have.
  loginNameOf: loginNameOf,
  liveNamesOf: liveNamesOf,
  uuidOf: uuidOf,
  normDn: normDn
};
