// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_tiers.js
//
// ---------------------------------------------------------------------------
// THE TIERS OF A CELL'S STORE (#98). Four things, each the kind of mistake
// that fails nothing and puts a person's data in the wrong country:
//
//   1. EVERY `persist:` handle in the tree is classified global or cell in
//      `persistence/tiers.js`, and neither list names a store that no longer
//      exists. A new store cannot arrive without somebody deciding where it
//      lives.
//   2. The directory: a person and a person's device are cell-tier, an
//      application's device and every other entry global, a group split —
//      and the split and the join give back what went in.
//   3. The tiered driver sends each write to the right database, joins a
//      group's halves on the way back, splits minted rows by handle, and
//      keeps the routing index: one claim per person, a release on delete,
//      and a conflict counted rather than swallowed. The expiry purge
//      reaches both databases, and a stale batch's handles go to the tier
//      that holds them (#360).
//   4. Sealing: a cell-tier row sealed under the cell key does not open
//      without it, and a global row opens in every cell.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const tiers = require('../persistence/tiers');
const tiered = require('../persistence/persistence_tiered');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'cell_tiers',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
// Directories never scanned: dependencies, vendored copies of other
// projects, and build output.
const SKIP = ['node_modules', '.git', 'vendored', 'embedded', 'apidocs',
              'coverage', 'node-ldapjs', 'deploy', 'docs'];

function sourcesUnder(dir, out) {
  log.debug("Entering sourcesUnder().");
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (one) {
    if (SKIP.indexOf(one.name) >= 0) {
      return;
    }
    const full = path.join(dir, one.name);
    if (one.isDirectory()) {
      sourcesUnder(full, out);
    } else if (/\.(js|ts)$/.test(one.name) && !/\.d\.ts$/.test(one.name)) {
      out.push(full);
    }
  });
  log.debug("Leaving sourcesUnder().");
  return out;
}

function everyClassified(t) {
  log.debug("Entering everyClassified().");
  const handles = new Set();
  sourcesUnder(ROOT, []).forEach(function (file) {
    // A compiled copy of a .ts file says the same thing twice; read one.
    if (/\.js$/.test(file) && fs.existsSync(file.replace(/\.js$/, '.ts'))) {
      return;
    }
    const text = fs.readFileSync(file, 'utf8');
    const re = /persist:\s*'([A-Za-z0-9_.:-]+)'/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      handles.add(m[1]);
    }
  });
  t.check(handles.size > 100, 'the scan found the persisted stores',
          handles.size + ' handle(s)');
  const missing = Array.from(handles).filter(function (h) {
    return !tiers.isClassified(h);
  });
  t.check(!missing.length, 'every persisted store is classified global or ' +
          'cell in persistence/tiers.js', missing.join(', ') || 'all');
  const named = Object.keys(tiers.GLOBAL_MINTED).concat(tiers.CELL_MINTED);
  const stale = named.filter(function (h) {
    return !handles.has(h);
  });
  t.check(!stale.length, 'neither list names a store that does not exist',
          stale.join(', ') || 'none');
  const both = Object.keys(tiers.GLOBAL_MINTED).filter(function (h) {
    return tiers.CELL_MINTED.indexOf(h) >= 0;
  });
  t.check(!both.length, 'no store is in both lists', both.join(', ') ||
          'none');
  let threw = false;
  try {
    tiers.mintedTierOf('nobody.decided');
  } catch (e) {
    log.debug("Caught in everyClassified(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw, 'an unclassified handle is refused, not defaulted');
  log.debug("Leaving everyClassified().");
}

function directory(t) {
  log.debug("Entering directory().");
  const base = 'dc=acme,dc=example,dc=com';
  t.equal(tiers.directoryTierOf('uid=alice,ou=users,' + base, {}), 'cell',
          'a person is cell-tier');
  t.equal(tiers.directoryTierOf('ou=users,' + base, {}), 'global',
          'the people container itself is global');
  t.equal(tiers.directoryTierOf('cn=d1,ou=devices,' + base,
                                { stsDeviceOwnerKind: ['person'] }), 'cell',
          'a person\'s device is cell-tier');
  t.equal(tiers.directoryTierOf('cn=d2,ou=devices,' + base,
                                { stsDeviceOwnerKind: ['application'] }),
          'global', 'an application\'s device is global');
  t.equal(tiers.directoryTierOf('cn=admins,ou=groups,' + base, {}), 'split',
          'a group is split');
  t.equal(tiers.directoryTierOf('cn=app,ou=applications,' + base, {}),
          'global', 'an application is global');
  t.equal(tiers.directoryTierOf(base, {}), 'global',
          'the realm base is global');
  const group = { cn: ['admins'], objectClass: ['groupOfNames'],
                  member: ['uid=alice,ou=users,' + base,
                           'cn=app,ou=applications,' + base,
                           'uid=bob,ou=users,' + base] };
  const halves = tiers.splitGroup(group);
  t.check(JSON.stringify(halves.global.member) ===
          JSON.stringify(['cn=app,ou=applications,' + base]),
          'the global half of a group keeps only its non-person members');
  t.check(halves.cell.member.length === 2 && !halves.cell.cn,
          'the cell half carries only the person members');
  const joined = tiers.joinGroup(halves.global, halves.cell);
  t.check(joined.member.length === 3 && joined.cn[0] === 'admins',
          'joining the halves gives the group back');
  const posix = tiers.splitGroup({ cn: ['posix'], memberUid: ['alice',
                                                               'bob'] });
  t.check(!posix.global.memberUid && posix.cell.memberUid.length === 2,
          'a posixGroup\'s memberUid values are login names, all of them ' +
          'cell-tier');
  const onlyPeople = tiers.splitGroup({ cn: ['p'], member: [
    'uid=carol,ou=users,' + base] });
  t.check(!onlyPeople.global.member && onlyPeople.cell.member.length === 1,
          'a group of people only has no member attribute on its global ' +
          'half');
  log.debug("Leaving directory().");
}

// A stub of the postgres driver's interface, recording what it was asked.
function stubDriver(name) {
  log.debug("Entering stubDriver().");
  const calls = [];
  const directoryRows = {};
  const minted = [];
  const routes = new Map();
  const stub = {
    calls: calls,
    directoryRows: directoryRows,
    routes: routes,
    open: function () { return Promise.resolve(); },
    close: function () { return Promise.resolve(); },
    loadDirectory: function () {
      return Promise.resolve(Object.keys(directoryRows).length
        ? directoryRows : null);
    },
    saveDirectory: function (change) {
      calls.push({ op: 'saveDirectory', change: change });
      return Promise.resolve({ outcomes: [] });
    },
    readEntry: function () { return Promise.resolve(null); },
    // Refuses a read with no filter, as the postgres driver does (#333).
    loadMinted: function (filter) {
      calls.push({ op: 'loadMinted', filter: filter });
      if (!filter || !Array.isArray(filter.realms)) {
        return Promise.reject(new Error('loadMinted() needs a filter'));
      }
      return Promise.resolve(minted.slice());
    },
    saveMinted: function (u, d) {
      calls.push({ op: 'saveMinted', upserts: u, deletes: d });
      return Promise.resolve({ refused: [], merged: [] });
    },
    readMinted: function () { return Promise.resolve(null); },
    readMintedMany: function (refs) {
      calls.push({ op: 'readMintedMany', refs: refs });
      return Promise.resolve([]);
    },
    purgeMinted: function () { return Promise.resolve(1); },
    purgeExpiredMinted: function (kind, options) {
      log.debug("Entering purgeExpiredMinted().");
      calls.push({ op: 'purgeExpiredMinted', kind: kind,
                   options: options });
      log.debug("Leaving purgeExpiredMinted().");
      return Promise.resolve(1);
    },
    claimOnce: function (scope) {
      calls.push({ op: 'claimOnce', scope: scope });
      return Promise.resolve({ ok: true });
    },
    releaseClaim: function (scope) {
      calls.push({ op: 'releaseClaim', scope: scope });
      return Promise.resolve(true);
    },
    claimHeld: function (scope) {
      calls.push({ op: 'claimHeld', scope: scope });
      return Promise.resolve(false);
    },
    purgeClaims: function () {
      calls.push({ op: 'purgeClaims' });
      return Promise.resolve(2);
    },
    purgeTombstones: function (beforeMs, options) {
      log.debug("Entering purgeTombstones().");
      calls.push({ op: 'purgeTombstones', beforeMs: beforeMs,
                   options: options, args: arguments.length });
      log.debug("Leaving purgeTombstones().");
      return Promise.resolve(1);
    },
    changeRowsWritten: function () { return 2; },
    adoptOrigin: function () {
      return Promise.resolve({ adopted: true, origin: name });
    },
    renewOrigin: function () { return Promise.resolve(true); },
    releaseOrigin: function () { return Promise.resolve(true); },
    setOriginLost: function () {},
    loadRealms: function () {
      calls.push({ op: 'loadRealms' });
      return Promise.resolve([]);
    },
    heartbeat: function () {
      calls.push({ op: 'heartbeat' });
      return Promise.resolve({ alive: true });
    },
    routeClaim: function (realm, kind, digest, cell) {
      calls.push({ op: 'routeClaim', kind: kind });
      const k = realm + '|' + kind + '|' + digest;
      if (routes.has(k)) {
        return Promise.resolve({ cell: routes.get(k), claimed: false });
      }
      routes.set(k, cell);
      return Promise.resolve({ cell: cell, claimed: true });
    },
    routeRelease: function (realm, kind, digest, cell) {
      calls.push({ op: 'routeRelease', kind: kind });
      const k = realm + '|' + kind + '|' + digest;
      if (routes.get(k) === cell) {
        routes.delete(k);
        return Promise.resolve(true);
      }
      return Promise.resolve(false);
    },
    routeRemoveRealm: function () { return Promise.resolve(0); }
  };
  log.debug("Leaving stubDriver().");
  return stub;
}

// A job whose work is the global tier's claims its run there, so one cell
// runs each slot rather than every cell rotating the same key; every other
// claim stays in the cell's own database.
async function globalJobs(t) {
  log.debug("Entering globalJobs().");
  t.check(tiers.isGlobalJob('signing.rotate') &&
          tiers.isGlobalJob('krb5.krbtgt-rotate') &&
          !tiers.isGlobalJob('mail.deliver'),
          'a key rotation is a global job, a mail delivery is not');
  t.equal(tiers.claimTierOf(tiers.GLOBAL_RUN_SCOPE), 'global',
          'the global run scope is kept in the global tier');
  t.equal(tiers.claimTierOf('scheduler.run'), 'cell',
          'an ordinary run is claimed in the cell');
  const g = stubDriver('global');
  const c = stubDriver('cell');
  const d = tiered.create({ global: g, cell: c, cellId: 'usw2',
                            digest: function (realm, kind, value) {
                              return kind + ':' + value;
                            } });
  await d.claimOnce(tiers.GLOBAL_RUN_SCOPE, '', 'k', {});
  await d.releaseClaim(tiers.GLOBAL_RUN_SCOPE, '', 'k', 'r');
  await d.claimOnce('scheduler.run', '', 'k', {});
  const scopes = function (s) {
    return s.calls.filter(function (x) {
      return x.op === 'claimOnce' || x.op === 'releaseClaim';
    }).map(function (x) { return x.scope; }).join(',');
  };
  t.equal(scopes(g), tiers.GLOBAL_RUN_SCOPE + ',' + tiers.GLOBAL_RUN_SCOPE,
          'a global run is claimed and released in the global database');
  t.equal(scopes(c), 'scheduler.run',
          'an ordinary run is claimed in the cell\'s database');
  t.equal(await d.purgeClaims(), 4, 'expired claims are purged in both');

  // THE GLOBAL TIER'S EXPIRY PURGE IS ONE CELL'S (#695). Its cell half is
  // an ordinary job, run in every cell; its global half is a global job,
  // so its run is claimed in the ONE global database every cell shares,
  // under a run id that is the same in every cell for the same slot — the
  // cell that wins the claim purges the global tier, and the other does
  // not even ask it.
  t.check(tiers.isGlobalJob('persistence.minted-expiry-purge-global') &&
          !tiers.isGlobalJob('persistence.minted-expiry-purge'),
          'the global tier\'s expiry purge is a global job and the cell\'s ' +
          'is not');
  const shared = stubDriver('global');
  const held = new Set();
  shared.claimOnce = function (scope, realm, key) {
    log.debug("Entering claimOnce(), the shared global claims.");
    shared.calls.push({ op: 'claimOnce', scope: scope });
    const k = scope + '|' + realm + '|' + key;
    const ok = !held.has(k);
    held.add(k);
    log.debug("Leaving claimOnce(). " + ok);
    return Promise.resolve({ ok: ok });
  };
  const cellA = stubDriver('cell-a');
  const cellB = stubDriver('cell-b');
  const inA = tiered.create({ global: shared, cell: cellA, cellId: 'a' });
  const inB = tiered.create({ global: shared, cell: cellB, cellId: 'b' });
  const runGlobalPurge = function (store) {
    log.debug("Entering runGlobalPurge().");
    log.debug("Leaving runGlobalPurge().");
    return store.claimOnce(tiers.GLOBAL_RUN_SCOPE, '', 's-slot-1', {})
      .then(function (answer) {
        if (!answer.ok) {
          return { ran: false };
        }
        return store.purgeExpiredMinted('expired', { nowMs: 9, limit: 7,
                                                     tier: 'global' })
          .then(function (n) {
            return { ran: true, removed: n };
          });
      });
  };
  const ranA = await runGlobalPurge(inA);
  const ranB = await runGlobalPurge(inB);
  const globalPurges = shared.calls.filter(function (x) {
    return x.op === 'purgeExpiredMinted';
  });
  t.check(ranA.ran === true && ranA.removed === 1 && ranB.ran === false &&
          globalPurges.length === 1 && globalPurges[0].options.limit === 7 &&
          !('tier' in globalPurges[0].options),
          'THE CELL THAT WINS THE GLOBAL RUN CLAIM PURGES THE GLOBAL TIER, ' +
          'once, with its own limit; the other cell does not purge it',
          JSON.stringify([ranA, ranB, globalPurges.length]));
  t.check(!cellA.calls.concat(cellB.calls).some(function (x) {
    return x.op === 'purgeExpiredMinted';
  }), 'and neither cell\'s own database is asked by the global purge');

  // AND THE GLOBAL TIER'S TOMBSTONE SWEEP THE SAME (#1313).
  t.check(tiers.isGlobalJob('persistence.tombstone-purge-global') &&
          !tiers.isGlobalJob('persistence.tombstone-purge'),
          'the global tier\'s tombstone sweep is a global job and the ' +
          'cell\'s is not');
  const sweepGlobal = function (store) {
    log.debug("Entering sweepGlobal().");
    log.debug("Leaving sweepGlobal().");
    return store.claimOnce(tiers.GLOBAL_RUN_SCOPE, '', 't-slot-1', {})
      .then(function (answer) {
        if (!answer.ok) {
          return { ran: false };
        }
        return store.purgeTombstones(9, { tier: 'global', limit: 7 })
          .then(function (n) {
            return { ran: true, removed: n };
          });
      });
  };
  const sweptB = await sweepGlobal(inB);
  const sweptA = await sweepGlobal(inA);
  const globalSweeps = shared.calls.filter(function (x) {
    return x.op === 'purgeTombstones';
  });
  t.check(sweptB.ran === true && sweptB.removed === 1 &&
          sweptA.ran === false && globalSweeps.length === 1 &&
          JSON.stringify(globalSweeps[0].options) === '{"limit":7}',
          'ONLY THE CELL THAT WINS THE GLOBAL RUN CLAIM SWEEPS THE GLOBAL ' +
          'TOMBSTONES, once, with its own limit',
          JSON.stringify([sweptA, sweptB, globalSweeps]));
  t.check(!cellA.calls.concat(cellB.calls).some(function (x) {
    return x.op === 'purgeTombstones';
  }), 'and no cell\'s own database is swept by it');
  log.debug("Leaving globalJobs().");
}

async function tieredDriver(t) {
  log.debug("Entering tieredDriver().");
  const base = 'dc=acme,dc=example,dc=com';
  const g = stubDriver('global');
  const c = stubDriver('cell');
  const d = tiered.create({ global: g, cell: c, cellId: 'usw2',
                            digest: function (realm, kind, value) {
                              return kind + ':' + value;
                            } });
  t.check(d.tiered === true && d.name === 'postgres',
          'the tiered driver presents itself as the postgres store');
  await d.loadRealms();
  t.check(g.calls.some(function (x) { return x.op === 'loadRealms'; }) &&
          !c.calls.some(function (x) { return x.op === 'loadRealms'; }),
          'realms are read from the global tier only');
  await d.heartbeat();
  t.check(c.calls.some(function (x) { return x.op === 'heartbeat'; }) &&
          !g.calls.some(function (x) { return x.op === 'heartbeat'; }),
          'the cluster (a heartbeat) is the cell\'s');

  const alice = { realm: '', key: 'uid=alice,ou=users,' + base,
                  entry: { dn: 'uid=alice,ou=users,' + base,
                           attributes: { uid: ['alice'],
                                         entryUUID: ['u-1'] } } };
  const app = { realm: '', key: 'cn=app,ou=applications,' + base,
                entry: { dn: 'cn=app,ou=applications,' + base,
                         attributes: { cn: ['app'] } } };
  const grp = { realm: '', key: 'cn=admins,ou=groups,' + base,
                entry: { dn: 'cn=admins,ou=groups,' + base,
                         attributes: { cn: ['admins'],
                                       member: ['uid=alice,ou=users,' + base,
                                                'cn=app,ou=applications,' +
                                                base] } } };
  await d.saveDirectory({ upserts: [alice, app, grp], deletes: [],
                          removedRealms: [] });
  const gSave = g.calls.filter(function (x) {
    return x.op === 'saveDirectory';
  })[0].change;
  const cSave = c.calls.filter(function (x) {
    return x.op === 'saveDirectory';
  })[0].change;
  t.check(gSave.upserts.map(function (r) { return r.key; }).join('|') ===
          app.key + '|' + grp.key, 'the application and the group\'s ' +
          'definition go to the global tier, and no person does');
  t.check(cSave.upserts.map(function (r) { return r.key; }).join('|') ===
          alice.key + '|' + grp.key, 'the person and the group\'s person ' +
          'members go to the cell');
  const cellGroup = cSave.upserts.filter(function (r) {
    return r.key === grp.key;
  })[0];
  t.check(JSON.stringify(cellGroup.entry.attributes) ===
          JSON.stringify({ member: ['uid=alice,ou=users,' + base] }),
          'the cell half of the group holds only alice');
  // THE FIRST RESIDENT MEMBER OF A GROUP (2026-09-28): the base held none,
  // so this cell stored no half, and the cell half is sent with NO base —
  // the base's empty half read as "stored and deleted since", and the
  // merge dropped the member (sts_cells_console.js).
  const firstBase = JSON.stringify({ dn: grp.entry.dn, attributes: {
    cn: ['admins'], member: ['cn=app,ou=applications,' + base] } });
  await d.saveDirectory({ upserts: [Object.assign({}, grp,
                                                  { base: firstBase })],
                          deletes: [], removedRealms: [] });
  const firstCell = c.calls.filter(function (x) {
    return x.op === 'saveDirectory';
  })[1].change.upserts[0];
  const firstGlobal = g.calls.filter(function (x) {
    return x.op === 'saveDirectory';
  })[1].change.upserts[0];
  t.check(firstCell.key === grp.key && firstCell.base === null,
          'a group\'s first resident member goes to the cell with no base: ' +
          'its cell half was never stored');
  t.check(typeof firstGlobal.base === 'string',
          'and the global half keeps its base');
  const claims = g.calls.filter(function (x) {
    return x.op === 'routeClaim';
  }).length;
  t.equal(claims, 2, 'a new person claims their login name and entryUUID ' +
          'in the routing index');
  await d.saveDirectory({ upserts: [alice], deletes: [], removedRealms: [] });
  t.equal(g.calls.filter(function (x) {
    return x.op === 'routeClaim';
  }).length, 2, 'writing the same person again claims nothing more');

  // A second cell holding a person of the same name: the claim answers
  // with the other cell and the conflict is counted.
  const other = tiered.create({ global: g, cell: stubDriver('cell2'),
                                cellId: 'cac1',
                                digest: function (realm, kind, value) {
                                  return kind + ':' + value;
                                } });
  await other.saveDirectory({ upserts: [alice], deletes: [],
                              removedRealms: [] });
  t.equal(other.routingStatus().conflicts, 1, 'a person already homed ' +
          'elsewhere is counted as a conflict, not swallowed');

  await d.saveDirectory({ upserts: [], deletes: [{ realm: '',
                                                   key: alice.key }],
                          removedRealms: [] });
  t.equal(g.calls.filter(function (x) {
    return x.op === 'routeRelease';
  }).length, 2, 'deleting a person releases both of their index rows');
  t.equal(g.routes.size, 0, 'and the index no longer holds them');

  // The load joins the group's halves.
  g.directoryRows[''] = [{ dn: grp.entry.dn, attributes: {
    cn: ['admins'], member: ['cn=app,ou=applications,' + base] } }];
  c.directoryRows[''] = [{ dn: grp.entry.dn, attributes: {
    member: ['uid=alice,ou=users,' + base] } },
  { dn: alice.entry.dn, attributes: alice.entry.attributes }];
  const loaded = await d.loadDirectory();
  const loadedGroup = loaded[''].filter(function (e) {
    return e.dn === grp.entry.dn;
  });
  t.check(loadedGroup.length === 1 && loadedGroup[0].attributes.member
          .length === 2, 'a load restores the group once, with both halves ' +
          'of its membership');
  t.check(loaded[''].some(function (e) { return e.dn === alice.entry.dn; }),
          'and the cell\'s person');

  // A minted read carries its filter to BOTH tiers: dropping it made every
  // node of testidpna refuse to start (STS-STORE-0026).
  const filter = { realms: [''], staleBefore: 0, ageHandles: [] };
  let readRefused = null;
  await d.loadMinted(filter).catch(function (e) { readRefused = e; });
  const reads = g.calls.concat(c.calls).filter(function (x) {
    return x.op === 'loadMinted';
  });
  t.check(!readRefused && reads.length === 2 &&
          reads.every(function (x) { return x.filter === filter; }),
          'loadMinted() hands its filter to the global and the cell tier',
          readRefused ? readRefused.message : reads.length + ' read(s)');

  // Minted rows by handle.
  await d.saveMinted([{ handle: 'dpop.seenJtis', realm: '', key: 'j' },
                      { handle: 'authn.sessions', realm: '', key: 's' }], []);
  const gm = g.calls.filter(function (x) { return x.op === 'saveMinted'; });
  const cm = c.calls.filter(function (x) { return x.op === 'saveMinted'; });
  t.check(gm.length === 1 && gm[0].upserts[0].handle === 'dpop.seenJtis' &&
          cm.length === 1 && cm[0].upserts[0].handle === 'authn.sessions',
          'a global store\'s row goes to the global tier and a session to ' +
          'the cell');

  // The expiry purge reaches the global tier (#360). Bound to the cell
  // driver, it deleted only this cell's rows.
  const given = ['dpop.seenJtis', 'authn.sessions', 'nobody.decided'];
  const expired = await d.purgeExpiredMinted('expired', { nowMs: 5,
                                                          limit: 10 });
  // The realms are the GLOBAL registry's (#360): a cell's own sts_realms is
  // not one, and judged against it every cell row of a later realm was an
  // orphan.
  const realmsBefore = g.loadRealms;
  g.loadRealms = function () {
    log.debug("Entering loadRealms(), the registry of acme.");
    log.debug("Leaving loadRealms().");
    return Promise.resolve([{ id: 'acme' }]);
  };
  const orphan = await d.purgeExpiredMinted('orphan', {
    defaultRealm: 'default', orphanBeforeMs: 4, limit: 10 });
  const stale = await d.purgeExpiredMinted('stale', {
    handles: given, staleBeforeMs: 3, limit: 10 });
  t.equal(expired, 2, 'an expiry purge counts both tiers');
  t.equal(orphan, 2, 'an orphan purge counts both tiers');
  t.equal(stale, 2, 'a stale purge counts both tiers');
  const ofKind = function (driver, kind) {
    log.debug("Entering ofKind().");
    const out = driver.calls.filter(function (x) {
      return x.op === 'purgeExpiredMinted' && x.kind === kind;
    });
    log.debug("Leaving ofKind().");
    return out;
  };
  const gExpired = ofKind(g, 'expired');
  const cExpired = ofKind(c, 'expired');
  t.check(gExpired.length === 1 && cExpired.length === 1 &&
          gExpired[0].options.nowMs === 5 &&
          cExpired[0].options.nowMs === 5 &&
          gExpired[0].options.limit === 10,
          'expired rows are purged in the global tier and in the cell');
  const gOrphan = ofKind(g, 'orphan');
  const cOrphan = ofKind(c, 'orphan');
  t.check(gOrphan.length === 1 && cOrphan.length === 1 &&
          gOrphan[0].options.defaultRealm === 'default' &&
          cOrphan[0].options.orphanBeforeMs === 4 &&
          cOrphan[0].options.orphanBeforeMs ===
          gOrphan[0].options.orphanBeforeMs,
          'orphan rows are purged in both tiers, with the same rule');
  t.check(JSON.stringify(gOrphan[0].options.realms) === '["acme"]' &&
          JSON.stringify(cOrphan[0].options.realms) === '["acme"]',
          'and both are judged against the global registry\'s realms, ' +
          'never the cell database\'s own sts_realms',
          JSON.stringify(cOrphan[0].options.realms));
  g.loadRealms = function () {
    log.debug("Entering loadRealms(), which fails.");
    log.debug("Leaving loadRealms().");
    return Promise.reject(new Error('the global database is down'));
  };
  let unreadRefused = null;
  await d.purgeExpiredMinted('orphan', { defaultRealm: 'default',
                                         orphanBeforeMs: 4, limit: 10 })
    .catch(function (e) {
      log.debug("Caught in the orphan purge: " + ((e && e.message) || e));
      unreadRefused = e;
    });
  t.check(!!unreadRefused && ofKind(c, 'orphan').length === 1 &&
          ofKind(g, 'orphan').length === 1,
          'when the registry cannot be read, no tier purges an orphan');
  t.check(!!unreadRefused && unreadRefused.registryUnreadable === true &&
          unreadRefused.removed === 0 &&
          /global realm registry could not be read/.test(
            unreadRefused.message),
          'and the refusal is MARKED as an unreadable registry (#1313), so ' +
          'the cell\'s job can count the orphan check skipped rather than ' +
          'its run failed', unreadRefused ? unreadRefused.message : '');
  g.loadRealms = realmsBefore;
  const gStale = ofKind(g, 'stale');
  const cStale = ofKind(c, 'stale');
  t.check(gStale.length === 1 && gStale[0].options.staleBeforeMs === 3 &&
          gStale[0].options.limit === 10 &&
          JSON.stringify(gStale[0].options.handles) ===
          JSON.stringify(['dpop.seenJtis']),
          'a stale purge hands the global tier only its own stores');
  t.check(cStale.length === 1 && cStale[0].options.staleBeforeMs === 3 &&
          JSON.stringify(cStale[0].options.handles) ===
          JSON.stringify(['authn.sessions', 'nobody.decided']),
          'and the cell its own, an unclassified handle included');
  t.check(given.join(',') === 'dpop.seenJtis,authn.sessions,nobody.decided',
          'the caller\'s handle list is left as it was given');

  // ONE TIER WHEN ONE IS NAMED, AND THE TWO SETTLED APART (#695). The
  // purge jobs name a tier, so a batch's limit and count are one
  // database's; asked of both, one failing no longer hides the other's.
  const purgesBefore = { g: ofKind(g, 'expired').length,
                         c: ofKind(c, 'expired').length };
  const cellOnly = await d.purgeExpiredMinted('expired', { nowMs: 6,
                                                           limit: 4,
                                                           tier: 'cell' });
  t.check(cellOnly === 1 && ofKind(g, 'expired').length === purgesBefore.g &&
          ofKind(c, 'expired').length === purgesBefore.c + 1 &&
          ofKind(c, 'expired')[purgesBefore.c].options.limit === 4 &&
          !('tier' in ofKind(c, 'expired')[purgesBefore.c].options),
          'a purge naming the cell tier asks only the cell, with the whole ' +
          'limit, and the tier name stops at the tiered driver');
  const globalOnly = await d.purgeExpiredMinted('expired', { nowMs: 6,
                                                             limit: 4,
                                                             tier: 'global' });
  t.check(globalOnly === 1 &&
          ofKind(g, 'expired').length === purgesBefore.g + 1 &&
          ofKind(c, 'expired').length === purgesBefore.c + 1,
          'and one naming the global tier asks only the global database');
  const globalPurge = g.purgeExpiredMinted;
  g.purgeExpiredMinted = function () {
    log.debug("Entering purgeExpiredMinted(), the global one, unreachable.");
    log.debug("Leaving purgeExpiredMinted().");
    return Promise.reject(new Error('the global database is unreachable'));
  };
  let bothRefused = null;
  await d.purgeExpiredMinted('expired', { nowMs: 6, limit: 4 })
    .catch(function (e) {
      log.debug("Caught in the purge of both: " + ((e && e.message) || e));
      bothRefused = e;
    });
  t.check(!!bothRefused && bothRefused.removed === 1 &&
          bothRefused.tier === 'global' &&
          ofKind(c, 'expired').length === purgesBefore.c + 2,
          'asked of both with the global database unreachable, the cell is ' +
          'still purged and its count rides on the refusal, which names ' +
          'the tier that failed',
          bothRefused ? bothRefused.message + ' ' + bothRefused.removed : '');
  t.equal(await d.purgeExpiredMinted('expired', { nowMs: 6, limit: 4,
                                                  tier: 'cell' }), 1,
          'and the cell tier\'s own purge does not notice the global one ' +
          'is down');
  g.purgeExpiredMinted = globalPurge;

  // THE TOMBSTONES, ONE TIER WHEN ONE IS NAMED (#1313), the expiry purge's
  // rule: the tier consumed here, the limit that database's alone; asked
  // of both, settled apart.
  const tombsOf = function (driver) {
    log.debug("Entering tombsOf().");
    log.debug("Leaving tombsOf().");
    return driver.calls.filter(function (x) {
      return x.op === 'purgeTombstones';
    });
  };
  t.equal(await d.purgeTombstones(11, { tier: 'cell', limit: 5 }), 1,
          'a tombstone sweep naming the cell counts the cell\'s');
  t.check(tombsOf(c).length === 1 && tombsOf(g).length === 0 &&
          tombsOf(c)[0].beforeMs === 11 &&
          JSON.stringify(tombsOf(c)[0].options) === '{"limit":5}',
          'and asks only the cell, with its own limit, the tier name ' +
          'stopping at the tiered driver', JSON.stringify(tombsOf(c)));
  t.equal(await d.purgeTombstones(12, { tier: 'global', limit: 5 }), 1,
          'one naming the global tier counts the global tier\'s');
  t.check(tombsOf(g).length === 1 && tombsOf(c).length === 1,
          'and asks only the global database');
  t.equal(await d.purgeTombstones(13), 2,
          'with no tier both are asked and the counts summed');
  t.check(tombsOf(g)[1].options === undefined &&
          tombsOf(c)[1].options === undefined,
          'each with no limit, the statement each database always ran');
  const globalTombs = g.purgeTombstones;
  g.purgeTombstones = function () {
    log.debug("Entering purgeTombstones(), the global one, unreachable.");
    log.debug("Leaving purgeTombstones().");
    return Promise.reject(new Error('the global database is unreachable'));
  };
  let tombsRefused = null;
  await d.purgeTombstones(14).catch(function (e) {
    log.debug("Caught in the sweep of both: " + ((e && e.message) || e));
    tombsRefused = e;
  });
  t.check(!!tombsRefused && tombsRefused.removed === 1 &&
          tombsRefused.tier === 'global' && tombsOf(c).length === 3,
          'A DOWN GLOBAL DATABASE LOSES NO CELL COUNT: asked of both, the ' +
          'cell is swept and its count rides on the refusal, which names ' +
          'the tier that failed',
          tombsRefused ? tombsRefused.message + ' ' + tombsRefused.removed
            : 'it succeeded');
  t.equal(await d.purgeTombstones(15, { tier: 'cell', limit: 5 }), 1,
          'and the cell\'s own sweep does not notice');
  g.purgeTombstones = globalTombs;
  t.equal(d.changeRowsWritten(), 4, 'the change rows written are both ' +
          'databases\' together');
  ['STS-CELL-0001', 'STS-CELL-0002', 'STS-CELL-0003', 'STS-CELL-0004',
   'STS-CELL-0010', 'STS-CELL-0011', 'STS-CELL-0012', 'STS-CELL-0020',
   'STS-CELL-0021', 'STS-CELL-0022'].forEach(function (code) {
    t.check(errorCodes.isKnown(code), code + ' is registered');
  });
  log.debug("Leaving tieredDriver().");
}

// 4. The cell key. Required here rather than at the top: the keystore loads
// the realm registry, which is TypeScript, so this part runs where the tree
// is compiled (the tests image), as every in-process test does.
function sealing(t) {
  log.debug("Entering sealing().");
  const keystore = require('../common/keystore');
  const crypto = require('crypto');
  const service = crypto.randomBytes(32).toString('hex');
  const cell = crypto.randomBytes(32).toString('hex');
  t.check(keystore.useEphemeralKek(service), 'a service key is installed');
  t.check(keystore.useEphemeralCellKek(cell), 'a cell key is installed');
  const cellRow = keystore.seal('resident', 'test', 'cell');
  const globalRow = keystore.seal('configuration', 'test', 'global');
  t.equal(keystore.open(cellRow, 'test'), 'resident',
          'a cell-tier row opens where the cell key is');
  t.equal(keystore.open(globalRow, 'test'), 'configuration',
          'a global row opens there too');
  keystore.useEphemeralCellKek('');
  t.equal(keystore.open(cellRow, 'test'), null,
          'a cell-tier row does NOT open in a process without the cell key');
  t.equal(keystore.open(globalRow, 'test'), 'configuration',
          'a global row opens in every cell');
  t.check(keystore.seal('x', 'test', 'cell') !== null,
          'without a cell key the cell tier is sealed under the service key');
  keystore.reset();
  log.debug("Leaving sealing().");
}

async function run(t) {
  log.debug("Entering run().");
  everyClassified(t);
  directory(t);
  await tieredDriver(t);
  await globalJobs(t);
  sealing(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_tiers',
  describe: 'A cell\'s store (#98): every persisted store is classified ' +
            'global or cell, the directory is split by where an entry sits ' +
            'and a group into two halves, and the tiered driver sends each ' +
            'write to its database, purges expired minted rows from both, ' +
            'and keeps the routing index',
  run: run
};
