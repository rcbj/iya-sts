// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
//      and a conflict counted rather than swallowed.
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
    loadMinted: function () { return Promise.resolve(minted.slice()); },
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
    purgeTombstones: function () { return Promise.resolve(1); },
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

  // Minted rows by handle.
  await d.saveMinted([{ handle: 'dpop.seenJtis', realm: '', key: 'j' },
                      { handle: 'authn.sessions', realm: '', key: 's' }], []);
  const gm = g.calls.filter(function (x) { return x.op === 'saveMinted'; });
  const cm = c.calls.filter(function (x) { return x.op === 'saveMinted'; });
  t.check(gm.length === 1 && gm[0].upserts[0].handle === 'dpop.seenJtis' &&
          cm.length === 1 && cm[0].upserts[0].handle === 'authn.sessions',
          'a global store\'s row goes to the global tier and a session to ' +
          'the cell');
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
            'write to its database and keeps the routing index',
  run: run
};
