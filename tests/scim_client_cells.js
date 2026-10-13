// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: scim_client_cells.js
// ===========================================================================
// THE OUTBOUND SCIM CLIENT IN A SERVICE DEPLOYED AS CELLS (#553).
//
// In process, TWO CELLS in one process: two instances of
// `scim/scim_client.ts`'s `ScimClients`, each with a directory of its own
// (a fake: the people homed in that cell, and that cell's SHARE of each
// group, whose definition both hold), stores of its own (its deliveries,
// links and last reconciliation, as the cell tier keeps them) and ONE shared
// pause store (the global tier). What `tests/cell_handlers_c.js` stubs is
// stubbed here the same way, as each instance's dependencies: the cell map,
// the routing index and the inter-cell channel — whose `call()` hands the
// body to the OTHER instance's registered operation, through JSON, so the
// operations' own handlers answer. The transfer question is the real
// `cell_transfer.ts` over the stubbed cell map, so the issuance policy's
// built-in rule decides it. The service provider is an in-memory fake
// behind the client's `transport`, so nothing listens.
//
//   A. HOME-CELL PUSHING: each cell pushes the people homed there and never
//      another cell's; a projection is not pushed; a cell left out of
//      scimClientCells pushes nothing.
//   B. THE TRANSFER DECISION (purpose scim-provision): a person the policy
//      keeps out is not pushed and no delivery is made (no dead letter); a
//      person pushed before is deprovisioned when the policy stops letting
//      them go.
//   C. A MOVE IS A HANDOVER: the old cell sends nothing and drops its link;
//      the new home finds the resource by externalId and keeps it active.
//      A person gone everywhere is deprovisioned.
//   D. A GROUP ACROSS CELLS, WITH PATCH: members from both cells kept
//      through changes in either; a group two cells create is one group (the
//      second adopts it on 409 by externalId, and PATCHes its share in); a
//      cell never removes another cell's member; the OWNER deletes only
//      when every cell answers none, and not while one is unreachable — and
//      a member-groups group with members in the other cell is kept.
//   E. WITHOUT PATCH: the owner PUTs every cell's share merged, the other
//      cell never writes the group, and nothing is PUT while a cell cannot
//      be asked.
//   F. THE SHARED PAUSE: a 503 one cell sees pauses both; one probe goes
//      for the whole service and the other cell waits for it, taking it
//      over only once the probing cell has been silent past the pause; the
//      concurrency budget is scimClient.concurrency split across the cells
//      that push, and the queue holds a cell to it.
//   Z. NOTHING A SERVICE PROVIDER SEES NAMES A CELL, and a service that is
//      one cell asks no transfer question.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const config = require('../common/config');
const gate = require('../common/issuance_gate');
const cellTransfer = require('../common/cell_transfer');
const scimClient = require('../scim/scim_client');

const log = require('bunyan').createLogger({ name: 'scim_client_cells',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const BASE = 'https://sp.example.test/scim/v2';
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const CELLS = [{ id: 'cella', jurisdiction: 'us' },
               { id: 'cellb', jurisdiction: 'ca' }];

// ---------------------------------------------------------------------------
// THE WORLD BOTH CELLS SHARE: the clock, the cell map's settings, the
// routing index, the reachable cells, and the service provider.
// ---------------------------------------------------------------------------
const world = {
  multi: true,
  t: Date.now(),
  permitted: ['us>eu', 'ca>eu'],
  homes: {},
  unreachable: {},
  settings: {},
  transferAsks: 0,
  // The global tier's pause store, one for both cells.
  pauses: realms.map(),
  cells: {}
};

function freshProvider() {
  log.debug('Entering freshProvider().');
  log.debug('Leaving freshProvider().');
  return { users: {}, groups: {}, seq: 0, patch: true, requests: [],
           fail: [], hideSearch: 0, delayMs: 0, inFlight: {},
           maxInFlight: {} };
}

let sp = freshProvider();

function uuidFor(name) {
  log.debug('Entering uuidFor().');
  const hex = nodeCrypto.createHash('sha256').update(RUN + name)
    .digest('hex');
  log.debug('Leaving uuidFor().');
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-4' + hex.slice(13, 16) +
         '-8' + hex.slice(17, 20) + '-' + hex.slice(20, 32);
}

// ---------------------------------------------------------------------------
// THE FAKE SERVICE PROVIDER, behind `transport`.
// ---------------------------------------------------------------------------
function answer(status, body, headers) {
  log.debug('Entering answer().');
  log.debug('Leaving answer().');
  return Promise.resolve({ status: status,
    headers: Object.assign({ 'content-type': 'application/scim+json' },
                           headers || {}),
    text: body === undefined ? '' : JSON.stringify(body) });
}

function scimError(status, scimType) {
  log.debug('Entering scimError().');
  log.debug('Leaving scimError().');
  return answer(status, { schemas: [
    'urn:ietf:params:scim:api:messages:2.0:Error'], status: String(status),
    scimType: scimType, detail: 'scripted' });
}

function withMeta(r, type) {
  log.debug('Entering withMeta().');
  log.debug('Leaving withMeta().');
  return Object.assign({}, r.body, { id: r.id,
    meta: { resourceType: type, version: 'W/"' + r.v + '"' } });
}

function matches(r, filter) {
  log.debug('Entering matches().');
  const m = /^(\w+) eq (".*")$/.exec(filter || '');
  log.debug('Leaving matches().');
  return !!m && String(r.body[m[1]] || '') === JSON.parse(m[2]);
}

function applyPatch(r, ops) {
  log.debug('Entering applyPatch().');
  ops.forEach(function (op) {
    if (op.path === 'active') {
      r.body.active = op.value;
    } else if (op.path === 'displayName') {
      r.body.displayName = op.value;
    } else if (op.path === 'members' && op.op === 'add') {
      const have = (r.body.members || []).map(function (one) {
        return one.value;
      });
      r.body.members = (r.body.members || []).concat(
        op.value.filter(function (one) {
          return have.indexOf(one.value) < 0;
        }));
    } else if (/^members\[value eq /.test(op.path) && op.op === 'remove') {
      const v = JSON.parse(/eq (".*")\]$/.exec(op.path)[1]);
      r.body.members = (r.body.members || []).filter(function (one) {
        return one.value !== v;
      });
    }
  });
  log.debug('Leaving applyPatch().');
}

// The provider: one request, from one cell (`from`, for the test's eyes
// only — nothing of it is on the wire).
function provider(from, options, text) {
  log.debug('Entering provider(). ' + options.method);
  const url = new URL(options.path, 'https://sp.example.test');
  const parts = url.pathname.replace(/^\/scim\/v2/, '').split('/')
    .filter(Boolean);
  const body = text ? JSON.parse(text) : null;
  // Time passes as requests are answered, so a change made while a
  // delivery is in flight is LATER than its attempt, as it is in life.
  world.t += 1;
  sp.requests.push({ from: from, method: options.method,
                     path: url.pathname + url.search, body: body,
                     headers: options.headers, text: text || '' });
  for (let i = 0; i < sp.fail.length; i++) {
    const f = sp.fail[i];
    if ((!f.from || f.from === from) && f.method === options.method &&
        url.pathname.indexOf(f.path) >= 0) {
      sp.fail.splice(i, 1);
      return f.status === 503
        ? answer(503, { status: '503' }, { 'retry-after': '1' })
        : scimError(f.status, f.scimType);
    }
  }
  if (parts[0] === 'ServiceProviderConfig') {
    log.debug('Leaving provider(). Configuration.');
    return answer(200, { patch: { supported: sp.patch },
                         filter: { supported: true, maxResults: 100 },
                         etag: { supported: false },
                         bulk: { supported: false } });
  }
  if (parts[0] === 'ResourceTypes') {
    log.debug('Leaving provider(). Types.');
    return answer(200, { Resources: [
      { name: 'User', endpoint: '/Users', schemaExtensions: [] },
      { name: 'Group', endpoint: '/Groups', schemaExtensions: [] }] });
  }
  const type = parts[0] === 'Users' ? 'User'
    : parts[0] === 'Groups' ? 'Group' : '';
  const store = type === 'User' ? sp.users : sp.groups;
  const id = parts[1];
  if (!type) {
    log.debug('Leaving provider(). No endpoint.');
    return scimError(404);
  }
  if (!id && options.method === 'GET') {
    let all = Object.keys(store).map(function (k) {
      return store[k];
    });
    const filter = url.searchParams.get('filter');
    if (filter) {
      if (sp.hideSearch > 0 && type === 'Group' &&
          /^externalId eq/.test(filter)) {
        sp.hideSearch -= 1;
        all = [];
      } else {
        all = all.filter(function (r) {
          return matches(r, filter);
        });
      }
    }
    log.debug('Leaving provider(). A list.');
    return answer(200, { totalResults: all.length, startIndex: 1,
      Resources: all.map(function (r) {
        return withMeta(r, type);
      }) });
  }
  if (!id && options.method === 'POST') {
    const clash = Object.keys(store).some(function (k) {
      const r = store[k].body;
      return r.externalId === body.externalId ||
             (type === 'User' ? r.userName === body.userName
                              : r.displayName === body.displayName);
    });
    if (clash) {
      log.debug('Leaving provider(). Uniqueness.');
      return scimError(409, 'uniqueness');
    }
    const made = { id: 'sp-' + (++sp.seq), v: 1, body: body };
    store[made.id] = made;
    log.debug('Leaving provider(). Created.');
    return answer(201, withMeta(made, type));
  }
  const r = store[id];
  if (!r) {
    log.debug('Leaving provider(). Not there.');
    return scimError(404);
  }
  if (options.method === 'GET') {
    log.debug('Leaving provider(). One.');
    return answer(200, withMeta(r, type));
  }
  if (options.method === 'PUT') {
    r.body = body;
    r.v++;
    log.debug('Leaving provider(). Replaced.');
    return answer(200, withMeta(r, type));
  }
  if (options.method === 'PATCH') {
    if (!sp.patch) {
      log.debug('Leaving provider(). No PATCH.');
      return scimError(501);
    }
    applyPatch(r, body.Operations || []);
    r.v++;
    log.debug('Leaving provider(). Patched.');
    return answer(200, withMeta(r, type));
  }
  if (options.method === 'DELETE') {
    delete store[id];
    log.debug('Leaving provider(). Deleted.');
    return answer(204);
  }
  log.debug('Leaving provider(). A method.');
  return scimError(405);
}

// ---------------------------------------------------------------------------
// A CELL: its directory, its stores, its stubs, and its instance.
// ---------------------------------------------------------------------------
const DOMAIN = 'dc=example,dc=test';

function personDn(name) {
  log.debug('Entering personDn().');
  log.debug('Leaving personDn().');
  return 'uid=' + name + ',ou=users,' + DOMAIN;
}

function groupDn(name) {
  log.debug('Entering groupDn().');
  log.debug('Leaving groupDn().');
  return 'cn=' + name + ',ou=groups,' + DOMAIN;
}

// The group DEFINITIONS, global: every cell's directory has each one.
const groupDefinitions = {};

function fakeDirectory(cellId) {
  log.debug('Entering fakeDirectory(). ' + cellId);
  // This cell's residents, by dn, and its share of each group (group dn ->
  // member dns).
  const people = {};
  const shares = {};
  const norm = function (dn) {
    return String(dn || '').toLowerCase();
  };
  const dir = {
    people: people,
    shares: shares,
    addAccountObserver: function () {
      return undefined;
    },
    normalizeDn: norm,
    add: function (name) {
      const dn = personDn(name);
      people[norm(dn)] = { dn: dn, attributes: {
        entryUUID: [uuidFor(name)], uid: [name], cn: [name] } };
      return people[norm(dn)];
    },
    drop: function (name) {
      delete people[norm(personDn(name))];
      Object.keys(shares).forEach(function (g) {
        shares[g] = shares[g].filter(function (one) {
          return one !== norm(personDn(name));
        });
      });
    },
    join: function (name, group) {
      const g = norm(groupDn(group));
      shares[g] = (shares[g] || []).concat([norm(personDn(name))]);
    },
    leave: function (name, group) {
      const g = norm(groupDn(group));
      shares[g] = (shares[g] || []).filter(function (one) {
        return one !== norm(personDn(name));
      });
    },
    readPerson: function (dn) {
      return people[norm(dn)] || null;
    },
    isPersonEntry: function (entry) {
      return !!entry && /,ou=users,/i.test(entry.dn);
    },
    usernameOfEntry: function (entry) {
      return entry.attributes.uid[0];
    },
    resourceIdOfDn: function (dn) {
      const p = people[norm(dn)];
      if (p) {
        return p.attributes.entryUUID[0];
      }
      const g = groupDefinitions[norm(dn)];
      return g ? g.uuid : '';
    },
    entryByUuid: function (uuid) {
      const hit = Object.keys(people).filter(function (k) {
        return people[k].attributes.entryUUID[0] === uuid;
      })[0];
      if (hit) {
        return people[hit];
      }
      const g = Object.keys(groupDefinitions).filter(function (k) {
        return groupDefinitions[k].uuid === uuid;
      })[0];
      return g ? { dn: groupDefinitions[g].dn } : null;
    },
    readGroupEntry: function (dn) {
      const g = groupDefinitions[norm(dn)];
      if (!g) {
        return null;
      }
      return { dn: g.dn, attributes: { entryUUID: [g.uuid], cn: [g.cn] },
               members: (shares[norm(dn)] || []).map(function (m) {
                 return { dn: m };
               }) };
    },
    groupsOfUser: function (dn) {
      const out = [];
      Object.keys(shares).forEach(function (g) {
        if (groupDefinitions[g] && shares[g].indexOf(norm(dn)) >= 0) {
          out.push({ dn: groupDefinitions[g].dn, cn: groupDefinitions[g].cn });
        }
      });
      return { groups: out };
    },
    allPersons: function () {
      return Object.keys(people).map(function (k) {
        return people[k];
      });
    },
    allGroupEntries: function () {
      return Object.keys(groupDefinitions).map(function (k) {
        return dir.readGroupEntry(groupDefinitions[k].dn);
      });
    }
  };
  log.debug('Leaving fakeDirectory().');
  return dir;
}

function defineGroup(name) {
  log.debug('Entering defineGroup().');
  const dn = groupDn(name);
  groupDefinitions[dn.toLowerCase()] = { dn: dn, cn: name,
                                         uuid: uuidFor('group-' + name) };
  log.debug('Leaving defineGroup().');
  return groupDefinitions[dn.toLowerCase()];
}

function undefineGroup(name) {
  log.debug('Entering undefineGroup().');
  delete groupDefinitions[groupDn(name).toLowerCase()];
  log.debug('Leaving undefineGroup().');
}

// The client, as the global tier's application entry reads.
const client = { fields: {} };

function setClient(fields) {
  log.debug('Entering setClient().');
  client.fields = Object.assign({
    scimClientBaseUrl: BASE, scimClientEnabled: 'TRUE',
    scimClientAuthMethod: 'basic', scimClientUsername: 'pusher',
    scimClientPassword: '(withheld)', scimClientScopeMode: 'all',
    scimClientGroupMode: 'none', scimClientDeprovision: 'deactivate',
    scimClientJurisdiction: 'eu'
  }, fields || {});
  log.debug('Leaving setClient().');
}

const applicationsStub = {
  list: function () {
    return [{ identifier: 'pusher-' + RUN, dn: 'cn=pusher,ou=applications',
              name: 'Pusher', fields: client.fields }];
  },
  declaredFamiliesOf: function () {
    return ['scim-client'];
  },
  scimClientCredentialOf: function () {
    return 'pusher-password';
  }
};

const scimMapStub = {
  toScimUser: function (entry) {
    return { schemas: [USER_SCHEMA], userName: entry.attributes.uid[0],
             displayName: entry.attributes.cn[0], active: true };
  },
  prune: function (x) {
    return x;
  }
};

function cellsStub(cellId) {
  log.debug('Entering cellsStub().');
  log.debug('Leaving cellsStub().');
  return {
    isMulti: function () {
      return world.multi;
    },
    id: function () {
      return world.multi ? cellId : '';
    },
    all: function () {
      return CELLS.map(function (one) {
        return { id: one.id, jurisdiction: one.jurisdiction,
                 self: one.id === cellId };
      });
    },
    get: function (id) {
      return CELLS.filter(function (one) {
        return one.id === id;
      })[0] || null;
    },
    jurisdictionOf: function (id) {
      const hit = CELLS.filter(function (one) {
        return one.id === id;
      })[0];
      return hit ? hit.jurisdiction : '';
    },
    transferListed: function (home, serving) {
      world.transferAsks += 1;
      return home === serving ||
             world.permitted.indexOf(home + '>' + serving) >= 0;
    }
  };
}

// The channel: `call()` hands the body, through JSON, to the named cell's
// registered operation; an unreachable cell rejects, as the real one does.
function channelStub(cellId) {
  log.debug('Entering channelStub().');
  const ops = {};
  log.debug('Leaving channelStub().');
  return {
    ops: ops,
    registerOp: function (name, handler) {
      ops[name] = handler;
    },
    call: function (target, name, body) {
      world.calls = (world.calls || []).concat([{ from: cellId, to: target,
                                                  name: name }]);
      if (world.unreachable[target]) {
        return Promise.reject(new Error('cell "' + target + '" is not ' +
                                        'reachable'));
      }
      const peer = world.cells[target];
      const handler = peer && peer.channel.ops[name];
      if (!handler) {
        return Promise.reject(new Error('no operation "' + name + '"'));
      }
      const sent = JSON.parse(JSON.stringify(body === undefined ? {}
                                                                : body));
      return realms.run(realms.get(sent.realm) || realms.get('default'),
        function () {
          return Promise.resolve(handler(sent, { peer: cellId }));
        }).then(function (got) {
          return JSON.parse(JSON.stringify(got === undefined ? {} : got));
        });
    }
  };
}

function makeCell(cellId) {
  log.debug('Entering makeCell(). ' + cellId);
  const dir = fakeDirectory(cellId);
  const channel = channelStub(cellId);
  const cells = cellsStub(cellId);
  const claimed = new Set();
  const projections = new Set();
  const transfer = new cellTransfer.CellTransfer({
    cells: cells,
    value: function (key) {
      return world.settings[key];
    },
    gate: gate,
    realms: realms,
    log: log
  });
  const settings = {
    value: function (key) {
      return Object.prototype.hasOwnProperty.call(world.settings, key)
        ? world.settings[key] : config.value(key);
    }
  };
  const deps = Object.assign(scimClient.ScimClients.defaultDeps(), {
    config: settings,
    now: function () {
      return world.t;
    },
    random: function () {
      return 0.5;
    },
    applications: function () {
      return applicationsStub;
    },
    directory: function () {
      return dir;
    },
    scimMap: function () {
      return scimMapStub;
    },
    scheduler: function () {
      return { job: function () {
        return true;
      }, register: function () {
        return undefined;
      } };
    },
    cells: function () {
      return cells;
    },
    channel: function () {
      return channel;
    },
    routing: function () {
      return { homeOf: function (realmId, kind, value) {
        return Promise.resolve(world.homes[value] || '');
      } };
    },
    transfer: function () {
      return transfer;
    },
    projected: function (realmId, uuid) {
      return projections.has(uuid);
    },
    stores: { deliveries: realms.map(), links: realms.map(),
              states: realms.map(), pauses: world.pauses },
    deliveryDeps: {
      now: function () {
        return world.t;
      },
      config: settings,
      claims: { claim: function (o) {
        const key = o.scope + '|' + o.value;
        if (claimed.has(key)) {
          return Promise.resolve({ ok: false, reason: 'held' });
        }
        claimed.add(key);
        return Promise.resolve({ ok: true, claimedAt: world.t });
      } },
      beforeSend: function () {
        return Promise.resolve();
      }
    },
    transport: function (options, text) {
      if (!sp.delayMs) {
        return provider(cellId, options, text);
      }
      // A SLOW PROVIDER, for the concurrency budget: requests overlap, and
      // the most in flight at once from each cell is counted.
      sp.inFlight[cellId] = (sp.inFlight[cellId] || 0) + 1;
      sp.maxInFlight[cellId] = Math.max(sp.maxInFlight[cellId] || 0,
                                        sp.inFlight[cellId]);
      return new Promise(function (resolve) {
        setTimeout(resolve, sp.delayMs);
      }).then(function () {
        sp.inFlight[cellId] -= 1;
        return provider(cellId, options, text);
      });
    }
  });
  const instance = new scimClient.ScimClients(deps);
  if (typeof instance.registerCellOps === 'function') {
    instance.registerCellOps();
  }
  const cell = { id: cellId, dir: dir, channel: channel, instance: instance,
                 projections: projections, deps: deps };
  world.cells[cellId] = cell;
  log.debug('Leaving makeCell().');
  return cell;
}

// ---------------------------------------------------------------------------
// THE HARNESS.
// ---------------------------------------------------------------------------
function clientOf(cell) {
  log.debug('Entering clientOf().');
  log.debug('Leaving clientOf().');
  return cell.instance.get('pusher-' + RUN);
}

// A directory change in one cell, as the directory's observer tells it.
function changed(cell, name, kind, group) {
  log.debug('Entering changed(). ' + cell.id + ' ' + name);
  cell.instance.observe({ kind: kind || 'modified', realm: realms.currentId(),
                          dn: personDn(name), username: name,
                          after: kind === 'deleted' ? null
                            : { entryUUID: [uuidFor(name)] },
                          before: { entryUUID: [uuidFor(name)] },
                          group: group ? groupDn(group) : undefined });
  log.debug('Leaving changed().');
}

// Sends what is due in the given cells until nothing more is sent.
async function drain(list, rounds) {
  log.debug('Entering drain().');
  let quiet = 0;
  for (let i = 0; i < (rounds || 30) && quiet < 2; i++) {
    const before = sp.requests.length;
    for (const cell of list) {
      await cell.instance.delivery.sweep();
    }
    quiet = sp.requests.length === before ? quiet + 1 : 0;
  }
  log.debug('Leaving drain().');
}

// A cell's rows of the client, by state.
function rowsOf(cell, state) {
  log.debug('Entering rowsOf().');
  const out = [];
  cell.deps.stores.deliveries.realmMap(realms.currentId())
    .forEach(function (row) {
      if (!state || row.state === state) {
        out.push(row);
      }
    });
  log.debug('Leaving rowsOf(). ' + out.length);
  return out;
}

function userThere(name) {
  log.debug('Entering userThere().');
  const uuid = uuidFor(name);
  const hit = Object.keys(sp.users).map(function (k) {
    return sp.users[k];
  }).filter(function (r) {
    return r.body.externalId === uuid;
  })[0] || null;
  log.debug('Leaving userThere().');
  return hit;
}

function fromCell(cellId) {
  log.debug('Entering fromCell().');
  log.debug('Leaving fromCell().');
  return sp.requests.filter(function (r) {
    return r.from === cellId;
  });
}

// A request names a person when its path or body carries their UUID or name.
function names(request, name) {
  log.debug('Entering names().');
  const text = request.path + ' ' + (request.text || '');
  log.debug('Leaving names().');
  return text.indexOf(uuidFor(name)) >= 0 || text.indexOf(name) >= 0;
}

// ---------------------------------------------------------------------------
// A. HOME-CELL PUSHING.
// ---------------------------------------------------------------------------
async function homeCells(t, a, b) {
  log.debug('Entering homeCells().');
  sp = freshProvider();
  setClient();
  a.dir.add('alice');
  b.dir.add('bob');
  changed(a, 'alice');
  changed(b, 'bob');
  await drain([a, b]);
  t.check(!!userThere('alice') && !!userThere('bob'),
          'A1. users from both cells end up at the service provider');
  t.check(!fromCell('cella').some(function (r) {
    return names(r, 'bob');
  }) && !fromCell('cellb').some(function (r) {
    return names(r, 'alice');
  }), 'A2. each cell pushes only the people homed there');

  // A PROJECTION: bob's session held at cell A, his entry projected there.
  const projected = a.dir.add('bob');
  a.projections.add(uuidFor('bob'));
  const before = fromCell('cella').length;
  changed(a, 'bob');
  await drain([a]);
  t.check(fromCell('cella').length === before &&
          !rowsOf(a).some(function (row) {
            return row.uuid === uuidFor('bob') && row.state === 'pending';
          }), 'A3. a projection is not pushed by the cell holding it');
  a.projections.delete(uuidFor('bob'));
  a.dir.drop('bob');
  t.check(!!projected, 'A3. (the projection was in cell A\'s directory)');

  // scimClientCells: only cell A pushes.
  setClient({ scimClientCells: ['cella'] });
  b.dir.add('erin');
  changed(b, 'erin');
  await drain([a, b]);
  t.check(!userThere('erin') && !rowsOf(b).some(function (row) {
    return row.uuid === uuidFor('erin');
  }), 'A4. a cell scimClientCells leaves out queues and sends nothing');
  setClient();
  log.debug('Leaving homeCells().');
}

// ---------------------------------------------------------------------------
// B. THE TRANSFER DECISION.
// ---------------------------------------------------------------------------
async function transferDecision(t, a, b) {
  log.debug('Entering transferDecision().');
  // Cell B is in `ca`; the provider in `eu`; the realm no longer lists it.
  world.permitted = ['us>eu'];
  b.dir.add('carol');
  const asked = world.transferAsks;
  changed(b, 'carol');
  t.check(world.transferAsks > asked && !rowsOf(b).some(function (row) {
    return row.uuid === uuidFor('carol');
  }), 'B1. a person the policy keeps out is no delivery at all (asked, ' +
      'release-attributes, purpose scim-provision)');
  await b.instance.reconcile(clientOf(b), 'tester');
  await drain([b]);
  t.check(!userThere('carol') && !fromCell('cellb').some(function (r) {
    return names(r, 'carol');
  }), 'B2. a refused transfer pushes nothing, not even a lookup');
  const bob = userThere('bob');
  t.check(bob && bob.body.active === false,
          'B3. a person pushed before the policy refused is deprovisioned ' +
          '(active false)', bob && bob.body);
  t.check(rowsOf(b, 'dead').length === 0,
          'B4. a refusal is never a dead letter');
  world.permitted = ['us>eu', 'ca>eu'];
  await b.instance.reconcile(clientOf(b), 'tester');
  await drain([b]);
  t.check(!!userThere('carol') && userThere('bob').body.active !== false,
          'B5. listed again, they are pushed and active again');
  log.debug('Leaving transferDecision().');
}

// ---------------------------------------------------------------------------
// C. A MOVE IS A HANDOVER.
// ---------------------------------------------------------------------------
async function handover(t, a, b) {
  log.debug('Entering handover().');
  const alice = userThere('alice');
  const id = alice.id;
  // Moved from A to B: the index names B, A's directory lets them go.
  world.homes[uuidFor('alice')] = 'cellb';
  a.dir.drop('alice');
  const before = fromCell('cella').length;
  changed(a, 'alice', 'deleted');
  await drain([a]);
  t.check(fromCell('cella').length === before,
          'C1. the cell they left sends nothing for them',
          fromCell('cella').slice(before));
  t.check(userThere('alice').body.active !== false,
          'C2. moving a person to the other cell does not deactivate them');
  b.dir.add('alice');
  changed(b, 'alice');
  await drain([b]);
  const after = userThere('alice');
  t.check(after.id === id && after.body.active !== false &&
          fromCell('cellb').some(function (r) {
            return r.method === 'PUT' && r.path.indexOf(id) >= 0;
          }), 'C3. the new home finds them by externalId and replaces, ' +
              'never re-creating');

  // Gone everywhere: deprovisioned as before.
  a.dir.add('dave');
  changed(a, 'dave');
  await drain([a]);
  a.dir.drop('dave');
  world.homes[uuidFor('dave')] = '';
  changed(a, 'dave', 'deleted');
  await drain([a]);
  t.check(userThere('dave') && userThere('dave').body.active === false,
          'C4. a person gone from every cell is deprovisioned');
  log.debug('Leaving handover().');
}

// ---------------------------------------------------------------------------
// D. A GROUP ACROSS CELLS, WITH PATCH.
// ---------------------------------------------------------------------------
function groupThere(name) {
  log.debug('Entering groupThere().');
  const uuid = uuidFor('group-' + name);
  const hits = Object.keys(sp.groups).map(function (k) {
    return sp.groups[k];
  }).filter(function (r) {
    return r.body.externalId === uuid;
  });
  log.debug('Leaving groupThere().');
  return hits;
}

function memberNames(group) {
  log.debug('Entering memberNames().');
  const out = (group.body.members || []).map(function (m) {
    const user = sp.users[m.value];
    return user ? user.body.userName : '?' + m.value;
  }).sort();
  log.debug('Leaving memberNames().');
  return out.join(',');
}

function patchesFrom(cellId, since) {
  log.debug('Entering patchesFrom().');
  const out = sp.requests.slice(since).filter(function (r) {
    return r.from === cellId && r.method === 'PATCH' &&
           r.path.indexOf('/Groups/') >= 0;
  });
  log.debug('Leaving patchesFrom().');
  return out;
}

async function groupsWithPatch(t, a, b) {
  log.debug('Entering groupsWithPatch().');
  sp.patch = true;
  world.settings['cells.homeCell'] = 'cella';
  setClient({ scimClientGroupMode: 'all' });
  const staff = defineGroup('staff');
  a.dir.add('gina');
  b.dir.add('hank');
  a.dir.join('gina', 'staff');
  b.dir.join('hank', 'staff');
  changed(a, 'gina');
  await drain([a]);
  t.check(groupThere('staff').length === 1,
          'D1. cell A creates the group with its share');
  sp.hideSearch = 1;
  const before = sp.requests.length;
  changed(b, 'hank');
  await drain([b]);
  const posts = sp.requests.slice(before).filter(function (r) {
    return r.from === 'cellb' && r.method === 'POST' &&
           r.path.indexOf('/Groups') >= 0;
  });
  t.check(posts.length === 1 && groupThere('staff').length === 1 &&
          patchesFrom('cellb', before).length >= 1,
          'D2. a group two cells create is one group: the second POST is ' +
          'answered 409 and the group adopted by externalId, its share ' +
          'PATCHed in (never PUT)', sp.requests.slice(before).map(function (r) {
            return r.from + ' ' + r.method + ' ' + r.path;
          }));
  t.check(memberNames(groupThere('staff')[0]) === 'gina,hank',
          'D3. a group with members in both cells keeps every member',
          memberNames(groupThere('staff')[0]));
  t.check(!sp.requests.slice(before).some(function (r) {
    return r.from === 'cellb' && r.method === 'PUT' &&
           r.path.indexOf('/Groups') >= 0;
  }), 'D4. no cell PUTs a member list where PATCH is supported');

  const mark = sp.requests.length;
  a.dir.add('ivy');
  a.dir.join('ivy', 'staff');
  changed(a, 'ivy');
  await drain([a]);
  const hankId = userThere('hank').id;
  t.check(memberNames(groupThere('staff')[0]) === 'gina,hank,ivy' &&
          !patchesFrom('cella', mark).some(function (r) {
            return r.text.indexOf(hankId) >= 0;
          }), 'D5. a change in cell A adds its member and never touches ' +
              'cell B\'s', memberNames(groupThere('staff')[0]));
  const mark2 = sp.requests.length;
  b.dir.leave('hank', 'staff');
  changed(b, 'hank', 'membership', 'staff');
  await drain([b]);
  const ginaId = userThere('gina').id;
  t.check(memberNames(groupThere('staff')[0]) === 'gina,ivy' &&
          !patchesFrom('cellb', mark2).some(function (r) {
            return r.text.indexOf(ginaId) >= 0;
          }), 'D6. a change in cell B removes only its own member',
          memberNames(groupThere('staff')[0]));
  b.dir.join('hank', 'staff');
  changed(b, 'hank', 'membership', 'staff');
  await drain([b]);
  const mark3 = sp.requests.length;
  a.instance.enqueue(clientOf(a), 'Group', staff.uuid, 'staff');
  await drain([a]);
  t.check(memberNames(groupThere('staff')[0]) === 'gina,hank,ivy' &&
          !patchesFrom('cella', mark3).some(function (r) {
            return r.text.indexOf(hankId) >= 0;
          }), 'D7. cell A syncing the group again leaves cell B\'s member ' +
              'alone', memberNames(groupThere('staff')[0]));

  // DELETION BY THE OWNER (cella, the realm's cells.homeCell).
  undefineGroup('staff');
  world.unreachable.cellb = true;
  a.instance.enqueue(clientOf(a), 'Group', staff.uuid, 'staff');
  await drain([a]);
  const waiting = rowsOf(a).filter(function (row) {
    return row.uuid === staff.uuid;
  })[0];
  t.check(groupThere('staff').length === 1 && waiting &&
          waiting.state === 'pending' && waiting.errorCode === 'STS-SCIMC-0032',
          'D8. the owner does not delete while a cell cannot be reached ' +
          '(retried, STS-SCIMC-0032)', waiting);
  world.unreachable.cellb = false;
  world.t += 3600000;
  await drain([a]);
  t.check(groupThere('staff').length === 0,
          'D9. deleting a group needs every cell to report no members: ' +
          'deleted once cell B answered none');
  t.check(rowsOf(a, 'dead').length === 0 && rowsOf(b, 'dead').length === 0,
          'D10. no dead letter on either cell');

  // member-groups: members only in cell B keep the group the owner has no
  // share of; the last one leaving lets the owner delete it.
  setClient({ scimClientGroupMode: 'member-groups' });
  const ops = defineGroup('ops');
  b.dir.join('hank', 'ops');
  changed(b, 'hank', 'membership', 'ops');
  await drain([b]);
  a.instance.enqueue(clientOf(a), 'Group', ops.uuid, 'ops');
  await drain([a]);
  t.check(groupThere('ops').length === 1 &&
          memberNames(groupThere('ops')[0]) === 'hank',
          'D11. the owner keeps a group whose members are all in another ' +
          'cell');
  b.dir.leave('hank', 'ops');
  changed(b, 'hank', 'membership', 'ops');
  await drain([b, a]);
  t.check(groupThere('ops').length === 0,
          'D12. the last member leaving in cell B tells the owner, which ' +
          'deletes it once every cell answers none');
  log.debug('Leaving groupsWithPatch().');
}

// ---------------------------------------------------------------------------
// E. A SERVICE PROVIDER WITHOUT PATCH.
// ---------------------------------------------------------------------------
async function groupsWithoutPatch(t, a, b) {
  log.debug('Entering groupsWithoutPatch().');
  sp.patch = false;
  // Past the ten minutes a discovery is believed, so both cells read that
  // the provider has no PATCH.
  world.t += 11 * 60000;
  setClient({ scimClientGroupMode: 'all' });
  defineGroup('eng');
  a.dir.join('gina', 'eng');
  b.dir.join('hank', 'eng');
  const before = sp.requests.length;
  changed(b, 'hank');
  await drain([b, a]);
  const eng = groupThere('eng');
  t.check(eng.length === 1 && memberNames(eng[0]) === 'gina,hank',
          'E1. the owner writes the group with every cell\'s share merged',
          sp.requests.slice(before).map(function (r) {
            return r.from + ' ' + r.method + ' ' + r.path + ' ' +
                   (r.text || '').slice(0, 200);
          }));
  t.check(!sp.requests.slice(before).some(function (r) {
    return r.from === 'cellb' && r.path.indexOf('/Groups') >= 0 &&
           r.method !== 'GET';
  }), 'E2. without PATCH the other cell never writes the group');
  b.dir.add('jack');
  b.dir.join('jack', 'eng');
  world.unreachable.cellb = true;
  const mark = sp.requests.length;
  changed(b, 'jack');
  await drain([b, a]);
  t.check(!sp.requests.slice(mark).some(function (r) {
    return r.method === 'PUT' && r.path.indexOf('/Groups') >= 0;
  }) && memberNames(groupThere('eng')[0]) === 'gina,hank',
          'E3. no PUT while a cell cannot be asked for its share — never ' +
          'a partial membership');
  world.unreachable.cellb = false;
  world.t += 3600000;
  await drain([a, b]);
  t.check(memberNames(groupThere('eng')[0]) === 'gina,hank,jack',
          'E4. once every cell answers, the merged membership is PUT',
          memberNames(groupThere('eng')[0]));
  sp.patch = true;
  world.t += 11 * 60000;
  setClient();
  log.debug('Leaving groupsWithoutPatch().');
}

// ---------------------------------------------------------------------------
// F. THE SHARED PAUSE AND THE CONCURRENCY BUDGET.
// ---------------------------------------------------------------------------
function pauseRow() {
  log.debug('Entering pauseRow().');
  log.debug('Leaving pauseRow().');
  return world.pauses.realmMap(realms.currentId()).get('pusher-' + RUN) ||
         null;
}

function writesSince(mark) {
  log.debug('Entering writesSince().');
  const out = sp.requests.slice(mark).filter(function (r) {
    return r.method !== 'GET';
  });
  log.debug('Leaving writesSince().');
  return out;
}

async function sharedPause(t, a, b) {
  log.debug('Entering sharedPause().');
  setClient();
  a.dir.add('kim');
  b.dir.add('lee');
  sp.fail.push({ from: 'cella', method: 'POST', path: '/Users',
                 status: 503 });
  changed(a, 'kim');
  await drain([a]);
  const paused = pauseRow();
  t.check(!!paused && paused.failures === 1 &&
          paused.pausedUntil > world.t && /^cella#/.test(paused.probe),
          'F1. a 503 at cell A writes the client\'s pause to the shared ' +
          '(global) store, cell A\'s row the probe', paused);
  const mark = sp.requests.length;
  changed(b, 'lee');
  await drain([b]);
  t.check(!sp.requests.slice(mark).some(function (r) {
    return r.from === 'cellb';
  }) && rowsOf(b, 'pending').some(function (row) {
    return row.uuid === uuidFor('lee');
  }), 'F2. a 503 seen by one cell pauses both: cell B sends nothing');
  // Past the pause, and past the probe's own retry, which was set a moment
  // after the pause was.
  world.t = paused.pausedUntil + 1000;
  const mark2 = sp.requests.length;
  await drain([b]);
  t.check(writesSince(mark2).length === 0,
          'F3. the pause over, cell B still waits for cell A\'s probe');
  await drain([a]);
  const probes = writesSince(mark2);
  t.check(probes.length === 1 && probes[0].from === 'cella' &&
          !pauseRow().failures,
          'F4. one probe goes for the whole service, and its success ends ' +
          'the pause', probes.map(function (r) {
            return r.from + ' ' + r.method + ' ' + r.path;
          }));
  await drain([b]);
  t.check(!!userThere('lee'), 'F5. then cell B sends');

  // Cell A probes and goes silent: cell B takes the probe over, once.
  a.dir.add('mia');
  b.dir.add('ned');
  sp.fail.push({ from: 'cella', method: 'POST', path: '/Users',
                 status: 503 });
  changed(a, 'mia');
  await drain([a]);
  changed(b, 'ned');
  const again = pauseRow();
  world.t = again.pausedUntil + 1000;
  await drain([b]);
  t.check(!userThere('ned'),
          'F6. within the grace after the pause cell B leaves the probe to ' +
          'cell A');
  world.t = again.pausedUntil + 130000;
  await drain([b]);
  t.check(!!userThere('ned') && !pauseRow().failures,
          'F7. cell A silent past the grace, cell B takes the probe over');
  await drain([a]);

  // THE CONCURRENCY BUDGET: scimClient.concurrency (4) over two cells.
  world.t += 6000;
  const lane = a.instance.laneOf({ realm: realms.currentId(),
                                   clientId: 'pusher-' + RUN });
  t.check(lane && lane.limit === 2,
          'F8. each of two pushing cells has ceil(4 / 2) = 2', lane);
  setClient({ scimClientCells: ['cella'] });
  world.t += 6000;
  const solo = a.instance.laneOf({ realm: realms.currentId(),
                                   clientId: 'pusher-' + RUN });
  t.check(solo && solo.limit === 4,
          'F9. one pushing cell has the whole budget', solo);
  setClient();
  world.t += 6000;
  ['oli', 'pat', 'quin', 'rae', 'sam', 'tia'].forEach(function (name) {
    a.dir.add(name);
    changed(a, name);
  });
  sp.delayMs = 15;
  await a.instance.delivery.sweep();
  sp.delayMs = 0;
  await drain([a]);
  t.check(sp.maxInFlight.cella === 2 && !!userThere('tia'),
          'F10. the queue holds cell A to its budget: at most 2 requests ' +
          'in flight', sp.maxInFlight);
  log.debug('Leaving sharedPause().');
}

// ---------------------------------------------------------------------------
// Z. WHAT A SERVICE PROVIDER SEES, AND ONE CELL.
// ---------------------------------------------------------------------------
function noCellNamed(t) {
  log.debug('Entering noCellNamed().');
  const seen = sp.requests.map(function (r) {
    return r.path + ' ' + r.text + ' ' + JSON.stringify(r.headers || {});
  }).join('\n');
  t.check(sp.requests.length > 0 && !/cella|cellb/.test(seen),
          'Z1. no URL, header or body a service provider sees names a cell (' +
          sp.requests.length + ' requests)');
  log.debug('Leaving noCellNamed().');
}

async function oneCell(t) {
  log.debug('Entering oneCell().');
  world.multi = false;
  sp = freshProvider();
  const solo = makeCell('solo');
  solo.dir.add('frank');
  world.permitted = [];
  const asked = world.transferAsks;
  changed(solo, 'frank');
  await drain([solo]);
  t.check(!!userThere('frank') && world.transferAsks === asked,
          'Z2. a service that is one cell pushes everybody it holds and ' +
          'asks no transfer question');
  t.check(solo.instance.laneOf({ realm: realms.currentId(),
                                 clientId: 'pusher-' + RUN }) === null &&
          !world.pauses.realmMap(realms.currentId()).has('solo'),
          'Z3. and has no lane of its own nor a shared pause');
  world.multi = true;
  world.permitted = ['us>eu', 'ca>eu'];
  log.debug('Leaving oneCell().');
}

async function run(t) {
  log.debug('Entering run().');
  const realm = realms.create({ id: 'scimcc-' + RUN,
                                name: 'scim client cells ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      const a = makeCell('cella');
      const b = makeCell('cellb');
      await homeCells(t, a, b);
      await transferDecision(t, a, b);
      await handover(t, a, b);
      await groupsWithPatch(t, a, b);
      await groupsWithoutPatch(t, a, b);
      await sharedPause(t, a, b);
      noCellNamed(t);
      await oneCell(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'scim_client_cells',
  describe: 'The outbound SCIM client in a service deployed as cells ' +
            '(#553), two cells in one process with the channel, the routing ' +
            'index and the cell map stubbed: home-cell pushing, the ' +
            'scim-provision transfer decision, a move as a handover, and ' +
            'groups by per-cell PATCH, owner-cell deletion and the merged ' +
            'PUT without PATCH',
  run: run
};
