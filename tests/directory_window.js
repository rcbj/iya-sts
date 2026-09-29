// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: directory_window.js
//
// ===========================================================================
// THE DIRECTORY AS A WINDOW ONTO THE STORE (#349 phase 4, 2026-09-29).
//
// `ldap/directory_window.ts` is what a request worker holds as `entries` with
// `ldap.workerDirectory=postgres-lru`. Its bridge here is a synchronous
// stand-in answering `persistence/directory_queries.js`'s questions out of a
// table in memory — the real bridge is `tests/sync_query.js`'s.
//
//   A. ROUTING: a resident key is a Map; a windowed key is read from the
//      store once, then from the window; an absence is held; the bound holds.
//   B. WRITES: a set or delete is pinned until a flush has written it, with
//      the base the store held; an entry edited IN PLACE is found — handed
//      out in the same tick, named by the journal, or (a write naming
//      nothing) anything held, and an evicted entry a caller still holds.
//   C. THE FLUSH'S ANSWER: committed releases, a change made while in flight
//      stays, a store outcome is forgotten or becomes the base.
//   D. SCANS AND SIZE: resident, then the store's pages, local changes
//      winning, local deletes skipped, local creates visited; the count.
//   E. ANOTHER PROCESS: a clean key is forgotten, a busy one is not; a realm
//      removed is dropped; attach() forgets absences recorded before it.
//   F. THROUGH persistence.js, in a child over a `pg` double: a create, an
//      in-place edit and a delete reach the table with their bases; a row
//      another process wrote replaces a clean entry and is MERGED with a
//      changed one (both changes survive); the shadow never holds a
//      windowed key.
//   G. THE REFUSAL: postgres-lru with a memory store does not start
//      (STS-LDAP-0133).
//
// WHAT NEEDS AN HTTP RUN (on #349): the whole service in a windowed worker —
// every protocol family's reads and writes through the window, the change
// log between workers, and a database stopped under a request (503).
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'directory_window',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_DIRECTORY_WINDOW_CHILD';
const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;
const DEVICES = 'ou=devices,' + BASE;

// A table in memory, keyed `realm\nkey`, holding rows in the table's shape.
function table() {
  log.debug("Entering table().");
  log.debug("Leaving table().");
  return new Map();
}

function row(realm, dn, attributes) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return { realm: realm, dn_key: dn.toLowerCase(), dn: dn,
           attrs: attributes, origin: 'test', created_at: '1',
           modified_at: '1' };
}

// The synchronous stand-in for the bridge, answering out of `rows`.
function fakeBridge(rows) {
  log.debug("Entering fakeBridge().");
  const queries = require('../persistence/directory_queries');
  const bridge = { asked: [] };
  const under = function (key, base) {
    return key.length > base.length + 1 && key.endsWith(',' + base);
  };
  // COPIES, as a database answers: an entry read back must never be the
  // table's own object, or a change to one would be a change to the other.
  const sorted = function (realm) {
    return Array.from(rows.values()).filter(function (r) {
      return r.realm === realm;
    }).map(function (r) {
      return JSON.parse(JSON.stringify(r));
    }).sort(function (a, b) {
      return a.dn_key < b.dn_key ? -1 : (a.dn_key > b.dn_key ? 1 : 0);
    });
  };
  bridge.query = function (name, args) {
    bridge.asked.push(name);
    if (name === 'byKeys') {
      return sorted(args[0]).filter(function (r) {
        return args[1].indexOf(r.dn_key) >= 0;
      }).map(queries.rowOf);
    }
    if (name === 'page') {
      const self = !!(args[4] && args[4].self);
      return sorted(args[0]).filter(function (r) {
        return (under(r.dn_key, args[1]) ||
                (self && r.dn_key === args[1])) && r.dn_key > args[2];
      }).slice(0, args[3]).map(queries.rowOf);
    }
    if (name === 'withAttribute') {
      return sorted(args[0]).filter(function (r) {
        return under(r.dn_key, args[1]) && r.attrs[args[2]] !== undefined &&
          r.dn_key > args[3];
      }).slice(0, args[4]).map(queries.rowOf);
    }
    if (name === 'anyWithAttribute') {
      return sorted(args[0]).some(function (r) {
        return r.attrs[args[1]] !== undefined;
      });
    }
    if (name === 'byName') {
      return sorted(args[0]).filter(function (r) {
        const rdn = r.dn_key.split(',')[0];
        return r.dn_key.slice(r.dn_key.indexOf(',') + 1) === args[1] &&
          ((r.attrs.uid || []).map(function (v) {
            return String(v).toLowerCase();
          }).indexOf(args[2]) >= 0 || rdn.slice(rdn.indexOf('=') + 1) ===
            args[2]);
      }).slice(0, 2).map(queries.rowOf);
    }
    if (name === 'byUuid') {
      return sorted(args[0]).filter(function (r) {
        return (r.attrs.entryuuid || []).concat(r.attrs.stsentryuuidalias ||
                                                [])
          .map(function (v) { return String(v).toLowerCase(); })
          .indexOf(args[1]) >= 0;
      }).map(queries.rowOf);
    }
    if (name === 'byMail') {
      return sorted(args[0]).filter(function (r) {
        return (r.attrs.mail || []).map(function (v) {
          return String(v).toLowerCase();
        }).indexOf(args[1]) >= 0;
      }).map(queries.rowOf);
    }
    if (name === 'byAttribute') {
      return sorted(args[0]).filter(function (r) {
        return (r.attrs[args[1]] || []).indexOf(args[2]) >= 0;
      }).map(queries.rowOf);
    }
    if (name === 'count') {
      return sorted(args[0]).filter(function (r) {
        return !args[1] || under(r.dn_key, args[1]);
      }).length;
    }
    if (name === 'hasChild') {
      return sorted(args[0]).some(function (r) {
        return under(r.dn_key, args[1]);
      });
    }
    throw new Error('the fake bridge knows no ' + name);
  };
  log.debug("Leaving fakeBridge().");
  return bridge;
}

// A window over `rows`, the default realm ambient unless `ambient.id` says.
function windowOver(rows, bound, ambient) {
  log.debug("Entering windowOver().");
  const DirectoryWindow = require('../ldap/directory_window');
  const removers = [];
  const touched = { n: 0 };
  const w = new DirectoryWindow({
    currentId: function () { return (ambient && ambient.id) || 'default'; },
    onRemove: function (fn) { removers.push(fn); },
    windowedContainers: function () {
      return [USERS, DEVICES];
    },
    fromRow: function (realmId, r) {
      return { dn: r.dn, attributes: r.attributes, createdAt: r.createdAt,
               modifiedAt: r.modifiedAt };
    },
    maxEntries: function () { return bound; },
    onTouched: function () { touched.n += 1; }
  });
  const bridge = fakeBridge(rows);
  w.attach(bridge);
  log.debug("Leaving windowOver().");
  return { w: w, bridge: bridge, touched: touched,
           remove: function (id) {
             removers.forEach(function (fn) { fn(id); });
           } };
}

function person(uid, extra) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return Object.assign({ uid: [uid], objectclass: ['inetOrgPerson'] },
                       extra || {});
}

function routing(t) {
  log.debug("Entering routing().");
  t.log.info('=== A. routing ===');
  const rows = table();
  rows.set('default\nuid=alice,' + USERS,
           row('default', 'uid=alice,' + USERS, person('alice')));
  const o = windowOver(rows, 3);
  const f = o.w.facade();
  f.set('cn=ops,ou=groups,' + BASE, { dn: 'cn=ops', attributes: {} });
  t.check(f.get('cn=ops,ou=groups,' + BASE) && o.bridge.asked.length === 0,
          'A1. a resident key is a Map, and the store is not asked');
  const alice = f.get('uid=alice,' + USERS);
  t.check(alice && alice.attributes.uid[0] === 'alice' &&
          o.bridge.asked.join() === 'byKeys',
          'A2. a windowed key not held is read from the store',
          o.bridge.asked.join());
  t.check(f.get('uid=alice,' + USERS) === alice &&
          o.bridge.asked.length === 1,
          'A3. then answered from the window, the same object');
  t.equal(f.get('uid=nobody,' + USERS), undefined,
          'A4. a key the store has not is undefined');
  f.get('uid=nobody,' + USERS);
  t.equal(o.bridge.asked.length, 2,
          'A5. and the absence is held: asked once, not twice');
  for (let i = 0; i < 20; i++) {
    rows.set('default\nuid=u' + i + ',' + USERS,
             row('default', 'uid=u' + i + ',' + USERS, person('u' + i)));
    f.get('uid=u' + i + ',' + USERS);
  }
  o.w.collect(new Set());
  t.check(o.w.stats().size <= 3, 'A6. the window holds no more than its ' +
          'bound once what was handed out is let go',
          JSON.stringify(o.w.stats()));
  t.check(o.touched.n >= 1,
          'A7. handing an entry out asks for a flush (onTouched)');
  const view = f.realmMap('acme');
  view.set('uid=x,' + USERS, { dn: 'uid=x', attributes: {} });
  t.check(o.w.peekIn('acme', 'uid=x,' + USERS) &&
          !o.w.peekIn('default', 'uid=x,' + USERS),
          'A8. realmMap(id) is that realm, whatever is ambient');
  log.debug("Leaving routing().");
}

function writes(t) {
  log.debug("Entering writes().");
  t.log.info('=== B. writes and edits in place ===');
  const rows = table();
  ['bob', 'carol', 'dave'].forEach(function (u) {
    rows.set('default\nuid=' + u + ',' + USERS,
             row('default', 'uid=' + u + ',' + USERS, person(u)));
  });
  const o = windowOver(rows, 2);
  const f = o.w.facade();
  const created = { dn: 'uid=erin,' + USERS, attributes: person('erin') };
  f.set('uid=erin,' + USERS, created);
  let c = o.w.collect(new Set(['uid=erin,' + USERS.toLowerCase()]));
  t.check(c.upserts.length === 1 && c.upserts[0].base === null &&
          c.upserts[0].key === 'uid=erin,' + USERS,
          'B1. a create is an upsert with no base', JSON.stringify(c.upserts));
  o.w.committed(c, []);
  const bob = f.get('uid=bob,' + USERS);
  bob.attributes.mail = ['bob@example.com'];
  c = o.w.collect(new Set());
  t.check(c.upserts.length === 1 && c.upserts[0].key === 'uid=bob,' + USERS &&
          JSON.parse(c.upserts[0].base).attributes.mail === undefined,
          'B2. an entry handed out and edited in place in the same tick is ' +
          'found, with the base the store held', JSON.stringify(c.upserts));
  o.w.committed(c, []);
  bob.attributes.sn = ['Later'];
  c = o.w.collect(new Set(['uid=bob,' + USERS]));
  t.check(c.upserts.length === 1 && /bob@example/.test(c.upserts[0].base),
          'B3. an edit made after a flush let it go is found when the ' +
          'journal names it, against the base last written',
          JSON.stringify(c.upserts));
  o.w.committed(c, []);
  bob.attributes.title = ['Unnamed'];
  c = o.w.collect(null);
  t.equal(c.upserts.length, 1,
          'B4. and when a write named nothing, every held entry is compared');
  o.w.committed(c, []);
  // EVICTED, AND STILL HELD BY A CALLER.
  const carol = f.get('uid=carol,' + USERS);
  o.w.collect(new Set());
  f.get('uid=dave,' + USERS);
  f.get('uid=erin,' + USERS);
  o.w.collect(new Set());
  t.check(!o.w.peekIn('default', 'uid=carol,' + USERS),
          'B5. (carol is evicted by the bound)');
  carol.attributes.mail = ['carol@example.com'];
  c = o.w.collect(new Set(['uid=carol,' + USERS]));
  t.check(c.upserts.length === 1 && c.upserts[0].key === 'uid=carol,' + USERS,
          'B6. an EVICTED entry a caller still holds and edits is found — ' +
          'through its WeakRef — when the journal names it',
          JSON.stringify(c.upserts));
  t.check(f.get('uid=carol,' + USERS) === carol,
          'B7. and read again it is the same object, not a fresh copy');
  o.w.committed(c, []);
  t.check(f.delete('uid=dave,' + USERS) === true,
          'B8. a delete answers whether it held an entry');
  c = o.w.collect(new Set());
  t.check(c.deletes.length === 1 && c.deletes[0].key === 'uid=dave,' + USERS &&
          c.deletes[0].base !== null,
          'B9. a delete is written with the base it removes',
          JSON.stringify(c.deletes));
  o.w.committed(c, []);
  // The store now holds no dave either (what the flush would have done).
  rows.delete('default\nuid=dave,' + USERS);
  t.equal(f.get('uid=dave,' + USERS), undefined,
          'B10. and afterwards the window holds the absence');
  // DIRTY ENTRIES ARE NEVER EVICTED.
  const many = [];
  for (let i = 0; i < 5; i++) {
    const e = { dn: 'uid=n' + i + ',' + USERS, attributes: person('n' + i) };
    many.push(e);
    f.set('uid=n' + i + ',' + USERS, e);
  }
  const s = o.w.stats();
  t.check(s.dirty === 5 && s.overBound >= 3,
          'B11. five writes over a bound of two: all five held, pinned, and ' +
          'the overrun reported', JSON.stringify(s));
  c = o.w.collect(new Set());
  o.w.committed(c, []);
  t.check(o.w.stats().dirty === 0 && o.w.stats().size <= 2,
          'B12. once written they are released and the bound holds again',
          JSON.stringify(o.w.stats()));
  log.debug("Leaving writes().");
}

function flushAnswers(t) {
  log.debug("Entering flushAnswers().");
  t.log.info('=== C. what the flush answers ===');
  const rows = table();
  rows.set('default\nuid=fay,' + USERS,
           row('default', 'uid=fay,' + USERS, person('fay')));
  const o = windowOver(rows, 10);
  const f = o.w.facade();
  const fay = f.get('uid=fay,' + USERS);
  fay.attributes.mail = ['one'];
  let c = o.w.collect(new Set());
  fay.attributes.mail = ['two'];
  o.w.committed(c, []);
  t.check(o.w.busy('default', 'uid=fay,' + USERS),
          'C1. a change made while its flush was in flight stays changed');
  c = o.w.collect(new Set());
  t.check(c.upserts.length === 1 && /"one"/.test(c.upserts[0].base),
          'C2. and is written next, against what the first flush sent',
          JSON.stringify(c.upserts));
  o.w.committed(c, [{ realm: 'default', key: 'uid=fay,' + USERS,
                      outcome: 'merged',
                      entry: { dn: fay.dn, attributes: { merged: ['y'] } } }]);
  t.check(!o.w.peekIn('default', 'uid=fay,' + USERS),
          'C3. a row the store MERGED is forgotten when nothing changed ' +
          'since, and read again next time');
  const again = f.get('uid=fay,' + USERS);
  again.attributes.late = ['z'];
  c = o.w.collect(new Set());
  again.attributes.later = ['w'];
  o.w.committed(c, [{ realm: 'default', key: 'uid=fay,' + USERS,
                      outcome: 'merged',
                      entry: { dn: fay.dn, attributes: { merged: ['q'] } } }]);
  c = o.w.collect(new Set());
  t.check(c.upserts.length === 1 && /"q"/.test(c.upserts[0].base),
          'C4. and when something did change since, the store\'s row is ' +
          'its base for the next write', JSON.stringify(c.upserts));
  o.w.failed(c);
  t.check(o.w.busy('default', 'uid=fay,' + USERS),
          'C5. a failed flush leaves the key changed, for the next one');
  log.debug("Leaving flushAnswers().");
}

function scans(t) {
  log.debug("Entering scans().");
  t.log.info('=== D. scans and size ===');
  const rows = table();
  for (let i = 0; i < 1203; i++) {
    const uid = 'p' + String(i).padStart(4, '0');
    rows.set('default\nuid=' + uid + ',' + USERS,
             row('default', 'uid=' + uid + ',' + USERS, person(uid)));
  }
  rows.set('default\ncn=phone,' + DEVICES,
           row('default', 'cn=phone,' + DEVICES, { cn: ['phone'] }));
  const o = windowOver(rows, 50);
  const f = o.w.facade();
  f.set(USERS, { dn: USERS, attributes: {} });
  f.get('uid=p0001,' + USERS).attributes.mail = ['changed'];
  f.delete('uid=p0002,' + USERS);
  f.set('uid=zz-new,' + USERS, { dn: 'uid=zz-new,' + USERS,
                                 attributes: person('zz-new') });
  const seen = [];
  let changedSeen = false;
  f.forEach(function (entry, key) {
    seen.push(key);
    if (key === 'uid=p0001,' + USERS) {
      changedSeen = entry.attributes.mail && entry.attributes.mail[0] ===
        'changed';
    }
  });
  t.check(seen[0] === USERS && seen.indexOf('cn=phone,' + DEVICES) > 0,
          'D1. a walk visits the resident entries and every windowed ' +
          'container');
  t.equal(seen.length, 1 + 1203 - 1 + 1 + 1,
          'D2. across pages of 500: every stored person but the one deleted ' +
          'here, the one created here, the device and the container');
  t.check(changedSeen, 'D3. a key changed here is visited as changed here');
  t.check(seen.indexOf('uid=p0002,' + USERS) < 0 &&
          seen.indexOf('uid=zz-new,' + USERS) > 0,
          'D4. a key deleted here is skipped; one created here is visited');
  let n = 0;
  for (const pair of f) {
    n += pair ? 1 : 0;
  }
  t.equal(n, seen.length, 'D5. for…of iterates the same walk');
  t.equal(f.size, 1 + 1203 + 1 - 1 + 1,
          'D6. size is the resident entries and the store\'s count, moved ' +
          'by this process\'s own create and delete');
  t.check(o.w.hasChildIn('default', USERS) &&
          !o.w.hasChildIn('default', 'uid=p0005,' + USERS),
          'D7. hasChild asks the store for a windowed container');
  o.w.collect(new Set());
  log.debug("Leaving scans().");
}

function lookups(t) {
  log.debug("Entering lookups().");
  t.log.info('=== D2. walks under a base, and the indexed questions ===');
  const rows = table();
  ['kim', 'lee', 'max'].forEach(function (u) {
    rows.set('default\nuid=' + u + ',' + USERS,
             row('default', 'uid=' + u + ',' + USERS,
                 person(u, u === 'lee' ? { mail: ['Lee@Example.com'],
                                           oauthconsent: ['c1'] } : {})));
  });
  rows.set('default\ncn=tab,' + DEVICES,
           row('default', 'cn=tab,' + DEVICES, { cn: ['tab'] }));
  const o = windowOver(rows, 10);
  const f = o.w.facade();
  f.set('cn=ops,ou=groups,' + BASE, { dn: 'cn=ops', attributes: {} });
  const under = [];
  for (const pair of o.w.walk('default', 'uid=lee,' + USERS, true)) {
    under.push(pair[0]);
  }
  t.equal(under.join('|'), 'uid=lee,' + USERS,
          'D2-1. a walk based at one person reaches that person alone');
  const devices = [];
  for (const pair of o.w.walk('default', DEVICES, true)) {
    devices.push(pair[0]);
  }
  t.equal(devices.join('|'), 'cn=tab,' + DEVICES,
          'D2-2. a walk based at a windowed container pages that container ' +
          'only, and no resident entry outside it');
  t.equal(o.w.stats().touched, 0,
          'D2-3. a read-only walk hands nothing out, so holds nothing');
  f.set('uid=new,' + USERS, { dn: 'uid=new,' + USERS,
                              attributes: person('new', { mail: ['lee@' +
                                'example.com'] }) });
  f.delete('uid=kim,' + USERS);
  const mail = o.w.findWindowed('default', 'byMail',
    ['default', 'lee@example.com', 10], function (entry) {
      return (entry.attributes.mail || []).some(function (m) {
        return String(m).toLowerCase() === 'lee@example.com';
      });
    }).map(function (hit) { return hit.key; });
  t.equal(mail.join('|'), 'uid=lee,' + USERS + '|uid=new,' + USERS,
          'D2-4. an indexed question answers the store\'s rows AND the ' +
          'entries changed here and not yet written');
  const kim = o.w.findWindowed('default', 'byName', ['default', USERS,
                                                     'kim'],
                               function (entry) {
                                 return (entry.attributes.uid || [])
                                   .indexOf('kim') >= 0;
                               });
  t.equal(kim.length, 0,
          'D2-5. and not an entry deleted here, whatever the store still says');
  const consent = o.w.holders('default', USERS, 'oauthconsent',
                              function () { return true; });
  t.check(consent.length === 1 && consent[0].key === 'uid=lee,' + USERS,
          'D2-6. holders() pages the store\'s holders of an attribute',
          JSON.stringify(consent.map(function (h) { return h.key; })));
  t.check(o.w.anyHolder('default', 'oauthconsent') &&
          !o.w.anyHolder('default', 'userpassword'),
          'D2-7. anyHolder() answers whether anybody holds one');
  t.equal(o.w.countUnder('default', USERS), 3,
          'D2-8. countUnder() is the store\'s count moved by this ' +
          'process\'s create and delete (3 + 1 - 1)');
  t.equal(o.w.capCount('default'), 1 + 4,
          'D2-9. capCount() is the realm\'s: resident plus the store\'s ' +
          'windowed count and this process\'s net');
  o.w.collect(new Set());
  log.debug("Leaving lookups().");
}

function otherProcesses(t) {
  log.debug("Entering otherProcesses().");
  t.log.info('=== E. another process, a realm removed, attach ===');
  const rows = table();
  rows.set('default\nuid=gus,' + USERS,
           row('default', 'uid=gus,' + USERS, person('gus')));
  const o = windowOver(rows, 10);
  const f = o.w.facade();
  f.get('uid=gus,' + USERS);
  o.w.collect(new Set());
  t.check(!o.w.busy('default', 'uid=gus,' + USERS),
          'E1. a clean key is not busy once a flush has looked');
  rows.get('default\nuid=gus,' + USERS).attrs.mail = ['from-b'];
  o.w.forget('default', 'uid=gus,' + USERS);
  t.equal((f.get('uid=gus,' + USERS).attributes.mail || [])[0], 'from-b',
          'E2. forgotten, it is read again with another process\'s change');
  f.get('uid=gus,' + USERS);
  rows.get('default\nuid=gus,' + USERS).attrs.title = ['changed-by-b'];
  o.w.markStale('default', 'uid=gus,' + USERS);
  o.w.collect(new Set());
  t.equal((f.get('uid=gus,' + USERS).attributes.title || [])[0],
          'changed-by-b',
          'E2b. a key merely HANDED OUT when another process changed it is ' +
          'dropped once the flush lets it go, and read again — not kept ' +
          'stale until evicted');
  f.get('uid=gus,' + USERS).attributes.sn = ['mine'];
  t.check(o.w.busy('default', 'uid=gus,' + USERS),
          'E3. a key handed out and not yet looked at is busy — its own ' +
          'flush goes first');
  o.w.collect(new Set());
  f.set('uid=hal,' + USERS, { dn: 'uid=hal', attributes: {} });
  o.remove('default');
  t.check(o.w.stats().dirty === 0 && !o.w.peekIn('default', 'uid=gus,' +
                                                  USERS),
          'E4. a removed realm is dropped whole, changes and all');
  const DirectoryWindow = require('../ldap/directory_window');
  const early = new DirectoryWindow({
    currentId: function () { return 'default'; },
    onRemove: function () {},
    windowedContainers: function () { return [USERS]; },
    fromRow: function (id, r) { return r; },
    maxEntries: function () { return 10; },
    onTouched: function () {}
  });
  const ef = early.facade();
  t.equal(ef.get('uid=gus,' + USERS), undefined,
          'E5. before the store is open a windowed key reads as absent');
  ef.set('uid=seed,' + USERS, { dn: 'uid=seed', attributes: {} });
  early.attach(fakeBridge(rows));
  t.check(!!ef.get('uid=gus,' + USERS) && !!early.peekIn('default',
                                                         'uid=seed,' + USERS),
          'E6. attach() asks the store again for what read as absent, and ' +
          'keeps what was written before it');
  log.debug("Leaving otherProcesses().");
}

// --- F and G run in a child: persistence.js over a `pg` double ------------

function fakeDatabase() {
  log.debug("Entering fakeDatabase().");
  const db = { entries: new Map(), log: [] };
  const eid = function (realm, key) {
    return String(realm) + '\n' + String(key);
  };
  const json = function (value) {
    return typeof value === 'string' ? JSON.parse(value) : value;
  };
  db.query = function (sql, params) {
    const text = String(sql).replace(/\s+/g, ' ').trim();
    const p = params || [];
    const rows = function (list) {
      return Promise.resolve({ rows: list, rowCount: list.length });
    };
    if (/^SELECT to_regclass/.test(text)) {
      const one = {};
      for (let i = 0; i < 200; i++) {
        one['o' + i] = 'present';
      }
      return rows([one]);
    }
    if (/^INSERT INTO sts_changes/.test(text)) {
      for (let i = 0; i + 3 < p.length; i += 4) {
        db.log.push({ seq: db.log.length + 1, origin: p[i], kind: p[i + 1],
                      realm: p[i + 2], key: p[i + 3] });
      }
      return rows([]);
    }
    if (/SELECT COALESCE\(MAX\(seq\), 0\) AS seq FROM sts_changes/
          .test(text)) {
      return rows([{ seq: db.log.length }]);
    }
    if (/^SELECT seq, origin, kind, realm, key FROM sts_changes WHERE seq > /
          .test(text)) {
      return rows(db.log.filter(function (r) {
        return r.seq > Number(p[0]);
      }).slice(0, Number(p[1]) || 500));
    }
    if (/FROM sts_ldap_entries ORDER BY realm, dn_key$/.test(text)) {
      return rows(Array.from(db.entries.values()));
    }
    if (/NOT EXISTS \(SELECT 1 FROM unnest/.test(text)) {
      db.residentRead = true;
      return rows(Array.from(db.entries.values()).filter(function (r) {
        return !p[0].some(function (realm, i) {
          return realm === r.realm && r.dn_key.endsWith(',' + p[1][i]);
        });
      }));
    }
    if (/FROM sts_ldap_entries WHERE \(realm, dn_key\) IN/.test(text)) {
      const wanted = new Set(p[0].map(function (r, i) {
        return eid(r, p[1][i]);
      }));
      return rows(Array.from(db.entries.keys()).filter(function (k) {
        return wanted.has(k);
      }).sort().map(function (k) { return db.entries.get(k); }));
    }
    if (/^SELECT .* FROM sts_ldap_entries WHERE realm = \$1 AND dn_key = \$2/
          .test(text)) {
      const one = db.entries.get(eid(p[0], p[1]));
      return rows(one ? [one] : []);
    }
    if (/^INSERT INTO sts_ldap_entries/.test(text) ||
        /^UPDATE sts_ldap_entries/.test(text)) {
      const k = eid(p[0], p[1]);
      if (db.entries.has(k) && /DO NOTHING/.test(text)) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      db.entries.set(k, { realm: p[0], dn_key: p[1], dn: p[2],
                          attrs: json(p[3]), origin: p[4],
                          created_at: p[5], modified_at: p[6] });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^DELETE FROM sts_ldap_entries WHERE realm = \$1 AND dn_key/
          .test(text)) {
      db.entries.delete(eid(p[0], p[1]));
      return rows([]);
    }
    return rows([]);
  };
  log.debug("Leaving fakeDatabase().");
  return db;
}

function installFakePg(db) {
  log.debug("Entering installFakePg().");
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    return db.query(sql, params);
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  const pgPath = require.resolve('pg');
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: { Pool: FakePool, Client: FakeClient } };
  log.debug("Leaving installFakePg().");
}

function tick(ms) {
  log.debug("Entering tick().");
  log.debug("Leaving tick().");
  return new Promise(function (resolve) { setTimeout(resolve, ms || 5); });
}

async function throughPersistence(t) {
  log.debug("Entering throughPersistence().");
  const db = fakeDatabase();
  installFakePg(db);
  process.env.STS_PERSISTENCE_MODE = 'postgres';
  process.env.STS_PERSISTENCE_COORDINATE = 'true';
  const persistence = require('../persistence/persistence');
  const DirectoryWindow = require('../ldap/directory_window');
  const w = new DirectoryWindow({
    currentId: function () { return 'default'; },
    onRemove: function () {},
    windowedContainers: function () { return [USERS, DEVICES]; },
    fromRow: function (realmId, r) {
      return { dn: r.dn, attributes: r.attributes, createdAt: r.createdAt,
               modifiedAt: r.modifiedAt };
    },
    maxEntries: function () { return 100; },
    onTouched: function () { persistence.directoryTouched(); }
  });
  const f = w.facade();
  persistence.setDirectory({
    realmEntries: function (realmId) { return w.residentRows(realmId); },
    replaceRealm: function (realmId, list) {
      w.clearIn(realmId);
      list.forEach(function (r) {
        w.adopt(realmId, String(r.dn).toLowerCase(), r);
      });
    },
    entryAt: function (realmId, key) {
      return w.isWindowed(realmId, key) ? null : w.peekIn(realmId, key);
    },
    applyEntry: function (realmId, key, r) { w.adopt(realmId, key, r); },
    removeEntry: function (realmId, key) { w.forget(realmId, key); },
    forgetEntry: function (realmId, key) { w.forget(realmId, key); },
    windowedContainers: function () { return [USERS, DEVICES]; },
    window: w
  });
  db.entries.set('default\nuid=ivy,' + USERS,
                 row('default', 'uid=ivy,' + USERS, person('ivy')));
  db.entries.set('default\ncn=ops,ou=groups,' + BASE,
                 row('default', 'cn=ops,ou=groups,' + BASE, { cn: ['ops'] }));
  await persistence.start();
  t.equal(persistence.activeMode(), 'postgres',
          'F0. the store opened over the double', persistence.status()
            .lastError);
  t.check(db.residentRead && !!w.peekIn('default', 'cn=ops,ou=groups,' +
                                               BASE) &&
          !w.peekIn('default', 'uid=ivy,' + USERS),
          'F0b. a windowed worker reads back the RESIDENT entries at start ' +
          'and none of the people');
  w.attach(fakeBridge(db.entries));
  await persistence.coordinate();

  f.set('uid=jan,' + USERS, { dn: 'uid=jan,' + USERS,
                              attributes: person('jan') });
  persistence.directoryChanged('uid=jan,' + USERS);
  await persistence.flush();
  t.check(db.entries.has('default\nuid=jan,' + USERS),
          'F1. a create in the window reaches the table');
  const ivy = f.get('uid=ivy,' + USERS);
  ivy.attributes.mail = ['ivy@example.com'];
  await tick(10);
  await persistence.flush();
  t.equal((db.entries.get('default\nuid=ivy,' + USERS).attrs.mail || [])[0],
          'ivy@example.com',
          'F2. an edit made IN PLACE, reported to nobody, reaches the table');
  f.delete('uid=jan,' + USERS);
  persistence.directoryChanged('uid=jan,' + USERS);
  await persistence.flush();
  t.check(!db.entries.has('default\nuid=jan,' + USERS),
          'F3. a delete in the window reaches the table',
          JSON.stringify(w.stats()));
  const status = persistence.status();
  t.check(JSON.stringify(status).indexOf('uid=ivy') < 0,
          'F4. (nothing about a windowed key in the status)');

  // ANOTHER PROCESS changes ivy while she is clean here: forgotten, re-read.
  await persistence.flush();
  db.entries.get('default\nuid=ivy,' + USERS).attrs.title = ['from-b'];
  db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'directory',
                realm: 'default', key: 'uid=ivy,' + USERS });
  await persistence.syncNow();
  t.equal((f.get('uid=ivy,' + USERS).attributes.title || [])[0], 'from-b',
          'F5. a row another process wrote replaces a clean entry here');

  // AND WHILE SHE IS CHANGED HERE: both changes survive the store's merge.
  await persistence.flush();
  const mine = f.get('uid=ivy,' + USERS);
  mine.attributes.sn = ['mine'];
  db.entries.get('default\nuid=ivy,' + USERS).attrs.description = ['theirs'];
  db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'directory',
                realm: 'default', key: 'uid=ivy,' + USERS });
  await persistence.syncNow();
  await tick(10);
  await persistence.flush();
  await tick(10);
  await persistence.flush();
  const stored = db.entries.get('default\nuid=ivy,' + USERS).attrs;
  t.check(String(stored.sn) === 'mine' && String(stored.description) ===
          'theirs',
          'F6. a change made here and one made there to the same entry both ' +
          'survive: the store merged against the window\'s base',
          JSON.stringify(stored));
  const after = f.get('uid=ivy,' + USERS).attributes;
  t.check(String(after.sn) === 'mine' && String(after.description) ===
          'theirs',
          'F7. and the window, told the store merged, reads the merged row',
          JSON.stringify(after));
  log.debug("Leaving throughPersistence().");
}

// H. THE DIRECTORY'S OWN LOOKUPS THROUGH A WINDOW: `ldap_server.js` loaded
// as a windowed request worker would load it, its window given a stand-in
// bridge over a table, and the exported doors asked.
function throughTheDirectory(t) {
  log.debug("Entering throughTheDirectory().");
  const config = require('../common/config');
  const ldap = require('../ldap/ldap_server');
  const w = ldap.directoryWindow;
  t.check(!!w, 'H0. a request worker with ldap.workerDirectory=postgres-lru ' +
          'holds its directory as a window');
  if (!w) {
    log.debug("Leaving throughTheDirectory(). No window.");
    return;
  }
  const users = ldap.usersDn().toLowerCase();
  const rows = table();
  const nia = '6f1e2d3c-4b5a-4968-8776-655443322110';
  rows.set('default\nuid=nia,' + users,
           row('default', 'uid=nia,' + users,
               { uid: ['Nia'], mail: ['nia@example.com'], entryuuid: [nia],
                 objectclass: ['inetOrgPerson'] }));
  for (let i = 0; i < 40; i++) {
    const uid = 'bulk' + String(i).padStart(2, '0');
    rows.set('default\nuid=' + uid + ',' + users,
             row('default', 'uid=' + uid + ',' + users,
                 { uid: [uid], objectclass: ['inetOrgPerson'],
                   entryuuid: ['00000000-0000-4000-8000-0000000000' +
                               String(10 + i)] }));
  }
  rows.set('default\ncn=quinn example,' + users,
           row('default', 'cn=Quinn Example,' + users,
               { uid: ['quinn'], cn: ['Quinn Example'],
                 objectclass: ['inetOrgPerson'] }));
  w.attach(fakeBridge(rows));
  const quinn = ldap.existingUserEntry('Quinn');
  t.check(quinn && /^cn=quinn example,/i.test(quinn.dn),
          'H1b. a person named by cn with a uid beside it is found by the ' +
          'uid, through the store\'s name question', quinn && quinn.dn);
  const found = ldap.existingUserEntry('NIA');
  t.check(found && found.dn === 'uid=nia,' + users,
          'H1. existingUserEntry() finds a person the worker never held, by ' +
          'asking the store — case-insensitively, as the index did',
          found && found.dn);
  t.equal(ldap.existingUserEntry('zed'), null,
          'H2. and nobody for a name the store has not');
  const byUuid = ldap.entryByUuid('urn:uuid:' + nia);
  t.check(byUuid && byUuid.dn === 'uid=nia,' + users,
          'H3. entryByUuid() — a person\'s `sub` — is asked of the store');
  const all = ldap.allPersons();
  t.check(all.length === ldap.personCount() &&
          all.some(function (p) { return p.dn === 'uid=nia,' + users; }),
          'H4. allPersons() pages the people from the store, and ' +
          'personCount() agrees with it', all.length + ' / ' +
          ldap.personCount());
  const made = ldap.createUser('omar');
  t.check(made && made.ok !== false,
          'H5. a person can be created in a windowed worker',
          JSON.stringify(made).slice(0, 300));
  const omar = ldap.existingUserEntry('omar');
  t.check(omar && w.stats().dirty >= 1,
          'H6. and is found at once, before any flush: a change made here ' +
          'is part of every answer', JSON.stringify(w.stats()));
  config.setOverride('ldap.maxEntries', '20');
  const refused = ldap.createUser('pat');
  t.check(refused && refused.ok === false &&
          /maximum/.test(JSON.stringify(refused)),
          'H7. ldap.maxEntries is the REALM\'s count in the store: forty-one ' +
          'people there and a cap of twenty refuses the next create, though ' +
          'this worker holds a handful', JSON.stringify(refused).slice(0, 200));
  config.clearOverride('ldap.maxEntries');
  t.check(w.stats().size <= Number(config.value('ldap.workerCacheEntries')),
          'H8. and the window stays within its bound',
          JSON.stringify(w.stats()));
  log.debug("Leaving throughTheDirectory().");
}

async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  const seen = [];
  const t = {
    log: log,
    check: function (ok, what, detail) {
      seen.push({ ok: !!ok, what: what, detail: detail || '' });
      return !!ok;
    },
    equal: function (a, b, what, detail) {
      return t.check(a === b, what, 'expected ' + JSON.stringify(b) +
                     ', got ' + JSON.stringify(a) +
                     (detail ? ' — ' + detail : ''));
    }
  };
  let threw = '';
  try {
    if (process.env.DW_PART === 'ldap') {
      throughTheDirectory(t);
    } else if (process.env.DW_PART === 'refusal') {
      process.env.STS_PERSISTENCE_MODE = 'memory';
      process.env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
      const persistence = require('../persistence/persistence');
      let message = '';
      await persistence.start().catch(function (e) {
        message = e.message;
      });
      t.check(/STS-LDAP-0133/.test(message) && /persistence\.mode/.test(
        message), 'G1. postgres-lru with a memory store does not start ' +
        '(STS-LDAP-0133), and the message says which setting', message);
    } else {
      await throughPersistence(t);
    }
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug("Leaving childMain().");
  process.exit(0);
}

function inChild(t, part, minimum) {
  log.debug("Entering inChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dw-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal',
                                               DW_PART: part });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  delete env.LDAP_WORKER_DIRECTORY;
  delete env.STS_REQUEST_WORKER;
  if (part === 'ldap') {
    env.STS_REQUEST_WORKER = '1';
    env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
    env.STS_PERSISTENCE_MODE = 'postgres';
    env.LDAP_WORKER_CACHE_ENTRIES = '100';
  }
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    t.bad('the ' + part + ' child reported nothing', 'status ' +
          child.status + ': ' + String(child.stderr || '').slice(-2000));
    log.debug("Leaving inChild().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the ' + part + ' child threw', result.threw);
  }
  t.check(result.seen.length >= minimum, 'every assertion of the ' + part +
          ' child ran', String(result.seen.length));
  log.debug("Leaving inChild().");
}

// I. A REQUEST THE DIRECTORY COULD NOT ANSWER FOR: request_worker.ts's last
// error middleware, called as Express would call it.
function refusedRequest(t) {
  log.debug("Entering refusedRequest().");
  t.log.info('=== I. a request the store could not answer for ===');
  const errorCodes = require('../common/error_codes');
  const RequestWorker = require('../common/request_worker').RequestWorker;
  const answer = { headers: {}, statusCode: 200, body: '', headersSent: false,
                   setHeader: function (k, v) { answer.headers[k] = v; },
                   end: function (b) { answer.body = String(b || ''); } };
  let passed = null;
  const err = errorCodes.mark(new Error('[STS-LDAP-0130] the store did not ' +
                                        'answer'), 'STS-LDAP-0130');
  RequestWorker.directoryUnavailable(err, { method: 'GET',
                                            url: '/oauth2/userinfo' },
                                     answer, function (e) { passed = e; });
  t.check(answer.statusCode === 503 && answer.headers['Retry-After'] &&
          passed === null && errorCodes.codeOf(answer) === 'STS-LDAP-0130' &&
          !/store/.test(answer.body),
          'I1. STS-LDAP-0130 is a 503 with Retry-After, the code marked for ' +
          'the call log, and a body that says nothing about the store',
          JSON.stringify({ status: answer.statusCode, body: answer.body }));
  const other = new Error('something else');
  RequestWorker.directoryUnavailable(other, { method: 'GET', url: '/' },
                                     { headersSent: false },
                                     function (e) { passed = e; });
  t.check(passed === other, 'I2. any other error is passed on unchanged');
  log.debug("Leaving refusedRequest().");
}

function run(t) {
  log.debug("Entering run().");
  refusedRequest(t);
  routing(t);
  writes(t);
  flushAnswers(t);
  scans(t);
  lookups(t);
  otherProcesses(t);
  t.log.info('=== F. through persistence.js ===');
  inChild(t, 'persistence', 8);
  t.log.info('=== G. the refusal ===');
  inChild(t, 'refusal', 1);
  t.log.info('=== H. the directory\'s own lookups through a window ===');
  inChild(t, 'ldap', 10);
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'directory_window',
  describe: 'the directory as a bounded window onto the store (#349): ' +
            'routing, writes and in-place edits, the flush\'s answers, ' +
            'scans and size, other processes, persistence.js over a pg ' +
            'double, and the refusal',
  run: run
};
