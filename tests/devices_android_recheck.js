// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: devices_android_recheck.js
//
// ===========================================================================
// THE ANDROID ATTESTATION RECHECK READS ITS HOLDERS, NOT EVERYBODY (#615).
//
// On 8081 (about 191,000 people, a windowed directory) the daily
// `devices.android-status-recheck` held every listener for minutes: it asked
// `persons()` for every name and `keysOf()` for each, a synchronous store
// read per person on the serving front process, to find the one person who
// held a security key. `common/attestation_revocation.ts` argues the fix.
// What is held here, in process, over the real directory in memory and over
// a `DirectoryWindow` with a counting bridge:
//
//   A. THE OLD COST, MEASURED: the walk asks `persons()` once and reads the
//      keys of every one of the PEOPLE people.
//   B. THE MARKER'S BACKFILL: a directory written before the marker has
//      none, so the holder query finds nobody; the backfill reads the
//      holders of `stsWebauthnCredential` only (never `persons()`), writes
//      the marker on exactly the people whose keys say so, and a second
//      backfill writes nothing.
//   C. O(HOLDERS): the new list asks `persons()` never, reads no person's
//      keys one at a time, answers from as many holders as carry the marker,
//      and lists exactly the credentials the walk lists.
//   D. THE SAME DOWNGRADES: a status list revoking some of those chains,
//      and a recheck asked for, untrusts exactly the credentials the walk's
//      list and the same lookup say it should — and their marker goes with
//      them, since the marker is derived from the keys on every write.
//   E. SKIPPED WHEN NOTHING MOVED: a scheduled run after a complete one
//      reads no holder in any realm and says so; a registration (the mark),
//      a run asked for, and a new list each make it read again.
//   F. THE WINDOW: `DirectoryWindow.holdersAsync()` asks `withAttribute()`
//      a page at a time through `queryAsync()` where the bridge has it,
//      never `byKeys` per row, and through `query()` where it has not.
//   G. THE RULES: what the marker names, for a person's keys and a device's.
//
// NAMED TO RUN AFTER `attestation_revocation.js` AND `device_enrolment.js`:
// the suite is one process, and a status list this file activates is the
// active list for every file after it — `attestation_revocation.js`'s C1
// asks what happens with none.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const credentials = require('../common/credentials');
const devices = require('../common/devices');
const datasets = require('../risk/risk_datasets');
const revocation = require('../common/attestation_revocation');
const ldap = require('../ldap/ldap_server');
const queries = require('../persistence/directory_queries');

const log = require('bunyan').createLogger({ name: 'devices_android_recheck',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const REALM = 'arh' + STAMP.slice(-6);
const PEOPLE = 3000;
// Every HOLDER_EVERY-th person holds an Android-attested key: six of them.
const HOLDER_EVERY = 500;
// Every PLAIN_EVERY-th person holds an ordinary key, which is a holder of
// `stsWebauthnCredential` and not of the marker.
const PLAIN_EVERY = 97;
const MARKER = 'stsandroidattestedcredential';

const counts = { persons: 0, reads: 0, holders: 0, holderRows: 0 };

function nameOf(i) {
  log.debug("Entering nameOf().");
  log.debug("Leaving nameOf().");
  return 'arh-' + STAMP + '-' + String(i).padStart(4, '0');
}

// The serial a holder's chain carries, as the status list keys it.
function serialOf(i) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return 'a615' + Number(i).toString(16);
}

function keyValue(id, android, trusted, serial) {
  log.debug("Entering keyValue().");
  const out = { credentialId: id, role: 'mfa', signCount: 0,
                publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' } };
  if (android) {
    out.attestation = { format: 'android-key', trusted: trusted,
      anchor: 'synthetic', androidRevocation: { status: 'good',
        chainSerials: [serial, 'a615ffff'], listVersion: 'seed' } };
  }
  log.debug("Leaving keyValue().");
  return JSON.stringify(out);
}

// The directory `credentials.ts` was given, found by asking an instance
// method for its own `this.directory` (the module exports no accessor).
function installedDirectory() {
  log.debug("Entering installedDirectory().");
  const proto = credentials.Credentials.prototype;
  const real = proto.keysOf;
  let found = null;
  proto.keysOf = function () {
    found = this.directory;
    return [];
  };
  try {
    credentials.keysOf('nobody');
  } finally {
    proto.keysOf = real;
  }
  log.debug("Leaving installedDirectory().");
  return found;
}

// Counts `persons()`, each person's key read and each holder query.
function installSpies(directory) {
  log.debug("Entering installSpies().");
  const real = { persons: directory.persons,
                 readWebauthn: directory.readWebauthn,
                 holdersAsync: directory.holdersAsync };
  directory.persons = function () {
    counts.persons += 1;
    return real.persons.apply(this, arguments);
  };
  directory.readWebauthn = function () {
    counts.reads += 1;
    return real.readWebauthn.apply(this, arguments);
  };
  directory.holdersAsync = function () {
    counts.holders += 1;
    return real.holdersAsync.apply(this, arguments).then(function (rows) {
      counts.holderRows += rows.length;
      return rows;
    });
  };
  log.debug("Leaving installSpies().");
  return function restore() {
    log.debug("Entering restore().");
    directory.persons = real.persons;
    directory.readWebauthn = real.readWebauthn;
    directory.holdersAsync = real.holdersAsync;
    log.debug("Leaving restore().");
  };
}

function reset() {
  log.debug("Entering reset().");
  counts.persons = 0;
  counts.reads = 0;
  counts.holders = 0;
  counts.holderRows = 0;
  log.debug("Leaving reset().");
}

// PEOPLE people, written as a directory written before #615 holds them: the
// keys on the entry and no marker. Six Android holders, one of them with a
// second, UNTRUSTED Android key that is never rechecked; a few dozen plain
// key holders.
function seed(t) {
  log.debug("Entering seed().");
  const android = [];
  for (let i = 0; i < PEOPLE; i++) {
    const name = nameOf(i);
    const made = ldap.createUser(name, { invent: false, origin: 'test' });
    if (!made || !made.ok) {
      t.bad('seeding ' + name, JSON.stringify(made && made.errors));
      log.debug("Leaving seed(). A create failed.");
      return android;
    }
    const keys = [];
    if (i % HOLDER_EVERY === 0) {
      keys.push(keyValue('and-' + i, true, true, serialOf(i)));
      android.push({ username: name, credentialId: 'and-' + i, i: i });
      if (i === 0) {
        keys.push(keyValue('and-untrusted-' + i, true, false, serialOf(i)));
      }
    } else if (i % PLAIN_EVERY === 0) {
      keys.push(keyValue('plain-' + i, false));
    }
    if (keys.length) {
      ldap.existingUserEntry(name).attributes.stswebauthncredential = keys;
    }
  }
  log.debug("Leaving seed(). " + android.length + " Android holder(s).");
  return android;
}

function markerOf(name) {
  log.debug("Entering markerOf().");
  const stored = ldap.existingUserEntry(name);
  log.debug("Leaving markerOf().");
  return ((stored && stored.attributes[MARKER]) || []).slice().sort();
}

function sameRows(a, b) {
  log.debug("Entering sameRows().");
  const key = function (one) {
    return one.username + '|' + one.credentialId + '|' +
           one.chainSerials.join(',');
  };
  const left = a.map(key).sort();
  const right = b.map(key).sort();
  log.debug("Leaving sameRows().");
  return left.length === right.length && left.every(function (v, i) {
    return v === right[i];
  });
}

async function loadList(revoked) {
  log.debug("Entering loadList().");
  const entries = {};
  revoked.forEach(function (serial) {
    entries[serial.toUpperCase()] = { status: 'REVOKED',
                                      reason: 'KEY_COMPROMISE' };
  });
  const out = await datasets.importVersion({
    dataset: 'android.attestation-status',
    format: 'android-attestation-status-json',
    content: JSON.stringify({ entries: entries, stamp: STAMP + revoked.length,
                              at: Date.now() }),
    source: 'upload', actor: 'the test' });
  log.debug("Leaving loadList().");
  return out;
}

// --- A–D: the old walk, the backfill, the holders and the downgrades -------
async function body(t, android) {
  log.debug("Entering body().");
  // A. THE OLD COST.
  reset();
  const walked = credentials.androidAttestedCredentials();
  const before = Object.assign({}, counts);
  t.log.info('A. the walk: ' + before.persons + ' persons(), ' +
             before.reads + ' key read(s), ' + walked.length + ' found');
  t.check(before.persons === 1 && before.reads >= PEOPLE &&
          walked.length === android.length,
          'A1. the old walk asks persons() and reads every one of the ' +
          PEOPLE + ' people to find ' + android.length + ' key(s)',
          JSON.stringify(before));

  // B. THE BACKFILL.
  reset();
  const unmarked = await credentials.androidAttestedCredentialsAsync();
  t.check(unmarked.viaHolders && unmarked.rows.length === 0 &&
          counts.persons === 0,
          'B1. before the backfill the marker query finds nobody: a ' +
          'directory written before #615 carries no marker',
          JSON.stringify({ rows: unmarked.rows.length, counts: counts }));
  reset();
  const filled = await credentials.backfillAndroidMarkers();
  const plainHolders = Math.ceil(PEOPLE / PLAIN_EVERY) -
    android.filter(function (one) {
      return one.i % PLAIN_EVERY === 0;
    }).length;
  t.check(filled.available && filled.written === android.length &&
          filled.failed === 0 &&
          filled.holders === android.length + plainHolders &&
          counts.persons === 0 && counts.reads === android.length,
          'B2. the backfill reads the ' + filled.holders + ' key holders ' +
          '(never persons()), and writes the marker on the ' +
          android.length + ' whose keys say so, re-reading only those',
          JSON.stringify({ filled: filled, counts: counts }));
  const marked = android.every(function (one) {
    return markerOf(one.username).join() === one.credentialId;
  });
  const unmarkedPlain = markerOf(nameOf(PLAIN_EVERY)).length === 0 &&
    markerOf(nameOf(1)).length === 0;
  t.check(marked && unmarkedPlain,
          'B3. the marker names the trusted Android key, not the untrusted ' +
          'one, and nobody else carries it', JSON.stringify(
            android.map(function (one) {
              return markerOf(one.username);
            })));
  reset();
  const again = await credentials.backfillAndroidMarkers();
  t.check(again.written === 0 && counts.reads === 0,
          'B4. a second backfill writes nothing and reads nobody',
          JSON.stringify(again));

  // C. O(HOLDERS).
  reset();
  const listed = await credentials.androidAttestedCredentialsAsync();
  const after = Object.assign({}, counts);
  t.log.info('C. the holders: ' + after.persons + ' persons(), ' +
             after.reads + ' key read(s), ' + after.holderRows +
             ' holder row(s), ' + listed.rows.length + ' found');
  t.check(listed.viaHolders && after.persons === 0 && after.reads === 0 &&
          after.holders === 1 && after.holderRows === android.length &&
          listed.holders === android.length,
          'C1. the recheck\'s list asks persons() never, reads no person ' +
          'one at a time, and is answered by one holder query of ' +
          android.length + ' row(s) for ' + PEOPLE + ' people',
          JSON.stringify(after));
  t.check(sameRows(listed.rows, walked),
          'C2. and lists exactly the credentials the walk lists',
          JSON.stringify({ holders: listed.rows, walked: walked }));

  // D. THE SAME DOWNGRADES.
  const revokedOnes = android.filter(function (one, n) {
    return n % 2 === 0;
  });
  const loaded = await loadList(revokedOnes.map(function (one) {
    return serialOf(one.i);
  }));
  t.check(loaded.ok && loaded.activated, 'D0. a list revoking ' +
          revokedOnes.length + ' of the chains is active',
          JSON.stringify(loaded));
  const expected = [];
  for (const one of walked) {
    const hit = await datasets.lookupAttestationSerials(one.chainSerials);
    if (hit.checked && hit.hits.some(function (h) {
      return h.status === 'REVOKED' || h.status === 'SUSPENDED';
    })) {
      expected.push(one.username + '|' + one.credentialId);
    }
  }
  reset();
  const ran = await realms.run(realms.DEFAULT_REALM, function () {
    return revocation.recheckAll({ trigger: 'manual' });
  });
  const untrusted = [];
  android.forEach(function (one) {
    const key = credentials.keysOf(one.username).filter(function (k) {
      return k.credentialId === one.credentialId;
    })[0];
    if (key && key.attestation && key.attestation.trusted === false) {
      untrusted.push(one.username + '|' + one.credentialId);
    }
  });
  t.check(expected.length === revokedOnes.length &&
          expected.slice().sort().join() === untrusted.slice().sort().join() &&
          counts.persons === 0 && ran.downgraded >= expected.length,
          'D1. the recheck untrusts exactly the credentials the walk and the ' +
          'same lookup say it should, without persons()',
          JSON.stringify({ expected: expected, untrusted: untrusted,
                           ran: ran }));
  t.check(revokedOnes.every(function (one) {
    return markerOf(one.username).length === 0;
  }) && android.filter(function (one, n) {
    return n % 2 === 1;
  }).every(function (one) {
    return markerOf(one.username).join() === one.credentialId;
  }), 'D2. an untrusted key\'s marker is gone with it; the others keep ' +
     'theirs');
  log.debug("Leaving body().");
  return ran;
}

// --- E: skipped when nothing moved ------------------------------------------
async function skips(t, realm) {
  log.debug("Entering skips().");
  const runAll = function (ctx) {
    log.debug("Entering runAll().");
    log.debug("Leaving runAll().");
    return realms.run(realms.DEFAULT_REALM, function () {
      return revocation.recheckAll(ctx);
    });
  };
  reset();
  const quiet = await runAll({ trigger: 'schedule' });
  t.check(quiet.skipped === quiet.realms && counts.holders === 0 &&
          counts.persons === 0 && /as the last recheck found them/
            .test(quiet.summary),
          'E1. a scheduled run after a complete one reads nothing in any ' +
          'realm, and says why', JSON.stringify({ quiet: quiet,
                                                   counts: counts }));
  realms.run(realm, function () {
    revocation.noteRegistration('the test');
  });
  reset();
  const moved = await runAll({ trigger: 'schedule' });
  t.check(moved.skipped === moved.realms - 1 && counts.holders >= 1 &&
          counts.persons === 0,
          'E2. a registration in one realm makes that realm, and only it, ' +
          'read its holders again', JSON.stringify({ moved: moved,
                                                     counts: counts }));
  reset();
  const asked = await runAll({ trigger: 'manual' });
  t.check(asked.skipped === 0 && counts.holders >= asked.realms,
          'E3. a run asked for reads every realm\'s holders, whatever moved',
          JSON.stringify({ asked: asked, counts: counts }));
  await loadList([serialOf(0), 'a615eeee']);
  reset();
  const listed = await runAll({ trigger: 'schedule' });
  t.check(listed.skipped === 0 && counts.holders >= listed.realms,
          'E4. a newer list makes every realm read its holders again',
          JSON.stringify({ listed: listed, counts: counts }));
  // A registration through the one door that writes a key moves the mark.
  const stateBefore = realms.run(realm, function () {
    return JSON.stringify(revocationState());
  });
  const name = nameOf(1);
  const added = realms.run(realm, function () {
    return credentials.addKey(name, { credentialId: 'and-added',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      signCount: 0, attestation: JSON.parse(keyValue('x', true, true,
        serialOf(1))).attestation });
  });
  const stateAfter = realms.run(realm, function () {
    return JSON.stringify(revocationState());
  });
  t.check(added && added.ok && stateAfter !== stateBefore &&
          realms.run(realm, function () {
            return markerOf(name).join() === 'and-added';
          }),
          'E5. an Android-attested key enrolled through addKey() is marked ' +
          'on the write and moves the registration mark',
          JSON.stringify({ added: added && (added.ok || added.errors),
                           before: stateBefore, after: stateAfter }));
  log.debug("Leaving skips().");
}

// The ambient realm's `registered` row of the recheck's state.
function revocationState() {
  log.debug("Entering revocationState().");
  const deps = revocation.AttestationRevocation.defaultDeps();
  log.debug("Leaving revocationState().");
  return deps.state().get('registered') || null;
}

// --- F: the window -----------------------------------------------------------
async function windowed(t) {
  log.debug("Entering windowed().");
  const DirectoryWindow = require('../ldap/directory_window');
  const USERS = 'ou=users,dc=w615';
  const rows = [];
  for (let i = 0; i < 1200; i++) {
    const key = 'uid=w' + String(i).padStart(4, '0') + ',' + USERS;
    const attrs = { uid: ['w' + i] };
    if (i % 2 === 0) {
      attrs[MARKER] = ['c' + i];
    }
    rows.push({ realm: 'default', dn_key: key, dn: key, attrs: attrs,
                origin: '', created_at: null, modified_at: null });
  }
  const asked = { sync: [], async: [] };
  const answer = function (name, args) {
    log.debug("Entering answer().");
    if (name !== 'withAttribute') {
      log.debug("Leaving answer(). Not a holder query.");
      return [];
    }
    log.debug("Leaving answer().");
    return rows.filter(function (r) {
      return r.dn_key.endsWith(',' + args[1]) &&
        r.attrs[args[2]] !== undefined && r.dn_key > args[3];
    }).slice(0, args[4]).map(queries.rowOf);
  };
  const make = function (withAsync) {
    log.debug("Entering make().");
    const w = new DirectoryWindow({
      currentId: function () {
        return 'default';
      },
      onRemove: function () {
        return undefined;
      },
      windowedContainers: function () {
        return [USERS];
      },
      fromRow: function (realmId, r) {
        return { dn: r.dn, attributes: r.attributes };
      },
      maxEntries: function () {
        return 100;
      },
      onTouched: function () {
        return false;
      }
    });
    const bridge = { query: function (name, args) {
      asked.sync.push(name);
      return answer(name, args);
    } };
    if (withAsync) {
      bridge.queryAsync = function (name, args) {
        asked.async.push(name);
        return Promise.resolve(answer(name, args));
      };
    }
    w.attach(bridge);
    log.debug("Leaving make().");
    return w;
  };
  const w = make(true);
  const found = await w.holdersAsync('default', USERS, MARKER, function () {
    return true;
  });
  t.check(found.length === 600 && asked.sync.length === 0 &&
          asked.async.length === 2 &&
          asked.async.every(function (n) {
            return n === 'withAttribute';
          }),
          'F1. the window asks withAttribute() a page at a time through ' +
          'queryAsync(), and never byKeys per row',
          JSON.stringify({ found: found.length, asked: asked }));
  asked.sync = [];
  asked.async = [];
  const plain = make(false);
  const again = await plain.holdersAsync('default', USERS, MARKER,
                                         function () {
                                           return true;
                                         });
  t.check(again.length === 600 && asked.sync.length === 2 &&
          asked.sync.every(function (n) {
            return n === 'withAttribute';
          }),
          'F2. a bridge without queryAsync() is asked synchronously, one ' +
          'statement a page, still never byKeys per row',
          JSON.stringify(asked));
  log.debug("Leaving windowed().");
}

// --- G: the rules ----------------------------------------------------------
function rules(t) {
  log.debug("Entering rules().");
  const marked = credentials.androidMarkerOf([
    keyValue('b', true, true, 'aa'), keyValue('a', true, true, 'bb'),
    keyValue('u', true, false, 'cc'), keyValue('p', false),
    'not json']);
  t.check(marked.join() === 'a,b',
          'G1. a person\'s marker is the sorted ids of the trusted Android ' +
          'keys with serials; untrusted, plain and unreadable values are not ' +
          'in it', JSON.stringify(marked));
  const attested = { level: 'attested', format: 'android-key-attestation',
                     summary: '', verifiedAt: 'x', chainSerials: ['aa'] };
  const keys = [{ id: 'k2', attestation: attested },
                { id: 'k1', attestation: attested },
                { id: 'k3', attestation: Object.assign({}, attested,
                    { level: 'self-asserted' }) },
                { id: 'k4', attestation: Object.assign({}, attested,
                    { chainSerials: [] }) }];
  t.check(devices.androidMarkerOf(keys).join() === 'k1,k2',
          'G2. a device\'s marker is the sorted ids of its attested Android ' +
          'keys with serials', JSON.stringify(devices.androidMarkerOf(keys)));
  log.debug("Leaving rules().");
}

async function run(t) {
  log.debug("Entering run().");
  rules(t);
  await windowed(t);
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  const directory = installedDirectory();
  if (!directory || typeof directory.holdersAsync !== 'function') {
    t.bad('the directory offers no holdersAsync()');
    realms.remove(REALM);
    log.debug("Leaving run().");
    return;
  }
  const restore = installSpies(directory);
  config.setOverride('ldap.maxEntries', '100000');
  try {
    const android = realms.run(made.realm, function () {
      return seed(t);
    });
    await realms.run(made.realm, function () {
      return body(t, android);
    });
    await skips(t, made.realm);
  } finally {
    config.clearOverride('ldap.maxEntries');
    restore();
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'android recheck holders',
  describe: 'the Android attestation recheck reads the holders of its ' +
            'marker, not everybody, without blocking, and only when the ' +
            'list or the registrations moved (#615)',
  run: run
};
