// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_heartbeat_writes.js
//
// ===========================================================================
// A REMOTE PEP'S HEARTBEAT WRITES THE DIRECTORY ONLY WHEN SOMETHING DURABLE
// CHANGED (#1882).
//
// Every heartbeat, and every pull naming a registered PEP, rewrote the PEP's
// whole `ou=peps` entry: a directory write, a persistence flush, a change-log
// row on every node and an audit `entry.update` row, about five a minute per
// PEP at its defaults (8081's audit log held ~1,900 of them). Now the volatile
// half — last seen, the counters, the signal health, the in-use reports'
// figures, the last nudge — is kept in the minted store
// `xacml_pep_registry.liveness`, and the entry is written when something an
// operator would call a change moved.
//
//   H1. N heartbeats that change nothing durable write the entry ZERO times
//       after the first, and journal the liveness record at most once;
//   H2. a changed durable member (the version, a listener's state) writes the
//       entry exactly once, and repeating it writes nothing;
//   H3. `lastSeen` and the counters read through `all()` — what the console
//       and `/admin-api/xacml/peps` draw — move with every heartbeat, with no
//       entry write; counters that moved are journalled at once;
//   H4. the stale determination is the same rule over the newest record, and
//       the journal interval is a fifth of the stale threshold;
//   H5. a nudge's outcome moves no `lastSeen` and writes no entry; a
//       re-registration still drops what a new process has not reported, and
//       a removal takes the record with it;
//   H6. TWO PROCESSES: what process A journals, applied in process B through
//       the replication path (`persistence_minted.applyChange()`), is what
//       B's register reads — A's fresh `lastSeen` over B's older entry — and
//       an older arrival does not go over a newer record B holds.
//
// The entry write is the only door to the audit row (`ldap_server.js`'s
// `writePep()` audits every write it makes), so counting the writes is
// counting the `entry.update` rows.
//
// IN CHILD PROCESSES: each installs the persistence observer, a stand-in
// directory and (B) a stand-in driver and keystore, one life of each per
// process, and H6 is two processes by construction.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'xacml_pep_heartbeat_writes',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's
// scope; a `node -e` child is exempt from the Entering/Leaving rule.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.PEP_HB_OUT;
  const ROOT = process.env.PEP_HB_ROOT;
  const DIR = process.env.PEP_HB_DIR;
  const MODE = process.env.PEP_HB_MODE;
  const HANDLE = 'xacml_pep_registry.liveness';
  const nodeFs = require('fs');
  const nodePath = require('path');
  const pause = function (ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  };
  (async function () {
    let keystore = null;
    if (MODE === 'nodeB') {
      // B opens what A sealed, as a node of one cluster does.
      process.env.STS_KEYS_SOURCE = 'persisted';
      process.env.STS_KEYS_KEK_PROVIDER = 'file';
      process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
      process.env.STS_KEYS_KEK_FILE = nodePath.join(DIR, 'kek');
      keystore = require(ROOT + '/common/keystore');
      keystore.reset();
      keystore.setStore({
        loadKeys: function () {
          return Promise.resolve([]);
        },
        saveKeys: function () {
          return Promise.resolve();
        },
        deleteKeys: function () {
          return Promise.resolve();
        }
      });
      await keystore.start();
    }
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const registry = require(ROOT + '/xacml/xacml_pep_registry');
    const store = require(ROOT + '/xacml/xacml_store');
    const realmId = realms.currentId();
    let journalled = 0;
    realms.setPersistObserver(function (handle) {
      if (handle === HANDLE) {
        journalled++;
      }
    });
    store.setDirectory({
      allPolicies: function () {
        return [];
      },
      writePolicy: function () {
        return true;
      },
      deletePolicy: function () {
        return true;
      }
    });
    // ou=peps, held here, attribute names lower-cased as the directory
    // does (RFC 4512) — `tests/xacml_pep.js`'s stand-in, counting writes.
    const entries = new Map();
    let writes = 0;
    const lower = function (attributes) {
      const out = {};
      Object.keys(attributes || {}).forEach(function (key) {
        const value = attributes[key];
        out[key.toLowerCase()] = Array.isArray(value) ? value.slice(0)
                                                      : [String(value)];
      });
      return out;
    };
    registry.setDirectory({
      allPeps: function () {
        return Array.from(entries.entries()).map(function (pair) {
          return { name: pair[0], dn: 'cn=' + pair[0] + ',ou=peps',
                   attributes: pair[1] };
        });
      },
      writePep: function (name, attributes) {
        writes++;
        entries.set(name, lower(attributes));
        return true;
      },
      deletePep: function (name) {
        return entries.delete(name);
      },
      certificateIdentity: function () {
        return { dn: '', commonName: '', subject: '' };
      }
    });
    // What a PEP serving traffic reports: the figures move every time, the
    // listener's state and certificate do not.
    const listeners = function (n, state) {
      return {
        listeners: [{
          id: 'api', source: 'environment', protocol: 'https',
          purpose: 'api', address: '0.0.0.0', port: 8443,
          state: state || 'listening', reason: 'none', renew: 0,
          certificate: { subject: 'CN=pep-1', notAfter: '2027-01-01' },
          stats: { accepted: 10 * n, open: n, refused: 0, http1: 7 * n,
                   http2: 3 * n, handshakes: 10 * n }
        }],
        memory: { rssBytes: 1000000 + n, virtualBytes: 2000000 + n,
                  dataBytes: 300000 + n, threads: 8 },
        paths: [{ method: 'GET', path: '/api', count: n, refused: 0 }]
      };
    };
    const report = function (n, extra) {
      return Object.assign({
        syncToken: registry.syncToken(), policyCount: 3,
        decisions: 40, allowed: 30, refused: 10, undischargeable: 0,
        bias: 'deny-biased', resource: 'https://pep/api', version: 'v1',
        notifyUrl: 'https://pep.example.com/notify',
        hostname: 'pep-1.internal',
        settings: { token: 'settings-1', values: {} },
        signals: { receivers: 1, healthy: 1, stale: 0, setsAccepted: n },
        listeners: listeners(n)
      }, extra || {});
    };

    if (MODE === 'single') {
      // ---------------------------------------------------------------
      // H1. N HEARTBEATS THAT CHANGE NOTHING DURABLE.
      // ---------------------------------------------------------------
      const made = registry.register({ name: 'pep-1', identity: 'cn=pep-1',
        certificateSubject: 'CN=pep-1', thumbprint: 't', authenticated: true,
        notifyUrl: 'https://pep.example.com/notify', bias: 'deny-biased',
        resource: 'https://pep/api', version: 'v1',
        hostname: 'pep-1.internal' });
      note(made.ok && writes === 1, 'H0. a registration writes the entry once',
           JSON.stringify({ made: made, writes: writes }));
      const first = registry.heartbeat('pep-1', report(1));
      note(first.ok && writes === 2,
           'H1. the first heartbeat after a registration writes the entry ' +
           'once: the settings and listeners in force are durable and the ' +
           'registration dropped them', 'writes=' + writes);
      const afterFirst = writes;
      const journalBefore = journalled;
      const N = 25;
      const seen = [];
      for (let i = 2; i <= N + 1; i++) {
        await pause(2);
        const beat = registry.heartbeat('pep-1', report(i));
        seen.push(registry.read('pep-1').lastSeen);
        if (!beat.ok) {
          note(false, 'H1. heartbeat ' + i + ' is answered', beat.why);
        }
      }
      note(writes === afterFirst,
           'H1. ' + N + ' further heartbeats that change nothing durable ' +
           'write the entry ZERO times (were ' + N + ' writes and ' + N +
           ' audit entry.update rows)',
           'writes after first=' + (writes - afterFirst));
      note(journalled - journalBefore === 0,
           'H1. and journal the liveness record not at all: the counters ' +
           'did not move and the interval has not passed',
           'journalled=' + (journalled - journalBefore));
      // Five pulls: `heartbeat(name, {})`, what GET /xacml/pep/policies
      // does for a registered PEP.
      for (let i = 0; i < 5; i++) {
        registry.heartbeat('pep-1', {});
      }
      note(writes === afterFirst,
           'H1. and the pull\'s own heartbeat(name, {}) writes nothing ' +
           'either', 'writes=' + writes);

      // ---------------------------------------------------------------
      // H3. WHAT THE CONSOLE READS MOVES WITH EVERY HEARTBEAT.
      // ---------------------------------------------------------------
      const increasing = seen.every(function (one, i) {
        return i === 0 || Date.parse(one) > Date.parse(seen[i - 1]);
      });
      const entrySeen = entries.get('pep-1').xacmlpeplastseen[0];
      note(increasing && Date.parse(seen[seen.length - 1]) >
             Date.parse(entrySeen),
           'H3. lastSeen as read by all() advances with every heartbeat ' +
           'and is later than the entry\'s, which was not rewritten',
           JSON.stringify({ first: seen[0], last: seen[seen.length - 1],
                            entry: entrySeen }));
      const row = registry.read('pep-1');
      note(row.listenersInUse &&
           row.listenersInUse.listeners[0].stats.accepted === 10 * (N + 1) &&
           row.signals && row.signals.setsAccepted === N + 1,
           'H3. and so do the volatile reports: the listener figures and the ' +
           'signal health are the last heartbeat\'s',
           JSON.stringify(row.listenersInUse && row.listenersInUse.listeners));
      const journalCounters = journalled;
      registry.heartbeat('pep-1', report(N + 2, { decisions: 41,
                                                  allowed: 31 }));
      const moved = registry.read('pep-1');
      const stored = realms.handleFor(HANDLE).read(realmId, 'pep-1');
      note(writes === afterFirst && moved.decisions === 41 &&
           moved.allowed === 31 && journalled === journalCounters + 1 &&
           stored.present && stored.value.decisions === 41,
           'H3. counters that moved are read at once and journalled at ' +
           'once, with no entry write',
           JSON.stringify({ writes: writes - afterFirst,
                            journalled: journalled - journalCounters,
                            stored: stored.value }));
      const listed = require(ROOT + '/xacml/xacml_admin').pepsJson();
      const mine = (listed.peps || []).filter(function (one) {
        return one.name === 'pep-1';
      })[0];
      note(mine && mine.decisions === 41 && mine.lastSeen === moved.lastSeen,
           'H3. GET /admin-api/xacml/peps\' row carries the same values',
           JSON.stringify(mine && { decisions: mine.decisions,
                                    lastSeen: mine.lastSeen }));

      // ---------------------------------------------------------------
      // H2. A DURABLE CHANGE WRITES EXACTLY ONCE.
      // ---------------------------------------------------------------
      const beforeVersion = writes;
      registry.heartbeat('pep-1', report(N + 3, { decisions: 41,
        allowed: 31, version: 'v2' }));
      note(writes === beforeVersion + 1 &&
           entries.get('pep-1').xacmlpepversion[0] === 'v2',
           'H2. a changed version writes the entry exactly once',
           'writes=' + (writes - beforeVersion));
      note(entries.get('pep-1').xacmlpepdecisions[0] === '41',
           'H2. and the write carries the newest counters into the entry');
      registry.heartbeat('pep-1', report(N + 4, { decisions: 41,
        allowed: 31, version: 'v2' }));
      registry.heartbeat('pep-1', report(N + 5, { decisions: 41,
        allowed: 31, version: 'v2' }));
      note(writes === beforeVersion + 1,
           'H2. and repeating it writes nothing', 'writes=' +
           (writes - beforeVersion));
      const beforeState = writes;
      registry.heartbeat('pep-1', Object.assign(report(N + 6, {
        decisions: 41, allowed: 31, version: 'v2' }),
        { listeners: listeners(N + 6, 'failed') }));
      note(writes === beforeState + 1,
           'H2. a listener that stops listening is durable: one write',
           'writes=' + (writes - beforeState));
      const beforeSync = writes;
      registry.heartbeat('pep-1', Object.assign(report(N + 7, {
        decisions: 41, allowed: 31, version: 'v2', syncToken: 'older' }),
        { listeners: listeners(N + 7, 'failed') }));
      note(writes === beforeSync + 1 &&
           registry.read('pep-1').current === false,
           'H2. so is the sync token the PEP holds: one write, and the row ' +
           'is not current');

      // ---------------------------------------------------------------
      // H4. THE STALE DETERMINATION.
      // ---------------------------------------------------------------
      const interval = function (seconds) {
        config.setOverride('xacml.pepStaleAfterS', seconds);
        return registry.journalIntervalMs();
      };
      const was = config.value('xacml.pepStaleAfterS');
      const at300 = interval(300);
      const at10 = interval(10);
      const at100 = interval(100);
      const at86400 = interval(86400);
      note(at300 === 60000 && at10 === 2000 && at100 === 20000 &&
           at86400 === 60000,
           'H4. the journal interval is a fifth of xacml.pepStaleAfterS, at ' +
           'most a minute, so another process\'s lastSeen can never make a ' +
           'heartbeating PEP stale',
           JSON.stringify([at300, at10, at100, at86400]));
      config.setOverride('xacml.pepStaleAfterS', was);
      // A PEP whose entry was last written 400 s ago and that has not been
      // heard from since: stale at 300, as before.
      registry.register({ name: 'pep-old', identity: 'cn=pep-old',
                          authenticated: true });
      const old = new Date(Date.now() - 400000).toISOString();
      entries.get('pep-old').xacmlpeplastseen = [old];
      note(registry.read('pep-old').stale === true,
           'H4. an entry not seen for longer than xacml.pepStaleAfterS is ' +
           'stale, as it always was');
      const beforeOld = writes;
      const journalOld = journalled;
      registry.heartbeat('pep-old', {});
      note(registry.read('pep-old').stale === false &&
           writes === beforeOld && journalled === journalOld + 1,
           'H4. a heartbeat makes it fresh with no entry write, and is ' +
           'journalled at once because the last one written is older than ' +
           'the interval — so every process sees it come back',
           JSON.stringify({ writes: writes - beforeOld,
                            journalled: journalled - journalOld }));
      // Another process's heartbeat, 11 s ago, as the replication path
      // restores it, over a fresh registration whose entry is 400 s old:
      // stale at 10 s, fresh at 300 s — the same rule.
      const elsewhere = new Date(Date.now() - 11000).toISOString();
      registry.remove('pep-old');
      registry.register({ name: 'pep-old', identity: 'cn=pep-old',
                          authenticated: true });
      const registered = entries.get('pep-old').xacmlpepregisteredat[0];
      entries.get('pep-old').xacmlpeplastseen = [old];
      realms.handleFor(HANDLE).restore(realmId, 'pep-old', {
        registeredAt: registered, seenAt: elsewhere, decisions: 2,
        allowed: 1, refused: 1, undischargeable: 0, signals: null,
        settingsInUse: null, listenersInUse: null, lastNotify: '' });
      config.setOverride('xacml.pepStaleAfterS', 10);
      const at10s = registry.read('pep-old');
      config.setOverride('xacml.pepStaleAfterS', 300);
      const at300s = registry.read('pep-old');
      config.setOverride('xacml.pepStaleAfterS', was);
      note(at10s.lastSeen === elsewhere && at10s.stale === true &&
           at300s.stale === false && at300s.decisions === 2,
           'H4. a record journalled elsewhere is read as the newest, and ' +
           'stale is (now - lastSeen) > xacml.pepStaleAfterS over it',
           JSON.stringify({ at10: at10s.stale, at300: at300s.stale,
                            lastSeen: at10s.lastSeen }));
      // A record of an EARLIER registration is never read.
      realms.handleFor(HANDLE).restore(realmId, 'pep-old', {
        registeredAt: '2000-01-01T00:00:00.000Z',
        seenAt: new Date().toISOString(), decisions: 99, allowed: 0,
        refused: 0, undischargeable: 0, signals: null, settingsInUse: null,
        listenersInUse: null, lastNotify: '' });
      note(registry.read('pep-old').stale === true &&
           registry.read('pep-old').decisions !== 99,
           'H4. and a record of another registration under the name is not');

      // ---------------------------------------------------------------
      // H5. THE NUDGE, A RE-REGISTRATION, A REMOVAL.
      // ---------------------------------------------------------------
      await pause(3);
      const seenBefore = registry.read('pep-1').lastSeen;
      const beforeNudge = writes;
      const nudged = registry.recordNotify('pep-1', 'HTTP 204');
      const afterNudge = registry.read('pep-1');
      note(nudged && writes === beforeNudge &&
           / — HTTP 204$/.test(afterNudge.lastNotify) &&
           afterNudge.lastSeen === seenBefore,
           'H5. a nudge\'s outcome is recorded with no entry write and ' +
           'moves no lastSeen', JSON.stringify({ writes: writes - beforeNudge,
             lastNotify: afterNudge.lastNotify }));
      registry.heartbeat('pep-1', report(N + 8, { decisions: 41,
        allowed: 31, version: 'v2', syncToken: 'older' }));
      registry.register({ name: 'pep-1', identity: 'cn=pep-1',
        certificateSubject: 'CN=pep-1', thumbprint: 't', authenticated: true,
        notifyUrl: 'https://pep.example.com/notify', version: 'v3' });
      const restarted = registry.read('pep-1');
      note(restarted.signals === null && restarted.listenersInUse === null &&
           restarted.decisions === 41 &&
           / — HTTP 204$/.test(restarted.lastNotify),
           'H5. a re-registration still drops what a new process has not ' +
           'reported, and keeps the counters and the last nudge',
           JSON.stringify({ signals: restarted.signals,
                            decisions: restarted.decisions }));
      registry.remove('pep-1');
      note(!realms.handleFor(HANDLE).read(realmId, 'pep-1').present,
           'H5. and a removal takes the journalled record with it');
    } else if (MODE === 'nodeA') {
      // ---------------------------------------------------------------
      // H6, NODE A: registers, then heartbeats; what it journals is what
      // its flush would write, and the entry is what the directory
      // replicates.
      // ---------------------------------------------------------------
      const keys = [];
      realms.setPersistObserver(function (handle, realm, key) {
        if (handle === HANDLE) {
          keys.push(key);
        }
      });
      registry.register({ name: 'pep-x', identity: 'cn=pep-x',
                          authenticated: true, version: 'v1' });
      registry.heartbeat('pep-x', report(1));
      const entryAfterFirst = JSON.stringify(entries.get('pep-x'));
      await pause(5);
      registry.heartbeat('pep-x', report(2, { decisions: 77 }));
      const journalledRow = realms.handleFor(HANDLE).read(realmId, 'pep-x');
      note(keys.indexOf('pep-x') >= 0 && journalledRow.present &&
           JSON.stringify(entries.get('pep-x')) === entryAfterFirst,
           'H6. node A journals the heartbeat and does not rewrite the entry',
           JSON.stringify(keys));
      nodeFs.writeFileSync(nodePath.join(DIR, 'a.json'), JSON.stringify({
        entry: entries.get('pep-x'), row: journalledRow.value,
        lastSeen: registry.read('pep-x').lastSeen }));
    } else {
      // ---------------------------------------------------------------
      // H6, NODE B: holds the replicated entry, and applies A's row through
      // the replication path a change-log page takes.
      // ---------------------------------------------------------------
      const fromA = JSON.parse(nodeFs.readFileSync(
        nodePath.join(DIR, 'a.json'), 'utf8'));
      entries.set('pep-x', fromA.entry);
      const before = registry.read('pep-x');
      const minted = require(ROOT + '/persistence/persistence_minted');
      const rows = new Map();
      minted.setDriver({
        loadMinted: function () {
          return Promise.resolve([]);
        },
        saveMinted: function () {
          return Promise.resolve({});
        },
        readMinted: function (handle, realm, key) {
          return Promise.resolve(rows.get(handle + '|' + realm + '|' + key) ||
                                 null);
        }
      }, 'postgres');
      const b64 = function (text) {
        return Buffer.from(String(text), 'utf8').toString('base64url');
      };
      const put = function (value) {
        const column = minted.keyColumnOf
          ? minted.keyColumnOf(HANDLE, realmId, 'pep-x') : null;
        const key = column || 'pep-x';
        rows.set(HANDLE + '|' + realmId + '|' + key,
                 { handle: HANDLE, realm: realmId, key: key,
                   body: keystore.seal(JSON.stringify(value), 'minted-rows'),
                   writtenAt: Date.now() });
      };
      const change = { kind: 'minted', realm: realmId,
                       key: b64(HANDLE) + '.' + b64('pep-x') };
      put(fromA.row);
      await minted.applyChange(change);
      const after = registry.read('pep-x');
      note(Date.parse(before.lastSeen) < Date.parse(fromA.lastSeen) &&
           after.lastSeen === fromA.lastSeen && after.decisions === 77 &&
           writes === 0,
           'H6. NODE B READS NODE A\'S FRESH lastSeen AND COUNTERS through ' +
           'the replication path, over an entry that was never rewritten',
           JSON.stringify({ entry: before.lastSeen, a: fromA.lastSeen,
                            b: after.lastSeen, decisions: after.decisions }));
      // B now hears the PEP itself, later; A's older row arriving again
      // (a page applied late) does not go over it.
      await pause(5);
      registry.heartbeat('pep-x', report(3, { decisions: 78 }));
      const mineNow = registry.read('pep-x');
      put(fromA.row);
      await minted.applyChange(change);
      const held = realms.handleFor(HANDLE).read(realmId, 'pep-x');
      note(registry.read('pep-x').lastSeen === mineNow.lastSeen &&
           registry.read('pep-x').decisions === 78 && held.present &&
           held.value.decisions === 78 && writes === 0,
           'H6. and an older record arriving does not go over a newer one ' +
           'held here (mergeRow, mergeOnApply)',
           JSON.stringify(held.value && { seenAt: held.value.seenAt,
                                          decisions: held.value.decisions }));
    }
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    nodeFs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function runChild(t, root, dir, mode) {
  log.debug("Entering runChild(). " + mode);
  const out = path.join(dir, mode + '.findings.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { PEP_HB_OUT: out, PEP_HB_ROOT: root, PEP_HB_DIR: dir,
                       PEP_HB_MODE: mode, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  if (t.check(Array.isArray(findings),
              'the ' + mode + ' child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving runChild().");
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-pep-hb-'));
  // The key-encryption key node B opens node A's rows with, as one cluster's
  // nodes share one.
  fs.writeFileSync(path.join(dir, 'kek'),
                   require('crypto').randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  try {
    runChild(t, root, dir, 'single');
    runChild(t, root, dir, 'nodeA');
    runChild(t, root, dir, 'nodeB');
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is not a failed assertion.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep_heartbeat_writes',
  describe: 'a remote PEP heartbeat writes its ou=peps entry only when ' +
            'something durable changed; lastSeen and the counters live in ' +
            'a minted store every process reads (#1882)',
  run: run
};
