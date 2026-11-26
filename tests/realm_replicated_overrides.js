// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_replicated_overrides.js
//
// ===========================================================================
// A REALM'S OVERRIDES ANOTHER PROCESS WROTE ARE TAKEN AS WRITTEN, AND A COPY
// THIS PROCESS COULD NOT TAKE IS NEVER WRITTEN BACK (2026-11-15, GitHub
// Actions run #300).
//
// `tests/protocol/sts_signature_policy.js` section H failed in every mode
// with request workers (single-node, mariadb, cluster) and passed in cells,
// which has none. A keyless `/admin-api` caller set
// `oauth2.accessTokenSigningAlg=ES256` and then `keys.signingAlgorithms=
// PS256,RS256` — each taken by the realm's config/set, the second not judged
// against the first — and a token from another worker was signed RS256. The
// read barrier was not the cause: the write moved the generation and the
// reader's worker pulled it. That worker's `realms.update(…, replicated)`
// then re-judged the PAIR (cfa8ca851, #444's D12), refused it STS-KEYS-0192,
// said nothing, and kept the old overrides — and its realm shadow, advanced
// to the stored row, made its next flush CLEAR the setting from the store
// for every process, so a later reset of it was refused STS-CORE-0007 on the
// writer as well.
//
//   A. the realm registry, in this process:
//      1. a replicated update carrying that pair is taken whole;
//      2. a realm created from a replicated row carrying it is taken whole;
//      3. a replicated row's value is not dropped for a rule between
//         settings judged against the DEFAULT realm's companion
//         (restorableOverrides(), checkStoredOverride());
//      4. and an update made HERE is still judged as one write (D12):
//         STS-KEYS-0192.
//   B. over a PostgreSQL double, `persistence.js`'s change-log apply:
//      1. a row another node wrote with that pair is held here whole;
//      2. a flush of an unrelated change here leaves both in the store;
//      3. a replicated update the registry refuses (a NUL in the name,
//         STS-CORE-0171) leaves this process's copy as it was, and a flush
//         here does not write that copy back over the stored overrides —
//         neither a key it lacks nor its old value of one it holds
//         (STS-STORE-0174);
//      4. a stored value this process leaves out (STS-CORE-0008) stays in
//         the store after a flush here, as restorableOverrides() says.
//      5. a change to one realm's row updates that realm here and no
//         other (2026-11-18: every realm was updated on every change).
//      6. a realm created and flushed here while another node's change has
//         the realm list in flight is not removed by that stale answer
//         (GitHub run 45732176952, `sts_pseudonyms`).
//
// Each part in a CHILD PROCESS: B puts a database double in the require
// cache, and A sets a process-wide override.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name:
  'realm_replicated_overrides', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// A: the realm registry alone.
// ---------------------------------------------------------------------------
function registryChild() {
  const ROOT = process.env.RRO_ROOT;
  const OUT = process.env.RRO_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const errorCodes = require(ROOT + '/common/error_codes');
    require(ROOT + '/common/signature_policy');
    const PAIR = { 'oauth2.accessTokenSigningAlg': 'ES256',
                   'keys.signingAlgorithms': 'PS256,RS256' };

    realms.create({ id: 'rro-a', name: 'rro-a' });
    const up = realms.update('rro-a', { overrides: PAIR, replicated: true });
    const held = (realms.get('rro-a') || {}).overrides || {};
    note(up && up.ok === true &&
         held['oauth2.accessTokenSigningAlg'] === 'ES256' &&
         held['keys.signingAlgorithms'] === 'PS256,RS256',
         'A1. a replicated update carrying a chosen algorithm and a list ' +
         'without it is taken whole',
         JSON.stringify({ up: up && (up.errors || up.ok), held: held }));

    const made = realms.create({ id: 'rro-b', name: 'rro-b',
                                 overrides: PAIR, restored: true,
                                 replicated: true });
    const madeHeld = (realms.get('rro-b') || {}).overrides || {};
    note(made && made.ok !== false &&
         madeHeld['oauth2.accessTokenSigningAlg'] === 'ES256',
         'A2. a realm created from a replicated row carrying it is taken ' +
         'whole', JSON.stringify(made && (made.errors || made.ok)));

    // The default realm lists RS256 only; a realm whose own list holds
    // ES256 chose ES256. Judged one value at a time against the default
    // realm's list, the choice was dropped (STS-CORE-0008).
    config.setOverride('keys.signingAlgorithms', 'RS256');
    const own = realms.create({ id: 'rro-c', name: 'rro-c', overrides: {
      'keys.signingAlgorithms': 'ES256,RS256',
      'oauth2.accessTokenSigningAlg': 'ES256' },
      restored: true, replicated: true });
    const ownHeld = (realms.get('rro-c') || {}).overrides || {};
    note(own && own.ok !== false &&
         ownHeld['oauth2.accessTokenSigningAlg'] === 'ES256',
         'A3. a replicated row\'s value is not dropped for a rule judged ' +
         'against the default realm\'s companion', JSON.stringify(ownHeld));
    config.clearOverride('keys.signingAlgorithms');

    const here = realms.update('rro-a', { overrides: {
      'keys.signingAlgorithms': 'RS256',
      'oauth2.accessTokenSigningAlg': 'ES256' } });
    note(here && here.ok === false &&
         errorCodes.codeOf(here) === 'STS-KEYS-0192',
         'A4. an update made here is still judged as one write, ' +
         'STS-KEYS-0192', JSON.stringify(here && (here.errors || here.ok)));
  } catch (e) {
    findings.push({ ok: false, what: 'the registry child ran to the end',
                    detail: e && e.stack });
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

// ---------------------------------------------------------------------------
// B: persistence.js over a PostgreSQL double.
// ---------------------------------------------------------------------------
function storeChild() {
  const ROOT = process.env.RRO_ROOT;
  const OUT = process.env.RRO_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const db = { realms: new Map(), log: [], holdRealmReads: false,
               heldRealmReads: [], realmReads: 0 };
  const rows = function (list) {
    return Promise.resolve({ rows: list, rowCount: list.length });
  };
  const json = function (value) {
    return typeof value === 'string' ? JSON.parse(value) : value;
  };
  db.query = function (sql, params) {
    const text = String(sql).replace(/\s+/g, ' ').trim();
    const p = params || [];
    if (/^SELECT to_regclass/.test(text)) {
      const row = {};
      for (let i = 0; i < 200; i++) {
        row['o' + i] = 'present';
      }
      return rows([row]);
    }
    if (/^INSERT INTO sts_changes/.test(text)) {
      for (let i = 0; i + 3 < p.length; i += 4) {
        db.log.push({ seq: db.log.length + 1, origin: p[i], kind: p[i + 1],
                      realm: p[i + 2], key: p[i + 3] });
      }
      return rows([]);
    }
    if ((/SELECT COALESCE\(MAX\(seq\), 0\) AS seq FROM sts_changes/
          .test(text) || /sts:(latestChangeSeq|changeCeiling) /.test(text))) {
      return rows([{ seq: db.log.length }]);
    }
    if (/sts:changesSince /.test(text)) {
      return rows(db.log.filter(function (row) {
        return row.seq > Number(p[0]);
      }).slice(0, Number(p[1]) || 500));
    }
    if (/^SELECT id, name, description, created_at, overrides, domain, retiring_at FROM sts_realms/
          .test(text)) {
      // The snapshot is taken when the statement is sent, as a database
      // takes it; B6 holds the ANSWER back while this process writes.
      const snapshot = rows(Array.from(db.realms.values()).map(function (row) {
        return Object.assign({}, row,
                             { overrides: Object.assign({}, row.overrides) });
      }));
      if (db.holdRealmReads) {
        db.realmReads += 1;
        return new Promise(function (resolve) {
          db.heldRealmReads.push(function () {
            resolve(snapshot);
          });
        });
      }
      return snapshot;
    }
    if (/^INSERT INTO sts_realms/.test(text)) {
      // The driver's merge, as the real statement makes it:
      // `(stored - cleared) || set`, or the whole object for `whole`.
      const had = db.realms.get(p[0]);
      let overrides = Object.assign({}, (had && had.overrides) || {});
      if (!had || p[9]) {
        overrides = json(p[4]) || {};
      } else {
        (p[7] || []).forEach(function (key) {
          delete overrides[key];
        });
        Object.assign(overrides, json(p[8]) || {});
      }
      db.realms.set(p[0], { id: p[0],
                            name: had && !p[5] ? had.name : p[1],
                            description: had && !p[6] ? had.description
                                                      : p[2],
                            created_at: (had && had.created_at) || p[3],
                            overrides: overrides,
                            domain: (had && had.domain) || p[10],
                            retiring_at: null });
      return rows([]);
    }
    return rows([]);
  };
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
  require(ROOT + '/tests/tools/store_double')
    .install({ Pool: FakePool, Client: FakeClient });

  // Another node's write: the stored row's overrides, and its change row.
  function anotherNodeWrites(id, change) {
    const row = db.realms.get(id);
    change(row);
    db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'realms',
                  realm: '', key: '' });
  }

  (async function () {
    process.env.STS_PERSISTENCE_MODE = 'postgres';
    process.env.STS_PERSISTENCE_COORDINATE = 'true';
    const realms = require(ROOT + '/common/realms');
    require(ROOT + '/common/signature_policy');
    const persistence = require(ROOT + '/persistence/persistence');
    persistence.setDirectory({
      realmEntries: function () { return []; },
      replaceRealm: function () {},
      entryAt: function () { return null; },
      applyEntry: function () {},
      removeEntry: function () {}
    });
    await persistence.start();
    note(persistence.activeMode() === 'postgres',
         'B0. (the store opened over the double)',
         JSON.stringify(persistence.status().lastError || ''));
    await persistence.coordinate();

    const ID = 'rro-s';
    realms.create({ id: ID, name: ID });
    await persistence.flush();
    note(!!db.realms.get(ID), 'B0. (the realm is written down)');

    anotherNodeWrites(ID, function (row) {
      row.overrides['oauth2.accessTokenSigningAlg'] = 'ES256';
      row.overrides['keys.signingAlgorithms'] = 'PS256,RS256';
    });
    await persistence.syncNow();
    const held = realms.get(ID).overrides;
    note(held['oauth2.accessTokenSigningAlg'] === 'ES256' &&
         held['keys.signingAlgorithms'] === 'PS256,RS256',
         'B1. a row another node wrote with a chosen algorithm and a list ' +
         'without it is held here whole', JSON.stringify(held));

    realms.setOverride(ID, 'saml2.publishAlgorithmSupport', 'false');
    await persistence.flush();
    const after = db.realms.get(ID).overrides;
    note(after['oauth2.accessTokenSigningAlg'] === 'ES256' &&
         after['keys.signingAlgorithms'] === 'PS256,RS256' &&
         after['saml2.publishAlgorithmSupport'] === 'false',
         'B2. a flush of an unrelated change here leaves both in the store',
         JSON.stringify(after));

    // A replicated update the registry refuses: a NUL in the name.
    anotherNodeWrites(ID, function (row) {
      row.name = 'bad\u0000name';
      row.overrides['saml2.signAssertion'] = 'false';
      row.overrides['oauth2.accessTokenSigningAlg'] = 'PS256';
    });
    await persistence.syncNow();
    const kept = realms.get(ID);
    note(kept.name === ID &&
         kept.overrides['oauth2.accessTokenSigningAlg'] === 'ES256' &&
         !Object.prototype.hasOwnProperty.call(kept.overrides,
                                               'saml2.signAssertion'),
         'B3a. a replicated update the registry refuses leaves this ' +
         'process\'s copy as it was', JSON.stringify(kept.overrides));
    realms.setOverride(ID, 'saml2.publishAlgorithmSupport', 'true');
    await persistence.flush();
    const notBack = db.realms.get(ID).overrides;
    note(notBack['saml2.signAssertion'] === 'false' &&
         notBack['oauth2.accessTokenSigningAlg'] === 'PS256' &&
         notBack['saml2.publishAlgorithmSupport'] === 'true',
         'B3b. and a flush here writes its own change and not that old ' +
         'copy back over the stored overrides (STS-STORE-0174)',
         JSON.stringify(notBack));
    anotherNodeWrites(ID, function (row) {
      row.name = ID;
    });
    await persistence.syncNow();

    // A stored value this process leaves out (STS-CORE-0008).
    anotherNodeWrites(ID, function (row) {
      row.overrides['saml2.assertionLifetimeMin'] = '0';
    });
    await persistence.syncNow();
    note(!Object.prototype.hasOwnProperty.call(realms.get(ID).overrides,
                                               'saml2.assertionLifetimeMin'),
         'B4a. (a stored value no longer valid is left out here)',
         JSON.stringify(realms.get(ID).overrides));
    realms.setOverride(ID, 'saml2.publishAlgorithmSupport', 'false');
    await persistence.flush();
    note(db.realms.get(ID).overrides['saml2.assertionLifetimeMin'] === '0',
         'B4b. and stays in the store after a flush here',
         JSON.stringify(db.realms.get(ID).overrides));

    // B5 (2026-11-18): a change to ONE realm's row is an update of that
    // realm alone. The apply hands every stored row to restoreRealms(), and
    // until then every realm was updated — one realms.onChange() round per
    // realm per change, 554,190 "updated" lines on one node of run #468.
    const QUIET = 'rro-quiet';
    realms.create({ id: QUIET, name: QUIET });
    await persistence.flush();
    const updated = [];
    realms.onChange(function (id, what) {
      if (what === 'update') {
        updated.push(id);
      }
    });
    anotherNodeWrites(ID, function (row) {
      row.overrides['saml2.publishAlgorithmSupport'] = 'true';
    });
    await persistence.syncNow();
    note(updated.indexOf(ID) >= 0 && updated.indexOf(QUIET) < 0 &&
         realms.get(ID).overrides['saml2.publishAlgorithmSupport'] === 'true',
         'B5. a change to one realm\'s row updates that realm here and no ' +
         'other', JSON.stringify(updated));

    // B6 (GitHub run 45732176952): a realm list read that this process's
    // own realm write overtakes is read again, and never removes the realm
    // it did not yet hold. Another node's change asks for the list; the
    // answer is held while a realm is created and flushed HERE, so it is a
    // snapshot from before that realm existed in the store.
    const FRESH = 'rro-fresh';
    const removedHere = [];
    realms.onChange(function (id, what) {
      if (what === 'remove') {
        removedHere.push(id);
      }
    });
    db.holdRealmReads = true;
    anotherNodeWrites(ID, function (row) {
      row.overrides['saml2.publishAlgorithmSupport'] = 'false';
    });
    const pulling = persistence.syncNow();
    for (let i = 0; i < 200 && !db.heldRealmReads.length; i++) {
      await new Promise(function (resolve) { setImmediate(resolve); });
    }
    const heldOne = db.heldRealmReads.length === 1;
    realms.create({ id: FRESH, name: FRESH });
    db.holdRealmReads = false;
    await persistence.flush();
    db.heldRealmReads.splice(0).forEach(function (release) {
      release();
    });
    await pulling;
    note(heldOne && !!db.realms.get(FRESH) && !!realms.get(FRESH) &&
         removedHere.indexOf(FRESH) < 0 &&
         realms.get(ID).overrides['saml2.publishAlgorithmSupport'] ===
           'false',
         'B6. a realm created and flushed here while another node\'s ' +
         'change had the realm list in flight is kept: the overtaken answer ' +
         'is read again, and the other change still lands',
         JSON.stringify({ held: heldOne, stored: !!db.realms.get(FRESH),
                          here: !!realms.get(FRESH), removed: removedHere,
                          reads: db.realmReads }));

    await persistence.stop();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the store child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t, main, label) {
  log.debug("Entering inAChild(). " + label);
  const out = path.join(os.tmpdir(), 'realm-replicated-overrides-' + label +
                        '-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + main.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', RRO_ROOT: ROOT,
                                  RRO_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the ' + label + ' child process ' +
                                        'reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t, registryChild, 'registry');
  inAChild(t, storeChild, 'store');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_replicated_overrides',
  describe: 'A realm\'s overrides another process wrote are taken as ' +
            'written — a rule between settings is not asked again of a ' +
            'replicated or restored row — and a copy this process could ' +
            'not take is never written back over the store (run #300, ' +
            'STS-STORE-0174)',
  run: run
};
