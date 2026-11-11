// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_counter_commit.js
//
// ===========================================================================
// AN APPLICATION'S AUTHENTICATION COUNTS DO NOT HOLD THE RESPONSE (#878).
//
// The authorization response's sighting of a client that already exists, and
// whose scope, redirect, grant and the rest did not change, increments
// counts. The token endpoint does not read them. They are still written, on
// the tally pool when that batch is the whole directory flush, and the
// directory generation does not move. A new application, and any structural
// field, stays a durable write. A counter beside a durable write of another
// entry rides that one transaction.
//
// Two children. The first is the store, with a directory stub, because
// requiring the real directory would be the service. The second is the
// classification, and it does require the directory, because `seen()` writes
// nothing until that slot is filled.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'application_counter_commit',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file.
async function persistChild() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ACC_OUT;
  const ROOT = process.env.ACC_ROOT;
  const until = function (pred) {
    const deadline = Date.now() + 2000;
    const step = function () {
      if (pred() || Date.now() >= deadline) {
        return Promise.resolve(!!pred());
      }
      return new Promise(function (resolve) {
        setTimeout(resolve, 20);
      }).then(step);
    };
    return step();
  };
  try {
    const realms = require(ROOT + '/common/realms');
    const persistence = require(ROOT + '/persistence/persistence');
    const entries = new Map();
    persistence.setDirectory({
      realmEntries: function (id) {
        if (id !== realms.currentId()) {
          return [];
        }
        const out = [];
        entries.forEach(function (entry, key) {
          out.push({ key: key, entry: entry });
        });
        return out;
      },
      replaceRealm: function () {
        return undefined;
      },
      entryAt: function (id, key) {
        if (id !== realms.currentId()) {
          return null;
        }
        return entries.get(key) || null;
      }
    });
    await persistence.start();
    const saves = [];
    const driver = persistence.currentDriver();
    const original = driver.saveDirectory.bind(driver);
    driver.saveDirectory = function (change, how) {
      const record = {
        tally: !!(how && how.tally),
        keys: (change.upserts || []).map(function (row) {
          return row.key;
        })
      };
      return original(change, how).then(function (result) {
        saves.push(record);
        return result;
      });
    };
    const dn = 'cn=counter,ou=applications,dc=example,dc=com';
    const entry = { dn: dn, attributes: { cn: ['counter'],
                                          appauthentications: ['1'] } };
    entries.set(dn, entry);
    const before = persistence.writeGeneration().directory;
    persistence.directoryChanged(dn);
    note(persistence.writeGeneration().directory === before + 1,
         'a structural directory write moves the generation',
         String(persistence.writeGeneration().directory));
    await persistence.commitThrough(persistence.writeGeneration());
    note(saves.some(function (one) {
      return !one.tally && one.keys.indexOf(dn) >= 0;
    }), 'a structural directory write is not a tally batch',
         JSON.stringify(saves));

    const held = persistence.writeGeneration().directory;
    entry.attributes.appauthentications = ['2'];
    persistence.directoryChanged(dn, { observation: true });
    note(persistence.writeGeneration().directory === held,
         'a counter sighting does not move the directory generation',
         String(persistence.writeGeneration().directory));
    const saw = await until(function () {
      return saves.some(function (one) {
        return one.tally && one.keys.indexOf(dn) >= 0;
      });
    });
    note(saw, 'a counter sighting is written with the tally flag',
         JSON.stringify(saves));

    const other = 'cn=other,ou=applications,dc=example,dc=com';
    entries.set(other, { dn: other, attributes: { cn: ['other'] } });
    entry.attributes.appauthentications = ['3'];
    const at = saves.length;
    const generation = persistence.writeGeneration().directory;
    persistence.directoryChanged(dn, { observation: true });
    persistence.directoryChanged(other);
    note(persistence.writeGeneration().directory === generation + 1,
         'a counter beside a durable write bumps the generation once',
         String(persistence.writeGeneration().directory));
    await persistence.commitThrough(persistence.writeGeneration());
    const batch = saves.slice(at);
    note(batch.length === 1 && !batch[0].tally &&
         batch[0].keys.indexOf(dn) >= 0 &&
         batch[0].keys.indexOf(other) >= 0,
         'both entries ride the one durable save',
         JSON.stringify(batch));
    await persistence.stop();
  } catch (e) {
    note(false, 'the persistence child threw', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
}

// Runs in the child. The real directory, so `seen()` has somewhere to write.
async function classifyChild() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ACC_OUT;
  const ROOT = process.env.ACC_ROOT;
  try {
    const persistence = require(ROOT + '/persistence/persistence');
    require(ROOT + '/ldap/ldap_server');
    const applications = require(ROOT + '/common/applications');
    const calls = [];
    const original = persistence.directoryChanged;
    persistence.directoryChanged = function (dn, how) {
      calls.push({ dn: String(dn || ''),
                   observation: !!(how && how.observation) });
      return original.apply(this, arguments);
    };
    const id = 'counter-878-' + process.pid;
    const mine = function () {
      return calls.filter(function (one) {
        return one.dn.indexOf(id) >= 0;
      });
    };
    const base = { identifier: id, kind: 'oauth2-client',
                   protocol: 'OAuth 2.0',
                   fields: { oauthClientId: id, oauthScope: 'openid' } };
    applications.seen(Object.assign({}, base, {
      sessionId: 's1', user: 'u1' }));
    const first = mine();
    note(first.length === 1 && first[0].observation === false,
         'the first sight of a client is a durable create',
         JSON.stringify(first));
    applications.seen(Object.assign({}, base, {
      sessionId: 's2', user: 'u2' }));
    const second = mine();
    note(second.length === 2 && second[1].observation === true,
         'a repeat sighting that only counts is an observation',
         JSON.stringify(second));
    applications.seen({
      identifier: id, kind: 'oauth2-client', protocol: 'OAuth 2.0',
      fields: { oauthScope: 'email' }, sessionId: 's3', user: 'u3'
    });
    const third = mine();
    note(third.length === 3 && third[2].observation === false,
         'a sighting that adds a scope stays durable',
         JSON.stringify(third));
  } catch (e) {
    note(false, 'the classification child threw', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
}

function childEnv(extra) {
  log.debug("Entering childEnv().");
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, extra, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' });
  log.debug("Leaving childEnv().");
  return env;
}

function spawnChild(fn, env) {
  log.debug("Entering spawnChild().");
  const root = path.join(__dirname, '..');
  const script = '(' + fn.toString() + ')().then(function () {' +
    ' process.exit(0); }, function (e) {' +
    ' console.error(e && e.stack || e); process.exit(1); })';
  const result = childProcess.spawnSync(process.execPath, ['-e', script], {
    cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  log.debug("Leaving spawnChild().");
  return result;
}

function report(t, out, result) {
  log.debug("Entering report().");
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in report(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in report(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving report().");
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-acc-'));
  const persistOut = path.join(dir, 'persist.json');
  const classifyOut = path.join(dir, 'classify.json');
  try {
    report(t, persistOut, spawnChild(persistChild, childEnv({
      ACC_OUT: persistOut, ACC_ROOT: root,
      STS_PERSISTENCE_MODE: 'ldif',
      STS_PERSISTENCE_DATA_DIR: dir,
      STS_PERSISTENCE_WRITE_DELAY: '0'
    })));
    report(t, classifyOut, spawnChild(classifyChild, childEnv({
      ACC_OUT: classifyOut, ACC_ROOT: root
    })));
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_counter_commit',
  describe: 'application authentication counts do not hold the response, ' +
            'and a structural sighting still does (#878)',
  run: run
};
